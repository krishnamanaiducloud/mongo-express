package identity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
)

// OpenShift verifies identities forwarded by the OpenShift OAuth proxy.
//
// The proxy forwards the user name and the user's OAuth access token. The
// token is validated against the OpenShift API (users/~), and the returned
// user name must match the forwarded header; this defeats header spoofing
// even if the loopback restriction were bypassed. Group membership is read
// from OpenShift Group objects with the portal's service account and cached.
type OpenShift struct {
	cfg     config.OpenShiftConfig
	mapper  RoleMapper
	trusted []*net.IPNet
	client  *http.Client
	now     func() time.Time

	tokMu  sync.Mutex
	tokens map[[32]byte]tokenEntry

	grpMu      sync.Mutex
	groups     map[string]map[string]bool // group -> member set
	groupsAt   time.Time
	refreshing bool
}

type tokenEntry struct {
	user    string
	expires time.Time
}

// NewOpenShift creates an OpenShift resolver.
func NewOpenShift(cfg config.OpenShiftConfig, mapper RoleMapper, trusted []*net.IPNet) (*OpenShift, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read OpenShift CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("OpenShift CA file contains no certificates")
		}
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: cfg.RequestTimeout,
		Proxy:               http.ProxyFromEnvironment,
	}
	return &OpenShift{
		cfg:     cfg,
		mapper:  mapper,
		trusted: trusted,
		client:  &http.Client{Transport: tr, Timeout: cfg.RequestTimeout},
		now:     time.Now,
		tokens:  map[[32]byte]tokenEntry{},
	}, nil
}

// Resolve implements Resolver.
func (o *OpenShift) Resolve(r *http.Request) (*Identity, error) {
	user := r.Header.Get(o.cfg.UserHeader)
	token := r.Header.Get(o.cfg.TokenHeader)
	if user == "" || token == "" {
		return nil, ErrUnauthenticated
	}
	if !peerTrusted(r, o.trusted) {
		return nil, ErrUntrustedProxy
	}
	if !ValidUsername(user) || len(token) > 8192 {
		return nil, ErrUnauthenticated
	}
	verified, err := o.verifyToken(r.Context(), token)
	if err != nil {
		return nil, err
	}
	if verified != user {
		slog.Warn("identity header does not match token owner", "event", "identity_mismatch")
		return nil, ErrUnauthenticated
	}
	groups, err := o.groupsFor(r.Context(), user)
	if err != nil {
		return nil, err
	}
	id := &Identity{User: user, Groups: groups, Role: o.mapper.RoleFor(groups)}
	if id.Role == RoleNone {
		return id, ErrNotAuthorized
	}
	return id, nil
}

func (o *OpenShift) verifyToken(ctx context.Context, token string) (string, error) {
	key := sha256.Sum256([]byte(token))
	now := o.now()
	o.tokMu.Lock()
	if e, ok := o.tokens[key]; ok && now.Before(e.expires) {
		o.tokMu.Unlock()
		return e.user, nil
	}
	o.tokMu.Unlock()

	var u struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	status, err := o.get(ctx, "/apis/user.openshift.io/v1/users/~", token, &u)
	if err != nil {
		slog.Warn("openshift token review failed", "error", err.Error())
		return "", ErrUnavailable
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "", ErrUnauthenticated
	}
	if status != http.StatusOK || u.Metadata.Name == "" {
		slog.Warn("openshift token review unexpected status", "status", status)
		return "", ErrUnavailable
	}

	o.tokMu.Lock()
	defer o.tokMu.Unlock()
	if len(o.tokens) > 10000 {
		for k, e := range o.tokens {
			if now.After(e.expires) {
				delete(o.tokens, k)
			}
		}
		if len(o.tokens) > 10000 {
			o.tokens = map[[32]byte]tokenEntry{}
		}
	}
	o.tokens[key] = tokenEntry{user: u.Metadata.Name, expires: now.Add(o.cfg.TokenCacheTTL)}
	return u.Metadata.Name, nil
}

// groupsFor returns the configured portal groups the user belongs to.
func (o *OpenShift) groupsFor(ctx context.Context, user string) ([]string, error) {
	members, err := o.groupMembers(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for g, set := range members {
		if set[user] {
			out = append(out, g)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (o *OpenShift) groupMembers(ctx context.Context) (map[string]map[string]bool, error) {
	now := o.now()
	o.grpMu.Lock()
	fresh := o.groups != nil && now.Sub(o.groupsAt) < o.cfg.GroupCacheTTL
	usable := o.groups != nil && now.Sub(o.groupsAt) < o.cfg.GroupMaxStale
	if fresh || (usable && o.refreshing) {
		g := o.groups
		o.grpMu.Unlock()
		return g, nil
	}
	o.refreshing = true
	o.grpMu.Unlock()

	g, err := o.fetchGroups(ctx)

	o.grpMu.Lock()
	defer o.grpMu.Unlock()
	o.refreshing = false
	if err != nil {
		slog.Warn("openshift group refresh failed", "error", err.Error())
		if usable {
			return o.groups, nil
		}
		return nil, ErrUnavailable
	}
	o.groups, o.groupsAt = g, now
	return g, nil
}

func (o *OpenShift) fetchGroups(ctx context.Context) (map[string]map[string]bool, error) {
	saToken, err := os.ReadFile(o.cfg.ServiceAccountFile)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	tok := strings.TrimSpace(string(saToken))
	names := append(slices.Clone(o.mapper.SREGroups), o.mapper.DeveloperGroups...)
	out := make(map[string]map[string]bool, len(names))
	for _, name := range names {
		var grp struct {
			Users []string `json:"users"`
		}
		status, err := o.get(ctx, "/apis/user.openshift.io/v1/groups/"+url.PathEscape(name), tok, &grp)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
		case http.StatusNotFound:
			// A configured group that does not exist simply has no members.
		default:
			return nil, fmt.Errorf("get group %q: HTTP %d", name, status)
		}
		set := make(map[string]bool, len(grp.Users))
		for _, u := range grp.Users {
			set[u] = true
		}
		out[name] = set
	}
	return out, nil
}

func (o *OpenShift) get(ctx context.Context, path, bearer string, into any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(o.cfg.APIURL, "/")+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 4<<20)
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(body).Decode(into); err != nil {
			return 0, fmt.Errorf("decode response: %w", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, body)
	}
	return resp.StatusCode, nil
}
