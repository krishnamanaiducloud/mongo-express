// Package identity resolves the SSO identity of a request and maps it to a
// portal role. Identity is only accepted from a trusted reverse proxy.
package identity

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
)

// Role is the portal-level authorization tier. It caps what the portal will
// attempt; MongoDB remains the final authority for every operation.
type Role string

const (
	RoleNone      Role = ""
	RoleDeveloper Role = "developer"
	RoleSRE       Role = "sre"
)

// CanWrite reports whether the portal role permits data-modifying requests.
func (r Role) CanWrite() bool { return r == RoleSRE }

// Identity is an authenticated SSO principal.
type Identity struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
	Role   Role     `json:"role"`
}

var (
	// ErrUnauthenticated means no valid SSO identity was presented.
	ErrUnauthenticated = errors.New("sso identity required")
	// ErrUntrustedProxy means identity headers arrived from an untrusted peer.
	ErrUntrustedProxy = errors.New("identity headers from untrusted source")
	// ErrNotAuthorized means the user is authenticated but in no portal group.
	ErrNotAuthorized = errors.New("user is not a member of an authorized group")
	// ErrUnavailable means identity could not be verified (fail closed).
	ErrUnavailable = errors.New("identity verification unavailable")
)

// Resolver authenticates a request.
type Resolver interface {
	Resolve(r *http.Request) (*Identity, error)
}

// RoleMapper maps group membership to a portal role.
type RoleMapper struct {
	DeveloperGroups []string
	SREGroups       []string
}

// RoleFor returns the highest portal role granted by groups.
func (m RoleMapper) RoleFor(groups []string) Role {
	for _, g := range groups {
		if slices.Contains(m.SREGroups, g) {
			return RoleSRE
		}
	}
	for _, g := range groups {
		if slices.Contains(m.DeveloperGroups, g) {
			return RoleDeveloper
		}
	}
	return RoleNone
}

// New builds the resolver selected by configuration.
func New(cfg config.IdentityConfig) (Resolver, error) {
	trusted, err := parseCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	mapper := RoleMapper{DeveloperGroups: cfg.DeveloperGroups, SREGroups: cfg.SREGroups}
	switch cfg.Mode {
	case config.IdentityOpenShift:
		return NewOpenShift(cfg.OpenShift, mapper, trusted)
	case config.IdentityHeader:
		return &headerResolver{cfg: cfg.Header, mapper: mapper, trusted: trusted}, nil
	case config.IdentityDev:
		return &devResolver{id: Identity{User: cfg.Dev.User, Groups: cfg.Dev.Groups, Role: mapper.RoleFor(cfg.Dev.Groups)}}, nil
	}
	return nil, errors.New("unknown identity mode")
}

// headerResolver trusts user and group headers set by a generic
// authenticating proxy (for example oauth2-proxy). Group membership is
// asserted by the proxy, so the proxy must be the only network path.
type headerResolver struct {
	cfg     config.HeaderConfig
	mapper  RoleMapper
	trusted []*net.IPNet
}

func (h *headerResolver) Resolve(r *http.Request) (*Identity, error) {
	user := r.Header.Get(h.cfg.UserHeader)
	if user == "" {
		return nil, ErrUnauthenticated
	}
	if !peerTrusted(r, h.trusted) {
		return nil, ErrUntrustedProxy
	}
	if !ValidUsername(user) {
		return nil, ErrUnauthenticated
	}
	var groups []string
	for _, g := range strings.Split(r.Header.Get(h.cfg.GroupsHeader), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	id := &Identity{User: user, Groups: groups, Role: h.mapper.RoleFor(groups)}
	if id.Role == RoleNone {
		return id, ErrNotAuthorized
	}
	return id, nil
}

// devResolver returns a fixed identity. Only enabled behind an explicit
// environment gate for local development.
type devResolver struct{ id Identity }

func (d *devResolver) Resolve(*http.Request) (*Identity, error) {
	id := d.id
	if id.Role == RoleNone {
		return &id, ErrNotAuthorized
	}
	return &id, nil
}

// ValidUsername rejects empty, oversized or control-character identities.
func ValidUsername(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func peerTrusted(r *http.Request, trusted []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
