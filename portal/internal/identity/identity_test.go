package identity

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
)

var mapper = RoleMapper{DeveloperGroups: []string{"devs"}, SREGroups: []string{"sres"}}

func loopback() []*net.IPNet {
	n, _ := parseCIDRs([]string{"127.0.0.1/32"})
	return n
}

func TestRoleFor(t *testing.T) {
	cases := map[string]struct {
		groups []string
		want   Role
	}{
		"none":      {nil, RoleNone},
		"other":     {[]string{"x"}, RoleNone},
		"developer": {[]string{"x", "devs"}, RoleDeveloper},
		"sre wins":  {[]string{"devs", "sres"}, RoleSRE},
	}
	for name, tc := range cases {
		if got := mapper.RoleFor(tc.groups); got != tc.want {
			t.Errorf("%s: got %q want %q", name, got, tc.want)
		}
	}
}

func TestHeaderResolver(t *testing.T) {
	h := &headerResolver{cfg: config.HeaderConfig{UserHeader: "X-User", GroupsHeader: "X-Groups"}, mapper: mapper, trusted: loopback()}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	if _, err := h.Resolve(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing header: %v", err)
	}

	r.Header.Set("X-User", "alice")
	r.Header.Set("X-Groups", "other, devs")
	id, err := h.Resolve(r)
	if err != nil || id.Role != RoleDeveloper {
		t.Fatalf("developer: %v %+v", err, id)
	}

	r.Header.Set("X-Groups", "other")
	if _, err := h.Resolve(r); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("unauthorized group: %v", err)
	}

	// Spoofed headers from a non-proxy peer are rejected.
	r.Header.Set("X-Groups", "sres")
	r.RemoteAddr = "10.1.2.3:5000"
	if _, err := h.Resolve(r); !errors.Is(err, ErrUntrustedProxy) {
		t.Fatalf("untrusted peer: %v", err)
	}

	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-User", "bad\nuser")
	if _, err := h.Resolve(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("control char user: %v", err)
	}
}

// fakeOpenShift serves users/~ and groups endpoints.
func fakeOpenShift(t *testing.T, groupCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/apis/user.openshift.io/v1/users/~":
			users := map[string]string{"Bearer tok-alice": "alice", "Bearer tok-bob": "bob", "Bearer tok-eve": "eve"}
			u, ok := users[auth]
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"name": u}})
		case strings.HasPrefix(r.URL.Path, "/apis/user.openshift.io/v1/groups/"):
			if auth != "Bearer sa-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			groupCalls.Add(1)
			members := map[string][]string{"devs": {"alice"}, "sres": {"bob"}}
			name := strings.TrimPrefix(r.URL.Path, "/apis/user.openshift.io/v1/groups/")
			m, ok := members[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"users": m})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newTestOpenShift(t *testing.T, srv *httptest.Server) *OpenShift {
	t.Helper()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.OpenShiftConfig{
		APIURL: srv.URL, ServiceAccountFile: tokFile,
		UserHeader: "X-Forwarded-User", TokenHeader: "X-Forwarded-Access-Token",
		TokenCacheTTL: time.Minute, GroupCacheTTL: time.Minute, GroupMaxStale: 5 * time.Minute,
		RequestTimeout: 2 * time.Second,
	}
	o, err := NewOpenShift(cfg, RoleMapper{DeveloperGroups: []string{"devs", "missing"}, SREGroups: []string{"sres"}}, loopback())
	if err != nil {
		t.Fatal(err)
	}
	o.client = srv.Client()
	return o
}

func osReq(user, token string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	if user != "" {
		r.Header.Set("X-Forwarded-User", user)
	}
	if token != "" {
		r.Header.Set("X-Forwarded-Access-Token", token)
	}
	return r
}

func TestOpenShiftResolver(t *testing.T) {
	var calls atomic.Int32
	srv := fakeOpenShift(t, &calls)
	defer srv.Close()
	o := newTestOpenShift(t, srv)

	id, err := o.Resolve(osReq("alice", "tok-alice"))
	if err != nil || id.Role != RoleDeveloper {
		t.Fatalf("alice: %v %+v", err, id)
	}
	id, err = o.Resolve(osReq("bob", "tok-bob"))
	if err != nil || id.Role != RoleSRE {
		t.Fatalf("bob: %v %+v", err, id)
	}
	// Authenticated but not in any portal group.
	if _, err := o.Resolve(osReq("eve", "tok-eve")); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("eve: %v", err)
	}
	// Header claims bob but token belongs to alice: spoofing attempt.
	if _, err := o.Resolve(osReq("bob", "tok-alice")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("spoof: %v", err)
	}
	// Invalid token.
	if _, err := o.Resolve(osReq("alice", "bogus")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("invalid token: %v", err)
	}
	// Missing token.
	if _, err := o.Resolve(osReq("alice", "")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing token: %v", err)
	}
	// Untrusted peer.
	r := osReq("bob", "tok-bob")
	r.RemoteAddr = "10.0.0.9:1234"
	if _, err := o.Resolve(r); !errors.Is(err, ErrUntrustedProxy) {
		t.Fatalf("untrusted: %v", err)
	}
	// Groups are cached: 3 configured groups fetched once.
	if got := calls.Load(); got != 3 {
		t.Fatalf("group fetches = %d, want 3 (cached)", got)
	}
}

func TestOpenShiftFailsClosedWhenAPIUnavailable(t *testing.T) {
	var calls atomic.Int32
	srv := fakeOpenShift(t, &calls)
	o := newTestOpenShift(t, srv)
	srv.Close()
	if _, err := o.Resolve(osReq("alice", "tok-alice")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestOpenShiftStaleGroupsUsedWithinMaxStale(t *testing.T) {
	var calls atomic.Int32
	srv := fakeOpenShift(t, &calls)
	o := newTestOpenShift(t, srv)
	// Keep validated tokens cached for the whole test so only the group
	// cache behaviour is exercised once the API goes away.
	o.cfg.TokenCacheTTL = time.Hour
	now := time.Now()
	o.now = func() time.Time { return now }
	if _, err := o.Resolve(osReq("bob", "tok-bob")); err != nil {
		t.Fatal(err)
	}
	srv.Close()

	now = now.Add(2 * time.Minute) // beyond GroupCacheTTL, within GroupMaxStale
	if id, err := o.Resolve(osReq("bob", "tok-bob")); err != nil || id.Role != RoleSRE {
		t.Fatalf("stale groups should be used: %v", err)
	}
	now = now.Add(10 * time.Minute) // beyond GroupMaxStale
	if _, err := o.Resolve(osReq("bob", "tok-bob")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected fail closed after max stale, got %v", err)
	}
}
