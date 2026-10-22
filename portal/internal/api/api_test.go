package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.yaml.in/yaml/v3"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/session"
)

const testConfig = `
environment: test
identity:
  mode: header
  developerGroups: [devs]
  sreGroups: [sres]
login:
  attemptsPerWindow: 100
  failuresBeforeLock: 3
profiles:
  - name: primary
    uri: mongodb://127.0.0.1:1/
    tls:
      mode: disabled
`

type harness struct {
	t       *testing.T
	srv     *Server
	h       http.Handler
	store   *session.Store
	connect ConnectFunc
	calls   int
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	res, err := identity.New(cfg.Identity)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(session.Options{IdleTimeout: cfg.Session.IdleTimeout, AbsoluteTimeout: cfg.Session.AbsoluteTimeout, MaxPerUser: 3, MaxTotal: 100})
	t.Cleanup(store.Close)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := &harness{t: t, store: store}
	h.srv = New(Deps{
		Config: cfg, Identity: res, Store: store, Audit: audit.New(logger, 100),
		Metrics: metrics.New(), Logger: logger,
		Connect: func(ctx context.Context, p *config.Profile, c mongoconn.Credentials, hk mongoconn.PoolHooks) (*mongoconn.ConnectResult, error) {
			h.calls++
			if c.Password != "good" {
				return nil, &mongoconn.Error{Kind: mongoconn.KindAuthFailed, Msg: "Authentication failed"}
			}
			// A lazily connecting client: no network I/O until used.
			client, err := mongo.Connect(options.Client().ApplyURI(p.URI))
			if err != nil {
				return nil, err
			}
			st := &mongoconn.ConnectionStatus{}
			st.AuthInfo.AuthenticatedUsers = []mongoconn.UserRef{{User: c.Username, DB: c.AuthSource}}
			return &mongoconn.ConnectResult{Client: client, Status: st, Mechanism: "SCRAM-SHA-256"}, nil
		},
	})
	h.h = h.srv.Handler()
	return h
}

type reqOpt func(*http.Request)

func as(user, groups string) reqOpt {
	return func(r *http.Request) {
		r.Header.Set("X-Forwarded-User", user)
		r.Header.Set("X-Forwarded-Groups", groups)
	}
}
func withCookie(c *http.Cookie) reqOpt { return func(r *http.Request) { r.AddCookie(c) } }
func withHeader(k, v string) reqOpt    { return func(r *http.Request) { r.Header.Set(k, v) } }
func fromPeer(addr string) reqOpt      { return func(r *http.Request) { r.RemoteAddr = addr } }

func (h *harness) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			buf, _ := json.Marshal(b)
			rd = bytes.NewReader(buf)
		}
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "127.0.0.1:50000"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := decode(t, w)
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (h *harness) preauth(user, groups string) string {
	w := h.do("GET", "/api/v1/me", nil, as(user, groups))
	if w.Code != 200 {
		h.t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	return decode(h.t, w)["csrfToken"].(string)
}

// login performs a successful MongoDB login and returns the session cookie
// and session CSRF token.
func (h *harness) login(user, groups string) (*http.Cookie, string) {
	h.t.Helper()
	tok := h.preauth(user, groups)
	w := h.do("POST", "/api/v1/session", map[string]string{"profile": "primary", "username": "u-" + user, "password": "good"},
		as(user, groups), withHeader("X-CSRF-Token", tok))
	if w.Code != 200 {
		h.t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-mongo_portal_session" {
			cookie = c
		}
	}
	if cookie == nil {
		h.t.Fatal("no session cookie")
	}
	return cookie, decode(h.t, w)["csrfToken"].(string)
}

func TestSSOStage(t *testing.T) {
	h := newHarness(t, nil)
	if w := h.do("GET", "/api/v1/me", nil); w.Code != 401 || errCode(t, w) != "sso_required" {
		t.Fatalf("no identity: %d %s", w.Code, w.Body)
	}
	// Identity headers from a peer other than the proxy are ignored.
	if w := h.do("GET", "/api/v1/me", nil, as("alice", "sres"), fromPeer("10.9.9.9:1234")); w.Code != 401 {
		t.Fatalf("spoofed headers: %d", w.Code)
	}
	if w := h.do("GET", "/api/v1/me", nil, as("eve", "other")); w.Code != 403 || errCode(t, w) != "portal_access_denied" {
		t.Fatalf("unauthorized group: %d %s", w.Code, w.Body)
	}
	w := h.do("GET", "/api/v1/me", nil, as("dana", "devs"))
	m := decode(t, w)
	if w.Code != 200 || m["role"] != "developer" || m["canWrite"] != false || m["csrfToken"] == "" {
		t.Fatalf("developer me: %d %v", w.Code, m)
	}
	if w := h.do("GET", "/api/v1/me", nil, as("sam", "devs,sres")); decode(t, w)["role"] != "sre" {
		t.Fatal("sre role")
	}
}

func TestProfilesHideHosts(t *testing.T) {
	h := newHarness(t, nil)
	w := h.do("GET", "/api/v1/profiles", nil, as("dana", "devs"))
	if w.Code != 200 || strings.Contains(w.Body.String(), "127.0.0.1") {
		t.Fatalf("profiles must not disclose hosts: %s", w.Body)
	}
	if !strings.Contains(w.Body.String(), `"plaintextWarning":true`) {
		t.Fatal("plaintext warning missing")
	}
}

func TestLoginCSRFAndOrigin(t *testing.T) {
	h := newHarness(t, nil)
	body := map[string]string{"profile": "primary", "username": "u", "password": "good"}
	if w := h.do("POST", "/api/v1/session", body, as("dana", "devs")); w.Code != 403 || errCode(t, w) != "csrf_failed" {
		t.Fatalf("missing csrf: %d", w.Code)
	}
	if w := h.do("POST", "/api/v1/session", body, as("dana", "devs"), withHeader("X-CSRF-Token", "p1.1.forged")); w.Code != 403 {
		t.Fatalf("forged csrf: %d", w.Code)
	}
	// A pre-auth token issued to another user is not accepted.
	other := h.preauth("sam", "sres")
	if w := h.do("POST", "/api/v1/session", body, as("dana", "devs"), withHeader("X-CSRF-Token", other)); w.Code != 403 {
		t.Fatalf("token of other user: %d", w.Code)
	}
	tok := h.preauth("dana", "devs")
	if w := h.do("POST", "/api/v1/session", body, as("dana", "devs"), withHeader("X-CSRF-Token", tok), withHeader("Origin", "https://evil.example")); w.Code != 403 {
		t.Fatalf("cross origin: %d", w.Code)
	}
	if w := h.do("POST", "/api/v1/session", body, as("dana", "devs"), withHeader("X-CSRF-Token", tok), withHeader("Sec-Fetch-Site", "cross-site")); w.Code != 403 {
		t.Fatalf("cross site: %d", w.Code)
	}
	if h.calls != 0 {
		t.Fatal("MongoDB must not be contacted when CSRF checks fail")
	}
	w := h.do("POST", "/api/v1/session", `profile=primary`, as("dana", "devs"), withHeader("X-CSRF-Token", tok), withHeader("Content-Type", "application/x-www-form-urlencoded"))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", w.Code)
	}
}

func TestLoginFailureAndLockout(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.preauth("dana", "devs")
	bad := map[string]string{"profile": "primary", "username": "u", "password": "wrong"}
	for i := 0; i < 3; i++ {
		w := h.do("POST", "/api/v1/session", bad, as("dana", "devs"), withHeader("X-CSRF-Token", tok))
		if w.Code != 401 || errCode(t, w) != "mongo_auth_failed" || len(w.Result().Cookies()) != 0 {
			t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body)
		}
	}
	w := h.do("POST", "/api/v1/session", bad, as("dana", "devs"), withHeader("X-CSRF-Token", tok))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("lockout: %d", w.Code)
	}
	if h.calls != 3 {
		t.Fatalf("locked account must not reach MongoDB, calls=%d", h.calls)
	}
	// Unknown profile (SSRF attempt with an arbitrary host is impossible: only names are accepted).
	w = h.do("POST", "/api/v1/session", map[string]string{"profile": "mongodb://attacker:27017", "username": "u", "password": "good"}, as("dana", "devs"), withHeader("X-CSRF-Token", tok))
	if w.Code != 400 || errCode(t, w) != "unknown_profile" {
		t.Fatalf("unknown profile: %d", w.Code)
	}
	// Unknown JSON fields (e.g. smuggling a URI) are rejected.
	w = h.do("POST", "/api/v1/session", map[string]string{"profile": "primary", "username": "u", "password": "good", "uri": "mongodb://x"}, as("dana", "devs"), withHeader("X-CSRF-Token", tok))
	if w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
}

func TestLoginSessionCookieAndLogout(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.login("dana", "devs")
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("insecure cookie: %+v", cookie)
	}
	w := h.do("GET", "/api/v1/session", nil, as("dana", "devs"), withCookie(cookie))
	if w.Code != 200 || decode(t, w)["mongoUser"] != "u-dana" {
		t.Fatalf("session: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "good") {
		t.Fatal("password must never be returned")
	}
	// Logout requires the session CSRF token.
	if w := h.do("DELETE", "/api/v1/session", nil, as("dana", "devs"), withCookie(cookie)); w.Code != 403 {
		t.Fatalf("logout without csrf: %d", w.Code)
	}
	if w := h.do("DELETE", "/api/v1/session", nil, as("dana", "devs"), withCookie(cookie), withHeader("X-CSRF-Token", csrf)); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := h.do("GET", "/api/v1/session", nil, as("dana", "devs"), withCookie(cookie)); w.Code != 401 || errCode(t, w) != "mongo_session_required" {
		t.Fatalf("after logout: %d", w.Code)
	}
}

func TestSessionRotationOnLogin(t *testing.T) {
	h := newHarness(t, nil)
	first, _ := h.login("dana", "devs")
	tok := h.preauth("dana", "devs")
	w := h.do("POST", "/api/v1/session", map[string]string{"profile": "primary", "username": "u2", "password": "good"},
		as("dana", "devs"), withCookie(first), withHeader("X-CSRF-Token", tok))
	if w.Code != 200 {
		t.Fatalf("relogin: %d", w.Code)
	}
	var second *http.Cookie
	for _, c := range w.Result().Cookies() {
		second = c
	}
	if second == nil || second.Value == first.Value {
		t.Fatal("session id must rotate on login")
	}
	if w := h.do("GET", "/api/v1/session", nil, as("dana", "devs"), withCookie(first)); w.Code != 401 {
		t.Fatal("old session must be invalidated (fixation protection)")
	}
}

func TestCrossUserCookieRejected(t *testing.T) {
	h := newHarness(t, nil)
	cookie, _ := h.login("dana", "devs")
	if w := h.do("GET", "/api/v1/session", nil, as("sam", "sres"), withCookie(cookie)); w.Code != 401 {
		t.Fatalf("other SSO user with stolen cookie: %d", w.Code)
	}
	if w := h.do("GET", "/api/v1/session", nil, as("dana", "devs"), withCookie(cookie)); w.Code != 401 {
		t.Fatal("leaked session must be destroyed")
	}
}

func TestDeveloperCannotWriteViaDirectAPI(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.login("dana", "devs")
	doc := map[string]string{"document": `{"a":1}`}
	id := base64.RawURLEncoding.EncodeToString([]byte(`{"_id":{"$numberInt":"1"}}`))
	cases := []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/databases/app/collections", map[string]string{"name": "x"}},
		{"DELETE", "/api/v1/databases/app/collections/orders", nil},
		{"POST", "/api/v1/databases/app/collections/orders/documents", doc},
		{"PUT", "/api/v1/databases/app/collections/orders/documents/" + id, doc},
		{"DELETE", "/api/v1/databases/app/collections/orders/documents/" + id, nil},
		{"POST", "/api/v1/databases/app/collections/orders/indexes", map[string]string{"keys": `{"a":1}`}},
		{"DELETE", "/api/v1/databases/app/collections/orders/indexes/a_1", nil},
	}
	for _, c := range cases {
		w := h.do(c.method, c.path, c.body, as("dana", "devs"), withCookie(cookie), withHeader("X-CSRF-Token", csrf), withHeader("X-Confirm", "orders"))
		if w.Code != 403 || errCode(t, w) != "portal_role_forbidden" {
			t.Errorf("%s %s: got %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
	// Write-capable aggregation stages are rejected for developers.
	for _, p := range []string{`[{"$out":"copy"}]`, `[{"$match":{}},{"$merge":{"into":"x"}}]`, `[{"$lookup":{"from":"o","pipeline":[{"$out":"x"}],"as":"y"}}]`} {
		w := h.do("POST", "/api/v1/databases/app/collections/orders/query", map[string]any{"operation": "aggregate", "pipeline": p},
			as("dana", "devs"), withCookie(cookie), withHeader("X-CSRF-Token", csrf))
		if w.Code != 400 || errCode(t, w) != "invalid_query" {
			t.Errorf("pipeline %s: %d %s", p, w.Code, w.Body)
		}
	}
	// Server-side JavaScript is rejected.
	w := h.do("POST", "/api/v1/databases/app/collections/orders/query", map[string]any{"operation": "find", "filter": `{"$where":"sleep(100)"}`},
		as("dana", "devs"), withCookie(cookie), withHeader("X-CSRF-Token", csrf))
	if w.Code != 400 {
		t.Errorf("$where: %d", w.Code)
	}
	w = h.do("GET", `/api/v1/databases/app/collections/orders/documents?filter=%7B%22%24where%22%3A%221%22%7D`, nil, as("dana", "devs"), withCookie(cookie))
	if w.Code != 400 {
		t.Errorf("$where via GET: %d", w.Code)
	}
}

func TestSREWriteNeedsCSRFAndConfirmation(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.login("sam", "sres")
	if w := h.do("DELETE", "/api/v1/databases/app/collections/orders", nil, as("sam", "sres"), withCookie(cookie)); w.Code != 403 || errCode(t, w) != "csrf_failed" {
		t.Fatalf("no csrf: %d", w.Code)
	}
	for _, c := range []struct{ path, confirm string }{
		{"/api/v1/databases/app/collections/orders", ""},
		{"/api/v1/databases/app/collections/orders", "other"},
		{"/api/v1/databases/app/collections/orders/indexes/a_1", "orders"},
	} {
		w := h.do("DELETE", c.path, nil, as("sam", "sres"), withCookie(cookie), withHeader("X-CSRF-Token", csrf), withHeader("X-Confirm", c.confirm))
		if w.Code != http.StatusPreconditionRequired {
			t.Errorf("%s confirm=%q: %d", c.path, c.confirm, w.Code)
		}
	}
	if w := h.do("DELETE", "/api/v1/databases/app/collections/orders/indexes/_id_", nil, as("sam", "sres"), withCookie(cookie), withHeader("X-CSRF-Token", csrf), withHeader("X-Confirm", "_id_")); w.Code != 400 {
		t.Errorf("drop _id_: %d", w.Code)
	}
	if w := h.do("DELETE", "/api/v1/databases/admin/collections/system.users", nil, as("sam", "sres"), withCookie(cookie), withHeader("X-CSRF-Token", csrf), withHeader("X-Confirm", "system.users")); w.Code != 403 {
		t.Errorf("drop system collection: %d", w.Code)
	}
}

func TestSessionExpiry(t *testing.T) {
	h := newHarness(t, nil)
	h.store = session.NewStore(session.Options{IdleTimeout: 50 * time.Millisecond, AbsoluteTimeout: time.Hour})
	t.Cleanup(h.store.Close)
	h.srv.Store = h.store
	cookie, _ := h.login("dana", "devs")
	time.Sleep(80 * time.Millisecond)
	w := h.do("GET", "/api/v1/session", nil, as("dana", "devs"), withCookie(cookie))
	if w.Code != 401 || errCode(t, w) != "mongo_session_expired" {
		t.Fatalf("expired: %d %s", w.Code, w.Body)
	}
}

func TestBackendRestartRequiresReauthentication(t *testing.T) {
	h := newHarness(t, nil)
	cookie, _ := h.login("dana", "devs")
	// A new process (or another replica) has an empty store.
	h2 := newHarness(t, nil)
	if w := h2.do("GET", "/api/v1/databases", nil, as("dana", "devs"), withCookie(cookie)); w.Code != 401 || errCode(t, w) != "mongo_session_required" {
		t.Fatalf("restart: %d %s", w.Code, w.Body)
	}
}

func TestSecurityHeadersAndBodyLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.MaxBodyBytes = 256 })
	w := h.do("GET", "/api/v1/me", nil, as("dana", "devs"))
	for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "X-Request-Id"} {
		if w.Header().Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("API responses must not be cached")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Error("CSP")
	}
	tok := h.preauth("dana", "devs")
	big := map[string]string{"profile": "primary", "username": strings.Repeat("u", 1000), "password": "good"}
	if w := h.do("POST", "/api/v1/session", big, as("dana", "devs"), withHeader("X-CSRF-Token", tok)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit: %d", w.Code)
	}
}

func TestDecodeIDRejectsOperators(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	if v, err := decodeID(enc(`{"_id":{"$oid":"507f1f77bcf86cd799439011"}}`)); err != nil || v == nil {
		t.Fatalf("valid oid: %v", err)
	}
	for _, bad := range []string{`{"_id":{"$gt":""}}`, `{"_id":{"a":{"$ne":1}}}`, `{"x":1}`, `{"_id":1,"y":2}`, `not json`} {
		if _, err := decodeID(enc(bad)); err == nil {
			t.Errorf("%s should be rejected", bad)
		}
	}
	if _, err := decodeID("%%%"); err == nil {
		t.Error("bad base64")
	}
}

// TestServerWithUI builds the server exactly as main does (with the UI
// handler) to catch route registration conflicts.
func TestServerWithUI(t *testing.T) {
	h := newHarness(t, func(*config.Config) {})
	h.srv = New(Deps{Config: h.srv.Config, Identity: h.srv.Identity, Store: h.store, Audit: h.srv.Audit,
		Metrics: metrics.New(), Logger: h.srv.Logger, UI: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ui")
		})})
	h.h = h.srv.Handler()
	if w := h.do("GET", "/db/app/orders", nil); w.Code != 200 || w.Body.String() != "ui" {
		t.Fatalf("ui route: %d %q", w.Code, w.Body)
	}
	if w := h.do("POST", "/", "x"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to UI: %d", w.Code)
	}
	if w := h.do("GET", "/api/v1/nope", nil, as("dana", "devs")); w.Code != 404 || errCode(t, w) != "not_found" {
		t.Fatalf("api 404 with UI: %d", w.Code)
	}
	if w := h.do("GET", "/api/v1/me", nil, as("dana", "devs")); w.Code != 200 {
		t.Fatalf("api with UI: %d", w.Code)
	}
}

func TestUnknownAPIRouteIsJSON404(t *testing.T) {
	h := newHarness(t, nil)
	w := h.do("GET", "/api/v1/nope", nil, as("dana", "devs"))
	if w.Code != 404 || errCode(t, w) != "not_found" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// TestOpenAPIContract checks that every registered route is documented in
// openapi.yaml and every documented operation is implemented.
func TestOpenAPIContract(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPISpec(), &spec); err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for p, ops := range spec.Paths {
		for m := range ops {
			if slices.Contains([]string{"get", "post", "put", "delete", "patch"}, m) {
				documented[strings.ToUpper(m)+" /api/v1"+p] = true
			}
		}
	}
	h := newHarness(t, nil)
	implemented := map[string]bool{}
	for _, r := range h.srv.Routes() {
		implemented[r.Method+" "+r.Path] = true
	}
	for k := range implemented {
		if !documented[k] {
			t.Errorf("route %s is not documented in openapi.yaml", k)
		}
	}
	for k := range documented {
		if !implemented[k] {
			t.Errorf("documented operation %s is not implemented", k)
		}
	}
}

func TestMongoErrorKinds(t *testing.T) {
	e := mongoconn.Classify(errors.New("server selection error: context deadline exceeded"))
	if e.HTTPStatus() != 503 && e.HTTPStatus() != 504 {
		t.Fatalf("unavailable: %d", e.HTTPStatus())
	}
}
