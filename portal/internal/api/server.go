// Package api implements the portal's REST API and serves the web UI.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/ratelimit"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/telemetry"
)

// BuildInfo identifies the running build.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// ConnectFunc authenticates a user against a profile. Replaceable in tests.
type ConnectFunc func(ctx context.Context, p *config.Profile, c mongoconn.Credentials, h mongoconn.PoolHooks) (*mongoconn.ConnectResult, error)

// Deps are the server's collaborators.
type Deps struct {
	Config   *config.Config
	Identity identity.Resolver
	Store    *session.Store
	Audit    *audit.Log
	Metrics  *metrics.Metrics
	Logger   *slog.Logger
	CSRFKey  []byte
	Connect  ConnectFunc
	UI       http.Handler
	Build    BuildInfo
}

// Server is the HTTP API.
type Server struct {
	Deps
	limiter  *ratelimit.Limiter
	loginSem chan struct{}
	routes   []Route
	mux      *http.ServeMux
}

// Route describes a registered API route (used by the OpenAPI contract test).
type Route struct {
	Method string
	Path   string
}

type ctxKey int

const reqKey ctxKey = 0

type reqCtx struct {
	requestID string
	id        *identity.Identity
	sess      *session.Session
	secret    string
	span      trace.Span
}

func from(r *http.Request) *reqCtx {
	rc, _ := r.Context().Value(reqKey).(*reqCtx)
	if rc == nil {
		rc = &reqCtx{}
	}
	return rc
}

// New creates the API server.
func New(d Deps) *Server {
	if d.Connect == nil {
		d.Connect = mongoconn.Connect
	}
	if len(d.CSRFKey) < 32 {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		d.CSRFKey = k
	}
	l := d.Config.Login
	s := &Server{
		Deps:     d,
		limiter:  ratelimit.New(l.AttemptsPerWindow, l.Window, l.FailuresBeforeLock, l.LockDuration, l.MaxLockDuration),
		loginSem: make(chan struct{}, l.MaxConcurrent),
		mux:      http.NewServeMux(),
	}
	s.register()
	return s
}

// Routes returns the registered API routes.
func (s *Server) Routes() []Route { return s.routes }

// access levels for routes.
type level int

const (
	levelIdentity level = iota // SSO identity required
	levelSession               // plus MongoDB session
	levelWrite                 // plus portal write role
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, rc *reqCtx)

func (s *Server) handle(method, path string, lvl level, bodyLimit int64, h handlerFunc) {
	s.routes = append(s.routes, Route{Method: method, Path: path})
	pattern := method + " " + path
	s.mux.Handle(pattern, s.instrument(pattern, bodyLimit, s.guard(lvl, h)))
}

func (s *Server) register() {
	const v = "/api/v1"
	small := s.Config.Server.MaxBodyBytes
	docBody := s.Config.Query.MaxDocumentBytes*2 + 4096

	s.handle("GET", v+"/me", levelIdentity, 0, s.handleMe)
	s.handle("GET", v+"/profiles", levelIdentity, 0, s.handleProfiles)
	s.handle("POST", v+"/session", levelIdentity, small, s.handleLogin)
	s.handle("GET", v+"/session", levelSession, 0, s.handleSessionInfo)
	s.handle("DELETE", v+"/session", levelSession, 0, s.handleLogout)
	s.handle("GET", v+"/sessions", levelIdentity, 0, s.handleListSessions)
	s.handle("DELETE", v+"/sessions/{handle}", levelIdentity, 0, s.handleTerminateSession)
	s.handle("GET", v+"/audit", levelIdentity, 0, s.handleAudit)
	s.handle("GET", v+"/server", levelSession, 0, s.handleServerInfo)

	s.handle("GET", v+"/databases", levelSession, 0, s.handleListDatabases)
	s.handle("GET", v+"/databases/{db}/stats", levelSession, 0, s.handleDatabaseStats)
	s.handle("GET", v+"/databases/{db}/collections", levelSession, 0, s.handleListCollections)
	s.handle("POST", v+"/databases/{db}/collections", levelWrite, small, s.handleCreateCollection)
	s.handle("DELETE", v+"/databases/{db}/collections/{coll}", levelWrite, 0, s.handleDropCollection)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/stats", levelSession, 0, s.handleCollectionStats)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/documents", levelSession, 0, s.handleFindDocuments)
	s.handle("POST", v+"/databases/{db}/collections/{coll}/documents", levelWrite, docBody, s.handleInsertDocument)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/documents/{id}", levelSession, 0, s.handleGetDocument)
	s.handle("PUT", v+"/databases/{db}/collections/{coll}/documents/{id}", levelWrite, docBody, s.handleReplaceDocument)
	s.handle("DELETE", v+"/databases/{db}/collections/{coll}/documents/{id}", levelWrite, 0, s.handleDeleteDocument)
	s.handle("POST", v+"/databases/{db}/collections/{coll}/query", levelSession, small, s.handleQuery)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/indexes", levelSession, 0, s.handleListIndexes)
	s.handle("POST", v+"/databases/{db}/collections/{coll}/indexes", levelWrite, small, s.handleCreateIndex)
	s.handle("DELETE", v+"/databases/{db}/collections/{coll}/indexes/{name}", levelWrite, 0, s.handleDropIndex)
	s.handle("POST", v+"/shell", levelSession, docBody, s.handleShell)

	s.routes = append(s.routes, Route{Method: "GET", Path: v + "/openapi.yaml"})
	s.mux.Handle("GET "+v+"/openapi.yaml", s.instrument("GET "+v+"/openapi.yaml", 0, http.HandlerFunc(serveOpenAPI)))

	s.mux.Handle("/api/", s.instrument("api_not_found", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "No such API endpoint")
	})))
	if s.UI != nil {
		// Registered without a method so it does not conflict with the
		// method-less "/api/" catch-all; non-GET requests are rejected here.
		s.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.UI.ServeHTTP(w, r)
		}))
	}
}

// Handler returns the main HTTP handler with global middleware.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.requestID(securityHeaders(s.Config.Server.HSTS, s.mux)))
}

// guard enforces identity, CSRF, session and role requirements.
func (s *Server) guard(lvl level, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := from(r)
		id, err := s.Identity.Resolve(r)
		if err != nil {
			s.identityError(w, r, rc, id, err)
			return
		}
		rc.id = id
		if rc.span != nil {
			rc.span.SetAttributes(attribute.String("portal.role", string(id.Role)))
		}

		unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead
		if unsafe {
			if err := s.checkOrigin(r); err != nil {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "csrf_origin").Inc()
				writeError(w, r, http.StatusForbidden, "csrf_failed", "Cross-site request rejected")
				return
			}
			if r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
				return
			}
		}

		if c, err := r.Cookie(s.Config.Session.CookieName); err == nil {
			rc.secret = c.Value
		}
		if lvl >= levelSession {
			sess, err := s.Store.Get(rc.secret, id.User)
			if err != nil {
				reason := "mongo_session_required"
				if errors.Is(err, session.ErrExpired) {
					reason = "mongo_session_expired"
				}
				if errors.Is(err, session.ErrWrongOwner) {
					s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, SSOUser: id.User, Action: "session_owner_mismatch", Outcome: audit.Denied})
				}
				s.clearCookie(w)
				writeError(w, r, http.StatusUnauthorized, reason, "Sign in to MongoDB to continue")
				return
			}
			rc.sess = sess
			if unsafe && !constantEq(r.Header.Get("X-CSRF-Token"), sess.CSRFToken) {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "csrf_token").Inc()
				writeError(w, r, http.StatusForbidden, "csrf_failed", "Missing or invalid CSRF token")
				return
			}
		} else if unsafe {
			// Identity-level unsafe requests (login, terminate session) use a
			// session token when a session exists, else the pre-login token.
			ok := false
			if sess, err := s.Store.Get(rc.secret, id.User); err == nil {
				ok = constantEq(r.Header.Get("X-CSRF-Token"), sess.CSRFToken)
			}
			if !ok {
				ok = s.validPreauthToken(r.Header.Get("X-CSRF-Token"), id.User)
			}
			if !ok {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "csrf_token").Inc()
				writeError(w, r, http.StatusForbidden, "csrf_failed", "Missing or invalid CSRF token")
				return
			}
		}
		if lvl >= levelWrite && !id.Role.CanWrite() {
			s.Metrics.AuthzDenials.WithLabelValues("portal", "role_read_only").Inc()
			s.auditEvent(r, rc, "write_denied", audit.Denied, "portal role "+string(id.Role)+" is read-only")
			writeError(w, r, http.StatusForbidden, "portal_role_forbidden", "Your portal role is read-only; this operation requires SRE access")
			return
		}
		h(w, r, rc)
	})
}

func (s *Server) identityError(w http.ResponseWriter, r *http.Request, rc *reqCtx, id *identity.Identity, err error) {
	switch {
	case errors.Is(err, identity.ErrNotAuthorized):
		s.Metrics.AuthAttempts.WithLabelValues("sso", "not_in_group").Inc()
		s.Metrics.AuthzDenials.WithLabelValues("portal", "not_in_group").Inc()
		user := ""
		if id != nil {
			user = id.User
		}
		s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, SSOUser: user, Action: "portal_access", Outcome: audit.Denied, Reason: "not in an authorized group"})
		writeJSON(w, http.StatusForbidden, map[string]any{"error": apiError{Code: "portal_access_denied", Message: "Your account is not a member of a group authorized to use this portal", RequestID: rc.requestID}, "user": user})
	case errors.Is(err, identity.ErrUntrustedProxy):
		s.Metrics.AuthAttempts.WithLabelValues("sso", "untrusted_proxy").Inc()
		s.Logger.Warn("identity headers received from untrusted peer", "request_id", rc.requestID)
		writeError(w, r, http.StatusUnauthorized, "sso_required", "Corporate SSO authentication is required")
	case errors.Is(err, identity.ErrUnavailable):
		s.Metrics.AuthAttempts.WithLabelValues("sso", "unavailable").Inc()
		writeError(w, r, http.StatusServiceUnavailable, "identity_unavailable", "Identity verification is temporarily unavailable")
	default:
		s.Metrics.AuthAttempts.WithLabelValues("sso", "unauthenticated").Inc()
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": apiError{Code: "sso_required", Message: "Corporate SSO authentication is required", RequestID: rc.requestID}, "loginURL": s.Config.Identity.SSOLoginURL})
	}
}

// checkOrigin rejects cross-site state-changing requests.
func (s *Server) checkOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return errors.New("cross-site fetch")
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	if s.Config.Server.PublicOrigin != "" {
		if strings.TrimSuffix(s.Config.Server.PublicOrigin, "/") != origin {
			return errors.New("origin mismatch")
		}
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host != requestHost(r) {
		return errors.New("origin mismatch")
	}
	return nil
}

func requestHost(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return r.Host
}

// Pre-login CSRF tokens are HMACs bound to the SSO user and issue time.
func (s *Server) preauthToken(user string, now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	return "p1." + ts + "." + s.sign("login|"+user+"|"+ts)
}

func (s *Server) validPreauthToken(tok, user string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "p1" {
		return false
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(ts, 0))
	if age < -time.Minute || age > 2*time.Hour {
		return false
	}
	return constantEq(parts[2], s.sign("login|"+user+"|"+parts[1]))
}

func (s *Server) sign(msg string) string {
	m := hmac.New(sha256.New, s.CSRFKey)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func constantEq(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Secure is always true except with the gated local development identity
// mode (config validation enforces this).
func (s *Server) setCookie(w http.ResponseWriter, secret string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly and SameSite=Strict set; Secure enforced by config
		Name: s.Config.Session.CookieName, Value: secret, Path: "/",
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expiring cookie; same attributes as setCookie
		Name: s.Config.Session.CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

// statusWriter captures the response status.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// instrument adds per-route body limits, tracing, metrics and access logs.
func (s *Server) instrument(route string, bodyLimit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if bodyLimit <= 0 {
			bodyLimit = 64 << 10
		}
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)

		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := telemetry.Start(ctx, route, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("http.route", route)))
		defer span.End()
		rc := from(r)
		rc.span = span
		r = r.WithContext(ctx)

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		dur := time.Since(start)
		span.SetAttributes(attribute.Int("http.response.status_code", sw.status))
		if sw.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(sw.status))
		}
		s.Metrics.HTTPRequests.WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).Inc()
		s.Metrics.HTTPDuration.WithLabelValues(route, r.Method).Observe(dur.Seconds())

		attrs := []slog.Attr{
			slog.String("request_id", rc.requestID),
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", sw.status),
			slog.Int64("duration_ms", dur.Milliseconds()),
			slog.Int("bytes", sw.bytes),
		}
		if sc := span.SpanContext(); sc.HasTraceID() {
			attrs = append(attrs, slog.String("trace_id", sc.TraceID().String()))
		}
		if rc.id != nil {
			attrs = append(attrs, slog.String("sso_user", rc.id.User))
		}
		s.Logger.LogAttrs(r.Context(), slog.LevelInfo, "http_request", attrs...)
	})
}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !requestIDRe.MatchString(id) {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		rc := &reqCtx{requestID: id}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqKey, rc)))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Logger.Error("panic serving request", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				writeError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func securityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId,omitempty"`
	MongoCode int32  `json:"mongoCode,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": apiError{Code: code, Message: msg, RequestID: from(r).requestID}})
}

// decodeJSON decodes a JSON request body strictly.
func decodeJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "Request body is too large")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "invalid_json", "Request body is not valid JSON for this endpoint")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "Request body must contain a single JSON object")
		return false
	}
	return true
}

func (s *Server) auditEvent(r *http.Request, rc *reqCtx, action, outcome, reason string) {
	e := audit.Event{RequestID: rc.requestID, Action: action, Outcome: outcome, Reason: reason,
		Database: r.PathValue("db"), Collection: r.PathValue("coll")}
	if rc.id != nil {
		e.SSOUser, e.PortalRole = rc.id.User, string(rc.id.Role)
	}
	if rc.sess != nil {
		e.MongoUser, e.Profile = rc.sess.MongoUser+"@"+rc.sess.AuthSource, rc.sess.Profile
	}
	if n := r.PathValue("name"); n != "" {
		e.Target = n
	}
	s.Audit.Record(r.Context(), e)
}

// OpsHandler serves health, readiness and metrics on the ops listener.
func OpsHandler(ready func() bool, metricsHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.Handle("GET /metrics", metricsHandler)
	return mux
}
