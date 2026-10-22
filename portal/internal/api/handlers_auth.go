package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/session"
)

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	_, err := s.Store.Get(rc.secret, rc.id.User)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":         rc.id.User,
		"groups":       rc.id.Groups,
		"role":         rc.id.Role,
		"canWrite":     rc.id.Role.CanWrite(),
		"csrfToken":    s.preauthToken(rc.id.User, time.Now()),
		"hasSession":   err == nil,
		"ssoLogoutURL": s.Config.Identity.SSOLogoutURL,
		"environment":  s.Config.Environment,
		"build":        s.Build,
	})
}

type profileView struct {
	Name              string   `json:"name"`
	DisplayName       string   `json:"displayName"`
	Description       string   `json:"description,omitempty"`
	DefaultAuthSource string   `json:"defaultAuthSource"`
	AuthMechanisms    []string `json:"authMechanisms"`
	TLSMode           string   `json:"tlsMode"`
	ClientCertificate bool     `json:"clientCertificate"`
	PlaintextWarning  bool     `json:"plaintextWarning"`
	ReplicaSet        string   `json:"replicaSet,omitempty"`
}

func viewProfile(p *config.Profile) profileView {
	return profileView{
		Name: p.Name, DisplayName: p.DisplayName, Description: p.Description,
		DefaultAuthSource: p.DefaultAuthSource, AuthMechanisms: p.AuthMechanisms,
		TLSMode: p.TLS.Mode, ClientCertificate: p.TLS.ClientCertFile != "",
		PlaintextWarning: p.TLS.Mode == config.TLSDisabled, ReplicaSet: p.ReplicaSet,
	}
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	out := make([]profileView, 0, len(s.Config.Profiles))
	for i := range s.Config.Profiles {
		out = append(out, viewProfile(&s.Config.Profiles[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

type loginRequest struct {
	Profile    string `json:"profile"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthSource string `json:"authSource"`
	Mechanism  string `json:"mechanism"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, ok := s.Config.Profile(req.Profile)
	if !ok {
		writeError(w, r, http.StatusBadRequest, "unknown_profile", "Unknown connection profile")
		return
	}
	if req.AuthSource == "" {
		req.AuthSource = p.DefaultAuthSource
	}
	cred := mongoconn.Credentials{Username: req.Username, Password: req.Password, AuthSource: req.AuthSource, Mechanism: req.Mechanism}
	req.Password = ""
	if err := cred.Validate(p); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}

	ev := audit.Event{RequestID: rc.requestID, SSOUser: rc.id.User, PortalRole: string(rc.id.Role),
		MongoUser: cred.Username + "@" + cred.AuthSource, Profile: p.Name, Action: "mongodb_login"}
	target := p.Name + "\x00" + cred.AuthSource + "\x00" + cred.Username
	if ok, wait := s.limiter.Allow("sso\x00"+rc.id.User, target); !ok {
		s.Metrics.AuthAttempts.WithLabelValues("mongodb", "rate_limited").Inc()
		ev.Outcome, ev.Reason = audit.Denied, "rate limited"
		s.Audit.Record(r.Context(), ev)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many login attempts; try again later")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.Config.Login.Timeout)
	defer cancel()
	select {
	case s.loginSem <- struct{}{}:
		defer func() { <-s.loginSem }()
	case <-ctx.Done():
		writeError(w, r, http.StatusServiceUnavailable, "busy", "The portal is handling too many logins; try again")
		return
	}

	res, err := s.Connect(ctx, p, cred, mongoconn.PoolHooks{
		Created: func() {
			s.Metrics.MongoConns.Inc()
			s.Metrics.MongoConnEvents.WithLabelValues("created").Inc()
		},
		Closed: func() {
			s.Metrics.MongoConns.Dec()
			s.Metrics.MongoConnEvents.WithLabelValues("closed").Inc()
		},
	})
	cred.Password = ""
	if err != nil {
		me := mongoconn.Classify(err)
		ev.Outcome, ev.Reason = audit.Failure, string(me.Kind)
		s.Audit.Record(r.Context(), ev)
		s.Metrics.AuthAttempts.WithLabelValues("mongodb", string(me.Kind)).Inc()
		s.Logger.Warn("mongodb login failed", "request_id", rc.requestID, "profile", p.Name, "kind", me.Kind, "error", safeErr(me))
		if me.Kind == mongoconn.KindAuthFailed {
			s.limiter.Failure(target)
			writeError(w, r, http.StatusUnauthorized, string(me.Kind), "Authentication failed. Check the username, password and authentication database.")
			return
		}
		writeError(w, r, me.HTTPStatus(), string(me.Kind), me.Msg)
		return
	}
	s.limiter.Success(target)

	sess := &session.Session{
		SSOUser: rc.id.User, PortalRole: rc.id.Role, Profile: p.Name,
		MongoUser: cred.Username, AuthSource: cred.AuthSource, Mechanism: res.Mechanism,
		TLS: res.TLSEnabled, Client: res.Client, Status: res.Status, UserAgent: truncateUA(r.UserAgent()),
	}
	secret, err := s.Store.Create(sess, rc.secret)
	if err != nil {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = res.Client.Disconnect(dctx)
		dcancel()
		ev.Outcome, ev.Reason = audit.Failure, "session capacity"
		s.Audit.Record(r.Context(), ev)
		writeError(w, r, http.StatusServiceUnavailable, "capacity", "The portal has reached its session limit; try again later")
		return
	}
	s.setCookie(w, secret)
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	s.Metrics.AuthAttempts.WithLabelValues("mongodb", "success").Inc()
	ev.Outcome = audit.Success
	s.Audit.Record(r.Context(), ev)
	if !res.TLSEnabled {
		s.Logger.Warn("mongodb session established without TLS", "profile", p.Name, "request_id", rc.requestID)
	}
	rc.sess = sess
	writeJSON(w, http.StatusOK, s.sessionView(sess, rc.id))
}

func truncateUA(ua string) string {
	if len(ua) > 200 {
		return ua[:200]
	}
	return ua
}

func safeErr(e *mongoconn.Error) string {
	if e.Err == nil {
		return e.Msg
	}
	s := e.Err.Error()
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

func (s *Server) sessionView(sess *session.Session, id *identity.Identity) map[string]any {
	idle := s.Config.Session.IdleTimeout
	var roles any = []any{}
	if sess.Status != nil {
		roles = sess.Status.AuthInfo.AuthenticatedRoles
	}
	view := map[string]any{
		"handle":             sess.Handle,
		"profile":            sess.Profile,
		"mongoUser":          sess.MongoUser,
		"authSource":         sess.AuthSource,
		"mechanism":          sess.Mechanism,
		"tls":                sess.TLS,
		"portalRole":         id.Role,
		"canWrite":           id.Role.CanWrite(),
		"mongoRoles":         roles,
		"createdAt":          sess.CreatedAt.UTC(),
		"expiresAt":          sess.ExpiresAt.UTC(),
		"idleExpiresAt":      sess.IdleExpiry(idle).UTC(),
		"idleTimeoutSeconds": int(idle.Seconds()),
		"csrfToken":          sess.CSRFToken,
	}
	if p, ok := s.Config.Profile(sess.Profile); ok {
		view["profileInfo"] = viewProfile(p)
	}
	return view
}

func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	writeJSON(w, http.StatusOK, s.sessionView(rc.sess, rc.id))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.Store.Delete(rc.secret, "logout")
	s.clearCookie(w)
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	s.auditEvent(r, rc, "mongodb_logout", audit.Success, "")
	writeJSON(w, http.StatusOK, map[string]any{"loggedOut": true, "ssoLogoutURL": s.Config.Identity.SSOLogoutURL})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	current := ""
	if sess, err := s.Store.Get(rc.secret, rc.id.User); err == nil {
		current = sess.Handle
	}
	list := s.Store.ListByUser(rc.id.User)
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, map[string]any{
			"handle": x.Handle, "profile": x.Profile, "mongoUser": x.MongoUser, "authSource": x.AuthSource,
			"createdAt": x.CreatedAt.UTC(), "lastSeen": x.LastSeen().UTC(), "expiresAt": x.ExpiresAt.UTC(),
			"userAgent": x.UserAgent, "current": x.Handle == current, "tls": x.TLS,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out, "note": "Sessions are held by the portal instance serving this request."})
}

func (s *Server) handleTerminateSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	h := r.PathValue("handle")
	if !s.Store.DeleteByHandle(rc.id.User, h, "terminated") {
		writeError(w, r, http.StatusNotFound, "not_found", "Session not found")
		return
	}
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, SSOUser: rc.id.User, PortalRole: string(rc.id.Role), Action: "session_terminate", Outcome: audit.Success})
	writeJSON(w, http.StatusOK, map[string]any{"terminated": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	scope := rc.id.User
	if rc.id.Role == identity.RoleSRE && r.URL.Query().Get("scope") == "all" {
		scope = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": s.Audit.Recent(scope, limit),
		"scope":  map[bool]string{true: "all", false: "self"}[scope == ""],
		"note":   "Recent events recorded by this portal instance. The durable audit trail is the structured log stream.",
	})
}

// onSessionClosed is wired into the session store.
func (s *Server) OnSessionClosed(sess *session.Session, reason string) {
	s.Metrics.SessionsClosed.WithLabelValues(reason).Inc()
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	if reason != "logout" {
		s.Audit.Record(context.Background(), audit.Event{SSOUser: sess.SSOUser, MongoUser: sess.MongoUser + "@" + sess.AuthSource, Profile: sess.Profile, Action: "session_closed", Outcome: audit.Success, Reason: reason})
	}
}
