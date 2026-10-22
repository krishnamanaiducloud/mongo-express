// Package config loads and validates the portal configuration.
//
// Configuration comes from a YAML file (normally a mounted ConfigMap) with a
// small number of environment variable overrides. Secrets are never placed in
// the YAML file; they are referenced by file path (mounted Kubernetes Secrets).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Identity modes.
const (
	IdentityOpenShift = "openshift"
	IdentityHeader    = "header"
	IdentityDev       = "dev"
)

// TLS modes for MongoDB connection profiles. There is intentionally no
// default: every profile must state its transport security explicitly.
const (
	TLSEnabled  = "enabled"
	TLSDisabled = "disabled"
)

// DevIdentityGateEnv must be set to "true" before the insecure development
// identity mode is accepted. This prevents accidental use in a cluster.
const DevIdentityGateEnv = "PORTAL_ALLOW_INSECURE_DEV_IDENTITY"

type Config struct {
	// Environment is a free-form label (dev, test, prod). The value
	// "production" or "prod" enables stricter startup checks.
	Environment string         `yaml:"environment"`
	Server      ServerConfig   `yaml:"server"`
	Identity    IdentityConfig `yaml:"identity"`
	Session     SessionConfig  `yaml:"session"`
	Query       QueryConfig    `yaml:"query"`
	Login       LoginConfig    `yaml:"login"`
	Audit       AuditConfig    `yaml:"audit"`
	Profiles    []Profile      `yaml:"profiles"`
}

type ServerConfig struct {
	// ListenAddress serves the UI and API. In OpenShift it must be a loopback
	// address so only the OAuth proxy sidecar can reach it.
	ListenAddress string `yaml:"listenAddress"`
	// OpsListenAddress serves /healthz, /readyz and /metrics only.
	OpsListenAddress string `yaml:"opsListenAddress"`
	// PublicOrigin is the externally visible origin (https://host). When set,
	// unsafe requests must carry a matching Origin header.
	PublicOrigin    string        `yaml:"publicOrigin"`
	MaxBodyBytes    int64         `yaml:"maxBodyBytes"`
	ReadTimeout     time.Duration `yaml:"readTimeout"`
	WriteTimeout    time.Duration `yaml:"writeTimeout"`
	ShutdownDelay   time.Duration `yaml:"shutdownDelay"`
	ShutdownTimeout time.Duration `yaml:"shutdownTimeout"`
	HSTS            bool          `yaml:"hsts"`
}

type IdentityConfig struct {
	Mode string `yaml:"mode"`
	// DeveloperGroups and SREGroups are OpenShift (or IdP) group names.
	DeveloperGroups []string `yaml:"developerGroups"`
	SREGroups       []string `yaml:"sreGroups"`
	// TrustedProxyCIDRs lists the source networks allowed to supply identity
	// headers. Defaults to loopback only.
	TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`
	// SSOLogoutURL, if set, is offered in the UI to end the SSO session.
	SSOLogoutURL string          `yaml:"ssoLogoutURL"`
	SSOLoginURL  string          `yaml:"ssoLoginURL"`
	OpenShift    OpenShiftConfig `yaml:"openshift"`
	Header       HeaderConfig    `yaml:"header"`
	Dev          DevConfig       `yaml:"dev"`
}

type OpenShiftConfig struct {
	APIURL             string        `yaml:"apiURL"`
	CAFile             string        `yaml:"caFile"`
	ServiceAccountFile string        `yaml:"serviceAccountTokenFile"`
	UserHeader         string        `yaml:"userHeader"`
	TokenHeader        string        `yaml:"tokenHeader"`
	TokenCacheTTL      time.Duration `yaml:"tokenCacheTTL"`
	GroupCacheTTL      time.Duration `yaml:"groupCacheTTL"`
	GroupMaxStale      time.Duration `yaml:"groupMaxStale"`
	RequestTimeout     time.Duration `yaml:"requestTimeout"`
}

type HeaderConfig struct {
	UserHeader   string `yaml:"userHeader"`
	GroupsHeader string `yaml:"groupsHeader"`
}

type DevConfig struct {
	User   string   `yaml:"user"`
	Groups []string `yaml:"groups"`
}

type SessionConfig struct {
	CookieName      string        `yaml:"cookieName"`
	SecureCookie    *bool         `yaml:"secureCookie"`
	IdleTimeout     time.Duration `yaml:"idleTimeout"`
	AbsoluteTimeout time.Duration `yaml:"absoluteTimeout"`
	MaxPerUser      int           `yaml:"maxPerUser"`
	MaxTotal        int           `yaml:"maxTotal"`
	// KeyFile holds the HMAC key (>= 32 bytes) used for pre-login CSRF
	// tokens. It must be identical on all replicas. If unset, a random key is
	// generated at startup (acceptable for a single replica only).
	KeyFile string `yaml:"keyFile"`
}

type QueryConfig struct {
	DefaultLimit           int64         `yaml:"defaultLimit"`
	MaxLimit               int64         `yaml:"maxLimit"`
	MaxSkip                int64         `yaml:"maxSkip"`
	DefaultMaxTime         time.Duration `yaml:"defaultMaxTime"`
	MaxMaxTime             time.Duration `yaml:"maxMaxTime"`
	MaxResponseBytes       int           `yaml:"maxResponseBytes"`
	MaxDocumentBytes       int64         `yaml:"maxDocumentBytes"`
	MaxCount               int64         `yaml:"maxCount"`
	AllowWriteStagesForSRE bool          `yaml:"allowWriteStagesForSRE"`
}

type LoginConfig struct {
	// Per SSO identity: at most AttemptsPerWindow login attempts per Window.
	AttemptsPerWindow int           `yaml:"attemptsPerWindow"`
	Window            time.Duration `yaml:"window"`
	// Per (profile, MongoDB user): lock after FailuresBeforeLock failures.
	FailuresBeforeLock int           `yaml:"failuresBeforeLock"`
	LockDuration       time.Duration `yaml:"lockDuration"`
	MaxLockDuration    time.Duration `yaml:"maxLockDuration"`
	MaxConcurrent      int           `yaml:"maxConcurrent"`
	Timeout            time.Duration `yaml:"timeout"`
}

type AuditConfig struct {
	BufferSize int `yaml:"bufferSize"`
}

// Profile is an administrator-approved MongoDB deployment. Users can only
// connect to hosts listed in profiles; they never supply addresses.
type Profile struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName"`
	Description string `yaml:"description"`
	// URI contains hosts and non-security options only. Credentials, auth
	// and TLS options are rejected; TLS is configured in the TLS block.
	URI                    string        `yaml:"uri"`
	ReplicaSet             string        `yaml:"replicaSet"`
	DefaultAuthSource      string        `yaml:"defaultAuthSource"`
	AuthMechanisms         []string      `yaml:"authMechanisms"`
	ReadPreference         string        `yaml:"readPreference"`
	ConnectTimeout         time.Duration `yaml:"connectTimeout"`
	ServerSelectionTimeout time.Duration `yaml:"serverSelectionTimeout"`
	OperationTimeout       time.Duration `yaml:"operationTimeout"`
	MaxPoolSize            uint64        `yaml:"maxPoolSize"`
	MaxConnIdleTime        time.Duration `yaml:"maxConnIdleTime"`
	TLS                    TLSConfig     `yaml:"tls"`
	// PlaintextApproved records an explicit security exception for non-TLS
	// connections. Required when Environment is production.
	PlaintextApproved    bool   `yaml:"plaintextApproved"`
	SecurityExceptionRef string `yaml:"securityExceptionRef"`
}

type TLSConfig struct {
	Mode string `yaml:"mode"`
	// VerifyServerCertificate exists so configuration is self-describing. It
	// must be true (or omitted); disabling verification is not supported.
	VerifyServerCertificate *bool  `yaml:"verifyServerCertificate"`
	CAFile                  string `yaml:"caFile"`
	// UseSystemRoots adds the container's system trust store to CAFile.
	UseSystemRoots bool   `yaml:"useSystemRoots"`
	ClientCertFile string `yaml:"clientCertFile"`
	ClientKeyFile  string `yaml:"clientKeyFile"`
	MinVersion     string `yaml:"minVersion"`
	// ServerName overrides the hostname used for certificate verification.
	ServerName string `yaml:"serverName"`
}

var (
	profileNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerNameRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	authSourceRe  = regexp.MustCompile(`^[^/\\. "$*<>:|?\x00]{1,64}$`)
)

// SupportedMechanisms lists MongoDB auth mechanisms usable with a password.
var SupportedMechanisms = []string{"SCRAM-SHA-256", "SCRAM-SHA-1"}

// forbiddenURIOptions may not appear in a profile URI. Credentials, auth and
// TLS behaviour are controlled exclusively by structured configuration so
// that certificate verification can never be disabled through the URI.
var forbiddenURIOptions = []string{
	"tls", "ssl", "tlsinsecure", "tlsallowinvalidcertificates",
	"tlsallowinvalidhostnames", "tlsdisableocspendpointcheck",
	"tlsdisablecertificaterevocationcheck", "sslallowinvalidcertificates",
	"sslallowinvalidhostnames", "tlscafile", "tlscertificatekeyfile",
	"tlscertificatekeyfilepassword", "sslcafile", "sslpemkeyfile",
	"authmechanism", "authsource", "authmechanismproperties",
	"username", "password",
}

// Load reads the YAML file at path, applies defaults and environment
// overrides, and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is operator supplied
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse parses YAML configuration bytes.
func Parse(raw []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyEnv()
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("PORTAL_LISTEN_ADDRESS"); v != "" {
		c.Server.ListenAddress = v
	}
	if v := os.Getenv("PORTAL_OPS_LISTEN_ADDRESS"); v != "" {
		c.Server.OpsListenAddress = v
	}
	if v := os.Getenv("PORTAL_PUBLIC_ORIGIN"); v != "" {
		c.Server.PublicOrigin = v
	}
	if v := os.Getenv("PORTAL_SESSION_KEY_FILE"); v != "" {
		c.Session.KeyFile = v
	}
}

func (c *Config) applyDefaults() {
	s := &c.Server
	setDefault(&s.ListenAddress, "127.0.0.1:8080")
	setDefault(&s.OpsListenAddress, "0.0.0.0:9090")
	if s.MaxBodyBytes == 0 {
		s.MaxBodyBytes = 1 << 20
	}
	setDuration(&s.ReadTimeout, 30*time.Second)
	setDuration(&s.WriteTimeout, 90*time.Second)
	setDuration(&s.ShutdownDelay, 5*time.Second)
	setDuration(&s.ShutdownTimeout, 30*time.Second)

	id := &c.Identity
	if len(id.TrustedProxyCIDRs) == 0 {
		id.TrustedProxyCIDRs = []string{"127.0.0.1/32", "::1/128"}
	}
	o := &id.OpenShift
	setDefault(&o.APIURL, "https://kubernetes.default.svc")
	setDefault(&o.CAFile, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	setDefault(&o.ServiceAccountFile, "/var/run/secrets/kubernetes.io/serviceaccount/token")
	setDefault(&o.UserHeader, "X-Forwarded-User")
	setDefault(&o.TokenHeader, "X-Forwarded-Access-Token")
	setDuration(&o.TokenCacheTTL, time.Minute)
	setDuration(&o.GroupCacheTTL, time.Minute)
	setDuration(&o.GroupMaxStale, 5*time.Minute)
	setDuration(&o.RequestTimeout, 5*time.Second)
	setDefault(&id.Header.UserHeader, "X-Forwarded-User")
	setDefault(&id.Header.GroupsHeader, "X-Forwarded-Groups")

	ss := &c.Session
	setDefault(&ss.CookieName, "__Host-mongo_portal_session")
	if ss.SecureCookie == nil {
		t := true
		ss.SecureCookie = &t
	}
	setDuration(&ss.IdleTimeout, 15*time.Minute)
	setDuration(&ss.AbsoluteTimeout, 8*time.Hour)
	setInt(&ss.MaxPerUser, 3)
	setInt(&ss.MaxTotal, 200)

	q := &c.Query
	setInt64(&q.DefaultLimit, 20)
	setInt64(&q.MaxLimit, 200)
	setInt64(&q.MaxSkip, 100000)
	setDuration(&q.DefaultMaxTime, 10*time.Second)
	setDuration(&q.MaxMaxTime, 60*time.Second)
	setInt(&q.MaxResponseBytes, 8<<20)
	setInt64(&q.MaxDocumentBytes, 4<<20)
	setInt64(&q.MaxCount, 1000000)

	l := &c.Login
	setInt(&l.AttemptsPerWindow, 10)
	setDuration(&l.Window, 5*time.Minute)
	setInt(&l.FailuresBeforeLock, 5)
	setDuration(&l.LockDuration, 5*time.Minute)
	setDuration(&l.MaxLockDuration, 30*time.Minute)
	setInt(&l.MaxConcurrent, 20)
	setDuration(&l.Timeout, 15*time.Second)

	setInt(&c.Audit.BufferSize, 1000)

	for i := range c.Profiles {
		p := &c.Profiles[i]
		setDefault(&p.DisplayName, p.Name)
		setDefault(&p.DefaultAuthSource, "admin")
		if len(p.AuthMechanisms) == 0 {
			p.AuthMechanisms = slices.Clone(SupportedMechanisms)
		}
		setDefault(&p.ReadPreference, "primary")
		setDuration(&p.ConnectTimeout, 10*time.Second)
		setDuration(&p.ServerSelectionTimeout, 10*time.Second)
		setDuration(&p.OperationTimeout, 2*time.Minute)
		if p.MaxPoolSize == 0 {
			p.MaxPoolSize = 5
		}
		setDuration(&p.MaxConnIdleTime, 5*time.Minute)
		setDefault(&p.TLS.MinVersion, "1.2")
	}
}

// IsProduction reports whether strict production checks apply.
func (c *Config) IsProduction() bool {
	e := strings.ToLower(c.Environment)
	return e == "prod" || e == "production"
}

// Validate checks the configuration for unsafe or inconsistent settings.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if _, _, err := net.SplitHostPort(c.Server.ListenAddress); err != nil {
		add("server.listenAddress: %v", err)
	}
	if _, _, err := net.SplitHostPort(c.Server.OpsListenAddress); err != nil {
		add("server.opsListenAddress: %v", err)
	}
	if c.Server.PublicOrigin != "" {
		u, err := url.Parse(c.Server.PublicOrigin)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
			add("server.publicOrigin must be an origin such as https://portal.example.com")
		}
	}

	id := c.Identity
	switch id.Mode {
	case IdentityOpenShift:
		if !hostIsLoopback(c.Server.ListenAddress) {
			add("identity.mode=openshift requires server.listenAddress on loopback so only the OAuth proxy can reach it")
		}
		if !validHeader(id.OpenShift.UserHeader) || !validHeader(id.OpenShift.TokenHeader) {
			add("identity.openshift header names are invalid")
		}
		if u, err := url.Parse(id.OpenShift.APIURL); err != nil || u.Scheme != "https" {
			add("identity.openshift.apiURL must be an https URL")
		}
	case IdentityHeader:
		if !validHeader(id.Header.UserHeader) || !validHeader(id.Header.GroupsHeader) {
			add("identity.header header names are invalid")
		}
	case IdentityDev:
		if os.Getenv(DevIdentityGateEnv) != "true" {
			add("identity.mode=dev requires %s=true and must never be used in a cluster", DevIdentityGateEnv)
		}
		if c.IsProduction() {
			add("identity.mode=dev is not allowed when environment is production")
		}
		if id.Dev.User == "" {
			add("identity.dev.user is required")
		}
	default:
		add("identity.mode must be one of %q, %q, %q", IdentityOpenShift, IdentityHeader, IdentityDev)
	}
	if len(id.DeveloperGroups) == 0 && len(id.SREGroups) == 0 {
		add("identity.developerGroups or identity.sreGroups must list at least one group")
	}
	for _, cidr := range id.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("identity.trustedProxyCIDRs: %v", err)
		}
	}
	if !*c.Session.SecureCookie && id.Mode != IdentityDev {
		add("session.secureCookie=false is only permitted with identity.mode=dev")
	}
	if strings.HasPrefix(c.Session.CookieName, "__Host-") && !*c.Session.SecureCookie {
		add("session.cookieName with __Host- prefix requires secureCookie")
	}
	if c.Session.AbsoluteTimeout < c.Session.IdleTimeout {
		add("session.absoluteTimeout must be >= session.idleTimeout")
	}
	if c.Query.DefaultLimit > c.Query.MaxLimit || c.Query.DefaultMaxTime > c.Query.MaxMaxTime {
		add("query defaults must not exceed maximums")
	}

	if len(c.Profiles) == 0 {
		add("at least one MongoDB connection profile is required")
	}
	seen := map[string]bool{}
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if !profileNameRe.MatchString(p.Name) {
			add("profiles[%d].name %q must be a DNS-label style name", i, p.Name)
		}
		if seen[p.Name] {
			add("profiles[%d].name %q is duplicated", i, p.Name)
		}
		seen[p.Name] = true
		if err := ValidateProfileURI(p.URI); err != nil {
			add("profiles[%s].uri: %v", p.Name, err)
		}
		if !authSourceRe.MatchString(p.DefaultAuthSource) {
			add("profiles[%s].defaultAuthSource is invalid", p.Name)
		}
		for _, m := range p.AuthMechanisms {
			if !slices.Contains(SupportedMechanisms, m) {
				add("profiles[%s].authMechanisms: %q is not supported", p.Name, m)
			}
		}
		switch strings.ToLower(p.ReadPreference) {
		case "primary", "primarypreferred", "secondary", "secondarypreferred", "nearest":
		default:
			add("profiles[%s].readPreference %q is invalid", p.Name, p.ReadPreference)
		}
		if err := p.TLS.validate(); err != nil {
			add("profiles[%s].tls: %v", p.Name, err)
		}
		if p.TLS.Mode == TLSDisabled && c.IsProduction() && !p.PlaintextApproved {
			add("profiles[%s]: tls.mode=disabled in production requires plaintextApproved=true (security exception)", p.Name)
		}
	}
	return errors.Join(errs...)
}

func (t TLSConfig) validate() error {
	switch t.Mode {
	case TLSEnabled:
	case TLSDisabled:
		if t.CAFile != "" || t.ClientCertFile != "" || t.ClientKeyFile != "" {
			return errors.New("certificate files are set but mode is disabled; refusing ambiguous configuration")
		}
		return nil
	case "":
		return errors.New("mode is required and must be \"enabled\" or \"disabled\"")
	default:
		return fmt.Errorf("mode %q must be \"enabled\" or \"disabled\"", t.Mode)
	}
	if t.VerifyServerCertificate != nil && !*t.VerifyServerCertificate {
		return errors.New("verifyServerCertificate=false is not supported; provide a trusted CA instead")
	}
	if (t.ClientCertFile == "") != (t.ClientKeyFile == "") {
		return errors.New("clientCertFile and clientKeyFile must be set together")
	}
	if t.MinVersion != "1.2" && t.MinVersion != "1.3" {
		return fmt.Errorf("minVersion %q must be 1.2 or 1.3", t.MinVersion)
	}
	return nil
}

// ValidateProfileURI ensures a profile URI is a credential-free MongoDB URI
// without security-relevant options.
func ValidateProfileURI(uri string) error {
	var rest string
	switch {
	case strings.HasPrefix(uri, "mongodb://"):
		rest = strings.TrimPrefix(uri, "mongodb://")
	case strings.HasPrefix(uri, "mongodb+srv://"):
		rest = strings.TrimPrefix(uri, "mongodb+srv://")
	default:
		return errors.New("must start with mongodb:// or mongodb+srv://")
	}
	authority, query, _ := strings.Cut(rest, "?")
	hosts, _, _ := strings.Cut(authority, "/")
	if hosts == "" {
		return errors.New("no hosts")
	}
	if strings.Contains(hosts, "@") {
		return errors.New("must not contain credentials")
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}
	for k := range vals {
		if slices.Contains(forbiddenURIOptions, strings.ToLower(k)) {
			return fmt.Errorf("option %q is not permitted in profile URIs", k)
		}
	}
	return nil
}

// ValidAuthSource reports whether s is an acceptable authentication database.
func ValidAuthSource(s string) bool { return authSourceRe.MatchString(s) }

// Profile returns the named profile.
func (c *Config) Profile(name string) (*Profile, bool) {
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			return &c.Profiles[i], true
		}
	}
	return nil, false
}

func hostIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validHeader(h string) bool { return headerNameRe.MatchString(h) }

func setDefault(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func setDuration(p *time.Duration, v time.Duration) {
	if *p == 0 {
		*p = v
	}
}

func setInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setInt64(p *int64, v int64) {
	if *p == 0 {
		*p = v
	}
}
