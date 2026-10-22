// Command mongo-portal runs the MongoDB management portal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/krishnamanaiducloud/mongo-express/portal/internal/api"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/telemetry"
	"github.com/krishnamanaiducloud/mongo-express/portal/internal/webui"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Args[2:]))
	}
	configPath := flag.String("config", envOr("PORTAL_CONFIG", "/etc/mongo-portal/config.yaml"), "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mongo-portal %s (%s) %s\n", version, commit, runtime.Version())
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("invalid configuration", "error", err.Error())
		os.Exit(2)
	}
	if *checkConfig {
		fmt.Println("configuration is valid")
		return
	}
	if err := run(cfg, logger); err != nil {
		logger.Error("portal stopped with error", "error", err.Error())
		os.Exit(1)
	}
}

func run(cfg *config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := telemetry.Setup(ctx, version)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(c)
	}()

	for _, p := range cfg.Profiles {
		if p.TLS.Mode == config.TLSDisabled {
			logger.Warn("connection profile uses plaintext MongoDB traffic: credentials and data are not encrypted in transit",
				"profile", p.Name, "plaintext_approved", p.PlaintextApproved, "security_exception", p.SecurityExceptionRef)
		}
	}
	if cfg.Identity.Mode == config.IdentityDev {
		logger.Warn("INSECURE development identity mode is enabled; never use this in a cluster", "user", cfg.Identity.Dev.User)
	}

	resolver, err := identity.New(cfg.Identity)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	key, err := loadKey(cfg.Session.KeyFile)
	if err != nil {
		return err
	}
	if key == nil {
		logger.Warn("session.keyFile not set; using a random per-process CSRF key (single replica only)")
	}

	m := metrics.New()
	m.BuildInfo.WithLabelValues(version, commit, runtime.Version()).Set(1)
	auditLog := audit.New(logger, cfg.Audit.BufferSize)

	var srv *api.Server
	store := session.NewStore(session.Options{
		IdleTimeout: cfg.Session.IdleTimeout, AbsoluteTimeout: cfg.Session.AbsoluteTimeout,
		MaxPerUser: cfg.Session.MaxPerUser, MaxTotal: cfg.Session.MaxTotal,
		OnClose: func(s *session.Session, reason string) {
			if srv != nil {
				srv.OnSessionClosed(s, reason)
			}
		},
	})
	srv = api.New(api.Deps{
		Config: cfg, Identity: resolver, Store: store, Audit: auditLog, Metrics: m, Logger: logger,
		CSRFKey: key, UI: webui.Handler(), Build: api.BuildInfo{Version: version, Commit: commit},
	})

	var ready atomic.Bool
	mainSrv := &http.Server{
		Addr: cfg.Server.ListenAddress, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	opsSrv := &http.Server{
		Addr:              cfg.Server.OpsListenAddress,
		Handler:           api.OpsHandler(ready.Load, promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
	}

	mainLn, err := net.Listen("tcp", cfg.Server.ListenAddress)
	if err != nil {
		return err
	}
	opsLn, err := net.Listen("tcp", cfg.Server.OpsListenAddress)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- serve(mainSrv, mainLn) }()
	go func() { errc <- serve(opsSrv, opsLn) }()
	ready.Store(true)
	logger.Info("mongo portal started", "version", version, "commit", commit, "listen", cfg.Server.ListenAddress,
		"ops_listen", cfg.Server.OpsListenAddress, "identity_mode", cfg.Identity.Mode, "profiles", len(cfg.Profiles),
		"environment", cfg.Environment)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}

	// Stop receiving new traffic, give the endpoints controller time to
	// remove this pod, then drain and close all MongoDB sessions.
	ready.Store(false)
	logger.Info("shutting down", "delay", cfg.Server.ShutdownDelay.String())
	time.Sleep(cfg.Server.ShutdownDelay)
	sctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	_ = mainSrv.Shutdown(sctx)
	store.Close()
	_ = opsSrv.Shutdown(sctx)
	logger.Info("shutdown complete")
	return nil
}

func serve(s *http.Server, ln net.Listener) error {
	if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator supplied secret mount
	if err != nil {
		return nil, fmt.Errorf("read session key: %w", err)
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	return b, nil
}

// healthcheck probes the ops listener; used as a container HEALTHCHECK in
// images that contain no shell or curl.
func healthcheck(args []string) int {
	addr := envOr("PORTAL_HEALTHCHECK_URL", "http://127.0.0.1:9090/healthz")
	if len(args) > 0 {
		addr = args[0]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(addr) // #nosec G107 G704 -- operator-supplied local health endpoint, not user input
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy:", resp.Status)
		return 1
	}
	return 0
}

func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("PORTAL_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
