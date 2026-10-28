// Package server composes the tt-core HTTP surface: the admin/UI listener
// and the intake listener (mTLS-capable), their middleware chains, the
// built-in auth/setup/audit/health routes and the mounting API other
// packages use to plug in their handlers.
//
// Mounting (before Run):
//
//	srv.Mount("/fleet/v1/admin", fleetAdmin, auth.RoleOperator)   // session + CSRF + any-of roles
//	srv.MountAuthenticated("/api/v1/notifications", h)            // any logged-in user
//	srv.MountPublic("/api/v1/public-thing", h)                    // explicit opt-out
//	srv.MountIntake("/v1/logs", otlpHandler)                       // verified client cert required
//	srv.MountIntake("/fleet/v1/enroll", enroll, server.AllowNoClientCert())
//
// Handlers receive the full request path (no prefix stripping), so they can
// use http.ServeMux patterns such as "GET /fleet/v1/admin/sources/{id}".
// auth.PrincipalFrom(r.Context()) returns the caller on admin routes;
// server.PeerCertificate(r) returns the verified source certificate on
// intake routes.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Deps are the services the server composes.
type Deps struct {
	Logger *slog.Logger
	Auth   *auth.Service
	Audit  *audit.Log
	DB     *store.DB
	UI     http.Handler // served at "/"; nil serves 404
}

// IntakeTLSHooks let the fleet package drive the intake TLS configuration
// at runtime (CA rotation, revocation, managed server certificates).
type IntakeTLSHooks struct {
	// ClientCAs returns the pool that verifies source certificates. It is
	// called on every handshake, so a rotated CA applies immediately.
	// When nil, intake.tls.client_ca_file is used.
	ClientCAs func() *x509.CertPool
	// VerifyPeer runs after chain verification when a client certificate
	// was presented (e.g. revocation or source-id checks). An error aborts
	// the handshake.
	VerifyPeer func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// GetCertificate supplies the server certificate; required when
	// intake.tls.managed is true.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// IntakeOption tunes a MountIntake call.
type IntakeOption func(*intakeMount)

type intakeMount struct{ allowNoCert bool }

// AllowNoClientCert admits requests without a client certificate (only
// for bootstrap endpoints such as enrollment, which authenticate by token).
// A presented certificate is still verified during the handshake.
func AllowNoClientCert() IntakeOption { return func(m *intakeMount) { m.allowNoCert = true } }

// Server is the tt-core HTTP server.
type Server struct {
	cfg  config.Config
	deps Deps
	log  *slog.Logger

	mu        sync.Mutex
	started   bool
	adminMux  *http.ServeMux
	intakeMux *http.ServeMux
	prefixes  []string // admin mounts, for overlap checks
	intakePfx []string
	intakeTLS IntakeTLSHooks
	ready     []readinessCheck
	limiter   *rateLimiter
}

type readinessCheck struct {
	name string
	fn   func(context.Context) error
}

// reservedPrefixes belong to the server itself.
var reservedPrefixes = []string{"/api/v1/auth", "/api/v1/setup", "/api/v1/audit", "/healthz", "/readyz"}

// New builds a server from a validated configuration.
func New(cfg config.Config, deps Deps) (*Server, error) {
	if deps.Auth == nil || deps.Audit == nil || deps.DB == nil {
		return nil, errors.New("server: auth, audit and db are required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		cfg: cfg, deps: deps, log: deps.Logger,
		adminMux:  http.NewServeMux(),
		intakeMux: http.NewServeMux(),
		limiter:   newRateLimiter(cfg.Auth.RateLimit.RequestsPerMinute, cfg.Auth.RateLimit.Burst),
	}
	s.AddReadinessCheck("db", func(ctx context.Context) error { return deps.DB.PingContext(ctx) })
	s.routes()
	return s, nil
}

func (s *Server) handleAdmin(pattern string, h http.Handler) {
	s.adminMux.Handle(pattern, withRoute(pattern, h))
}

func (s *Server) routes() {
	a := s.deps.Auth
	rl := s.limiter.middleware
	authed := a.Require()

	s.handleAdmin("GET /healthz", http.HandlerFunc(healthz))
	s.handleAdmin("GET /readyz", http.HandlerFunc(s.readyz))

	s.handleAdmin("/api/v1/auth/login", rl(a.LoginHandler()))
	s.handleAdmin("/api/v1/auth/logout", authed(a.LogoutHandler()))
	s.handleAdmin("/api/v1/auth/me", authed(a.MeHandler()))
	s.handleAdmin("/api/v1/auth/config", a.ConfigHandler())
	s.handleAdmin("/api/v1/auth/oidc/start", rl(a.OIDCStartHandler()))
	s.handleAdmin("/api/v1/auth/oidc/callback", rl(a.OIDCCallbackHandler()))
	s.handleAdmin("/api/v1/auth/oidc/stepup", rl(authed(a.StepUpStartHandler())))
	s.handleAdmin("/api/v1/auth/oidc/stepup/callback", rl(a.StepUpCallbackHandler()))
	s.handleAdmin("/api/v1/setup", rl(a.SetupHandler()))

	auditor := a.Require(auth.RoleAuditor)
	s.handleAdmin("/api/v1/audit/export", auditor(s.deps.Audit.ExportHandler(auth.RequestActor)))
	s.handleAdmin("/api/v1/audit/verify", auditor(s.deps.Audit.VerifyHandler(auth.RequestActor)))

	// Unknown API paths get a JSON 404, never the UI.
	s.handleAdmin("/api/", http.HandlerFunc(notFound))
	ui := s.deps.UI
	if ui == nil {
		ui = http.HandlerFunc(notFound)
	}
	s.handleAdmin("/", ui)

	s.intakeMux.Handle("GET /healthz", withRoute("GET /healthz", http.HandlerFunc(healthz)))
	s.intakeMux.Handle("/", withRoute("/", http.HandlerFunc(notFound)))
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
}

// AddReadinessCheck registers a check run by GET /readyz. Names appear in
// the response; errors are logged, never returned to the client.
func (s *Server) AddReadinessCheck(name string, fn func(context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = append(s.ready, readinessCheck{name, fn})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	checks := slices.Clone(s.ready)
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	failed := []string{}
	for _, c := range checks {
		if err := c.fn(ctx); err != nil {
			s.log.WarnContext(ctx, "readiness check failed", "check", c.name, "err", err)
			failed = append(failed, c.name)
		}
	}
	if len(failed) > 0 {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "failed": failed})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func validPrefix(p string) bool {
	return strings.HasPrefix(p, "/") && len(p) > 1 && !strings.HasSuffix(p, "/") &&
		!strings.ContainsAny(p, " {}*?#%") && !strings.Contains(p, "//")
}

// overlaps reports whether a and b share a path-segment prefix.
func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func (s *Server) checkMount(prefix string, existing []string, reserved []string) {
	if s.started {
		panic("server: mount after Run: " + prefix)
	}
	if !validPrefix(prefix) {
		panic(fmt.Sprintf("server: invalid mount prefix %q (absolute, no trailing slash, no patterns)", prefix))
	}
	for _, p := range append(slices.Clone(reserved), existing...) {
		if overlaps(prefix, p) {
			panic(fmt.Sprintf("server: mount prefix %q overlaps %q", prefix, p))
		}
	}
}

func (s *Server) mountAdmin(prefix string, h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkMount(prefix, s.prefixes, reservedPrefixes)
	s.prefixes = append(s.prefixes, prefix)
	s.handleAdmin(prefix, h)
	s.handleAdmin(prefix+"/", h)
}

// Mount serves h under prefix on the admin listener for authenticated
// users holding at least one of roles (CSRF enforced on unsafe methods).
// At least one role is required: use MountAuthenticated or MountPublic to
// opt out explicitly. It panics on invalid or overlapping prefixes.
func (s *Server) Mount(prefix string, h http.Handler, roles ...auth.Role) {
	if len(roles) == 0 {
		panic("server: Mount needs at least one role; use MountAuthenticated or MountPublic")
	}
	s.mountAdmin(prefix, s.deps.Auth.Require(roles...)(h))
}

// MountAuthenticated serves h for any authenticated user (CSRF enforced).
func (s *Server) MountAuthenticated(prefix string, h http.Handler) {
	s.mountAdmin(prefix, s.deps.Auth.Require()(h))
}

// MountPublic serves h without authentication. Use sparingly.
func (s *Server) MountPublic(prefix string, h http.Handler) {
	s.mountAdmin(prefix, h)
}

// MountIntake serves h under prefix on the intake listener. By default a
// verified client certificate is required (403 otherwise).
func (s *Server) MountIntake(prefix string, h http.Handler, opts ...IntakeOption) {
	var m intakeMount
	for _, o := range opts {
		o(&m)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkMount(prefix, s.intakePfx, []string{"/healthz"})
	s.intakePfx = append(s.intakePfx, prefix)
	if !m.allowNoCert {
		h = requireClientCert(h)
	}
	for _, p := range []string{prefix, prefix + "/"} {
		s.intakeMux.Handle(p, withRoute(p, h))
	}
}

// SetIntakeTLS installs runtime TLS hooks for the intake listener.
func (s *Server) SetIntakeTLS(h IntakeTLSHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		panic("server: SetIntakeTLS after Run")
	}
	s.intakeTLS = h
}

// PeerCertificate returns the verified client certificate of an intake
// request, or nil.
func PeerCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

func requireClientCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PeerCertificate(r) == nil {
			httpx.WriteError(w, http.StatusForbidden, "client_certificate_required", "a verified client certificate is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminHandler returns the fully wrapped admin handler (for tests).
func (s *Server) AdminHandler() http.Handler {
	tlsOn := s.cfg.Admin.TLS.Enabled()
	var h http.Handler = s.adminMux
	h = limitBody(s.cfg.Admin.HTTP.MaxBodyBytes, h)
	h = sameOrigin(tlsOn, h)
	h = securityHeaders(tlsOn, h)
	h = recoverPanics(s.log, h)
	return accessLog(s.log, "admin", h)
}

// IntakeHandler returns the fully wrapped intake handler (for tests).
func (s *Server) IntakeHandler() http.Handler {
	limited := limitBody(s.cfg.Intake.HTTP.MaxBodyBytes, s.intakeMux)
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		limited.ServeHTTP(w, r)
	})
	h = recoverPanics(s.log, h)
	return accessLog(s.log, "intake", h)
}

func (s *Server) httpServer(h http.Handler, c config.HTTP) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		ReadTimeout:       c.ReadTimeout,
		WriteTimeout:      c.WriteTimeout,
		IdleTimeout:       c.IdleTimeout,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

func baseTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func (s *Server) adminTLS() (*tls.Config, error) {
	if !s.cfg.Admin.TLS.Enabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.Admin.TLS.CertFile, s.cfg.Admin.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("server: admin tls: %w", err)
	}
	c := baseTLS()
	c.Certificates = []tls.Certificate{cert}
	return c, nil
}

func (s *Server) buildIntakeTLS() (*tls.Config, error) {
	t := s.cfg.Intake.TLS
	hooks := s.intakeTLS
	c := baseTLS()
	switch {
	case t.Managed:
		if hooks.GetCertificate == nil {
			return nil, errors.New("server: intake.tls.managed is set but no certificate provider is registered")
		}
		c.GetCertificate = hooks.GetCertificate
	default:
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("server: intake tls: %w", err)
		}
		c.Certificates = []tls.Certificate{cert}
	}

	var static *x509.CertPool
	if t.ClientCAFile != "" {
		pem, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("server: intake client CA: %w", err)
		}
		static = x509.NewCertPool()
		if !static.AppendCertsFromPEM(pem) {
			return nil, errors.New("server: intake client CA file contains no certificate")
		}
	}
	pool := func() *x509.CertPool {
		if hooks.ClientCAs != nil {
			return hooks.ClientCAs()
		}
		return static
	}
	if hooks.ClientCAs == nil && static == nil {
		s.log.Warn("intake: no client CA configured; only routes mounted with AllowNoClientCert are usable")
	}
	c.ClientAuth = tls.VerifyClientCertIfGiven
	c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cc := c.Clone()
		cc.GetConfigForClient = nil
		cc.ClientCAs = pool()
		if cc.ClientCAs == nil {
			// Nothing can verify a client certificate: do not request one.
			cc.ClientAuth = tls.NoClientCert
		}
		if hooks.VerifyPeer != nil {
			cc.VerifyPeerCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
				if len(chains) == 0 || len(chains[0]) == 0 {
					return nil // no certificate presented
				}
				return hooks.VerifyPeer(chains[0][0], chains)
			}
		}
		return cc, nil
	}
	return c, nil
}

// Run listens on the configured addresses and serves until ctx is done,
// then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	adminLn, err := net.Listen("tcp", s.cfg.Admin.Addr)
	if err != nil {
		return fmt.Errorf("server: admin listener: %w", err)
	}
	var intakeLn net.Listener
	if s.cfg.Intake.Addr != "" {
		intakeLn, err = net.Listen("tcp", s.cfg.Intake.Addr)
		if err != nil {
			_ = adminLn.Close()
			return fmt.Errorf("server: intake listener: %w", err)
		}
	}
	return s.Serve(ctx, adminLn, intakeLn)
}

// Serve serves on the given listeners (intakeLn may be nil) until ctx is
// done. TLS is applied here according to the configuration.
func (s *Server) Serve(ctx context.Context, adminLn, intakeLn net.Listener) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("server: already started")
	}
	s.started = true
	s.mu.Unlock()

	closeAll := func() {
		_ = adminLn.Close()
		if intakeLn != nil {
			_ = intakeLn.Close()
		}
	}
	adminTLS, err := s.adminTLS()
	if err != nil {
		closeAll()
		return err
	}
	if adminTLS != nil {
		adminLn = tls.NewListener(adminLn, adminTLS)
	}
	servers := []*http.Server{s.httpServer(s.AdminHandler(), s.cfg.Admin.HTTP)}
	lns := []net.Listener{adminLn}
	if intakeLn != nil {
		itls, err := s.buildIntakeTLS()
		if err != nil {
			closeAll()
			return err
		}
		servers = append(servers, s.httpServer(s.IntakeHandler(), s.cfg.Intake.HTTP))
		lns = append(lns, tls.NewListener(intakeLn, itls))
	} else if len(s.intakePfx) > 0 {
		s.log.Warn("intake routes are mounted but the intake listener is disabled (intake.addr is empty)")
	}

	janitorCtx, stopJanitor := context.WithCancel(ctx)
	defer stopJanitor()
	go s.deps.Auth.RunJanitor(janitorCtx, 5*time.Minute)

	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(lns[i]) }()
	}
	s.log.Info("tt core listening", "admin", adminLn.Addr().String(), "admin_tls", adminTLS != nil, "intake", addrOf(intakeLn))

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Admin.ShutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = err
		}
	}
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	s.log.Info("tt core stopped")
	return runErr
}

func addrOf(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}
