package mock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

const (
	defaultSession = "default"
	// Version is reported in HAR exports.
	Version = "0.1.0"

	// Latency modes.
	LatencyReal   = "real"   // sleep for the injected latency
	LatencyRecord = "record" // record it in the journal, do not sleep
	LatencyOff    = "off"    // no latency at all
)

// Config configures the mock.
type Config struct {
	// Pack is the path of a pack directory or .ttpack archive (required).
	Pack string
	// GatePubKeys is the trusted key list (inline "kid:base64url,..." or a
	// file path). When empty, Keys is used, and then $TT_GATE_PUBKEYS.
	GatePubKeys string
	Keys        pack.KeySet
	// Now is the clock of the pack checks (not_after, age, created_at in
	// the future); default time.Now.
	Now func() time.Time
	// RevokedKIDs are gate key ids that are not trusted any more, added to
	// $TT_GATE_REVOKED_KIDS.
	RevokedKIDs []string
	// MaxPackAge: 0 refuses packs without not_after created more than
	// pack.DefaultMaxAge (90 days) ago; > 0 refuses every pack created
	// longer ago than this; < 0 disables the check.
	MaxPackAge time.Duration

	// Addr is the listen address (default 127.0.0.1:8480). Listener, when set,
	// is used instead.
	Addr     string
	Listener net.Listener
	// ControlToken protects /__tt/ when non-empty (TT_CONTROL_TOKEN). Without
	// it the mock refuses to listen on a non-loopback address.
	ControlToken string

	// Seed overrides the pack seed of the default session.
	Seed *uint64
	// Faults is the fault mode of new sessions: "observed" (default) or "off".
	Faults string
	// Latency: "real" (default), "record" or "off".
	Latency string
	// NetTimeout is how long a simulated network timeout holds the connection.
	NetTimeout time.Duration

	MaxSessions  int   // default 1000
	MaxBodyBytes int64 // default 1 MiB
	JournalMax   int   // entries kept per session (default 10000)
	// JournalMaxBytes bounds the journal of a session by its JSON size
	// (default 32 MiB): the oldest entries go first.
	JournalMaxBytes int64
	// SessionIdleTTL evicts the sessions (except the default one) not used
	// for this long (default 24h; negative: never). Evicted sessions free
	// their entities and journal; the limit MaxSessions then has room.
	SessionIdleTTL  time.Duration
	MaxAdvance      time.Duration // largest single clock advance (default 3660d)
	MaxAdvanceSteps int           // scheduled steps per advance (default 1,000,000)

	// Wall provides the wall-clock timestamps of the journal (default
	// time.Now). Tests inject a deterministic clock.
	Wall   func() time.Time
	Logger *slog.Logger
	// OnListen is called with the bound address once the mock accepts calls.
	OnListen func(net.Addr)
	// OnCall, when set, receives the summary of every journaled call (console
	// mode reports them to tt-core). It runs under the session lock: it must
	// not block.
	OnCall func(Call)
	// Identity chooses the session by the caller's identity when the
	// request has no X-TT-Session (docs/spec/mock.md 2.6); nil: off.
	Identity *IdentityConfig
	// S3 serves a minimal S3-compatible API (docs/spec/mock.md 8); nil: off.
	S3 *S3Config
	// Pages are the third-party pages (docs/spec/mock.md 9); nil: none.
	// They can be replaced at run time (control API, console).
	Pages *PagesConfig
	// HTTPClient makes the server-to-server callbacks of the third-party
	// pages (default: 10 s timeout, no redirects).
	HTTPClient *http.Client
}

func (c *Config) applyDefaults() error {
	if c.Pack == "" {
		return errors.New("mock: pack path is required")
	}
	if c.Addr == "" {
		c.Addr = "127.0.0.1:8480"
	}
	switch c.Faults {
	case "":
		c.Faults = "observed"
	case "observed", "off":
	default:
		return fmt.Errorf("mock: faults must be observed or off, got %q", c.Faults)
	}
	switch c.Latency {
	case "":
		c.Latency = LatencyReal
	case LatencyReal, LatencyRecord, LatencyOff:
	default:
		return fmt.Errorf("mock: latency must be real, record or off, got %q", c.Latency)
	}
	if c.NetTimeout <= 0 {
		c.NetTimeout = 30 * time.Second
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 1000
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.JournalMax <= 0 {
		c.JournalMax = 10000
	}
	if c.JournalMaxBytes <= 0 {
		c.JournalMaxBytes = 32 << 20
	}
	if c.SessionIdleTTL == 0 {
		c.SessionIdleTTL = 24 * time.Hour
	}
	if c.MaxAdvance <= 0 {
		c.MaxAdvance = 3660 * 24 * time.Hour
	}
	if c.MaxAdvanceSteps <= 0 {
		c.MaxAdvanceSteps = 1_000_000
	}
	if c.Wall == nil {
		c.Wall = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.S3 != nil && c.S3.Enabled {
		if err := c.S3.applyDefaults(); err != nil {
			return err
		}
	}
	return nil
}

// Mock is a loaded twin pack served as a stateful mock.
type Mock struct {
	cfg   Config
	log   *slog.Logger
	model *model

	mu       sync.RWMutex
	sessions map[string]*session
	nextAuto int
	// ident is the identity session setting (nil: off).
	ident atomic.Pointer[identityState]
	// pages are the third-party pages (pages.go; nil: none).
	pages atomic.Pointer[PagesConfig]
}

// identityHeader is the canonical name of the identity header ("" when off).
func (m *Mock) identityHeader() string {
	if st := m.ident.Load(); st != nil {
		return st.header
	}
	return ""
}

// New loads and verifies the pack and returns the mock. Nothing is served
// before the signature has been verified.
func New(cfg Config) (*Mock, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	keys := cfg.Keys
	if cfg.GatePubKeys != "" {
		var err error
		if keys, err = pack.ParseKeySet(cfg.GatePubKeys); err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		var err error
		if keys, err = pack.KeySetFromEnv(); err != nil {
			return nil, err
		}
	}
	revoked, err := pack.RevokedKIDsFromEnv()
	if err != nil {
		return nil, err
	}
	revoked = append(revoked, cfg.RevokedKIDs...)
	p, err := pack.Load(cfg.Pack, pack.Options{Keys: keys, RevokedKIDs: revoked, MaxAge: cfg.MaxPackAge, Now: cfg.Now})
	if err != nil {
		return nil, fmt.Errorf("mock: refusing pack: %w", err)
	}
	mod, err := compileModel(p)
	if err != nil {
		return nil, fmt.Errorf("mock: invalid pack: %w", err)
	}
	m := &Mock{cfg: cfg, log: cfg.Logger, model: mod, sessions: map[string]*session{}}
	seed := p.Manifest.Seed
	if cfg.Seed != nil {
		seed = *cfg.Seed
	}
	for _, sc := range mod.presets {
		if sc.Faults != nil {
			if err := mod.validateFaults(faultsFromPack(sc.Faults)); err != nil {
				return nil, fmt.Errorf("mock: invalid pack: preset %s: %w", sc.ID, err)
			}
		}
	}
	def := newSession(m, sessionInit{id: defaultSession, seed: seed, t0: mod.t0,
		createFaults: FaultsConfig{Mode: cfg.Faults}, baseFaults: FaultsConfig{Mode: cfg.Faults}})
	m.sessions[defaultSession] = def
	if err := m.SetIdentity(cfg.Identity); err != nil {
		return nil, err
	}
	if err := m.SetPages(cfg.Pages); err != nil {
		return nil, fmt.Errorf("mock: pages: %w", err)
	}
	return m, nil
}

// PackID is the id of the loaded pack.
func (m *Mock) PackID() string { return m.model.pack.Manifest.PackID }

// Manifest is the manifest of the loaded (verified) pack.
func (m *Mock) Manifest() pack.Manifest { return m.model.pack.Manifest }

// Handler serves the control API under /__tt/ and the data plane elsewhere.
func (m *Mock) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__tt" || strings.HasPrefix(r.URL.Path, "/__tt/") {
			m.serveControl(w, r)
			return
		}
		if b, k, ok := m.s3Target(r); ok {
			m.serveS3(w, r, b, k)
			return
		}
		if r.URL.Path == pagesPrefix || strings.HasPrefix(r.URL.Path, pagesPrefix+"/") {
			m.servePage(w, r)
			return
		}
		m.serveData(w, r)
	})
}

// Run loads the pack, binds the listener and serves until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.applyDefaults(); err != nil {
		return err
	}
	ln := cfg.Listener
	if ln == nil {
		if cfg.ControlToken == "" && !isLoopbackAddr(cfg.Addr) {
			return errors.New("mock: refusing to listen on a non-loopback address without a control token (set TT_CONTROL_TOKEN)")
		}
	} else if cfg.ControlToken == "" && !isLoopbackAddr(ln.Addr().String()) {
		return errors.New("mock: refusing to serve on a non-loopback listener without a control token (set TT_CONTROL_TOKEN)")
	}
	m, err := New(cfg)
	if err != nil {
		return err
	}
	if ln == nil {
		if ln, err = net.Listen("tcp", cfg.Addr); err != nil {
			return err
		}
	}
	srv := &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(m.log.Handler(), slog.LevelWarn),
	}
	m.log.Info("mock serving", "pack_id", m.PackID(), "addr", ln.Addr().String(), "services", len(m.model.services),
		"control_token", cfg.ControlToken != "")
	if cfg.OnListen != nil {
		cfg.OnListen(ln.Addr())
	}
	if na := m.model.pack.NotAfter; !na.IsZero() {
		// a running mock keeps serving the loaded pack, but says so when it expires
		t := time.AfterFunc(time.Until(na), func() {
			m.log.Warn("pack validity ended: restart with a newer pack", "pack_id", m.PackID(), "not_after", na.UTC().Format(time.RFC3339))
		})
		defer t.Stop()
	}
	if cfg.SessionIdleTTL > 0 {
		t := time.NewTicker(min(time.Minute, cfg.SessionIdleTTL))
		defer t.Stop()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if n := m.EvictIdle(); n > 0 {
						m.log.Info("idle sessions evicted", "sessions", n)
					}
				}
			}
		}()
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		<-errc
		return nil
	}
}

// isLoopbackAddr reports whether a host:port address binds loopback only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// envOr returns the environment variable or the fallback.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
