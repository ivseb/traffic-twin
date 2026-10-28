package mock

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Console mode ("server mode", docs/spec/mock.md section 6): instead of a
// pack file the mock gets the latest published pack of one group from
// tt-core with a mock token, verifies it exactly like a file (signature with
// TT_GATE_PUBKEYS, hashes, content), refuses a pack of another group, and
// swaps it in when a newer one is published. It reports to tt-core its
// status, the base URL of every simulated service, its sessions and a
// summary of the calls (method, path, status, scenario, fault: never
// headers, bodies or query strings), and runs the control commands the
// console queued for it (scenarios, faults, clock) on its own control API.
//
// The mock token can only download that group's published pack and post
// this report: it opens nothing else of the console.

// Agent API paths on tt-core (internal/mockreg).
const (
	AgentPackPath   = "/api/v1/mock-agent/pack"
	AgentReportPath = "/api/v1/mock-agent/report"
	// HeaderPackID carries the id of the pack served by AgentPackPath.
	HeaderPackID = "X-TT-Pack-Id"
)

// Environment variables of console mode.
const (
	EnvConsoleURL   = "TT_MOCK_CONSOLE"
	EnvMockToken    = "TT_MOCK_TOKEN"
	EnvMockGroup    = "TT_MOCK_GROUP"
	EnvConsoleCA    = "TT_MOCK_CONSOLE_CA"
	EnvPublicURL    = "TT_MOCK_PUBLIC_URL"
	EnvInstanceName = "TT_MOCK_INSTANCE"
)

var (
	mockTokenRE   = regexp.MustCompile(`^ttm_[A-Za-z0-9_-]{20,64}\.[A-Za-z0-9_-]{32,64}$`)
	mockGroupRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	instanceRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	commandPathRE = regexp.MustCompile(`^/__tt/(pack|scenarios|customers|pages|sessions(/[A-Za-z0-9_-]{1,64}(/(reset|customer|clock|clock/advance|faults|scenario|entities|pages/[a-z0-9][a-z0-9-]{0,62}/(complete|auto)))?)?)$`)
)

// ErrTokenRefused is returned when tt-core refuses the mock token (unknown,
// expired or revoked): the mock stops.
var ErrTokenRefused = errors.New("the console refused the mock token (unknown, expired or revoked): create a new one in the console (Mock page)")

// ConsoleConfig configures console mode.
type ConsoleConfig struct {
	// URL is the base URL of the tt-core console (https; http only on the loopback).
	URL string
	// Token is the mock token (ttm_...), scoped to Group.
	Token string
	// Group is the group (team) whose published pack is served.
	Group string
	// CAFile is a PEM bundle trusted for the console's TLS, besides the system roots.
	CAFile string
	// PublicURL is the base URL the tests use to reach this mock (shown in
	// the console); default http://<listen address>.
	PublicURL string
	// Instance names this mock in the console (default: the host name).
	Instance string
	// Interval is the report period (default 5s).
	Interval time.Duration
	// Client replaces the HTTP client (tests).
	Client *http.Client
	// TempDir holds the downloaded pack while it is verified (default os.TempDir()).
	TempDir string
	// Version is reported to the console.
	Version string
}

func (c *ConsoleConfig) validate() error {
	u, err := url.Parse(strings.TrimSuffix(c.URL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.User != nil {
		return errors.New("--console must be the https URL of the console, e.g. https://tt.example.internal")
	}
	if u.Scheme == "http" && !isLoopbackAddr(hostPortOf(u)) {
		return errors.New("--console must use https outside the loopback (the mock token travels with every call)")
	}
	c.URL = strings.TrimSuffix(u.String(), "/")
	if !mockTokenRE.MatchString(c.Token) {
		return fmt.Errorf("the mock token is missing or malformed (set %s to the ttm_... value shown once in the console)", EnvMockToken)
	}
	if !mockGroupRE.MatchString(c.Group) {
		return errors.New("--group is required: the group (team) whose mock this is, as shown in the console")
	}
	if c.Instance == "" {
		h, _ := os.Hostname()
		c.Instance = h
	}
	if len(c.Instance) > 63 {
		c.Instance = c.Instance[:63]
	}
	if !instanceRE.MatchString(c.Instance) {
		c.Instance = "tt-mock"
	}
	if c.Interval <= 0 {
		c.Interval = 5 * time.Second
	}
	if c.PublicURL != "" {
		pu, err := url.Parse(c.PublicURL)
		if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
			return errors.New("--public-url must be an http(s) URL")
		}
		c.PublicURL = strings.TrimSuffix(pu.String(), "/")
	}
	return nil
}

func hostPortOf(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

func (c *ConsoleConfig) client() (*http.Client, error) {
	if c.Client != nil {
		return c.Client, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("console CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("console CA: no PEM certificate in the file")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: refuseRedirect}, nil
}

// refuseRedirect: the agent API never redirects. Following a redirect could
// send the mock token to another scheme (https -> http on the same host
// keeps the Authorization header) or another origin, bypassing the https
// rule of validate.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errors.New("the console answered with a redirect: refused (set --console to the final https URL)")
}

// Call is the summary of one journaled call, as reported to the console:
// no headers, no bodies, no query string.
type Call struct {
	Wall      string `json:"wall"`
	At        string `json:"at"`
	Session   string `json:"session"`
	Scenario  string `json:"scenario,omitempty"`
	Service   string `json:"service,omitempty"`
	Op        string `json:"op,omitempty"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Matched   bool   `json:"matched"`
	Reason    string `json:"reason,omitempty"`
	Fault     string `json:"fault,omitempty"`
	LatencyMS int    `json:"latency_ms,omitempty"`
}

const maxCallPath = 256

func (s *session) callSummary(e *journalEntry) Call {
	c := Call{Wall: e.Wall, At: e.At, Session: s.id, Scenario: s.scenario, Method: e.Method, Path: e.Path, Matched: e.Matched, Reason: e.Reason}
	if len(c.Path) > maxCallPath {
		c.Path = c.Path[:maxCallPath]
	}
	if e.Service != nil {
		c.Service = *e.Service
	}
	if e.Op != nil {
		c.Op = *e.Op
	}
	if e.Status != nil {
		c.Status = *e.Status
	}
	if e.Fault != nil {
		var parts []string
		if v, ok := e.Fault["status"].(int); ok {
			parts = append(parts, "status "+strconv.Itoa(v))
		}
		if v, ok := e.Fault["net_error"].(string); ok {
			parts = append(parts, "net_error "+v)
		}
		if v, ok := e.Fault["latency_ms"].(int); ok {
			c.LatencyMS = v
			parts = append(parts, "latency "+strconv.Itoa(v)+"ms")
		}
		c.Fault = strings.Join(parts, ", ")
	}
	return c
}

// SessionSummary describes one session for the console.
type SessionSummary struct {
	ID       string `json:"id"`
	Scenario string `json:"scenario,omitempty"`
	Clock    string `json:"clock"`
	Calls    int    `json:"calls"`
	Faults   string `json:"faults"`
}

// Sessions summarizes the sessions (default first, then by id; at most max).
func (m *Mock) Sessions(max int) []SessionSummary {
	m.mu.RLock()
	list := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s)
	}
	m.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		if (list[i].id == defaultSession) != (list[j].id == defaultSession) {
			return list[i].id == defaultSession
		}
		return list[i].id < list[j].id
	})
	if max > 0 && len(list) > max {
		list = list[:max]
	}
	out := make([]SessionSummary, 0, len(list))
	for _, s := range list {
		s.mu.Lock()
		out = append(out, SessionSummary{ID: s.id, Scenario: s.scenario, Clock: fmtTime(s.now), Calls: s.jseq, Faults: s.faults.Mode})
		s.mu.Unlock()
	}
	return out
}

// ServiceURL is one simulated service and the base URL that replaces the real one.
type ServiceURL struct {
	Name    string `json:"name"`
	Alias   string `json:"alias,omitempty"`
	BaseURL string `json:"base_url"`
}

// ServiceURLs lists the simulated services with their base URL under base
// (base/__svc/<service>).
func (m *Mock) ServiceURLs(base string) []ServiceURL {
	out := make([]ServiceURL, 0, len(m.model.services))
	for _, s := range m.model.services {
		seg := s.name
		if s.alias != "" {
			seg = s.alias
		} else if h, ok := strings.CutPrefix(s.name, "host:"); ok {
			seg = h
		}
		out = append(out, ServiceURL{Name: s.name, Alias: s.alias, BaseURL: base + svcPrefix + url.PathEscape(seg)})
	}
	return out
}

// Command is a control call queued by the console for this mock.
type Command struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// CommandResult is the answer of a command (its control API answer).
type CommandResult struct {
	ID     string          `json:"id"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// Report is what the mock posts to the console.
type Report struct {
	Instance  string           `json:"instance"`
	Version   string           `json:"version"`
	Group     string           `json:"group"`
	Status    string           `json:"status"` // waiting, serving, error
	Error     string           `json:"error,omitempty"`
	PackID    string           `json:"pack_id,omitempty"`
	PackError string           `json:"pack_error,omitempty"`
	PublicURL string           `json:"public_url"`
	Services  []ServiceURL     `json:"services"`
	Sessions  []SessionSummary `json:"sessions"`
	Calls     []Call           `json:"calls"`
	Dropped   int              `json:"dropped_calls,omitempty"`
	Results   []CommandResult  `json:"results,omitempty"`
	StartedAt string           `json:"started_at"`
}

// ReportAnswer is the console's answer to a report.
type ReportAnswer struct {
	// PackID is the latest published pack of the group ("" when none).
	PackID   string    `json:"pack_id"`
	Commands []Command `json:"commands"`
	// IntervalS, when > 0, sets the next report period.
	IntervalS int `json:"interval_s,omitempty"`
	// Held: the console held the answer (long poll) until something
	// happened or an interval passed; the mock reports again at once.
	Held bool `json:"held,omitempty"`
	// Identity is the group's "session per user" setting (mock.md 2.6),
	// absent when the console has none (the local flags then apply).
	Identity *IdentityWire `json:"identity,omitempty"`
	// Pages are the group's third-party pages (mock.md 9), absent when the
	// console has none (the local --pages file then applies).
	Pages *PagesConfig `json:"pages,omitempty"`
}

// IdentityWire is the identity session setting as the console sends it:
// the hashing key (base64url, the group's own, stable across restarts) and
// the map with hashed users only ("h:" + IdentityHash).
type IdentityWire struct {
	Header string            `json:"header"`
	Claim  string            `json:"claim,omitempty"`
	Key    string            `json:"key,omitempty"`
	Map    map[string]string `json:"map,omitempty"`
}

// Config converts the wire form (nil when the setting is off).
func (w *IdentityWire) Config() (*IdentityConfig, error) {
	if w == nil || w.Header == "" {
		return nil, nil
	}
	c := &IdentityConfig{Header: w.Header, Claim: w.Claim, Map: w.Map}
	if w.Key != "" {
		k, err := base64.RawURLEncoding.DecodeString(w.Key)
		if err != nil {
			return nil, errors.New("mock: identity key from the console is not base64url")
		}
		c.Key = k
	}
	return c, c.Validate()
}

const (
	maxPendingCalls   = 500
	maxReportSessions = 100
	maxResultBody     = 64 << 10
	maxPackDownload   = 1 << 30
)

// consoleRunner is the state of a mock in console mode.
type consoleRunner struct {
	cfg    Config
	cc     ConsoleConfig
	hc     *http.Client
	keys   pack.KeySet
	cur    atomic.Pointer[Mock]
	start  time.Time
	public string

	mu        sync.Mutex
	calls     []Call
	dropped   int
	results   []CommandResult
	packError string
	// identityApplied is the last identity setting applied (JSON), loop only.
	identityApplied string
	// pagesApplied is the last pages configuration applied (JSON).
	pagesApplied string
}

// ServeHTTP serves the current pack, or only the health check while the
// first pack has not arrived.
func (r *consoleRunner) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if m := r.cur.Load(); m != nil {
		m.Handler().ServeHTTP(w, req)
		return
	}
	if req.URL.Path == "/__tt/health" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	}
	writeError(w, http.StatusServiceUnavailable, "no_pack", "the mock is waiting for the first published pack of its group from the console")
}

func (r *consoleRunner) onCall(c Call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) >= maxPendingCalls {
		r.calls = r.calls[1:]
		r.dropped++
	}
	r.calls = append(r.calls, c)
}

// RunConsole runs the mock in console mode until ctx ends. cfg.Pack is
// ignored: the packs come from the console.
func RunConsole(ctx context.Context, cfg Config, cc ConsoleConfig) error {
	cfg.Pack = "console"
	if err := cfg.applyDefaults(); err != nil {
		return err
	}
	if err := cc.validate(); err != nil {
		return err
	}
	keys := cfg.Keys
	if cfg.GatePubKeys != "" {
		var err error
		if keys, err = pack.ParseKeySet(cfg.GatePubKeys); err != nil {
			return err
		}
	}
	if len(keys) == 0 {
		var err error
		if keys, err = pack.KeySetFromEnv(); err != nil {
			return err
		}
	}
	cfg.Keys, cfg.GatePubKeys = keys, ""
	if cfg.ControlToken == "" {
		// The console drives the control API through the report channel;
		// direct calls to /__tt/ need a TT_CONTROL_TOKEN set by the user.
		var b [24]byte
		_, _ = rand.Read(b[:])
		cfg.ControlToken = hex.EncodeToString(b[:])
		cfg.Logger.Info("no TT_CONTROL_TOKEN: the control API /__tt/ is driven by the console only")
	}
	hc, err := cc.client()
	if err != nil {
		return err
	}
	ln := cfg.Listener
	if ln == nil {
		if ln, err = net.Listen("tcp", cfg.Addr); err != nil {
			return err
		}
	}
	r := &consoleRunner{cfg: cfg, cc: cc, hc: hc, keys: keys, start: time.Now().UTC()}
	r.public = cc.PublicURL
	if r.public == "" {
		r.public = "http://" + ln.Addr().String()
	}
	r.cfg.OnCall = r.onCall
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	cfg.Logger.Info("mock in console mode", "console", cc.URL, "group", cc.Group, "addr", ln.Addr().String(), "instance", cc.Instance)
	if cfg.OnListen != nil {
		cfg.OnListen(ln.Addr())
	}
	loopErr := make(chan error, 1)
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { loopErr <- r.loop(lctx) }()
	if cfg.SessionIdleTTL > 0 {
		t := time.NewTicker(min(time.Minute, cfg.SessionIdleTTL))
		defer t.Stop()
		go func() {
			for {
				select {
				case <-lctx.Done():
					return
				case <-t.C:
					if m := r.cur.Load(); m != nil {
						m.EvictIdle()
					}
				}
			}
		}()
	}
	var out error
	select {
	case out = <-errc:
	case out = <-loopErr:
	case <-ctx.Done():
	}
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = srv.Shutdown(sctx)
	return out
}

// loop fetches the first pack, then reports every interval and follows the
// console's answers (new pack, commands).
func (r *consoleRunner) loop(ctx context.Context) error {
	interval := r.cc.Interval
	backoff := interval
	for {
		ans, err := r.report(ctx)
		switch {
		case errors.Is(err, ErrTokenRefused):
			r.cfg.Logger.Error("the console refused the mock token: stopping", "console", r.cc.URL)
			return err
		case err != nil:
			r.cfg.Logger.Warn("console not reachable, retrying", "err", err.Error())
			backoff = min(backoff*2, 2*time.Minute)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			continue
		}
		backoff = interval
		if ans.IntervalS > 0 && ans.IntervalS <= 300 {
			interval = time.Duration(ans.IntervalS) * time.Second
		}
		r.applyIdentity(ans.Identity)
		r.applyPages(ans.Pages)
		if cur := r.cur.Load(); ans.PackID != "" && (cur == nil || cur.PackID() != ans.PackID) && r.packErrorFor() != ans.PackID {
			if err := r.fetch(ctx, ans.PackID); errors.Is(err, ErrTokenRefused) {
				return err
			} else if err != nil {
				r.cfg.Logger.Error("new pack refused, keeping the current one", "pack_id", ans.PackID, "err", err.Error())
			}
			continue // report the new state right away
		}
		if len(ans.Commands) > 0 {
			r.run(ans.Commands)
			continue // send the results right away
		}
		if ans.Held {
			// the console already waited: a short pause, not a full interval
			if !sleepCtx(ctx, 100*time.Millisecond) {
				return nil
			}
			continue
		}
		if !sleepCtx(ctx, interval) {
			return nil
		}
	}
}

// applyIdentity follows the console's identity setting: it replaces the
// local one on the current mock and on the next packs.
func (r *consoleRunner) applyIdentity(w *IdentityWire) {
	if w == nil {
		return
	}
	b, _ := json.Marshal(w)
	if string(b) == r.identityApplied {
		return
	}
	c, err := w.Config()
	if err != nil {
		r.cfg.Logger.Error("identity setting from the console refused", "err", err.Error())
		return
	}
	r.cfg.Identity = c
	if m := r.cur.Load(); m != nil {
		if err := m.SetIdentity(c); err != nil {
			r.cfg.Logger.Error("identity setting from the console refused", "err", err.Error())
			return
		}
	}
	r.identityApplied = string(b)
	if c != nil {
		r.cfg.Logger.Info("session per user from the console", "header", c.Header, "claim", c.Claim, "mapped_users", len(c.Map))
	} else {
		r.cfg.Logger.Info("session per user turned off by the console")
	}
}

// applyPages follows the console's third-party pages: they replace the
// local ones on the current mock and on the next packs.
func (r *consoleRunner) applyPages(c *PagesConfig) {
	if c == nil {
		return
	}
	b, _ := json.Marshal(c)
	if string(b) == r.pagesApplied {
		return
	}
	if err := c.Validate(); err != nil {
		r.cfg.Logger.Error("third-party pages from the console refused", "err", err.Error())
		return
	}
	r.cfg.Pages = c
	if m := r.cur.Load(); m != nil {
		_ = m.SetPages(c)
	}
	r.pagesApplied = string(b)
	r.cfg.Logger.Info("third-party pages from the console", "pages", len(c.Pages))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// packErrorFor is the pack id the last refusal was about ("" none): a
// refused pack is not downloaded again at every report.
func (r *consoleRunner) packErrorFor() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, _, _ := strings.Cut(r.packError, ":")
	return id
}

func (r *consoleRunner) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.cc.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.cc.Token)
	req.Header.Set("User-Agent", "tt-mock/"+r.version())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, ErrTokenRefused
	}
	return resp, nil
}

func (r *consoleRunner) version() string {
	if r.cc.Version != "" {
		return r.cc.Version
	}
	return Version
}

// fetch downloads, verifies and swaps in the pack want ("" any).
func (r *consoleRunner) fetch(ctx context.Context, want string) error {
	resp, err := r.do(ctx, http.MethodGet, AgentPackPath, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("no published pack for the group yet")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pack download: status %d", resp.StatusCode)
	}
	id := resp.Header.Get(HeaderPackID)
	refuse := func(err error) error {
		about := id
		if about == "" {
			about = want // remembered, so the same pack is not downloaded again
		}
		r.mu.Lock()
		r.packError = about + ": " + err.Error()
		r.mu.Unlock()
		return err
	}
	if id == "" {
		// mock.md 6.2: the console announces the pack it sends; a pack
		// without its id is not the announced one.
		return refuse(errors.New("the console sent a pack without " + HeaderPackID + ": refused"))
	}
	f, err := os.CreateTemp(r.cc.TempDir, "tt-mock-*.ttpack")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxPackDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxPackDownload {
		return refuse(errors.New("pack larger than 1 GiB"))
	}
	cfg := r.cfg
	cfg.Pack = name
	m, err := New(cfg)
	if err != nil {
		return refuse(err)
	}
	man := m.Manifest()
	if man.Group != r.cc.Group {
		got := man.Group
		if got == "" {
			got = "(every group)"
		}
		return refuse(fmt.Errorf("pack %s belongs to group %s, not %s: refused", man.PackID, got, r.cc.Group))
	}
	if id != man.PackID {
		return refuse(fmt.Errorf("the console announced pack %s but sent %s: refused", id, man.PackID))
	}
	if want != "" && man.PackID != want {
		r.cfg.Logger.Info("the console sent a newer pack than announced", "pack_id", man.PackID)
	}
	old := r.cur.Swap(m)
	r.mu.Lock()
	r.packError = ""
	r.mu.Unlock()
	if old != nil {
		r.cfg.Logger.Info("pack replaced: sessions start again from the new pack", "old", old.PackID(), "pack_id", man.PackID)
	} else {
		r.cfg.Logger.Info("mock serving", "pack_id", man.PackID, "services", len(m.model.services))
	}
	return nil
}

// report posts the state and returns the console's answer.
func (r *consoleRunner) report(ctx context.Context) (*ReportAnswer, error) {
	rep := Report{Instance: r.cc.Instance, Version: r.version(), Group: r.cc.Group, Status: "waiting", PublicURL: r.public,
		Services: []ServiceURL{}, Sessions: []SessionSummary{}, StartedAt: r.start.Format(time.RFC3339)}
	if m := r.cur.Load(); m != nil {
		rep.Status, rep.PackID = "serving", m.PackID()
		rep.Services = m.ServiceURLs(r.public)
		rep.Sessions = m.Sessions(maxReportSessions)
	}
	r.mu.Lock()
	calls, dropped, results := r.calls, r.dropped, r.results
	r.calls, r.dropped, r.results = nil, 0, nil
	rep.PackError = r.packError
	r.mu.Unlock()
	rep.Calls, rep.Dropped, rep.Results = calls, dropped, results
	if rep.Calls == nil {
		rep.Calls = []Call{}
	}
	restore := func() {
		r.mu.Lock()
		r.calls = append(calls, r.calls...)
		if len(r.calls) > maxPendingCalls {
			r.dropped += len(r.calls) - maxPendingCalls
			r.calls = r.calls[len(r.calls)-maxPendingCalls:]
		}
		r.dropped += dropped
		r.results = append(results, r.results...)
		r.mu.Unlock()
	}
	body, _ := json.Marshal(rep)
	resp, err := r.do(ctx, http.MethodPost, AgentReportPath, body)
	if err != nil {
		if !errors.Is(err, ErrTokenRefused) {
			restore()
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		restore()
		return nil, fmt.Errorf("report: status %d", resp.StatusCode)
	}
	var ans ReportAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ans); err != nil {
		return nil, fmt.Errorf("report: bad answer: %w", err)
	}
	return &ans, nil
}

// run executes the console's commands on the control API of the current
// pack, as an authenticated control client.
func (r *consoleRunner) run(cmds []Command) {
	m := r.cur.Load()
	for _, c := range cmds {
		res := CommandResult{ID: c.ID}
		switch {
		case m == nil:
			res.Status, res.Body = http.StatusServiceUnavailable, json.RawMessage(`{"code":"no_pack","message":"no pack loaded yet"}`)
		case !commandPathRE.MatchString(c.Path) || !validCommandMethod(c.Method):
			res.Status, res.Body = http.StatusBadRequest, json.RawMessage(`{"code":"bad_command","message":"this control call is not allowed from the console"}`)
		default:
			var body io.Reader = http.NoBody
			if len(c.Body) > 0 {
				body = bytes.NewReader(c.Body)
			}
			req := httptest.NewRequest(c.Method, c.Path, body)
			req.Header.Set("Authorization", "Bearer "+r.cfg.ControlToken)
			if len(c.Body) > 0 {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			m.Handler().ServeHTTP(rec, req)
			res.Status = rec.Code
			b := bytes.TrimSpace(rec.Body.Bytes())
			if len(b) > maxResultBody || !json.Valid(b) {
				b = []byte(`{"code":"too_large","message":"the answer is too large to show in the console"}`)
			}
			if len(b) > 0 {
				res.Body = json.RawMessage(b)
			}
		}
		r.mu.Lock()
		r.results = append(r.results, res)
		r.mu.Unlock()
	}
}

func validCommandMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}
