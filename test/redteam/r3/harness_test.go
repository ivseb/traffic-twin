package r3_rt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

const testPassword = "correct-horse-battery-1"

// offClock is real time plus an offset that tests can only move forward
// (session timeouts; Dex tokens keep real iat/exp).
type offClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *offClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().UTC().Add(c.off)
}
func (c *offClock) Advance(d time.Duration) { c.mu.Lock(); c.off += d; c.mu.Unlock() }

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// session is a cookie + CSRF pair on the admin API.
type session struct {
	t      testing.TB
	base   string
	hc     *http.Client
	cookie string
	csrf   string
	name   string
}

func (s *session) req(method, path string, body any) (int, []byte) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
		req.Header.Set(auth.CSRFHeader, s.csrf)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (s *session) must(want int, method, path string, body any) []byte {
	s.t.Helper()
	code, b := s.req(method, path, body)
	if code != want {
		s.t.Fatalf("[%s] %s %s = %d (want %d): %.500s", s.name, method, path, code, want, b)
	}
	return b
}

func (s *session) json(want int, method, path string, body, out any) {
	s.t.Helper()
	b := s.must(want, method, path, body)
	if err := json.Unmarshal(b, out); err != nil {
		s.t.Fatalf("%s %s: %v: %.300s", method, path, err, b)
	}
}

func errCodeOf(b []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Code
}

// coreEnv is a composed tt-core (real HTTP, TLS) with a restartable
// in-process keyguard on a fixed Unix socket.
type coreEnv struct {
	t       *testing.T
	ctx     context.Context
	cancel  context.CancelFunc
	clock   *offClock // tt-core
	kgClock *offClock
	kgDir   string
	kgTune  func(*keyguard.Config)
	kg      *core.DevKeyguard
	core    *core.Core
	dir     string
	base    string
	hc      *http.Client
	pool    *x509.CertPool
	coreLog *lockedBuf
	kgLog   *lockedBuf
	cfg     *config.Config
	users   map[string]*session
	ids     map[string]string
	hmac    sanitizer.KeySet
}

type envOpts struct {
	// cfg adjusts the tt-core configuration (OIDC, session timeouts).
	cfg func(*config.Config)
	// kg adjusts keyguard's configuration (OIDC verification).
	kg func(*keyguard.Config)
	// policyKey, when set, is written as keys/policy.key before start.
	policyKey string
	// team lists local users to create (name -> roles).
	team map[string][]string
	// adminAddr, when set, is the admin listener address (OIDC redirect URL).
	adminAddr string
}

func newCoreEnv(t *testing.T, o envOpts) *coreEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e := &coreEnv{t: t, ctx: ctx, cancel: cancel, clock: &offClock{}, kgClock: &offClock{}, coreLog: &lockedBuf{}, kgLog: &lockedBuf{},
		users: map[string]*session{}, ids: map[string]string{}, kgTune: o.kg}
	var err error
	// Short directory: the socket path must fit in sun_path.
	e.kgDir, err = os.MkdirTemp("", "rt3kg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.kgDir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if o.policyKey != "" {
		writeFile(t, filepath.Join(e.kgDir, "keys", "policy.key"), o.policyKey)
	}
	e.startKG()
	hk, _ := os.ReadFile(filepath.Join(e.kgDir, "keys", "hmac.keys"))
	if e.hmac, err = sanitizer.ParseKeys(string(hk)); err != nil {
		t.Fatal(err)
	}
	e.dir = t.TempDir()
	if o.adminAddr == "" {
		o.adminAddr = "127.0.0.1:0"
	}
	adminLn, err := net.Listen("tcp", o.adminAddr)
	if err != nil {
		t.Fatal(err)
	}
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(e.dir, e.kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fleet.PublicURL = "https://" + intakeLn.Addr().String()
	cfg.Fleet.HeartbeatInterval, cfg.Fleet.PolicyPollInterval = 50*time.Millisecond, 50*time.Millisecond
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Miner.Schedule = 0
	cfg.Log.Level = "debug"
	e.base = "https://" + adminLn.Addr().String()
	if o.cfg != nil {
		o.cfg(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	e.cfg = cfg
	e.core, err = core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-rt3", AdminListener: adminLn, IntakeListener: intakeLn,
		Now: e.clock.Now, Logger: server.NewLogger(e.coreLog, "debug", "json"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.core.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
		if e.kg != nil {
			_ = e.kg.Close()
		}
		_ = os.RemoveAll(e.kgDir)
	})
	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	e.pool = x509.NewCertPool()
	e.pool.AppendCertsFromPEM(pem)
	e.hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	eventually(t, 5*time.Second, "readyz", func() bool {
		resp, err := e.hc.Get(e.base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	if cfg.Auth.Local.Enabled {
		ada := e.signIn("/api/v1/setup", map[string]string{"setup_token": e.core.SetupToken(), "username": "ada", "password": testPassword}, "ada")
		e.users["ada"] = ada
		for name, roles := range o.team {
			ada.must(201, "POST", "/api/v1/users", map[string]any{"username": name, "password": testPassword, "roles": roles})
			e.users[name] = e.login(name)
		}
		var ul []map[string]any
		ada.json(200, "GET", "/api/v1/users", nil, &ul)
		for _, u := range ul {
			e.ids[fmt.Sprint(u["username"])] = fmt.Sprint(u["id"])
		}
	}
	return e
}

func (e *coreEnv) startKG() {
	e.t.Helper()
	var err error
	e.kg, err = core.StartDevKeyguard(context.Background(), core.DevKeyguardOptions{Dir: e.kgDir, Now: e.kgClock.Now,
		Logger: keyguard.NewLogger(e.kgLog, "debug", "json"),
		Tune: func(c *keyguard.Config) {
			c.MatchInterval, c.PackInterval, c.BloomCapacity = 0, 0, 20000
			c.Socket = filepath.Join(e.kgDir, "kg.sock")
			if e.kgTune != nil {
				e.kgTune(c)
			}
		}})
	if err != nil {
		e.t.Fatalf("keyguard: %v", err)
	}
}

// restartKG stops keyguard, lets the caller change key files, and starts it
// again on the same socket and database.
func (e *coreEnv) restartKG(between func(keysDir string), tune func(*keyguard.Config)) {
	e.t.Helper()
	if err := e.kg.Close(); err != nil {
		e.t.Logf("keyguard close: %v", err)
	}
	_ = os.Remove(filepath.Join(e.kgDir, "kg.sock"))
	if between != nil {
		between(filepath.Join(e.kgDir, "keys"))
	}
	prev := e.kgTune
	e.kgTune = func(c *keyguard.Config) {
		if prev != nil {
			prev(c)
		}
		if tune != nil {
			tune(c)
		}
	}
	e.startKG()
}

func (e *coreEnv) signIn(path string, body map[string]string, name string) *session {
	e.t.Helper()
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.base+path, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		e.t.Fatalf("sign in %s: %d %s", name, resp.StatusCode, b)
	}
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(b, &me)
	s := &session{t: e.t, base: e.base, hc: e.hc, name: name, csrf: me.CSRF}
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "tt_session") {
			s.cookie = c.Name + "=" + c.Value
		}
	}
	return s
}

func (e *coreEnv) login(name string) *session {
	return e.signIn("/api/v1/auth/login", map[string]string{"username": name, "password": testPassword}, name)
}

// relogin signs every stored user in again: tt-core's auth follows the
// virtual clock, so advancing it past the session timeouts ends the sessions.
func (e *coreEnv) relogin() {
	for name := range e.users {
		e.users[name] = e.login(name)
	}
}

// u rebinds a stored session to the current test.
func (e *coreEnv) u(t *testing.T, name string) *session { s := *e.users[name]; s.t = t; return &s }

// jarClient is a browser-like client (cookie jar, no auto redirects) that
// trusts tt-core's certificate.
func (e *coreEnv) jarClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func eventually(t testing.TB, d time.Duration, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Fleet helpers

type pv struct {
	PolicyID     string `json:"policy_id"`
	Version      int64  `json:"version"`
	Status       string `json:"status"`
	ApprovalMode string `json:"approval_mode"`
}

// group creates a group bound to policy pid, a starter policy approved by
// the admin, and returns an enrollment token.
func (e *coreEnv) group(name, pid string) string {
	e.t.Helper()
	ada := e.u(e.t, "olga")
	ada.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": name, "allowed_service_names": []string{"shop-api"}, "policy_id": pid})
	var v pv
	ada.json(201, "POST", "/api/v1/fleet/groups/"+name+"/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10"}, &v)
	e.adminApprove(v.PolicyID, v.Version)
	var tok struct {
		Token string `json:"token"`
	}
	ada.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": name, "token_type": "one_time"}, &tok)
	return tok.Token
}

func (e *coreEnv) adminApprove(pid string, ver int64) []byte {
	// An observe-safe version (policy.md 7, spec v1.6) is already active:
	// keyguard signed it without approvals.
	b := e.u(e.t, "ada").must(200, "GET", fmt.Sprintf("/api/v1/fleet/policies/%s/versions/%d", pid, ver), nil)
	var cur pv
	_ = json.Unmarshal(b, &cur)
	if cur.Status == "active" && cur.ApprovalMode == "observe" {
		return b
	}
	return e.u(e.t, "ada").must(200, "POST", fmt.Sprintf("/api/v1/fleet/policies/%s/versions/%d/approve", pid, ver), map[string]any{"reason": "rt3 trial"})
}

func (e *coreEnv) source(tok, instance string) *sourceclient.Source {
	e.t.Helper()
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: e.cfg.Fleet.PublicURL, Token: tok, StateDir: filepath.Join(e.dir, "src-"+instance),
		Kind: "sdk-go", Version: "0.1.0", ServiceName: "shop-api", Instance: instance, Keys: e.hmac, KeyKids: []string{core.DevHMACKid},
		HeartbeatInterval: 40 * time.Millisecond, PolicyPollInterval: 40 * time.Millisecond, Now: e.clock.Now,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	src.Start(e.ctx)
	eventually(e.t, 10*time.Second, "source capturing", func() bool { _, ok := src.Active(); return ok })
	return src
}

// propose proposes an author policy (JSON form of tt.policy/v1).
func (e *coreEnv) propose(author string) pv {
	e.t.Helper()
	var v pv
	e.u(e.t, "olga").json(201, "POST", "/api/v1/fleet/policies", json.RawMessage(author), &v)
	return v
}
