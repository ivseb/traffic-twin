// Package frameworks_rt red-teams the SDK framework integrations (red team
// round 3, scope item 5): one real application per stack, built in Docker
// with the SDK exactly as it is deployed (init images of deploy/images, or
// the PHP package), talking to a REAL tt-core started in this process (dev
// keyguard on a Unix socket, intake on 0.0.0.0 behind a switchable TCP
// proxy, reached by the containers as host.docker.internal).
//
// Run (Docker required):
//
//	TT_RT_FRAMEWORKS=1 go test ./test/redteam/frameworks/   # after build_images.sh
//	test/redteam/frameworks/run_all.sh                 # build + every stack
//	test/redteam/frameworks/<stack>/run.sh             # build + one stack
//	RT3FW_STACKS=node,python go test ./test/redteam/frameworks/ -count=1 -v -timeout 40m
//
// Every app (java = Spring Boot + -javaagent, dotnet = ASP.NET Core +
// DOTNET_STARTUP_HOOKS, python = FastAPI + traffic_twin.install, php =
// Symfony + SymfonySubscriber + tt-shipper, node = Express + --import
// register) serves the same contract on :8080:
//
//	GET  /health                   200 "ok"
//	POST /orders/{id}?ref=…        201 {"id","status":"created","echo":body.secret,"email":body.nested.email}
//	                               + x-echo: <x-secret>, set-cookie sess=<body.secret>
//	GET  /fail/{v}                 500 {"error":{"code":"E_FAIL","message":"order <v> failed"}}
//	GET  /boom/{v}                 unhandled exception "boom <v>" (framework default 500)
//
// The apps never log request data themselves (framework access logs are off
// or filtered). Canaries are random per request and sit only in values:
// path, query, request headers, cookies, authorization (JWT sub), JSON body
// (one field the policy keeps, $.keepme), response body, response headers,
// set-cookie, error message, exception message.
//
// For each stack:
//
//	TestFW/<stack>/capture    (a) no canary in the app's stdout/stderr (the
//	                           exception canary excepted: the framework itself
//	                           logs it) or in the SDK state/spool directory,
//	                           except the kept field in sanitized events;
//	                          (b) no canary in what tt-core stored (events
//	                           export, raw scan of every tt-core data file,
//	                           tt-core log) except the kept field, which MUST
//	                           be present (otherwise capture is broken);
//	TestFW/<stack>/core_down  (c) same status codes and bodies as with the SDK
//	                           disabled, bounded latency and start-up time, no
//	                           extra canary in the logs, with tt-core refusing
//	                           connections and with a TCP server that accepts
//	                           and never answers, from app start-up;
//	TestFW/<stack>/core_lost  (c) the same when tt-core is lost while the SDK
//	                           is capturing (proxy switched to blackhole, then
//	                           to reset), then back: capture resumes.
//
// Every value is invented.
package frameworks_rt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/server"
)

const testPassword = "correct-horse-battery-1"

var allStacks = []string{"java", "dotnet", "python", "php", "node"}

// The policy keeps exactly one request field ($.keepme) and the response
// status (a constant); everything else is dropped by default.
func authorPolicy() string {
	svcs := []string{}
	for _, s := range allStacks {
		svcs = append(svcs, fmt.Sprintf(`"fw-%s":{"match":{"inbound":true},"ops":{
  "POST /orders/{id}":{"request":{"path":{"id":"hmac(order)"},"body":{"$.keepme":"keep"}},"response":{"$.status":"keep"}},
  "GET /fail/{v}":{"request":{"path":{"v":"hmac(order)"}}}}}`, s))
	}
	return `{"format":"tt.policy/v1","policy_id":"p-fw","default":"drop",
 "hmac":{"kid":"` + core.DevHMACKid + `","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "sampling":{"rate":1},
 "global":{"errors":{"body":{"$.error.code":"keep"}}},
 "services":{` + strings.Join(svcs, ",") + `}}`
}

// ---------------------------------------------------------------------------
// Admin API session

type session struct {
	base   string
	hc     *http.Client
	cookie string
	csrf   string
}

func (s *session) do(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
		req.Header.Set(auth.CSRFHeader, s.csrf)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func (s *session) must(t testing.TB, want int, method, path string, body any, out any) []byte {
	t.Helper()
	code, b, err := s.do(method, path, body)
	if err != nil || code != want {
		t.Fatalf("%s %s = %d (want %d) %v: %.500s", method, path, code, want, err, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return b
}

func signIn(t testing.TB, base string, hc *http.Client, path string, body map[string]string) *session {
	t.Helper()
	j, _ := json.Marshal(body)
	resp, err := hc.Post(base+path, "application/json", bytes.NewReader(j))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(b, &me)
	s := &session{base: base, hc: hc, csrf: me.CSRF}
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "tt_session") {
			s.cookie = c.Name + "=" + c.Value
		}
	}
	if s.cookie == "" {
		t.Fatalf("sign in %s: %d %s", path, resp.StatusCode, b)
	}
	return s
}

// ---------------------------------------------------------------------------
// Switchable TCP proxy in front of the intake: normal, blackhole (accept and
// hold, forward nothing in either direction) or reset (close everything).

const (
	modeNormal int32 = iota
	modeBlackhole
	modeReset
)

type proxy struct {
	ln     net.Listener
	target string
	mode   atomic.Int32
	mu     sync.Mutex
	conns  map[net.Conn]bool
}

func newProxy(target string) (*proxy, error) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	p := &proxy{ln: ln, target: target, conns: map[net.Conn]bool{}}
	go p.serve()
	return p, nil
}

func (p *proxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *proxy) track(c net.Conn, on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if on {
		p.conns[c] = true
	} else {
		delete(p.conns, c)
	}
}

func (p *proxy) set(m int32) {
	p.mode.Store(m)
	if m == modeReset {
		p.mu.Lock()
		for c := range p.conns {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			c.Close()
		}
		p.mu.Unlock()
	}
}

func (p *proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		switch p.mode.Load() {
		case modeReset:
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			c.Close()
			continue
		case modeBlackhole:
			p.track(c, true) // held open, never answered
			continue
		}
		up, err := net.Dial("tcp", p.target)
		if err != nil {
			c.Close()
			continue
		}
		p.track(c, true)
		p.track(up, true)
		go p.pump(up, c)
		go p.pump(c, up)
	}
}

// pump copies src to dst; while the proxy is a blackhole it forwards nothing
// (the data waits), on reset the connections are closed by set.
func (p *proxy) pump(dst, src net.Conn) {
	defer func() { dst.Close(); src.Close(); p.track(dst, false); p.track(src, false) }()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			for p.mode.Load() == modeBlackhole {
				time.Sleep(20 * time.Millisecond)
			}
			if p.mode.Load() == modeReset {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// The tt-core environment (one per test binary)

type env struct {
	core      *core.Core
	kg        *core.DevKeyguard
	dir       string
	kgDir     string
	proxy     *proxy
	intakePub string // https://host.docker.internal:<proxy port>
	token     string // k8s-inject group token, any sdk-* kind
	hmacKey   string // content of the dev HMAC key file
	admin     *session
	operator  *session
	exporter  *session
	coreLog   *lockedBuf
}

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

var (
	envOnce sync.Once
	theEnv  *env
	envErr  error
)

func getEnv(t *testing.T) *env {
	t.Helper()
	envOnce.Do(func() { theEnv, envErr = buildEnv(t) })
	if envErr != nil {
		t.Fatalf("environment: %v", envErr)
	}
	return theEnv
}

type fatalErr struct{ msg string }

type buildT struct{ testing.TB }

func (b *buildT) Fatal(args ...any)                 { panic(fatalErr{fmt.Sprint(args...)}) }
func (b *buildT) Fatalf(format string, args ...any) { panic(fatalErr{fmt.Sprintf(format, args...)}) }
func (b *buildT) Helper()                           {}

func buildEnv(t *testing.T) (e *env, err error) {
	defer func() {
		if r := recover(); r != nil {
			if fe, ok := r.(fatalErr); ok {
				err = fmt.Errorf("%s", fe.msg)
				return
			}
			panic(r)
		}
	}()
	bt := &buildT{TB: t}
	ctx := context.Background()
	e = &env{coreLog: &lockedBuf{}}
	if e.kgDir, err = os.MkdirTemp("", "rt3fwkg"); err != nil {
		return nil, err
	}
	e.kg, err = core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: e.kgDir,
		Logger: keyguard.NewLogger(io.Discard, "warn", "text")})
	if err != nil {
		return nil, err
	}
	hk, err := os.ReadFile(e.kg.HMACKeyFile)
	if err != nil {
		return nil, err
	}
	e.hmacKey = strings.TrimSpace(string(hk))

	if e.dir, err = os.MkdirTemp("", "rt3fwcore"); err != nil {
		return nil, err
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	intakeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	// The containers reach the intake through the proxy, on every interface
	// (host.docker.internal on Docker Desktop, the host gateway on Linux).
	if e.proxy, err = newProxy(intakeLn.Addr().String()); err != nil {
		return nil, err
	}
	cfg, err := core.DevConfig(e.dir, e.kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		return nil, err
	}
	e.intakePub = fmt.Sprintf("https://host.docker.internal:%d", e.proxy.port())
	cfg.Fleet.PublicURL = e.intakePub
	cfg.Fleet.HeartbeatInterval, cfg.Fleet.PolicyPollInterval = time.Second, time.Second
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Miner.Schedule = 0
	e.core, err = core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-rt3fw", AdminListener: adminLn, IntakeListener: intakeLn,
		Logger:         server.NewLogger(e.coreLog, "info", "json"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		return nil, err
	}
	go func() { _ = e.core.Run(ctx) }()

	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "https://" + adminLn.Addr().String()
	waitUntil(bt, 10*time.Second, "readyz", func() bool {
		r, err := hc.Get(base + "/readyz")
		if err != nil {
			return false
		}
		r.Body.Close()
		return r.StatusCode == 200
	})
	e.admin = signIn(bt, base, hc, "/api/v1/setup", map[string]string{"setup_token": e.core.SetupToken(), "username": "ada", "password": testPassword})
	for name, roles := range map[string][]string{"olga": {"operator"}, "eve": {"event-exporter"}} {
		e.admin.must(bt, 201, "POST", "/api/v1/users", map[string]any{"username": name, "password": testPassword, "roles": roles}, nil)
	}
	e.operator = signIn(bt, base, hc, "/api/v1/auth/login", map[string]string{"username": "olga", "password": testPassword})
	e.exporter = signIn(bt, base, hc, "/api/v1/auth/login", map[string]string{"username": "eve", "password": testPassword})

	names := []string{}
	for _, s := range allStacks {
		names = append(names, "fw-"+s)
	}
	e.operator.must(bt, 201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "fw", "allowed_service_names": names, "policy_id": "p-fw"}, nil)
	var pv struct {
		Version int64 `json:"version"`
	}
	e.operator.must(bt, 201, "POST", "/api/v1/fleet/policies", authorPolicy(), &pv)
	e.admin.must(bt, 200, "POST", fmt.Sprintf("/api/v1/fleet/policies/p-fw/versions/%d/approve", pv.Version), map[string]any{"reason": "red team round 3 trial"}, nil)
	var tok struct {
		Token string `json:"token"`
	}
	e.operator.must(bt, 201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "k8s-inject", "group": "fw", "token_type": "group"}, &tok)
	e.token = tok.Token
	return e, nil
}

func waitUntil(t testing.TB, d time.Duration, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type sourceView struct {
	SourceID    string `json:"source_id"`
	ServiceName string `json:"service_name"`
	State       string `json:"state"`
	LastErrors  []struct {
		Code string `json:"code"`
	} `json:"last_errors"`
}

func (e *env) sources(t testing.TB) []sourceView {
	code, b, err := e.operator.do("GET", "/api/v1/fleet/sources", nil)
	if err != nil || code != 200 {
		t.Fatalf("sources: %d %v %s", code, err, b)
	}
	var out []sourceView
	if err := json.Unmarshal(b, &out); err != nil {
		var wrap struct {
			Items []sourceView `json:"items"`
		}
		if err2 := json.Unmarshal(b, &wrap); err2 != nil {
			t.Fatalf("sources: %v: %.300s", err, b)
		}
		out = wrap.Items
	}
	return out
}

// exportEvents returns the jsonl export of every stored event.
func (e *env) exportEvents(t testing.TB) []byte {
	var job struct {
		JobID string `json:"job_id"`
	}
	e.exporter.must(t, 202, "POST", "/api/v1/events/export", map[string]any{
		"from": time.Now().Add(-48 * time.Hour).UTC(), "to": time.Now().Add(48 * time.Hour).UTC(), "format": "jsonl"}, &job)
	return e.exporter.must(t, 200, "GET", "/api/v1/events/export/"+job.JobID+"/download", nil, nil)
}

// eventsOf returns the exported events of one service (raw lines).
func eventsOf(export []byte, service string) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(export, []byte("\n")) {
		var ev struct {
			Service string `json:"service"`
		}
		if json.Unmarshal(line, &ev) == nil && ev.Service == service {
			out = append(out, line)
		}
	}
	return out
}

// rawCoreFiles returns every file of the tt-core data directory (database,
// WAL, exports, certificates): a canary there is stored data.
func (e *env) rawCoreFiles(t testing.TB) map[string][]byte {
	out := map[string][]byte{}
	_ = filepath.Walk(e.dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if b, err := os.ReadFile(p); err == nil {
				out[p] = b
			}
		}
		return nil
	})
	return out
}

// ---------------------------------------------------------------------------
// Docker

func docker(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

type container struct {
	name string
	port int // host port mapped to 8080
}

func startApp(t *testing.T, stack, name string, envs map[string]string) *container {
	t.Helper()
	_, _ = docker("rm", "-f", name)
	args := []string{"run", "-d", "--name", name, "--add-host", "host.docker.internal:host-gateway", "-p", "127.0.0.1::8080"}
	keys := make([]string, 0, len(envs))
	for k := range envs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+envs[k])
	}
	args = append(args, "rt3fw-app-"+stack+":local")
	if out, err := docker(args...); err != nil {
		t.Fatalf("docker run %s: %v: %s", name, err, out)
	}
	c := &container{name: name}
	t.Cleanup(func() {
		if os.Getenv("RT3FW_KEEP") == "" {
			_, _ = docker("rm", "-f", name)
		}
	})
	out, err := docker("port", name, "8080/tcp")
	if err != nil {
		t.Fatalf("docker port: %v %s", err, out)
	}
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(out), "\n")[0])
	_, p, _ := net.SplitHostPort(line)
	c.port, _ = strconv.Atoi(p)
	return c
}

func (c *container) logs() string {
	out, _ := docker("logs", c.name)
	return out
}

// copyOut copies a directory of the container to a fresh host directory and
// returns every regular file it holds.
func (c *container) copyOut(t *testing.T, path string) map[string][]byte {
	dst := t.TempDir()
	if out, err := docker("cp", c.name+":"+path, dst); err != nil {
		t.Logf("docker cp %s: %v %s", path, err, out)
		return nil
	}
	files := map[string][]byte{}
	_ = filepath.Walk(dst, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			files[strings.TrimPrefix(p, dst)] = b
		}
		return nil
	})
	return files
}

// appClient drops idle connections before the servers' keep-alive timeouts
// (Node and uvicorn: 5 s), so a POST never races a server-side close.
var appClient = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{IdleConnTimeout: 2 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

var noKeepAlive = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// waitHealthy returns how long the app took to answer GET /health with 200.
func (c *container) waitHealthy(t *testing.T, d time.Duration) time.Duration {
	t.Helper()
	t0 := time.Now()
	for time.Since(t0) < d {
		r, err := appClient.Get(fmt.Sprintf("http://127.0.0.1:%d/health", c.port))
		if err == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == 200 {
				return time.Since(t0)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s not healthy after %s; logs:\n%s", c.name, d, tail(c.logs(), 4000))
	return 0
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// ---------------------------------------------------------------------------
// Traffic

type canaries struct {
	Keep, Body, Nested, Path, Query, Header, Cookie, Auth, Fail, Boom string
}

func (c canaries) all() map[string]string {
	return map[string]string{"keep": c.Keep, "body": c.Body, "nested": c.Nested, "path": c.Path, "query": c.Query,
		"header": c.Header, "cookie": c.Cookie, "auth": c.Auth, "fail": c.Fail, "boom": c.Boom}
}

// newCanaries: values the sanitizer can only hide (never names), each
// unique to the stack and the run.
func newCanaries(stack string) canaries {
	r := func(what string) string {
		var b [6]byte
		_, _ = rand.Read(b[:])
		return "cnry" + what + stack + hex.EncodeToString(b[:])
	}
	return canaries{Keep: r("keep"), Body: r("body"), Nested: r("nest"), Path: r("path"), Query: r("qry"),
		Header: r("hdr"), Cookie: r("cook"), Auth: r("auth"), Fail: r("fail"), Boom: r("boom")}
}

var kinds = []string{"order", "fail", "boom"}

type answer struct {
	Status  int
	Body    string
	Latency time.Duration
	Echo    string // x-echo response header
	Err     error
}

func (c *container) call(t *testing.T, cn canaries, kind string) answer {
	t.Helper()
	var req *http.Request
	base := fmt.Sprintf("http://127.0.0.1:%d", c.port)
	switch kind {
	case "order":
		body := fmt.Sprintf(`{"keepme":%q,"secret":%q,"nested":{"email":%q}}`, cn.Keep, cn.Body, cn.Nested+"@example.com")
		req, _ = http.NewRequest("POST", base+"/orders/"+cn.Path+"?ref="+cn.Query, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Secret", cn.Header)
		req.Header.Set("Cookie", "sid="+cn.Cookie)
		// A JWT-shaped bearer whose sub is a canary: identity is hmac'd.
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0."+b64url(`{"sub":"`+cn.Auth+`"}`)+".")
	case "fail":
		req, _ = http.NewRequest("GET", base+"/fail/"+cn.Fail, nil)
	case "boom":
		req, _ = http.NewRequest("GET", base+"/boom/"+cn.Boom, nil)
	default:
		t.Fatalf("kind %s", kind)
	}
	t0 := time.Now()
	hc := appClient
	if kind == "boom" {
		// Some servers close the connection after an unhandled exception
		// (uvicorn): a fresh connection keeps the next request off it.
		hc = noKeepAlive
	}
	resp, err := hc.Do(req)
	if err != nil {
		return answer{Err: err, Latency: time.Since(t0)}
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return answer{Status: resp.StatusCode, Body: normJSON(b), Latency: time.Since(t0), Echo: resp.Header.Get("X-Echo")}
}

func normJSON(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		n, _ := json.Marshal(v)
		return string(n)
	}
	return string(b)
}

func b64url(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		k := min(3, len(b)-i)
		for j := 0; j < 3; j++ {
			n <<= 8
			if j < k {
				n |= uint32(b[i+j])
			}
		}
		for j := 0; j < k+1; j++ {
			out.WriteByte(alpha[(n>>(18-6*j))&63])
		}
	}
	return out.String()
}

// checkContract checks the answers of the app contract (the exception route
// only by status: its body is the framework's default error page).
func checkContract(t *testing.T, label string, cn canaries, kind string, a answer) {
	t.Helper()
	if a.Err != nil {
		t.Errorf("[%s] %s: %v", label, kind, a.Err)
		return
	}
	switch kind {
	case "order":
		want := normJSON([]byte(fmt.Sprintf(`{"id":%q,"status":"created","echo":%q,"email":%q}`, cn.Path, cn.Body, cn.Nested+"@example.com")))
		if a.Status != 201 || a.Body != want || a.Echo != cn.Header {
			t.Errorf("[%s] order: status %d body %s x-echo %q (want 201 %s %q)", label, a.Status, a.Body, a.Echo, want, cn.Header)
		}
	case "fail":
		want := normJSON([]byte(fmt.Sprintf(`{"error":{"code":"E_FAIL","message":"order %s failed"}}`, cn.Fail)))
		if a.Status != 500 || a.Body != want {
			t.Errorf("[%s] fail: status %d body %s (want 500 %s)", label, a.Status, a.Body, want)
		}
	case "boom":
		if a.Status != 500 {
			t.Errorf("[%s] boom: status %d (want 500)", label, a.Status)
		}
	}
}

// findCanaries returns "where: which" for every canary found in blobs,
// skipping the allowed ones.
func findCanaries(blobs map[string][]byte, cns []canaries, allowed func(kind string) bool) []string {
	var hits []string
	for where, b := range blobs {
		for _, cn := range cns {
			for kind, v := range cn.all() {
				if allowed(kind) {
					continue
				}
				if bytes.Contains(b, []byte(v)) {
					hits = append(hits, fmt.Sprintf("%s: %s canary", where, kind))
				}
			}
		}
	}
	slices.Sort(hits)
	return slices.Compact(hits)
}

func countCanary(s string, cns []canaries, kind string) int {
	n := 0
	for _, cn := range cns {
		n += strings.Count(s, cn.all()[kind])
	}
	return n
}

// ---------------------------------------------------------------------------
// Per-stack knowledge

type stackInfo struct {
	stateDir string // SDK state directory inside the container
	// logFilter removes the web server's own access-log lines (not written
	// by the SDK) before the logs are scanned.
	logFilter *regexp.Regexp
}

func (si stackInfo) filterLogs(s string) string {
	if si.logFilter == nil {
		return s
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !si.logFilter.MatchString(l) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

var stackInfos = map[string]stackInfo{
	"java":   {stateDir: "/var/lib/tt-state"},
	"dotnet": {stateDir: "/var/lib/tt-state"},
	"python": {stateDir: "/var/lib/tt-state"},
	// PHP built-in server: "[date] 172.17.0.1:54321 [201]: POST /orders/…"
	"php":  {stateDir: "/var/lib/tt-state", logFilter: regexp.MustCompile(`^\[[^\]]+\] \S+:\d+ \[\d+\]: [A-Z]+ /`)},
	"node": {stateDir: "/var/lib/tt-state"},
}

func selected() []string {
	v := os.Getenv("RT3FW_STACKS")
	if v == "" {
		return allStacks
	}
	return strings.Split(v, ",")
}

func sdkEnv(stack, enrollURL, token, hmacKey string) map[string]string {
	return map[string]string{
		"TT_ENROLL_URL": enrollURL, "TT_ENROLL_TOKEN": token, "TT_HMAC_KEY": hmacKey,
		"TT_SERVICE_NAME": "fw-" + stack, "TT_STATE_DIR": stackInfos[stack].stateDir,
		"TT_HEARTBEAT_INTERVAL_MS": "500", "TT_POLICY_POLL_INTERVAL_MS": "500", "TT_EXPORT_FLUSH_MS": "200",
		// Debug output on: it must still carry no value (M14).
		"TT_DEBUG": "1",
	}
}

func TestFW(t *testing.T) {
	if os.Getenv("TT_RT_FRAMEWORKS") == "" {
		t.Skip("set TT_RT_FRAMEWORKS=1 (after build_images.sh) to run the Docker framework checks")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	for _, stack := range selected() {
		t.Run(stack, func(t *testing.T) {
			if out, err := docker("image", "inspect", "rt3fw-app-"+stack+":local"); err != nil {
				t.Fatalf("image rt3fw-app-%s:local missing (run test/redteam/frameworks/build_images.sh %s): %s", stack, stack, tail(out, 300))
			}
			t.Run("capture", func(t *testing.T) { testCapture(t, stack) })
			t.Run("core_down", func(t *testing.T) { testCoreDown(t, stack) })
			t.Run("core_lost", func(t *testing.T) { testCoreLost(t, stack) })
		})
	}
}

// sendRound sends one exchange of each kind with fresh canaries.
func sendRound(t *testing.T, c *container, stack string) canaries {
	cn := newCanaries(stack)
	for _, kind := range kinds {
		checkContract(t, stack, cn, kind, c.call(t, cn, kind))
	}
	return cn
}

// testCapture: (a) and (b).
func testCapture(t *testing.T, stack string) {
	e := getEnv(t)
	e.proxy.set(modeNormal)
	svc := "fw-" + stack
	c := startApp(t, stack, "rt3fw-"+stack+"-up", sdkEnv(stack, e.intakePub, e.token, e.hmacKey))
	c.waitHealthy(t, 120*time.Second)

	// Drive traffic until a few POST /orders events of this stack are stored
	// (the source captures), then look for the kept canary in them.
	var sent []canaries
	var orders [][]byte
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && len(orders) < 3 {
		sent = append(sent, sendRound(t, c, stack))
		time.Sleep(500 * time.Millisecond)
		orders = nil
		for _, ev := range eventsOf(e.exportEvents(t), svc) {
			if bytes.Contains(ev, []byte(`"op":"POST /orders/{id}"`)) {
				orders = append(orders, ev)
			}
		}
	}
	for i := 0; i < 5; i++ {
		sent = append(sent, sendRound(t, c, stack))
	}
	time.Sleep(4 * time.Second) // let the exporter flush

	var mine []sourceView
	for _, s := range e.sources(t) {
		if s.ServiceName == svc {
			mine = append(mine, s)
		}
	}
	t.Logf("[%s] sources: %+v", stack, mine)
	ev := e.exportEvents(t)
	evs := eventsOf(ev, svc)
	t.Logf("[%s] %d events of %s in the export; %d exchanges sent", stack, len(evs), svc, len(kinds)*len(sent))
	if len(orders) == 0 {
		t.Fatalf("[%s] no POST /orders event reached tt-core in 90 s; app logs:\n%s", stack, tail(c.logs(), 4000))
	}
	keptSeen := false
	for _, s := range sent {
		if bytes.Contains(ev, []byte("keep:"+s.Keep)) {
			keptSeen = true
		}
	}
	if !keptSeen {
		// Capture works (events arrive) but the request body that the
		// policy keeps never does: show what the event says instead.
		var shape struct {
			Req struct {
				Body any    `json:"body"`
				Size string `json:"size"`
			} `json:"req"`
		}
		_ = json.Unmarshal(orders[0], &shape)
		t.Errorf("[%s] (b) the kept request field $.keepme never reached tt-core: request body is %v, size %q in %d POST /orders events (capture of JSON request bodies read by the framework is lost)",
			stack, shape.Req.Body, shape.Req.Size, len(orders))
	}

	checkFidelity(t, stack, orders)

	logs := stackInfos[stack].filterLogs(c.logs())
	state := c.copyOut(t, stackInfos[stack].stateDir)
	if len(state) == 0 {
		t.Errorf("[%s] SDK state directory %s is empty or missing", stack, stackInfos[stack].stateDir)
	}
	never := func(string) bool { return false }
	onlyKeep := func(k string) bool { return k == "keep" }
	// The framework logs unhandled exceptions with their message: the
	// exception canary is checked against the SDK-disabled run in core_down.
	notBoom := func(k string) bool { return k == "boom" }
	if hits := findCanaries(map[string][]byte{"app stdout/stderr": []byte(logs)}, sent, notBoom); len(hits) > 0 {
		t.Errorf("[%s] (a) canaries in the app logs: %v\n%s", stack, hits, tail(logs, 3000))
	}
	stateBlobs := map[string][]byte{}
	for p, b := range state {
		stateBlobs["state "+p] = b
	}
	if hits := findCanaries(stateBlobs, sent, onlyKeep); len(hits) > 0 {
		t.Errorf("[%s] (a) canaries in the SDK state/spool directory: %v", stack, hits)
	}
	if hits := findCanaries(map[string][]byte{"events export": ev}, sent, onlyKeep); len(hits) > 0 {
		t.Errorf("[%s] (b) canaries in exported events beyond the policy: %v", stack, hits)
	}
	if hits := findCanaries(e.rawCoreFiles(t), sent, onlyKeep); len(hits) > 0 {
		t.Errorf("[%s] (b) canaries stored by tt-core beyond the policy: %v", stack, hits)
	}
	if hits := findCanaries(map[string][]byte{"tt-core log": []byte(e.coreLog.String())}, sent, never); len(hits) > 0 {
		t.Errorf("[%s] (b) canaries in the tt-core log: %v", stack, hits)
	}
	if os.Getenv("RT3FW_DUMP") != "" {
		_ = os.WriteFile(filepath.Join(os.TempDir(), "rt3fw-"+stack+"-events.jsonl"), bytes.Join(evs, []byte("\n")), 0o600)
		_ = os.WriteFile(filepath.Join(os.TempDir(), "rt3fw-"+stack+"-app.log"), []byte(c.logs()), 0o600)
	}
}

// wireRequestHeaders are the header names the Go client of this test puts on
// the wire for POST /orders.
var wireRequestHeaders = []string{"host", "user-agent", "content-length", "content-type", "x-secret", "authorization", "accept-encoding", "cookie"}

// checkFidelity: the event describes the exchange on the wire (sanitizer.md:
// the twin is built from it). A request header the client never sent, or a
// Set-Cookie counted twice, ends up in the contracts and in the mock.
func checkFidelity(t *testing.T, stack string, orders [][]byte) {
	t.Helper()
	for i, raw := range orders {
		var ev struct {
			Req struct {
				Headers map[string][]string `json:"headers"`
			} `json:"req"`
			Resp struct {
				Cookies map[string][]string `json:"cookies"`
			} `json:"resp"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatalf("event: %v", err)
		}
		var extra []string
		for h := range ev.Req.Headers {
			if !slices.Contains(wireRequestHeaders, h) {
				extra = append(extra, h)
			}
		}
		slices.Sort(extra)
		if len(extra) > 0 {
			t.Errorf("[%s] fidelity: POST /orders event #%d lists request headers the client never sent: %v", stack, i, extra)
		}
		if n := len(ev.Resp.Cookies["sess"]); n != 1 {
			t.Errorf("[%s] fidelity: POST /orders event #%d has %d Set-Cookie sess (the app sets exactly 1)", stack, i, n)
		}
		if i == 0 {
			break // one event is enough
		}
	}
}

// blackhole accepts TCP connections and never answers (nor closes).
type blackhole struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newBlackhole(t *testing.T) *blackhole {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns = append(b.conns, c)
			b.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		b.mu.Lock()
		for _, c := range b.conns {
			c.Close()
		}
		b.mu.Unlock()
	})
	return b
}

func (b *blackhole) port() int { return b.ln.Addr().(*net.TCPAddr).Port }

func (b *blackhole) accepted() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.conns) }

func closedPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

type runStats struct {
	startup time.Duration
	answers map[string][]answer
	logs    string
}

// testCoreDown: (c) from start-up. The baseline is the same image with
// TT_DISABLED=1.
func testCoreDown(t *testing.T, stack string) {
	// A well-formed token and key (from the real environment) so that the
	// SDK really tries to reach the unreachable tt-core.
	e := getEnv(t)
	bh := newBlackhole(t)
	refused := closedPort(t)
	modes := []struct {
		name string
		env  map[string]string
	}{
		{"disabled", map[string]string{"TT_DISABLED": "1"}},
		{"refused", sdkEnv(stack, fmt.Sprintf("https://host.docker.internal:%d", refused), e.token, e.hmacKey)},
		{"blackhole", sdkEnv(stack, fmt.Sprintf("https://host.docker.internal:%d", bh.port()), e.token, e.hmacKey)},
	}
	// Same canaries in every mode, so answers compare byte for byte.
	cns := []canaries{newCanaries(stack), newCanaries(stack), newCanaries(stack)}
	res := map[string]runStats{}
	for _, m := range modes {
		c := startApp(t, stack, "rt3fw-"+stack+"-"+m.name, m.env)
		rs := runStats{answers: map[string][]answer{}}
		rs.startup = c.waitHealthy(t, 120*time.Second)
		for round := 0; round < 4; round++ {
			for _, cn := range cns {
				for _, kind := range kinds {
					a := c.call(t, cn, kind)
					checkContract(t, stack+"/"+m.name, cn, kind, a)
					rs.answers[kind] = append(rs.answers[kind], a)
				}
			}
			if round == 0 {
				time.Sleep(2 * time.Second) // let the SDK try and fail in the background
			}
		}
		rs.logs = stackInfos[stack].filterLogs(c.logs())
		res[m.name] = rs
		_, _ = docker("rm", "-f", c.name)
	}
	base := res["disabled"]
	for _, m := range modes[1:] {
		r := res[m.name]
		t.Logf("[%s/%s] start-up %s (disabled %s)", stack, m.name, r.startup.Round(time.Millisecond), base.startup.Round(time.Millisecond))
		// Start-up: time to the first 200 on /health, with a generous margin
		// for container noise; a blocking enrollment would add the TLS/connect
		// timeout (typically 10-30 s).
		if r.startup > base.startup+5*time.Second {
			t.Errorf("[%s/%s] start-up took %s vs %s with the SDK disabled", stack, m.name, r.startup, base.startup)
		}
		for kind, as := range r.answers {
			for i, a := range as {
				b := base.answers[kind][i]
				same := a.Status == b.Status && a.Echo == b.Echo && (kind == "boom" || a.Body == b.Body)
				if !same {
					t.Errorf("[%s/%s] %s #%d differs from disabled: %d %s vs %d %s", stack, m.name, kind, i, a.Status, a.Body, b.Status, b.Body)
				}
				// Per-request latency: the SDK must never wait on tt-core in
				// the request path.
				if a.Latency > b.Latency+time.Second {
					t.Errorf("[%s/%s] %s #%d took %s (disabled %s)", stack, m.name, kind, i, a.Latency, b.Latency)
				}
			}
		}
		if hits := findCanaries(map[string][]byte{m.name + " logs": []byte(r.logs)}, cns, func(k string) bool { return k == "boom" }); len(hits) > 0 {
			t.Errorf("[%s/%s] canaries in logs: %v", stack, m.name, hits)
		}
		// The exception message: the framework logs it; the SDK must not
		// log it once more.
		if n, nb := countCanary(r.logs, cns, "boom"), countCanary(base.logs, cns, "boom"); n > nb {
			t.Errorf("[%s/%s] the exception canary appears %d times in the logs, %d with the SDK disabled", stack, m.name, n, nb)
		}
	}
	if bh.accepted() == 0 {
		t.Logf("[%s] note: the blackhole saw no connection (SDK did not try to enroll?)", stack)
	}
}

// testCoreLost: (c) while capturing. The SDK enrolls through the proxy; the
// proxy then becomes a blackhole (connections accepted and held, nothing
// forwarded), then resets every connection, then forwards again.
func testCoreLost(t *testing.T, stack string) {
	e := getEnv(t)
	e.proxy.set(modeNormal)
	defer e.proxy.set(modeNormal)
	svc := "fw-" + stack
	c := startApp(t, stack, "rt3fw-"+stack+"-lost", sdkEnv(stack, e.intakePub, e.token, e.hmacKey))
	c.waitHealthy(t, 120*time.Second)
	count := func() int { return len(eventsOf(e.exportEvents(t), svc)) }
	start := count()
	waitUntil(t, 60*time.Second, svc+" capturing", func() bool {
		sendRound(t, c, stack)
		return count() > start
	})

	measure := func(label string, rounds int) (time.Duration, []canaries) {
		var worst time.Duration
		var cns []canaries
		for i := 0; i < rounds; i++ {
			cn := newCanaries(stack)
			cns = append(cns, cn)
			for _, kind := range kinds {
				a := c.call(t, cn, kind)
				checkContract(t, stack+"/"+label, cn, kind, a)
				worst = max(worst, a.Latency)
			}
		}
		return worst, cns
	}
	normal, _ := measure("normal", 10)
	e.proxy.set(modeBlackhole)
	bh1, c1 := measure("blackhole", 20)
	time.Sleep(6 * time.Second) // in-flight exports and heartbeats now hang
	bh2, c2 := measure("blackhole+6s", 40)
	e.proxy.set(modeReset)
	rs, c3 := measure("reset", 20)
	t.Logf("[%s] worst latency: normal %s, blackhole %s / %s, reset %s", stack, normal, bh1, bh2, rs)
	for label, d := range map[string]time.Duration{"blackhole": bh1, "blackhole+6s": bh2, "reset": rs} {
		if d > normal+time.Second {
			t.Errorf("[%s] with tt-core lost (%s) a request took %s (normal worst %s)", stack, label, d, normal)
		}
	}
	e.proxy.set(modeNormal)
	before := count()
	recovered := false
	end := time.Now().Add(60 * time.Second)
	for time.Now().Before(end) && !recovered {
		sendRound(t, c, stack)
		time.Sleep(time.Second)
		recovered = count() > before
	}
	if !recovered {
		t.Errorf("[%s] capture did not resume within 60 s after tt-core came back; logs:\n%s", stack, tail(c.logs(), 3000))
	}
	all := append(append(c1, c2...), c3...)
	logs := stackInfos[stack].filterLogs(c.logs())
	if hits := findCanaries(map[string][]byte{"app logs": []byte(logs)}, all, func(k string) bool { return k == "boom" }); len(hits) > 0 {
		t.Errorf("[%s] canaries in the app logs while tt-core was lost: %v", stack, hits)
	}
}
