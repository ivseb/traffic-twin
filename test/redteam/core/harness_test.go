// Package core_rt red-teams the composed tt-core over real HTTP, with a real
// in-process keyguard on a Unix socket (red team round 2).
//
// Run:  go test ./test/redteam/core/ -count=1 -v
//
// The environment is built once per test binary (the same flow as
// internal/core/e2e_test.go, demo shop traffic for a simulated week) and
// shared by the tests; tests that change global state create their own
// users or groups. Every value is invented. Tests named TestRT_*_Fixed_*
// were reproducers of round-2 findings, now regression tests that pass
// since the fix; TestRT_*_Holds_* are guards.
package core_rt

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/core/demosim"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

const testPassword = "correct-horse-battery-1"

// ---------------------------------------------------------------------------
// Virtual clock, locked log buffer, recording transport

type vclock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *vclock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *vclock) Set(t time.Time) {
	c.mu.Lock()
	if t.After(c.t) {
		c.t = t
	}
	c.mu.Unlock()
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

// recorder keeps a copy of every admin API response (headers and body) so
// tests can look for key material or echoed values across everything the
// API ever returned.
type recorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	all  []recorded
}

type recorded struct {
	method, path string
	status       int
	header       http.Header
	body         []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	r.mu.Lock()
	r.all = append(r.all, recorded{req.Method, req.URL.Path, resp.StatusCode, resp.Header.Clone(), b})
	r.mu.Unlock()
	return resp, nil
}

func (r *recorder) snapshot() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.all...)
}

// ---------------------------------------------------------------------------
// Sessions

type session struct {
	t      testing.TB
	base   string
	hc     *http.Client
	cookie string
	csrf   string
	name   string
}

// req sends a request with the session cookie and CSRF token (both may be
// blanked by the caller through hdr: "Cookie" or CSRF header set to "-").
func (s *session) req(method, path string, body any, hdr map[string]string) (int, []byte, http.Header) {
	s.t.Helper()
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case string:
		rd, ctype = strings.NewReader(b), "application/json"
	case []byte:
		rd, ctype = bytes.NewReader(b), "application/json"
	default:
		j, _ := json.Marshal(b)
		rd, ctype = bytes.NewReader(j), "application/json"
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
		req.Header.Set(auth.CSRFHeader, s.csrf)
	}
	for k, v := range hdr {
		if v == "-" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (s *session) do(method, path string, body any) (int, []byte) {
	s.t.Helper()
	c, b, _ := s.req(method, path, body, nil)
	return c, b
}

func (s *session) must(want int, method, path string, body any) []byte {
	s.t.Helper()
	code, b := s.do(method, path, body)
	if code != want {
		s.t.Fatalf("[%s] %s %s = %d (want %d): %.400s", s.name, method, path, code, want, b)
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

func errCode(b []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Code
}

// signIn posts credentials and returns the session (cookie + CSRF).
func signIn(t testing.TB, base string, hc *http.Client, path string, body map[string]string, name string) *session {
	t.Helper()
	s, code, b := trySignIn(t, base, hc, path, body, nil)
	if s == nil {
		t.Fatalf("POST %s as %s = %d: %s", path, name, code, b)
	}
	s.name = name
	return s
}

func trySignIn(t testing.TB, base string, hc *http.Client, path string, body map[string]string, extra map[string]string) (*session, int, []byte) {
	t.Helper()
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+path, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, resp.StatusCode, b
	}
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(b, &me)
	s := &session{t: t, base: base, hc: hc}
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "tt_session") {
			s.cookie, s.csrf = c.Name+"="+c.Value, me.CSRF
		}
	}
	if s.cookie == "" {
		return nil, resp.StatusCode, b
	}
	return s, resp.StatusCode, b
}

func eventually(t testing.TB, d time.Duration, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Webhook receiver (plain HTTP on loopback, allow-listed in the env)

type hookHit struct {
	path   string
	header http.Header
	body   []byte
}

type hookSink struct {
	srv  *http.Server
	addr string
	mu   sync.Mutex
	hits []hookHit
}

func newHookSink() (*hookSink, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := &hookSink{addr: ln.Addr().String()}
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		h.add(r)
		http.Redirect(w, r, "http://"+h.addr+"/landing", http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.add(r)
		w.WriteHeader(204)
	})
	h.srv = &http.Server{Handler: mux}
	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

func (h *hookSink) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.hits = append(h.hits, hookHit{r.URL.Path, r.Header.Clone(), b})
	h.mu.Unlock()
}

func (h *hookSink) get() []hookHit {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hookHit(nil), h.hits...)
}

// ---------------------------------------------------------------------------
// The shared environment

type env struct {
	ctx       context.Context
	clock     *vclock
	core      *core.Core
	kg        *core.DevKeyguard
	kgDir     string
	dir       string
	base      string
	hc        *http.Client // recording client
	rec       *recorder
	coreLog   *lockedBuf
	kgLog     *lockedBuf
	keyFiles  map[string]string // name -> content of keyguard key files
	hmacKeys  sanitizer.KeySet
	users     map[string]*session
	ids       map[string]string // username -> user id
	src       *sourceclient.Source
	sim       *demosim.Sim
	start     time.Time
	end       time.Time
	orderIDs  []string // real order ids seen by the source (their tokens are in keyguard's filter)
	packID    string
	worldID   string
	exportID  string
	eveJob    string
	quarItem  string
	hooks     *hookSink
	hookID    string
	hookSec   string
	redirHook string
}

var (
	envOnce sync.Once
	theEnv  *env
	envErr  error
)

// roleUser maps each role to the user that holds only that role.
var roleUser = map[string]string{
	"admin": "ada", "operator": "olga", "rule-reviewer": "rita", "policy-approver": "pia",
	"publisher": "paul", "auditor": "audrey", "event-exporter": "eve", "": "nora",
}

func getEnv(t *testing.T) *env {
	t.Helper()
	if testing.Short() {
		t.Skip("composed red-team environment")
	}
	envOnce.Do(func() { theEnv, envErr = buildEnv(t) })
	if envErr != nil {
		t.Fatalf("environment: %v", envErr)
	}
	return theEnv
}

// fatalT turns t.Fatal inside buildEnv into a recorded error.
type buildErr struct{ msg string }

func buildEnv(t *testing.T) (e *env, err error) {
	defer func() {
		if r := recover(); r != nil {
			if be, ok := r.(buildErr); ok {
				err = fmt.Errorf("%s", be.msg)
				return
			}
			panic(r)
		}
	}()
	bt := &buildT{TB: t}
	e = &env{ctx: context.Background(), keyFiles: map[string]string{}, users: map[string]*session{}, ids: map[string]string{}}
	e.clock = &vclock{t: time.Now().UTC().Truncate(time.Second)}
	e.coreLog, e.kgLog = &lockedBuf{}, &lockedBuf{}

	e.kgDir, err = os.MkdirTemp("", "ttrt2")
	if err != nil {
		return nil, err
	}
	e.kg, err = core.StartDevKeyguard(e.ctx, core.DevKeyguardOptions{Dir: e.kgDir, Now: e.clock.Now,
		Logger: keyguard.NewLogger(e.kgLog, "debug", "json"),
		Tune:   func(c *keyguard.Config) { c.MatchInterval, c.PackInterval, c.BloomCapacity = 0, 0, 200000 }})
	if err != nil {
		return nil, err
	}
	for _, f := range []string{"hmac.keys", "policy.key", "pack.key"} {
		b, err := os.ReadFile(filepath.Join(e.kgDir, "keys", f))
		if err != nil {
			return nil, err
		}
		e.keyFiles[f] = string(b)
	}
	if e.hmacKeys, err = sanitizer.ParseKeys(e.keyFiles["hmac.keys"]); err != nil {
		return nil, err
	}
	if e.hooks, err = newHookSink(); err != nil {
		return nil, err
	}

	e.dir, err = os.MkdirTemp("", "ttrt2core")
	if err != nil {
		return nil, err
	}
	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(e.dir, e.kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		return nil, err
	}
	cfg.Fleet.PublicURL = "https://" + intakeLn.Addr().String()
	cfg.Fleet.ClientCertTTL = 30 * 24 * time.Hour
	cfg.Fleet.PolicyMaxAge = 30 * 24 * time.Hour
	cfg.Fleet.HeartbeatInterval, cfg.Fleet.PolicyPollInterval = 50*time.Millisecond, 50*time.Millisecond
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Retention.Events = 365 * 24 * time.Hour
	cfg.Miner.Schedule = 0
	cfg.Log.Level = "debug"
	// Webhooks: the loopback receiver only, plain HTTP (delivery tests).
	cfg.Drift.WebhookAllow = []string{e.hooks.addr}
	cfg.Drift.WebhookAllowHTTP = true
	e.core, err = core.New(e.ctx, core.Options{Config: cfg, Version: "0.0.0-rt2", AdminListener: adminLn, IntakeListener: intakeLn,
		Now: e.clock.Now, Logger: server.NewLogger(e.coreLog, "debug", "json"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		return nil, err
	}
	go func() { _ = e.core.Run(e.ctx) }()

	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	e.rec = &recorder{base: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	e.hc = &http.Client{Timeout: 60 * time.Second, Transport: e.rec,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	e.base = "https://" + adminLn.Addr().String()
	eventually(bt, 5*time.Second, "readyz", func() bool {
		resp, err := e.hc.Get(e.base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	ada := signIn(bt, e.base, e.hc, "/api/v1/setup", map[string]string{"setup_token": e.core.SetupToken(), "username": "ada", "password": testPassword}, "ada")
	e.users["ada"] = ada
	team := map[string][]string{"olga": {"operator"}, "rita": {"rule-reviewer"}, "paul": {"publisher"}, "paula": {"publisher"},
		"eve": {"event-exporter"}, "evan": {"event-exporter"}, "audrey": {"auditor"}, "pia": {"policy-approver"},
		"pete": {"policy-approver"}, "nora": {}}
	for name, roles := range team {
		ada.must(201, "POST", "/api/v1/users", map[string]any{"username": name, "password": testPassword, "roles": roles})
		e.users[name] = signIn(bt, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": name, "password": testPassword}, name)
	}
	var ul []map[string]any
	ada.json(200, "GET", "/api/v1/users", nil, &ul)
	for _, u := range ul {
		e.ids[fmt.Sprint(u["username"])] = fmt.Sprint(u["id"])
	}

	// A webhook subscribed to every event, before any traffic, and one
	// that answers with a redirect.
	var wh struct {
		ID     string `json:"webhook_id"`
		Secret string `json:"secret"`
	}
	ada.json(201, "POST", "/api/v1/webhooks", map[string]any{"name": "rt-all", "url": "http://" + e.hooks.addr + "/hook",
		"events": []string{"contract.drift", "rule.stale", "quarantine.opened", "source.problem", "kill.changed", "keyguard.alert", "pack.published"}}, &wh)
	e.hookID, e.hookSec = wh.ID, wh.Secret
	ada.json(201, "POST", "/api/v1/webhooks", map[string]any{"name": "rt-redirect", "url": "http://" + e.hooks.addr + "/redirect",
		"events": []string{"kill.changed", "keyguard.alert", "quarantine.opened"}}, &wh)
	e.redirHook = wh.ID

	olga := e.users["olga"]
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "demo", "allowed_service_names": []string{"shop-api"}, "policy_id": "p-demo"})
	var tok struct {
		Token string `json:"token"`
	}
	olga.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "demo", "token_type": "one_time"}, &tok)
	var pv struct {
		PolicyID string `json:"policy_id"`
		Version  int64  `json:"version"`
		Status   string `json:"status"`
	}
	olga.json(201, "POST", "/api/v1/fleet/groups/demo/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10"}, &pv)
	approve := func(v int64) {
		ada.must(200, "POST", fmt.Sprintf("/api/v1/fleet/policies/p-demo/versions/%d/approve", v), map[string]any{"reason": "single-maintainer trial"})
	}
	// The starter policy opens no value: active at once (policy.md 7).
	if pv.Status != "active" {
		return nil, fmt.Errorf("starter policy not active: %s", pv.Status)
	}

	e.src, err = sourceclient.New(sourceclient.Config{
		EnrollURL: cfg.Fleet.PublicURL, Token: tok.Token, StateDir: filepath.Join(e.dir, "source"),
		Kind: "sdk-go", Version: "0.1.0", ServiceName: "shop-api", Instance: "rt-1", Keys: e.hmacKeys, KeyKids: []string{core.DevHMACKid},
		HeartbeatInterval: 40 * time.Millisecond, PolicyPollInterval: 40 * time.Millisecond, Now: e.clock.Now,
		Exporter: sourceclient.ExporterOptions{MaxEvents: 20000, FlushInterval: 20 * time.Millisecond, BaseBackoff: 10 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, MaxRetries: 50},
	})
	if err != nil {
		return nil, err
	}
	e.src.Start(e.ctx)
	eventually(bt, 10*time.Second, "source capturing", func() bool { _, ok := e.src.Active(); return ok })
	olga.json(201, "POST", "/api/v1/fleet/policies", demosim.AuthorPolicy, &pv)
	approve(pv.Version)
	eventually(bt, 10*time.Second, "source on the demo policy", func() bool {
		cp, ok := e.src.Active()
		return ok && cp.Policy.Policy.Version == pv.Version
	})

	e.start = e.clock.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	e.sim = demosim.Run(demosim.Config{Seed: 42, Customers: 600, Days: 7, Start: e.start})
	xs := e.sim.Exchanges()
	sent := 0
	for i := range xs {
		x := &xs[i]
		e.clock.Set(x.TS)
		if x.Inbound && x.Ex.Method == "POST" && x.Ex.Status == 201 && len(e.orderIDs) < 50 {
			var o struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(x.Ex.RespBody, &o) == nil && o.ID != "" {
				e.orderIDs = append(e.orderIDs, o.ID)
			}
		}
		e.emit(bt, x.Ex, x.TS, x.SampledBy(), x.Latency, x.Trace, x.Span, x.Parent)
		sent++
	}
	srcID := e.src.Identity().SourceID
	eventually(bt, 60*time.Second, "events stored", func() bool {
		st := e.core.Intake().SourceStats(srcID)
		return int(st.Accepted+st.RejectedTotal) >= sent
	})
	if err := e.core.Intake().WaitIdle(e.ctx); err != nil {
		return nil, err
	}
	if len(e.orderIDs) == 0 {
		return nil, fmt.Errorf("no real order id captured")
	}
	e.end = e.sim.End()
	e.clock.Set(e.end.Add(time.Hour))
	// tt-core's sessions follow the virtual clock: sign in again.
	for name, s := range e.users {
		*s = *signIn(bt, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": name, "password": testPassword}, name)
	}

	for _, svc := range []string{"shop-api", "shipping-ext"} {
		olga.must(201, "POST", "/api/v1/contracts/"+svc+"/snapshots", map[string]any{"from": e.start, "to": e.end})
	}
	var job struct {
		JobID  string `json:"job_id"`
		Status string `json:"status"`
	}
	olga.json(202, "POST", "/api/v1/rules/mine", nil, &job)
	var drafts []map[string]any
	e.users["rita"].json(200, "GET", "/api/v1/rules?status=draft", nil, &drafts)
	for _, r := range drafts {
		e.users["rita"].must(200, "POST", "/api/v1/rules/"+fmt.Sprint(r["id"])+"/approve", nil)
	}
	olga.must(202, "POST", "/api/v1/archetypes/build", map[string]any{"k_min": 20})
	var wj struct {
		Result struct {
			WorldID string `json:"world_id"`
		} `json:"result"`
	}
	olga.json(202, "POST", "/api/v1/worlds", map[string]any{"seed": 42, "customers": 30}, &wj)
	e.worldID = wj.Result.WorldID
	var pj struct {
		Result struct {
			PackID string `json:"pack_id"`
			Status string `json:"status"`
		} `json:"result"`
	}
	olga.json(202, "POST", "/api/v1/packs", map[string]any{"world_id": e.worldID}, &pj)
	if pj.Result.Status != "signed" {
		return nil, fmt.Errorf("pack not signed: %s", pj.Result.Status)
	}
	e.packID = pj.Result.PackID
	e.users["paul"].must(200, "POST", "/api/v1/packs/"+e.packID+"/publish", nil)
	var ej struct {
		Result struct {
			ExportID string `json:"export_id"`
		} `json:"result"`
	}
	e.users["paul"].json(202, "POST", "/api/v1/exports", map[string]any{"pack_id": e.packID, "target": "wiremock"}, &ej)
	e.exportID = ej.Result.ExportID
	e.users["eve"].json(202, "POST", "/api/v1/events/export", map[string]any{"from": e.start, "to": e.end, "format": "jsonl"}, &job)
	e.eveJob = job.JobID

	// A keep field with many distinct values: quarantine.
	var tmpl *demosim.Exchange
	for i := range xs {
		if xs[i].Inbound && xs[i].Ex.Method == "GET" && xs[i].Ex.Status == 200 && strings.Count(string(xs[i].Ex.RawPath), "/") == 2 {
			tmpl = &xs[i]
			break
		}
	}
	var body map[string]any
	_ = json.Unmarshal(tmpl.Ex.RespBody, &body)
	for i := range 80 {
		x := *tmpl
		body["status"] = fmt.Sprintf("RTQSTATE%04d", i)
		x.Ex.RespBody, _ = json.Marshal(body)
		e.emit(bt, x.Ex, e.clock.Now().Add(time.Duration(i)*time.Second), x.SampledBy(), 5, x.Trace, x.Span, "")
	}
	var qs []map[string]any
	eventually(bt, 20*time.Second, "quarantine", func() bool {
		qs = nil
		e.users["audrey"].json(200, "GET", "/api/v1/quarantine", nil, &qs)
		return len(qs) > 0
	})
	e.quarItem = fmt.Sprint(qs[0]["item_id"])
	return e, nil
}

// emit sanitizes one exchange at the source and sends it.
func (e *env) emit(t testing.TB, ex sanitizer.Exchange, ts time.Time, by sanitizer.SampledBy, lat int64, trace, span, parent string) {
	cp, ok := e.src.Active()
	for wait := time.Now(); !ok; cp, ok = e.src.Active() {
		if time.Since(wait) > 10*time.Second {
			t.Fatalf("source stopped capturing (state %s)", e.src.State())
		}
		e.src.Kick()
		time.Sleep(2 * time.Millisecond)
	}
	out, err := cp.Engine.Sanitize(&ex, ts, by)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
		TS: ts, LatencyMS: lat, Status: ex.Status, TraceID: trace, SpanID: span, ParentSpanID: parent}, cp.Policy)
	ev, err := sanitizer.BuildEvent(meta, out)
	if err != nil {
		t.Fatalf("build event: %v", err)
	}
	for e.src.Stats().QueueEvents > 10000 {
		time.Sleep(2 * time.Millisecond)
	}
	e.src.Emit(sourceclient.Event{JSON: ev, TS: ts.Truncate(time.Millisecond), TraceID: trace, SpanID: span, PolicyHash: cp.Policy.Hash})
}

// buildT adapts testing.TB so that Fatal inside buildEnv aborts the build
// with an error (shared by all tests) instead of failing only the first.
type buildT struct{ testing.TB }

func (b *buildT) Fatal(args ...any)                 { panic(buildErr{fmt.Sprint(args...)}) }
func (b *buildT) Fatalf(format string, args ...any) { panic(buildErr{fmt.Sprintf(format, args...)}) }
func (b *buildT) Helper()                           {}

// u returns the named user's session bound to t.
func (e *env) u(t *testing.T, name string) *session {
	s := *e.users[name]
	s.t = t
	return &s
}

// anon is a session without cookie bound to t.
func (e *env) anon(t *testing.T) *session {
	return &session{t: t, base: e.base, hc: e.hc, name: "anonymous"}
}

// newUser creates a local user with roles and signs them in.
func (e *env) newUser(t *testing.T, name string, roles ...string) *session {
	t.Helper()
	if roles == nil {
		roles = []string{}
	}
	var u map[string]any
	e.u(t, "ada").json(201, "POST", "/api/v1/users", map[string]any{"username": name, "password": testPassword, "roles": roles}, &u)
	e.ids[name] = fmt.Sprint(u["id"])
	return signIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": name, "password": testPassword}, name)
}

// auditEntries exports the tt-core audit log as the auditor.
func (e *env) auditEntries(t *testing.T) []map[string]any {
	t.Helper()
	b := e.u(t, "audrey").must(200, "GET", "/api/v1/audit/export", nil)
	var out []map[string]any
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("audit line: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func (e *env) auditSince(t *testing.T, seq float64) []map[string]any {
	var out []map[string]any
	for _, a := range e.auditEntries(t) {
		if a["seq"].(float64) > seq {
			out = append(out, a)
		}
	}
	return out
}

func (e *env) auditHead(t *testing.T) float64 {
	es := e.auditEntries(t)
	if len(es) == 0 {
		return 0
	}
	return es[len(es)-1]["seq"].(float64)
}

func hasAction(es []map[string]any, action string) bool {
	for _, a := range es {
		if a["action"] == action {
			return true
		}
	}
	return false
}
