package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/core/demosim"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/store"
)

const perfPassword = "perf-harness-password-1" // test account of the throwaway core

type harness struct {
	sc     Scale
	dir    string
	rep    *Report
	phases map[string]bool
	skip   map[string]bool // endpoint names not measured
	// memLimit is the memory of the emulated host (-memlimit), given to
	// the core as its limit; minerMaxEvents is miner.max_events.
	memLimit       uint64
	minerMaxEvents int
	memScenarios   map[string]bool // -mem: scenarios of the memory phase (all when empty)

	kg      *core.DevKeyguard
	c       *core.Core
	cfg     *config.Config
	stop    context.CancelFunc
	runDone chan error
	base    string
	hc      *http.Client
	admin   *apiSession

	hook     *hookServer
	sourceID string
	tpl      []*event.Event
	wire     [][]byte // wire events for the live ingestion load
	ids      map[string]string
}

func (h *harness) dbPath() string { return filepath.Join(h.dir, "core", "tt-core.db") }

func (h *harness) run(ctx context.Context) error {
	t0 := time.Now()
	h.ids = map[string]string{}
	var err error
	if h.kg, err = core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: filepath.Join(h.dir, "keyguard"),
		Logger: keyguard.NewLogger(io.Discard, "error", "text"),
		// Segments of a tenth of the tokens the keyguard bench sends: the
		// growth of the filter shows at every scale.
		Tune: func(c *keyguard.Config) {
			c.MatchInterval, c.PackInterval = 0, 0
			c.BloomCapacity = uint64(max(10_000, h.sc.KGTokens/10))
		}}); err != nil {
		return fmt.Errorf("keyguard: %w", err)
	}
	defer h.kg.Close()
	h.hook = newHookServer()
	defer h.hook.Close()

	fresh := true
	if _, err := os.Stat(h.dbPath()); err == nil {
		fresh = false // -dir of a previous run: reuse its dataset
	}
	if fresh {
		step("bootstrap: admin, policy signed by keyguard, one real source")
		if err := h.startCore(ctx); err != nil {
			return err
		}
		if err := h.bootstrap(ctx); err != nil {
			return err
		}
		if err := h.stopCore(); err != nil {
			return err
		}
		step(fmt.Sprintf("dataset: %d events", h.sc.Events))
		if err := h.generate(ctx); err != nil {
			return fmt.Errorf("generate: %w", err)
		}
	} else {
		step("reusing the dataset in " + h.dir)
		if err := h.loadState(); err != nil {
			return err
		}
	}
	h.rep.Dataset.GenerateSeconds = time.Since(t0).Seconds()

	trace.setOn(true)
	st := time.Now()
	if err := h.startCore(ctx); err != nil {
		return err
	}
	h.rep.Dataset.StartupSeconds = time.Since(st).Seconds()
	defer h.stopCore()
	if err := h.login(); err != nil {
		return err
	}
	if fresh {
		step("analysis jobs on the dataset, then history (snapshots, rules, alerts, worlds, packs)")
		if err := h.firstJobs(ctx); err != nil {
			return err
		}
		if err := h.history(ctx); err != nil {
			return fmt.Errorf("history: %w", err)
		}
		if err := h.saveState(); err != nil {
			return err
		}
	}
	if err := h.rowCounts(ctx); err != nil {
		return err
	}
	if h.phases["http"] {
		step("GET endpoints")
		h.benchEndpoints(ctx)
	}
	if h.phases["jobs"] {
		step("jobs on the full history")
		h.benchJobs(ctx)
	}
	if h.phases["memory"] {
		step("memory: mining alone, twice, next to a snapshot and a pack build")
		h.benchMemory()
	}
	if h.phases["purge"] {
		step("retention purge under ingestion load")
		h.benchPurge(ctx)
	}
	if h.phases["keyguard"] {
		step("keyguard Bloom filter and match")
		h.benchKeyguard(ctx)
	}
	if h.phases["mock"] {
		step("mock: sessions, journal, clock advance")
		h.benchMock(ctx)
	}
	trace.setOn(false)
	step("query plans")
	if err := h.explain(ctx); err != nil {
		return err
	}
	return nil
}

func step(s string) { fmt.Printf("%s %s\n", time.Now().Format("15:04:05"), s) }

// ---- core lifecycle ----

func (h *harness) startCore(ctx context.Context) error {
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	intakeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	cfg, err := core.DevConfig(filepath.Join(h.dir, "core"), h.kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		return err
	}
	cfg.Fleet.PublicURL = "https://" + intakeLn.Addr().String()
	cfg.Fleet.HeartbeatInterval, cfg.Fleet.PolicyPollInterval = 200*time.Millisecond, 200*time.Millisecond
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Retention.Events = time.Duration(h.sc.Days+5) * 24 * time.Hour
	cfg.Retention.PurgeInterval = 24 * time.Hour
	cfg.Miner.Schedule = 0
	if h.minerMaxEvents > 0 {
		cfg.Miner.MaxEvents = h.minerMaxEvents
	}
	cfg.Log.Level = "error"
	cfg.Drift.WebhookAllow = []string{"127.0.0.1"}
	cfg.Drift.WebhookAllowHTTP = true
	h.cfg = cfg
	cctx, cancel := context.WithCancel(ctx)
	logf, err := os.OpenFile(filepath.Join(h.dir, "core.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		cancel()
		return err
	}
	c, err := core.New(cctx, core.Options{Config: cfg, Version: "0.0.0-perf", AdminListener: adminLn, IntakeListener: intakeLn,
		Logger:         server.NewLogger(logf, "warn", "text"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, MemoryLimit: h.memLimit})
	if err != nil {
		cancel()
		return fmt.Errorf("core: %w", err)
	}
	h.c, h.stop = c, cancel
	h.runDone = make(chan error, 1)
	go func() { h.runDone <- c.Run(cctx) }()
	pem, err := os.ReadFile(cfg.Admin.TLS.CertFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	h.hc = &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{MaxIdleConnsPerHost: 64,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	h.base = "https://" + adminLn.Addr().String()
	for deadline := time.Now().Add(60 * time.Second); ; {
		resp, err := h.hc.Get(h.base + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("core not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *harness) stopCore() error {
	if h.c == nil {
		return nil
	}
	h.stop()
	err := <-h.runDone
	h.c = nil
	return err
}

// ---- API session ----

type apiSession struct {
	h      *harness
	cookie string
	csrf   string
}

func (h *harness) signIn(path string, body map[string]string) (*apiSession, error) {
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", h.base+path, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("POST %s = %d: %s", path, resp.StatusCode, b)
	}
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(b, &me)
	s := &apiSession{h: h, csrf: me.CSRF}
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "tt_session") {
			s.cookie = c.Name + "=" + c.Value
		}
	}
	if s.cookie == "" {
		return nil, fmt.Errorf("no session cookie from %s", path)
	}
	return s, nil
}

func (h *harness) login() error {
	var err error
	h.admin, err = h.signIn("/api/v1/auth/login", map[string]string{"username": "perfadmin", "password": perfPassword})
	return err
}

func (s *apiSession) do(method, path string, body any) (int, []byte, time.Duration, error) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, s.h.base+path, rd)
	if err != nil {
		return 0, nil, 0, err
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Cookie", s.cookie)
	req.Header.Set(auth.CSRFHeader, s.csrf)
	t0 := time.Now()
	resp, err := s.h.hc.Do(req)
	if err != nil {
		return 0, nil, time.Since(t0), err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, b, time.Since(t0), err
}

func (s *apiSession) json(want int, method, path string, body, out any) error {
	code, b, _, err := s.do(method, path, body)
	if err != nil {
		return err
	}
	if code != want {
		return fmt.Errorf("%s %s = %d (want %d): %.300s", method, path, code, want, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---- bootstrap: admin, policy, a real enrolled source, templates ----

func (h *harness) bootstrap(ctx context.Context) error {
	admin, err := h.signIn("/api/v1/setup", map[string]string{"setup_token": h.c.SetupToken(), "username": "perfadmin", "password": perfPassword})
	if err != nil {
		return err
	}
	h.admin = admin
	if err := admin.json(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "demo",
		"allowed_service_names": []string{"shop-api"}, "policy_id": "p-demo"}, nil); err != nil {
		return err
	}
	var tok struct {
		Token   string `json:"token"`
		TokenID string `json:"token_id"`
	}
	if err := admin.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "demo", "token_type": "group"}, &tok); err != nil {
		return err
	}
	h.ids["token_id"] = tok.TokenID
	var pv struct {
		Version int64 `json:"version"`
	}
	if err := admin.json(201, "POST", "/api/v1/fleet/groups/demo/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10"}, &pv); err != nil {
		return err
	}
	// A version an administrator creates is approved with it (409
	// not_draft): only a draft still needs the approval.
	approve := func(v int64) error {
		code, b, _, err := admin.do("POST", fmt.Sprintf("/api/v1/fleet/policies/p-demo/versions/%d/approve", v), map[string]any{"reason": "perf harness"})
		if err != nil {
			return err
		}
		if code != 200 && !(code == 409 && bytes.Contains(b, []byte("not_draft"))) {
			return fmt.Errorf("approve policy version %d = %d: %.200s", v, code, b)
		}
		return nil
	}
	if err := approve(pv.Version); err != nil {
		return err
	}
	keyText, err := os.ReadFile(h.kg.HMACKeyFile)
	if err != nil {
		return err
	}
	keys, err := sanitizer.ParseKeys(string(keyText))
	if err != nil {
		return err
	}
	src, err := sourceclient.New(sourceclient.Config{EnrollURL: h.cfg.Fleet.PublicURL, Token: tok.Token, StateDir: filepath.Join(h.dir, "source"),
		Kind: "sdk-go", Version: "0.1.0", ServiceName: "shop-api", Instance: "perf-1", Keys: keys, KeyKids: []string{core.DevHMACKid},
		HeartbeatInterval: 100 * time.Millisecond, PolicyPollInterval: 100 * time.Millisecond,
		Logger: server.NewLogger(io.Discard, "error", "text")})
	if err != nil {
		return err
	}
	src.Start(ctx)
	defer func() {
		cctx, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_ = src.Close(cctx)
	}()
	if err := admin.json(201, "POST", "/api/v1/fleet/policies", demosim.AuthorPolicy, &pv); err != nil {
		return err
	}
	if err := approve(pv.Version); err != nil {
		return err
	}
	var cp sourceclient.Capture
	for deadline := time.Now().Add(30 * time.Second); ; {
		var ok bool
		cp, ok = src.Active()
		if ok && cp.Policy.Policy.Version == pv.Version {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("source not capturing under the demo policy")
		}
		src.Kick()
		time.Sleep(50 * time.Millisecond)
	}
	h.sourceID = cp.SourceID
	// One week of the demo shop: the templates of the dataset.
	sim := demosim.Run(demosim.Config{Seed: 42, Customers: h.sc.Customers, Days: 7, Start: time.Now().UTC().Truncate(24 * time.Hour).Add(-8 * 24 * time.Hour)})
	for _, x := range sim.Exchanges() {
		out, err := cp.Engine.Sanitize(&x.Ex, x.TS, x.SampledBy())
		if err != nil {
			return err
		}
		meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
			TS: x.TS, LatencyMS: x.Latency, Status: x.Ex.Status, TraceID: x.Trace, SpanID: x.Span, ParentSpanID: x.Parent}, cp.Policy)
		w, err := sanitizer.BuildEvent(meta, out)
		if err != nil {
			return err
		}
		ev, derr := event.Decode(w)
		if derr != nil {
			return fmt.Errorf("template is not canonical: %v", derr)
		}
		h.tpl = append(h.tpl, ev)
		if len(h.wire) < 20000 {
			h.wire = append(h.wire, w)
		}
	}
	h.rep.Dataset.Templates = len(h.tpl)
	// Users of every role (the endpoints are measured as the admin, the
	// role checks cost the same).
	return h.saveTemplates()
}

// ---- state kept between runs on the same -dir ----

type savedState struct {
	SourceID string            `json:"source_id"`
	IDs      map[string]string `json:"ids"`
}

func (h *harness) saveTemplates() error {
	f, err := os.OpenFile(filepath.Join(h.dir, "wire.ndjson"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, w := range h.wire {
		f.Write(w)
		f.Write([]byte("\n"))
	}
	return nil
}

func (h *harness) saveState() error {
	b, _ := json.MarshalIndent(savedState{SourceID: h.sourceID, IDs: h.ids}, "", " ")
	return os.WriteFile(filepath.Join(h.dir, "state.json"), b, 0o600)
}

func (h *harness) loadState() error {
	b, err := os.ReadFile(filepath.Join(h.dir, "state.json"))
	if err != nil {
		return fmt.Errorf("reuse: %w (the previous run did not finish its dataset)", err)
	}
	var s savedState
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	h.sourceID, h.ids = s.SourceID, s.IDs
	w, err := os.ReadFile(filepath.Join(h.dir, "wire.ndjson"))
	if err != nil {
		return err
	}
	for _, l := range bytes.Split(w, []byte("\n")) {
		if len(l) > 0 {
			h.wire = append(h.wire, l)
		}
	}
	return nil
}

// ---- measurement helpers ----

// sampler records the peak of the Go heap while a job runs.
type sampler struct {
	stop chan struct{}
	done chan struct{}
	peak atomic.Uint64
}

var heapSamples = []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/memory/classes/heap/unused:bytes"}}

func heapNow() uint64 {
	s := append([]metrics.Sample(nil), heapSamples...)
	metrics.Read(s)
	var t uint64
	for _, x := range s {
		if x.Value.Kind() == metrics.KindUint64 {
			t += x.Value.Uint64()
		}
	}
	return t
}

func startSampler() *sampler {
	s := &sampler{stop: make(chan struct{}), done: make(chan struct{})}
	s.peak.Store(heapNow())
	go func() {
		defer close(s.done)
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				if v := heapNow(); v > s.peak.Load() {
					s.peak.Store(v)
				}
			}
		}
	}()
	return s
}

func (s *sampler) end() float64 {
	close(s.stop)
	<-s.done
	return float64(s.peak.Load()) / (1 << 20)
}

func (h *harness) dbSize() int64 {
	var n int64
	for _, suf := range []string{"", "-wal"} {
		if fi, err := os.Stat(h.dbPath() + suf); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// job measures fn as one job of the report.
func (h *harness) job(name string, fn func() (map[string]any, error)) *JobStats {
	before := h.dbSize()
	s := startSampler()
	t0 := time.Now()
	det, err := fn()
	j := &JobStats{Name: name, Seconds: time.Since(t0).Seconds(), HeapPeakMB: s.end(), Detail: det, OK: err == nil}
	j.DBGrowthMB = mb(h.dbSize() - before)
	if err != nil {
		j.Error = err.Error()
	}
	fmt.Printf("    job %-32s %8.2f s  heap %6.0f MB  %v\n", name, j.Seconds, j.HeapPeakMB, errOr(err, ""))
	h.rep.Jobs = append(h.rep.Jobs, j)
	return j
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(float64(len(s)-1)*p + 0.5)
	return s[i]
}

// rowCounts fills the dataset table counts and sizes.
func (h *harness) rowCounts(ctx context.Context) error {
	db, err := sql.Open("sqlite", "file:"+h.dbPath()+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	h.rep.Dataset.Rows = map[string]int64{}
	for _, n := range names {
		var c int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM "`+n+`"`).Scan(&c); err == nil {
			h.rep.Dataset.Rows[n] = c
		}
	}
	if fi, err := os.Stat(h.dbPath()); err == nil {
		h.rep.Dataset.FileBytes = fi.Size()
	}
	if fi, err := os.Stat(h.dbPath() + "-wal"); err == nil {
		h.rep.Dataset.WALBytes = fi.Size()
	}
	if n := h.rep.Dataset.Rows["intake_events"]; n > 0 {
		h.rep.Dataset.BytesPerEvent = float64(h.rep.Dataset.FileBytes) / float64(n)
	}
	return nil
}

// explain runs the plans on a plain connection to the same file.
func (h *harness) explain(ctx context.Context) error {
	db, err := store.OpenWith(ctx, h.dbPath(), store.NewRegistry())
	if err != nil {
		return err
	}
	defer db.Close()
	trace.explain(ctx, db.DB)
	return nil
}

// ---- webhook receiver ----

type hookServer struct {
	srv   *http.Server
	ln    net.Listener
	URL   string
	n     atomic.Int64
	delay atomic.Int64 // ns
	mu    sync.Mutex
}

func newHookServer() *hookServer {
	h := &hookServer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	h.ln = ln
	h.URL = "http://" + ln.Addr().String()
	h.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if d := time.Duration(h.delay.Load()); d > 0 && strings.HasPrefix(r.URL.Path, "/slow") {
			time.Sleep(d)
		}
		h.n.Add(1)
		w.WriteHeader(204)
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = h.srv.Serve(ln) }()
	return h
}

func (h *hookServer) Close() { _ = h.srv.Close() }
