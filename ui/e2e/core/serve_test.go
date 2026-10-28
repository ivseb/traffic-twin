//go:build e2e

// Package e2e starts the real composed tt-core (internal/core: the same code `tt dev up` runs)
// with a week of the invented demo shop already in it, for the Playwright tests of the UI.
//
// Everything is created through the public API: the first administrator with the setup token,
// the team (one user per role), a group, an enrollment token, the starter and the demo policy
// (approved with the admin override), a source enrolled over mTLS (internal/sourceclient) that
// sends the sanitized traffic, contract snapshots, mined rules (all approved but one), archetypes,
// a world, a released pack and a signed one waiting for release, a quarantined field and a
// scenario preset. The simulated week runs on a virtual clock, which is why this is not a
// separately started `tt dev up` (the first-run test uses the real binary).
//
//	go test -c -tags e2e -o e2e/.bin/core.test ./e2e/core
//	TT_E2E_ADDR=127.0.0.1:17180 e2e/.bin/core.test -test.run TestServe -test.timeout 0
//
// It prints READY when everything is in place and serves until it is killed.
package e2e

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
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	"github.com/ivseb/traffic-twin/internal/ui"
)

// Password of every user.
const password = "correct-horse-battery-1"

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

type session struct {
	t      *testing.T
	base   string
	hc     *http.Client
	cookie string
	csrf   string
}

func (s *session) must(want int, method, path string, body any) []byte {
	s.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string: // a ready-made JSON document
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, s.base+path, rd)
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
	if resp.StatusCode != want {
		s.t.Fatalf("%s %s = %d (want %d): %s", method, path, resp.StatusCode, want, b)
	}
	return b
}

func (s *session) json(want int, method, path string, body, out any) {
	s.t.Helper()
	if err := json.Unmarshal(s.must(want, method, path, body), out); err != nil {
		s.t.Fatal(err)
	}
}

func signIn(t *testing.T, base string, hc *http.Client, path string, body map[string]string) *session {
	t.Helper()
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+path, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Fatalf("POST %s = %d: %s", path, resp.StatusCode, b)
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
		t.Fatalf("no session cookie from %s", path)
	}
	return s
}

func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServe(t *testing.T) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	addr := os.Getenv("TT_E2E_ADDR")
	if addr == "" {
		addr = "127.0.0.1:17180"
	}
	clock := &vclock{t: time.Now().UTC().Truncate(time.Second)}

	dir, err := os.MkdirTemp("", "tte2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	kg, err := core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: dir, Now: clock.Now, Logger: keyguard.NewLogger(io.Discard, "error", "text"),
		Tune: func(c *keyguard.Config) { c.MatchInterval, c.PackInterval, c.BloomCapacity = 0, 0, 200000 }})
	if err != nil {
		t.Fatal(err)
	}
	defer kg.Close()

	adminLn, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(dir, kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fleet.PublicURL = "https://" + intakeLn.Addr().String()
	cfg.Fleet.ClientCertTTL = 30 * 24 * time.Hour
	cfg.Fleet.PolicyMaxAge = 30 * 24 * time.Hour
	cfg.Fleet.HeartbeatInterval, cfg.Fleet.PolicyPollInterval = 50*time.Millisecond, 50*time.Millisecond
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Retention.Events = 365 * 24 * time.Hour
	cfg.Miner.Schedule = 0
	c, err := core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-e2e", AdminListener: adminLn, IntakeListener: intakeLn, UI: ui.Handler(),
		Now: clock.Now, Logger: server.NewLogger(io.Discard, "error", "text"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx) }()

	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	base := "https://" + adminLn.Addr().String()
	eventually(t, 10*time.Second, "readyz", func() bool {
		resp, err := hc.Get(base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// The administrator and the team.
	ada := signIn(t, base, hc, "/api/v1/setup", map[string]string{"setup_token": c.SetupToken(), "username": "ada", "password": password})
	team := map[string][]string{
		"olga": {"operator"}, "rita": {"rule-reviewer"}, "paul": {"publisher"}, "eve": {"event-exporter"}, "audrey": {"auditor"},
		"pia": {"policy-approver"}, "pete": {"policy-approver"},
		"root": {"admin", "operator", "rule-reviewer", "policy-approver", "publisher", "auditor", "event-exporter"},
	}
	users := map[string]*session{}
	for name, roles := range team {
		ada.must(201, "POST", "/api/v1/users", map[string]any{"username": name, "password": password, "roles": roles})
		users[name] = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": name, "password": password})
	}
	olga, rita, paul := users["olga"], users["rita"], users["paul"]

	// Group, token, starter policy and the demo policy, approved by the admin alone with a reason.
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "demo", "allowed_service_names": []string{"shop-api"}, "policy_id": "p-demo"})
	var tok struct {
		Token string `json:"token"`
	}
	olga.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "demo", "token_type": "one_time"}, &tok)
	var pv struct {
		Version int64  `json:"version"`
		Status  string `json:"status"`
	}
	olga.json(201, "POST", "/api/v1/fleet/groups/demo/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10"}, &pv)
	approve := func(v int64) {
		ada.must(200, "POST", fmt.Sprintf("/api/v1/fleet/policies/p-demo/versions/%d/approve", v), map[string]any{"reason": "single-maintainer trial"})
	}
	if pv.Status != "active" { // the starter policy opens no value: active at once (policy.md 7)
		approve(pv.Version)
	}

	keyText, _ := os.ReadFile(kg.HMACKeyFile)
	keys, err := sanitizer.ParseKeys(string(keyText))
	if err != nil {
		t.Fatal(err)
	}
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: cfg.Fleet.PublicURL, Token: tok.Token, StateDir: filepath.Join(dir, "source"),
		Kind: "sdk-go", Version: "0.1.0", ServiceName: "shop-api", Instance: "e2e-1", Keys: keys, KeyKids: []string{core.DevHMACKid},
		HeartbeatInterval: 40 * time.Millisecond, PolicyPollInterval: 40 * time.Millisecond, Now: clock.Now,
		Exporter: sourceclient.ExporterOptions{MaxEvents: 20000, FlushInterval: 20 * time.Millisecond, BaseBackoff: 10 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, MaxRetries: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	src.Start(ctx)
	defer func() {
		cctx, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_ = src.Close(cctx)
	}()
	eventually(t, 10*time.Second, "source capturing", func() bool { _, ok := src.Active(); return ok })
	olga.json(201, "POST", "/api/v1/fleet/policies", demosim.AuthorPolicy, &pv)
	approve(pv.Version)
	eventually(t, 10*time.Second, "source on the demo policy", func() bool {
		a := src.AcceptedPolicy()
		cp, ok := src.Active()
		return ok && a != nil && a.Policy.Version == pv.Version && cp.Policy.Policy.Version == pv.Version
	})

	// A simulated week, sanitized at the source.
	start := clock.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	sim := demosim.Run(demosim.Config{Seed: 42, Customers: 600, Days: 7, Start: start})
	xs := sim.Exchanges()
	emit := func(x *demosim.Exchange) {
		cp, ok := src.Active()
		for wait := time.Now(); !ok; cp, ok = src.Active() {
			if time.Since(wait) > 10*time.Second {
				t.Fatalf("source stopped capturing (state %s)", src.State())
			}
			src.Kick()
			time.Sleep(2 * time.Millisecond)
		}
		out, err := cp.Engine.Sanitize(&x.Ex, x.TS, x.SampledBy())
		if err != nil {
			t.Fatalf("sanitize: %v", err)
		}
		meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
			TS: x.TS, LatencyMS: x.Latency, Status: x.Ex.Status, TraceID: x.Trace, SpanID: x.Span, ParentSpanID: x.Parent}, cp.Policy)
		ev, err := sanitizer.BuildEvent(meta, out)
		if err != nil {
			t.Fatalf("build event: %v", err)
		}
		src.Emit(sourceclient.Event{JSON: ev, TS: x.TS.Truncate(time.Millisecond), TraceID: x.Trace, SpanID: x.Span, PolicyHash: cp.Policy.Hash})
	}
	for i := range xs {
		clock.Set(xs[i].TS)
		if i%256 == 0 {
			for src.Stats().QueueEvents > 10000 {
				time.Sleep(2 * time.Millisecond)
			}
		}
		emit(&xs[i])
	}
	srcID := src.Identity().SourceID
	eventually(t, 60*time.Second, "events stored", func() bool {
		st := c.Intake().SourceStats(srcID)
		return int(st.Accepted+st.RejectedTotal) >= len(xs)
	})
	if err := c.Intake().WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	end := sim.End()
	clock.Set(end.Add(time.Hour))
	// The virtual clock jumped days ahead: the sessions of the team are idle-expired. Sign in again in place, so the
	// variables and closures that hold them keep working.
	for name := range team {
		*users[name] = *signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": name, "password": password})
	}

	// Contract snapshots: two windows, so the history has a diff.
	mid := start.Add(4 * 24 * time.Hour)
	for _, w := range [][2]time.Time{{start, mid}, {mid, end}} {
		for _, svc := range []string{"shop-api", "shipping-ext"} {
			olga.must(201, "POST", "/api/v1/contracts/"+svc+"/snapshots", map[string]any{"from": w[0], "to": w[1]})
		}
	}

	// Rules: mined, all approved but the last one.
	olga.must(202, "POST", "/api/v1/rules/mine", nil)
	var drafts []map[string]any
	rita.json(200, "GET", "/api/v1/rules?status=draft", nil, &drafts)
	for i, r := range drafts {
		if i == len(drafts)-1 && len(drafts) > 1 {
			break
		}
		rita.must(200, "POST", "/api/v1/rules/"+fmt.Sprint(r["id"])+"/approve", nil)
	}

	// Archetypes, world, two packs: one released, one waiting for release.
	olga.must(202, "POST", "/api/v1/archetypes/build", map[string]any{"k_min": 20, "group": "demo"})
	var wj struct {
		Result struct {
			WorldID string `json:"world_id"`
		} `json:"result"`
	}
	olga.json(202, "POST", "/api/v1/worlds", map[string]any{"seed": 42, "customers": 30, "group": "demo"}, &wj)
	var packIDs []string
	for range 2 {
		var pj struct {
			Result struct {
				PackID string `json:"pack_id"`
				Status string `json:"status"`
			} `json:"result"`
		}
		olga.json(202, "POST", "/api/v1/packs", map[string]any{"world_id": wj.Result.WorldID}, &pj)
		if pj.Result.Status != "signed" {
			t.Fatalf("pack status %s", pj.Result.Status)
		}
		packIDs = append(packIDs, pj.Result.PackID)
	}
	paul.must(200, "POST", "/api/v1/packs/"+packIDs[0]+"/publish", nil)
	olga.must(201, "POST", "/api/v1/scenario-presets", map[string]any{"preset_id": "busy-customer", "name": "Cliente abituale", "description": "Un cliente che ordina spesso"})

	// A kept field that suddenly carries many distinct values: quarantined, left for the UI test.
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
		body["status"] = fmt.Sprintf("STATE%04d", i)
		x.Ex.RespBody, _ = json.Marshal(body)
		x.TS = clock.Now().Add(time.Duration(i) * time.Second)
		x.Latency = 5
		emit(&x)
	}
	eventually(t, 20*time.Second, "quarantine", func() bool {
		var qs []map[string]any
		users["audrey"].json(200, "GET", "/api/v1/quarantine", nil, &qs)
		return len(qs) > 0
	})

	t.Logf("tt-core e2e on %s", base)
	fmt.Fprintf(os.Stdout, "READY %s\n", base)
	<-ctx.Done()
	select {
	case <-runDone:
	case <-time.After(20 * time.Second):
	}
}
