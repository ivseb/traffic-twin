package core_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// vclock is the virtual clock shared by keyguard, tt-core's analysis
// components and the source: the simulated week runs in seconds.
type vclock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *vclock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// Set moves the clock forward (never back).
func (c *vclock) Set(t time.Time) {
	c.mu.Lock()
	if t.After(c.t) {
		c.t = t
	}
	c.mu.Unlock()
}

const testPassword = "correct-horse-battery-1"

type session struct {
	t      *testing.T
	base   string
	hc     *http.Client
	cookie string
	csrf   string
}

func (s *session) do(method, path string, body any) (int, []byte) {
	s.t.Helper()
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case string:
		rd, ctype = strings.NewReader(b), "application/json"
	default:
		j, _ := json.Marshal(b)
		rd, ctype = bytes.NewReader(j), "application/json"
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
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
	code, b := s.do(method, path, body)
	if code != want {
		s.t.Fatalf("%s %s = %d (want %d): %s", method, path, code, want, b)
	}
	return b
}

func (s *session) json(want int, method, path string, body, out any) {
	s.t.Helper()
	b := s.must(want, method, path, body)
	if err := json.Unmarshal(b, out); err != nil {
		s.t.Fatalf("%s %s: %v: %s", method, path, err, b)
	}
}

// signIn reads the session cookie and CSRF token from a login or setup
// answer.
func signIn(t *testing.T, base string, hc *http.Client, path string, body map[string]string) *session {
	t.Helper()
	s := &session{t: t, base: base, hc: hc}
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

// TestProductEndToEnd is the acceptance test of the product: a real
// keyguard and a real tt-core in one process, a source enrolled through
// Fleet sending sanitized demo traffic over mTLS, contracts, rules, world,
// gate, signed pack, mock and exports, all through the admin API.
func TestProductEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end acceptance test")
	}
	began := time.Now()
	step := func(name string) { t.Logf("%6.2fs %s", time.Since(began).Seconds(), name) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &vclock{t: time.Now().UTC().Truncate(time.Second)}

	// keyguard, in-process on a Unix socket, generated keys.
	kgDir, err := os.MkdirTemp("", "tte2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(kgDir) })
	kg, err := core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: kgDir, Now: clock.Now,
		Logger: keyguard.NewLogger(io.Discard, "error", "text"),
		Tune:   func(c *keyguard.Config) { c.MatchInterval, c.PackInterval, c.BloomCapacity = 0, 0, 200000 }})
	if err != nil {
		t.Fatal(err)
	}
	defer kg.Close()

	// tt-core: admin over TLS (self-signed loopback), intake with the
	// Fleet-managed certificate.
	dir := t.TempDir()
	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
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
	cfg.Log.Level = "error"
	c, err := core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-e2e", AdminListener: adminLn, IntakeListener: intakeLn,
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
	eventually(t, 5*time.Second, "readyz", func() bool {
		resp, err := hc.Get(base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	step("keyguard and core ready")

	// First administrator with the setup token, then the team.
	if c.SetupToken() == "" {
		t.Fatal("no setup token")
	}
	ada := signIn(t, base, hc, "/api/v1/setup", map[string]string{"setup_token": c.SetupToken(), "username": "ada", "password": testPassword})
	team := map[string][]string{"olga": {"operator"}, "rita": {"rule-reviewer"}, "paul": {"publisher"}, "eve": {"event-exporter"},
		"audrey": {"auditor"}, "pia": {"policy-approver"}}
	users := map[string]*session{}
	for name, roles := range team {
		ada.must(201, "POST", "/api/v1/users", map[string]any{"username": name, "password": testPassword, "roles": roles})
		users[name] = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": name, "password": testPassword})
	}
	olga, rita, paul, eve, audrey := users["olga"], users["rita"], users["paul"], users["eve"], users["audrey"]
	var ul []map[string]any
	audrey.json(200, "GET", "/api/v1/users", nil, &ul)
	if len(ul) != 7 {
		t.Fatalf("users: %v", ul)
	}
	olga.must(403, "POST", "/api/v1/users", map[string]any{"username": "mallory", "password": testPassword, "roles": []string{"admin"}})
	var ver map[string]string
	olga.json(200, "GET", "/api/v1/version", nil, &ver)
	if ver["version"] != "0.0.0-e2e" || ver["spec"] == "" {
		t.Fatalf("version: %v", ver)
	}
	var kst map[string]any
	olga.json(200, "GET", "/api/v1/keyguard/status", nil, &kst)
	if kst["reachable"] != true || kst["admin_override"] != true {
		t.Fatalf("keyguard status: %v", kst)
	}

	// Group, enrollment token, starter policy approved by the admin alone
	// (admin override with a reason).
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "demo", "allowed_service_names": []string{"shop-api"}, "policy_id": "p-demo"})
	var tok struct {
		Token string `json:"token"`
	}
	olga.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "demo", "token_type": "one_time"}, &tok)
	var pv struct {
		PolicyID     string `json:"policy_id"`
		Version      int64  `json:"version"`
		Status       string `json:"status"`
		ApprovalMode string `json:"approval_mode"`
	}
	olga.json(201, "POST", "/api/v1/fleet/groups/demo/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10"}, &pv)
	approve := func(v int64) {
		t.Helper()
		path := fmt.Sprintf("/api/v1/fleet/policies/p-demo/versions/%d/approve", v)
		ada.must(422, "POST", path, nil) // an admin approves alone only with a reason
		ada.must(200, "POST", path, map[string]any{"reason": "single-maintainer trial"})
	}
	// The starter policy opens no value: keyguard signs it without
	// approvals (policy.md 7, observe phase).
	if pv.Status != "active" || pv.ApprovalMode != "observe" {
		t.Fatalf("starter policy: %+v", pv)
	}
	step("starter policy signed by keyguard")

	// The source: enrollment with the pinned token, mTLS from then on.
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
	eventually(t, 10*time.Second, "source capturing under the starter policy", func() bool { _, ok := src.Active(); return ok })

	// The demo policy (HMAC on ids, keep on states and codes): proposed by
	// the operator, approved by the admin.
	olga.json(201, "POST", "/api/v1/fleet/policies", demosim.AuthorPolicy, &pv)
	approve(pv.Version)
	eventually(t, 10*time.Second, "source on the demo policy", func() bool {
		a := src.AcceptedPolicy()
		cp, ok := src.Active()
		return ok && a != nil && a.Policy.Version == pv.Version && cp.Policy.Policy.Version == pv.Version
	})
	step("demo policy active at the source")

	// A simulated week of the demo shop, sanitized at the source and sent
	// over mTLS. The virtual clock follows the traffic.
	start := clock.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)
	sim := demosim.Run(demosim.Config{Seed: 42, Customers: 600, Days: 7, Start: start})
	xs := sim.Exchanges()
	var sent int
	for i := range xs {
		x := &xs[i]
		clock.Set(x.TS)
		cp, ok := src.Active()
		for wait := time.Now(); !ok; cp, ok = src.Active() {
			if time.Since(wait) > 10*time.Second {
				t.Fatalf("source stopped capturing at exchange %d (state %s)", i, src.State())
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
		if i%256 == 0 {
			for src.Stats().QueueEvents > 10000 {
				time.Sleep(2 * time.Millisecond)
			}
		}
		src.Emit(sourceclient.Event{JSON: ev, TS: x.TS.Truncate(time.Millisecond), TraceID: x.Trace, SpanID: x.Span, PolicyHash: cp.Policy.Hash})
		sent++
	}
	srcID := src.Identity().SourceID
	eventually(t, 60*time.Second, "events stored", func() bool {
		st := c.Intake().SourceStats(srcID)
		return int(st.Accepted+st.RejectedTotal) >= sent || src.Counters().Snapshot().EventsDroppedQueue > 0
	})
	if err := c.Intake().WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	st := c.Intake().SourceStats(srcID)
	if d := src.Counters().Snapshot().EventsDroppedQueue; d > 0 || st.RejectedTotal > 0 || int(st.Accepted) != sent {
		t.Fatalf("sent %d, accepted %d, rejected %v, dropped at source %d", sent, st.Accepted, st.Rejected, d)
	}
	end := sim.End()
	clock.Set(end.Add(time.Hour))
	// tt-core runs on the virtual clock too: the sessions opened before the
	// traffic ran are long past their timeouts, people sign in again.
	for _, u := range []struct {
		s    *session
		name string
	}{{ada, "ada"}, {olga, "olga"}, {rita, "rita"}, {paul, "paul"}, {eve, "eve"}, {audrey, "audrey"}, {users["pia"], "pia"}} {
		*u.s = *signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": u.name, "password": testPassword})
	}
	step(fmt.Sprintf("%d sanitized events stored", sent))

	// Contracts: a snapshot per service now, through the admin API.
	for _, svc := range []string{"shop-api", "shipping-ext"} {
		olga.must(201, "POST", "/api/v1/contracts/"+svc+"/snapshots", map[string]any{"from": start, "to": end})
	}
	code, b := audrey.do("GET", "/api/v1/contracts/shop-api", nil)
	if code != 200 || !bytes.Contains(b, []byte(`"/orders/{id}/shipment"`)) || bytes.Contains(b, []byte("tk1:")) {
		t.Fatalf("contract: %d %.300s", code, b)
	}

	// Rules: mining run, then the reviewer approves the drafts.
	var job struct {
		JobID  string         `json:"job_id"`
		Status string         `json:"status"`
		Result map[string]any `json:"result"`
	}
	olga.json(202, "POST", "/api/v1/rules/mine", nil, &job)
	if job.Status != "done" {
		t.Fatalf("mining job: %+v", job)
	}
	var drafts []map[string]any
	rita.json(200, "GET", "/api/v1/rules?status=draft", nil, &drafts)
	kinds := map[string]int{}
	for _, r := range drafts {
		kinds[fmt.Sprint(r["kind"])]++
		rita.must(200, "POST", "/api/v1/rules/"+fmt.Sprint(r["id"])+"/approve", nil)
	}
	if kinds["causal"] < 1 || kinds["batch"] < 1 {
		t.Fatalf("mined rules: %v", kinds)
	}
	step(fmt.Sprintf("contracts snapshotted, %d rules mined and approved %v", len(drafts), kinds))

	// Archetypes, world, pack: built by the operator, released by the
	// publisher.
	olga.must(202, "POST", "/api/v1/archetypes/build", map[string]any{"k_min": 20})
	olga.must(422, "POST", "/api/v1/archetypes/build", map[string]any{"k_min": 5}) // below world.k_min
	var wj struct {
		Result struct {
			WorldID string `json:"world_id"`
		} `json:"result"`
	}
	olga.json(202, "POST", "/api/v1/worlds", map[string]any{"seed": 42, "customers": 30}, &wj)
	var pj struct {
		Result struct {
			PackID     string          `json:"pack_id"`
			Status     string          `json:"status"`
			GateReport json.RawMessage `json:"gate_report"`
		} `json:"result"`
	}
	olga.json(202, "POST", "/api/v1/packs", map[string]any{"world_id": wj.Result.WorldID}, &pj)
	if pj.Result.Status != "signed" {
		t.Fatalf("pack: %s %s", pj.Result.Status, pj.Result.GateReport)
	}
	packID := pj.Result.PackID
	paul.must(200, "POST", "/api/v1/packs/"+packID+"/publish", nil)
	archive := paul.must(200, "GET", "/api/v1/packs/"+packID+"/download", nil)
	step("pack " + packID + " built, gated, signed and published")

	// The pack verifies with keyguard's public keys and runs in the mock.
	pks, err := c.Keyguard().PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gateKeys, err := pack.ParseKeySet(pks.GatePubKeys())
	if err != nil {
		t.Fatal(err)
	}
	packFile := filepath.Join(dir, packID+".ttpack")
	if err := os.WriteFile(packFile, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	pk, err := pack.Load(packFile, pack.Options{Keys: gateKeys, Now: clock.Now})
	if err != nil {
		t.Fatalf("pack.Load: %v", err)
	}
	if len(pk.World.Customers) != 30 {
		t.Fatalf("customers in the pack: %d", len(pk.World.Customers))
	}
	m, err := mock.New(mock.Config{Pack: packFile, Keys: gateKeys, Latency: "off", Faults: "off", Now: clock.Now})
	if err != nil {
		t.Fatalf("mock: %v", err)
	}
	ms := httptest.NewServer(m.Handler())
	defer ms.Close()
	mockTest(t, ms.URL, pk.World.Customers[0].ID)
	step("mock serves the pack: order, clock advance, shipment states")

	consoleMockTest(t, ctx, base, hc, olga, ada, paul, pks.GatePubKeys(), packID, clock.Now)
	step("mock in console mode: fetch, verify, report, commands, prepare and hot reload, revoked token")

	// Exports to the other mock tools, as zip downloads.
	for _, target := range []string{"wiremock", "microcks", "prism"} {
		var ej struct {
			Status string `json:"status"`
			Result struct {
				ExportID string `json:"export_id"`
			} `json:"result"`
		}
		paul.json(202, "POST", "/api/v1/exports", map[string]any{"pack_id": packID, "target": target}, &ej)
		if ej.Status != "done" {
			t.Fatalf("export %s: %+v", target, ej)
		}
		audrey.must(200, "GET", "/api/v1/exports/"+ej.Result.ExportID, nil)
		z := paul.must(200, "GET", "/api/v1/exports/"+ej.Result.ExportID+"/download", nil)
		files := unzip(t, z, filepath.Join(dir, "exports"))
		if !files[target+"/export-report.json"] || len(files) < 2 {
			t.Fatalf("export %s files: %v", target, files)
		}
	}
	step("exported to wiremock, microcks and prism")

	// Event-level export (OCEL 2.0) for the event-exporter only.
	olga.must(403, "POST", "/api/v1/events/export", map[string]any{"from": start, "to": end, "format": "ocel2-json"})
	eve.json(202, "POST", "/api/v1/events/export", map[string]any{"from": start, "to": end, "format": "ocel2-json"}, &job)
	ocel := eve.must(200, "GET", "/api/v1/events/export/"+job.JobID+"/download", nil)
	var od map[string]any
	if err := json.Unmarshal(ocel, &od); err != nil || od["objects"] == nil || od["events"] == nil {
		t.Fatalf("ocel: %v %.200s", err, ocel)
	}
	eve.must(200, "GET", "/api/v1/jobs/"+job.JobID, nil)
	paul.must(404, "GET", "/api/v1/jobs/"+job.JobID, nil)
	audrey.must(200, "GET", "/api/v1/quarantine", nil)
	audrey.must(200, "GET", "/api/v1/store/retention", nil)
	step("events exported (OCEL)")

	// The rest of the composed admin API.
	ada.must(400, "PUT", "/api/v1/store/retention", map[string]any{"events_days": 400})
	ada.must(200, "PUT", "/api/v1/store/retention", map[string]any{"events_days": 60})
	if c.Intake().Retention() != 60*24*time.Hour {
		t.Fatalf("retention not applied: %v", c.Intake().Retention())
	}
	var pj2 struct {
		JobID  string `json:"job_id"`
		Status string `json:"status"`
		Result struct {
			Events int64 `json:"events"`
		} `json:"result"`
	}
	ada.json(202, "POST", "/api/v1/store/purge", map[string]any{"before": start.Add(-time.Hour)}, &pj2)
	if pj2.JobID == "" || (pj2.Status != "running" && pj2.Status != "done") {
		t.Fatalf("purge is a background job: %+v", pj2)
	}
	for deadline := time.Now().Add(10 * time.Second); pj2.Status == "running" && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		ada.json(200, "GET", "/api/v1/jobs/"+pj2.JobID, nil, &pj2)
	}
	if pj2.Status != "done" || pj2.Result.Events != 0 {
		t.Fatalf("purge: %+v", pj2)
	}
	// Settings: two labels are editable by an admin, the rest is read-only.
	var sv struct {
		General struct {
			InstallationName string `json:"installation_name"`
			Environment      string `json:"environment"`
		} `json:"general"`
		Privacy struct {
			KMin map[string]int `json:"k_min"`
		} `json:"privacy"`
		Access struct {
			Session map[string]int `json:"session"`
			OIDC    map[string]any `json:"oidc"`
		} `json:"access"`
	}
	olga.json(200, "GET", "/api/v1/settings", nil, &sv)
	if sv.Privacy.KMin["contract"] != 20 || sv.Privacy.KMin["gate"] != 20 || sv.Access.Session["idle_timeout_s"] != 1800 || sv.Access.OIDC["enabled"] != false {
		t.Fatalf("settings: %+v", sv)
	}
	paul.must(403, "GET", "/api/v1/settings", nil)
	olga.must(403, "PATCH", "/api/v1/settings", map[string]any{"environment": "staging"})
	ada.must(400, "PATCH", "/api/v1/settings", map[string]any{"k_min": 2})                 // security settings are config-only
	ada.must(400, "PATCH", "/api/v1/settings", map[string]any{"environment": "prod"})      // not a known label
	ada.must(400, "PATCH", "/api/v1/settings", map[string]any{"installation_name": "<b>"}) // not a plain name
	ada.json(200, "PATCH", "/api/v1/settings", map[string]any{"installation_name": "Acme Lab", "environment": "staging"}, &sv)
	if sv.General.InstallationName != "Acme Lab" || sv.General.Environment != "staging" {
		t.Fatalf("settings after patch: %+v", sv)
	}
	var verInfo map[string]string
	paul.json(200, "GET", "/api/v1/version", nil, &verInfo)
	if verInfo["installation_name"] != "Acme Lab" || verInfo["environment"] != "staging" {
		t.Fatalf("version: %v", verInfo)
	}

	// Twin selection: stored by the server and used as the default of pack builds.
	var svcs []map[string]any
	olga.json(200, "GET", "/api/v1/services", nil, &svcs)
	var external, inbound string
	for _, s := range svcs {
		if s["kind"] == "inbound" && inbound == "" {
			inbound = fmt.Sprint(s["service"])
		}
		if s["kind"] != "inbound" && external == "" {
			external = fmt.Sprint(s["service"])
			if s["twin"] != true {
				t.Fatalf("external services are twinned by default: %v", s)
			}
		}
	}
	if external == "" || inbound == "" {
		t.Fatalf("services: %v", svcs)
	}
	audrey.must(403, "PUT", "/api/v1/services/"+external+"/twin", map[string]any{"twin": false})
	ada.must(200, "PUT", "/api/v1/services/"+external+"/twin", map[string]any{"twin": true}) // admin implies operator (audited override)
	olga.must(400, "PUT", "/api/v1/services/"+external+"/twin", map[string]any{})
	olga.must(404, "PUT", "/api/v1/services/nope/twin", map[string]any{"twin": false})
	olga.must(422, "PUT", "/api/v1/services/"+inbound+"/twin", map[string]any{"twin": false})
	olga.must(200, "PUT", "/api/v1/services/"+external+"/twin", map[string]any{"twin": false})
	svcs = nil
	audrey.json(200, "GET", "/api/v1/services", nil, &svcs)
	for _, s := range svcs {
		if s["service"] == external && s["twin"] != false {
			t.Fatalf("twin not stored: %v", s)
		}
	}
	// The rules use the service that was switched off: the default build says so.
	var perr struct {
		Code string `json:"code"`
	}
	olga.json(422, "POST", "/api/v1/packs", map[string]any{"world_id": wj.Result.WorldID}, &perr)
	if perr.Code != "missing_service" {
		t.Fatalf("pack build ignores the twin selection: %+v", perr)
	}
	olga.must(200, "PUT", "/api/v1/services/"+external+"/twin", map[string]any{"twin": true})

	// The audit log has who asked for the mining run, settings and twin changes; tail paging.
	var tail []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(audrey.must(200, "GET", "/api/v1/audit/export?last=200", nil))), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		tail = append(tail, e)
	}
	actions := map[string]bool{}
	for _, e := range tail {
		actions[fmt.Sprint(e["action"])] = true
	}
	for _, a := range []string{"rule.mine_request", "settings.update", "service.twin", "store.purge.start", "store.purge"} {
		if !actions[a] {
			t.Errorf("audit lacks %s", a)
		}
	}
	if len(tail) < 2 || tail[0]["seq"].(float64) >= tail[len(tail)-1]["seq"].(float64) {
		t.Fatalf("tail is not ascending: %d entries", len(tail))
	}

	preset := map[string]any{"preset_id": "busy-customer", "name": "Cliente abituale", "archetype": "arch-01"}
	olga.must(201, "POST", "/api/v1/scenario-presets", preset)
	olga.must(409, "POST", "/api/v1/scenario-presets", preset)
	preset["description"] = "Un cliente che ordina spesso"
	olga.must(200, "PUT", "/api/v1/scenario-presets/busy-customer", preset)
	var presets []map[string]any
	paul.json(200, "GET", "/api/v1/scenario-presets", nil, &presets)
	if len(presets) != 1 || presets[0]["description"] == nil {
		t.Fatalf("presets: %v", presets)
	}
	olga.must(204, "DELETE", "/api/v1/scenario-presets/busy-customer", nil)
	ids := map[string]string{}
	for _, u := range ul {
		ids[fmt.Sprint(u["username"])] = fmt.Sprint(u["id"])
	}
	uid := ids["audrey"]
	ada.must(200, "PATCH", "/api/v1/users/"+uid, map[string]any{"roles": []string{"auditor", "operator"}})
	audrey.must(200, "GET", "/api/v1/fleet/sources", nil)                                           // roles are re-read at every request
	ada.must(400, "PATCH", "/api/v1/users/"+uid, map[string]any{"disabled": true, "password": "x"}) // too short: nothing applied
	ada.must(409, "PATCH", "/api/v1/users/"+ids["ada"], map[string]any{"disabled": true})
	audrey.must(200, "GET", "/api/v1/keyguard/audit", nil)

	// A keep field that suddenly carries many distinct values goes into
	// quarantine; lifting it (dismiss) opens data: two policy-approvers.
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
		cp, _ := src.Active()
		out, err := cp.Engine.Sanitize(&x.Ex, x.TS, x.SampledBy())
		if err != nil {
			t.Fatal(err)
		}
		meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
			TS: x.TS, LatencyMS: 5, Status: 200, TraceID: x.Trace, SpanID: x.Span}, cp.Policy)
		ev, _ := sanitizer.BuildEvent(meta, out)
		src.Emit(sourceclient.Event{JSON: ev, TS: x.TS.Truncate(time.Millisecond), TraceID: x.Trace, SpanID: x.Span, PolicyHash: cp.Policy.Hash})
	}
	var qs []map[string]any
	eventually(t, 20*time.Second, "quarantine", func() bool {
		qs = nil
		audrey.json(200, "GET", "/api/v1/quarantine", nil, &qs)
		return len(qs) > 0
	})
	item := fmt.Sprint(qs[0]["item_id"])
	if qs[0]["kind"] != "keep-value" || qs[0]["state"] != "quarantined" || strings.Contains(fmt.Sprint(qs), "STATE00") {
		t.Fatalf("quarantine: %v", qs)
	}
	pia := users["pia"]
	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "pete", "password": testPassword, "roles": []string{"policy-approver"}})
	pete := signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "pete", "password": testPassword})
	olga.must(403, "POST", "/api/v1/quarantine/"+item+"/resolve", map[string]any{"resolution": "dismiss"})
	var qi map[string]any
	pia.json(200, "POST", "/api/v1/quarantine/"+item+"/resolve", map[string]any{"resolution": "dismiss"}, &qi)
	if qi["state"] != "dismiss-pending" {
		t.Fatalf("after one dismiss: %v", qi)
	}
	pia.must(409, "POST", "/api/v1/quarantine/"+item+"/resolve", map[string]any{"resolution": "dismiss"})
	pete.json(200, "POST", "/api/v1/quarantine/"+item+"/resolve", map[string]any{"resolution": "dismiss"}, &qi)
	if qi["state"] != "resolved" {
		t.Fatalf("after two dismissals: %v", qi)
	}
	step("quarantine raised and lifted by two approvers")

	// Hosts registry (spec v1.5): calls to hosts the policy does not declare
	// leave as host patterns and are grouped by registrable domain; one of
	// them is twinned through a policy draft.
	cp, _ := src.Active()
	for i, ub := range []string{"https://api.payments.example", "https://API.Payments.example:443", "https://t-3912345678.tenant.example:8443"} {
		ts := clock.Now().Add(time.Duration(100+i) * time.Second)
		ex := sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: ub, Method: "POST", RawPath: []byte("/v1/charges"), Status: 502 - 300*(i%2)}
		out, err := cp.Engine.Sanitize(&ex, ts, sanitizer.ByRandom)
		if err != nil {
			t.Fatal(err)
		}
		meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
			TS: ts, LatencyMS: int64(40 + i), Status: ex.Status}, cp.Policy)
		ev, _ := sanitizer.BuildEvent(meta, out)
		src.Emit(sourceclient.Event{JSON: ev, TS: ts.Truncate(time.Millisecond), PolicyHash: cp.Policy.Hash})
	}
	type hostsView struct {
		Domains []struct {
			Domain   string `json:"domain"`
			Calls    int64  `json:"calls"`
			Patterns []struct {
				Pattern   string  `json:"pattern"`
				Service   string  `json:"service"`
				Declared  bool    `json:"declared"`
				Exact     bool    `json:"exact"`
				Calls     int64   `json:"calls"`
				ErrorRate float64 `json:"error_rate"`
				P50       *int64  `json:"latency_p50_ms"`
				Callers   []struct {
					Service string `json:"service"`
				} `json:"callers"`
				Policies []string `json:"policies"`
			} `json:"patterns"`
		} `json:"domains"`
		Discovery map[string]string `json:"discovery"`
	}
	var hv hostsView
	eventually(t, 20*time.Second, "hosts registry", func() bool {
		hv = hostsView{}
		olga.json(200, "GET", "/api/v1/hosts", nil, &hv)
		return len(hv.Domains) >= 3
	})
	rita.must(403, "GET", "/api/v1/hosts", nil)
	got := map[string]string{}
	for _, d := range hv.Domains {
		for _, p := range d.Patterns {
			got[d.Domain+" "+p.Pattern] = fmt.Sprintf("%s declared=%v exact=%v calls=%d", p.Service, p.Declared, p.Exact, p.Calls)
			if p.Pattern == "api.payments.example" && (p.Calls != 2 || p.ErrorRate != 0.5 || p.P50 == nil || *p.P50 != 40 ||
				len(p.Callers) != 1 || p.Callers[0].Service != "shop-api" || len(p.Policies) != 1 || p.Policies[0] != "p-demo") {
				t.Fatalf("payments host: %+v", p)
			}
		}
	}
	for k, want := range map[string]string{
		"payments.example api.payments.example":  "host:api.payments.example declared=false exact=true calls=2",
		"tenant.example {*}.tenant.example:8443": "host:{*}.tenant.example:8443 declared=false exact=false calls=1",
		"carrier.example api.carrier.example":    "shipping-ext declared=true exact=true",
	} {
		if !strings.HasPrefix(got[k], want) {
			t.Fatalf("hosts registry %q = %q, want %q (all: %v)", k, got[k], want, got)
		}
	}
	if b := olga.must(200, "GET", "/api/v1/hosts", nil); bytes.Contains(b, []byte("3912345678")) {
		t.Fatal("hosts registry shows a value")
	}
	if hv.Discovery["p-demo"] != "auto" {
		t.Fatalf("discovery modes: %v", hv.Discovery)
	}
	var tv struct {
		PolicyID string `json:"policy_id"`
		Version  int64  `json:"version"`
		Status   string `json:"status"`
		Origin   string `json:"origin"`
		Author   string `json:"author_yaml"`
	}
	// The events do not carry the scheme of a host: it is asked, never guessed.
	olga.must(422, "POST", "/api/v1/hosts/host:api.payments.example/twin", map[string]any{})
	olga.json(201, "POST", "/api/v1/hosts/host:api.payments.example/twin", map[string]any{"scheme": "https"}, &tv)
	if tv.PolicyID != "p-demo" || tv.Status != "active" || tv.Origin != "host-twin" || !strings.Contains(tv.Author, "api.payments.example:") || !strings.Contains(tv.Author, "https://api.payments.example") {
		t.Fatalf("twin draft: %+v", tv)
	}
	olga.must(409, "POST", "/api/v1/hosts/api.carrier.example/twin", map[string]any{"policy_id": "p-demo", "scheme": "https"})
	olga.must(422, "POST", "/api/v1/hosts/"+url.PathEscape("{*}.tenant.example:8443")+"/twin", map[string]any{"policy_id": "p-demo"})
	olga.must(422, "POST", "/api/v1/hosts/"+url.PathEscape("{*}.tenant.example:8443")+"/twin",
		map[string]any{"policy_id": "p-demo", "base": "https://eu1.other.example:8443"})
	olga.json(201, "POST", "/api/v1/hosts/"+url.PathEscape("{*}.tenant.example:8443")+"/twin",
		map[string]any{"policy_id": "p-demo", "base": "https://eu1.tenant.example:8443", "service": "tenant-ext"}, &tv)
	if !strings.Contains(tv.Author, "tenant-ext:") {
		t.Fatalf("twin draft with an explicit base: %+v", tv)
	}
	// Declared once (usability test 5): a host that was declared since shows
	// as one entry with the calls it made before, not as the old pattern row
	// next to the declared one; the header counts include every entry.
	type foldedView struct {
		Domains []struct {
			Patterns []struct {
				Pattern    string   `json:"pattern"`
				Service    string   `json:"service"`
				Declared   bool     `json:"declared"`
				Calls      int64    `json:"calls"`
				FoldedFrom []string `json:"folded_from"`
			} `json:"patterns"`
		} `json:"domains"`
		Counts struct {
			Domains, Hosts, IPHosts, Declared, Undeclared, Folded int
		} `json:"counts"`
	}
	var fv foldedView
	olga.json(200, "GET", "/api/v1/hosts", nil, &fv)
	entries, listed := 0, 0
	for _, d := range fv.Domains {
		for _, p := range d.Patterns {
			listed++
			if p.Pattern == "api.payments.example" {
				entries++
				if !p.Declared || p.Calls != 2 || len(p.FoldedFrom) != 1 || p.FoldedFrom[0] != "api.payments.example" || strings.HasPrefix(p.Service, "host:") {
					t.Fatalf("declared host after the twin: %+v", p)
				}
			}
		}
	}
	if entries != 1 || fv.Counts.Hosts != listed || fv.Counts.Domains != len(fv.Domains) || fv.Counts.Folded < 1 || fv.Counts.Declared == 0 {
		t.Fatalf("hosts after the twin: %d entries for the declared host; counts %+v; %d listed", entries, fv.Counts, listed)
	}
	step("hosts registry grouped by domain, twin drafts created")

	// Graceful shutdown.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("core.Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("core did not stop")
	}
	step("stopped")
}

// orderBody is an invented order, shaped like the demo shop's requests.
var orderBody = map[string]any{
	"items": []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 1}}, "email": "anna.rossi@example.com",
	"shippingAddress": map[string]any{"fullName": "Anna Rossi", "line1": "Via Inventata 2", "city": "Roma", "postcode": "00100", "country": "IT"},
}

// mockTest drives the mock like a test of the system under test would.
func mockTest(t *testing.T, base, customer string) {
	t.Helper()
	call := func(method, path string, body any, sess string) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, base+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if sess != "" {
			req.Header.Set("X-TT-Session", sess)
			// Required by the inferred contract (the demo shop always gets them).
			req.Header.Set("Authorization", "Bearer synthetic-test-token")
			req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if out == nil {
			out = map[string]any{"_raw": string(raw)}
		}
		return resp.StatusCode, out
	}
	code, s := call("POST", "/__tt/sessions", map[string]any{"seed": 7, "customer": customer}, "")
	if code != 201 {
		t.Fatalf("session: %d %v", code, s)
	}
	sid := s["id"].(string)
	states := map[string]int{}
	var orders []string
	for range 20 {
		code, o := call("POST", "/__svc/shop-api/orders", orderBody, sid)
		if code != 201 {
			_, j := call("GET", "/__tt/sessions/"+sid+"/journal", nil, "")
			t.Fatalf("POST /orders: %d %v\njournal: %v", code, o, j)
		}
		id, _ := o["id"].(string)
		if id == "" || o["shipmentId"] == nil {
			t.Fatalf("order without id or shipment link: %v", o)
		}
		orders = append(orders, id)
	}
	for _, by := range []string{"30m", "12h", "72h"} {
		if code, r := call("POST", "/__tt/sessions/"+sid+"/clock/advance", map[string]any{"by": by}, ""); code != 200 {
			t.Fatalf("advance: %d %v", code, r)
		}
		for _, id := range orders {
			code, sh := call("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sid)
			switch code {
			case 200:
				states[fmt.Sprint(sh["status"])]++
			case 404:
				states["(not visible)"]++
			default:
				t.Fatalf("GET shipment: %d %v", code, sh)
			}
		}
	}
	t.Logf("shipment states over the advances: %v", states)
	if states["DELIVERED"] == 0 || states["CREATED"]+states["IN_TRANSIT"] == 0 {
		t.Fatalf("shipments do not follow their lifecycle: %v", states)
	}

	// A carrier shipment created in a session of a mined pack stays visible
	// for days (docs/GETTING_STARTED.md step 9: no retention in the mock).
	for seed := range 4 {
		_, s := call("POST", "/__tt/sessions", map[string]any{"seed": seed}, "")
		sid := s["id"].(string)
		req := func(method, path string, body any) (int, map[string]any) {
			var rd io.Reader
			if body != nil {
				b, _ := json.Marshal(body)
				rd = bytes.NewReader(b)
			}
			r, _ := http.NewRequest(method, base+path, rd)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-TT-Session", sid)
			r.Header.Set("X-Api-Key", "ck_test_0000") // required by the inferred contract
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var out map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&out)
			return resp.StatusCode, out
		}
		order := fmt.Sprintf("ORD-NEW-%d", seed)
		if code, r := req("POST", "/__svc/shipping-ext/v1/shipments", map[string]any{"orderId": order, "service": "STANDARD", "parcels": 1,
			"recipient": map[string]any{"fullName": "Anna Leone", "email": "anna@example.org"},
			"address":   map[string]any{"line1": "Via Roma 1", "city": "Bologna", "postcode": "40121", "country": "IT"}}); code != 202 {
			t.Fatalf("carrier shipment: %d %v", code, r)
		}
		seen := false
		for day := range 16 {
			call("POST", "/__tt/sessions/"+sid+"/clock/advance", map[string]any{"by": "12h"}, "")
			_, l := req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+order, nil)
			items, _ := l["items"].([]any)
			if len(items) == 0 && seen {
				t.Fatalf("seed %d: the shipment disappeared after %d half days", seed, day+1)
			}
			seen = seen || len(items) > 0
		}
	}
}

func unzip(t *testing.T, z []byte, dir string) map[string]bool {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			t.Fatalf("unsafe zip entry %q", f.Name)
		}
		files[f.Name] = true
		p := filepath.Join(dir, f.Name)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		_ = os.WriteFile(p, b, 0o600)
	}
	return files
}
