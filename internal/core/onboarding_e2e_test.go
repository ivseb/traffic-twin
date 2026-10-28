package core_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/core/demosim"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// Wire shapes of the policy assistant (admin-api policyAssistant).
type assistField struct {
	Part       string `json:"part"`
	Path       string `json:"path"`
	Suggestion string `json:"suggestion"`
}
type assistOp struct {
	Op        string        `json:"op"`
	Calls     int64         `json:"calls"`
	NeedCalls int64         `json:"need_calls"`
	Fields    []assistField `json:"fields"`
}
type assistService struct {
	Service     string     `json:"service"`
	Kind        string     `json:"kind"`
	Declared    bool       `json:"declared"`
	Name        string     `json:"name"`
	HostPattern string     `json:"host_pattern"`
	Exact       bool       `json:"exact"`
	Ops         []assistOp `json:"ops"`
}
type assistResult struct {
	Ready     bool            `json:"ready"`
	NeedCalls int64           `json:"need_calls"`
	Message   string          `json:"message"`
	Services  []assistService `json:"services"`
	Identity  *struct {
		Name string `json:"name"`
	} `json:"identity"`
}

// TestOnboardingWizardEndToEnd is the onboarding wizard without the UI: a
// group without service names, the starter policy approved by the only
// administrator (override with a reason), discovery traffic of the demo,
// the assistant's operations and fields accepted as they are, the draft
// proposed and approved, and capture under the new policy. No YAML is
// written by hand.
func TestOnboardingWizardEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end acceptance test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &vclock{t: time.Now().UTC().Truncate(time.Second)}

	kgDir, err := os.MkdirTemp("", "ttonb")
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
	go func() { _ = c.Run(ctx) }()
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

	// The only administrator, as in docs/GETTING_STARTED.md.
	ada := signIn(t, base, hc, "/api/v1/setup", map[string]string{"setup_token": c.SetupToken(), "username": "ada", "password": testPassword})
	// A second login (curl next to the browser) keeps the first session.
	other := signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "ada", "password": testPassword})
	ada.must(200, "GET", "/api/v1/auth/me", nil)
	other.must(200, "GET", "/api/v1/auth/me", nil)

	// Wizard step 1: group without service names (the first source names
	// it), one-time token, starter policy.
	ada.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "shop", "allowed_service_names": []string{}, "policy_id": nil})
	var tok struct {
		Token string `json:"token"`
	}
	ada.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "shop", "token_type": "one_time"}, &tok)
	var pv struct {
		PolicyID string `json:"policy_id"`
		Version  int64  `json:"version"`
		Status   string `json:"status"`
	}
	ada.json(201, "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"hmac_kid": core.DevHMACKid, "epoch": "2026-10", "sampling_rate": "1"}, &pv)
	if pv.PolicyID != "p-shop" {
		t.Fatalf("starter: %+v", pv)
	}
	approve := func(v int64) {
		t.Helper()
		var out struct {
			Status string `json:"status"`
		}
		ada.json(200, "POST", fmt.Sprintf("/api/v1/fleet/policies/p-shop/versions/%d/approve", v), map[string]any{"reason": "single-maintainer trial"}, &out)
		if out.Status != "active" {
			t.Fatalf("version %d after the admin approval: %s", v, out.Status)
		}
	}
	// The starter policy opens no value: active at once, no approval (policy.md 7).
	if pv.Status != "active" {
		t.Fatalf("starter: %+v", pv)
	}

	// Before any traffic the assistant says what it needs.
	var as assistResult
	ada.json(200, "GET", "/api/v1/fleet/policies/p-shop/assist", nil, &as)
	if as.Ready || as.NeedCalls != 20 || len(as.Services) != 0 || !strings.Contains(as.Message, "20 calls per operation") {
		t.Fatalf("assistant without traffic: %+v", as)
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
	eventually(t, 10*time.Second, "source capturing under the starter policy", func() bool { _, ok := src.Active(); return ok })
	var g struct {
		Allowed []string `json:"allowed_service_names"`
	}
	ada.json(200, "GET", "/api/v1/fleet/groups/shop", nil, &g)
	if len(g.Allowed) != 1 || g.Allowed[0] != "shop-api" {
		t.Fatalf("the first enrollment names the group's service: %v", g.Allowed)
	}

	// send sanitizes the exchanges of a simulation with the policy in force.
	send := func(sim *demosim.Sim) int {
		t.Helper()
		xs := sim.Exchanges()
		before := c.Intake().SourceStats(src.Identity().SourceID).Accepted
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
			by := x.SampledBy()
			if by == sanitizer.BySubject && cp.Policy.Policy.Subject == nil {
				by = sanitizer.ByTrace // no identity.subject yet: no subject token
			}
			out, err := cp.Engine.Sanitize(&x.Ex, x.TS, by)
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
		}
		eventually(t, 60*time.Second, "events stored", func() bool {
			st := c.Intake().SourceStats(src.Identity().SourceID)
			return int(st.Accepted-before)+int(st.RejectedTotal) >= len(xs)
		})
		if err := c.Intake().WaitIdle(ctx); err != nil {
			t.Fatal(err)
		}
		if st := c.Intake().SourceStats(src.Identity().SourceID); st.RejectedTotal > 0 {
			t.Fatalf("rejected events: %v", st.Rejected)
		}
		clock.Set(sim.End().Add(time.Minute))
		ada = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "ada", "password": testPassword})
		return len(xs)
	}

	// Discovery traffic: one simulated day under the starter policy.
	start := clock.Now().Truncate(time.Hour).Add(time.Hour)
	n := send(demosim.Run(demosim.Config{Seed: 7, Customers: 150, Days: 1, Start: start}))
	t.Logf("%d discovery events", n)

	// Wizard step 5: the assistant proposes operations, not "(raw)".
	ada.json(200, "GET", "/api/v1/fleet/policies/p-shop/assist", nil, &as)
	svcOps := map[string]map[string]assistOp{}
	for _, s := range as.Services {
		svcOps[s.Service] = map[string]assistOp{}
		for _, o := range s.Ops {
			svcOps[s.Service][o.Op] = o
		}
	}
	for svc, ops := range map[string][]string{
		"shop-api":                 {"POST /orders", "GET /orders/{id}", "GET /orders/{id}/shipment", "GET /customers/{id}/orders"},
		"host:api.carrier.example": {"POST /v1/shipments", "GET /v1/shipments"},
	} {
		for _, op := range ops {
			if _, ok := svcOps[svc][op]; !ok {
				t.Errorf("assistant: %s %s missing; got %v", svc, op, svcOps)
			}
		}
	}
	for svc, ops := range svcOps {
		for op := range ops {
			if strings.Contains(op, "(raw)") || strings.Contains(op, "drop:") {
				t.Errorf("not a template: %s %s", svc, op)
			}
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if po := svcOps["shop-api"]["POST /orders"]; po.NeedCalls != 0 || len(po.Fields) == 0 {
		t.Fatalf("POST /orders: %+v", po)
	}
	if as.Identity == nil || as.Identity.Name != "authorization" {
		t.Fatalf("identity proposal: %+v", as.Identity)
	}

	// The person accepts every proposal (actions only, never values), names
	// the external service and picks its scheme.
	var services []any
	for _, s := range as.Services {
		ds := map[string]any{"service": s.Service}
		if s.Kind == "external" && !s.Declared {
			if !s.Exact || s.HostPattern != "api.carrier.example" {
				t.Fatalf("external service: %+v", s)
			}
			ds["name"], ds["base"] = "shipping-ext", "https://"+s.HostPattern
		}
		var ops []any
		for _, o := range s.Ops {
			var rules []any
			for _, f := range o.Fields {
				if f.Suggestion != "drop" {
					rules = append(rules, map[string]any{"part": f.Part, "path": f.Path, "action": f.Suggestion})
				}
			}
			ops = append(ops, map[string]any{"op": o.Op, "rules": rules})
		}
		ds["ops"] = ops
		services = append(services, ds)
	}
	draft := map[string]any{"dry_run": true, "identity": map[string]any{"from": "header", "name": "authorization", "jwt_claim": "sub"}, "services": services}
	var dry struct {
		Before string `json:"before"`
		After  string `json:"after"`
	}
	ada.json(200, "POST", "/api/v1/fleet/policies/p-shop/assist/draft", draft, &dry)
	for _, want := range []string{"shipping-ext:", "https://api.carrier.example", "POST /orders", "GET /orders/{id}", "id: hmac(order)",
		"$.shipmentId: hmac(shipment)", "$.customerId: hmac(customer)", "$.status: keep", "orderId: hmac(order)", "jwt_claim: sub"} {
		if !strings.Contains(dry.After, want) {
			t.Fatalf("draft without %q:\n%s", want, dry.After)
		}
	}
	// Personal data and trace context stay drop.
	for _, never := range []string{"shippingAddress", "email", "fullName", "traceparent", "authorization: ", "x-api-key"} {
		if strings.Contains(dry.After, never) {
			t.Fatalf("draft opens %q:\n%s", never, dry.After)
		}
	}
	t.Logf("policy from the wizard:\n%s", dry.After)
	delete(draft, "dry_run")
	ada.json(201, "POST", "/api/v1/fleet/policies/p-shop/assist/draft", draft, &pv)
	if pv.Status != "draft" {
		t.Fatalf("draft: %+v", pv)
	}
	approve(pv.Version)
	eventually(t, 10*time.Second, "source on the wizard policy", func() bool {
		a := src.AcceptedPolicy()
		cp, ok := src.Active()
		return ok && a != nil && a.Policy.Version == pv.Version && cp.Policy.Policy.Version == pv.Version
	})

	// Capture under the new policy: declared operations, tokens and kept
	// values, a subject.
	from := clock.Now()
	send(demosim.Run(demosim.Config{Seed: 8, Customers: 150, Days: 1, Start: from.Add(time.Minute)}))
	seen := map[string]int{}
	var tokens, kept, subjects int
	err = c.Intake().Store().Scan(ctx, intake.Query{PolicyID: "p-shop", From: from}, func(se *intake.StoredEvent) error {
		ev := se.Event
		if ev.Policy.Version != pv.Version {
			return nil
		}
		seen[ev.Service+" "+ev.Op+" "+ev.RouteSource]++
		if ev.Subject != "" {
			subjects++
		}
		if ev.Resp != nil && ev.Resp.Body != nil {
			for _, v := range leaves(*ev.Resp.Body) {
				switch {
				case strings.HasPrefix(v, "tk1:"):
					tokens++
				case strings.HasPrefix(v, "keep:"):
					kept++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shop-api POST /orders policy", "shop-api GET /orders/{id}/shipment policy", "shipping-ext POST /v1/shipments policy", "shipping-ext GET /v1/shipments policy"} {
		if seen[want] == 0 {
			t.Errorf("no events %q under the wizard policy: %v", want, seen)
		}
	}
	if tokens == 0 || kept == 0 || subjects == 0 {
		t.Errorf("capture under the wizard policy: %d tokens, %d kept values, %d subjects", tokens, kept, subjects)
	}
}

// leaves returns the string leaves of a sanitized body.
func leaves(v event.Value) []string {
	switch v.Kind {
	case event.String:
		return []string{v.S}
	case event.Array:
		var out []string
		for _, x := range v.A {
			out = append(out, leaves(x)...)
		}
		return out
	case event.Object:
		var out []string
		for _, m := range v.O {
			out = append(out, leaves(m.V)...)
		}
		return out
	}
	return nil
}
