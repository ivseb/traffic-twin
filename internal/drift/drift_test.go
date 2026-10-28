package drift_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
	"github.com/ivseb/traffic-twin/internal/drift"
)

var day1 = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

type received struct {
	sig, event, delivery, ts string
	body                     []byte
}

type sink struct {
	mu   sync.Mutex
	got  []received
	fail int // answer 500 this many times first
	srv  *httptest.Server
}

func newSink(t *testing.T) *sink {
	s := &sink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.got = append(s.got, received{sig: r.Header.Get("X-TT-Signature"), event: r.Header.Get("X-TT-Event"),
			delivery: r.Header.Get("X-TT-Delivery"), ts: r.Header.Get("X-TT-Timestamp"), body: b})
		if s.fail > 0 {
			s.fail--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *sink) all() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.got...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	h   *contracttest.Harness
	eng *contract.Engine
	mgr *drift.Manager
	clk *clock
	rcv *sink
	hid string
	sec string
	ctx context.Context
}

func setup(t *testing.T) *fixture { return setupWith(t, true) }

func setupWith(t *testing.T, attach bool) *fixture {
	t.Helper()
	h := contracttest.New(t)
	clk := &clock{t: day1.Add(72 * time.Hour)}
	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	rcv := newSink(t)
	mgr, err := drift.New(drift.Config{
		Allow: []string{"127.0.0.1"}, AllowHTTP: true, MaxAttempts: 4,
		Backoff: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second},
	}, drift.Deps{DB: h.DB, Audit: audit.New(h.DB), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if attach {
		mgr.Attach(eng)
	}
	ctx := context.Background()
	wh, err := mgr.CreateWebhook(ctx, drift.Webhook{Name: "ops chat", URL: rcv.srv.URL + "/hook", Events: []string{"contract.drift", "rule.stale"}})
	if err != nil {
		t.Fatal(err)
	}
	if wh.Secret == "" || !wh.SecretSet {
		t.Fatal("a generated secret must be returned once")
	}
	return &fixture{h: h, eng: eng, mgr: mgr, clk: clk, rcv: rcv, hid: wh.ID, sec: wh.Secret, ctx: ctx}
}

func (f *fixture) snapshotDays(t *testing.T, v2 contracttest.Variant, orders int) {
	t.Helper()
	day2 := day1.Add(24 * time.Hour)
	f.h.DemoDay(day1, orders, contracttest.Variant{})
	f.h.DemoDay(day2, orders, v2)
	f.h.Wait()
	for _, d := range []time.Time{day1, day2} {
		if _, err := f.eng.SnapshotWindow(f.ctx, contract.Window{From: d, To: d.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTypeChangeRaisesBreakingAlertAndSignedWebhook(t *testing.T) {
	f := setup(t)
	f.snapshotDays(t, contracttest.Variant{EtaEpoch: true, CarrierBadGateway: 0.08}, 900)

	alerts, err := f.mgr.List(f.ctx, drift.ListFilter{Severity: "breaking"})
	if err != nil {
		t.Fatal(err)
	}
	var eta, status *drift.Alert
	for i, a := range alerts {
		if a.Service == "shipping-ext" && a.Op == "GET /v1/shipments" {
			switch a.ChangeKind {
			case "type-changed":
				eta = &alerts[i]
			case "status-added":
				status = &alerts[i]
			}
		}
	}
	if eta == nil {
		t.Fatalf("no breaking type-change alert: %+v", alerts)
	}
	if !strings.Contains(eta.Change, "'eta'") || !strings.Contains(eta.Change, "string(date-time) -> integer") || eta.State != "open" {
		t.Errorf("alert: %+v", eta)
	}
	if eta.Evidence.CallsAfterChange < 100 {
		t.Errorf("evidence: %+v", eta.Evidence)
	}
	if status == nil || !strings.Contains(status.Change, "502") {
		t.Errorf("new frequent error status not reported: %+v", status)
	}

	// Webhook delivered, with a valid signature and no values.
	n, err := f.mgr.DeliverDue(f.ctx)
	if err != nil || n == 0 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	got := f.rcv.all()
	if len(got) < 2 {
		t.Fatalf("deliveries: %d", len(got))
	}
	var sawEta bool
	for _, g := range got {
		if g.event != "contract.drift" {
			t.Errorf("event header %q", g.event)
		}
		if !drift.VerifySignature(f.sec, g.sig, g.body, f.clk.Now(), time.Minute) {
			t.Errorf("invalid signature %q", g.sig)
		}
		if drift.VerifySignature("whsec_other_secret_value", g.sig, g.body, f.clk.Now(), time.Minute) {
			t.Error("signature verifies with another secret")
		}
		if drift.VerifySignature(f.sec, g.sig, append([]byte(nil), append(g.body, ' ')...), f.clk.Now(), time.Minute) {
			t.Error("tampered body verifies")
		}
		if drift.VerifySignature(f.sec, g.sig, g.body, f.clk.Now().Add(time.Hour), time.Minute) {
			t.Error("stale timestamp accepted")
		}
		var p map[string]any
		if err := json.Unmarshal(g.body, &p); err != nil {
			t.Fatal(err)
		}
		if p["type"] != "contract.drift" || p["service"] == nil || p["severity"] == nil || p["drift_id"] == nil {
			t.Errorf("payload: %s", g.body)
		}
		for _, secret := range []string{"CREATED", "DELIVERED", "CARRIER_UNAVAILABLE", "tk1:", "ORD-", "SHP-", "BAD_GATEWAY"} {
			if strings.Contains(string(g.body), secret) {
				t.Errorf("payload contains a value (%s): %s", secret, g.body)
			}
		}
		if strings.Contains(string(g.body), "'eta'") && p["severity"] == "breaking" {
			sawEta = true
		}
	}
	if !sawEta {
		t.Error("eta alert not delivered")
	}

	// Delivery log.
	log, err := f.mgr.Deliveries(f.ctx, f.hid, 50)
	if err != nil || len(log) != len(got) || log[0].State != "delivered" || log[0].Attempts != 1 {
		t.Fatalf("delivery log: %+v %v", log, err)
	}

	// Re-running the same comparison does not duplicate open alerts.
	before, _ := f.mgr.List(f.ctx, drift.ListFilter{Kind: "all"})
	snaps, _ := f.eng.Snapshots().List(f.ctx, "shipping-ext", 2)
	newer, _ := f.eng.Snapshots().Get(f.ctx, "shipping-ext", snaps[0].SnapshotID)
	older, _ := f.eng.Snapshots().Get(f.ctx, "shipping-ext", snaps[1].SnapshotID)
	if err := f.mgr.HandleSnapshot(f.ctx, older, newer); err != nil {
		t.Fatal(err)
	}
	after, _ := f.mgr.List(f.ctx, drift.ListFilter{Kind: "all"})
	if len(after) != len(before) {
		t.Errorf("duplicate alerts: %d -> %d", len(before), len(after))
	}
	if n, _ := f.mgr.DeliverDue(f.ctx); n != 0 {
		t.Errorf("duplicate alert must not be notified again: %d", n)
	}

	// Acknowledge.
	if err := f.mgr.Ack(f.ctx, eta.DriftID, "usr_test"); err != nil {
		t.Fatal(err)
	}
	if err := f.mgr.Ack(f.ctx, eta.DriftID, "usr_test"); err != nil {
		t.Errorf("second ack: %v", err)
	}
	if err := f.mgr.Ack(f.ctx, "dr-99999999", "usr_test"); err == nil {
		t.Error("unknown alert acknowledged")
	}
	acked, _ := f.mgr.List(f.ctx, drift.ListFilter{State: "acknowledged"})
	if len(acked) != 1 || acked[0].DriftID != eta.DriftID {
		t.Errorf("acknowledged: %+v", acked)
	}
}

func TestRetriesWithBackoff(t *testing.T) {
	f := setup(t)
	f.rcv.fail = 2
	if err := f.mgr.Emit(f.ctx, "contract.drift", map[string]any{"service": "shop-api", "severity": "breaking", "change": "x"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.mgr.DeliverDue(f.ctx); n != 1 {
		t.Fatalf("first attempt: %d", n)
	}
	if n, _ := f.mgr.DeliverDue(f.ctx); n != 0 {
		t.Fatal("must wait for the backoff")
	}
	f.clk.Advance(1500 * time.Millisecond) // > 1s +-20%
	if n, _ := f.mgr.DeliverDue(f.ctx); n != 1 {
		t.Fatal("second attempt")
	}
	f.clk.Advance(3 * time.Second)
	if n, _ := f.mgr.DeliverDue(f.ctx); n != 1 {
		t.Fatal("third attempt")
	}
	log, _ := f.mgr.Deliveries(f.ctx, f.hid, 10)
	if log[0].State != "delivered" || log[0].Attempts != 3 {
		t.Fatalf("log: %+v", log[0])
	}
	// Same delivery id on every attempt, so receivers can deduplicate.
	got := f.rcv.all()
	if len(got) != 3 || got[0].delivery != got[2].delivery {
		t.Errorf("delivery ids: %+v", got)
	}

	// Permanent failure after MaxAttempts.
	f.rcv.fail = 100
	_ = f.mgr.Emit(f.ctx, "contract.drift", map[string]any{"service": "s"})
	for i := 0; i < 8; i++ {
		_, _ = f.mgr.DeliverDue(f.ctx)
		f.clk.Advance(time.Minute)
	}
	log, _ = f.mgr.Deliveries(f.ctx, f.hid, 10)
	if log[0].State != "failed" || log[0].Attempts != 4 || log[0].LastStatus != 500 || log[0].LastError != "http_500" {
		t.Fatalf("log: %+v", log[0])
	}
}

func TestWebhookValidationAndAllowList(t *testing.T) {
	f := setup(t)
	bad := []drift.Webhook{
		{Name: "x", URL: "https://evil.example/h", Events: []string{"contract.drift"}},
		{Name: "x", URL: "ftp://127.0.0.1/h", Events: []string{"contract.drift"}},
		{Name: "x", URL: "http://user:pw@127.0.0.1/h", Events: []string{"contract.drift"}},
		{Name: "", URL: "http://127.0.0.1/h", Events: []string{"contract.drift"}},
		{Name: "x", URL: "http://127.0.0.1/h", Events: []string{"nope"}},
		{Name: "x", URL: "http://127.0.0.1/h"},
		{Name: "x", URL: "http://127.0.0.1/h", Events: []string{"contract.drift"}, Secret: "short"},
	}
	for i, w := range bad {
		if _, err := f.mgr.CreateWebhook(f.ctx, w); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// Plain http is refused unless allowed.
	strict, _ := drift.New(drift.Config{Allow: []string{"*.hooks.example", "chat.example:8443"}}, drift.Deps{DB: f.h.DB})
	for url, ok := range map[string]bool{
		"https://a.hooks.example/x": true, "https://hooks.example/x": false, "https://chat.example:8443/x": true,
		"https://chat.example/x": false, "http://a.hooks.example/x": false, "https://evilhooks.example/x": false,
	} {
		if (strict.CheckURL(url) == nil) != ok {
			t.Errorf("CheckURL(%s) = %v, want ok=%v", url, strict.CheckURL(url), ok)
		}
	}
	// Redirects are not followed.
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	}))
	defer redirect.Close()
	w, err := f.mgr.CreateWebhook(f.ctx, drift.Webhook{Name: "r", URL: redirect.URL, Events: []string{"pack.published"}, Secret: strings.Repeat("s", 20)})
	if err != nil {
		t.Fatal(err)
	}
	if w.Secret != "" {
		t.Error("a given secret must not be echoed")
	}
	if err := f.mgr.SendTest(f.ctx, w.ID); err == nil {
		t.Error("a redirect must count as a failure")
	}
}

type fakeRules struct {
	marked []string
}

func (r *fakeRules) RulesTouching(service, op string) []string {
	if service == "shipping-ext" && op == "GET /v1/shipments" {
		return []string{"r-0007"}
	}
	return nil
}
func (r *fakeRules) MarkStale(_ context.Context, id, _ string) error {
	r.marked = append(r.marked, id)
	return nil
}

func TestRuleStalenessHookAndAffectedRules(t *testing.T) {
	f := setupWith(t, false)
	rules := &fakeRules{}
	mgr, _ := drift.New(drift.Config{Allow: []string{"127.0.0.1"}, AllowHTTP: true}, drift.Deps{DB: f.h.DB, Now: f.clk.Now, Rules: rules})
	f.eng.OnSnapshot(mgr.HandleSnapshot)
	var hook drift.RuleStaleness = mgr
	if err := hook.RuleStale(f.ctx, drift.RuleStaleReport{RuleID: "r-0007", Service: "shipping-ext", Op: "POST /v1/shipments", Confidence: 0.4, Previous: 0.9, Reason: "confidence-drop"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := mgr.DeliverDue(f.ctx); n != 1 {
		t.Fatalf("rule.stale delivery: %d", n)
	}
	got := f.rcv.all()
	if len(got) != 1 || got[0].event != "rule.stale" {
		t.Fatalf("got %+v", got)
	}
	stale, _ := mgr.List(f.ctx, drift.ListFilter{Kind: "rule.stale"})
	if len(stale) != 1 || stale[0].AffectedRules[0] != "r-0007" {
		t.Errorf("stale alerts: %+v", stale)
	}
	if def, _ := mgr.List(f.ctx, drift.ListFilter{}); len(def) != 0 {
		t.Error("rule.stale must not show in the default drift list")
	}

	f.snapshotDays(t, contracttest.Variant{EtaEpoch: true}, 600)
	al, _ := mgr.List(f.ctx, drift.ListFilter{Severity: "breaking"})
	var with bool
	for _, a := range al {
		if a.Op == "GET /v1/shipments" && len(a.AffectedRules) == 1 && a.AffectedRules[0] == "r-0007" {
			with = true
		}
	}
	if !with {
		t.Errorf("affected_rules missing: %+v", al)
	}
	if len(rules.marked) == 0 {
		t.Error("breaking drift must mark the affected rules stale")
	}
}

func TestAdminAPI(t *testing.T) {
	f := setup(t)
	f.snapshotDays(t, contracttest.Variant{EtaEpoch: true}, 600)
	h := drift.Handler(f.mgr)
	do := func(roles []auth.Role, method, url, body string) *httptest.ResponseRecorder {
		var rd io.Reader
		if body != "" {
			rd = bytes.NewReader([]byte(body))
		}
		req := httptest.NewRequest(method, url, rd)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{UserID: "usr_test", Roles: roles}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	op, adm, aud := []auth.Role{auth.RoleOperator}, []auth.Role{auth.RoleAdmin}, []auth.Role{auth.RoleAuditor}

	rec := do(aud, "GET", "/api/v1/drift?severity=breaking&state=open", "")
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list) == 0 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	for _, k := range []string{"drift_id", "service", "op", "severity", "change", "first_seen", "state", "evidence"} {
		if list[0][k] == nil {
			t.Errorf("Drift lacks %s", k)
		}
	}
	if rec := do(aud, "GET", "/api/v1/drift?severity=bogus", ""); rec.Code != 400 {
		t.Errorf("bad severity: %d", rec.Code)
	}
	id := list[0]["drift_id"].(string)
	if rec := do(aud, "POST", "/api/v1/drift/"+id+"/ack", ""); rec.Code != 403 {
		t.Errorf("auditor cannot ack: %d", rec.Code)
	}
	if rec := do(op, "POST", "/api/v1/drift/"+id+"/ack", ""); rec.Code != 204 {
		t.Errorf("ack: %d", rec.Code)
	}
	if rec := do(op, "POST", "/api/v1/drift/dr-77777777/ack", ""); rec.Code != 404 {
		t.Errorf("ack unknown: %d", rec.Code)
	}

	// Webhooks: only admin writes.
	create := `{"name":"mail","url":"` + f.rcv.srv.URL + `/m","events":["contract.drift"]}`
	if rec := do(op, "POST", "/api/v1/webhooks", create); rec.Code != 403 {
		t.Errorf("operator creates: %d", rec.Code)
	}
	rec = do(adm, "POST", "/api/v1/webhooks", create)
	var wh drift.Webhook
	_ = json.Unmarshal(rec.Body.Bytes(), &wh)
	if rec.Code != 201 || wh.ID == "" || !wh.SecretSet {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := do(adm, "POST", "/api/v1/webhooks", `{"name":"x","url":"https://evil.example/","events":["contract.drift"]}`); rec.Code != 400 {
		t.Errorf("allow list: %d", rec.Code)
	}
	if rec := do(adm, "POST", "/api/v1/webhooks", `{"name":"x","url":"`+f.rcv.srv.URL+`","events":["contract.drift"],"extra":1}`); rec.Code != 400 {
		t.Errorf("unknown field: %d", rec.Code)
	}
	rec = do(aud, "GET", "/api/v1/webhooks", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "whsec_") || strings.Contains(rec.Body.String(), `"secret":`) {
		t.Fatalf("list must never show secrets: %d %s", rec.Code, rec.Body)
	}
	rec = do(adm, "PUT", "/api/v1/webhooks/"+wh.ID, `{"name":"mail2","url":"`+f.rcv.srv.URL+`/m","events":["contract.drift","rule.stale"]}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "mail2") {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if rec := do(adm, "POST", "/api/v1/webhooks/"+wh.ID+"/test", ""); rec.Code != 204 {
		t.Errorf("test: %d %s", rec.Code, rec.Body)
	}
	got := f.rcv.all()
	last := got[len(got)-1]
	if last.event != "webhook.test" {
		t.Errorf("test event: %q", last.event)
	}
	if rec := do(aud, "GET", "/api/v1/webhooks/"+wh.ID+"/deliveries", ""); rec.Code != 200 {
		t.Errorf("deliveries: %d", rec.Code)
	}
	if rec := do(adm, "DELETE", "/api/v1/webhooks/"+wh.ID, ""); rec.Code != 204 {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec := do(adm, "DELETE", "/api/v1/webhooks/"+wh.ID, ""); rec.Code != 404 {
		t.Errorf("delete twice: %d", rec.Code)
	}

	// The audit log recorded the mutating calls, without payload data.
	var actions []string
	_ = audit.New(f.h.DB).Iterate(f.ctx, 0, 100, func(e audit.Entry) error { actions = append(actions, e.Action); return nil })
	joined := strings.Join(actions, ",")
	for _, a := range []string{"drift.ack", "webhook.create", "webhook.update", "webhook.test", "webhook.delete"} {
		if !strings.Contains(joined, a) {
			t.Errorf("audit lacks %s (%s)", a, joined)
		}
	}
}

// The same behavior on two days must not raise breaking alerts: sampling
// noise (enum values near the k threshold, rare statuses, presence of
// optional fields) is not drift.
func TestNoFalsePositivesOnStableTraffic(t *testing.T) {
	f := setup(t)
	f.snapshotDays(t, contracttest.Variant{}, 1200)
	alerts, err := f.mgr.List(f.ctx, drift.ListFilter{Severity: "breaking"})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("false positives: %+v", alerts)
	}
}
