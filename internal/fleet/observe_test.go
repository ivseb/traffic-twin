package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// newObserveEnv is a fleet whose keyguard signs observe-safe changes without
// approvals, with the observe phase on, and a group "shop" without policy.
func newObserveEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, func(o *Options) {
		o.Observe = ObserveOptions{Enabled: true, After: 10 * time.Minute, MinEvents: 300}
	})
	e.signer.status.ObserveAuto = true
	e.signer.status.HMACKids = []string{"k1"}
	e.fleet.refreshSignerStatus(context.Background())
	e.user("olivia", auth.RoleOperator)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{"name": "shop", "allowed_service_names": []string{"shop-api"}}), 201)
	return e
}

// observedTraffic is what the intake would report after a few hundred calls
// under the starter policy (shapes and distinct counts, never values).
func observedTraffic(calls int64) fakeDiscovery {
	return fakeDiscovery{
		ops: []DiscoveredOp{
			{Service: "shop-api", Op: "POST /orders", Inbound: true, Calls: calls, RawOps: []string{"POST /orders"}},
			{Service: "shop-api", Op: "GET /orders/{id}", Inbound: true, Calls: calls, RawOps: []string{"GET /orders/{drop:str:l32}"}},
			{Service: "host:api.carrier.example", Op: "POST /v1/shipments", Calls: calls / 2},
		},
		fields: []DiscoveredField{
			{Service: "shop-api", Op: "POST /orders", Path: "resp.body.id", Distinct: int(calls), Observed: calls, Shape: "drop:str:l32"},
			{Service: "shop-api", Op: "POST /orders", Path: "resp.body.status", Distinct: 4, Observed: calls, Shape: "drop:str:l8"},
			{Service: "shop-api", Op: "POST /orders", Path: "resp.body.total", Distinct: int(calls) - 10, Observed: calls, Shape: "drop:dec"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.body.email", Distinct: int(calls) / 2, Observed: calls, Shape: "drop:str:email"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.body.items[*].sku", Distinct: 12, Observed: calls, Shape: "drop:str:l32"},
			{Service: "shop-api", Op: "GET /orders/{id}", Path: "req.path.id", Distinct: int(calls), Observed: calls, Shape: "drop:str:l32"},
			{Service: "shop-api", Op: "GET /orders/{id}", Path: "resp.body.customerId", Distinct: int(calls) / 3, Observed: calls, Shape: "drop:str:uuid"},
			{Service: "shop-api", Op: "GET /orders/{id}", Path: "req.headers.authorization", Distinct: int(calls) / 3, Observed: calls, Shape: "drop:str:jwt"},
			{Service: "host:api.carrier.example", Op: "POST /v1/shipments", Path: "req.body.orderId", Distinct: int(calls / 2), Observed: calls / 2, Shape: "drop:str:l32"},
		},
		auth: map[string]AuthStat{"shop-api": {Calls: 2 * calls, WithAuthorization: 2*calls - 3}},
	}
}

func activeOf(t *testing.T, e *env, pid string) *PolicyVersion {
	t.Helper()
	vs, err := e.fleet.ListPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.PolicyID == pid && v.Status == StatusActive {
			return v
		}
	}
	return nil
}

func TestObserveStarterActiveWithoutApproval(t *testing.T) {
	e := newObserveEnv(t)
	var v PolicyVersion
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201).json(t, &v)
	if v.Status != StatusActive || v.ApprovalsRequired != 0 || v.OpensValues || v.ApprovalMode != ApprovalObserve || v.Origin != OriginStarter {
		t.Fatalf("starter: %+v", v)
	}
	if !strings.Contains(v.AuthorYAML, "kid: k1") || !strings.Contains(v.AuthorYAML, "rate: 0.1") {
		t.Fatalf("starter defaults (keyguard kid, observe sampling): %s", v.AuthorYAML)
	}
	if len(e.signer.signs) != 1 || len(e.signer.signs[0].Approvals) != 0 {
		t.Fatalf("signed without approvals: %+v", e.signer.signs)
	}
	dump := e.auditDump()
	if !strings.Contains(dump, `"action":"policy.activate"`) || !strings.Contains(dump, `"approval_mode":"observe"`) {
		t.Fatalf("audit: %s", dump)
	}
	// The group's sources receive it.
	if env, _ := e.fleet.CurrentEnvelope("shop"); env == nil {
		t.Fatal("no envelope for the group")
	}
}

func TestObserveAutoMasksIdentifiers(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)
	// Few calls and little time: nothing happens yet.
	e.fleet.SetDiscoverySource(observedTraffic(40))
	e.fleet.ObserveTick(ctx)
	if a := activeOf(t, e, "p-shop"); a.Origin != OriginStarter {
		t.Fatalf("too early: %+v", a)
	}
	var st ObserveStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if st.Phase != "listening" || st.StartedAt == nil || st.DueAt == nil || st.Events == 0 || st.MinEvents != 300 || len(st.Masked) != 0 {
		t.Fatalf("listening: %+v", st)
	}
	// Enough calls: the observe version is derived and applied by itself.
	e.fleet.SetDiscoverySource(observedTraffic(400))
	e.fleet.ObserveTick(ctx)
	a := activeOf(t, e, "p-shop")
	if a.Origin != OriginObserveAuto || a.ApprovalMode != ApprovalObserve || a.ApprovalsRequired != 0 || a.ProposedBy != systemUser {
		t.Fatalf("observe version: %+v", a)
	}
	y := a.AuthorYAML
	// Statuses come out as codes without a person (policy.md 1.5); a
	// low-cardinality field without a status-like name does not.
	if !strings.Contains(y, "$.status: code") || strings.Contains(y, "sku: code") {
		t.Errorf("observe version and code values:\n%s", y)
	}
	for _, want := range []string{"$.id: hmac(order)", "id: hmac(order)", "$.customerId: hmac(customer)", "jwt_claim: sub", "name: authorization"} {
		if !strings.Contains(y, want) {
			t.Errorf("observe version lacks %q:\n%s", want, y)
		}
	}
	for _, never := range []string{"keep", "bucket", "email", "carrier"} {
		if strings.Contains(y, never) {
			t.Errorf("observe version must not contain %q:\n%s", never, y)
		}
	}
	if len(e.signer.signs) != 2 || len(e.signer.signs[1].Approvals) != 0 {
		t.Fatalf("signs: %d", len(e.signer.signs))
	}
	dump := e.auditDump()
	if !strings.Contains(dump, `"action":"policy.observe-auto"`) || !strings.Contains(dump, `"kind":"system"`) {
		t.Fatalf("audit of the system actor: %s", dump)
	}
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if st.Phase != "masked" || st.ObserveVersion != a.Version || st.ObserveActivatedAt == nil || st.Identity == nil || st.Identity.JWTClaim != "sub" {
		t.Fatalf("masked: %+v", st)
	}
	fields := map[string]string{}
	for _, m := range st.Masked {
		fields[m.Op+" "+m.Part+" "+m.Kind+" "+m.Field] = m.Domain
	}
	if fields["POST /orders response body $.id"] != "order" || fields["GET /orders/{id} request path id"] != "order" {
		t.Fatalf("masked fields: %+v", st.Masked)
	}
	// A second pass with nothing new does nothing.
	e.fleet.ObserveTick(ctx)
	if b := activeOf(t, e, "p-shop"); b.Version != a.Version {
		t.Fatalf("a pass without new identifiers made v%d", b.Version)
	}

	// A person: masking one more field applies at once; keeping a value waits.
	e.user("paula", auth.RolePolicyApprover)
	doc := strings.Replace(y, "$.id: hmac(order)", "$.id: hmac(order)\n          $.items[*].sku: hmac(sku)", 1)
	var c Classification
	e.must(e.as("paula", "POST", "/api/v1/fleet/policies/classify", doc, "application/yaml"), 200).json(t, &c)
	if c.OpensValues || c.ApprovalsRequired != 0 {
		t.Fatalf("classify hmac: %+v", c)
	}
	v := e.propose("paula", doc)
	if v.Status != StatusActive || v.ApprovalMode != ApprovalObserve {
		t.Fatalf("observe-safe change applies at once: %+v", v)
	}
	// From code (codes only) to keep (any value): it opens values.
	keep := strings.Replace(doc, "$.status: code", "$.status: keep", 1)
	e.must(e.as("paula", "POST", "/api/v1/fleet/policies/classify", keep, "application/yaml"), 200).json(t, &c)
	if !c.OpensValues || c.ApprovalsRequired != 2 || len(c.ValueReasons) != 1 || c.ValueReasons[0].Code != policy.ReasonKeep {
		t.Fatalf("classify keep: %+v", c)
	}
	d := e.propose("paula", keep)
	if d.Status != StatusDraft || !d.OpensValues || d.ApprovalsRequired != 2 || d.ValueReasons[0].Where != "services.shop-api.ops.POST /orders.response.body.$.status" {
		t.Fatalf("opening draft: %+v", d)
	}
	// A person changed the policy: tt-core stops deriving by itself.
	e.must(e.as("paula", "POST", "/api/v1/fleet/policies/p-shop/versions/"+itoa(d.Version)+"/reject", map[string]any{}), 200)
	e.fleet.SetDiscoverySource(observedTraffic(800))
	e.fleet.ObserveTick(ctx)
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if st.Phase != "managed" {
		t.Fatalf("managed: %+v", st.Phase)
	}
	if b := activeOf(t, e, "p-shop"); b.Version != v.Version {
		t.Fatalf("tt-core derived after a person's change: v%d", b.Version)
	}
}

func TestObserveAfterDelay(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)
	e.fleet.SetDiscoverySource(observedTraffic(60))
	e.fleet.ObserveTick(ctx)
	if a := activeOf(t, e, "p-shop"); a.Origin != OriginStarter {
		t.Fatal("derived before the delay")
	}
	e.clk.Add(11 * time.Minute)
	e.fleet.ObserveTick(ctx)
	if a := activeOf(t, e, "p-shop"); a.Origin != OriginObserveAuto {
		t.Fatalf("not derived after the delay: %+v", a)
	}
}

func TestObserveRefusedByKeyguardStaysDraft(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)
	e.fleet.SetDiscoverySource(observedTraffic(400))
	// keyguard's own verdict differs (for instance another core changed the
	// group): the automatic version is not signed and waits for people.
	e.signer.refuse = "insufficient_approvals"
	e.fleet.ObserveTick(ctx)
	if a := activeOf(t, e, "p-shop"); a.Origin != OriginStarter {
		t.Fatalf("refused version activated: %+v", a)
	}
	vs, _ := e.fleet.ListPolicies(ctx)
	var draft *PolicyVersion
	for _, v := range vs {
		if v.Status == StatusDraft {
			draft = v
		}
	}
	if draft == nil || draft.Origin != OriginObserveAuto || draft.ApprovalsRequired != 2 {
		t.Fatalf("draft: %+v", draft)
	}
	if !strings.Contains(e.auditDump(), `"keyguard_code":"insufficient_approvals"`) {
		t.Fatal("refusal not audited")
	}
}

func TestObserveDisabledByKeyguard(t *testing.T) {
	e := newObserveEnv(t)
	e.signer.status.ObserveAuto = false
	e.fleet.refreshSignerStatus(context.Background())
	var v PolicyVersion
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"hmac_kid": "k1", "epoch": "2026-10"}), 201).json(t, &v)
	if v.Status != StatusDraft || v.ApprovalsRequired != 2 {
		t.Fatalf("without observe_auto the starter waits for approvals: %+v", v)
	}
}

func TestObserveDecisionsOnlyHMAC(t *testing.T) {
	res := &AssistResult{
		Services: []AssistService{{Service: "shop-api", Name: "shop-api", Kind: "inbound", Ops: []AssistOp{{Op: "POST /orders", Fields: []Suggestion{
			{Part: "response", Path: "$.id", Suggestion: "hmac(order)", ReasonCode: "id"},
			{Part: "response", Path: "$.status", Suggestion: "keep", ReasonCode: "enum_name"},
			{Part: "response", Path: "$.total", Suggestion: "bucket(num, [0, 10])", ReasonCode: "amount"},
			{Part: "request", Path: "headers.authorization", Suggestion: "hmac(x)", ReasonCode: "id"},
			{Part: "response", Path: "$.ref", Suggestion: "hmac(ref)", ReasonCode: "id"},
		}}}}},
		IdentityBest: &AssistIdentity{From: "header", Name: "x-user-id"},
	}
	a := &policy.Author{Services: map[string]policy.AuthorService{"shop-api": {Ops: map[string]policy.AuthorOp{
		"POST /orders": {Response: &policy.AuthorPart{Body: map[string]string{"$.ref": "drop"}}}}}}}
	req := observeDecisions(res, a, nil, codeOptions{on: true, alnum: true})
	if len(req.Services) != 1 || len(req.Services[0].Ops[0].Rules) != 1 || req.Services[0].Ops[0].Rules[0].Path != "$.id" {
		t.Fatalf("rules: %+v", req.Services)
	}
	// A short low-cardinality status-like field becomes code, unless the codes
	// are off (fleet.observe.codes false: sources older than v1.11).
	res.Services[0].Ops[0].Fields = append(res.Services[0].Ops[0].Fields,
		Suggestion{Part: "response", Path: "$.state", Shape: "drop:str:l8", Observed: 100, DistinctEstimate: 4, Suggestion: "keep", ReasonCode: "enum_name"})
	on := observeDecisions(res, a, nil, codeOptions{on: true, alnum: true}).Services[0].Ops[0].Rules
	if len(on) != 2 || on[1].Path != "$.state" || on[1].Action != "code" {
		t.Fatalf("codes on: %+v", on)
	}
	if off := observeDecisions(res, a, nil, codeOptions{}).Services[0].Ops[0].Rules; len(off) != 1 {
		t.Fatalf("codes off: %+v", off)
	}
	// Spec v1.19: digits on a code-like name and short strings on a code or
	// type name become code(alnum); without code_digits the digits field gets
	// nothing and the type field gets the v1.11 code; a field the intake
	// quarantined (too many distinct values) never gets code again.
	res.Services[0].Ops[0].Fields = append(res.Services[0].Ops[0].Fields,
		Suggestion{Part: "response", Path: "$.storeCode", Shape: "drop:str:digits", Observed: 100, DistinctEstimate: 9, Suggestion: "drop", ReasonCode: "enum"},
		Suggestion{Part: "response", Path: "$.channelType", Shape: "drop:str:l8", Observed: 100, DistinctEstimate: 3, Suggestion: "keep", ReasonCode: "enum_name"},
		Suggestion{Part: "response", Path: "$.itemCode", Shape: "drop:str:digits", Observed: 100, DistinctEstimate: 15, Suggestion: "drop", ReasonCode: "enum"})
	got := map[string]string{}
	quarantined := func(_, _, _, path string) bool { return path == "$.itemCode" }
	for _, r := range observeDecisions(res, a, nil, codeOptions{on: true, alnum: true, quarantined: quarantined}).Services[0].Ops[0].Rules {
		got[r.Path] = r.Action
	}
	if got["$.storeCode"] != "code(alnum)" || got["$.channelType"] != "code(alnum)" || got["$.state"] != "code" || got["$.itemCode"] != "" {
		t.Fatalf("alnum proposals: %v", got)
	}
	got = map[string]string{}
	for _, r := range observeDecisions(res, a, nil, codeOptions{on: true}).Services[0].Ops[0].Rules {
		got[r.Path] = r.Action
	}
	if got["$.storeCode"] != "" || got["$.channelType"] != "code" {
		t.Fatalf("without code_digits: %v", got)
	}
	if req.Identity == nil || req.Identity.Name != "x-user-id" || req.Identity.JWTClaim != "" {
		t.Fatalf("identity: %+v", req.Identity)
	}
}

func TestObserveExpiredWindowsClosedAtRenewal(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)
	// Past the 72 h windows and close to not_after: the starter body cannot
	// be renewed as is; a version without the windows replaces it.
	e.clk.Add(25 * 24 * time.Hour)
	e.fleet.RenewExpiringPolicies(ctx)
	a := activeOf(t, e, "p-shop")
	if a.Origin != OriginObserveAuto || a.Note != noteWindowsClosed || strings.Contains(a.AuthorYAML, "discovery:") || strings.Contains(a.AuthorYAML, "auto_words") {
		t.Fatalf("windows not closed: %+v", a)
	}
	if a.NotAfter == nil || !a.NotAfter.After(e.clk.Now().Add(20*24*time.Hour)) {
		t.Fatalf("not_after: %v", a.NotAfter)
	}
}

func TestObserveDecisionsIdentityFromDetection(t *testing.T) {
	pick := func(best *AssistIdentity, a *policy.Author, hc *humanChoice) *AssistIdentity {
		return observeDecisions(&AssistResult{IdentityBest: best}, a, hc, codeOptions{on: true, alnum: true}).Identity
	}
	best := &AssistIdentity{From: "header", Name: "x-kunden-nr"}
	if id := pick(best, &policy.Author{}, nil); id == nil || id.Name != "x-kunden-nr" || id.JWTClaim != "" {
		t.Fatalf("detected header: %+v", id)
	}
	if id := pick(nil, &policy.Author{}, nil); id != nil {
		t.Fatalf("nothing convincing: %+v", id)
	}
	// A person's choice is never replaced: an identity set, or removed by a person.
	if id := pick(best, &policy.Author{Subject: &policy.Subject{From: "header", Name: "x-member"}}, nil); id != nil {
		t.Fatalf("identity already set: %+v", id)
	}
	if id := pick(best, &policy.Author{}, &humanChoice{identityRemoved: true}); id != nil {
		t.Fatalf("removed by a person: %+v", id)
	}
}
