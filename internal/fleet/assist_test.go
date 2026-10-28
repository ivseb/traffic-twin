package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/policy"
)

type fakeDiscovery struct {
	ops      []DiscoveredOp
	fields   []DiscoveredField
	auth     map[string]AuthStat
	subjects int
}

func (d fakeDiscovery) Discover(_ context.Context, pid string, _ map[string][]string) (*Discovery, error) {
	if pid != "p-shop" {
		return &Discovery{}, nil
	}
	return &Discovery{Ops: d.ops, Fields: d.fields, Auth: d.auth, Subjects: d.subjects}, nil
}

func TestAssistHeuristics(t *testing.T) {
	cases := []struct {
		f    DiscoveredField
		want string
	}{
		{DiscoveredField{Service: "shop-api", Path: "resp.body.id", Distinct: 4120, Observed: 4120, Shape: "drop:str:l32"}, "hmac(shop)"},
		{DiscoveredField{Service: "shop-api", Path: "resp.body.items[*].orderId", Distinct: 900, Observed: 1000, Shape: "drop:str:l32"}, "hmac(order)"},
		{DiscoveredField{Service: "shop-api", Path: "resp.body.shipment_id", Distinct: 30, Observed: 40, Shape: "drop:str:uuid"}, "hmac(shipment)"},
		{DiscoveredField{Path: "resp.body.status", Distinct: 5, Observed: 4120, Shape: "drop:str:l8"}, "keep"},
		{DiscoveredField{Path: "resp.body.total", Distinct: 3870, Observed: 4000, Shape: "drop:dec"}, "bucket(num, [0, 10, 50, 100, 500])"},
		{DiscoveredField{Path: "resp.body.weight", Distinct: 3870, Observed: 4000, Shape: "drop:dec"}, "bucket(num, [0, 10, 100, 1000])"},
		{DiscoveredField{Path: "resp.body.qty", Distinct: 9, Observed: 4000, Shape: "drop:int"}, "bucket(num, [0, 1, 2, 5, 10])"},
		{DiscoveredField{Path: "resp.body.email", Distinct: 1290, Observed: 4000, Shape: "drop:str:email"}, "drop"},
		{DiscoveredField{Path: "req.body.contact", Distinct: 1290, Observed: 4000, Shape: "drop:str:phone"}, "drop"},
		{DiscoveredField{Path: "req.body.customer.firstName", Distinct: 3, Observed: 4000, Shape: "drop:str:l8"}, "drop"},
		{DiscoveredField{Path: "req.body.note", Distinct: 2000, Observed: 4000, Shape: "drop:str:l128"}, "drop"},
		{DiscoveredField{Path: "req.body.comment", Distinct: 4, Observed: 4000, Shape: "drop:str:l8"}, "drop"},
		{DiscoveredField{Path: "resp.body.created", Distinct: 4000, Observed: 4000, Shape: "drop:str:datetime"}, "drop"}, // a timestamp of the call
		{DiscoveredField{Path: "resp.body.dueDate", Distinct: 30, Observed: 4000, Shape: "drop:str:date"}, "bucket(time, day)"},
		{DiscoveredField{Path: "req.headers.host", Distinct: 2, Observed: 4000, Shape: "drop:str:l32"}, "drop"},
		{DiscoveredField{Path: "req.headers.user-agent", Distinct: 3, Observed: 4000, Shape: "drop:str:l32"}, "drop"},
		{DiscoveredField{Path: "resp.body.paid", Distinct: 2, Observed: 4000, Shape: "drop:bool"}, "keep"},
		{DiscoveredField{Path: "req.headers.authorization", Distinct: 3, Observed: 4000, Shape: "drop:str:l32"}, "drop"},
		{DiscoveredField{Path: "req.query.{*}", Distinct: 3, Observed: 4000, Shape: "drop:str:l8"}, "drop"},
		{DiscoveredField{Path: "req.body.*", Distinct: 3, Observed: 4000, Shape: "drop:str:l8"}, "drop"},
		{DiscoveredField{Path: "resp.body.status", Distinct: 3, Observed: 5, Shape: "drop:str:l8"}, "drop"}, // too few
		{DiscoveredField{Path: "resp.body.label", Distinct: 300, Observed: 4000, Shape: "drop:str:l32"}, "drop"},
		{DiscoveredField{Service: "shop-api", Op: "GET /orders/{id}", Path: "req.path.id", Distinct: 4000, Observed: 4000, Shape: "drop:str:l32"}, "hmac(order)"},
		{DiscoveredField{Service: "shop-api", Op: "GET /customers/{customerId}/orders", Path: "req.path.customerId", Distinct: 900, Observed: 1000, Shape: "drop:str:l32"}, "hmac(customer)"},
		{DiscoveredField{Path: "req.path.kind", Distinct: 3, Observed: 4000, Shape: "drop:str:l8"}, "keep"},
		// Found by the onboarding end-to-end run on the demo traffic.
		{DiscoveredField{Service: "shop-api", Op: "POST /orders", Path: "resp.body.id", Distinct: 34, Observed: 34, Shape: "drop:str:l32"}, "hmac(order)"},
		{DiscoveredField{Service: "shop-api", Op: "GET /orders/{id}/shipment", Path: "resp.body.orderId", Distinct: 32, Observed: 122, Shape: "drop:str:l32"}, "hmac(order)"},
		{DiscoveredField{Service: "shop-api", Op: "GET /customers/{id}/orders", Path: "resp.body.items[*].id", Distinct: 9, Observed: 20, Shape: "drop:str:l32"}, "hmac(order)"},
		{DiscoveredField{Path: "req.headers.traceparent", Distinct: 4000, Observed: 4000, Shape: "drop:str:l128"}, "drop"},
		{DiscoveredField{Path: "req.body.shippingAddress.line1", Distinct: 3, Observed: 4000, Shape: "drop:str:l32"}, "drop"},
		{DiscoveredField{Path: "resp.body.total", Distinct: 3800, Observed: 4000, Shape: "drop:int"}, "bucket(num, [0, 1000, 5000, 10000, 50000])"}, // cents
		{DiscoveredField{Path: "resp.body.currency", Distinct: 2, Observed: 25, Shape: "drop:str:l8"}, "keep"},                                      // enum by name, few calls
		{DiscoveredField{Path: "resp.body.items[*].status", Distinct: 30, Observed: 40, Shape: "drop:str:l32"}, "keep"},
		{DiscoveredField{Path: "resp.headers.content-type", Distinct: 1, Observed: 4000, Shape: "drop:str:l32"}, "keep"},
	}
	for _, c := range cases {
		s := suggest(c.f)
		if s.Suggestion != c.want || s.Reason == "" || s.ReasonCode == "" {
			t.Errorf("%s: got %q (%s), want %q", c.f.Path, s.Suggestion, s.Reason, c.want)
		}
	}
	// Every proposed action must be valid policy syntax.
	for _, c := range cases {
		if s := suggest(c.f); s.Suggestion != "" {
			if _, err := policy.ParseAction(s.Suggestion); err != nil {
				t.Errorf("invalid action %q: %v", s.Suggestion, err)
			}
		}
	}
	if p, pa, _ := splitDiscPath("resp.body.items[*].orderId"); p != "response" || pa != "$.items[*].orderId" {
		t.Errorf("split: %s %s", p, pa)
	}
	if _, pa, _ := splitDiscPath("req.body"); pa != "$" {
		t.Errorf("root: %s", pa)
	}
}

func TestAssistEndpoint(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("bob", auth.RolePolicyApprover)
	e.must(e.as("bob", "GET", "/api/v1/fleet/policies/p-shop/assist", nil), 503)
	e.fleet.SetDiscoverySource(fakeDiscovery{
		ops: []DiscoveredOp{
			{Service: "host:api.carrier.example", Op: "GET /v1/shipments", Calls: 5, RawOps: []string{"GET /v1/shipments"}},
			{Service: "shop-api", Op: "POST /orders", Inbound: true, Calls: 400, RawOps: []string{"POST /orders"}},
			{Service: "host:unlisted", Op: "GET /x", Calls: 40},
		},
		fields: []DiscoveredField{
			{Service: "shop-api", Op: "POST /orders", Path: "resp.body.status", Distinct: 5, Observed: 400, Shape: "drop:str:l8"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.body.email", Distinct: 390, Observed: 400, Shape: "drop:str:email"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.headers.authorization", Distinct: 300, Observed: 390, Shape: "drop:str:l128"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.cookies.sid", Distinct: 250, Observed: 400, Shape: "drop:str:l32"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.headers.personid", Distinct: 200, Observed: 399, Shape: "drop:str:l32"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.headers.x-session", Distinct: 200, Observed: 399, Shape: "drop:str:l32"},
			{Service: "shop-api", Op: "POST /orders", Path: "req.headers.traceparent", Distinct: 400, Observed: 400, Shape: "drop:str:l128"},
		},
		auth: map[string]AuthStat{"shop-api": {Calls: 400, WithAuthorization: 390}},
	})
	var out AssistResult
	e.must(e.as("bob", "GET", "/api/v1/fleet/policies/p-shop/assist", nil), 200).json(t, &out)
	if len(out.Services) != 2 || out.Services[0].Service != "shop-api" || out.Services[0].Kind != "inbound" || out.Services[0].Name != "shop-api" {
		t.Fatalf("services: %+v", out.Services)
	}
	ops := out.Services[0].Ops
	if len(ops) != 1 || ops[0].Op != "POST /orders" || ops[0].NeedCalls != 0 || len(ops[0].Fields) != 7 {
		t.Fatalf("ops: %+v", ops)
	}
	f := ops[0].Fields
	if f[0].Part != "request" || f[0].Suggestion != "drop" || f[6].Path != "$.status" || f[6].Suggestion != "keep" ||
		f[6].DistinctEstimate != 5 || f[6].Observed != 400 || f[6].Shape != "drop:str:l8" || f[6].Op != "POST /orders" {
		t.Fatalf("fields: %+v", f)
	}
	ext := out.Services[1]
	if ext.Kind != "external" || ext.Declared || ext.HostPattern != "api.carrier.example" || !ext.Exact || ext.Name != "api.carrier.example" || ext.Base != "" {
		t.Fatalf("external: %+v", ext)
	}
	// Not enough traffic for the carrier operation: the assistant says so.
	if out.Ready || out.NeedCalls != 15 || ext.Ops[0].NeedCalls != 15 || !strings.Contains(out.Message, "15 more calls") {
		t.Fatalf("readiness: %+v", out)
	}
	if out.HasIdentity || out.Identity == nil || out.Identity.Name != "authorization" || out.Identity.JWTClaim != "sub" {
		t.Fatalf("identity: %+v", out.Identity)
	}
	// Who the user is, ranked from the data: the bearer JWT first (and the pick), then
	// the header that repeats per user; a credential-like header and a cookie are
	// listed but never picked; the trace context never shows.
	c := out.IdentityCandidates
	if len(c) != 4 || c[0].Name != "authorization" || !c[0].JWT || c[0].JWTClaim != "sub" || !c[0].Best || !c[0].ObserveSafe ||
		c[1].Name != "personid" || c[1].Excluded != "" || c[1].Best || !c[1].ObserveSafe ||
		c[2].Name != "x-session" || c[2].Excluded != "credential" || c[2].ObserveSafe ||
		c[3].From != "cookie" || c[3].Name != "sid" || c[3].Excluded != "cookie" {
		t.Fatalf("identity candidates: %+v", c)
	}
	if b := out.IdentityBest; b == nil || b.Name != "authorization" || b.JWTClaim != "sub" {
		t.Fatalf("identity best: %+v", b)
	}
	// Proposals are never applied: no draft was created.
	vs, _ := e.fleet.ListPolicies(context.Background())
	if len(vs) != 0 {
		t.Fatal("the assistant must not create policies")
	}
	var empty AssistResult
	e.must(e.as("bob", "GET", "/api/v1/fleet/policies/p-other/assist", nil), 200).json(t, &empty)
	if len(empty.Services) != 0 || empty.Ready || empty.NeedCalls != assistMinObserved {
		t.Fatalf("other policy: %+v", empty)
	}
}

func TestTemplateOps(t *testing.T) {
	var ops [][2]string
	add := func(svc string, op ...string) {
		for _, o := range op {
			ops = append(ops, [2]string{svc, o})
		}
	}
	add("shop-api", "POST /orders", "GET /orders/{drop:str:l32}", "GET /orders/{drop:str:l8}", "GET /orders/{drop:str:l32}/shipment",
		"GET /customers/{drop:str:email}/orders", "GET /", "GET /orders/search")
	for i := 0; i < 12; i++ { // path words that are really values
		add("shop-api", "GET /products/"+string(rune('a'+i))+"word")
	}
	add("shop-api", "GET /orders/{drop:str:l32}/items/{drop:str:l8}")
	add("host:localhost:8080", "POST /v1/shipments", "GET /v1/shipments")
	add("legacy", "GET /orders/{drop:str:l32}")
	got := templateOps(ops, map[string][]string{"legacy": {"GET /orders/{orderId}"}})
	want := map[[2]string]string{
		{"shop-api", "POST /orders"}:                                   "POST /orders",
		{"shop-api", "GET /orders/{drop:str:l32}"}:                     "GET /orders/{id}",
		{"shop-api", "GET /orders/{drop:str:l8}"}:                      "GET /orders/{id}",
		{"shop-api", "GET /orders/search"}:                             "GET /orders/search",
		{"shop-api", "GET /orders/{drop:str:l32}/shipment"}:            "GET /orders/{id}/shipment",
		{"shop-api", "GET /customers/{drop:str:email}/orders"}:         "GET /customers/{id}/orders",
		{"shop-api", "GET /"}:                                          "GET /",
		{"shop-api", "GET /products/aword"}:                            "GET /products/{id}",
		{"shop-api", "GET /orders/{drop:str:l32}/items/{drop:str:l8}"}: "GET /orders/{orderId}/items/{itemId}",
		{"host:localhost:8080", "POST /v1/shipments"}:                  "POST /v1/shipments",
		{"legacy", "GET /orders/{drop:str:l32}"}:                       "GET /orders/{orderId}", // the declared key
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%v: %q, want %q", k, got[k], w)
		}
	}
}

func TestAssistDraft(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.activateV1()
	e.user("ada", auth.RoleAdmin)
	path := "/api/v1/fleet/policies/p-shop/assist/draft"
	req := map[string]any{
		"dry_run":  true,
		"identity": map[string]any{"from": "header", "name": "Authorization", "jwt_claim": "sub"},
		"services": []any{
			map[string]any{"service": "shop-api", "ops": []any{
				map[string]any{"op": "POST /orders", "rules": []any{
					map[string]any{"part": "request", "path": "$.items[*].sku", "action": "keep"},
					map[string]any{"part": "response", "path": "$.status", "action": "drop"}, // removes the existing keep
				}},
				map[string]any{"op": "GET /orders/{id}", "rules": []any{
					map[string]any{"part": "request", "path": "path.id", "action": "hmac(order)"},
					map[string]any{"part": "response", "path": "$.total", "action": "bucket(num, [0, 50, 100])"},
				}},
			}},
			map[string]any{"service": "host:localhost:8080", "name": "carrier", "base": "http://localhost:8080", "ops": []any{
				map[string]any{"op": "GET /v1/shipments", "rules": []any{map[string]any{"part": "request", "path": "query.orderId", "action": "hmac(order)"}}},
				map[string]any{"op": "POST /v1/shipments", "rules": []any{}},
			}},
		},
	}
	var dry AssistDraftResult
	e.must(e.as("olivia", "POST", path, req), 200).json(t, &dry)
	a, err := ParseAuthor([]byte(dry.After))
	if err != nil {
		t.Fatalf("%v\n%s", err, dry.After)
	}
	shop, carrier := a.Services["shop-api"], a.Services["carrier"]
	if shop.Ops["POST /orders"].Request.Body["$.items[*].sku"] != "keep" || shop.Ops["POST /orders"].Response.Body["$.status"] != "" ||
		shop.Ops["POST /orders"].Response.Body["$.id"] != "hmac(order)" || shop.Ops["GET /orders/{id}"].Request.Path["id"] != "hmac(order)" ||
		shop.Ops["GET /orders/{id}"].Response.Body["$.total"] != "bucket(num, [0, 50, 100])" {
		t.Fatalf("shop-api: %+v\n%s", shop, dry.After)
	}
	if carrier.Base != "http://localhost:8080" || carrier.Ops["GET /v1/shipments"].Request.Query["orderId"] != "hmac(order)" {
		t.Fatalf("carrier: %+v\n%s", carrier, dry.After)
	}
	if _, ok := carrier.Ops["POST /v1/shipments"]; !ok {
		t.Fatalf("an operation without rules is declared too:\n%s", dry.After)
	}
	if a.Subject == nil || a.Subject.Name != "authorization" || a.Subject.JWTClaim != "sub" {
		t.Fatalf("identity: %+v", a.Subject)
	}
	if dry.Before != policyV1 {
		t.Fatalf("before: %s", dry.Before)
	}
	vs, _ := e.fleet.ListPolicies(context.Background())
	n := len(vs)
	// Errors: no scheme guessed, unknown parameter, invalid action, value-like names.
	bad := func(code string, svc map[string]any) {
		t.Helper()
		r := e.as("olivia", "POST", path, map[string]any{"services": []any{svc}})
		if r.code != 422 && r.code != 409 || r.errCode() != code {
			t.Errorf("%s: %d %s", code, r.code, r.body)
		}
	}
	bad("base_required", map[string]any{"service": "host:localhost:8080", "name": "carrier", "ops": []any{}})
	bad("base_mismatch", map[string]any{"service": "host:localhost:8080", "name": "carrier", "base": "http://localhost:9090"})
	bad("invalid_rule", map[string]any{"service": "shop-api", "ops": []any{map[string]any{"op": "GET /orders/{id}", "rules": []any{map[string]any{"part": "request", "path": "path.nope", "action": "keep"}}}}})
	bad("invalid_action", map[string]any{"service": "shop-api", "ops": []any{map[string]any{"op": "POST /orders", "rules": []any{map[string]any{"part": "request", "path": "$.x", "action": "keep:CREATED"}}}}})
	bad("invalid_op", map[string]any{"service": "shop-api", "ops": []any{map[string]any{"op": "(raw)", "rules": []any{}}}})
	bad("invalid_service", map[string]any{"service": "host:{*}.tenant.example", "base": "https://eu1.tenant.example"})
	vs, _ = e.fleet.ListPolicies(context.Background())
	if len(vs) != n {
		t.Fatal("dry runs and errors must not create drafts")
	}
	// The real proposal: a draft that needs approvals, like any other.
	delete(req, "dry_run")
	var v PolicyVersion
	e.must(e.as("olivia", "POST", path, req), 201).json(t, &v)
	if v.Status != StatusDraft || v.Version != 2 || v.Classification != Opening || v.AuthorYAML != dry.After {
		t.Fatalf("draft: %+v", v)
	}
	var act PolicyVersion
	e.must(e.approve("ada", v, map[string]any{"reason": "single-maintainer trial"}), 200).json(t, &act)
	if act.Status != StatusActive {
		t.Fatalf("admin approval: %+v", act)
	}
	// The same decisions again change nothing.
	if r := e.as("olivia", "POST", path, req); r.code != 422 || r.errCode() != "no_change" {
		t.Fatalf("no change: %d %s", r.code, r.body)
	}
}

func TestShapeAt(t *testing.T) {
	body := event.Obj(
		event.Member{K: "items", V: event.Arr(event.Obj(event.Member{K: "sku", V: event.Str("drop:str:l32")}))},
		event.Member{K: "status", V: event.Str("keep:CREATED")},
		event.Member{K: "{*}", V: event.Arr(event.Str("drop:str:l8"))},
	)
	ev := &event.Event{Req: event.Request{Path: "/orders/{drop:str:uuid}", Body: &body,
		Query: event.Multi{{Name: "promo", Values: []string{"drop:str:l8"}}}}}
	for path, want := range map[string]string{
		"req.body.items[*].sku": "drop:str:l32", "req.body.status": "", "req.body.*": "drop:str:l8",
		"req.query.promo": "drop:str:l8", "req.path.1": "drop:str:uuid", "req.path.0": "", "resp.body.x": "", "req.body.nope": "",
	} {
		if got := ShapeAt(ev, path); got != want {
			t.Errorf("%s: %q want %q", path, got, want)
		}
	}
}

func TestStarterPolicyEndpoint(t *testing.T) {
	e := newEnv(t, nil)
	e.user("olivia", "operator")
	e.user("bob", auth.RolePolicyApprover)
	e.user("carol", auth.RolePolicyApprover)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{"name": "shop", "allowed_service_names": []string{"shop-api"}}), 201)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"hmac_kid": "k1", "epoch": "2026-10", "window_hours": 200}), 422)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"epoch": "2026-10"}), 422)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/nope/starter-policy", map[string]any{"hmac_kid": "k1", "epoch": "2026-10"}), 404)
	var v PolicyVersion
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"hmac_kid": "k1", "epoch": "2026-10"}), 201).json(t, &v)
	if v.PolicyID != "p-shop" || v.Status != StatusDraft || v.Origin != OriginStarter || v.Classification != Opening || v.ApprovalsRequired != 2 {
		t.Fatalf("starter draft: %+v", v)
	}
	var g Group
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop", nil), 200).json(t, &g)
	if g.PolicyID == nil || *g.PolicyID != "p-shop" {
		t.Fatal("group not bound to the starter policy")
	}
	full, _ := e.fleet.GetPolicyVersion(context.Background(), "p-shop", v.Version)
	if !strings.Contains(full.AuthorYAML, "discovery:") || !strings.Contains(full.AuthorYAML, e.clk.Now().Add(72*time.Hour).Format(time.RFC3339)) {
		t.Fatalf("starter yaml: %s", full.AuthorYAML)
	}
	e.must(e.approve("bob", v, nil), 200)
	var act PolicyVersion
	e.must(e.approve("carol", v, nil), 200).json(t, &act)
	if act.Status != StatusActive {
		t.Fatalf("starter activation: %+v", act)
	}
	// Another policy id for a bound group is refused.
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{"policy_id": "p-x", "hmac_kid": "k1", "epoch": "2026-10"}), 409)
}

func TestSigningKeyRevocationEndpoint(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("ada", auth.RoleAdmin)
	s := e.enrollSource(e.newToken(TokenOneTime, "sdk-node").Token, "sdk-node", "shop-api")
	// The only key cannot be revoked.
	if r := e.as("ada", "POST", "/api/v1/fleet/signing-keys/policy-2026-1/revoke", nil); r.code != 409 || r.errCode() != "last_signing_key" {
		t.Fatalf("last key: %d %s", r.code, r.body)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	e.signer.extra = []SigningKey{{Kid: "policy-2026-2", PublicKey: pub}}
	e.fleet.Maintain(context.Background())
	var ks []SigningKeyInfo
	e.must(e.as("olivia", "GET", "/api/v1/fleet/signing-keys", nil), 200).json(t, &ks)
	if len(ks) != 2 {
		t.Fatalf("keys: %+v", ks)
	}
	e.must(e.as("olivia", "POST", "/api/v1/fleet/signing-keys/policy-2026-1/revoke", nil), 403)
	// The source has not confirmed the new key yet (RT3-KEY-1).
	if r := e.as("ada", "POST", "/api/v1/fleet/signing-keys/policy-2026-1/revoke", nil); r.code != 409 || r.errCode() != "rotation_unconfirmed" {
		t.Fatalf("unconfirmed rotation: %d %s", r.code, r.body)
	}
	s.kids = []string{"policy-2026-1", "policy-2026-2"}
	s.heartbeat("capturing", 0)
	// keyguard's active kid is never revocable (RT3-KEY-2).
	e.signer.mu.Lock()
	e.signer.status.PolicyKid = "policy-2026-1"
	e.signer.mu.Unlock()
	if r := e.as("ada", "POST", "/api/v1/fleet/signing-keys/policy-2026-1/revoke", nil); r.code != 409 || r.errCode() != "active_signing_key" {
		t.Fatalf("active kid: %d %s", r.code, r.body)
	}
	e.signer.mu.Lock()
	e.signer.status.PolicyKid = "policy-2026-2"
	e.signer.mu.Unlock()
	e.must(e.as("ada", "POST", "/api/v1/fleet/signing-keys/policy-2026-1/revoke", nil), 204)
	e.must(e.as("ada", "POST", "/api/v1/fleet/signing-keys/policy-2026-1/revoke", nil), 409)
	e.must(e.as("ada", "POST", "/api/v1/fleet/signing-keys/nope/revoke", nil), 404)
	hb, _ := s.heartbeat("capturing", 0)
	if len(hb.RevokeSigningKeys) != 1 || hb.RevokeSigningKeys[0] != "policy-2026-1" {
		t.Fatalf("heartbeat revoke: %+v", hb.RevokeSigningKeys)
	}
	// A refresh from keyguard never re-enables a revoked kid, and new
	// enrollments no longer receive it.
	e.fleet.Maintain(context.Background())
	s2 := e.enrollSource(e.newToken(TokenOneTime, "sdk-node").Token, "sdk-node", "shop-api")
	if len(s2.enr.PolicySigningKeys) != 1 || s2.enr.PolicySigningKeys[0].Kid != "policy-2026-2" {
		t.Fatalf("enrollment keys: %+v", s2.enr.PolicySigningKeys)
	}
	if !strings.Contains(e.auditDump(), `"action":"fleet.signing_key_revoke"`) {
		t.Fatal("revocation not audited")
	}
}

func TestEnrollRateLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) {
		o.EnrollIPLimit = RateLimit{PerMinute: 1, Burst: 2}
		o.EnrollTokenLimit = RateLimit{PerMinute: -1}
	})
	e.setup()
	bad := "tte_" + strings.Repeat("A", 43) + "." + e.fleet.CAPin()
	for i := 0; i < 2; i++ {
		if r, _ := e.enroll(bad, map[string]any{"source": srcInfo("sdk-node", "shop-api")}); r.code != 401 {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	r, err := e.enroll(bad, map[string]any{"source": srcInfo("sdk-node", "shop-api")})
	if err != nil || r.code != 429 || r.hdr.Get("Retry-After") == "" || r.errCode() != "rate_limited" {
		t.Fatalf("ip limit: %v %d %v", err, r.code, r.hdr)
	}
	e.clk.Add(time.Minute)
	if r, _ := e.enroll(bad, map[string]any{"source": srcInfo("sdk-node", "shop-api")}); r.code != 401 {
		t.Fatalf("after refill: %d", r.code)
	}

	// Per token: IP limit off, one attempt per token per minute.
	e2 := newEnv(t, func(o *Options) {
		o.EnrollIPLimit = RateLimit{PerMinute: -1}
		o.EnrollTokenLimit = RateLimit{PerMinute: 1, Burst: 1}
	})
	e2.setup()
	gt := e2.newToken(TokenGroup, "sdk-node")
	e2.enrollSource(gt.Token, "sdk-node", "shop-api")
	if r, _ := e2.enroll(gt.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api")}); r.code != 429 {
		t.Fatalf("token limit: %d", r.code)
	}
	other := e2.newToken(TokenOneTime, "sdk-node")
	e2.enrollSource(other.Token, "sdk-node", "shop-api") // another token is not affected
}

func TestLimiter(t *testing.T) {
	l := newLimiter(RateLimit{PerMinute: 60, Burst: 2}, DefaultEnrollIPLimit)
	now := time.Unix(1000, 0)
	if ok, _ := l.allow("a", now); !ok {
		t.Fatal()
	}
	if ok, _ := l.allow("a", now); !ok {
		t.Fatal()
	}
	ok, wait := l.allow("a", now)
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("third: %v %v", ok, wait)
	}
	if ok, _ := l.allow("b", now); !ok {
		t.Fatal("keys must be independent")
	}
	if ok, _ := l.allow("a", now.Add(time.Second)); !ok {
		t.Fatal("refill")
	}
	if ipKey("2001:db8::1") != ipKey("2001:db8::2") || ipKey("192.0.2.1") == ipKey("192.0.2.2") {
		t.Fatal("ip grouping")
	}
}
