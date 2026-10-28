package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

func withCarrierService(t *testing.T, doc string) string {
	t.Helper()
	out, err := addServiceYAML([]byte(doc), "carrier-api", "https://api.carrier.example")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func mustBase(t *testing.T, s string) policy.BaseURL {
	t.Helper()
	b, ok := policy.ParseBase(s)
	if !ok {
		t.Fatalf("base %s", s)
	}
	return b
}

// Usability test 4 (Node orders-api): after a person's change (a "Simula
// nel mock" twin of an external host), the ids of the new services stayed
// drop because the automatic observe versions had stopped for good.

// withCarrier is observedTraffic plus the calls to the carrier, now declared
// as carrier-api (the old host:api.carrier.example calls stay as they were).
func withCarrier(calls int64) fakeDiscovery {
	d := observedTraffic(calls)
	d.ops = append(d.ops,
		DiscoveredOp{Service: "carrier-api", Op: "POST /v1/shipments", Calls: calls, RawOps: []string{"POST /v1/shipments"}},
		DiscoveredOp{Service: "carrier-api", Op: "GET /v1/shipments/{id}", Calls: calls, RawOps: []string{"GET /v1/shipments/{drop:str:l32}"}},
	)
	d.fields = append(d.fields,
		DiscoveredField{Service: "carrier-api", Op: "POST /v1/shipments", Path: "resp.body.id", Distinct: int(calls), Observed: calls, Shape: "drop:str:l32"},
		DiscoveredField{Service: "carrier-api", Op: "POST /v1/shipments", Path: "req.body.orderRef", Distinct: int(calls), Observed: calls, Shape: "drop:str:l32"},
		DiscoveredField{Service: "carrier-api", Op: "POST /v1/shipments", Path: "resp.body.status", Distinct: 3, Observed: calls, Shape: "drop:str:l8"},
		DiscoveredField{Service: "carrier-api", Op: "GET /v1/shipments/{id}", Path: "req.path.id", Distinct: int(calls), Observed: calls, Shape: "drop:str:l32"},
	)
	return d
}

func observeTo(t *testing.T, e *env) PolicyVersion {
	t.Helper()
	ctx := context.Background()
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)
	e.fleet.SetDiscoverySource(observedTraffic(400))
	e.fleet.ObserveTick(ctx)
	a := activeOf(t, e, "p-shop")
	if a.Origin != OriginObserveAuto {
		t.Fatalf("observe version: %+v", a)
	}
	return *a
}

func TestObserveAutoGoesOnAfterPersonChange(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	obs := observeTo(t, e)

	// A person declares the carrier and keeps the shop's order id as drop
	// (removes the hmac tt-core had put there).
	e.user("paula", auth.RolePolicyApprover)
	doc := strings.Replace(obs.AuthorYAML, "          $.id: hmac(order)\n", "", 1)
	if doc == obs.AuthorYAML {
		t.Fatalf("fixture: no $.id rule in\n%s", obs.AuthorYAML)
	}
	doc = withCarrierService(t, doc)
	v := e.propose("paula", doc)
	if v.Status != StatusActive {
		t.Fatalf("person's observe-safe change: %+v", v)
	}

	// The carrier's identifiers are seen: tt-core masks them by itself,
	// on top of the person's version, as observe-auto.
	e.fleet.SetDiscoverySource(withCarrier(400))
	e.fleet.ObserveTick(ctx)
	a := activeOf(t, e, "p-shop")
	if a.Version == v.Version || a.Origin != OriginObserveAuto || a.ProposedBy != systemUser || a.ApprovalsRequired != 0 {
		t.Fatalf("no observe version after the person's change: %+v", a)
	}
	y := a.AuthorYAML
	for _, want := range []string{"carrier-api:", "$.id: hmac(shipment)", "$.orderRef: hmac(order)", "id: hmac(shipment)"} {
		if !strings.Contains(y, want) {
			t.Errorf("observe version lacks %q:\n%s", want, y)
		}
	}
	if strings.Contains(y, "keep") || strings.Contains(y, "bucket") {
		t.Errorf("observe version opens values:\n%s", y)
	}
	// The field the person set back to drop stays drop.
	shop := y[strings.Index(y, "POST /orders"):]
	shop = shop[:strings.Index(shop, "GET /orders")]
	if strings.Contains(shop, "$.id:") {
		t.Errorf("the person's drop on POST /orders $.id was overridden:\n%s", y)
	}
	if !strings.Contains(e.auditDump(), `"action":"policy.observe-auto"`) {
		t.Fatal("not audited as observe-auto")
	}
	// Nothing new: no version.
	e.fleet.ObserveTick(ctx)
	if b := activeOf(t, e, "p-shop"); b.Version != a.Version {
		t.Fatalf("a pass without new identifiers made v%d", b.Version)
	}
	var st ObserveStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if st.Phase != "managed" || !st.Auto || !st.Enabled {
		t.Fatalf("status: %+v", st)
	}
}

func TestObserveAutoGroupSwitch(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	obs := observeTo(t, e)
	e.user("paula", auth.RolePolicyApprover)
	doc := withCarrierService(t, obs.AuthorYAML)
	v := e.propose("paula", doc)

	var st ObserveStatus
	e.must(e.as("paula", "PUT", "/api/v1/fleet/groups/shop/observe", map[string]any{"auto": false}), 200).json(t, &st)
	if st.Auto {
		t.Fatalf("switch off: %+v", st)
	}
	e.must(e.as("paula", "PUT", "/api/v1/fleet/groups/shop/observe", map[string]any{}), 422)
	e.must(e.as("paula", "PUT", "/api/v1/fleet/groups/nope/observe", map[string]any{"auto": false}), 404)
	e.fleet.SetDiscoverySource(withCarrier(400))
	e.fleet.ObserveTick(ctx)
	if a := activeOf(t, e, "p-shop"); a.Version != v.Version {
		t.Fatalf("derived with the group's automation off: v%d", a.Version)
	}
	if !strings.Contains(e.auditDump(), `"action":"fleet.group_observe_auto"`) {
		t.Fatal("switch not audited")
	}
	e.must(e.as("paula", "PUT", "/api/v1/fleet/groups/shop/observe", map[string]any{"auto": true}), 200)
	e.fleet.ObserveTick(ctx)
	if a := activeOf(t, e, "p-shop"); a.Origin != OriginObserveAuto || a.Version == v.Version {
		t.Fatalf("not derived once the switch is on again: %+v", a)
	}
}

func TestObserveAutoKeepsPersonIdentityChoice(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	obs := observeTo(t, e)
	if !strings.Contains(obs.AuthorYAML, "jwt_claim: sub") {
		t.Fatalf("fixture: %s", obs.AuthorYAML)
	}
	// A person removes the automatic identity.
	var lines []string
	for _, l := range strings.Split(obs.AuthorYAML, "\n") {
		if strings.HasPrefix(l, "identity:") || strings.HasPrefix(l, "  subject:") {
			continue
		}
		lines = append(lines, l)
	}
	e.user("paula", auth.RolePolicyApprover)
	v := e.propose("paula", strings.Join(lines, "\n"))
	e.fleet.SetDiscoverySource(withCarrier(400))
	e.fleet.ObserveTick(ctx)
	a := activeOf(t, e, "p-shop")
	if strings.Contains(a.AuthorYAML, "jwt_claim") {
		t.Fatalf("identity set again after a person removed it (v%d -> v%d):\n%s", v.Version, a.Version, a.AuthorYAML)
	}
}

func TestHostTwinMasksIdentifiers(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	obs := observeTo(t, e)
	e.fleet.SetDiscoverySource(observedTraffic(400))
	e.user("paula", auth.RolePolicyApprover, auth.RoleOperator)
	p := principal("paula")
	v, err := e.fleet.ProposeHostTwin(ctx, p, "api.carrier.example", HostTwinRequest{PolicyID: "p-shop", Scheme: "https", Service: "carrier-api", Group: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != StatusActive || v.OpensValues || v.Version == obs.Version {
		t.Fatalf("twin with ids applies at once: %+v", v)
	}
	if !strings.Contains(v.AuthorYAML, "carrier-api:") || !strings.Contains(v.AuthorYAML, "$.orderId: hmac(order)") {
		t.Fatalf("twin lacks the hmac of the host's identifiers:\n%s", v.AuthorYAML)
	}

	// With a path in the base, the operations become relative to it.
	ops := twinIdentifierOps(&AssistResult{Services: []AssistService{{Service: "host:x.example", Ops: []AssistOp{
		{Op: "GET /v1/items/{id}", Fields: []Suggestion{{Part: "request", Path: "path.id", Suggestion: "hmac(item)", ReasonCode: "path_id"}}},
		{Op: "GET /health", Fields: []Suggestion{{Part: "response", Path: "$.id", Suggestion: "hmac(x)", ReasonCode: "id"}}},
	}}}}, "host:x.example", mustBase(t, "https://x.example/v1"))
	if len(ops) != 1 || ops[0].Op != "GET /items/{id}" {
		t.Fatalf("relative ops: %+v", ops)
	}
}

func TestAssistMergesOldHostOps(t *testing.T) {
	e := newObserveEnv(t)
	ctx := context.Background()
	obs := observeTo(t, e)
	e.user("paula", auth.RolePolicyApprover)
	doc := withCarrierService(t, obs.AuthorYAML)
	e.propose("paula", doc)
	// The old calls (host:...) sort before the declared name: one
	// operation, one row per field.
	d := withCarrier(400)
	d.fields = append(d.fields, DiscoveredField{Service: "host:api.carrier.example", Op: "POST /v1/shipments", Path: "resp.body.id", Distinct: 200, Observed: 200, Shape: "drop:str:l32"})
	e.fleet.SetDiscoverySource(d)
	res, err := e.fleet.AssistIn(ctx, "p-shop", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Services {
		if strings.HasPrefix(s.Service, "host:") {
			t.Fatalf("old host shown apart: %+v", s.Service)
		}
		seen := map[string]bool{}
		for _, o := range s.Ops {
			if seen[o.Op] {
				t.Fatalf("%s: operation %s twice", s.Service, o.Op)
			}
			seen[o.Op] = true
			fs := map[string]bool{}
			for _, f := range o.Fields {
				k := f.Part + " " + f.Path
				if fs[k] {
					t.Fatalf("%s %s: field %s twice", s.Service, o.Op, k)
				}
				fs[k] = true
			}
			if s.Service == "carrier-api" && o.Op == "POST /v1/shipments" && o.Calls != 600 {
				t.Fatalf("calls not merged: %d", o.Calls)
			}
		}
	}
}
