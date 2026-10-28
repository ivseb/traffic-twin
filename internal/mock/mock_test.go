package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

func appliedLines(applied []any) []string {
	var out []string
	for _, a := range applied {
		am := a.(map[string]any)
		out = append(out, am["at"].(string)+" "+am["rule"].(string)+" "+am["effect"].(string)+" "+am["id"].(string))
	}
	return out
}

func httpGet(h http.Handler, path string) string {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Body.String()
}

// An order answers with the shipmentId of the shipment that rule r-0007
// creates at once (GROUND_TRUTH R2), the shipment stays invisible while
// PENDING, then follows its lifecycle on the virtual clock.
func TestHappyPathWithClock(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(map[string]any{"seed": 42, "customer": "CUS-SYN-0007"})
	e.force(sid, "r-0007", "happy")

	r := e.req("POST", "/__svc/shop-api/orders", orderBody, sess(sid))
	if r.status != 201 {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
	e.conforms("shop-api", "POST /orders", 201, r)
	o := r.json()
	orderID := o["id"].(string)
	if orderID != "ORD-SYN-0071" { // the world holds up to ORD-SYN-0070
		t.Fatalf("order id = %s", orderID)
	}
	// the immediate effects ran before the response was built
	if o["shipmentId"] != "SHP-SYN-0094" { // up to SHP-SYN-0093 in the world
		t.Fatalf("shipmentId = %v: %s", o["shipmentId"], r.body)
	}
	if o["customerId"] != "CUS-SYN-0007" || o["status"] != "CONFIRMED" || o["currency"] != "EUR" || o["email"] != "anna.rossi@example.com" {
		t.Fatalf("unexpected order: %s", r.body)
	}
	if _, has := o["phone"]; has {
		t.Fatal("optional field absent from the request must be absent from the response")
	}
	if got := r.header.Get("Location"); got != "/orders/"+orderID {
		t.Fatalf("Location = %q", got)
	}
	if o["createdAt"] != "2026-10-19T00:00:00Z" {
		t.Fatalf("createdAt must come from the virtual clock: %v", o["createdAt"])
	}
	if g := e.req("GET", "/__svc/shop-api/orders/"+orderID, nil, sess(sid)); g.json()["shipmentId"] != "SHP-SYN-0094" {
		t.Fatalf("the order must keep the link: %s", g.body)
	}

	// PENDING is invisible: empty list at the carrier, 404 at the shop
	if items := e.shipments(sid, orderID); len(items) != 0 {
		t.Fatalf("pending shipment visible: %v", items)
	}
	tr := e.req("GET", "/__svc/shop-api/orders/"+orderID+"/shipment", nil, sess(sid))
	if tr.status != 404 || tr.json()["error"].(map[string]any)["code"] != "SHIPMENT_NOT_FOUND" {
		t.Fatalf("tracking before creation: %d %s", tr.status, tr.body)
	}

	// 5 minutes later it is CREATED, with the exact transition instant
	e.advance(sid, "5m")
	rr := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+orderID, nil, sess(sid))
	e.conforms("shipping-ext", "GET /v1/shipments", 200, rr)
	sh := rr.json()["items"].([]any)[0].(map[string]any)
	if sh["status"] != "CREATED" || sh["orderId"] != orderID || sh["shipmentId"] != "SHP-SYN-0094" || sh["updatedAt"] != "2026-10-19T00:05:00Z" {
		t.Fatalf("shipment = %v", sh)
	}
	if _, has := sh["eta"]; has {
		t.Fatal("eta is not in the entity state and must not be invented")
	}
	tr = e.req("GET", "/__svc/shop-api/orders/"+orderID+"/shipment", nil, sess(sid))
	e.conforms("shop-api", "GET /orders/{id}/shipment", 200, tr)
	if tr.json()["status"] != "CREATED" {
		t.Fatalf("tracking = %s", tr.body)
	}

	// 4 hours later: in transit
	e.advance(sid, "4h")
	sh = e.shipments(sid, orderID)[0].(map[string]any)
	if sh["status"] != "IN_TRANSIT" || sh["updatedAt"] != "2026-10-19T04:05:00Z" {
		t.Fatalf("shipment = %v", sh)
	}

	// the entity view exposes the pending timer
	ents := e.ctl("GET", "/sessions/"+sid+"/entities?entity=shipment&id=SHP-SYN-0094", nil)
	var views []map[string]any
	_ = json.Unmarshal(ents.body, &views)
	if len(views) != 1 || views[0]["customer_id"] != "CUS-SYN-0007" {
		t.Fatalf("entities = %s", ents.body)
	}
	pe := views[0]["pending_effects"].([]any)
	if len(pe) != 1 {
		t.Fatalf("pending effects = %v", pe)
	}
	p0 := pe[0].(map[string]any)
	if p0["effect"] != "shipment-delivered" || p0["due"] != "2026-10-21T04:05:00Z" || p0["outcome"] != "happy" || p0["source"] != "session" || p0["rule"] != "r-0007" {
		t.Fatalf("pending effect = %v", p0)
	}

	// the 02:00 batch on the 20th delivers it before its own timer
	applied := e.advance(sid, "3d")
	var viaBatch, viaTimer int
	for _, a := range applied {
		am := a.(map[string]any)
		if am["id"] != "SHP-SYN-0094" {
			continue
		}
		switch am["effect"] {
		case "batch":
			viaBatch++
			if am["at"] != "2026-10-20T02:00:00Z" || am["rule"] != "r-0012" {
				t.Fatalf("batch applied = %v", am)
			}
		case "shipment-delivered":
			viaTimer++
		}
	}
	if viaBatch != 1 || viaTimer != 0 {
		t.Fatalf("batch=%d timer=%d: a shipment must be delivered once (applied=%v)", viaBatch, viaTimer, appliedLines(applied))
	}
	sh = e.shipments(sid, orderID)[0].(map[string]any)
	if sh["status"] != "DELIVERED" || sh["updatedAt"] != "2026-10-20T02:00:00Z" {
		t.Fatalf("shipment = %v", sh)
	}
	clock := e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()
	if clock["now"] != "2026-10-22T04:05:00Z" || clock["t0"] != "2026-10-19T00:00:00Z" || clock["next_due"] != nil {
		t.Fatalf("clock = %v", clock)
	}
}

func TestCancelledScenario(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(nil)
	e.force(sid, "r-0007", "cancelled")
	id := e.order(sid)
	e.advance(sid, "5m")
	if s := e.shipments(sid, id)[0].(map[string]any); s["status"] != "CREATED" {
		t.Fatalf("shipment = %v", s)
	}
	e.advance(sid, "1h")
	s := e.shipments(sid, id)[0].(map[string]any)
	if s["status"] != "CANCELLED" || s["cancelReason"] != "ADDRESS_UNREACHABLE" || s["updatedAt"] != "2026-10-19T01:05:00Z" {
		t.Fatalf("shipment = %v", s)
	}
	// the nightly batch only takes IN_TRANSIT shipments: a cancelled one stays
	e.advance(sid, "30d")
	if s := e.shipments(sid, id)[0].(map[string]any); s["status"] != "CANCELLED" {
		t.Fatalf("shipment = %v", s)
	}
}

func TestNeverShipped(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	e.force(sid, "r-0007", "never-shipped")
	r := e.req("POST", "/__svc/shop-api/orders", orderBody, sess(sid))
	o := r.json()
	if o["shipmentId"] != "SHP-SYN-0094" { // the shipment exists, PENDING, and the shop knows its id
		t.Fatalf("order = %s", r.body)
	}
	e.advance(sid, "30d")
	id := o["id"].(string)
	if items := e.shipments(sid, id); len(items) != 0 {
		t.Fatalf("shipment became visible: %v", items)
	}
	if tr := e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid)); tr.status != 404 {
		t.Fatalf("tracking: %d", tr.status)
	}
	ents := e.ctl("GET", "/sessions/"+sid+"/entities?entity=shipment&id=SHP-SYN-0094", nil)
	if !strings.Contains(string(ents.body), `"status":"PENDING"`) {
		t.Fatalf("entities = %s", ents.body)
	}
}

// When the mock plays the carrier (r-0008), POST /v1/shipments creates the
// shipment through created_by and the rule makes it visible and moves it on.
func TestCarrierSideRule(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(nil)
	e.force(sid, "r-0008", "happy")
	body := map[string]any{
		"orderId": "ORD-SYN-0099", "service": "STANDARD", "parcels": 1,
		"recipient": map[string]any{"fullName": "Anna Rossi", "email": "anna.rossi@example.com"},
		"address":   map[string]any{"line1": "Via Finta 1", "city": "Torino", "postcode": "10100", "country": "IT"},
	}
	r := e.req("POST", "/__svc/shipping-ext/v1/shipments", body, sess(sid))
	if r.status != 202 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	e.conforms("shipping-ext", "POST /v1/shipments", 202, r)
	j := r.json()
	if j["status"] != "PENDING" || j["orderId"] != "ORD-SYN-0099" || j["shipmentId"] != "SHP-SYN-0094" || j["service"] != "STANDARD" {
		t.Fatalf("body = %s", r.body)
	}
	if r.header.Get("Location") != "/v1/shipments/SHP-SYN-0094" {
		t.Fatalf("Location = %q", r.header.Get("Location"))
	}
	if items := e.shipments(sid, "ORD-SYN-0099"); len(items) != 0 {
		t.Fatalf("pending shipment visible: %v", items)
	}
	e.advance(sid, "5m") // r-0008 shipment-created is target_id ${shipment}
	it := e.shipments(sid, "ORD-SYN-0099")
	if len(it) != 1 || it[0].(map[string]any)["status"] != "CREATED" || it[0].(map[string]any)["service"] != "STANDARD" {
		t.Fatalf("shipments = %v", it)
	}
	e.advance(sid, "1d")
	if s := e.shipments(sid, "ORD-SYN-0099")[0].(map[string]any); s["status"] != "IN_TRANSIT" && s["status"] != "DELIVERED" {
		t.Fatalf("shipment = %v", s)
	}
}

// A shipment created in a session stays visible for as long as the clock
// runs: the mock has no retention window, and the pending effects of the
// world and the nightly batch never take it away (report of the walkthrough
// of docs/GETTING_STARTED.md: "gone after ~5 virtual days"). Once visible it
// only moves forward in its lifecycle; it is invisible only while PENDING
// (hidden_when) or for the never-shipped outcome, which never shows it.
func TestShipmentStaysVisibleForDays(t *testing.T) {
	for _, opt := range []envOpt{withSpec(func(*packtest.Spec) {}), exact()} {
		e := newEnv(t, opt)
		for seed := 0; seed < 8; seed++ {
			sid := e.newSession(map[string]any{"seed": seed})
			order := fmt.Sprintf("ORD-NEW-%d", seed)
			body := map[string]any{
				"orderId": order, "service": "STANDARD", "parcels": 1,
				"recipient": map[string]any{"fullName": "Anna Leone", "email": "anna@example.org"},
				"address":   map[string]any{"line1": "Via Roma 1", "city": "Bologna", "postcode": "40121", "country": "IT"},
			}
			if r := e.req("POST", "/__svc/shipping-ext/v1/shipments", body, sess(sid)); r.status != 202 {
				t.Fatalf("create: %d %s", r.status, r.body)
			}
			rank := map[string]int{"CREATED": 1, "IN_TRANSIT": 2, "DELIVERED": 3, "CANCELLED": 3}
			seen, last := false, 0
			for step := 0; step < 10*24*12; step++ { // ten days in 5-minute steps
				if step%6 == 0 || step < 24 {
					e.advance(sid, "5m")
				} else {
					e.advance(sid, "30m")
					step += 5
				}
				items := e.shipments(sid, order)
				if len(items) == 0 {
					if seen {
						t.Fatalf("seed %d: the shipment disappeared after %d steps", seed, step)
					}
					continue
				}
				st := fmt.Sprint(items[0].(map[string]any)["status"])
				if rank[st] < last {
					t.Fatalf("seed %d: status went back to %s", seed, st)
				}
				seen, last = true, rank[st]
			}
		}
	}
}

func TestForcedOutcomeQueue(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(nil)
	r := e.ctl("POST", "/sessions/"+sid+"/scenario", map[string]any{"rule": "r-0007", "outcome": "cancelled", "times": 2})
	if r.status != 200 || len(r.json()["pending"].([]any)) != 1 {
		t.Fatalf("scenario: %d %s", r.status, r.body)
	}
	e.force(sid, "r-0007", "never-shipped")
	ids := []string{e.order(sid), e.order(sid), e.order(sid)}
	e.advance(sid, "2h")
	want := []int{1, 1, 0}
	for i, id := range ids {
		if got := len(e.shipments(sid, id)); got != want[i] {
			t.Fatalf("order %d: %d shipments, want %d", i, got, want[i])
		}
	}
	for _, c := range []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"rule": "r-0007", "outcome": "nope"}, 404},
		{map[string]any{"rule": "r-0099", "outcome": "happy"}, 404},
		{map[string]any{"rule": "r-0012", "outcome": "happy"}, 404}, // a batch rule has no outcomes
		{map[string]any{"rule": "x", "outcome": "happy"}, 400},
		{map[string]any{"rule": "r-0007"}, 400},
		{map[string]any{"rule": "r-0007", "outcome": "happy", "times": 0}, 400},
	} {
		if r := e.ctl("POST", "/sessions/"+sid+"/scenario", c.body); r.status != c.code {
			t.Fatalf("%v: %d %s", c.body, r.status, r.body)
		}
	}
}

func TestBatchFractionAndSeededChoice(t *testing.T) {
	run := func(seed int) []string {
		e := newEnv(t, exact())
		sid := e.newSession(map[string]any{"seed": seed})
		r := e.ctl("POST", "/sessions/"+sid+"/scenario", map[string]any{"rule": "r-0007", "outcome": "happy", "times": 5})
		if r.status != 200 {
			t.Fatal(r.body)
		}
		for i := 0; i < 5; i++ {
			e.order(sid)
		}
		// shipments are in transit at 04:05; the nightly run of the 20th sees
		// those five (the world's shipments are delivered by then)
		e.advance(sid, "1d")
		var moved []string
		for _, a := range e.advance(sid, "1d") {
			am := a.(map[string]any)
			if am["effect"] == "batch" {
				moved = append(moved, am["id"].(string))
			}
		}
		return moved
	}
	a := run(5)
	if len(a) != 3 { // round(0.6 x 5)
		t.Fatalf("batch moved %d shipments, want 3: %v", len(a), a)
	}
	if b := run(5); strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("same seed, different choice: %v vs %v", a, b)
	}
}

func TestForcedFault503(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	id := e.order(sid)
	r := e.ctl("PUT", "/sessions/"+sid+"/faults", map[string]any{
		"mode":  "custom",
		"rules": []any{map[string]any{"service": "shipping-ext", "op": "GET /v1/shipments", "status": 503, "p": 1.0, "times": 1}},
	})
	if r.status != 200 {
		t.Fatalf("set faults: %d %s", r.status, r.body)
	}
	path := "/__svc/shipping-ext/v1/shipments?orderId=" + id
	got := e.req("GET", path, nil, sess(sid))
	if got.status != 503 {
		t.Fatalf("status = %d", got.status)
	}
	e.conforms("shipping-ext", "GET /v1/shipments", 503, got)
	if c := got.json()["error"].(map[string]any)["code"]; c != "CARRIER_UNAVAILABLE" {
		t.Fatalf("body = %s", got.body)
	}
	if got := e.req("GET", path, nil, sess(sid)); got.status != 200 {
		t.Fatalf("second call must succeed (times: 1), got %d", got.status)
	}
	j := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	var last map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(j.body), []byte("\n")) {
		var m map[string]any
		_ = json.Unmarshal(line, &m)
		if f, ok := m["fault"].(map[string]any); ok && f["status"] != nil {
			last = m
		}
	}
	if last == nil || last["matched"] != true || last["status"].(float64) != 503 {
		t.Fatalf("journal = %s", j.body)
	}
	if _, has := last["fault"].(map[string]any)["kind"]; has {
		t.Fatalf("fault object has extra keys: %v", last["fault"])
	}
}

func TestFaultOnCauseDoesNotFireRule(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	e.ctl("PUT", "/sessions/"+sid+"/faults", map[string]any{
		"mode":  "custom",
		"rules": []any{map[string]any{"service": "shop-api", "op": "POST /orders", "status": 503, "p": 1, "times": 1}},
	})
	r := e.req("POST", "/__svc/shop-api/orders", orderBody, sess(sid))
	if r.status != 503 {
		t.Fatalf("status = %d", r.status)
	}
	e.advance(sid, "30d")
	ents := e.ctl("GET", "/sessions/"+sid+"/entities?entity=shipment", nil)
	var views []map[string]any
	_ = json.Unmarshal(ents.body, &views)
	if len(views) != 3 { // only the world's shipments
		t.Fatalf("entities = %s", ents.body)
	}
}

func TestObservedFaultsAreSeededAndRoughlyAtObservedFrequency(t *testing.T) {
	seq := func(seed int) []int {
		e := newEnv(t, withFaults("observed"))
		sid := e.newSession(map[string]any{"seed": seed, "faults": map[string]any{"mode": "observed"}})
		var out []int
		for i := 0; i < 3000; i++ {
			r := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=ORD-SYN-0042", nil, sess(sid))
			out = append(out, r.status)
		}
		return out
	}
	a, b := seq(7), seq(7)
	n503 := 0
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("call %d differs between runs with the same seed", i)
		}
		if a[i] == 503 {
			n503++
		}
	}
	if n503 < 10 || n503 > 60 { // 1% of 3000 = 30
		t.Fatalf("503 count = %d of 3000", n503)
	}
	if c := seq(8); fmt.Sprint(c) == fmt.Sprint(a) {
		t.Fatal("different seeds gave the same fault sequence")
	}
}

func TestFaultsOffAndLatencyRecorded(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(map[string]any{"faults": map[string]any{"mode": "off"}})
	for i := 0; i < 300; i++ {
		if r := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=x", nil, sess(sid)); r.status != 200 {
			t.Fatalf("fault injected while off: %d", r.status)
		}
	}
	if r := e.ctl("PUT", "/sessions/"+sid+"/faults", map[string]any{"mode": "observed"}); r.status != 200 {
		t.Fatal(r.body)
	}
	e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=x", nil, sess(sid))
	j := e.ctl("GET", "/sessions/"+sid+"/journal?since=300", nil)
	if !strings.Contains(string(j.body), `"latency_ms"`) {
		t.Fatalf("observed latency not recorded: %s", j.body)
	}
}

func TestSessionIsolation(t *testing.T) {
	e := newEnv(t, exact())
	s1, s2 := e.newSession(nil), e.newSession(nil)
	if s1 == s2 {
		t.Fatal("same session id")
	}
	e.force(s1, "r-0007", "happy")
	id1 := e.order(s1)
	e.advance(s1, "10m")
	if r := e.req("GET", "/__svc/shop-api/orders/"+id1, nil, sess(s2)); r.status != 404 {
		t.Fatalf("order leaked into another session: %d", r.status)
	}
	if got := e.shipments(s2, id1); len(got) != 0 {
		t.Fatalf("shipment leaked: %v", got)
	}
	if now := e.ctl("GET", "/sessions/"+s2+"/clock", nil).json()["now"]; now != "2026-10-19T00:00:00Z" {
		t.Fatalf("clock leaked: %v", now)
	}
	if id2 := e.order(s2); id2 != id1 { // each session numbers its own entities
		t.Fatalf("ids: %s vs %s", id1, id2)
	}
	if r := e.req("GET", "/__svc/shop-api/orders/"+id1, nil, nil); r.status != 404 {
		t.Fatalf("order leaked into default: %d", r.status)
	}
	if n := bytes.Count(e.ctl("GET", "/sessions/"+s1+"/journal", nil).body, []byte("\n")); n != 1 {
		t.Fatalf("journal of s1 has %d entries", n)
	}
	if r := e.ctl("DELETE", "/sessions/"+s1, nil); r.status != 204 {
		t.Fatal(r.status)
	}
	if r := e.ctl("GET", "/sessions/"+s1, nil); r.status != 404 {
		t.Fatal(r.status)
	}
	if r := e.req("GET", "/__svc/shop-api/orders/x", nil, sess(s1)); r.status != 404 || r.json()["code"] != "session_not_found" {
		t.Fatalf("deleted session still serves: %d", r.status)
	}
}

func TestDeterministicJournals(t *testing.T) {
	run := func(seed int) (journal []byte, outcomes string) {
		e := newEnv(t)
		sid := e.newSession(map[string]any{"id": "det", "seed": seed, "customer": "CUS-SYN-0001", "faults": map[string]any{"mode": "observed"}})
		var ids []string
		for i := 0; i < 40; i++ {
			r := e.req("POST", "/__svc/shop-api/orders", orderBody, map[string]string{"X-TT-Session": sid, "Traceparent": "00-aaaa-bbbb-01"})
			if r.status == 201 {
				ids = append(ids, r.json()["id"].(string))
			}
		}
		e.advance(sid, "2d")
		for _, id := range ids {
			e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+id, nil, sess(sid))
		}
		e.advance(sid, "3d")
		for _, id := range ids {
			e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid))
		}
		e.req("GET", "/__svc/nope/x", nil, sess(sid))
		var oc []string
		for _, line := range bytes.Split(bytes.TrimSpace(e.ctl("GET", "/sessions/det/journal", nil).body), []byte("\n")) {
			var m struct {
				Triggered []struct{ Outcome string }
			}
			_ = json.Unmarshal(line, &m)
			for _, tr := range m.Triggered {
				oc = append(oc, tr.Outcome)
			}
		}
		return e.ctl("GET", "/sessions/det/journal", nil).body, strings.Join(oc, ",")
	}
	a, oa := run(11)
	b, _ := run(11)
	if !bytes.Equal(a, b) {
		t.Fatalf("journals differ with the same seed:\n%s\n---\n%s", a, b)
	}
	if len(a) == 0 || !strings.Contains(oa, "happy") {
		t.Fatalf("journal looks empty: %s", a)
	}
	if _, oc := run(12); oc == oa {
		t.Fatal("different seeds drew identical outcomes")
	}
}

func TestDelayRangesAreDrawnWithTheSeed(t *testing.T) {
	instants := func(seed int) map[string]string {
		e := newEnv(t)
		sid := e.newSession(map[string]any{"seed": seed})
		e.force(sid, "r-0007", "happy")
		id := e.order(sid)
		shipID := e.req("GET", "/__svc/shop-api/orders/"+id, nil, sess(sid)).json()["shipmentId"].(string)
		out := map[string]string{}
		for _, line := range appliedLines(e.advance(sid, "1d")) {
			f := strings.Fields(line)
			if f[3] == shipID {
				out[f[2]] = f[0]
			}
		}
		return out
	}
	parse := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	t0 := parse("2026-10-19T00:00:00Z")
	a := instants(3)
	created, transit := parse(a["shipment-created"]), parse(a["shipment-in-transit"])
	if d := created.Sub(t0); d < 2*time.Minute || d > 10*time.Minute {
		t.Fatalf("created after %v, want 2m..10m", d)
	}
	if d := transit.Sub(created); d < time.Hour || d > 6*time.Hour {
		t.Fatalf("in transit %v after creation, want 1h..6h", d)
	}
	if b := instants(3); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("same seed, different delays: %v vs %v", a, b)
	}
	diff := false
	for seed := 4; seed < 10 && !diff; seed++ {
		diff = fmt.Sprint(instants(seed)) != fmt.Sprint(a)
	}
	if !diff {
		t.Fatal("delays do not depend on the seed")
	}
}

func TestUnmatchedRequests(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	h := sess(sid)

	r := e.req("GET", "/anything", nil, map[string]string{"X-TT-Session": sid, "Host": "unknown.example"})
	if r.status != 404 || r.header.Get("X-TT-Unmatched") != "no-service" || r.json()["code"] != "no-service" {
		t.Fatalf("no-service: %d %s", r.status, r.body)
	}
	if r := e.req("GET", "/__svc/shop-api/ordres", nil, h); r.status != 404 {
		t.Fatalf("no-operation: %d", r.status)
	}
	if r := e.req("DELETE", "/__svc/shop-api/orders", nil, h); r.status != 405 || r.header.Get("Allow") != "POST" {
		t.Fatalf("405: %d allow=%q", r.status, r.header.Get("Allow"))
	}
	// invalid body: answered with the 400 of the contract
	bad := map[string]any{"items": []any{map[string]any{"sku": "S", "qty": 9}}, "email": "a@example.com"}
	r = e.req("POST", "/__svc/shop-api/orders", bad, h)
	if r.status != 400 || r.json()["error"].(map[string]any)["code"] != "VALIDATION_ERROR" {
		t.Fatalf("invalid body: %d %s", r.status, r.body)
	}
	e.req("POST", "/__svc/shop-api/orders", map[string]any{"items": []any{}}, h)
	e.req("POST", "/__svc/shop-api/orders", "{not json", h)
	// no 400 declared by the operation: the envelope, with the pointer
	if r := e.req("GET", "/__svc/shipping-ext/v1/shipments", nil, h); r.status != 400 || r.json()["code"] != "invalid-request" || r.json()["pointer"] != "/query/orderId" {
		t.Fatalf("missing query: %d %s", r.status, r.body)
	}
	e.order(sid) // a valid call stays out of the unmatched list

	u := e.ctl("GET", "/sessions/"+sid+"/journal/unmatched", nil)
	if ct := u.header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content type %q", ct)
	}
	type entry struct {
		Reason    string  `json:"reason"`
		Pointer   string  `json:"pointer"`
		NearestOp string  `json:"nearest_op"`
		Path      string  `json:"path"`
		Matched   bool    `json:"matched"`
		Status    int     `json:"status"`
		Service   *string `json:"service"`
	}
	var got []entry
	for _, line := range bytes.Split(bytes.TrimSpace(u.body), []byte("\n")) {
		var en entry
		if err := json.Unmarshal(line, &en); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		got = append(got, en)
	}
	want := []struct{ reason, pointer, nearest string }{
		{"no-service", "", ""},
		{"no-operation", "", "POST /orders"},
		{"no-operation", "", "POST /orders"},
		{"invalid-request", "/body/items/0/qty", ""},
		{"invalid-request", "/body/email", ""},
		{"invalid-request", "/body", ""},
		{"invalid-request", "/query/orderId", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("unmatched = %s", u.body)
	}
	for i, w := range want {
		g := got[i]
		if g.Matched || g.Reason != w.reason || g.Pointer != w.pointer || (w.nearest != "" && g.NearestOp != w.nearest) {
			t.Errorf("entry %d = %+v, want %+v", i, g, w)
		}
	}
	if got[0].Service != nil {
		t.Error("no-service entry must have a null service")
	}
	j := e.ctl("GET", "/sessions/"+sid+"/journal?since=7", nil)
	if !strings.Contains(string(j.body), `"rule":"r-0007"`) || strings.Count(string(j.body), "\n") != 1 {
		t.Fatalf("journal since=7: %s", j.body)
	}
}

func TestPayloadTooLargeIsJournaled(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	big := `{"email":"` + strings.Repeat("a", 2<<20) + `"}`
	r := e.req("POST", "/__svc/shop-api/orders", big, sess(sid))
	if r.status != 413 || r.json()["code"] != "payload_too_large" {
		t.Fatalf("oversize: %d %s", r.status, r.body)
	}
	if u := e.ctl("GET", "/sessions/"+sid+"/journal/unmatched", nil); !strings.Contains(string(u.body), `"reason":"payload_too_large"`) {
		t.Fatalf("unmatched = %s", u.body)
	}
}

func TestHostHeaderRouting(t *testing.T) {
	e := newEnv(t)
	for _, host := range []string{"carrier", "carrier:8080", "shipping-ext", "carrier.mock.internal"} {
		r := e.req("GET", "/v1/shipments?orderId=x", nil, map[string]string{"Host": host})
		if r.status != 200 {
			t.Fatalf("Host %s: %d %s", host, r.status, r.body)
		}
	}
	r := e.req("POST", "/__svc/shop/orders", orderBody, map[string]string{"Host": "carrier"})
	if r.status != 201 {
		t.Fatalf("prefix by alias: %d %s", r.status, r.body)
	}
}

func TestResetSession(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(map[string]any{"seed": 3, "customer": "CUS-SYN-0007"})
	e.force(sid, "r-0007", "happy")
	first := e.order(sid)
	e.advance(sid, "1d")
	e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"customer": "CUS-SYN-0009"})
	if r := e.ctl("POST", "/sessions/"+sid+"/reset", nil); r.status != 200 || r.json()["now"] != "2026-10-19T00:00:00Z" || r.json()["customer"] != "CUS-SYN-0007" {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if j := e.ctl("GET", "/sessions/"+sid+"/journal", nil); len(bytes.TrimSpace(j.body)) != 0 {
		t.Fatalf("journal not cleared: %s", j.body)
	}
	if again := e.order(sid); again != first {
		t.Fatalf("ids restart after reset: %s vs %s", again, first)
	}
}

func TestSelectCustomerPackAndControlErrors(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	r := e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"archetype": "arch-03"})
	if r.status != 200 || r.json()["id"] != "CUS-SYN-0007" { // first by id
		t.Fatalf("archetype: %d %s", r.status, r.body)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"customer": "CUS-SYN-0001"}); r.status != 200 {
		t.Fatal(r.body)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"customer": "CUS-SYN-9999"}); r.status != 404 {
		t.Fatal(r.status)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"customer": "a", "archetype": "b"}); r.status != 400 {
		t.Fatal(r.status)
	}
	var cs []map[string]any
	_ = json.Unmarshal(e.ctl("GET", "/customers?archetype=arch-03", nil).body, &cs)
	if len(cs) != 2 {
		t.Fatalf("customers = %v", cs)
	}
	p := e.ctl("GET", "/pack", nil).json()
	if p["pack_id"] != "pk-20261019-0001" || p["customers"].(json.Number).String() != "3" || len(p["rules"].([]any)) != 3 ||
		p["not_after"] != nil || fmt.Sprint(p["scenarios"]) != "[shipment-cancelled tracking-down]" {
		t.Fatalf("pack = %v", p)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"to": "2020-01-01T00:00:00Z"}); r.status != 400 || r.json()["code"] != "clock_backwards" {
		t.Fatalf("backwards: %d", r.status)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"by": "5x"}); r.status != 400 || r.json()["pointer"] != "/by" {
		t.Fatalf("bad duration: %d %s", r.status, r.body)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"by": "1h", "to": "2030-01-01T00:00:00Z"}); r.status != 400 {
		t.Fatalf("both: %d", r.status)
	}
	if r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"to": "2026-10-19T12:00:00Z"}); r.status != 200 || r.json()["now"] != "2026-10-19T12:00:00Z" {
		t.Fatalf("advance to: %d %s", r.status, r.body)
	}
	e.newSession(map[string]any{"id": "mine"})
	if r := e.ctl("POST", "/sessions", map[string]any{"id": "mine"}); r.status != 409 || r.json()["code"] != "session_exists" {
		t.Fatalf("duplicate: %d", r.status)
	}
	if r := e.ctl("GET", "/nothing", nil); r.status != 404 || r.json()["code"] != "not_found" {
		t.Fatal(r.status)
	}
	if r := e.ctl("DELETE", "/pack", nil); r.status != 405 || r.header.Get("Allow") != "GET" {
		t.Fatalf("405: %d", r.status)
	}
	if r := e.ctl("GET", "/sessions/bad%20id", nil); r.status != 400 || r.json()["code"] != "bad_session_id" {
		t.Fatalf("bad id: %d %s", r.status, r.body)
	}
}

func TestJournalHAR(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	e.order(sid)
	e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=ORD-SYN-0071", nil, sess(sid))
	r := e.ctl("GET", "/sessions/"+sid+"/journal?format=har", nil)
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
		t.Fatalf("har: %d %s", r.status, r.header.Get("Content-Type"))
	}
	log := r.json()["log"].(map[string]any)
	entries := log["entries"].([]any)
	if log["version"] != "1.2" || len(entries) != 2 {
		t.Fatalf("har = %s", r.body)
	}
	e0 := entries[0].(map[string]any)
	if e0["request"].(map[string]any)["method"] != "POST" || e0["response"].(map[string]any)["status"].(json.Number).String() != "201" {
		t.Fatalf("entry = %v", e0)
	}
	q := entries[1].(map[string]any)["request"].(map[string]any)["queryString"].([]any)
	if len(q) != 1 || q[0].(map[string]any)["name"] != "orderId" {
		t.Fatalf("queryString = %v", q)
	}
	if r := e.ctl("GET", "/sessions/"+sid+"/journal?format=xml", nil); r.status != 400 {
		t.Fatal(r.status)
	}
}

func TestJournalNeverRecordsCredentials(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0042", nil, map[string]string{
		"X-TT-Session": sid, "Authorization": "Bearer secret-token-value", "Cookie": "sid=secret-cookie-value"})
	j := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	if bytes.Contains(j.body, []byte("secret-")) {
		t.Fatalf("credentials leaked into the journal: %s", j.body)
	}
}

func TestControlTokenAuthAndPublicHealth(t *testing.T) {
	e := newEnv(t, withToken("s3cret"))
	// health is public and reveals nothing but "ok"
	h := e.req("GET", "/__tt/health", nil, nil)
	if h.status != 200 || strings.TrimSpace(string(h.body)) != `{"status":"ok"}` || h.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("health: %d %q %q", h.status, h.body, h.header.Get("Cache-Control"))
	}
	for _, path := range []string{"/__tt/pack", "/__tt/customers", "/__tt/scenarios", "/__tt/sessions/default"} {
		r := e.req("GET", path, nil, nil)
		if r.status != 401 || r.header.Get("WWW-Authenticate") != "Bearer" || r.json()["code"] != "unauthorized" {
			t.Fatalf("%s without token: %d", path, r.status)
		}
	}
	if r := e.req("GET", "/__tt/pack", nil, map[string]string{"Authorization": "Bearer wrong"}); r.status != 401 {
		t.Fatalf("wrong token: %d", r.status)
	}
	if r := e.req("GET", "/__tt/pack", nil, map[string]string{"Authorization": "Basic czNjcmV0"}); r.status != 401 {
		t.Fatalf("wrong scheme: %d", r.status)
	}
	if r := e.req("GET", "/__tt/pack", nil, map[string]string{"Authorization": "Bearer s3cret"}); r.status != 200 || r.json()["pack_id"] != "pk-20261019-0001" {
		t.Fatalf("right token: %d", r.status)
	}
	if r := e.req("GET", "/__svc/shop-api/ping", nil, nil); r.status != 200 {
		t.Fatalf("data plane: %d", r.status)
	}
}

func TestRefusesNonLoopbackWithoutToken(t *testing.T) {
	built, err := packtest.Build(filepath.Join(t.TempDir(), "p"), packtest.DemoSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.0.2.1:8480"} {
		err := Run(t.Context(), Config{Pack: built.Dir, GatePubKeys: built.Keys, Addr: addr})
		if err == nil || !strings.Contains(err.Error(), "control token") {
			t.Fatalf("%s: err = %v", addr, err)
		}
	}
}

func TestRefusesUnsignedForeignAndExpiredPacks(t *testing.T) {
	built, err := packtest.Build(filepath.Join(t.TempDir(), "p"), packtest.DemoSpec())
	if err != nil {
		t.Fatal(err)
	}
	_, otherKeys := packtest.NewKey("gate-test-1")
	if _, err := New(Config{Pack: built.Dir, GatePubKeys: otherKeys}); err == nil {
		t.Fatal("pack signed by another key was accepted")
	}
	t.Setenv("TT_GATE_PUBKEYS", "")
	if _, err := New(Config{Pack: built.Dir}); err == nil {
		t.Fatal("pack accepted without any trusted key")
	}
	if _, err := New(Config{Pack: built.Dir, GatePubKeys: built.Keys}); err != nil {
		t.Fatal(err)
	}

	// not_after in the past: pack_expired; in the far future: loads and is reported
	spec := packtest.DemoSpec()
	spec.Manifest["not_after"] = "2026-10-19T04:20:00Z"
	exp, err := packtest.Build(filepath.Join(t.TempDir(), "exp"), spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Pack: exp.Dir, GatePubKeys: exp.Keys}); err == nil || !strings.Contains(err.Error(), "pack_expired") {
		t.Fatalf("expired pack: %v", err)
	}
	spec.Manifest["not_after"] = "2099-01-01T00:00:00Z"
	fut, err := packtest.Build(filepath.Join(t.TempDir(), "fut"), spec)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Pack: fut.Dir, GatePubKeys: fut.Keys})
	if err != nil {
		t.Fatal(err)
	}
	if rec := httpGet(m.Handler(), "/__tt/pack"); !strings.Contains(rec, `"not_after":"2099-01-01T00:00:00Z"`) {
		t.Fatalf("pack = %s", rec)
	}
}

func TestConcurrentRequestsAreSafe(t *testing.T) {
	e := newEnv(t, withFaults("observed"))
	var wg sync.WaitGroup
	shared := e.newSession(nil)
	for w := 0; w < 8; w++ {
		own := e.newSession(nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				for _, sid := range []string{own, shared} {
					r := e.req("POST", "/__svc/shop-api/orders", orderBody, sess(sid))
					if r.status == 201 {
						e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+r.json()["id"].(string), nil, sess(sid))
					}
					e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"by": "1h"})
					e.ctl("GET", "/sessions/"+sid+"/journal", nil)
					e.ctl("GET", "/sessions/"+sid+"/entities", nil)
					if i%10 == 9 {
						e.ctl("POST", "/sessions/"+sid+"/scenario", map[string]any{"preset": "tracking-down"})
					}
				}
			}
		}()
	}
	wg.Wait()
	var views []map[string]any
	_ = json.Unmarshal(e.ctl("GET", "/sessions/"+shared+"/entities?entity=order", nil).body, &views)
	seen := map[any]bool{}
	for _, v := range views {
		if seen[v["id"]] {
			t.Fatalf("duplicate id %v", v["id"])
		}
		seen[v["id"]] = true
	}
}
