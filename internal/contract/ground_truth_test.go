package contract_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
)

var day1 = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func near(t *testing.T, what string, got, want, tol float64) {
	t.Helper()
	if got < want-tol || got > want+tol {
		t.Errorf("%s: got %.4f, want %.4f +- %.4f", what, got, want, tol)
	}
}

// Events sanitized by the Go reference sanitizer with a real policy, stored
// by the intake, must give back the facts of demo/GROUND_TRUTH.md section 3.
func TestGroundTruthFromSanitizedTraffic(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 2500, contracttest.Variant{})
	h.Wait()
	if h.Rejects != 0 {
		t.Fatalf("%d events rejected by the intake", h.Rejects)
	}

	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	snaps, err := eng.SnapshotWindow(context.Background(), contract.Window{From: day1, To: day1.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*contract.Contract{}
	for _, s := range snaps {
		by[s.Service] = s.Contract
	}
	carrier, shop := by["shipping-ext"], by["shop-api"]
	if carrier == nil || shop == nil {
		t.Fatalf("services: %v", by)
	}

	// --- carrier GET /v1/shipments
	get := carrier.Op("GET /v1/shipments")
	if get == nil {
		t.Fatal("GET /v1/shipments missing")
	}
	r200, r503 := get.Response(200), get.Response(503)
	if r200 == nil || r503 == nil {
		t.Fatalf("statuses: %+v", get.Responses)
	}
	near(t, "GET 200 frequency", r200.Frequency, 0.99, 0.01)
	near(t, "GET 503 frequency", r503.Frequency, 0.01, 0.006)
	if get.Latency == nil {
		t.Fatal("no latency")
	}
	near(t, "GET p50", float64(get.Latency.P50), 80, 12)
	near(t, "GET p95", float64(get.Latency.P95), 215, 60)
	if q := paramByName(get.Query, "orderId"); q == nil || !q.Required || q.Schema.Kind != "id" || q.Schema.Domain != "order" {
		t.Errorf("orderId query: %+v", q)
	}
	items := r200.Body[0].Schema.Prop("items")
	if items == nil || !items.Required || !items.Schema.HasType("array") {
		t.Fatalf("items: %+v", items)
	}
	it := items.Schema.Items
	for name, domain := range map[string]string{"shipmentId": "shipment", "orderId": "order"} {
		p := it.Prop(name)
		if p == nil || !p.Required || p.Schema.Kind != "id" || p.Schema.Domain != domain {
			t.Errorf("%s: %+v", name, p)
		}
	}
	st := it.Prop("status").Schema
	got := map[string]bool{}
	for _, e := range st.PublishedEnum() {
		got[e.Value] = true
	}
	for _, want := range []string{"CREATED", "IN_TRANSIT", "DELIVERED"} {
		if !got[want] {
			t.Errorf("status enum lacks %s: %v", want, got)
		}
	}
	if got["PENDING"] {
		t.Error("PENDING must never appear in the list")
	}
	eta := it.Prop("eta")
	if eta == nil || eta.Required {
		t.Fatalf("eta must be optional: %+v", eta)
	}
	near(t, "eta presence", eta.Presence, 0.37, 0.06)
	if eta.Schema.Kind != "bucket" || eta.Schema.Unit != "day" {
		t.Errorf("eta schema: %+v", eta.Schema)
	}
	cr := it.Prop("cancelReason")
	if cr == nil || cr.Required || cr.Presence > 0.1 {
		t.Errorf("cancelReason: %+v", cr)
	}
	code := r503.Body[0].Schema.Prop("error").Schema.Prop("code")
	if code == nil || !code.Required {
		t.Errorf("503 error.code: %+v", code)
	}

	// --- carrier POST /v1/shipments
	post := carrier.Op("POST /v1/shipments")
	if post == nil {
		t.Fatal("POST /v1/shipments missing")
	}
	near(t, "POST 202 frequency", post.Response(202).Frequency, 0.99, 0.01)
	near(t, "POST p50", float64(post.Latency.P50), 140, 20)
	reqS := post.Body[0].Schema
	for _, n := range []string{"orderId", "service", "parcels", "recipient", "address"} {
		if p := reqS.Prop(n); p == nil || !p.Required {
			t.Errorf("request %s: %+v", n, p)
		}
	}
	if svc := reqS.Prop("service").Schema; svc.Kind != "enum" || len(svc.PublishedEnum()) != 2 {
		t.Errorf("service enum: %+v", svc)
	}
	if p := reqS.Prop("recipient").Schema.Prop("phone"); p != nil && p.Required {
		t.Error("phone must be optional")
	}

	// --- shop POST /orders
	orders := shop.Op("POST /orders")
	if orders == nil {
		t.Fatal("POST /orders missing")
	}
	near(t, "201 frequency", orders.Response(201).Frequency, 0.96, 0.02)
	near(t, "400 frequency", orders.Response(400).Frequency, 0.03, 0.015)
	if orders.Response(409) == nil {
		t.Error("409 missing")
	}
	ok := orders.Response(201).Body[0].Schema
	for _, n := range []string{"id", "customerId", "status", "items", "currency", "total", "email", "shippingAddress", "shipmentId", "createdAt"} {
		if p := ok.Prop(n); p == nil || !p.Required {
			t.Errorf("201 %s: %+v", n, p)
		}
	}
	for name, want := range map[string]float64{"phone": 0.60, "note": 0.30, "couponCode": 0.15, "giftWrap": 0.10} {
		p := ok.Prop(name)
		if p == nil || p.Required {
			t.Errorf("%s should be optional: %+v", name, p)
			continue
		}
		near(t, name+" presence", p.Presence, want, 0.04)
	}
	if p := ok.Prop("shippingAddress").Schema.Prop("line2"); p == nil || p.Required {
		t.Errorf("line2: %+v", p)
	} else {
		near(t, "line2 presence", p.Presence, 0.25, 0.04)
	}
	if id := ok.Prop("id").Schema; id.Domain != "order" || id.Kind != "id" {
		t.Errorf("id: %+v", id)
	}
	if tot := ok.Prop("total").Schema; tot.Kind != "bucket" || len(tot.Bounds) != 4 {
		t.Errorf("total: %+v", tot)
	}
	var codes []string
	for _, e := range orders.Response(400).Body[0].Schema.Prop("error").Schema.Prop("code").Schema.PublishedEnum() {
		codes = append(codes, e.Value)
	}
	if !strings.Contains(strings.Join(codes, ","), "VALIDATION_ERROR") {
		t.Errorf("400 codes: %v", codes)
	}

	// --- shop GET /orders/{id}/shipment: 404 SHIPMENT_NOT_FOUND exists
	ship := shop.Op("GET /orders/{id}/shipment")
	if ship == nil || ship.Response(404) == nil || ship.Response(503) == nil {
		t.Fatalf("shipment op: %+v", ship)
	}
	if pp := paramByName(ship.PathParams, "id"); pp == nil || pp.Schema.Domain != "order" || !pp.Required {
		t.Errorf("path id: %+v", pp)
	}

	// --- OpenAPI documents: deterministic, valid shape, no hidden data.
	doc, err := carrier.JSON(contract.RenderOptions{Hints: contract.PolicyHints(h.Policy)})
	if err != nil {
		t.Fatal(err)
	}
	doc2, _ := carrier.JSON(contract.RenderOptions{Hints: contract.PolicyHints(h.Policy)})
	if string(doc) != string(doc2) {
		t.Error("non deterministic")
	}
	for _, want := range []string{`"openapi":"3.1.0"`, `"/v1/shipments"`, `"x-tt-presence"`, `"kind":"id"`, `"domain":"order"`, `"x-tt-frequency"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("document lacks %s", want)
		}
	}
	if _, err := carrier.YAML(contract.RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	// Examples carry no stored value: only invented placeholders.
	if strings.Contains(string(doc), "tk1:") {
		t.Error("token in the document")
	}
}

func paramByName(ps []*contract.Param, name string) *contract.Param {
	for _, p := range ps {
		if p.Name == name {
			return p
		}
	}
	return nil
}
