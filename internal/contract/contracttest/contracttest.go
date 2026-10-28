// Package contracttest builds demo-like traffic for the tests of the contract
// and drift packages: invented e-commerce exchanges (shop-api in, the
// shipping-ext carrier out, following demo/GROUND_TRUTH.md) are sanitized by
// the Go reference sanitizer with a real compiled policy, ingested through
// the intake and left in a real SQLite store.
//
// It is test support code: it uses only invented data and has no effect
// outside tests.
package contracttest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/store"
)

const authorPolicy = `{
 "format":"tt.policy/v1","policy_id":"p-demo","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "sampling":{"rate":1},
 "segments":{"allow":[]},
 "global":{
   "request":{"headers":{"content-type":"keep"}},
   "response":{"headers":{"content-type":"keep"}},
   "errors":{"body":{"$.error.code":"keep"}}},
 "services":{
  "shop-api":{"match":{"inbound":true},"ops":{
    "POST /orders":{
      "request":{"$.items[*].sku":"keep","$.items[*].qty":"keep","$.shippingAddress.country":"keep"},
      "response":{"$.id":"hmac(order)","$.customerId":"hmac(customer)","$.shipmentId":"hmac(shipment)",
        "$.status":"keep","$.currency":"keep","$.total":"bucket(num, [0, 50, 100, 250])","$.createdAt":"bucket(time, day)",
        "$.items[*].sku":"keep","$.items[*].qty":"keep"}},
    "GET /orders/{id}":{
      "request":{"path":{"id":"hmac(order)"}},
      "response":{"$.id":"hmac(order)","$.customerId":"hmac(customer)","$.shipmentId":"hmac(shipment)",
        "$.status":"keep","$.currency":"keep","$.total":"bucket(num, [0, 50, 100, 250])","$.createdAt":"bucket(time, day)"}},
    "GET /orders/{id}/shipment":{
      "request":{"path":{"id":"hmac(order)"}},
      "response":{"$.orderId":"hmac(order)","$.shipmentId":"hmac(shipment)","$.status":"keep","$.cancelReason":"keep",
        "$.eta":"bucket(time, day)","$.updatedAt":"bucket(time, hour)"}},
    "GET /customers/{id}/orders":{
      "request":{"path":{"id":"hmac(customer)"}},
      "response":{"$.customerId":"hmac(customer)","$.items[*].id":"hmac(order)","$.items[*].status":"keep","$.items[*].currency":"keep"}}}},
  "shipping-ext":{"match":{"base":"https://carrier.example"},"ops":{
    "POST /v1/shipments":{
      "request":{"$.orderId":"hmac(order)","$.service":"keep","$.parcels":"keep","$.address.country":"keep"},
      "response":{"$.shipmentId":"hmac(shipment)","$.orderId":"hmac(order)","$.status":"keep","$.service":"keep","$.createdAt":"bucket(time, day)"}},
    "GET /v1/shipments":{
      "request":{"query":{"orderId":"hmac(order)"}},
      "response":{"$.items[*].shipmentId":"hmac(shipment)","$.items[*].orderId":"hmac(order)","$.items[*].status":"keep",
        "$.items[*].service":"keep","$.items[*].cancelReason":"keep","$.items[*].eta":"bucket(time, day)","$.items[*].updatedAt":"bucket(time, hour)"}}}}
 }}`

// Harness is a sanitizer, an intake and an event store ready for traffic.
type Harness struct {
	T       testing.TB
	DB      *store.DB
	Intake  *intake.Intake
	Store   *intake.Store
	Policy  *policy.Policy
	Sanit   *sanitizer.Engine
	Rejects int

	rng    *rand.Rand
	source string
	hash   string
	seq    int
}

// Variant changes the traffic to provoke drift.
type Variant struct {
	// EtaEpoch makes the carrier return eta as an integer (epoch) instead of
	// a date-time string.
	EtaEpoch bool
	// CarrierError503 is the share of carrier calls answered 503 (default
	// 0.01).
	CarrierError503 float64
	// CarrierBadGateway is the share of carrier GETs answered 502 with a new
	// error code.
	CarrierBadGateway float64
}

// New creates the harness with a fresh database in a temporary directory.
func New(t testing.TB) *Harness {
	t.Helper()
	author := mustDecode(t, authorPolicy)
	a, err := policy.AuthorFromGeneric(author)
	if err != nil {
		t.Fatalf("author: %v", err)
	}
	created := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	body, pol, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: created, Groups: []string{"demo"}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := sanitizer.NewKey("k1", secret)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := sanitizer.NewEngineWithKey(pol, key)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := intake.ParsePolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sources, policies := intake.NewMemSourceRegistry(), intake.NewMemPolicyRegistry()
	const source = "src-demo1"
	sources.Set(intake.SourceInfo{ID: source, Group: "demo", ServiceName: "shop-api", AllowedServices: []string{"shop-api"}})
	policies.Add(ip)
	cfg := intake.DefaultConfig()
	cfg.FlushInterval, cfg.PurgeInterval = time.Hour, time.Hour
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	in, err := intake.New(context.Background(), cfg, intake.Deps{
		DB: db, Sources: sources, Policies: policies,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(context.Background()) })
	return &Harness{T: t, DB: db, Intake: in, Store: in.Store(), Policy: pol, Sanit: eng,
		rng: rand.New(rand.NewPCG(42, 7)), source: source, hash: policy.Hash(body)}
}

func mustDecode(t testing.TB, s string) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Wait blocks until the intake has stored everything accepted so far.
func (h *Harness) Wait() {
	h.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := h.Intake.WaitIdle(ctx); err != nil {
		h.T.Fatal(err)
	}
}

// exchange is one HTTP exchange before sanitizing.
type exchange struct {
	dir     sanitizer.Direction
	method  string
	path    string
	query   string
	reqAuth string
	reqBody any
	status  int
	resBody any
	latency int64
	trace   string
	at      time.Time
}

func (h *Harness) emit(x exchange) {
	h.T.Helper()
	ex := &sanitizer.Exchange{Dir: x.dir, Method: x.method, RawPath: []byte(x.path), Status: x.status, TraceID: x.trace}
	if x.query != "" {
		ex.RawQuery = []byte(x.query)
	}
	if x.dir == sanitizer.Inbound {
		ex.ServiceName = "shop-api"
	} else {
		ex.URLBase = "https://carrier.example"
	}
	if x.reqAuth != "" {
		ex.ReqHeaders = append(ex.ReqHeaders, sanitizer.Header{Name: "Authorization", Value: []byte("Bearer " + x.reqAuth)})
	}
	ex.RespHeaders = []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json; charset=utf-8")}}
	if x.reqBody != nil {
		b, _ := json.Marshal(x.reqBody)
		ex.ReqBody = b
		ex.ReqHeaders = append(ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
	}
	if x.resBody != nil {
		b, _ := json.Marshal(x.resBody)
		ex.RespBody = b
	}
	out, err := h.Sanit.Sanitize(ex, x.at, sanitizer.ByRandom)
	if err != nil {
		h.T.Fatalf("sanitize: %v", err)
	}
	h.seq++
	meta := sanitizer.EventMeta{
		PolicyID: h.Policy.PolicyID, PolicyVersion: h.Policy.Version, PolicyHash: h.hash,
		SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: h.source,
		TS: x.at, LatencyMS: x.latency, Status: x.status, TraceID: x.trace,
		SpanID: fmt.Sprintf("%016x", h.seq),
	}
	raw, err := sanitizer.BuildEvent(meta, out)
	if err != nil {
		h.T.Fatalf("build event: %v", err)
	}
	rej, err := h.Intake.IngestEvent(context.Background(), h.source, raw)
	if err != nil {
		h.T.Fatalf("ingest: %v", err)
	}
	if rej.Reason != intake.ReasonNone {
		h.Rejects++
		h.T.Errorf("intake rejected an event: %v", rej.Reason)
	}
}

func (h *Harness) lognormal(median, sigma float64) int64 {
	v := median * math.Exp(sigma*h.rng.NormFloat64())
	if v > 2000 {
		v = 2000
	}
	if v < 1 {
		v = 1
	}
	return int64(v)
}

func (h *Harness) chance(p float64) bool { return h.rng.Float64() < p }

func jwtFor(sub string) string {
	e := base64.RawURLEncoding
	return e.EncodeToString([]byte(`{"alg":"none"}`)) + "." + e.EncodeToString([]byte(`{"sub":"`+sub+`"}`)) + "."
}

var (
	skus     = []string{"SKU-A100", "SKU-B200", "SKU-C300", "SKU-D400", "SKU-E500", "SKU-F600", "SKU-G700", "SKU-H800"}
	cities   = []string{"Milano", "Torino", "Roma", "Napoli"}
	statuses = []string{"CREATED", "IN_TRANSIT", "DELIVERED"}
)

// DemoDay generates orders-driven traffic for one simulated day starting at
// day: orders orders by 120 customers, each followed by the carrier call and
// two shipment checks, plus customer order-list visits. Everything is
// derived from the harness random stream (fixed seed).
func (h *Harness) DemoDay(day time.Time, orders int, v Variant) {
	h.T.Helper()
	if v.CarrierError503 == 0 {
		v.CarrierError503 = 0.01
	}
	step := 80 * time.Second
	if d := 20 * time.Hour / time.Duration(orders+1); d < step {
		step = d
	}
	at := day.Add(2 * time.Hour)
	tick := func() time.Time { at = at.Add(step / 6); return at }
	for i := 0; i < orders; i++ {
		cust := fmt.Sprintf("CUS-%04d", h.rng.IntN(120))
		auth := jwtFor(cust)
		trace := fmt.Sprintf("%032x", uint64(day.Unix())<<20|uint64(i)+1)
		orderID := fmt.Sprintf("ORD-%08d", int(day.Unix()/86400)*100000+i)
		shipID := fmt.Sprintf("SHP-%08d", int(day.Unix()/86400)*100000+i)
		hasPhone, hasLine2 := h.chance(0.6), h.chance(0.25)

		items := []map[string]any{}
		for k := 0; k < 1+h.rng.IntN(4); k++ {
			items = append(items, map[string]any{"sku": skus[h.rng.IntN(len(skus))], "qty": 1 + h.rng.IntN(3), "unitPrice": 9.9})
		}
		addr := map[string]any{"fullName": "Giulia Neri", "line1": "Via Roma 1", "city": cities[h.rng.IntN(len(cities))], "postcode": "20100", "country": "IT"}
		if hasLine2 {
			addr["line2"] = "Interno 4"
		}
		req := map[string]any{"items": items, "email": fmt.Sprintf("giulia.neri.%d@example.com", i), "shippingAddress": addr}
		if hasPhone {
			req["phone"] = "+39 555 0100"
		}
		note, coupon, gift := h.chance(0.30), h.chance(0.15), h.chance(0.10)
		if note {
			req["note"] = "Citofonare Neri, interno 4"
		}
		if coupon {
			req["couponCode"] = "WELCOME10"
		}
		if gift {
			req["giftWrap"] = true
		}

		switch r := h.rng.Float64(); {
		case r < 0.03: // 400
			codes := []string{"VALIDATION_ERROR", "UNKNOWN_SKU", "INVALID_COUPON", "VALIDATION_ERROR"}
			e := map[string]any{"code": codes[h.rng.IntN(4)], "message": "Richiesta non valida"}
			if e["code"] == "VALIDATION_ERROR" {
				e["field"] = "email"
			}
			h.emit(exchange{dir: sanitizer.Inbound, method: "POST", path: "/orders", reqAuth: auth, reqBody: req, status: 400,
				resBody: map[string]any{"error": e}, latency: h.lognormal(30, 0.4), trace: trace, at: tick()})
			continue
		case r < 0.04: // 409
			h.emit(exchange{dir: sanitizer.Inbound, method: "POST", path: "/orders", reqAuth: auth, reqBody: req, status: 409,
				resBody: map[string]any{"error": map[string]any{"code": "IDEMPOTENCY_KEY_REUSED", "message": "Chiave già usata"}},
				latency: h.lognormal(30, 0.4), trace: trace, at: tick()})
			continue
		}

		// Carrier call (retried on 503 up to 3 times).
		created := tick()
		for attempt := 0; attempt < 3; attempt++ {
			creq := map[string]any{"orderId": orderID, "service": map[bool]string{true: "EXPRESS", false: "STANDARD"}[len(items) == 4],
				"parcels": 1, "recipient": map[string]any{"fullName": "Giulia Neri", "email": req["email"]}, "address": addr}
			if h.chance(v.CarrierError503) {
				h.emit(exchange{dir: sanitizer.Outbound, method: "POST", path: "/v1/shipments", reqBody: creq, status: 503,
					resBody: map[string]any{"error": map[string]any{"code": "CARRIER_UNAVAILABLE", "message": "Servizio non disponibile"}},
					latency: h.lognormal(140, 0.5), trace: trace, at: tick()})
				continue
			}
			h.emit(exchange{dir: sanitizer.Outbound, method: "POST", path: "/v1/shipments", reqBody: creq, status: 202,
				resBody: map[string]any{"shipmentId": shipID, "orderId": orderID, "status": "PENDING", "service": creq["service"], "createdAt": created.Format(time.RFC3339)},
				latency: h.lognormal(140, 0.5), trace: trace, at: tick()})
			break
		}

		total := 10 + h.rng.Float64()*290
		resp := map[string]any{"id": orderID, "customerId": cust, "status": "CONFIRMED", "items": items, "currency": "EUR",
			"subtotal": total, "total": total, "email": req["email"], "shippingAddress": addr, "shipmentId": shipID, "createdAt": created.Format(time.RFC3339)}
		if hasPhone {
			resp["phone"] = req["phone"]
		}
		if note {
			resp["note"] = req["note"]
		}
		if coupon {
			resp["couponCode"], resp["discount"] = "WELCOME10", 5.5
		}
		if gift {
			resp["giftWrap"] = true
		}
		h.emit(exchange{dir: sanitizer.Inbound, method: "POST", path: "/orders", reqAuth: auth, reqBody: req, status: 201,
			resBody: resp, latency: h.lognormal(180, 0.5), trace: trace, at: created})

		// Two shipment checks.
		fate := h.rng.Float64()
		hasEta := h.chance(0.37)
		for c := 0; c < 2; c++ {
			state := ""
			switch {
			case fate < 0.03: // never shipped: stays PENDING, invisible
			case fate < 0.07:
				state = map[bool]string{true: "CANCELLED", false: "CREATED"}[c == 1]
			default:
				state = statuses[h.rng.IntN(3)]
			}
			tr := fmt.Sprintf("%032x", uint64(day.Unix())<<20|uint64(orders+i*2+c+1))
			h.shipmentCheck(v, auth, orderID, shipID, state, hasEta, tr, tick())
		}
		if i%10 == 0 {
			h.customerVisit(cust, auth, tick())
		}
	}
}

func (h *Harness) shipmentCheck(v Variant, auth, orderID, shipID, state string, hasEta bool, trace string, at time.Time) {
	// Outbound GET to the carrier.
	var cbody any
	cst := 200
	switch {
	case h.chance(v.CarrierError503):
		cst, cbody = 503, map[string]any{"error": map[string]any{"code": "CARRIER_UNAVAILABLE", "message": "Servizio non disponibile"}}
	case v.CarrierBadGateway > 0 && h.chance(v.CarrierBadGateway):
		cst, cbody = 502, map[string]any{"error": map[string]any{"code": "BAD_GATEWAY", "message": "Gateway"}}
	case state == "":
		cbody = map[string]any{"items": []any{}}
	default:
		it := map[string]any{"shipmentId": shipID, "orderId": orderID, "status": state, "service": "STANDARD", "updatedAt": at.Format(time.RFC3339)}
		if hasEta {
			if v.EtaEpoch {
				it["eta"] = at.Add(48 * time.Hour).Unix()
			} else {
				it["eta"] = at.Add(48 * time.Hour).Format(time.RFC3339)
			}
		}
		if state == "CANCELLED" {
			it["cancelReason"] = []string{"ADDRESS_UNREACHABLE", "DAMAGED_IN_WAREHOUSE"}[h.rng.IntN(2)]
		}
		cbody = map[string]any{"items": []any{it}}
	}
	h.emit(exchange{dir: sanitizer.Outbound, method: "GET", path: "/v1/shipments", query: "orderId=" + orderID, status: cst, resBody: cbody,
		latency: h.lognormal(80, 0.6), trace: trace, at: at})

	// Shop answer.
	st, body := 200, any(nil)
	switch {
	case cst >= 500:
		st, body = 503, map[string]any{"error": map[string]any{"code": "TRACKING_UNAVAILABLE", "message": "Tracciamento non disponibile", "retryable": true}}
	case state == "":
		st, body = 404, map[string]any{"error": map[string]any{"code": "SHIPMENT_NOT_FOUND", "message": "Spedizione non trovata"}}
	default:
		b := map[string]any{"orderId": orderID, "shipmentId": shipID, "status": state, "updatedAt": at.Format(time.RFC3339)}
		if hasEta {
			b["eta"] = at.Add(48 * time.Hour).Format(time.RFC3339)
		}
		if state == "CANCELLED" {
			b["cancelReason"] = "ADDRESS_UNREACHABLE"
		}
		body = b
	}
	h.emit(exchange{dir: sanitizer.Inbound, method: "GET", path: "/orders/" + orderID + "/shipment", reqAuth: auth, status: st, resBody: body,
		latency: h.lognormal(120, 0.5), trace: trace, at: at.Add(-time.Millisecond * 50)})
}

func (h *Harness) customerVisit(cust, auth string, at time.Time) {
	trace := fmt.Sprintf("%032x", h.rng.Uint64()|1<<63)
	switch r := h.rng.Float64(); {
	case r < 0.0105:
		h.emit(exchange{dir: sanitizer.Inbound, method: "GET", path: "/customers/" + cust + "/orders", status: 401,
			resBody: map[string]any{"error": map[string]any{"code": "UNAUTHENTICATED", "message": "Accesso richiesto"}}, latency: 10, trace: trace, at: at})
	case r < 0.0315:
		h.emit(exchange{dir: sanitizer.Inbound, method: "GET", path: "/customers/" + cust + "/orders", reqAuth: auth, status: 403,
			resBody: map[string]any{"error": map[string]any{"code": "FORBIDDEN", "message": "Non consentito"}}, latency: 10, trace: trace, at: at})
	default:
		h.emit(exchange{dir: sanitizer.Inbound, method: "GET", path: "/customers/" + cust + "/orders", reqAuth: auth, status: 200,
			resBody: map[string]any{"customerId": cust, "count": 1, "items": []any{map[string]any{"id": "ORD-1", "status": "CONFIRMED", "total": 19.9, "currency": "EUR"}}},
			latency: 40, trace: trace, at: at})
	}
}
