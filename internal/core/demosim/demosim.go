// Package demosim is a deterministic simulation of the demo
// (demo/GROUND_TRUTH.md): the shop (shop-api, captured inbound), the carrier
// (shipping-ext, captured as the shop's outbound calls) and the invented
// customers of demo/loadgen. It produces the raw HTTP exchanges, in time
// order, that a source would capture; the caller sanitizes them with the
// policy in force and sends them to tt-core.
//
// Every value is invented (CUS-/ORD-/SHP- ids, example.com e-mails,
// invented addresses). It is used by the end-to-end acceptance test of
// tt-core and by the miner's evaluation.
package demosim

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// AuthorPolicy is the demo policy (tt.policy/v1, policy_id p-demo): it
// HMACs the identifiers and keeps the states and codes the rules need.
const AuthorPolicy = `{
 "format":"tt.policy/v1","policy_id":"p-demo","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "sampling":{"rate":1},
 "segments":{"allow":["v1"]},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}},
   "errors":{"body":{"$.error.code":"keep"}}},
 "services":{
  "shop-api":{"match":{"inbound":true},"ops":{
    "POST /orders":{"request":{"body":{"$.items[*].sku":"keep","$.items[*].qty":"keep"}},"response":{
      "$.id":"hmac(order)","$.customerId":"hmac(customer)","$.shipmentId":"hmac(shipment)","$.status":"keep",
      "$.currency":"keep","$.total":"bucket(num, [0, 50, 100, 250])","$.createdAt":"bucket(time, hour)"}},
    "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}},"response":{
      "$.id":"hmac(order)","$.customerId":"hmac(customer)","$.shipmentId":"hmac(shipment)","$.status":"keep",
      "$.currency":"keep","$.total":"bucket(num, [0, 50, 100, 250])","$.createdAt":"bucket(time, hour)"}},
    "GET /orders/{id}/shipment":{"request":{"path":{"id":"hmac(order)"}},"response":{
      "$.orderId":"hmac(order)","$.shipmentId":"hmac(shipment)","$.status":"keep","$.updatedAt":"bucket(time, hour)",
      "$.eta":"bucket(time, day)","$.cancelReason":"keep"}},
    "GET /customers/{id}/orders":{"request":{"path":{"id":"hmac(customer)"}},"response":{
      "$.customerId":"hmac(customer)","$.count":"keep","$.items[*].id":"hmac(order)","$.items[*].status":"keep",
      "$.items[*].currency":"keep","$.items[*].total":"bucket(num, [0, 50, 100, 250])","$.items[*].createdAt":"bucket(time, hour)"}}}},
  "shipping-ext":{"match":{"base":"https://api.carrier.example"},"ops":{
    "POST /v1/shipments":{"request":{"body":{"$.orderId":"hmac(order)","$.service":"keep"}},"response":{
      "$.shipmentId":"hmac(shipment)","$.orderId":"hmac(order)","$.status":"keep","$.service":"keep","$.createdAt":"bucket(time, hour)"}},
    "GET /v1/shipments":{"request":{"query":{"orderId":"hmac(order)"}},"response":{
      "$.items[*].shipmentId":"hmac(shipment)","$.items[*].orderId":"hmac(order)","$.items[*].status":"keep",
      "$.items[*].service":"keep","$.items[*].updatedAt":"bucket(time, hour)","$.items[*].eta":"bucket(time, day)",
      "$.items[*].cancelReason":"keep"}}}}
 }}`

type Config struct {
	Seed      uint64
	Customers int
	Days      int
	Start     time.Time
	NoBatch   bool // the carrier runs no nightly consolidation
}

type shipment struct {
	id, order, customer           string
	created                       time.Time // registered at the carrier (PENDING)
	tCreated, tTransit, tDelivery time.Time
	tCancel                       time.Time
	outcome                       string // happy, cancelled, never
	reason                        string
	service                       string
	eta                           string
	byBatch                       bool
}

func (s *shipment) state(t time.Time) (string, time.Time) {
	switch {
	case s.outcome == "never" || t.Before(s.tCreated):
		return "PENDING", s.created
	case s.outcome == "cancelled":
		if t.Before(s.tCancel) {
			return "CREATED", s.tCreated
		}
		return "CANCELLED", s.tCancel
	case t.Before(s.tTransit):
		return "CREATED", s.tCreated
	case t.Before(s.tDelivery):
		return "IN_TRANSIT", s.tTransit
	}
	return "DELIVERED", s.tDelivery
}

type order struct {
	id, customer string
	at           time.Time
	total        float64
	ship         *shipment
}

type customer struct {
	id, token, profile string
	orders             []*order
}

// BatchRun is one run of the carrier's nightly consolidation.
type BatchRun struct {
	at       time.Time
	eligible int
	moved    int
}

// Truth holds the exact counts produced (like GET /__truth).
type Truth struct {
	Orders, Shipments int
	Outcomes          map[string]int
	Runs              []BatchRun
	Events            int
	End               time.Time
	shipments         []*shipment
}

// Exchange is one HTTP exchange before sanitizing, with its capture
// metadata.
type Exchange struct {
	Ex       sanitizer.Exchange
	TS       time.Time
	Latency  int64
	Trace    string
	Span     string
	Parent   string
	Inbound  bool
	HasToken bool
}

// SampledBy is the sampling reason a source reports for the exchange.
func (x *Exchange) SampledBy() sanitizer.SampledBy {
	switch {
	case !x.Inbound:
		return sanitizer.ByInherited
	case x.HasToken:
		return sanitizer.BySubject
	}
	return sanitizer.ByRandom
}

// Sim is a finished simulation.
type Sim struct {
	cfg   Config
	r     *rand.Rand
	end   time.Time
	xs    []Exchange
	truth Truth
	ships []*shipment
	n     int
}

func (s *Sim) uniform(lo, hi time.Duration) time.Duration {
	return lo + time.Duration(s.r.Int64N(int64(hi-lo)+1))
}

func (s *Sim) hexID(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(s.r.UintN(256))
	}
	return hex.EncodeToString(b)
}

func jwtFor(sub string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString([]byte(`{"sub":"`+sub+`"}`)) + "."
}

func js(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (s *Sim) inbound(t time.Time, lat int64, c *customer, method, path string, body []byte, status int, resp []byte) Exchange {
	x := Exchange{TS: t, Latency: lat, Trace: s.hexID(16), Span: s.hexID(8), Inbound: true}
	x.Ex = sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: method, RawPath: []byte(path),
		Status: status, RespBody: resp,
		RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json; charset=utf-8")}}}
	x.Ex.ReqHeaders = []sanitizer.Header{{Name: "traceparent", Value: []byte("00-" + x.Trace + "-" + x.Span + "-01")}}
	if c != nil {
		x.Ex.ReqHeaders = append(x.Ex.ReqHeaders, sanitizer.Header{Name: "Authorization", Value: []byte("Bearer " + c.token)})
		x.HasToken = true
	}
	if body != nil {
		x.Ex.ReqBody = body
		x.Ex.ReqHeaders = append(x.Ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
	}
	return x
}

func (s *Sim) outbound(parent Exchange, t time.Time, lat int64, method, path, query string, body []byte, status int, resp []byte) Exchange {
	x := Exchange{TS: t, Latency: lat, Trace: parent.Trace, Span: s.hexID(8), Parent: parent.Span}
	x.Ex = sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://api.carrier.example", Method: method,
		RawPath: []byte(path), Status: status, RespBody: resp,
		ReqHeaders:  []sanitizer.Header{{Name: "X-Api-Key", Value: []byte("ck_test_0000")}},
		RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}}}
	if query != "" {
		x.Ex.RawQuery = []byte(query)
	}
	if body != nil {
		x.Ex.ReqBody = body
		x.Ex.ReqHeaders = append(x.Ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
	}
	return x
}

func errBody(code string) []byte {
	return js(map[string]any{"error": map[string]any{"code": code, "message": "invented message"}})
}

func orderView(o *order) map[string]any {
	return map[string]any{"id": o.id, "customerId": o.customer, "status": "CONFIRMED", "currency": "EUR",
		"total": o.total, "email": "mario.rossi.1@example.com", "shipmentId": o.ship.id, "createdAt": ts(o.at),
		"items":           []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 1, "unitPrice": o.total}},
		"shippingAddress": map[string]any{"fullName": "Mario Rossi", "line1": "Via Inventata 1", "city": "Roma", "postcode": "00100", "country": "IT"}}
}

func shipView(sh *shipment, t time.Time) (map[string]any, bool) {
	st, upd := sh.state(t)
	if st == "PENDING" {
		return nil, false
	}
	v := map[string]any{"shipmentId": sh.id, "orderId": sh.order, "status": st, "service": sh.service, "updatedAt": ts(upd)}
	if sh.eta != "" {
		v["eta"] = sh.eta
	}
	if st == "CANCELLED" {
		v["cancelReason"] = sh.reason
	}
	return v, true
}

// Run produces all exchanges, sorted by time.
func Run(cfg Config) *Sim {
	s := &Sim{cfg: cfg, r: rand.New(rand.NewPCG(cfg.Seed, 7)), end: cfg.Start.Add(time.Duration(cfg.Days) * 24 * time.Hour)}
	s.truth.Outcomes = map[string]int{}
	s.truth.End = s.end
	type profile struct {
		name               string
		w                  float64
		orderEvery, browse time.Duration
	}
	profiles := []profile{{"frequent_buyer", 0.15, 24 * time.Hour, 12 * time.Hour},
		{"occasional_buyer", 0.45, 6 * 24 * time.Hour, 48 * time.Hour}, {"browser_only", 0.40, 0, 12 * time.Hour}}
	expo := func(mean time.Duration) time.Duration {
		if mean == 0 {
			return time.Duration(math.MaxInt64 / 4)
		}
		return time.Duration(s.r.ExpFloat64() * float64(mean))
	}
	var customers []*customer
	type act struct {
		t     time.Time
		c     *customer
		order bool
	}
	var acts []act
	for i := 1; i <= cfg.Customers; i++ {
		u := s.r.Float64()
		p := profiles[len(profiles)-1]
		for _, pr := range profiles {
			if u < pr.w {
				p = pr
				break
			}
			u -= pr.w
		}
		id := fmt.Sprintf("CUS-%06d", i)
		c := &customer{id: id, token: jwtFor(id), profile: p.name}
		customers = append(customers, c)
		t := cfg.Start
		nextO, nextB := t.Add(expo(p.orderEvery)), t.Add(expo(p.browse))
		for {
			if nextO.Before(nextB) {
				if !nextO.Before(s.end) {
					break
				}
				acts = append(acts, act{nextO, c, true})
				nextO = nextO.Add(expo(p.orderEvery))
			} else {
				if !nextB.Before(s.end) {
					break
				}
				acts = append(acts, act{nextB, c, false})
				nextB = nextB.Add(expo(p.browse))
			}
		}
	}
	sort.SliceStable(acts, func(i, j int) bool { return acts[i].t.Before(acts[j].t) })

	// Orders first (the carrier's batch needs every shipment).
	type pendingTrack struct {
		o *order
		c *customer
	}
	var tracks []pendingTrack
	var browses []act
	orderN := 0
	for _, a := range acts {
		if !a.order {
			browses = append(browses, a)
			continue
		}
		c, t := a.c, a.t
		u := s.r.Float64()
		body := js(map[string]any{"items": []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 1 + s.r.IntN(3)}},
			"email": "mario.rossi.1@example.com", "shippingAddress": map[string]any{"fullName": "Mario Rossi", "line1": "Via Inventata 1",
				"city": "Roma", "postcode": "00100", "country": "IT"}})
		if u < 0.03 {
			s.xs = append(s.xs, s.inbound(t, 20, c, "POST", "/orders", body, 400, errBody("VALIDATION_ERROR")))
			continue
		}
		if len(c.orders) > 0 && s.r.Float64() < 0.02 {
			s.xs = append(s.xs, s.inbound(t, 20, c, "POST", "/orders", body, 409, errBody("IDEMPOTENCY_KEY_REUSED")))
			continue
		}
		orderN++
		o := &order{id: fmt.Sprintf("ORD-2026-%06d", orderN), customer: c.id, at: t, total: float64(10 + s.r.IntN(200))}
		in := s.inbound(t, 0, c, "POST", "/orders", body, 201, nil)
		at := t.Add(5 * time.Millisecond)
		var sh *shipment
		for attempt := 0; attempt < 3 && sh == nil; attempt++ {
			req := js(map[string]any{"orderId": o.id, "service": "STANDARD", "parcels": 1,
				"recipient": map[string]any{"fullName": "Mario Rossi", "email": "mario.rossi.1@example.com"}})
			if s.r.Float64() < 0.01 {
				s.xs = append(s.xs, s.outbound(in, at, 30, "POST", "/v1/shipments", "", req, 503, errBody("CARRIER_UNAVAILABLE")))
				at = at.Add(80 * time.Millisecond)
				continue
			}
			sh = &shipment{id: fmt.Sprintf("SHP-%s", strings.ToUpper(s.hexID(5))), order: o.id, customer: c.id,
				created: at.Add(140 * time.Millisecond), service: "STANDARD"}
			resp := js(map[string]any{"shipmentId": sh.id, "orderId": o.id, "status": "PENDING", "service": sh.service, "createdAt": ts(sh.created)})
			s.xs = append(s.xs, s.outbound(in, at, 140, "POST", "/v1/shipments", "", req, 202, resp))
			at = at.Add(140 * time.Millisecond)
		}
		if sh == nil {
			in.Ex.Status, in.Ex.RespBody = 503, errBody("CARRIER_UNAVAILABLE")
			in.Latency = at.Sub(t).Milliseconds() + 10
			s.xs = append(s.xs, in)
			orderN--
			continue
		}
		// Fate, from the carrier's truth.json defaults.
		u = s.r.Float64()
		sh.tCreated = sh.created.Add(s.uniform(2*time.Minute, 10*time.Minute))
		switch {
		case u < 0.93:
			sh.outcome = "happy"
			sh.tTransit = sh.tCreated.Add(s.uniform(time.Hour, 6*time.Hour))
			sh.tDelivery = sh.tTransit.Add(s.uniform(6*time.Hour, 36*time.Hour))
		case u < 0.97:
			sh.outcome = "cancelled"
			sh.tCancel = sh.tCreated.Add(s.uniform(30*time.Minute, 4*time.Hour))
			sh.reason = []string{"ADDRESS_UNREACHABLE", "DAMAGED_IN_WAREHOUSE"}[s.r.IntN(2)]
		default:
			sh.outcome = "never"
		}
		if s.r.Float64() < 0.37 {
			sh.eta = ts(sh.created.Add(72 * time.Hour))
		}
		o.ship = sh
		in.Ex.RespBody = js(orderView(o))
		in.Latency = at.Sub(t).Milliseconds() + 10
		s.xs = append(s.xs, in)
		c.orders = append(c.orders, o)
		s.ships = append(s.ships, sh)
		s.truth.Orders++
		s.truth.Shipments++
		s.truth.Outcomes[sh.outcome]++
		tracks = append(tracks, pendingTrack{o, c})
	}
	// Nightly batch at 02:00: 60% of the shipments IN_TRANSIT at that instant.
	for d := cfg.Start.Truncate(24 * time.Hour); d.Before(s.end); d = d.Add(24 * time.Hour) {
		T := d.Add(2 * time.Hour)
		if cfg.NoBatch || !T.Before(s.end) || T.Before(cfg.Start) {
			continue
		}
		var el []*shipment
		for _, sh := range s.ships {
			if sh.outcome == "happy" && !sh.tTransit.After(T) && sh.tDelivery.After(T) {
				el = append(el, sh)
			}
		}
		br := rand.New(rand.NewPCG(cfg.Seed, uint64(T.Unix())))
		br.Shuffle(len(el), func(i, j int) { el[i], el[j] = el[j], el[i] })
		n := int(math.Round(0.6 * float64(len(el))))
		for _, sh := range el[:n] {
			sh.tDelivery, sh.byBatch = T, true
		}
		s.truth.Runs = append(s.truth.Runs, BatchRun{at: T, eligible: len(el), moved: n})
	}
	// Customers following their shipments.
	for _, tr := range tracks {
		o, c := tr.o, tr.c
		t := o.at.Add(s.uniform(time.Minute, 20*time.Minute))
		for t.Before(s.end) {
			if s.r.Float64() < 0.30 {
				s.xs = append(s.xs, s.inbound(t, 15, c, "GET", "/orders/"+o.id, nil, 200, js(orderView(o))))
			}
			in := s.inbound(t, 0, c, "GET", "/orders/"+o.id+"/shipment", nil, 200, nil)
			ot := t.Add(3 * time.Millisecond)
			done := false
			if s.r.Float64() < 0.01 {
				s.xs = append(s.xs, s.outbound(in, ot, 20, "GET", "/v1/shipments", "orderId="+o.id, nil, 503, errBody("CARRIER_UNAVAILABLE")))
				in.Ex.Status, in.Ex.RespBody = 503, errBody("TRACKING_UNAVAILABLE")
			} else {
				v, ok := shipView(o.ship, ot)
				items := []any{}
				if ok {
					items = append(items, v)
				}
				s.xs = append(s.xs, s.outbound(in, ot, 80, "GET", "/v1/shipments", "orderId="+o.id, nil, 200, js(map[string]any{"items": items})))
				if ok {
					sv := map[string]any{"orderId": o.id, "shipmentId": o.ship.id, "status": v["status"], "updatedAt": v["updatedAt"]}
					for _, k := range []string{"eta", "cancelReason"} {
						if x, ok := v[k]; ok {
							sv[k] = x
						}
					}
					in.Ex.RespBody = js(sv)
					st := v["status"].(string)
					done = st == "DELIVERED" || st == "CANCELLED"
				} else {
					in.Ex.Status, in.Ex.RespBody = 404, errBody("SHIPMENT_NOT_FOUND")
				}
			}
			in.Latency = 100
			s.xs = append(s.xs, in)
			if done || t.Sub(o.at) > 4*24*time.Hour {
				break
			}
			t = t.Add(s.uniform(2*time.Hour, 4*time.Hour))
		}
	}
	// "My orders" visits.
	for _, a := range browses {
		c, t := a.c, a.t
		u := s.r.Float64()
		switch {
		case u < 0.01:
			s.xs = append(s.xs, s.inbound(t, 10, nil, "GET", "/customers/"+c.id+"/orders", nil, 401, errBody("UNAUTHENTICATED")))
		case u < 0.03:
			other := fmt.Sprintf("CUS-%06d", 1+s.r.IntN(999_999))
			s.xs = append(s.xs, s.inbound(t, 10, c, "GET", "/customers/"+other+"/orders", nil, 403, errBody("FORBIDDEN")))
		case u < 0.08:
			s.xs = append(s.xs, s.inbound(t, 10, c, "GET", "/orders/ORD-"+s.hexID(5), nil, 404, errBody("ORDER_NOT_FOUND")))
		default:
			items := []any{}
			var mine []*order
			for _, o := range c.orders {
				if o.at.Before(t) {
					mine = append(mine, o)
					items = append(items, map[string]any{"id": o.id, "status": "CONFIRMED", "total": o.total, "currency": "EUR", "createdAt": ts(o.at)})
				}
			}
			s.xs = append(s.xs, s.inbound(t, 30, c, "GET", "/customers/"+c.id+"/orders", nil, 200,
				js(map[string]any{"customerId": c.id, "count": len(items), "items": items})))
			if len(mine) > 0 && s.r.Float64() < 0.4 {
				o := mine[s.r.IntN(len(mine))]
				s.xs = append(s.xs, s.inbound(t.Add(time.Second), 15, c, "GET", "/orders/"+o.id, nil, 200, js(orderView(o))))
			}
		}
	}
	sort.SliceStable(s.xs, func(i, j int) bool { return s.xs[i].TS.Before(s.xs[j].TS) })
	s.truth.Events = len(s.xs)
	s.truth.shipments = s.ships
	return s
}

// Exchanges returns the exchanges in time order.
func (s *Sim) Exchanges() []Exchange { return s.xs }

// Truth returns the exact counts produced.
func (s *Sim) Truth() Truth { return s.truth }

// End is the end of the simulated period.
func (s *Sim) End() time.Time { return s.end }
