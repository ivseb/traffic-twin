package miner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/store"
)

// A deterministic simulation of the demo (demo/GROUND_TRUTH.md): the shop
// (shop-api, captured inbound), the carrier (shipping-ext, captured as the
// shop's outbound calls) and the fake customers of demo/loadgen. Every
// exchange goes through the Go reference sanitizer with a test policy that
// HMACs the identifiers, then through the intake checks into the store.

const simAuthorPolicy = `{
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

type simConfig struct {
	Seed      uint64
	Customers int
	Days      int
	Start     time.Time
	NoBatch   bool // the carrier runs no nightly consolidation
	// DropCreate is the share of orders whose creation exchange is not
	// captured (app restarts, retention cutoffs, sampling): DropMode "lost"
	// removes the POST /orders event, "unlinked" keeps it but its carrier
	// calls lose the trace link.
	DropCreate float64
	DropMode   string
}

type simShipment struct {
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

func (s *simShipment) state(t time.Time) (string, time.Time) {
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

type simOrder struct {
	id, customer string
	at           time.Time
	total        float64
	ship         *simShipment
}

type simCustomer struct {
	id, token, profile string
	orders             []*simOrder
}

type simBatchRun struct {
	at       time.Time
	eligible int
	moved    int
}

// simTruth holds the exact counts produced (like GET /__truth).
type simTruth struct {
	Orders, Shipments int
	Outcomes          map[string]int
	Runs              []simBatchRun
	Events            int
	End               time.Time
	shipments         []*simShipment
}

type xch struct {
	ex       sanitizer.Exchange
	ts       time.Time
	latency  int64
	trace    string
	span     string
	parent   string
	inbound  bool
	hasToken bool
}

type sim struct {
	cfg   simConfig
	r     *rand.Rand
	end   time.Time
	xs    []xch
	truth simTruth
	ships []*simShipment
	n     int
}

func (s *sim) uniform(lo, hi time.Duration) time.Duration {
	return lo + time.Duration(s.r.Int64N(int64(hi-lo)+1))
}

func (s *sim) hexID(n int) string {
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

func (s *sim) inbound(t time.Time, lat int64, c *simCustomer, method, path string, body []byte, status int, resp []byte) xch {
	x := xch{ts: t, latency: lat, trace: s.hexID(16), span: s.hexID(8), inbound: true}
	x.ex = sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: method, RawPath: []byte(path),
		Status: status, RespBody: resp,
		RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json; charset=utf-8")}}}
	x.ex.ReqHeaders = []sanitizer.Header{{Name: "traceparent", Value: []byte("00-" + x.trace + "-" + x.span + "-01")}}
	if c != nil {
		x.ex.ReqHeaders = append(x.ex.ReqHeaders, sanitizer.Header{Name: "Authorization", Value: []byte("Bearer " + c.token)})
		x.hasToken = true
	}
	if body != nil {
		x.ex.ReqBody = body
		x.ex.ReqHeaders = append(x.ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
	}
	return x
}

func (s *sim) outbound(parent xch, t time.Time, lat int64, method, path, query string, body []byte, status int, resp []byte) xch {
	x := xch{ts: t, latency: lat, trace: parent.trace, span: s.hexID(8), parent: parent.span}
	x.ex = sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: "https://api.carrier.example", Method: method,
		RawPath: []byte(path), Status: status, RespBody: resp,
		ReqHeaders:  []sanitizer.Header{{Name: "X-Api-Key", Value: []byte("ck_test_0000")}},
		RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}}}
	if query != "" {
		x.ex.RawQuery = []byte(query)
	}
	if body != nil {
		x.ex.ReqBody = body
		x.ex.ReqHeaders = append(x.ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
	}
	return x
}

func errBody(code string) []byte {
	return js(map[string]any{"error": map[string]any{"code": code, "message": "invented message"}})
}

func orderView(o *simOrder) map[string]any {
	return map[string]any{"id": o.id, "customerId": o.customer, "status": "CONFIRMED", "currency": "EUR",
		"total": o.total, "email": "mario.rossi.1@example.com", "shipmentId": o.ship.id, "createdAt": ts(o.at),
		"items":           []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 1, "unitPrice": o.total}},
		"shippingAddress": map[string]any{"fullName": "Mario Rossi", "line1": "Via Inventata 1", "city": "Roma", "postcode": "00100", "country": "IT"}}
}

func shipView(sh *simShipment, t time.Time) (map[string]any, bool) {
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

// runSim produces all exchanges, sorted by time.
func runSim(cfg simConfig) *sim {
	s := &sim{cfg: cfg, r: rand.New(rand.NewPCG(cfg.Seed, 7)), end: cfg.Start.Add(time.Duration(cfg.Days) * 24 * time.Hour)}
	s.truth.Outcomes = map[string]int{}
	s.truth.End = s.end
	dropR := rand.New(rand.NewPCG(cfg.Seed, 99))
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
	var customers []*simCustomer
	type act struct {
		t     time.Time
		c     *simCustomer
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
		c := &simCustomer{id: id, token: jwtFor(id), profile: p.name}
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
		o *simOrder
		c *simCustomer
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
		o := &simOrder{id: fmt.Sprintf("ORD-2026-%06d", orderN), customer: c.id, at: t, total: float64(10 + s.r.IntN(200))}
		in := s.inbound(t, 0, c, "POST", "/orders", body, 201, nil)
		dropped := cfg.DropCreate > 0 && dropR.Float64() < cfg.DropCreate
		parentOf := in
		if dropped && cfg.DropMode == "unlinked" {
			parentOf = xch{trace: s.hexID(16)}
		}
		at := t.Add(5 * time.Millisecond)
		var sh *simShipment
		for attempt := 0; attempt < 3 && sh == nil; attempt++ {
			req := js(map[string]any{"orderId": o.id, "service": "STANDARD", "parcels": 1,
				"recipient": map[string]any{"fullName": "Mario Rossi", "email": "mario.rossi.1@example.com"}})
			if s.r.Float64() < 0.01 {
				s.xs = append(s.xs, s.outbound(parentOf, at, 30, "POST", "/v1/shipments", "", req, 503, errBody("CARRIER_UNAVAILABLE")))
				at = at.Add(80 * time.Millisecond)
				continue
			}
			sh = &simShipment{id: fmt.Sprintf("SHP-%s", strings.ToUpper(s.hexID(5))), order: o.id, customer: c.id,
				created: at.Add(140 * time.Millisecond), service: "STANDARD"}
			resp := js(map[string]any{"shipmentId": sh.id, "orderId": o.id, "status": "PENDING", "service": sh.service, "createdAt": ts(sh.created)})
			s.xs = append(s.xs, s.outbound(parentOf, at, 140, "POST", "/v1/shipments", "", req, 202, resp))
			at = at.Add(140 * time.Millisecond)
		}
		if sh == nil {
			in.ex.Status, in.ex.RespBody = 503, errBody("CARRIER_UNAVAILABLE")
			in.latency = at.Sub(t).Milliseconds() + 10
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
		in.ex.RespBody = js(orderView(o))
		in.latency = at.Sub(t).Milliseconds() + 10
		if !(dropped && cfg.DropMode == "lost") {
			s.xs = append(s.xs, in)
		}
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
		var el []*simShipment
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
		s.truth.Runs = append(s.truth.Runs, simBatchRun{at: T, eligible: len(el), moved: n})
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
				in.ex.Status, in.ex.RespBody = 503, errBody("TRACKING_UNAVAILABLE")
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
					in.ex.RespBody = js(sv)
					st := v["status"].(string)
					done = st == "DELIVERED" || st == "CANCELLED"
				} else {
					in.ex.Status, in.ex.RespBody = 404, errBody("SHIPMENT_NOT_FOUND")
				}
			}
			in.latency = 100
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
			var mine []*simOrder
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
	sort.SliceStable(s.xs, func(i, j int) bool { return s.xs[i].ts.Before(s.xs[j].ts) })
	s.truth.Events = len(s.xs)
	s.truth.shipments = s.ships
	return s
}

type simFixture struct {
	sim   *sim
	store *intake.Store
	doms  *PolicyDomains
	db    *store.DB
	close func()
}

// ingestSim sanitizes every exchange and stores the events through the
// intake (database in dir); it returns the store and the policy domains.
func ingestSim(t testing.TB, s *sim, dir string) *simFixture {
	t.Helper()
	f := ingestExchanges(t, s.xs, simAuthorPolicy, "shop-api", s.cfg.Start, s.end, dir)
	f.sim = s
	return f
}

// ingestExchanges sanitizes the exchanges with the policy (author JSON) and
// stores them through the intake; the policy sampling applies (an inbound
// exchange by its subject, its outbound calls by inheritance).
func ingestExchanges(t testing.TB, xs []xch, policyJSON, service string, start, end time.Time, dir string) *simFixture {
	t.Helper()
	return ingestTeams(t, []simTeam{{xs: xs, policyJSON: policyJSON, service: service, source: "src-shop1"}}, start, end, dir)
}

// simTeam is the traffic of one team: its exchanges, its policy, its
// service and the source that captures it.
type simTeam struct {
	xs         []xch
	policyJSON string
	service    string
	source     string
}

// ingestTeams is ingestExchanges for several teams sharing one console
// (one intake, one HMAC key).
func ingestTeams(t testing.TB, teams []simTeam, start, end time.Time, dir string) *simFixture {
	t.Helper()
	ctx := context.Background()
	var closers []func()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := sanitizer.NewKey("k1", secret)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(dir, "tt.db"))
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { db.Close() })
	sources := intake.NewMemSourceRegistry()
	pols := intake.NewMemPolicyRegistry()
	doms := NewPolicyDomains()
	type compiled struct {
		pol  *policy.Policy
		hash string
		eng  *sanitizer.Engine
	}
	var cs []compiled
	for _, tm := range teams {
		d := json.NewDecoder(strings.NewReader(tm.policyJSON))
		d.UseNumber()
		var doc any
		if err := d.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		author, err := policy.AuthorFromGeneric(doc)
		if err != nil {
			t.Fatal(err)
		}
		body, pol, err := policy.Compile(author, policy.CompileMeta{Version: 1, IssuedSeq: 1,
			CreatedAt: start.Add(-24 * time.Hour), NotAfter: end.Add(24 * time.Hour), Groups: []string{"prod"}})
		if err != nil {
			t.Fatal(err)
		}
		hash := policy.Hash(body)
		eng, err := sanitizer.NewEngineWithKey(pol, key)
		if err != nil {
			t.Fatal(err)
		}
		sources.Set(intake.SourceInfo{ID: tm.source, Group: "prod", ServiceName: tm.service, AllowedServices: []string{tm.service}})
		ip, err := intake.ParsePolicyWithHash(body, hash)
		if err != nil {
			t.Fatal(err)
		}
		pols.Add(ip)
		doms.Add(hash, pol)
		cs = append(cs, compiled{pol, hash, eng})
	}
	icfg := intake.DefaultConfig()
	icfg.Retention = 365 * 24 * time.Hour
	now := end.Add(time.Hour)
	in, err := intake.New(ctx, icfg, intake.Deps{DB: db, Sources: sources, Policies: pols, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	closers = append(closers, func() { _ = in.Close(context.Background()) })
	rejected := map[string]int{}
	stored := 0
	for ti, tm := range teams {
		pol, hash, eng := cs[ti].pol, cs[ti].hash, cs[ti].eng
		sampledTrace := map[string]bool{}
		for _, x := range tm.xs {
			by := sanitizer.ByInherited
			if x.inbound {
				by = sanitizer.ByRandom
				if x.hasToken {
					by = sanitizer.BySubject
				}
				if pol.Sampling.RateBP < 10000 {
					sampledTrace[x.trace] = eng.Sample(&x.ex, sanitizer.SampleOptions{RateBP: -1}).Sampled
				}
			}
			if pol.Sampling.RateBP < 10000 && !sampledTrace[x.trace] {
				continue
			}
			stored++
			out, err := eng.Sanitize(&x.ex, x.ts, by)
			if err != nil {
				t.Fatalf("sanitize: %v", err)
			}
			meta := sanitizer.EventMeta{PolicyID: pol.PolicyID, PolicyVersion: pol.Version, PolicyHash: hash,
				SourceKind: "sdk-node", SourceVersion: "0.1.0", SourceID: tm.source, TS: x.ts, LatencyMS: x.latency,
				Status: x.ex.Status, TraceID: x.trace, SpanID: x.span, ParentSpanID: x.parent}
			ev, err := sanitizer.BuildEvent(meta, out)
			if err != nil {
				t.Fatalf("build event: %v", err)
			}
			for {
				rej, err := in.IngestEvent(ctx, tm.source, ev)
				if errors.Is(err, intake.ErrOverloaded) {
					if err := in.WaitIdle(ctx); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if rej.Reason != intake.ReasonNone {
					rejected[rej.Reason.String()+": "+rej.Detail]++
				}
				break
			}
		}
	}
	if err := in.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := in.Store().Count(ctx); err != nil || int(n) != stored {
		t.Fatalf("stored %d events of %d (%v)", n, stored, err)
	}
	if len(rejected) > 0 {
		t.Fatalf("intake rejected events: %v", rejected)
	}
	return &simFixture{store: in.Store(), doms: doms, db: db, close: func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}}
}
