package miner

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// The traffic shape of usability test 3 (test/fixtures/loans-app): a
// FastAPI "library loans" service (POST /loans, GET /loans/{id}, GET
// /members/{id}/loans, JWT sub as the user) that calls a catalog
// (POST /v1/reservations: 5 % 409, 1 % 503) and a notifications API
// (POST /v1/messages → 202 queued; GET /v1/messages/{id} → delivered 90 %,
// bounced 10 %, three seconds later). Members exist before the traffic and
// are never created by the API; the policy is the assistant's proposal,
// which names the domain of notificationId "notification" and the id of the
// notifications API "message". The miner proposed nothing for it in an hour
// of traffic: the member entity "created" by POST /loans, the lost link
// between the loan and its message, and causes younger than the fixed one-hour
// horizon never decided.

const loansPolicy = `{
 "format":"tt.policy/v1","policy_id":"p-library-loans","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "sampling":{"rate":0.15},
 "segments":{"allow":["v1"]},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}},
   "errors":{"body":{"$.error.code":"keep"}}},
 "services":{
  "library-loans-api":{"match":{"inbound":true},"ops":{
    "POST /loans":{"request":{"body":{"$.bookId":"hmac(book)"}},"response":{
      "$.id":"hmac(loan)","$.memberId":"hmac(member)","$.bookId":"hmac(book)","$.reservationId":"hmac(reservation)",
      "$.notificationId":"hmac(notification)","$.status":"keep","$.notification":"keep"}},
    "GET /loans/{id}":{"request":{"path":{"id":"hmac(loan)"}},"response":{
      "$.id":"hmac(loan)","$.memberId":"hmac(member)","$.bookId":"hmac(book)","$.reservationId":"hmac(reservation)",
      "$.notificationId":"hmac(notification)","$.status":"keep","$.notification":"keep"}},
    "GET /members/{id}/loans":{"request":{"path":{"id":"hmac(member)"}},"response":{
      "$.items[*].id":"hmac(loan)","$.items[*].memberId":"hmac(member)","$.items[*].bookId":"hmac(book)",
      "$.items[*].reservationId":"hmac(reservation)","$.items[*].notificationId":"hmac(notification)",
      "$.items[*].status":"keep","$.items[*].notification":"keep"}}}},
  "library-catalog":{"match":{"base":"http://127.0.0.1:9511"},"ops":{
    "POST /v1/reservations":{"request":{"body":{"$.bookId":"hmac(book)","$.memberId":"hmac(member)"}},"response":{
      "$.id":"hmac(reservation)","$.bookId":"hmac(book)","$.status":"keep","$.dueDays":"bucket(num, [0, 10, 100, 1000])"}}}},
  "library-notifications":{"match":{"base":"http://127.0.0.1:9512"},"ops":{
    "POST /v1/messages":{"request":{"body":{"$.channel":"keep","$.template":"keep","$.memberId":"hmac(member)"}},"response":{
      "$.id":"hmac(message)","$.status":"keep"}},
    "GET /v1/messages/{id}":{"request":{"path":{"id":"hmac(message)"}},"response":{
      "$.id":"hmac(message)","$.status":"keep","$.channel":"keep","$.reason":"keep"}}}}
 }}`

type loanMsg struct {
	id      string
	created time.Time
	final   string
}

type loanRec struct {
	id, member, book, reservation string
	msg                           *loanMsg
	notification                  string
}

type loansTruth struct {
	loans, delivered, bounced, conflicts, unavailable int
}

// runLoansSim produces the exchanges of rounds of the tester's load.py: every
// member creates three loans, reads them after one second and again after
// four and a half, then lists them.
func runLoansSim(seed uint64, members, rounds int, every time.Duration, start time.Time) ([]xch, loansTruth) {
	s := &sim{r: rand.New(rand.NewPCG(seed, 11))}
	var xs []xch
	var truth loansTruth
	own := map[string][]*loanRec{}
	in := func(t time.Time, lat int64, member, method, path string, body []byte, status int, resp []byte) xch {
		x := xch{ts: t, latency: lat, trace: s.hexID(16), span: s.hexID(8), inbound: true, hasToken: true}
		x.ex = sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: "library-loans-api", Method: method, RawPath: []byte(path),
			Status: status, RespBody: resp, RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}},
			ReqHeaders: []sanitizer.Header{{Name: "traceparent", Value: []byte("00-" + x.trace + "-" + x.span + "-01")},
				{Name: "Authorization", Value: []byte("Bearer " + jwtFor(member))}}}
		if body != nil {
			x.ex.ReqBody = body
			x.ex.ReqHeaders = append(x.ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
		}
		return x
	}
	out := func(parent xch, t time.Time, lat int64, base, method, path string, body []byte, status int, resp []byte) xch {
		x := xch{ts: t, latency: lat, trace: parent.trace, span: s.hexID(8), parent: parent.span}
		x.ex = sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: base, Method: method, RawPath: []byte(path), Status: status, RespBody: resp,
			ReqHeaders:  []sanitizer.Header{{Name: "x-api-key", Value: []byte("fake-key")}},
			RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}}}
		if body != nil {
			x.ex.ReqBody = body
			x.ex.ReqHeaders = append(x.ex.ReqHeaders, sanitizer.Header{Name: "Content-Type", Value: []byte("application/json")})
		}
		return x
	}
	const catalog, notify = "http://127.0.0.1:9511", "http://127.0.0.1:9512"
	view := func(l *loanRec) map[string]any {
		return map[string]any{"id": l.id, "memberId": l.member, "bookId": l.book, "reservationId": l.reservation,
			"notificationId": l.msg.id, "status": "active", "notification": l.notification, "createdAt": 1.7e9}
	}
	// refresh is the app's _refresh: a queued notification is asked again.
	refresh := func(parent xch, t time.Time, l *loanRec) {
		if l.notification != "queued" {
			return
		}
		st := "queued"
		if t.Sub(l.msg.created) > 3*time.Second {
			st = l.msg.final
		}
		resp := map[string]any{"id": l.msg.id, "status": st, "channel": "email"}
		if st == "bounced" {
			resp["reason"] = []string{"mailbox_full", "invalid_address"}[s.r.IntN(2)]
		}
		xs = append(xs, out(parent, t, 2, notify, "GET", "/v1/messages/"+l.msg.id, nil, 200, js(resp)))
		l.notification = st
	}
	for r := 0; r < rounds; r++ {
		for i := 1; i <= members; i++ {
			member := fmt.Sprintf("M-%05d", i)
			t := start.Add(time.Duration(r)*every + time.Duration(s.r.Int64N(int64(2*time.Second))))
			var mine []*loanRec
			for k := 0; k < 3; k++ {
				book := fmt.Sprintf("BK-%04d", 1+s.r.IntN(200))
				x := in(t, 0, member, "POST", "/loans", js(map[string]any{"bookId": book}), 201, nil)
				ct := t.Add(2 * time.Millisecond)
				req := js(map[string]any{"bookId": book, "memberId": member})
				u := s.r.Float64()
				switch {
				case u < 0.01:
					xs = append(xs, out(x, ct, 3, catalog, "POST", "/v1/reservations", req, 503,
						js(map[string]any{"error": map[string]any{"code": "unavailable", "message": "catalog down"}})))
					x.ex.Status, x.ex.RespBody, x.latency = 503, js(map[string]any{"detail": "catalog unavailable"}), 6
					truth.unavailable++
				case u < 0.06:
					xs = append(xs, out(x, ct, 3, catalog, "POST", "/v1/reservations", req, 409,
						js(map[string]any{"error": map[string]any{"code": "not_available", "message": "no copies left"}})))
					x.ex.Status, x.ex.RespBody, x.latency = 409, js(map[string]any{"detail": "book not available"}), 6
					truth.conflicts++
				default:
					l := &loanRec{id: "L-" + s.hexID(5), member: member, book: book, reservation: "RSV-" + s.hexID(5), notification: "queued"}
					xs = append(xs, out(x, ct, 3, catalog, "POST", "/v1/reservations", req, 201,
						js(map[string]any{"id": l.reservation, "bookId": book, "status": "reserved", "dueDays": 21})))
					nt := ct.Add(5 * time.Millisecond)
					l.msg = &loanMsg{id: "MSG-" + s.hexID(5), created: nt, final: "delivered"}
					if s.r.Float64() < 0.10 {
						l.msg.final = "bounced"
					}
					xs = append(xs, out(x, nt, 3, notify, "POST", "/v1/messages",
						js(map[string]any{"channel": "email", "template": "loan_confirmation", "memberId": member}), 202,
						js(map[string]any{"id": l.msg.id, "status": "queued"})))
					x.ex.RespBody, x.latency = js(view(l)), 12
					mine = append(mine, l)
					own[member] = append(own[member], l)
					truth.loans++
					if l.msg.final == "bounced" {
						truth.bounced++
					} else {
						truth.delivered++
					}
				}
				xs = append(xs, x)
				t = t.Add(time.Duration(s.r.Int64N(int64(200 * time.Millisecond))))
			}
			// Still queued one second later, final after four and a half.
			for _, wait := range []time.Duration{time.Second, 3500 * time.Millisecond} {
				t = t.Add(wait)
				for _, l := range mine {
					x := in(t, 0, member, "GET", "/loans/"+l.id, nil, 200, nil)
					refresh(x, t.Add(time.Millisecond), l)
					x.ex.RespBody, x.latency = js(view(l)), 4
					xs = append(xs, x)
					t = t.Add(5 * time.Millisecond)
				}
			}
			x := in(t, 0, member, "GET", "/members/"+member+"/loans", nil, 200, nil)
			items := []any{}
			for _, l := range own[member] {
				refresh(x, t.Add(time.Millisecond), l)
				items = append(items, view(l))
			}
			x.ex.RespBody, x.latency = js(map[string]any{"items": items}), 4
			xs = append(xs, x)
		}
	}
	sortXs(xs)
	return xs, truth
}

func sortXs(xs []xch) {
	// Stable by start time: a parent before its calls (they start later).
	sort.SliceStable(xs, func(i, j int) bool { return xs[i].ts.Before(xs[j].ts) })
}

// TestMinerLoansUsability3 is the regression test of usability test 3: the
// loans traffic, under the assistant's policy with 15 % sampling, must give
// rules within a short horizon: POST /loans reserves a book at the catalog
// and sends a notification that is later delivered or bounced, and the
// notifications API's own POST /v1/messages has the same two outcomes. The
// members, that exist before the traffic, are a reference and never block
// a rule or raise a warning.
func TestMinerLoansUsability3(t *testing.T) {
	start := time.Date(2026, 10, 24, 18, 0, 0, 0, time.UTC)
	xs, truth := runLoansSim(3, 300, 11, 30*time.Second, start)
	f := ingestExchanges(t, xs, loansPolicy, "library-loans-api", start, start.Add(10*time.Minute), t.TempDir())
	defer f.close()
	cfg := DefaultConfig()
	cfg.MinHorizon = 5 * time.Minute // the trial's -miner-horizon; the default is an hour
	res, err := Mine(context.Background(), f.store, time.Time{}, time.Time{}, f.doms, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Subjects < cfg.KMin {
		t.Fatalf("sampled %d members, the test needs at least k=%d", res.Subjects, cfg.KMin)
	}
	if err := res.Document(time.Now(), nil).Validate(); err != nil {
		t.Fatalf("mined document invalid: %v", err)
	}
	ents := map[string]Entity{}
	for _, e := range res.Entities {
		ents[e.Name] = e
	}
	for _, name := range []string{"loan", "reservation", "message"} {
		if _, ok := ents[name]; !ok {
			t.Errorf("entity %s missing: %v", name, res.Diag.Entities)
		}
	}
	for _, name := range []string{"member", "notification"} {
		if _, ok := ents[name]; ok {
			t.Errorf("%s must not be an entity created by the traffic", name)
		}
	}
	var member *EntityDiag
	for i, d := range res.Diag.Entities {
		if d.Name == "member" {
			member = &res.Diag.Entities[i]
		}
	}
	if member == nil || !member.Reference || member.Code != EntityReference || member.significant() {
		t.Errorf("member diagnostic: %+v", member)
	}
	merged := false
	for _, mg := range res.Diag.Merges {
		if mg.From == "notification" && mg.Into == "message" && strings.Contains(mg.Field, "POST /loans") && strings.Contains(mg.Source, "POST /v1/messages") {
			merged = true
		}
	}
	if !merged {
		t.Errorf("notificationId not linked to the message: %+v", res.Diag.Merges)
	}
	rel := map[string]string{}
	for _, r := range ents["loan"].Relations {
		rel[r.Field] = r.Entity
	}
	if rel["reservationId"] != "reservation" || rel["notificationId"] != "message" {
		t.Errorf("loan relations: %v", rel)
	}

	byCause := map[string]*CausalRule{}
	for _, mm := range res.Rules {
		if c := mm.Rule.Causal; c != nil {
			byCause[c.Cause.Service+" "+c.Cause.Op] = c
		}
	}
	loans := byCause["library-loans-api POST /loans"]
	if loans == nil {
		t.Fatalf("no rule for POST /loans; diagnostics: %+v", res.Diag.Rules)
	}
	created, linked, sets := map[string]bool{}, map[string]string{}, map[string]bool{}
	effOf := map[string]Effect{}
	for _, e := range loans.Effects {
		effOf[e.ID] = e
		if e.Create != nil {
			created[e.Entity] = true
		}
		for k, v := range e.Set {
			if e.Entity == "loan" {
				linked[k] = fmt.Sprint(v)
			}
			if k == "status" {
				sets[fmt.Sprint(v)] = true
			}
		}
	}
	if !created["reservation"] || !created["message"] {
		t.Errorf("POST /loans must create the reservation and the message: %v", created)
	}
	if !strings.Contains(linked["reservationId"], "reservation") || !strings.Contains(linked["notificationId"], "message") {
		t.Errorf("the loan must refer to its reservation and message: %v", linked)
	}
	if !sets["delivered"] || !sets["bounced"] {
		t.Errorf("notification outcomes: %v", sets)
	}
	checkOutcomes(t, "POST /loans", loans, effOf, float64(truth.bounced)/float64(truth.loans))
	msgs := byCause["library-notifications POST /v1/messages"]
	if msgs == nil {
		t.Fatalf("no rule for POST /v1/messages; diagnostics: %+v", res.Diag.Rules)
	}
	msgEff := map[string]Effect{}
	for _, e := range msgs.Effects {
		msgEff[e.ID] = e
	}
	checkOutcomes(t, "POST /v1/messages", msgs, msgEff, float64(truth.bounced)/float64(truth.loans))
	for _, mm := range res.Rules {
		if c := mm.Rule.Causal; c != nil && strings.Contains(c.Cause.Op, "POST /loans") {
			for name := range c.Cause.Bind {
				if name != "loan" {
					t.Errorf("POST /loans rule bound to %s: one rule per created entity, members are not created", name)
				}
			}
		}
	}
	st := &Status{State: StateOK, KMin: cfg.KMin, Entities: res.Diag.Entities, RuleDiagnostics: res.Diag.Rules, Rules: map[string]int{"draft": len(res.Rules)}}
	if w := warnings(st); len(w) != 0 {
		t.Errorf("warnings for a healthy run: %v", w)
	}
}

// checkOutcomes asserts the delivered (happy) and bounced outcomes of a rule
// and their shares against the simulated truth.
func checkOutcomes(t *testing.T, name string, c *CausalRule, effOf map[string]Effect, bounced float64) {
	t.Helper()
	p := map[string]float64{}
	final := map[string]string{}
	for _, o := range c.Outcomes {
		p[o.Name] = o.P
		for _, id := range o.Effects {
			if st, ok := effOf[id].Set["status"]; ok {
				final[o.Name] = fmt.Sprint(st)
			}
		}
	}
	if final["happy"] != "delivered" || final["bounced"] != "bounced" {
		t.Fatalf("%s outcomes: %+v", name, c.Outcomes)
	}
	if math.Abs(p["bounced"]-bounced) > 0.04 || math.Abs(p["happy"]-(1-bounced)) > 0.04 {
		t.Errorf("%s shares: %v, truth bounced %.3f", name, p, bounced)
	}
}
