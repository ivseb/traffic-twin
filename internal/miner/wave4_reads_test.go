package miner

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Rules v1.9, read side: customer attributes (C14), conditional outcomes
// (C6), aggregates (C8), list parameters (C12). Invented data only.

func header(tr *traffic, name, value string) {
	ev := tr.evs[len(tr.evs)-1].Event
	ev.Req.Headers = append(ev.Req.Headers, event.MultiEntry{Name: name, Values: []string{value}})
}

// ---- C14: customer attributes ----

// segmentTraffic: every user reads their profile twice and their offers
// once; the segment is the same in all of them. split decides the value of
// user u; flip makes it change between calls.
func segmentTraffic(users int, split func(u int) string, flip bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		seg := split(u)
		for k := 0; k < 2; k++ {
			s := seg
			if flip && k == 1 {
				s = seg + "X"
			}
			tr.add(xcall{op: "GET /me", user: user(u), resp: map[string]any{"name": "drop:l8", "segment": keep(s)}})
		}
		tr.add(xcall{op: "GET /offers", user: user(u), resp: map[string]any{"customer": map[string]any{"segment": keep(seg)}}})
	}
	return tr
}

func attrOf(res *Result, name string) *Attribute {
	for i := range res.Attributes {
		if res.Attributes[i].Name == name {
			return &res.Attributes[i]
		}
	}
	return nil
}

func TestAttributeOneValuePerUser(t *testing.T) {
	res := segmentTraffic(20, func(u int) string { return map[bool]string{true: "GOLD", false: "BASIC"}[u%4 == 0] }, false).mine(t, smallK(), MineOptions{})
	a := attrOf(res, "segment")
	if a == nil {
		t.Fatalf("no attribute: %+v", res.Attributes)
	}
	if a.Subjects != 20 || a.Values["GOLD"] != 0.25 || a.Values["BASIC"] != 0.75 {
		t.Fatalf("values: %+v", a)
	}
	if len(a.Fields) != 2 || a.Fields[0].Op != "GET /me" || a.Fields[0].At.Path != "$.segment" || a.Fields[1].Op != "GET /offers" || a.Fields[1].At.Path != "$.customer.segment" {
		t.Fatalf("fields: %+v", a.Fields)
	}
}

func TestAttributeNegative(t *testing.T) {
	cases := map[string]*traffic{
		// one value for everybody: not an attribute
		"constant": segmentTraffic(20, func(int) string { return "GOLD" }, false),
		// a value that changes between the calls of a user
		"changing": segmentTraffic(20, func(u int) string { return []string{"A", "B"}[u%2] }, true),
		// the second value is seen for fewer than k users
		"below_k": segmentTraffic(20, func(u int) string { return map[bool]string{true: "GOLD", false: "BASIC"}[u < 4] }, false),
	}
	for name, tr := range cases {
		res := tr.mine(t, smallK(), MineOptions{})
		if len(res.Attributes) != 0 {
			t.Fatalf("%s: unexpected attributes %+v", name, res.Attributes)
		}
	}
}

// ---- C6: conditional outcomes ----

// loanTraffic: a loan is created PENDING and is later APPROVED or
// REJECTED; approve(u) decides. The request carries the channel in the
// body and in a header; the user's segment is read from GET /me.
func loanTraffic(users int, channel func(u int) string, approve func(u int) bool) *traffic {
	return loanTrafficFrom(users, channel, approve, "body")
}

// loanTrafficFrom carries the channel in the body and a header ("body"),
// in a header only ("header"), or nowhere but in the segment ("customer").
func loanTrafficFrom(users int, channel func(u int) string, approve func(u int) bool, src string) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		id := tok("loan", u)
		body := func(st string) map[string]any { return map[string]any{"id": id, "status": keep(st)} }
		ch := channel(u)
		seg := map[bool]string{true: "GOLD", false: "BASIC"}[ch == "WEB"]
		tr.add(xcall{op: "GET /me", user: user(u), resp: map[string]any{"segment": keep(seg)}})
		tr.add(xcall{op: "GET /me", user: user(u), resp: map[string]any{"segment": keep(seg)}})
		req := map[string]any{"channel": keep(ch)}
		if src != "body" {
			req = map[string]any{"note": "drop:l8"}
		}
		tr.add(xcall{op: "POST /loans", status: 201, user: user(u), req: req, resp: body("PENDING")})
		if src != "customer" {
			header(tr, "x-channel", keep(ch))
		}
		tr.add(xcall{op: "GET /loans/{id}", path: "/loans/{" + id + "}", user: user(u), resp: body("PENDING")})
		tr.now = tr.now.Add(time.Hour)
		final := "REJECTED"
		if approve(u) {
			final = "APPROVED"
		}
		tr.add(xcall{op: "GET /loans/{id}", path: "/loans/{" + id + "}", user: user(u), resp: body(final)})
	}
	tr.now = tr.now.Add(72 * time.Hour)
	tr.add(xcall{op: "GET /health", resp: map[string]any{"ok": true}})
	return tr
}

func channelOf(u int) string { return []string{"WEB", "APP"}[u%2] }

func TestConditionalOutcomesByRequestCode(t *testing.T) {
	// WEB: 4 approved in 5; APP: 1 in 5.
	approve := func(u int) bool {
		if u%2 == 0 {
			return (u/2)%5 != 0
		}
		return (u/2)%5 == 0
	}
	res := loanTraffic(100, channelOf, approve).mine(t, smallK(), MineOptions{})
	c := creationRuleOf(res, "POST /loans")
	if c == nil {
		t.Fatalf("no creation rule: %+v", res.Diag.Rules)
	}
	whens := 0
	sum := 0.0
	for _, o := range c.Outcomes {
		sum += o.P
		if len(o.When) == 1 {
			whens++
			w := o.When[0]
			if (w.At == nil && w.Customer == "") || len(w.In) != 1 {
				t.Fatalf("condition: %+v", w)
			}
		}
		if c.Evidence.Counts.Outcomes[o.Name] == 0 {
			t.Fatalf("no count for %s: %+v", o.Name, c.Evidence.Counts.Outcomes)
		}
	}
	if whens != 4 || len(c.Outcomes) != 4 || sum < 0.999 || sum > 1.001 {
		t.Fatalf("outcomes: %s", mustJSON(c.Outcomes))
	}
	byName := map[string]Outcome{}
	for _, o := range c.Outcomes {
		byName[o.Name] = o
	}
	hw, ok := byName["happy-web"]
	if !ok || hw.P < 0.35 || hw.P > 0.45 {
		t.Fatalf("happy-web: %s", mustJSON(c.Outcomes))
	}
	// The document validates and the mined rule carries the condition in
	// its structure (a new draft when the condition changes).
	if err := res.Document(time.Time{}, nil).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConditionalOutcomesByHeaderAndCustomer(t *testing.T) {
	approve := func(u int) bool {
		if u%2 == 0 {
			return (u/2)%5 != 0
		}
		return (u/2)%5 == 0
	}
	for src, want := range map[string]string{"header": "req.headers:x-channel", "customer": "customer:segment"} {
		res := loanTrafficFrom(100, channelOf, approve, src).mine(t, smallK(), MineOptions{})
		c := creationRuleOf(res, "POST /loans")
		if c == nil {
			t.Fatalf("%s: no creation rule", src)
		}
		got := ""
		for _, o := range c.Outcomes {
			if len(o.When) == 1 {
				if w := o.When[0]; w.At != nil {
					got = w.At.String()
				} else {
					got = "customer:" + w.Customer
				}
			}
		}
		if got != want {
			t.Fatalf("%s: condition on %q, want %q: %s", src, got, want, mustJSON(c.Outcomes))
		}
	}
}

func TestConditionalOutcomesNegative(t *testing.T) {
	// The same distribution for both channels: no condition.
	approve := func(u int) bool { return (u/2)%5 != 0 }
	res := loanTraffic(100, channelOf, approve).mine(t, smallK(), MineOptions{})
	c := creationRuleOf(res, "POST /loans")
	if c == nil {
		t.Fatalf("no creation rule: %+v", res.Diag.Rules)
	}
	for _, o := range c.Outcomes {
		if len(o.When) > 0 {
			t.Fatalf("condition without a difference: %s", mustJSON(c.Outcomes))
		}
	}
	// Each channel seen by fewer than k users: no condition either.
	k := smallK()
	k.KMin = 30
	k.MinDistinct = 30
	approve2 := func(u int) bool { return u%2 == 0 }
	res = loanTraffic(50, channelOf, approve2).mine(t, k, MineOptions{})
	if c := creationRuleOf(res, "POST /loans"); c != nil {
		for _, o := range c.Outcomes {
			if len(o.When) > 0 {
				t.Fatalf("condition below k: %s", mustJSON(c.Outcomes))
			}
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ---- C8: aggregates ----

// noteTraffic: each user creates 1 to 4 notes (OPEN or DONE, an amount),
// lists them, then reads a summary with the totals.
func noteTraffic(users int, wrong bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		n := 1 + u%4
		var items []any
		total, open := 0, 0
		for k := 0; k < n; k++ {
			id := tok("note", u*10+k)
			st := []string{"OPEN", "DONE"}[(u+k)%2]
			amt := 10 * (k + 1)
			total += amt
			if st == "OPEN" {
				open++
			}
			note := map[string]any{"id": id, "status": keep(st), "amount": amt}
			tr.add(xcall{op: "POST /notes", status: 201, user: user(u), req: map[string]any{"status": keep(st), "amount": amt}, resp: note})
			items = append(items, note)
		}
		tr.add(xcall{op: "GET /notes", user: user(u), resp: map[string]any{"items": items, "count": n}})
		if wrong {
			n, total = u%7, u%5
		}
		tr.add(xcall{op: "GET /me/summary", user: user(u), resp: map[string]any{"notes": n, "spent": total, "open": open}})
	}
	return tr
}

func aggOf(res *Result, op, path string) *Aggregate {
	for i := range res.Aggregates {
		if g := &res.Aggregates[i]; g.Op == op && g.At.Path == path {
			return g
		}
	}
	return nil
}

func TestAggregateCountAndSum(t *testing.T) {
	res := noteTraffic(20, false).mine(t, smallK(), MineOptions{})
	g := aggOf(res, "GET /me/summary", "$.notes")
	if g == nil || g.Count == nil || g.Count.Entity != "note" || len(g.Count.Where) != 0 || g.Subjects != 20 {
		t.Fatalf("count: %s", mustJSON(res.Aggregates))
	}
	s := aggOf(res, "GET /me/summary", "$.spent")
	if s == nil || s.Sum == nil || s.Sum.Field != "amount" {
		t.Fatalf("sum: %s", mustJSON(res.Aggregates))
	}
	if aggOf(res, "GET /notes", "$.count") != nil {
		t.Fatalf("the list's own count is not an aggregate: %s", mustJSON(res.Aggregates))
	}
}

func TestAggregateNegative(t *testing.T) {
	res := noteTraffic(20, true).mine(t, smallK(), MineOptions{})
	if g := aggOf(res, "GET /me/summary", "$.notes"); g != nil {
		t.Fatalf("numbers unrelated to the notes: %+v", g)
	}
	res = noteTraffic(4, false).mine(t, smallK(), MineOptions{})
	if len(res.Aggregates) != 0 {
		t.Fatalf("below k: %s", mustJSON(res.Aggregates))
	}
}

// messageTraffic: GET /me shows a message counter that every POST
// /messages moves by one; reads without writes in between see it still.
func messageTraffic(users int, step int) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		n := u % 3
		read := func() { tr.add(xcall{op: "GET /me", user: user(u), resp: map[string]any{"messages": n}}) }
		read()
		read()
		for k := 0; k < 1+u%2; k++ {
			tr.add(xcall{op: "POST /messages", status: 201, user: user(u), req: map[string]any{"text": "drop:l32"}, resp: map[string]any{"ok": true}})
			n += step
		}
		read()
	}
	return tr
}

func TestAggregateCounterByWrites(t *testing.T) {
	res := messageTraffic(20, 1).mine(t, smallK(), MineOptions{})
	g := aggOf(res, "GET /me", "$.messages")
	if g == nil || len(g.Delta) != 1 || g.Delta[0].Op != "POST /messages" || g.Delta[0].By != 1 || g.Subjects != 20 {
		t.Fatalf("counter: %s", mustJSON(res.Aggregates))
	}
	res = messageTraffic(20, 0).mine(t, smallK(), MineOptions{})
	if g := aggOf(res, "GET /me", "$.messages"); g != nil {
		t.Fatalf("a number the writes do not move: %+v", g)
	}
}

// ---- C12: lists ----

// itemTraffic: each user creates six items, reads them three per page
// (limit, page), filtered by kind, newest last.
func itemTraffic(users int, overflow bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		var all []map[string]any
		for k := 0; k < 6; k++ {
			it := map[string]any{"id": tok("item", u*10+k), "kind": keep([]string{"BOOK", "DISC"}[k%2]),
				"createdAt": fmt.Sprintf("time:2026-10-0%dT1%d", 1+k/3, k%3)}
			tr.add(xcall{op: "POST /items", status: 201, user: user(u), req: map[string]any{"kind": it["kind"]}, resp: it})
			all = append(all, it)
		}
		page := func(lim, p int) {
			var items []any
			for k := (p - 1) * lim; k < p*lim && k < len(all); k++ {
				items = append(items, all[k])
			}
			if overflow {
				items = nil
				for _, it := range all {
					items = append(items, it)
				}
			}
			tr.add(xcall{op: "GET /items", query: map[string]string{"limit": keep(fmt.Sprint(lim)), "page": keep(fmt.Sprint(p))}, user: user(u),
				resp: map[string]any{"items": items}})
		}
		page(3, 1)
		page(3, 2)
		for _, kind := range []string{"BOOK", "DISC"} {
			var items []any
			for _, it := range all {
				if it["kind"] == keep(kind) {
					items = append(items, it)
				}
			}
			tr.add(xcall{op: "GET /items", query: map[string]string{"kind": keep(kind)}, user: user(u), resp: map[string]any{"items": items}})
		}
		// A catalog no entity reads, paged by size and page.
		for p := 1; p <= 2; p++ {
			var items []any
			for k := 0; k < 4; k++ {
				items = append(items, map[string]any{"title": keep(fmt.Sprintf("T%d", k))})
			}
			tr.add(xcall{op: "GET /catalog", query: map[string]string{"size": keep("4"), "page": keep(fmt.Sprint(p))}, user: user(u),
				resp: map[string]any{"items": items}})
		}
	}
	return tr
}

func TestListParameters(t *testing.T) {
	res := itemTraffic(10, false).mine(t, smallK(), MineOptions{})
	e := entOf(res, "item")
	if e == nil {
		t.Fatalf("no entity: %+v", res.Diag.Entities)
	}
	rb := readOf(e, "GET /items")
	if rb == nil || rb.List == nil {
		t.Fatalf("no list: %+v", e.ReadBy)
	}
	l := rb.List
	if l.Limit == nil || l.Limit.Name != "limit" || l.Page == nil || l.Page.Name != "page" || l.Offset != nil {
		t.Fatalf("paging: %s", mustJSON(l))
	}
	if l.OrderBy != "createdAt" || l.Order != "asc" {
		t.Fatalf("order: %s", mustJSON(l))
	}
	if len(l.Filters) != 1 || l.Filters[0].Param.Name != "kind" || l.Filters[0].Field != "kind" {
		t.Fatalf("filters: %s", mustJSON(l))
	}
	if len(res.Lists) != 1 || res.Lists[0].Op != "GET /catalog" || res.Lists[0].List.Limit == nil || res.Lists[0].List.Limit.Name != "size" ||
		res.Lists[0].List.Page == nil || res.Lists[0].At.Path != "$.items[*]" {
		t.Fatalf("static list: %s", mustJSON(res.Lists))
	}
}

func TestListParametersNegative(t *testing.T) {
	// The lists exceed the "limit": not a limit, and no page either.
	res := itemTraffic(10, true).mine(t, smallK(), MineOptions{})
	if e := entOf(res, "item"); e != nil {
		if rb := readOf(e, "GET /items"); rb != nil && rb.List != nil && (rb.List.Limit != nil || rb.List.Page != nil) {
			t.Fatalf("paging from lists that ignore it: %s", mustJSON(rb.List))
		}
	}
	// Below k: nothing.
	res = itemTraffic(4, false).mine(t, smallK(), MineOptions{})
	if len(res.Lists) != 0 {
		t.Fatalf("below k: %s", mustJSON(res.Lists))
	}
	if e := entOf(res, "item"); e != nil {
		if rb := readOf(e, "GET /items"); rb != nil && rb.List != nil && (rb.List.Limit != nil || rb.List.OrderBy != "" || len(rb.List.Filters) > 0) {
			t.Fatalf("below k: %s", mustJSON(rb.List))
		}
	}
}

func TestBucketRange(t *testing.T) {
	for _, c := range []struct {
		tok    string
		n      float64
		inside bool
	}{{"num:50-100", 50, true}, {"num:50-100", 100, false}, {"num:>=250", 300, true}, {"num:<0", -1, true}, {"num:<0", 0, false}, {"num:-10--5", -7, true}, {"num:7", 7, true}} {
		if numInBucket(c.n, c.tok) != c.inside {
			t.Fatalf("%s %v", c.tok, c.n)
		}
	}
	if p := chiSquareSurvival(6.635, 1); p < 0.0099 || p > 0.0101 {
		t.Fatalf("chi-square survival: %v", p)
	}
	if p := chiSquareSurvival(9.21, 2); p < 0.0099 || p > 0.0101 {
		t.Fatalf("chi-square survival df 2: %v", p)
	}
}
