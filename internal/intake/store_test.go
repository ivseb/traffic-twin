package intake

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRetentionPurge(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		h.ingest(t, orderPost(hash))
	}
	h.idle(t)
	h.clock.Advance(20 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		h.ingest(t, orderGet(hash))
	}
	h.idle(t)
	if n := h.count(t); n != 15 {
		t.Fatalf("stored %d", n)
	}
	// Nothing is old enough yet.
	if res, err := h.in.Purge(ctx); err != nil || res.Events != 0 {
		t.Fatalf("early purge: %+v %v", res, err)
	}
	h.clock.Advance(15 * 24 * time.Hour) // the first batch is now 35 days old
	res, err := h.in.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 10 || res.Tokens == 0 {
		t.Fatalf("purge result %+v", res)
	}
	if n := h.count(t); n != 5 {
		t.Fatalf("%d events left, want 5", n)
	}
	// The token index follows: only the order-get tokens remain.
	hits, err := h.in.Store().TokenHits(ctx, tokSubject, time.Time{}, time.Time{})
	if err != nil || len(hits) != 0 {
		t.Fatalf("subject token of purged events: %+v %v", hits, err)
	}
	hits, err = h.in.Store().TokenHits(ctx, tokOrder1, time.Time{}, time.Time{})
	if err != nil || len(hits) != 5 || hits[0].Field != "req.path[1]" {
		t.Fatalf("remaining token hits: %+v %v", hits, err)
	}
	// A shorter retention set at run time applies on the next run.
	h.in.SetRetention(24 * time.Hour)
	if res, err = h.in.Purge(ctx); err != nil || res.Events != 5 {
		t.Fatalf("second purge: %+v %v", res, err)
	}
	if n := h.count(t); n != 0 {
		t.Fatalf("%d events left", n)
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM intake_tokens`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d token rows left", n)
	}
}

func TestPurgeBoundaryWithGaps(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for round := 0; round < 4; round++ {
		for i := 0; i < 7; i++ {
			h.ingest(t, orderPost(hash))
		}
		h.idle(t)
		h.clock.Advance(10 * 24 * time.Hour)
	}
	// Remove a few rows in the middle (as an earlier purge or rewrite could).
	if _, err := h.db.Exec(`DELETE FROM intake_events WHERE id IN (9, 10, 11, 12)`); err != nil {
		t.Fatal(err)
	}
	// Now = day 40; retention 30d: the first round (day 0) and the second (day 10) are old?
	// day 0 and day 10 are 40 and 30 days old: cutoff is day 10, rows received before it go.
	res, err := h.in.Purge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 7-0 { // 7 rows of round 0, ids 1-7; round 1 (day 10) is exactly at the cutoff and stays
		t.Fatalf("purged %d, want 7", res.Events)
	}
}

func TestStoreQueries(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 3; i++ {
		h.ingest(t, orderPost(hash))
	}
	for i := 0; i < 2; i++ {
		h.ingest(t, orderGet(hash))
	}
	h.ingest(t, shipmentPost(hash))
	h.ingest(t, mutate(t, orderPost(hash), func(e eventT) { e.Status = 500; e.Resp.Body = nil; e.Resp.Size = "l8" }))
	h.ingest(t, mutate(t, shipmentPost(hash), func(e eventT) {
		e.Status = 0
		e.Resp = nil
		e.NetError = "timeout"
	}))
	h.idle(t)
	s := h.in.Store()
	ctx := context.Background()

	var got []*StoredEvent
	collect := func(q Query) []*StoredEvent {
		got = nil
		if err := s.Scan(ctx, q, func(se *StoredEvent) error { got = append(got, se); return nil }); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if n := len(collect(Query{Service: "shop-api", Op: "POST /orders"})); n != 4 {
		t.Fatalf("POST /orders: %d", n)
	}
	if n := len(collect(Query{Service: "shop-api", Op: "POST /orders", Status: 201})); n != 3 {
		t.Fatalf("POST /orders 201: %d", n)
	}
	if n := len(collect(Query{Service: "shop-api", Op: "POST /orders", Status: 500})); n != 1 {
		t.Fatalf("POST /orders 500: %d", n)
	}
	if n := len(collect(Query{NetErrorOnly: true})); n != 1 {
		t.Fatalf("net errors: %d", n)
	}
	if n := len(collect(Query{Dir: "outbound"})); n != 2 {
		t.Fatalf("outbound: %d", n)
	}
	if n := len(collect(Query{Subject: tokSubject})); n != 4 {
		t.Fatalf("subject: %d", n)
	}
	if n := len(collect(Query{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736"})); n != 4 {
		t.Fatalf("trace: %d", n)
	}
	if n := len(collect(Query{PolicyID: "p-shop", Limit: 2})); n != 2 {
		t.Fatalf("limit: %d", n)
	}
	if n := len(collect(Query{From: time.Date(2026, 10, 19, 10, 0, 1, 0, time.UTC)})); n != 0 {
		t.Fatalf("time window: %d", n)
	}
	if n := len(collect(Query{From: time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 19, 10, 0, 1, 0, time.UTC), ByTime: true})); n != 8 {
		t.Fatalf("time window: %d", n)
	}
	// Keyset pagination.
	first := collect(Query{Limit: 3})
	next := collect(Query{AfterID: first[2].ID, Limit: 100})
	if len(next) != 5 || next[0].ID <= first[2].ID {
		t.Fatalf("pagination: %d then %d", len(first), len(next))
	}
	// Stop.
	n := 0
	if err := s.Scan(ctx, Query{}, func(*StoredEvent) error { n++; return ErrStop }); err != nil || n != 1 {
		t.Fatalf("ErrStop: %d %v", n, err)
	}
	if err := s.Scan(ctx, Query{}, func(*StoredEvent) error { return errors.New("boom") }); err == nil {
		t.Fatal("callback error swallowed")
	}
	// Get.
	se, err := s.Get(ctx, got[0].ID)
	if err != nil || se.Event.Op == "" {
		t.Fatal(se, err)
	}

	// The unit of contract inference: (service, op, status).
	sums, err := s.OpSummaries(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	type k struct {
		svc, op string
		st      int
	}
	m := map[k]int64{}
	for _, o := range sums {
		m[k{o.Service, o.Op, o.Status}] = o.Count
	}
	want := map[k]int64{
		{"shop-api", "POST /orders", 201}:           3,
		{"shop-api", "POST /orders", 500}:           1,
		{"shop-api", "GET /orders/{id}", 200}:       2,
		{"shipping-ext", "POST /v1/shipments", 201}: 1,
		{"shipping-ext", "POST /v1/shipments", 0}:   1,
	}
	for key, c := range want {
		if m[key] != c {
			t.Fatalf("summary %v = %d, want %d (all: %v)", key, m[key], c, m)
		}
	}
	// Shipments are outbound.
	for _, o := range sums {
		if o.Service == "shipping-ext" && o.Dir != "outbound" {
			t.Fatalf("%+v", o)
		}
	}
}

func TestTokenIndex(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	h.ingest(t, orderPost(hash))    // order token in the response, subject
	h.ingest(t, orderGet(hash))     // order token in the path
	h.ingest(t, shipmentPost(hash)) // order token in the request, shipment token in the response
	h.idle(t)
	s := h.in.Store()
	ctx := context.Background()

	hits, err := s.TokenHits(ctx, tokOrder1, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, hit := range hits {
		fields[hit.Field] = true
		if hit.TS.IsZero() || hit.EventID == 0 {
			t.Fatalf("%+v", hit)
		}
	}
	if len(hits) != 3 || !fields["resp.body$.id"] || !fields["req.path[1]"] || !fields["req.body$.orderId"] {
		t.Fatalf("hits: %+v", hits)
	}
	if hits, _ := s.TokenHits(ctx, "tk1:k1:NoSuchTokenNoSuchToken", time.Time{}, time.Time{}); len(hits) != 0 {
		t.Fatalf("%+v", hits)
	}
	// Scan by time: all occurrences of a token come together.
	var order []string
	err = s.ScanTokens(ctx, time.Time{}, time.Time{}, func(tok string, hit TokenHit) error {
		order = append(order, tok)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 5 { // order x3, subject, shipment
		t.Fatalf("scan: %v", order)
	}
	for i := 1; i < len(order); i++ {
		if order[i] < order[i-1] {
			t.Fatalf("tokens are not ordered: %v", order)
		}
	}
	// Window filters.
	if hits, _ := s.TokenHits(ctx, tokOrder1, h.clock.Now().Add(time.Hour), time.Time{}); len(hits) != 0 {
		t.Fatalf("window: %+v", hits)
	}
}

func TestTokensReachKeyguardAtLeastOnce(t *testing.T) {
	h := newHarness(t, withConfig(func(c *Config) { c.OutboxInterval = 20 * time.Millisecond }))
	hash := h.pol.Hash
	h.ingest(t, orderPost(hash))
	eventually(t, "tokens at keyguard", func() bool { return h.tokens.Has("2026-10", tokOrder1) && h.tokens.Has("2026-10", tokSubject) })

	// Rejected events never feed the filter of real tokens.
	h.ingest(t, mutate(t, orderGet(hash), func(e eventT) { e.Req.Path = "/orders/{" + tokOrder2 + "}"; e.Source.ID = "src-ZZZZ" }))
	h.idle(t)
	time.Sleep(100 * time.Millisecond)
	if h.tokens.Has("2026-10", tokOrder2) {
		t.Fatal("token of a rejected event delivered")
	}

	// A failing keyguard does not lose tokens.
	h.tokens.SetFail(errors.New("keyguard down"))
	h.ingest(t, mutate(t, orderGet(hash), func(e eventT) { e.Req.Path = "/orders/{" + tokOrder2 + "}" }))
	h.idle(t)
	time.Sleep(150 * time.Millisecond)
	if h.tokens.Has("2026-10", tokOrder2) {
		t.Fatal("delivered while the sink was failing")
	}
	if err := h.in.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Restart with a working sink: the outbox is delivered.
	h.tokens.SetFail(nil)
	in, err := New(context.Background(), h.cfg, Deps{DB: h.db, Sources: h.sources, Policies: h.policies, Tokens: h.tokens, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close(context.Background())
	eventually(t, "redelivery after restart", func() bool { return h.tokens.Has("2026-10", tokOrder2) })
	var pending int
	eventually(t, "empty outbox", func() bool {
		_ = h.db.QueryRow(`SELECT count(*) FROM intake_outbox`).Scan(&pending)
		return pending == 0
	})
}

func TestSourceCountersPersist(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	h.ingest(t, orderPost(hash))
	h.ingest(t, orderPost(hash))
	h.ingest(t, strings.Replace(orderPost(hash), `"dir":"inbound"`, `"dir": "inbound"`, 1))
	h.ingest(t, mutate(t, orderPost(hash), func(e eventT) { *member(e.Req.Body, "note") = event.Str("keep:x") }))
	st := h.in.SourceStats(testSource)
	if st.Accepted != 2 || st.Rejected["non_canonical"] != 1 || st.Rejected["value_not_allowed"] != 1 || st.RejectedTotal != 2 {
		t.Fatalf("%+v", st)
	}
	if err := h.in.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	in, err := New(context.Background(), h.cfg, Deps{DB: h.db, Sources: h.sources, Policies: h.policies, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close(context.Background())
	st = in.SourceStats(testSource)
	if st.Accepted != 2 || st.Rejected["non_canonical"] != 1 || st.RejectedTotal != 2 {
		t.Fatalf("after restart: %+v", st)
	}
	all := in.AllSourceStats()
	if len(all) != 1 || all[0].SourceID != testSource {
		t.Fatalf("%+v", all)
	}
	if in.SourceStats("src-never").Accepted != 0 {
		t.Fatal("unseen source has counters")
	}
}

func TestManyEventsKeepOrderAndDedup(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 500; i++ {
		ev := strings.Replace(orderPost(hash), `"keep:CREATED"`, `"keep:OK"`, 1)
		if rej := h.ingest(t, ev); rej.Reason != ReasonNone {
			t.Fatalf("%d: %s", i, rej.Reason)
		}
	}
	if n := h.count(t); n != 500 {
		t.Fatalf("%d", n)
	}
	var last int64
	err := h.in.Store().Scan(context.Background(), Query{}, func(se *StoredEvent) error {
		if se.ID <= last {
			return fmt.Errorf("ids out of order")
		}
		last = se.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
