package intake

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func seedMixed(t *testing.T) *harness {
	t.Helper()
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
	return h
}

// ScanMeta returns the same events as Scan, with the columns equal to the
// decoded body.
func TestScanMetaMatchesScan(t *testing.T) {
	h := seedMixed(t)
	s, ctx := h.in.Store(), context.Background()
	for _, q := range []Query{{}, {Dir: "inbound", ByTime: true}, {Service: "shop-api", Op: "POST /orders"}, {NetErrorOnly: true}, {Limit: 3}} {
		var full []*StoredEvent
		if err := s.Scan(ctx, q, func(se *StoredEvent) error { full = append(full, se); return nil }); err != nil {
			t.Fatal(err)
		}
		var metas []EventMeta
		if err := s.ScanMeta(ctx, q, func(m *EventMeta) error { metas = append(metas, *m); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(full) != len(metas) {
			t.Fatalf("%+v: Scan %d, ScanMeta %d", q, len(full), len(metas))
		}
		for i, se := range full {
			m, ev := metas[i], se.Event
			want := EventMeta{ID: se.ID, ReceivedAt: se.ReceivedAt, Time: ev.Time, Dir: ev.Dir, Service: ev.Service, Op: ev.Op,
				Status: ev.Status, NetError: ev.NetError, LatencyMS: ev.LatencyMS, Subject: ev.Subject, SourceID: ev.Source.ID,
				PolicyID: ev.Policy.ID, TraceID: ev.TraceID}
			if !reflect.DeepEqual(m, want) {
				t.Fatalf("%+v #%d:\n got %+v\nwant %+v", q, i, m, want)
			}
		}
	}
}

// OpSummariesOf gives, for one service, exactly the groups of OpSummaries.
func TestOpSummariesOfMatchesOpSummaries(t *testing.T) {
	h := seedMixed(t)
	s, ctx := h.in.Store(), context.Background()
	for _, win := range [][2]time.Time{{}, {testNow.Add(-time.Hour), testNow.Add(time.Hour)}, {testNow.Add(time.Hour), testNow.Add(2 * time.Hour)}} {
		all, err := s.OpSummaries(ctx, win[0], win[1])
		if err != nil {
			t.Fatal(err)
		}
		by := map[string][]OpSummary{}
		for _, o := range all {
			by[o.Service] = append(by[o.Service], o)
		}
		for _, svc := range []string{"shop-api", "billing", "nobody"} {
			got, err := s.OpSummariesOf(ctx, svc, win[0], win[1])
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, by[svc]) {
				t.Fatalf("%s %v:\n got %+v\nwant %+v", svc, win, got, by[svc])
			}
		}
	}
}

// NewestSince finds the start of the newest n events of a window.
func TestNewestSince(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 10; i++ {
		h.ingest(t, mutate(t, orderGet(h.pol.Hash), func(e eventT) {
			at := testNow.Add(time.Duration(i) * time.Minute)
			e.Time, e.TS = at, at.Format("2006-01-02T15:04:05.000Z")
			e.SpanID = fmt.Sprintf("%016x", i+1)
		}))
	}
	h.idle(t)
	s, ctx := h.in.Store(), context.Background()
	from, to := testNow.Add(-time.Hour), testNow.Add(time.Hour)
	if n, err := s.CountWindow(ctx, from, to, ""); err != nil || n != 10 {
		t.Fatalf("count: %d %v", n, err)
	}
	if n, err := s.CountWindow(ctx, from, to, "nobody"); err != nil || n != 0 {
		t.Fatalf("count of another service: %d %v", n, err)
	}
	if _, over, err := s.NewestSince(ctx, from, to, 10); err != nil || over {
		t.Fatalf("10 events, limit 10: over %v %v", over, err)
	}
	cut, over, err := s.NewestSince(ctx, from, to, 4)
	if err != nil || !over {
		t.Fatalf("limit 4: over %v %v", over, err)
	}
	n := 0
	_ = s.ScanMeta(ctx, Query{From: cut, To: to}, func(*EventMeta) error { n++; return nil })
	if n != 4 {
		t.Fatalf("events from the cut: %d, want 4 (cut %v)", n, cut)
	}
}

// The token partitions are deleted in chunks, whatever their size.
func TestPurgeTokenHourChunks(t *testing.T) {
	h := newHarness(t)
	s, ctx := h.in.Store(), context.Background()
	const hour = 500000
	n := tokenChunk*2 + 77
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		tok := "tk1:k1:" + string(rune('A'+i%26)) + "aaaaaaaaaaaaaaaaaaaaa"
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_tokens (hour, token, event_id, field, ts_ms) VALUES (?, ?, ?, 0, 0)`, hour, tok, i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := s.purgeTokenHour(ctx, hour)
	if err != nil || got != int64(n) {
		t.Fatalf("deleted %d (%v), want %d", got, err, n)
	}
	var left int
	_ = h.db.QueryRowContext(ctx, `SELECT count(*) FROM intake_tokens WHERE hour = ?`, hour).Scan(&left)
	if left != 0 {
		t.Fatalf("%d rows left", left)
	}
}

// SampleEvery keeps about one event in k, spread over the group.
func TestScanSampleEvery(t *testing.T) {
	h := newHarness(t)
	const n = 600
	for i := 0; i < n; i++ {
		h.ingest(t, mutate(t, orderGet(h.pol.Hash), func(e eventT) { e.SpanID = fmt.Sprintf("%016x", i+1) }))
	}
	h.idle(t)
	s, ctx := h.in.Store(), context.Background()
	got := 0
	if err := s.Scan(ctx, Query{Service: "shop-api", SampleEvery: 10}, func(*StoredEvent) error { got++; return nil }); err != nil {
		t.Fatal(err)
	}
	if got < n/10/2 || got > n/10*2 {
		t.Fatalf("sampled %d of %d with k=10", got, n)
	}
	all := 0
	_ = s.Scan(ctx, Query{Service: "shop-api", SampleEvery: 1}, func(*StoredEvent) error { all++; return nil })
	if all != n {
		t.Fatalf("k=1 keeps everything: %d", all)
	}
	some := 0
	_ = s.Scan(ctx, Query{Service: "shop-api", Op: "GET /orders/{id}", Limit: 7, AnyOrder: true}, func(*StoredEvent) error { some++; return nil })
	if some != 7 {
		t.Fatalf("AnyOrder with Limit 7: %d", some)
	}
}
