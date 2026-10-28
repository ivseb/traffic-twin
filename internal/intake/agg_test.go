package intake

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// aggVsScan compares the ingest aggregates with the same numbers computed
// from the stored events.
func aggVsScan(t *testing.T, h *harness) {
	t.Helper()
	h.idle(t)
	ctx := context.Background()
	q := func(sql string) map[string]int64 {
		rows, err := h.db.QueryContext(ctx, sql)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int64{}
		for rows.Next() {
			var k string
			var n int64
			if err := rows.Scan(&k, &n); err != nil {
				t.Fatal(err)
			}
			out[k] = n
		}
		return out
	}
	scan := q(`SELECT service||'|'||op||'|'||coalesce(status,0)||'|'||source_id||'|'||policy_id||'|'||dir, count(*) FROM intake_events
		GROUP BY service, op, status, source_id, policy_id, dir`)
	agg := q(`SELECT service||'|'||op||'|'||status||'|'||source_id||'|'||policy_id||'|'||dir, n FROM intake_agg`)
	if !reflect.DeepEqual(scan, agg) {
		t.Fatalf("aggregates differ from the events:\nscan %v\nagg  %v", scan, agg)
	}
	latScan := map[string]int64{}
	for k, n := range q(`SELECT service||'|'||latency_ms, count(*) FROM intake_events WHERE dir = 1 GROUP BY service, latency_ms`) {
		var svc string
		var ms int64
		for i := len(k) - 1; i >= 0; i-- {
			if k[i] == '|' {
				svc = k[:i]
				fmt.Sscan(k[i+1:], &ms)
				break
			}
		}
		latScan[fmt.Sprintf("%s|%d", svc, latBucket(ms))] += n
	}
	latAgg := q(`SELECT service||'|'||lat, n FROM intake_agg_lat`)
	if !reflect.DeepEqual(latScan, latAgg) {
		t.Fatalf("latency histogram differs:\nscan %v\nagg  %v", latScan, latAgg)
	}
}

func TestAggregatesFollowIngestAndPurge(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	if !h.in.Store().AggregatesReady(context.Background()) {
		t.Fatal("a new database has nothing to backfill")
	}
	for i := 0; i < 10; i++ {
		h.ingest(t, orderPost(hash))
		h.ingest(t, shipmentPost(hash))
	}
	aggVsScan(t, h)
	h.clock.Advance(40 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		h.ingest(t, orderGet(hash))
	}
	aggVsScan(t, h)
	if res, err := h.in.Purge(context.Background()); err != nil || res.Events != 20 {
		t.Fatalf("purge: %+v %v", res, err)
	}
	aggVsScan(t, h)
	sums, err := h.in.Store().OpSummaries(context.Background(), time.Time{}, time.Time{})
	if err != nil || len(sums) != 1 || sums[0].Count != 4 {
		t.Fatalf("summaries after the purge: %+v %v", sums, err)
	}
}

func TestAggregatesFollowQuarantineRewrite(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 80; i++ {
		w := "w" + twoLetters(i)
		h.ingest(t, mutate(t, rawPromo(hash), func(e eventT) {
			e.Op = "GET /promo/" + w
			e.Req.Path = "/promo/" + w
		}))
	}
	var q Quarantine
	for _, c := range h.in.Quarantines(false) {
		if c.Kind == QuarantineSegment {
			q = c
		}
	}
	if q.ID == 0 {
		t.Fatal("no segment quarantine")
	}
	h.waitRewrite(t, q.ID)
	aggVsScan(t, h)
}

func TestAggregatesBackfillOlderDatabase(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		h.ingest(t, orderPost(hash))
		h.ingest(t, shipmentPost(hash))
	}
	h.idle(t)
	// As a database written before the aggregates existed: nothing aggregated.
	for _, s := range []string{`DELETE FROM intake_agg`, `DELETE FROM intake_agg_lat`,
		`UPDATE intake_agg_state SET v = CASE k WHEN 'hi' THEN (SELECT max(id) FROM intake_events) ELSE (SELECT min(id) FROM intake_events) END`} {
		if _, err := h.db.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	st := NewStore(h.db)
	if st.AggregatesReady(ctx) {
		t.Fatal("ready before the backfill")
	}
	// The lists still answer, from the events.
	sums, err := st.OpSummaries(ctx, time.Time{}, time.Time{})
	if err != nil || len(sums) != 2 {
		t.Fatalf("summaries during the backfill: %+v %v", sums, err)
	}
	// New events meanwhile are aggregated at ingest; a purge of old,
	// not yet aggregated events must not subtract them.
	for i := 0; i < 5; i++ {
		h.ingest(t, orderGet(hash))
	}
	h.idle(t)
	if _, err := st.backfillStep(ctx); err != nil {
		t.Fatal(err)
	}
	if !st.AggregatesReady(ctx) {
		t.Fatal("backfill did not complete")
	}
	aggVsScan(t, h)
	got, err := st.OpSummaries(ctx, time.Time{}, time.Time{})
	if err != nil || !reflect.DeepEqual(got, sumsPlusGet(t, h)) {
		t.Fatalf("aggregated summaries %+v, want %+v (%v)", got, sumsPlusGet(t, h), err)
	}
}

// sumsPlusGet is OpSummaries by event scan.
func sumsPlusGet(t *testing.T, h *harness) []OpSummary {
	t.Helper()
	// A bounded window forces the event scan.
	out, err := h.in.Store().OpSummaries(context.Background(), time.Unix(0, 0), time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLatBucket(t *testing.T) {
	for in, want := range map[int64]int64{-3: 0, 0: 0, 99: 99, 100: 100, 123: 120, 999: 990, 1234: 1200, 98765: 98000} {
		if got := latBucket(in); got != want {
			t.Errorf("latBucket(%d) = %d, want %d", in, got, want)
		}
	}
}

// A group's live contract of one service (rule editor catalog, contracts
// preview) reads the aggregates: the same summaries as the event scan, and
// nothing for the sources of another group.
func TestSourceSummariesOfOneServiceFromAggregates(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 6; i++ {
		h.ingest(t, orderPost(hash))
		h.ingest(t, orderGet(hash))
		h.ingest(t, shipmentPost(hash))
	}
	h.idle(t)
	ctx := context.Background()
	st := h.in.Store()
	if !st.AggregatesReady(ctx) {
		t.Fatal("aggregates not ready")
	}
	got, err := st.OpSummariesOfFor(ctx, "shop-api", time.Time{}, time.Time{}, []string{testSource})
	if err != nil {
		t.Fatal(err)
	}
	// A bounded window forces the event scan.
	want, err := st.OpSummariesOfFor(ctx, "shop-api", time.Unix(0, 0), time.Now().Add(365*24*time.Hour), []string{testSource})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("aggregated %+v, scanned %+v", got, want)
	}
	other, err := st.OpSummariesOfFor(ctx, "shop-api", time.Time{}, time.Time{}, []string{"src-of-another-group"})
	if err != nil || len(other) != 0 {
		t.Fatalf("another group's sources: %+v %v", other, err)
	}
}
