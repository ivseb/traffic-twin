package intake

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// rollupVsScan compares the hourly rollups with the stored events (all of
// them rolled up, none purged).
func rollupVsScan(t *testing.T, h *harness) {
	t.Helper()
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
	scan := q(`SELECT ((ts_ms/3600000)*3600)||'|'||service||'|'||op||'|'||coalesce(status,0)||'|'||dir, count(*) FROM intake_events GROUP BY 1`)
	roll := q(`SELECT bucket||'|'||service||'|'||op||'|'||status||'|'||dir, n FROM intake_rollup WHERE tier = 0`)
	if !reflect.DeepEqual(scan, roll) {
		t.Fatalf("rollup differs from the events:\nscan %v\nroll %v", scan, roll)
	}
	scanSrc := q(`SELECT ((ts_ms/3600000)*3600)||'|'||service||'|'||source_id||'|'||policy_id||'|'||dir, count(*) FROM intake_events GROUP BY 1`)
	rollSrc := q(`SELECT bucket||'|'||service||'|'||source_id||'|'||policy_id||'|'||dir, n FROM intake_rollup_src WHERE tier = 0`)
	if !reflect.DeepEqual(scanSrc, rollSrc) {
		t.Fatalf("source rollup differs:\nscan %v\nroll %v", scanSrc, rollSrc)
	}
	lat := q(`SELECT service||'|'||dir, sum(n) FROM intake_rollup_lat GROUP BY 1`)
	scanLat := q(`SELECT service||'|'||dir, count(*) FROM intake_events GROUP BY 1`)
	if !reflect.DeepEqual(lat, scanLat) {
		t.Fatalf("latency histogram counts differ:\nscan %v\nroll %v", scanLat, lat)
	}
}

func TestRollupsOutliveThePurge(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	ctx := context.Background()
	st := h.in.Store()
	for i := 0; i < 12; i++ {
		h.ingest(t, orderPost(hash))
		h.ingest(t, shipmentPost(hash))
	}
	h.idle(t)
	if r, err := st.RollupPending(ctx); err != nil || r.Events != 24 {
		t.Fatalf("rollup: %+v %v", r, err)
	}
	// Idempotent: nothing more to count.
	if r, err := st.RollupPending(ctx); err != nil || r.Events != 0 {
		t.Fatalf("second rollup: %+v %v", r, err)
	}
	rollupVsScan(t, h)
	hostsBefore, err := st.HostStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, err := st.Traffic(ctx, TrafficQuery{Step: TierDay})
	if err != nil || len(before) == 0 {
		t.Fatalf("traffic: %v %v", before, err)
	}

	// Events after the rollup run are counted by the purge itself.
	for i := 0; i < 3; i++ {
		h.ingest(t, orderGet(hash))
	}
	h.idle(t)
	h.clock.Advance(40 * 24 * time.Hour)
	res, err := h.in.Purge(ctx)
	if err != nil || res.Events != 27 || res.RolledUp != 3 {
		t.Fatalf("purge: %+v %v", res, err)
	}
	if n, _ := st.Count(ctx); n != 0 {
		t.Fatalf("%d events left", n)
	}
	var total int64
	if err := h.db.QueryRowContext(ctx, `SELECT sum(n) FROM intake_rollup`).Scan(&total); err != nil || total != 27 {
		t.Fatalf("rolled-up calls after the purge: %d %v", total, err)
	}

	// The hosts registry of the old period answers from the rollups, with
	// the numbers the events gave.
	far := time.Unix(0, 0)
	hostsAfter, err := st.HostStatsRange(ctx, far, testNow.Add(400*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hostsBefore, hostsAfter) {
		t.Fatalf("hosts from the rollups:\n%+v\nwant %+v", hostsAfter, hostsBefore)
	}

	// Compaction: hourly -> daily -> monthly, totals unchanged.
	h.clock.Advance(400 * 24 * time.Hour)
	cr, err := st.CompactRollups(ctx, h.clock.Now(), 30*24*time.Hour, 365*24*time.Hour)
	if err != nil || cr.Days == 0 || cr.Months == 0 {
		t.Fatalf("compact: %+v %v", cr, err)
	}
	var tiers []int
	rows, _ := h.db.QueryContext(ctx, `SELECT DISTINCT tier FROM intake_rollup`)
	for rows.Next() {
		var x int
		rows.Scan(&x)
		tiers = append(tiers, x)
	}
	rows.Close()
	if !reflect.DeepEqual(tiers, []int{TierMonth}) {
		t.Fatalf("tiers after compaction: %v", tiers)
	}
	after, err := st.Traffic(ctx, TrafficQuery{Step: TierDay})
	if err != nil {
		t.Fatal(err)
	}
	sum := func(ps []TrafficPoint) (n, es, ec int64) {
		for _, p := range ps {
			n, es, ec = n+p.Calls, es+p.ServerErrors, ec+p.ClientErrors
		}
		return
	}
	n, es, ec := sum(after)
	if n != 27 {
		t.Fatalf("calls after compaction %d", n)
	}
	n0, es0, ec0 := sum(before)
	if es0 > es || ec0 > ec || n0 != 24 {
		t.Fatalf("errors lost: before %d/%d/%d after %d/%d/%d", n0, es0, ec0, n, es, ec)
	}
	if after[0].Tier != "month" {
		t.Fatalf("tier of old data: %+v", after[0])
	}
	hostsMonth, err := st.HostStatsRange(ctx, far, h.clock.Now())
	if err != nil || !reflect.DeepEqual(hostsMonth, hostsBefore) {
		t.Fatalf("hosts after compaction %+v %v", hostsMonth, err)
	}
	// Idempotent.
	if cr, err := st.CompactRollups(ctx, h.clock.Now(), 30*24*time.Hour, 365*24*time.Hour); err != nil || cr.Days+cr.Months != 0 {
		t.Fatalf("second compaction: %+v %v", cr, err)
	}
}

func TestRollupsFollowQuarantineRewrite(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	ctx := context.Background()
	// Rolled up before the quarantine exists...
	for i := 0; i < 30; i++ {
		w := "w" + twoLetters(i)
		h.ingest(t, mutate(t, rawPromo(hash), func(e eventT) {
			e.Op = "GET /promo/" + w
			e.Req.Path = "/promo/" + w
		}))
	}
	h.idle(t)
	if _, err := h.in.Store().RollupPending(ctx); err != nil {
		t.Fatal(err)
	}
	// ... then enough distinct segments to quarantine them.
	for i := 30; i < 80; i++ {
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
	if _, err := h.in.Store().RollupPending(ctx); err != nil {
		t.Fatal(err)
	}
	rollupVsScan(t, h)
	var literal int
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM intake_rollup WHERE op LIKE 'GET /promo/w%'`).Scan(&literal); err != nil || literal != 0 {
		t.Fatalf("%d rollup rows keep a quarantined literal (%v)", literal, err)
	}
}

func TestRollupLatBuckets(t *testing.T) {
	prev := int64(-1)
	for _, ms := range []int64{0, 1, 2, 3, 5, 10, 100, 1000, 10_000, 600_000} {
		b := RollupLatBucket(ms)
		if b < prev {
			t.Fatalf("bucket of %d decreases", ms)
		}
		prev = b
		v := RollupLatValue(b)
		if ms >= 10 && (float64(v) < 0.85*float64(ms) || float64(v) > 1.2*float64(ms)) {
			t.Fatalf("value of bucket of %d ms is %d", ms, v)
		}
	}
	if bucketStart(TierMonth, time.Date(2026, 3, 17, 5, 0, 0, 0, time.UTC).UnixMilli()) != time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatal("month bucket")
	}
}
