package intake

import (
	"context"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

func TestPurgeReportsProgressPerChunk(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 12; i++ {
		h.ingest(t, orderPost(hash))
	}
	h.idle(t)
	h.clock.Advance(40 * 24 * time.Hour)

	var seen []PurgeProgress
	res, err := h.in.Store().PurgeBeforeProgress(context.Background(), h.clock.Now().Add(-time.Hour), func(p PurgeProgress) {
		seen = append(seen, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 12 || len(seen) < 2 {
		t.Fatalf("result %+v, %d progress reports", res, len(seen))
	}
	first, last := seen[0], seen[len(seen)-1]
	if first.Phase != "events" || first.EventsEstimated != 12 || first.Events != 0 {
		t.Errorf("first report: %+v", first)
	}
	if last.Events != 12 || last.Phase != "reclaim" {
		t.Errorf("last report: %+v", last)
	}

	// The purge hands the freed pages back (new databases are incremental).
	if res.ReclaimNote != "" {
		t.Errorf("reclaim note: %q", res.ReclaimNote)
	}
	if sp, err := h.db.Space(context.Background()); err != nil || sp.FreeBytes != 0 || sp.AutoVacuum != store.AutoVacuumIncremental {
		t.Errorf("space after the purge: %+v %v", sp, err)
	}

	// A cancelled context stops the purge between chunks.
	for i := 0; i < 3; i++ {
		h.ingest(t, orderPost(hash))
	}
	h.idle(t)
	h.clock.Advance(40 * 24 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.in.Store().PurgeBeforeProgress(ctx, h.clock.Now().Add(-time.Hour), nil); err == nil {
		t.Error("a cancelled purge must report the context error")
	}
}
