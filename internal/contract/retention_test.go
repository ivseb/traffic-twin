package contract

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

func TestCompactSnapshotsKeepsRecentWeeklyMonthlyAndProtected(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := NewSnapshotStore(db)
	day0 := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
	const days = 400
	var ids []string
	for d := 0; d < days; d++ {
		w := Window{From: day0.Add(time.Duration(d) * 24 * time.Hour), To: day0.Add(time.Duration(d+1) * 24 * time.Hour)}
		for _, svc := range []string{"a", "b"} {
			sn, err := st.Save(ctx, &Contract{Service: svc, Window: w}, w.To)
			if err != nil {
				t.Fatal(err)
			}
			if svc == "a" {
				ids = append(ids, sn.SnapshotID)
			}
		}
	}
	now := day0.Add(days * 24 * time.Hour)
	// Snapshot of day 10 of service a is referenced by a drift alert.
	protectedID := ids[10]
	seq, _ := ParseSnapshotID(protectedID)
	st.SetProtector(func(context.Context) (map[int64]bool, error) { return map[int64]bool{seq: true}, nil })

	res, err := st.Compact(ctx, now, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.List(ctx, "a", 1000)
	if err != nil {
		t.Fatal(err)
	}
	// 30 daily + ~22 weekly + ~8 monthly + the protected one.
	if len(list) < 55 || len(list) > 70 || res.Deleted != int64(2*days)-res.Kept {
		t.Fatalf("kept %d snapshots of a (result %+v)", len(list), res)
	}
	have := map[string]bool{}
	recent := 0
	for _, i := range list {
		have[i.SnapshotID] = true
		if now.Sub(i.Window.To) <= 30*24*time.Hour {
			recent++
		}
	}
	if !have[protectedID] || !have[ids[len(ids)-1]] || recent != 31 { // windows ending 0..30 days ago
		t.Fatalf("protected %v newest %v recent %d", have[protectedID], have[ids[len(ids)-1]], recent)
	}
	// Months older than 180 days: one per month.
	months := map[string]int{}
	for _, i := range list {
		if now.Sub(i.Window.To) > 180*24*time.Hour && i.SnapshotID != protectedID {
			months[i.Window.To.Format("2006-01")]++
		}
	}
	for m, n := range months {
		if n != 1 {
			t.Fatalf("month %s keeps %d snapshots", m, n)
		}
	}
	// Idempotent.
	again, err := st.Compact(ctx, now, DefaultSnapshotPolicy())
	if err != nil || again.Deleted != 0 {
		t.Fatalf("second compaction %+v %v", again, err)
	}
	// The hard cap skips the protected snapshot too.
	if err := st.Prune(ctx, "a", 5); err != nil {
		t.Fatal(err)
	}
	list, _ = st.List(ctx, "a", 1000)
	if len(list) != 6 || list[len(list)-1].SnapshotID != protectedID {
		t.Fatalf("after prune: %d, oldest %s", len(list), list[len(list)-1].SnapshotID)
	}
}
