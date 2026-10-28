package lifecycle

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/store"
)

func TestRunMeasuresShedsAndReports(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE big_rows (id INTEGER PRIMARY KEY, b BLOB); CREATE INDEX big_rows_b ON big_rows (length(b))`); err != nil {
		t.Fatal(err)
	}
	fill := func(n int) {
		if _, err := db.ExecContext(ctx, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < ?) INSERT INTO big_rows (b) SELECT randomblob(4000) FROM c`, n); err != nil {
			t.Fatal(err)
		}
	}
	fill(6000)
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	sp, err := db.Space(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The budget puts the database at 75%: over the critical watermark.
	budget := (sp.FileBytes + sp.WALBytes) * 100 / 75
	ran := 0
	var marks []Watermark
	al := audit.New(db)
	m, err := New(ctx, db, Config{MaxBytes: budget, HighPct: 60, CriticalPct: 70, Audit: al, Quotas: map[string]int64{"big": 1 << 40},
		OnWatermark: func(_ context.Context, w Watermark) { marks = append(marks, w) }},
		[]Dataset{{Name: "big", Tables: []string{"big_*"}, Policy: Policy{Code: "ttl"},
			Run: func(context.Context, time.Time) (Outcome, error) { ran++; return Outcome{}, nil }}},
		[]ShedStep{{Name: "drop_half", Datasets: []string{"big"}, Run: func(ctx context.Context, _ time.Time) (Outcome, error) {
			r, err := db.ExecContext(ctx, `DELETE FROM big_rows WHERE id % 2 = 0`)
			n, _ := r.RowsAffected()
			return Outcome{Deleted: n}, err
		}}})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := m.RunOnce(ctx, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ran != 1 || rep.Sizes["big"] < sp.FileBytes/2 {
		t.Fatalf("run %d, sizes %v", ran, rep.Sizes)
	}
	// Over 70% of the budget: shed, then back under the watermarks.
	if len(rep.Shed) != 1 || rep.Shed[0].Outcome.Deleted == 0 || rep.Reclaimed == 0 {
		t.Fatalf("shed: %+v reclaimed %d", rep.Shed, rep.Reclaimed)
	}
	if rep.Level != LevelOK || rep.UsedBytes > budget*60/100 {
		t.Fatalf("level %s used %d", rep.Level, rep.UsedBytes)
	}
	if len(marks) != 1 || marks[0].Shed[0] != "drop_half" || !marks[0].IngestionActive {
		t.Fatalf("watermarks: %+v", marks)
	}
	u, err := m.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if u.DB.MaxBytes != budget || u.LastRun == nil || u.NextRun == nil || len(u.Datasets) != 2 || u.Datasets[0].LastRun == nil {
		t.Fatalf("usage: %+v", u)
	}
	// A quota alone triggers the shedding of its dataset.
	m.cfg.MaxBytes = 0
	m.cfg.Quotas["big"] = rep.Sizes["big"] / 2
	rep, err = m.RunOnce(ctx, "test", nil)
	if err != nil || len(rep.Shed) != 1 || len(rep.OverQuota) != 1 {
		t.Fatalf("quota: %+v %v", rep, err)
	}
	// The state survives a restart; the audit has every run.
	m2, err := New(ctx, db, Config{}, nil, nil)
	if err != nil || m2.last == nil || m2.last.Trigger != "test" {
		t.Fatalf("reload: %v %+v", err, m2.last)
	}
	if _, err := al.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// One run at a time.
	m.running.Store(true)
	if _, err := m.RunOnce(ctx, "test", nil); err != ErrRunning {
		t.Fatalf("concurrent run: %v", err)
	}
}
