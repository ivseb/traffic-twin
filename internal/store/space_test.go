package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func fillAndDelete(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE blob (id INTEGER PRIMARY KEY, b BLOB)`); err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("x", 2000)
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		for i := 0; i < 20000; i++ {
			if _, err := tx.ExecContext(ctx, `INSERT INTO blob (b) VALUES (?)`, payload); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM blob`); err != nil {
		t.Fatal(err)
	}
}

func TestNewDatabaseReclaimsSpaceAfterDelete(t *testing.T) {
	ctx := context.Background()
	db, err := OpenWith(ctx, tempPath(t), NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if m, err := db.AutoVacuumMode(ctx); err != nil || m != AutoVacuumIncremental {
		t.Fatalf("auto_vacuum of a new database = %d, %v", m, err)
	}
	fillAndDelete(t, db)
	before, err := db.Space(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.FreeBytes < 30<<20 || before.FileBytes < 30<<20 {
		t.Fatalf("expected a big file full of free pages: %+v", before)
	}
	freed, err := db.Reclaim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := db.Space(ctx)
	if after.FreeBytes != 0 || after.FileBytes > before.FileBytes/10 || freed < before.FreeBytes/2 {
		t.Errorf("not reclaimed: freed=%d before=%+v after=%+v", freed, before, after)
	}
	// The database is intact and writable.
	if _, err := db.ExecContext(ctx, `INSERT INTO blob (b) VALUES ('ok')`); err != nil {
		t.Fatal(err)
	}
	// Nothing to reclaim is not an error.
	if _, err := db.Reclaim(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestReclaimIsInterruptible(t *testing.T) {
	db, err := OpenWith(context.Background(), tempPath(t), NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fillAndDelete(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.Reclaim(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled reclaim: %v", err)
	}
}

// A database made before the change has auto_vacuum=NONE: Reclaim refuses
// (it cannot work) and the explicit conversion fixes it for good.
func TestLegacyDatabaseNeedsConversion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE keep (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO keep (v) VALUES ('survives')`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	db, err := OpenWith(ctx, path, NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if m, _ := db.AutoVacuumMode(ctx); m != AutoVacuumNone {
		t.Fatalf("opening must not change an existing database: auto_vacuum=%d", m)
	}
	fillAndDelete(t, db)
	if _, err := db.Reclaim(ctx); !errors.Is(err, ErrNoIncrementalVacuum) {
		t.Fatalf("reclaim on a legacy database: %v", err)
	}
	before, _ := db.Space(ctx)
	if err := db.ConvertToIncrementalVacuum(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := db.Space(ctx)
	if after.AutoVacuum != AutoVacuumIncremental || after.FileBytes >= before.FileBytes/10 {
		t.Errorf("conversion: before=%+v after=%+v", before, after)
	}
	var v string
	if err := db.QueryRowContext(ctx, `SELECT v FROM keep`).Scan(&v); err != nil || v != "survives" {
		t.Errorf("data after conversion: %q %v", v, err)
	}
	// Idempotent, and online reclaim works from now on.
	if err := db.ConvertToIncrementalVacuum(ctx); err != nil {
		t.Fatal(err)
	}
	fillAndDelete2(t, db)
	if _, err := db.Reclaim(ctx); err != nil {
		t.Fatal(err)
	}
}

func fillAndDelete2(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	payload := strings.Repeat("y", 2000)
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		for i := 0; i < 5000; i++ {
			if _, err := tx.ExecContext(ctx, `INSERT INTO blob (b) VALUES (?)`, payload); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM blob`); err != nil {
		t.Fatal(err)
	}
}
