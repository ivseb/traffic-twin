package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// Space reclaim.
//
// SQLite never shrinks its file by itself: deleted rows leave free pages that
// later inserts reuse, so after a purge the file keeps its size (lab N2: 4.7
// GB after deleting millions of events). Two mechanisms are provided.
//
//   - New databases are created with auto_vacuum=INCREMENTAL ([Open] sets it
//     before the first table exists). Free pages are then handed back with
//     PRAGMA incremental_vacuum(N), a few thousand pages at a time, each step
//     a short write transaction: ingestion and the review UI keep working,
//     which is why it is the choice for a live system ([DB.Reclaim]).
//   - A database created before this change has auto_vacuum=NONE, a property
//     SQLite can change only by rewriting the file with VACUUM. That rewrite
//     needs the free disk space of a second copy and blocks every writer for
//     its whole duration, so it is never done automatically: run it in a
//     maintenance window with core stopped ([ConvertToIncrementalVacuum],
//     "tt compact"), once; from then on the database reclaims space online.

// Auto-vacuum modes (PRAGMA auto_vacuum).
const (
	AutoVacuumNone        = 0
	AutoVacuumFull        = 1
	AutoVacuumIncremental = 2
)

// ErrNoIncrementalVacuum is returned by Reclaim on a database that is not in
// incremental auto-vacuum mode (see the package comment on how to convert it).
var ErrNoIncrementalVacuum = errors.New("store: database is not in incremental auto_vacuum mode: stop the core and run \"tt compact\" once")

// SpaceStats describes the file space.
type SpaceStats struct {
	// FileBytes is the size of the main file, WALBytes of the write-ahead log.
	FileBytes, WALBytes int64
	// FreeBytes is the space held by free pages (reclaimable).
	FreeBytes int64
	// AutoVacuum is the PRAGMA auto_vacuum mode.
	AutoVacuum int
}

// AutoVacuumMode returns PRAGMA auto_vacuum of the database.
func (db *DB) AutoVacuumMode(ctx context.Context) (int, error) {
	var m int
	err := db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&m)
	return m, err
}

// Space reports the file size and the reclaimable space.
func (db *DB) Space(ctx context.Context) (SpaceStats, error) {
	var st SpaceStats
	var pageSize, free int64
	if err := db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return st, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
		return st, err
	}
	var err error
	if st.AutoVacuum, err = db.AutoVacuumMode(ctx); err != nil {
		return st, err
	}
	st.FreeBytes = free * pageSize
	if fi, err := os.Stat(db.path); err == nil {
		st.FileBytes = fi.Size()
	}
	if fi, err := os.Stat(db.path + "-wal"); err == nil {
		st.WALBytes = fi.Size()
	}
	return st, nil
}

// reclaimStep is the number of pages released per transaction (about 4 MB
// with the default 4 KB pages): short enough not to starve the writers.
// Each step is followed by a pause at least as long as the step, so that
// the reclaim never holds the write lock more than half of the time.
const reclaimStep = 1000

// Reclaim hands the free pages back to the file system, reclaimStep pages at
// a time, pausing between steps so that ingestion is never starved, and then
// truncates the write-ahead log. It returns the number of bytes released
// from the main file. It needs incremental auto_vacuum (ErrNoIncrementalVacuum
// otherwise) and can be interrupted through ctx: what was released stays so.
func (db *DB) Reclaim(ctx context.Context) (int64, error) {
	mode, err := db.AutoVacuumMode(ctx)
	if err != nil {
		return 0, err
	}
	if mode != AutoVacuumIncremental {
		return 0, ErrNoIncrementalVacuum
	}
	var pageSize int64
	if err := db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, err
	}
	var released int64
	for {
		var before, after int64
		if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&before); err != nil {
			return released * pageSize, err
		}
		if before == 0 {
			break
		}
		// The pragma returns no useful rows; Exec runs the steps.
		t0 := time.Now()
		if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", reclaimStep)); err != nil {
			return released * pageSize, err
		}
		if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&after); err != nil {
			return released * pageSize, err
		}
		released += before - after
		if after >= before {
			break // no progress: do not spin
		}
		select {
		case <-ctx.Done():
			return released * pageSize, ctx.Err()
		case <-time.After(max(20*time.Millisecond, time.Since(t0))):
		}
	}
	// The WAL holds the pages just freed until a checkpoint truncates it.
	// A busy result (a reader is active) is not an error: the next
	// checkpoint, automatic or from the next purge, gets it.
	if rows, err := db.QueryContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err == nil {
		rows.Close()
	}
	return released * pageSize, nil
}

// ConvertToIncrementalVacuum switches an existing database to incremental
// auto_vacuum and compacts it (VACUUM). It rewrites the whole file: it needs
// free disk space of about the database size and blocks all writers until it
// ends, so run it only with the core stopped (tt compact does). It is a
// no-op on a database that is already incremental.
func (db *DB) ConvertToIncrementalVacuum(ctx context.Context) error {
	mode, err := db.AutoVacuumMode(ctx)
	if err != nil {
		return err
	}
	if mode == AutoVacuumIncremental {
		return nil
	}
	// auto_vacuum and VACUUM must run on one connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("store: vacuum: %w", err)
	}
	// In WAL mode the rewritten file sits in the log until a checkpoint.
	if rows, err := conn.QueryContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err == nil {
		rows.Close()
	}
	if m, err := db.AutoVacuumMode(ctx); err != nil || m != AutoVacuumIncremental {
		return fmt.Errorf("store: auto_vacuum is %d after VACUUM (err %v)", m, err)
	}
	return nil
}
