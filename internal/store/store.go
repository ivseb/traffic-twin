package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver
)

// DB wraps *sql.DB with the path it was opened from.
type DB struct {
	*sql.DB
	path string
}

// DriverName is the database/sql driver that Open uses. The performance
// harness (test/perf) registers an instrumented wrapper of "sqlite" under
// another name and sets it before the first Open, to trace every query and
// its plan; nothing else should change it.
var DriverName = "sqlite"

// MaxIdleConns is the number of idle connections the pool keeps open.
const MaxIdleConns = 8

// BusyTimeoutMillis is how long a connection waits for a lock before failing
// with SQLITE_BUSY.
const BusyTimeoutMillis = 5000

// Open opens the SQLite database at path (creating it and its parent
// directory with owner-only permissions if needed), configures every
// connection (WAL, busy timeout, foreign keys, immediate write transactions)
// and applies all migrations registered with [Register].
func Open(ctx context.Context, path string) (*DB, error) {
	return OpenWith(ctx, path, defaultRegistry)
}

// OpenWith is Open with an explicit migration registry.
func OpenWith(ctx context.Context, path string, r *Registry) (*DB, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("store: a file path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := prepareFile(abs); err != nil {
		return nil, err
	}

	q := url.Values{}
	// auto_vacuum only takes effect on a database with no tables yet, and
	// before the first write: it must come before journal_mode. On an
	// existing database it is ignored (see space.go).
	q.Add("_pragma", "auto_vacuum(2)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", BusyTimeoutMillis))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "secure_delete(1)")
	// Write transactions take the lock up front: no deadlock when two
	// deferred transactions both try to upgrade from read to write.
	q.Set("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String()

	sqlDB, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// Pool: database/sql keeps only 2 idle connections by default, so the
	// parallel requests of one UI page close and reopen connections (each
	// reopening runs the pragmas above and starts with a cold page cache).
	// The number of open connections is not capped: a request may hold a
	// result set open while it queries again, and a cap could deadlock.
	sqlDB.SetMaxIdleConns(MaxIdleConns)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)
	db := &DB{DB: sqlDB, path: abs}
	if err := db.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := db.check(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	if err := Migrate(ctx, sqlDB, r); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	tightenSidecars(abs)
	return db, nil
}

// Path returns the absolute path of the database file.
func (db *DB) Path() string { return db.path }

func (db *DB) check(ctx context.Context) error {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("store: read journal_mode: %w", err)
	}
	if mode != "wal" {
		return fmt.Errorf("store: journal_mode is %q, want wal", mode)
	}
	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return fmt.Errorf("store: read foreign_keys: %w", err)
	}
	if fk != 1 {
		return errors.New("store: foreign keys are not enabled")
	}
	return nil
}

// InTx runs fn inside a write transaction, committing if fn returns nil.
func (db *DB) InTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func prepareFile(abs string) error {
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create directory: %w", err)
	}
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("store: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return tightenMode(abs)
}

// tightenSidecars applies owner-only permissions to the WAL and SHM files.
func tightenSidecars(abs string) {
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = tightenMode(abs + suffix)
	}
}

func tightenMode(p string) error {
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(p, 0o600); err != nil {
			return fmt.Errorf("store: restrict permissions of %s: %w", filepath.Base(p), err)
		}
	}
	return nil
}
