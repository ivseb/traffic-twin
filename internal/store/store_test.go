package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sub", "tt.db")
}

func TestOpenPragmasAndPermissions(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	db, err := OpenWith(ctx, path, NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var timeout int
	if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != BusyTimeoutMillis {
		t.Errorf("busy_timeout = %d", timeout)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("db mode = %v, want 0600", st.Mode().Perm())
		}
		dst, _ := os.Stat(filepath.Dir(path))
		if dst.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %v, want 0700", dst.Mode().Perm())
		}
	}
	// Foreign keys are enforced on every pooled connection.
	db.SetMaxOpenConns(4)
	if _, err := db.ExecContext(ctx, `CREATE TABLE p (id INTEGER PRIMARY KEY); CREATE TABLE c (pid INTEGER REFERENCES p(id))`); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := db.ExecContext(ctx, `INSERT INTO c (pid) VALUES (42)`); err == nil {
			t.Fatal("foreign key violation accepted")
		}
	}
}

func TestOpenTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "tt.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := OpenWith(context.Background(), path, NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
}

func TestOpenRejectsMemory(t *testing.T) {
	if _, err := OpenWith(context.Background(), ":memory:", NewRegistry()); err == nil {
		t.Fatal("expected error")
	}
}

func TestMigrationRegistry(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)

	r := NewRegistry()
	mustReg(t, r, Namespace{Name: "beta", DependsOn: []string{"alpha"}, Migrations: []Migration{
		{Version: 1, Name: "child", SQL: `CREATE TABLE beta_child (id INTEGER PRIMARY KEY, parent INTEGER NOT NULL REFERENCES alpha_parent(id))`},
	}})
	mustReg(t, r, Namespace{Name: "alpha", Migrations: []Migration{
		{Version: 1, Name: "parent", SQL: `CREATE TABLE alpha_parent (id INTEGER PRIMARY KEY)`},
		{Version: 2, Name: "two statements", SQL: `ALTER TABLE alpha_parent ADD COLUMN label TEXT; CREATE INDEX alpha_parent_label ON alpha_parent(label)`},
	}})

	db, err := OpenWith(ctx, path, r)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM store_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("applied = %d, want 3", n)
	}
	db.Close()

	// Re-opening is idempotent.
	db, err = OpenWith(ctx, path, r)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Adding a migration applies only the new one.
	r2 := NewRegistry()
	mustReg(t, r2, Namespace{Name: "alpha", Migrations: []Migration{
		{Version: 1, Name: "parent", SQL: `CREATE TABLE alpha_parent (id INTEGER PRIMARY KEY)`},
		{Version: 2, Name: "two statements", SQL: `ALTER TABLE alpha_parent ADD COLUMN label TEXT; CREATE INDEX alpha_parent_label ON alpha_parent(label)`},
		{Version: 3, Name: "three", SQL: `CREATE TABLE alpha_three (id INTEGER PRIMARY KEY)`},
	}})
	db, err = OpenWith(ctx, path, r2)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// A modified applied migration is refused.
	r3 := NewRegistry()
	mustReg(t, r3, Namespace{Name: "alpha", Migrations: []Migration{
		{Version: 1, Name: "parent", SQL: `CREATE TABLE alpha_parent (id INTEGER PRIMARY KEY, sneaky TEXT)`},
		{Version: 2, Name: "two statements", SQL: `ALTER TABLE alpha_parent ADD COLUMN label TEXT; CREATE INDEX alpha_parent_label ON alpha_parent(label)`},
		{Version: 3, Name: "three", SQL: `CREATE TABLE alpha_three (id INTEGER PRIMARY KEY)`},
	}})
	if _, err := OpenWith(ctx, path, r3); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("modified migration: err = %v", err)
	}

	// A binary that knows fewer migrations than the database refuses to run.
	r4 := NewRegistry()
	mustReg(t, r4, Namespace{Name: "alpha", Migrations: []Migration{
		{Version: 1, Name: "parent", SQL: `CREATE TABLE alpha_parent (id INTEGER PRIMARY KEY)`},
	}})
	if _, err := OpenWith(ctx, path, r4); !errors.Is(err, ErrUnknownMigration) {
		t.Fatalf("downgrade: err = %v", err)
	}
}

func TestMigrationFailureIsAtomic(t *testing.T) {
	ctx := context.Background()
	path := tempPath(t)
	r := NewRegistry()
	mustReg(t, r, Namespace{Name: "gamma", Migrations: []Migration{
		{Version: 1, Name: "ok", SQL: `CREATE TABLE gamma_a (id INTEGER PRIMARY KEY)`},
		{Version: 2, Name: "broken", SQL: `CREATE TABLE gamma_b (id INTEGER PRIMARY KEY); THIS IS NOT SQL`},
	}})
	if _, err := OpenWith(ctx, path, r); err == nil || !strings.Contains(err.Error(), "gamma version 2") {
		t.Fatalf("err = %v", err)
	}
	db, err := OpenWith(ctx, path, NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name = 'gamma_b'`).Scan(&n)
	if n != 0 {
		t.Error("partial migration left gamma_b behind")
	}
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM store_migrations WHERE namespace = 'gamma'`).Scan(&n)
	if n != 1 {
		t.Errorf("gamma applied = %d, want 1", n)
	}
}

func TestRegistryValidation(t *testing.T) {
	ok := []Migration{{Version: 1, Name: "x", SQL: "SELECT 1"}}
	cases := []Namespace{
		{Name: "", Migrations: ok},
		{Name: "Bad", Migrations: ok},
		{Name: "store", Migrations: ok},
		{Name: "empty"},
		{Name: "gap", Migrations: []Migration{{Version: 2, Name: "x", SQL: "SELECT 1"}}},
		{Name: "noname", Migrations: []Migration{{Version: 1, SQL: "SELECT 1"}}},
		{Name: "self", DependsOn: []string{"self"}, Migrations: ok},
	}
	for _, ns := range cases {
		if err := NewRegistry().Register(ns); err == nil {
			t.Errorf("%q accepted", ns.Name)
		}
	}
	r := NewRegistry()
	mustReg(t, r, Namespace{Name: "dup", Migrations: ok})
	if err := r.Register(Namespace{Name: "dup", Migrations: ok}); err == nil {
		t.Error("duplicate accepted")
	}

	cyc := NewRegistry()
	mustReg(t, cyc, Namespace{Name: "aa", DependsOn: []string{"bb"}, Migrations: ok})
	mustReg(t, cyc, Namespace{Name: "bb", DependsOn: []string{"aa"}, Migrations: ok})
	if _, err := cyc.order(); err == nil {
		t.Error("cycle accepted")
	}
	missing := NewRegistry()
	mustReg(t, missing, Namespace{Name: "aa", DependsOn: []string{"zz"}, Migrations: ok})
	if _, err := missing.order(); err == nil {
		t.Error("missing dependency accepted")
	}
}

func TestInTx(t *testing.T) {
	ctx := context.Background()
	r := NewRegistry()
	mustReg(t, r, Namespace{Name: "tx", Migrations: []Migration{{Version: 1, Name: "t", SQL: `CREATE TABLE tx_t (v INTEGER)`}}})
	db, err := OpenWith(ctx, tempPath(t), r)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boom := errors.New("boom")
	err = db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tx_t VALUES (1)`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM tx_t`).Scan(&n)
	if n != 0 {
		t.Error("rolled-back insert persisted")
	}
}

func mustReg(t *testing.T, r *Registry, ns Namespace) {
	t.Helper()
	if err := r.Register(ns); err != nil {
		t.Fatal(err)
	}
}
