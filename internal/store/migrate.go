package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"
)

// Migration is one forward-only schema change.
type Migration struct {
	// Version is 1-based and contiguous within a namespace.
	Version int
	// Name is a short description, part of the checksum.
	Name string
	// SQL is executed inside a transaction. It may contain several
	// statements separated by semicolons.
	SQL string
}

// Namespace groups the ordered migrations owned by one package.
type Namespace struct {
	// Name identifies the owner: lowercase, 2 to 32 characters, [a-z0-9_],
	// starting with a letter. The reserved name "store" is used internally.
	Name string
	// DependsOn lists namespaces that must be migrated first (for example
	// because of foreign keys into their tables).
	DependsOn []string
	// Migrations in ascending Version order, starting at 1.
	Migrations []Migration
}

var nsName = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

// Registry holds namespaces. The zero value is not usable; use NewRegistry.
type Registry struct {
	mu  sync.Mutex
	nss map[string]Namespace
}

// NewRegistry returns an empty registry (useful in tests).
func NewRegistry() *Registry { return &Registry{nss: map[string]Namespace{}} }

// defaultRegistry is the process-wide registry used by Open.
var defaultRegistry = NewRegistry()

// Register adds ns to the default registry. It panics on invalid input or
// duplicate namespaces: registration happens at init time and a mistake there
// is a programming error.
func Register(ns Namespace) {
	if err := defaultRegistry.Register(ns); err != nil {
		panic(err)
	}
}

// Register validates ns and adds it to r.
func (r *Registry) Register(ns Namespace) error {
	if !nsName.MatchString(ns.Name) || ns.Name == "store" {
		return fmt.Errorf("store: invalid namespace name %q", ns.Name)
	}
	if len(ns.Migrations) == 0 {
		return fmt.Errorf("store: namespace %q has no migrations", ns.Name)
	}
	for i, m := range ns.Migrations {
		if m.Version != i+1 {
			return fmt.Errorf("store: namespace %q: migration #%d has version %d, want %d", ns.Name, i, m.Version, i+1)
		}
		if m.Name == "" || m.SQL == "" {
			return fmt.Errorf("store: namespace %q: migration %d needs a name and SQL", ns.Name, m.Version)
		}
	}
	for _, d := range ns.DependsOn {
		if d == ns.Name {
			return fmt.Errorf("store: namespace %q depends on itself", ns.Name)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.nss[ns.Name]; dup {
		return fmt.Errorf("store: namespace %q registered twice", ns.Name)
	}
	ns.Migrations = slices.Clone(ns.Migrations)
	ns.DependsOn = slices.Clone(ns.DependsOn)
	r.nss[ns.Name] = ns
	return nil
}

// order returns namespaces in dependency order, ties broken by name, so the
// result is deterministic.
func (r *Registry) order() ([]Namespace, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.nss))
	for n := range r.nss {
		names = append(names, n)
	}
	slices.Sort(names)

	const (
		unvisited = iota
		visiting
		done
	)
	state := map[string]int{}
	var out []Namespace
	var visit func(n string, path []string) error
	visit = func(n string, path []string) error {
		ns, ok := r.nss[n]
		if !ok {
			return fmt.Errorf("store: namespace %q depends on unregistered namespace %q", path[len(path)-1], n)
		}
		switch state[n] {
		case visiting:
			return fmt.Errorf("store: dependency cycle: %v", append(path, n))
		case done:
			return nil
		}
		state[n] = visiting
		deps := slices.Clone(ns.DependsOn)
		slices.Sort(deps)
		for _, d := range deps {
			if err := visit(d, append(path, n)); err != nil {
				return err
			}
		}
		state[n] = done
		out = append(out, ns)
		return nil
	}
	for _, n := range names {
		if err := visit(n, []string{n}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Checksum returns the hex SHA-256 identifying a migration's content.
func (m Migration) Checksum() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s", m.Version, m.Name, m.SQL)
	return hex.EncodeToString(h.Sum(nil))
}

const bookkeeping = `CREATE TABLE IF NOT EXISTS store_migrations (
	namespace  TEXT    NOT NULL,
	version    INTEGER NOT NULL,
	name       TEXT    NOT NULL,
	checksum   TEXT    NOT NULL,
	applied_at TEXT    NOT NULL,
	PRIMARY KEY (namespace, version)
) STRICT`

// ErrChecksumMismatch reports an applied migration whose content changed.
var ErrChecksumMismatch = errors.New("store: applied migration was modified")

// ErrUnknownMigration reports a database migrated by a newer binary.
var ErrUnknownMigration = errors.New("store: database has migrations unknown to this binary")

// Migrate applies every pending migration of r to db. Each migration runs in
// its own transaction together with its bookkeeping row, so a failure leaves
// the database at the last fully applied version.
func Migrate(ctx context.Context, db *sql.DB, r *Registry) error {
	if _, err := db.ExecContext(ctx, bookkeeping); err != nil {
		return fmt.Errorf("store: create bookkeeping table: %w", err)
	}
	nss, err := r.order()
	if err != nil {
		return err
	}
	applied, err := loadApplied(ctx, db)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, ns := range nss {
		known[ns.Name] = true
		have := applied[ns.Name]
		for v := range have {
			if v > len(ns.Migrations) {
				return fmt.Errorf("%w: %s version %d", ErrUnknownMigration, ns.Name, v)
			}
		}
		for _, m := range ns.Migrations {
			if sum, ok := have[m.Version]; ok {
				if sum != m.Checksum() {
					return fmt.Errorf("%w: %s version %d (%s)", ErrChecksumMismatch, ns.Name, m.Version, m.Name)
				}
				continue
			}
			if err := apply(ctx, db, ns.Name, m); err != nil {
				return err
			}
		}
	}
	// A namespace present in the database but not registered is tolerated:
	// the owning package may simply not be linked into this binary (tests).
	return nil
}

func loadApplied(ctx context.Context, db *sql.DB) (map[string]map[int]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT namespace, version, checksum FROM store_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read applied migrations: %w", err)
	}
	defer rows.Close()
	out := map[string]map[int]string{}
	for rows.Next() {
		var ns, sum string
		var v int
		if err := rows.Scan(&ns, &v, &sum); err != nil {
			return nil, err
		}
		if out[ns] == nil {
			out[ns] = map[int]string{}
		}
		out[ns][v] = sum
	}
	return out, rows.Err()
}

func apply(ctx context.Context, db *sql.DB, ns string, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Another process may have applied it meanwhile (the transaction holds
	// the write lock from here on, see _txlock=immediate in Open).
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM store_migrations WHERE namespace = ? AND version = ?`, ns, m.Version).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("store: apply %s version %d (%s): %w", ns, m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO store_migrations (namespace, version, name, checksum, applied_at) VALUES (?, ?, ?, ?, ?)`,
		ns, m.Version, m.Name, m.Checksum(), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}
