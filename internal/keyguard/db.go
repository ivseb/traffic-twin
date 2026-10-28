package keyguard

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

// keyguard's own SQLite database is a separate file from tt-core's. Its
// namespace is registered lazily, only by a process that opens a keyguard
// database, so tt-core's database never gets keyguard tables.
var registerOnce sync.Once

var migrations = []store.Migration{
	{Version: 1, Name: "keyguard", SQL: `
CREATE TABLE kg_signed (
	issued_seq           INTEGER PRIMARY KEY,
	policy_id            TEXT NOT NULL,
	version              INTEGER NOT NULL,
	op                   TEXT NOT NULL,
	classification       TEXT NOT NULL,
	approval_mode        TEXT NOT NULL,
	body                 BLOB NOT NULL,
	hash                 TEXT NOT NULL,
	kid                  TEXT NOT NULL,
	signed_at            TEXT NOT NULL,
	approvals_unverified INTEGER NOT NULL
) STRICT;
CREATE INDEX kg_signed_policy ON kg_signed(policy_id, version);
CREATE TRIGGER kg_signed_no_update BEFORE UPDATE ON kg_signed
BEGIN SELECT RAISE(ABORT, 'kg_signed is append-only'); END;
CREATE TRIGGER kg_signed_no_delete BEFORE DELETE ON kg_signed
BEGIN SELECT RAISE(ABORT, 'kg_signed is append-only'); END;

CREATE TABLE kg_approvals (
	issued_seq   INTEGER NOT NULL REFERENCES kg_signed(issued_seq),
	user_id      TEXT NOT NULL,
	subject      TEXT NOT NULL,
	roles        TEXT NOT NULL,
	approved_at  TEXT NOT NULL,
	verified     INTEGER NOT NULL,
	reason       TEXT NOT NULL,
	token_sha256 TEXT,
	PRIMARY KEY (issued_seq, user_id)
) STRICT;
CREATE UNIQUE INDEX kg_approvals_token ON kg_approvals(token_sha256) WHERE token_sha256 IS NOT NULL;

CREATE TABLE kg_state (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) STRICT;

CREATE TABLE kg_bloom (
	epoch      TEXT NOT NULL,
	kid        TEXT NOT NULL,
	seg        INTEGER NOT NULL,
	capacity   INTEGER NOT NULL,
	count      INTEGER NOT NULL,
	m          INTEGER NOT NULL,
	k          INTEGER NOT NULL,
	bits       BLOB NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (epoch, kid, seg)
) STRICT;

CREATE TABLE kg_bloom_journal (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	epoch   TEXT NOT NULL,
	kid     TEXT NOT NULL,
	digests BLOB NOT NULL,
	at      INTEGER NOT NULL
) STRICT;
`},
	{Version: 2, Name: "token fingerprints", SQL: `
CREATE TABLE kg_token_fps (
	fp      TEXT PRIMARY KEY,
	op      TEXT NOT NULL,
	ref     TEXT NOT NULL,
	used_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER kg_token_fps_no_update BEFORE UPDATE ON kg_token_fps
BEGIN SELECT RAISE(ABORT, 'kg_token_fps is append-only'); END;
`},
}

// OpenDB opens (creating if needed) keyguard's database at path, with the
// keyguard and audit namespaces.
func OpenDB(ctx context.Context, path string) (*store.DB, error) {
	registerOnce.Do(func() {
		store.Register(store.Namespace{Name: "keyguard", Migrations: migrations})
	})
	return store.Open(ctx, path)
}

// signedRow is one policy body keyguard signed.
type signedRow struct {
	IssuedSeq      int64
	PolicyID       string
	Version        int64
	Op             string
	Classification string
	Body           []byte
	NotAfter       time.Time
}

type approvalRow struct {
	User, Subject, Roles, Reason string
	At                           time.Time
	Verified                     bool
	TokenSHA256                  string
}

const tsFormat = time.RFC3339Nano

var errSeqNotIncreasing = errors.New("issued_seq not increasing")
var errTokenReused = errors.New("id token reused")

// useTokens records the fingerprints of approval ID tokens inside tx and
// returns errTokenReused when one was recorded before (keyguard.md 3.2
// step 4: a token is never accepted twice, whatever it was used for).
func useTokens(ctx context.Context, tx *sql.Tx, fps []string, op, ref string, now time.Time) error {
	for _, fp := range fps {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM kg_token_fps WHERE fp = ?`, fp).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errTokenReused
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO kg_token_fps (fp, op, ref, used_at) VALUES (?, ?, ?, ?)`, fp, op, ref, now.UTC().Format(tsFormat)); err != nil {
			return err
		}
	}
	return nil
}

// recordTokens is useTokens in its own transaction (pack signing).
func recordTokens(ctx context.Context, db *store.DB, fps []string, op, ref string, now time.Time) error {
	if len(fps) == 0 {
		return nil
	}
	return db.InTx(ctx, func(tx *sql.Tx) error { return useTokens(ctx, tx, fps, op, ref, now) })
}

// insertSigned stores a signed body, its approvals and the fingerprints of
// every ID token presented (fps) in one transaction, refusing an issued_seq
// not greater than every one already signed and an ID token already used.
// Nothing is returned to the caller unless this commits.
func insertSigned(ctx context.Context, db *store.DB, r signedRow, mode, hash, kid string, unverified bool, apps []approvalRow, fps []string, now time.Time) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		var maxSeq sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT max(issued_seq) FROM kg_signed`).Scan(&maxSeq); err != nil {
			return err
		}
		if maxSeq.Valid && r.IssuedSeq <= maxSeq.Int64 {
			return errSeqNotIncreasing
		}
		for _, a := range apps {
			if a.TokenSHA256 == "" {
				continue
			}
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM kg_approvals WHERE token_sha256 = ?`, a.TokenSHA256).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return errTokenReused
			}
		}
		if err := useTokens(ctx, tx, fps, "policy_sign", r.PolicyID+"/"+strconv.FormatInt(r.Version, 10), now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO kg_signed (issued_seq, policy_id, version, op, classification, approval_mode, body, hash, kid, signed_at, approvals_unverified)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.IssuedSeq, r.PolicyID, r.Version, r.Op, r.Classification, mode, r.Body, hash, kid, now.UTC().Format(tsFormat), boolInt(unverified)); err != nil {
			return err
		}
		for _, a := range apps {
			var tok any
			if a.TokenSHA256 != "" {
				tok = a.TokenSHA256
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO kg_approvals (issued_seq, user_id, subject, roles, approved_at, verified, reason, token_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				r.IssuedSeq, a.User, a.Subject, a.Roles, a.At.UTC().Format(tsFormat), boolInt(a.Verified), a.Reason, tok); err != nil {
				return err
			}
		}
		return nil
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// lastIssuedSeq returns the greatest issued_seq signed (0 when none).
func lastIssuedSeq(ctx context.Context, db *store.DB) (int64, error) {
	var maxSeq sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT max(issued_seq) FROM kg_signed`).Scan(&maxSeq)
	return maxSeq.Int64, err
}

// signedBodies calls fn for every signed body, newest issued_seq first,
// until fn returns false.
func signedBodies(ctx context.Context, db *store.DB, fn func(seq int64, policyID string, body []byte) bool) error {
	rows, err := db.QueryContext(ctx, `SELECT issued_seq, policy_id, body FROM kg_signed ORDER BY issued_seq DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var id string
		var body []byte
		if err := rows.Scan(&seq, &id, &body); err != nil {
			return err
		}
		if !fn(seq, id, body) {
			break
		}
	}
	return rows.Err()
}

// lastBodyOf returns the newest body signed for policyID (nil when none).
func lastBodyOf(ctx context.Context, db *store.DB, policyID string) ([]byte, error) {
	var body []byte
	err := db.QueryRowContext(ctx, `SELECT body FROM kg_signed WHERE policy_id = ? ORDER BY issued_seq DESC LIMIT 1`, policyID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return body, err
}

// bodyOfVersion returns the newest body signed for (policyID, version).
func bodyOfVersion(ctx context.Context, db *store.DB, policyID string, version int64) ([]byte, error) {
	var body []byte
	err := db.QueryRowContext(ctx, `SELECT body FROM kg_signed WHERE policy_id = ? AND version = ? ORDER BY issued_seq DESC LIMIT 1`, policyID, version).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return body, err
}

// ---- small persistent state ----

func getState(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM kg_state WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func setState(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO kg_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// consumeBudget atomically consumes n strings from the daily budget of the
// UTC day of now. It returns the budget left and false when n does not fit
// (nothing is consumed then).
func consumeBudget(ctx context.Context, db *store.DB, now time.Time, n, budget int64) (left int64, ok bool, err error) {
	day := now.UTC().Format("2006-01-02")
	err = db.InTx(ctx, func(tx *sql.Tx) error {
		d, err := getState(ctx, tx, "budget.day")
		if err != nil {
			return err
		}
		var used int64
		if d == day {
			u, err := getState(ctx, tx, "budget.used")
			if err != nil {
				return err
			}
			used, _ = strconv.ParseInt(u, 10, 64)
		}
		if used+n > budget {
			left, ok = budget-used, false
			return nil
		}
		used += n
		left, ok = budget-used, true
		if err := setState(ctx, tx, "budget.day", day); err != nil {
			return err
		}
		return setState(ctx, tx, "budget.used", strconv.FormatInt(used, 10))
	})
	return left, ok, err
}

// budgetLeft returns the budget left for the UTC day of now.
func budgetLeft(ctx context.Context, db *store.DB, now time.Time, budget int64) (int64, error) {
	d, err := getState(ctx, db, "budget.day")
	if err != nil || d != now.UTC().Format("2006-01-02") {
		return budget, err
	}
	u, err := getState(ctx, db, "budget.used")
	if err != nil {
		return 0, err
	}
	used, _ := strconv.ParseInt(u, 10, 64)
	return max(budget-used, 0), nil
}
