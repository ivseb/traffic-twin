package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "fleet", Migrations: migrations})
}

// Times are unix seconds (UTC). JSON columns hold short identifier lists
// and counters only, never payload values (there are none in zone B).
var migrations = []store.Migration{
	{Version: 1, Name: "groups tokens sources certs policies keys", SQL: `
CREATE TABLE fleet_meta (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
) STRICT;
CREATE TABLE fleet_groups (
	name                  TEXT PRIMARY KEY,
	description           TEXT NOT NULL DEFAULT '',
	policy_id             TEXT,
	allowed_service_names TEXT NOT NULL,
	sampling_override_bp  INTEGER,
	killed                INTEGER NOT NULL DEFAULT 0,
	created_at            INTEGER NOT NULL,
	updated_at            INTEGER NOT NULL
) STRICT;
CREATE TABLE fleet_tokens (
	id              TEXT PRIMARY KEY,
	secret_hash     TEXT NOT NULL UNIQUE,
	kind            TEXT NOT NULL,
	grp             TEXT NOT NULL REFERENCES fleet_groups(name),
	token_type      TEXT NOT NULL CHECK (token_type IN ('one_time', 'group')),
	expires_at      INTEGER NOT NULL,
	max_uses        INTEGER NOT NULL,
	uses            INTEGER NOT NULL DEFAULT 0,
	revoked         INTEGER NOT NULL DEFAULT 0,
	created_by      TEXT NOT NULL,
	created_by_name TEXT NOT NULL,
	created_at      INTEGER NOT NULL
) STRICT;
CREATE TABLE fleet_sources (
	id                   TEXT PRIMARY KEY,
	token_id             TEXT NOT NULL REFERENCES fleet_tokens(id),
	grp                  TEXT NOT NULL REFERENCES fleet_groups(name),
	kind                 TEXT NOT NULL,
	version              TEXT NOT NULL,
	service_name         TEXT NOT NULL,
	instance             TEXT NOT NULL DEFAULT '',
	runtime              TEXT NOT NULL DEFAULT '{}',
	hmac_kids            TEXT NOT NULL DEFAULT '[]',
	enrolled_at          INTEGER NOT NULL,
	cert_not_after       INTEGER NOT NULL,
	revoked              INTEGER NOT NULL DEFAULT 0,
	killed               INTEGER NOT NULL DEFAULT 0,
	sampling_override_bp INTEGER,
	last_seen            INTEGER NOT NULL DEFAULT 0,
	state                TEXT NOT NULL DEFAULT 'enrolled',
	policy_id            TEXT NOT NULL DEFAULT '',
	policy_version       INTEGER NOT NULL DEFAULT 0,
	policy_seq           INTEGER NOT NULL DEFAULT 0,
	policy_hash          TEXT NOT NULL DEFAULT '',
	counters             TEXT NOT NULL DEFAULT '{}',
	events_per_min       REAL NOT NULL DEFAULT 0,
	drop_ratio           REAL NOT NULL DEFAULT 0,
	overhead_p50         INTEGER,
	overhead_p99         INTEGER,
	last_errors          TEXT NOT NULL DEFAULT '[]'
) STRICT;
CREATE INDEX fleet_sources_token ON fleet_sources(token_id);
CREATE INDEX fleet_sources_grp ON fleet_sources(grp);
CREATE TABLE fleet_certs (
	serial    TEXT PRIMARY KEY,
	source_id TEXT NOT NULL REFERENCES fleet_sources(id),
	issued_at INTEGER NOT NULL,
	not_after INTEGER NOT NULL,
	revoked   INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX fleet_certs_source ON fleet_certs(source_id);
CREATE TABLE fleet_policy_versions (
	policy_id          TEXT NOT NULL,
	version            INTEGER NOT NULL,
	status             TEXT NOT NULL CHECK (status IN ('draft', 'active', 'superseded', 'rejected')),
	origin             TEXT NOT NULL,
	author             TEXT NOT NULL,
	proposed_by        TEXT NOT NULL,
	proposed_by_name   TEXT NOT NULL,
	proposed_at        INTEGER NOT NULL,
	classification     TEXT NOT NULL,
	approvals_required INTEGER NOT NULL,
	diff               TEXT NOT NULL,
	targets            TEXT NOT NULL,
	draft_body         BLOB NOT NULL,
	issued_seq         INTEGER,
	not_after          INTEGER,
	hash               TEXT,
	body               BLOB,
	envelope           BLOB,
	signer_kid         TEXT,
	decided_by         TEXT,
	decided_at         INTEGER,
	approval_mode      TEXT NOT NULL DEFAULT '',
	note               TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (policy_id, version)
) STRICT;
CREATE UNIQUE INDEX fleet_policy_one_active ON fleet_policy_versions(policy_id) WHERE status = 'active';
CREATE UNIQUE INDEX fleet_policy_hash ON fleet_policy_versions(hash) WHERE hash IS NOT NULL;
CREATE TABLE fleet_policy_approvals (
	policy_id TEXT NOT NULL,
	version   INTEGER NOT NULL,
	user_id   TEXT NOT NULL,
	user_name TEXT NOT NULL,
	roles     TEXT NOT NULL,
	at        INTEGER NOT NULL,
	verified  INTEGER NOT NULL DEFAULT 0,
	admin     INTEGER NOT NULL DEFAULT 0,
	reason    TEXT NOT NULL DEFAULT '',
	note      TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (policy_id, version, user_id),
	FOREIGN KEY (policy_id, version) REFERENCES fleet_policy_versions(policy_id, version)
) STRICT;
CREATE TABLE fleet_signing_keys (
	kid         TEXT PRIMARY KEY,
	public_key  TEXT NOT NULL,
	endorsed_by TEXT NOT NULL DEFAULT '',
	endorsement TEXT NOT NULL DEFAULT '',
	revoked     INTEGER NOT NULL DEFAULT 0,
	added_at    INTEGER NOT NULL
) STRICT;
`},
	// Red team round 3 (RT3-KEY-1): the policy signing kids each source
	// trusts (pinned at enrollment, then reported by its heartbeat), so a
	// key revocation can wait until a rotation reached the fleet.
	{Version: 2, Name: "source signing kids", SQL: `
ALTER TABLE fleet_sources ADD COLUMN signing_kids TEXT NOT NULL DEFAULT '[]';
`},
	// Usability round 3 (multi-team isolation): the group of every source
	// ever enrolled, kept when the source row is deleted by retention, so
	// the stored events (keyed by source id) stay attributed to their group.
	// The existing sources are attributed now; a trigger records the new ones.
	{Version: 3, Name: "source group attribution", SQL: `
CREATE TABLE fleet_source_groups (
	source_id    TEXT PRIMARY KEY,
	grp          TEXT NOT NULL,
	service_name TEXT NOT NULL DEFAULT ''
) STRICT, WITHOUT ROWID;
INSERT OR REPLACE INTO fleet_source_groups (source_id, grp, service_name) SELECT id, grp, service_name FROM fleet_sources;
CREATE TRIGGER fleet_source_groups_ins AFTER INSERT ON fleet_sources BEGIN
	INSERT OR REPLACE INTO fleet_source_groups (source_id, grp, service_name) VALUES (new.id, new.grp, new.service_name);
END;
`},
	// Spec v1.6 (observe phase): why a version opens values (policy.md 7),
	// as JSON reasons; 'null' for versions stored before.
	{Version: 4, Name: "policy value reasons", SQL: `
ALTER TABLE fleet_policy_versions ADD COLUMN value_reasons TEXT NOT NULL DEFAULT 'null';
`},
	// Spec v1.6.1 (usability test 4): the automatic observe versions go on
	// after a person's change, for the fields nobody chose; each group can
	// turn them off (admin-api setObserveAuto).
	{Version: 5, Name: "group observe auto", SQL: `
ALTER TABLE fleet_groups ADD COLUMN observe_auto INTEGER NOT NULL DEFAULT 1;
`},
	// Spec v1.18 (C0): a group marked as test is mined (and packed) with a
	// lower k, 0 = off; set by an administrator, audited.
	{Version: 6, Name: "group test k", SQL: `
ALTER TABLE fleet_groups ADD COLUMN test_k_min INTEGER NOT NULL DEFAULT 0;
`},
}

// Meta keys.
const (
	metaIssuedSeq  = "issued_seq"  // last issued_seq handed out
	metaGlobalKill = "global_kill" // "1" when the global kill switch is on
)

func getMeta(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, k string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT v FROM fleet_meta WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func setMeta(ctx context.Context, tx *sql.Tx, k, v string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO fleet_meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

// nextIssuedSeq allocates the next global issued_seq (policy.md 2). The
// value is persisted before keyguard is asked to sign, so it is never
// reused even when signing fails.
func nextIssuedSeq(ctx context.Context, tx *sql.Tx) (int64, error) {
	cur, err := getMeta(ctx, tx, metaIssuedSeq)
	if err != nil {
		return 0, err
	}
	var n int64
	if cur != "" {
		if n, err = strconv.ParseInt(cur, 10, 64); err != nil {
			return 0, err
		}
	}
	// Never go below a sequence already stored (defense in depth).
	var maxStored sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(issued_seq) FROM fleet_policy_versions`).Scan(&maxStored); err != nil {
		return 0, err
	}
	if maxStored.Valid && maxStored.Int64 > n {
		n = maxStored.Int64
	}
	n++
	return n, setMeta(ctx, tx, metaIssuedSeq, strconv.FormatInt(n, 10))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func intPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}
