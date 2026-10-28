package intake

import "github.com/ivseb/traffic-twin/internal/store"

func init() {
	store.Register(store.Namespace{Name: "intake", Migrations: migrations})
}

// Schema of the intake namespace.
//
//   - intake_events keeps one row per accepted event: the canonical event in
//     body (without disc), plus the scalar columns analyzers filter on.
//     Contract inference reads by (service, op, status) in time order, the
//     miner by time or trace, the event exporter by subject. Rows get
//     increasing ids, and received_ms never decreases with the id, which lets
//     the retention job find its cut point by binary search without an extra
//     index.
//   - intake_tokens indexes the tk1 tokens of each event, partitioned by the
//     hour of reception so that retention is a range delete on the primary
//     key and a scan by time yields all occurrences of a token together.
//   - intake_outbox holds the tokens not yet delivered to keyguard
//     (at-least-once delivery for the Bloom filter of real tokens).
//   - intake_quarantine, intake_sketch persist the cardinality monitors.
//   - intake_source_counts persists the per-source counters shown in Fleet.
//   - intake_agg and intake_agg_lat are the aggregates of the stored events
//     maintained at ingest (version 2): calls by (service, op, status,
//     source, policy, direction) and the outbound latency histogram. The
//     services and hosts lists read them instead of scanning the events;
//     purge and quarantine rewrites keep them exact. intake_agg_state holds
//     the backfill cursor for databases created before version 2: events
//     with next <= id <= hi are not aggregated yet (agg.go).
//   - intake_rollup, intake_rollup_src and intake_rollup_lat (version 3)
//     are the time-bucketed rollups (hour, day, month) that outlive the raw
//     events; intake_agg_state key rollup_next is their cursor (rollup.go).
var migrations = []store.Migration{
	{Version: 1, Name: "events_tokens_monitors", SQL: `
CREATE TABLE intake_events (
	id             INTEGER PRIMARY KEY,
	received_ms    INTEGER NOT NULL,
	ts_ms          INTEGER NOT NULL,
	source_id      TEXT    NOT NULL,
	policy_id      TEXT    NOT NULL,
	policy_version INTEGER NOT NULL,
	dir            INTEGER NOT NULL,
	service        TEXT    NOT NULL,
	op             TEXT    NOT NULL,
	route_source   INTEGER NOT NULL,
	status         INTEGER,
	net_error      TEXT,
	latency_ms     INTEGER NOT NULL,
	subject        TEXT,
	trace_id       TEXT,
	span_id        TEXT,
	parent_span_id TEXT,
	body           BLOB    NOT NULL
) STRICT;
CREATE INDEX intake_events_op      ON intake_events (service, op, status, ts_ms);
CREATE INDEX intake_events_ts      ON intake_events (ts_ms);
CREATE INDEX intake_events_trace   ON intake_events (trace_id)       WHERE trace_id IS NOT NULL;
CREATE INDEX intake_events_subject ON intake_events (subject, ts_ms) WHERE subject  IS NOT NULL;

CREATE TABLE intake_fields (
	id    INTEGER PRIMARY KEY,
	field TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE intake_tokens (
	hour     INTEGER NOT NULL,
	token    TEXT    NOT NULL,
	event_id INTEGER NOT NULL,
	field    INTEGER NOT NULL,
	ts_ms    INTEGER NOT NULL,
	PRIMARY KEY (hour, token, event_id, field)
) STRICT, WITHOUT ROWID;

CREATE TABLE intake_outbox (
	id     INTEGER PRIMARY KEY,
	epoch  TEXT NOT NULL,
	tokens TEXT NOT NULL
) STRICT;

CREATE TABLE intake_quarantine (
	id         INTEGER PRIMARY KEY,
	kind       TEXT    NOT NULL,
	qkey       TEXT    NOT NULL,
	state      TEXT    NOT NULL,
	since_ms   INTEGER NOT NULL,
	changed_ms INTEGER,
	estimate   INTEGER NOT NULL,
	threshold  INTEGER NOT NULL,
	rewrite_done INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE intake_sketch (
	kind INTEGER NOT NULL,
	skey TEXT    NOT NULL,
	day  INTEGER NOT NULL,
	data BLOB    NOT NULL,
	PRIMARY KEY (kind, skey, day)
) STRICT, WITHOUT ROWID;

CREATE TABLE intake_source_counts (
	source_id TEXT    NOT NULL,
	reason    TEXT    NOT NULL,
	n         INTEGER NOT NULL,
	PRIMARY KEY (source_id, reason)
) STRICT, WITHOUT ROWID;
`},
	{Version: 2, Name: "ingest_aggregates", SQL: `
CREATE TABLE intake_agg (
	service   TEXT    NOT NULL,
	op        TEXT    NOT NULL,
	status    INTEGER NOT NULL,
	source_id TEXT    NOT NULL,
	policy_id TEXT    NOT NULL,
	dir       INTEGER NOT NULL,
	n         INTEGER NOT NULL,
	first_ms  INTEGER NOT NULL,
	last_ms   INTEGER NOT NULL,
	PRIMARY KEY (service, op, status, source_id, policy_id, dir)
) STRICT, WITHOUT ROWID;

CREATE TABLE intake_agg_lat (
	service TEXT    NOT NULL,
	lat     INTEGER NOT NULL,
	n       INTEGER NOT NULL,
	PRIMARY KEY (service, lat)
) STRICT, WITHOUT ROWID;

CREATE TABLE intake_agg_state (
	k TEXT    PRIMARY KEY,
	v INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

INSERT INTO intake_agg_state (k, v) VALUES
	('hi', (SELECT coalesce(max(id), 0) FROM intake_events)),
	('next', (SELECT coalesce(min(id), 1) FROM intake_events));
`},
	{Version: 3, Name: "time_bucketed_rollups", SQL: rollupMigration},
}
