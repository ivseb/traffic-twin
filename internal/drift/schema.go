package drift

import "github.com/ivseb/traffic-twin/internal/store"

func init() {
	store.Register(store.Namespace{Name: "drift", Migrations: []store.Migration{
		{Version: 1, Name: "alerts_webhooks_deliveries", SQL: `
CREATE TABLE drift_alerts (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	kind           TEXT    NOT NULL,
	dedupe_key     TEXT    NOT NULL,
	service        TEXT    NOT NULL,
	op             TEXT    NOT NULL,
	where_text     TEXT    NOT NULL,
	change_kind    TEXT    NOT NULL,
	severity       TEXT    NOT NULL,
	change         TEXT    NOT NULL,
	first_seen_ms  INTEGER NOT NULL,
	last_seen_ms   INTEGER NOT NULL,
	calls_after    INTEGER NOT NULL,
	state          TEXT    NOT NULL,
	ack_by         TEXT    NOT NULL DEFAULT '',
	ack_ms         INTEGER NOT NULL DEFAULT 0,
	affected_rules TEXT    NOT NULL DEFAULT '[]',
	snapshot_from  TEXT    NOT NULL DEFAULT '',
	snapshot_to    TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX drift_alerts_state ON drift_alerts (state, id);
CREATE UNIQUE INDEX drift_alerts_open_key ON drift_alerts (dedupe_key) WHERE state = 'open';

CREATE TABLE drift_webhooks (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL,
	url        TEXT    NOT NULL,
	events     TEXT    NOT NULL,
	secret     TEXT    NOT NULL,
	created_ms INTEGER NOT NULL,
	updated_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE drift_deliveries (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	webhook_id      INTEGER NOT NULL REFERENCES drift_webhooks(id) ON DELETE CASCADE,
	event_type      TEXT    NOT NULL,
	alert_id        INTEGER NOT NULL DEFAULT 0,
	payload         BLOB    NOT NULL,
	state           TEXT    NOT NULL,
	attempts        INTEGER NOT NULL DEFAULT 0,
	next_attempt_ms INTEGER NOT NULL,
	last_status     INTEGER NOT NULL DEFAULT 0,
	last_error      TEXT    NOT NULL DEFAULT '',
	created_ms      INTEGER NOT NULL,
	delivered_ms    INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX drift_deliveries_due ON drift_deliveries (state, next_attempt_ms);
CREATE INDEX drift_deliveries_webhook ON drift_deliveries (webhook_id, id);
`},
		{Version: 2, Name: "resolved_and_webhook_enabled", SQL: `
ALTER TABLE drift_alerts ADD COLUMN resolved_by TEXT NOT NULL DEFAULT '';
ALTER TABLE drift_alerts ADD COLUMN resolved_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE drift_webhooks ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;
`},
		// Multi-team isolation: the group of the contract an alert is about
		// ('' for rule alerts and older alerts: their service's groups).
		{Version: 3, Name: "alert_group", SQL: `
ALTER TABLE drift_alerts ADD COLUMN grp TEXT NOT NULL DEFAULT '';
`},
		// The names and figures behind the English text of an alert (JSON
		// object of strings): the console writes the sentence in its own
		// language from change_kind and these.
		{Version: 4, Name: "alert_params", SQL: `
ALTER TABLE drift_alerts ADD COLUMN params TEXT NOT NULL DEFAULT '{}';
`},
	}})
}
