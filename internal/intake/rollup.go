package intake

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"time"
)

// Time-bucketed rollups of the events (schema version 3): the "sintesi" that
// outlives the raw events.
//
// Raw events are kept for a short time (retention.events, 7 days by
// default). Before an event can be deleted it is counted into three tables,
// by event time:
//
//   - intake_rollup: calls by (bucket, service, op, status, direction), with
//     the latency sum and maximum; the unit of contract history and of the
//     traffic charts;
//   - intake_rollup_src: calls and errors by (bucket, service, source,
//     policy, direction), without the operation; the unit of the hosts
//     registry over an old period;
//   - intake_rollup_lat: a log-scale latency histogram by (bucket, service,
//     direction), four buckets per doubling (about 9% error at the bucket
//     midpoint), for the medians and p95 of old periods.
//
// Each row belongs to a tier: hourly (tier 0), daily (1) and monthly (2).
// The rollup job adds the events past its cursor (intake_agg_state key
// rollup_next) to the hourly tier, one id range per short transaction, so it
// never holds the write lock for long and resumes exactly where it stopped
// after a restart. CompactRollups merges the hourly rows of days older than
// the hourly retention into one daily row, and the daily rows of months
// older than the daily retention into a monthly row (kept forever). A day or
// a month moves in one transaction: totals are the same before and after.
//
// The rollups stay consistent with the raw events:
//   - the purge never deletes an event the rollup has not counted
//     (PurgeBefore stops at the cursor, after rolling up what it can);
//   - a quarantine rewrite of an event already counted moves the call from
//     the old (service, op) to the new one in the tier that holds it, so a
//     quarantined literal does not survive in the rollups.
//
// Rollups are never subtracted when raw events are purged: that is their
// purpose. The ingest aggregates (agg.go) describe the stored events; the
// rollups describe all traffic ever received.

// Rollup tiers.
const (
	TierHour  = 0
	TierDay   = 1
	TierMonth = 2
)

// rollupChunk is the number of event ids rolled up per transaction.
const rollupChunk = 5_000

const rollupCursorKey = "rollup_next"

var rollupMigration = `
CREATE TABLE intake_rollup (
	tier     INTEGER NOT NULL,
	bucket   INTEGER NOT NULL,
	service  TEXT    NOT NULL,
	op       TEXT    NOT NULL,
	status   INTEGER NOT NULL,
	dir      INTEGER NOT NULL,
	n        INTEGER NOT NULL,
	lat_sum  INTEGER NOT NULL,
	lat_max  INTEGER NOT NULL,
	first_ms INTEGER NOT NULL,
	last_ms  INTEGER NOT NULL,
	PRIMARY KEY (tier, bucket, service, op, status, dir)
) STRICT, WITHOUT ROWID;

CREATE TABLE intake_rollup_src (
	tier       INTEGER NOT NULL,
	bucket     INTEGER NOT NULL,
	service    TEXT    NOT NULL,
	source_id  TEXT    NOT NULL,
	policy_id  TEXT    NOT NULL,
	dir        INTEGER NOT NULL,
	n          INTEGER NOT NULL,
	err_server INTEGER NOT NULL,
	err_client INTEGER NOT NULL,
	first_ms   INTEGER NOT NULL,
	last_ms    INTEGER NOT NULL,
	PRIMARY KEY (tier, bucket, service, source_id, policy_id, dir)
) STRICT, WITHOUT ROWID;

CREATE TABLE intake_rollup_lat (
	tier    INTEGER NOT NULL,
	bucket  INTEGER NOT NULL,
	service TEXT    NOT NULL,
	dir     INTEGER NOT NULL,
	lb      INTEGER NOT NULL,
	n       INTEGER NOT NULL,
	PRIMARY KEY (tier, bucket, service, dir, lb)
) STRICT, WITHOUT ROWID;

INSERT INTO intake_agg_state (k, v) VALUES ('rollup_next', (SELECT coalesce(min(id), 1) FROM intake_events));
`

// RollupLatBucket maps a latency to its histogram bucket: 0 for 0 ms (or
// less), then floor(4*log2(ms))+1.
func RollupLatBucket(ms int64) int64 {
	if ms <= 0 {
		return 0
	}
	return int64(math.Floor(4*math.Log2(float64(ms)))) + 1
}

// RollupLatValue is the representative latency (geometric midpoint) of a
// bucket, in milliseconds.
func RollupLatValue(lb int64) int64 {
	if lb <= 0 {
		return 0
	}
	if lb == 1 {
		return 1
	}
	return int64(math.Round(math.Pow(2, (float64(lb-1)+0.5)/4)))
}

// bucketStart returns the start (unix seconds, UTC) of the tier bucket that
// holds t (unix milliseconds).
func bucketStart(tier int, ms int64) int64 {
	s := floorDiv(ms, 1000)
	switch tier {
	case TierHour:
		return floorDiv(s, 3600) * 3600
	case TierDay:
		return floorDiv(s, 86400) * 86400
	default:
		t := time.Unix(s, 0).UTC()
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).Unix()
	}
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// RollupCursor returns the id of the first event not rolled up yet.
func (s *Store) RollupCursor(ctx context.Context) (int64, error) {
	return readRollupCursor(ctx, s.db)
}

func readRollupCursor(ctx context.Context, q execer) (int64, error) {
	var v int64
	err := q.QueryRowContext(ctx, `SELECT v FROM intake_agg_state WHERE k = ?`, rollupCursorKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("intake: rollup cursor missing")
	}
	return v, err
}

// RollupResult reports a rollup run.
type RollupResult struct {
	// Events is the number of events counted into the hourly tier.
	Events int64
	// Cursor is the id of the first event not rolled up after the run.
	Cursor int64
}

// RollupPending counts every stored event past the cursor into the hourly
// tier, rollupChunk ids per transaction, until it reaches the newest event or
// ctx ends. It is idempotent and safe to run concurrently with ingestion
// (and with itself: the cursor is read and advanced inside each transaction).
//
// Each chunk is followed by a pause as long as the chunk (as in the purge,
// store_purge.go): a backlog of millions of events (the first purge after
// an upgrade, a long stop of the maintenance) must not starve the intake
// writer, which shares the single SQLite write lock.
func (s *Store) RollupPending(ctx context.Context) (RollupResult, error) {
	var res RollupResult
	for {
		t0 := time.Now()
		n, cur, done, err := s.rollupStep(ctx)
		res.Events += n
		res.Cursor = cur
		if err != nil || done {
			return res, err
		}
		if err := purgePauseFor(ctx, time.Since(t0)); err != nil {
			return res, err
		}
	}
}

func (s *Store) rollupStep(ctx context.Context) (n, cursor int64, done bool, err error) {
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		next, err := readRollupCursor(ctx, tx)
		if err != nil {
			return err
		}
		cursor = next
		var maxID sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT max(id) FROM intake_events`).Scan(&maxID); err != nil {
			return err
		}
		if !maxID.Valid || next > maxID.Int64 {
			done = true
			return nil
		}
		// Skip a gap left by a purge (or ids never used).
		var lo sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT min(id) FROM intake_events WHERE id >= ?`, next).Scan(&lo); err != nil {
			return err
		}
		if !lo.Valid {
			done = true
			return nil
		}
		hi := min(lo.Int64+rollupChunk-1, maxID.Int64)
		if n, err = addRollupRange(ctx, tx, lo.Int64, hi); err != nil {
			return err
		}
		cursor = hi + 1
		done = hi >= maxID.Int64
		_, err = tx.ExecContext(ctx, `UPDATE intake_agg_state SET v = ? WHERE k = ?`, cursor, rollupCursorKey)
		return err
	})
	return n, cursor, done, err
}

// addRollupRange adds the events lo <= id <= hi to the hourly tier.
func addRollupRange(ctx context.Context, tx execer, lo, hi int64) (int64, error) {
	var total int64
	rows, err := tx.QueryContext(ctx, `SELECT (ts_ms / 3600000) * 3600, service, op, coalesce(status, 0), dir,
		count(*), sum(latency_ms), max(latency_ms), min(ts_ms), max(ts_ms)
		FROM intake_events WHERE id BETWEEN ? AND ? GROUP BY 1, 2, 3, 4, 5`, lo, hi)
	if err != nil {
		return 0, err
	}
	type opRow struct {
		bucket                  int64
		service, op             string
		status, dir             int
		n, sum, mx, first, last int64
	}
	var ops []opRow
	for rows.Next() {
		var r opRow
		if err := rows.Scan(&r.bucket, &r.service, &r.op, &r.status, &r.dir, &r.n, &r.sum, &r.mx, &r.first, &r.last); err != nil {
			rows.Close()
			return 0, err
		}
		ops = append(ops, r)
		total += r.n
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, r := range ops {
		if err := upsertRollupOp(ctx, tx, TierHour, r.bucket, r.service, r.op, r.status, r.dir, r.n, r.sum, r.mx, r.first, r.last); err != nil {
			return 0, err
		}
	}

	rows, err = tx.QueryContext(ctx, `SELECT (ts_ms / 3600000) * 3600, service, source_id, policy_id, dir, count(*),
		sum(CASE WHEN net_error IS NOT NULL OR status >= 500 OR status IS NULL THEN 1 ELSE 0 END),
		sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END), min(ts_ms), max(ts_ms)
		FROM intake_events WHERE id BETWEEN ? AND ? GROUP BY 1, 2, 3, 4, 5`, lo, hi)
	if err != nil {
		return 0, err
	}
	type srcRow struct {
		bucket                  int64
		service, source, policy string
		dir                     int
		n, es, ec, first, last  int64
	}
	var srcs []srcRow
	for rows.Next() {
		var r srcRow
		if err := rows.Scan(&r.bucket, &r.service, &r.source, &r.policy, &r.dir, &r.n, &r.es, &r.ec, &r.first, &r.last); err != nil {
			rows.Close()
			return 0, err
		}
		srcs = append(srcs, r)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, r := range srcs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_rollup_src (tier, bucket, service, source_id, policy_id, dir, n, err_server, err_client, first_ms, last_ms)
			VALUES (0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET n = n + excluded.n, err_server = err_server + excluded.err_server, err_client = err_client + excluded.err_client,
				first_ms = min(first_ms, excluded.first_ms), last_ms = max(last_ms, excluded.last_ms)`,
			r.bucket, r.service, r.source, r.policy, r.dir, r.n, r.es, r.ec, r.first, r.last); err != nil {
			return 0, err
		}
	}

	rows, err = tx.QueryContext(ctx, `SELECT (ts_ms / 3600000) * 3600, service, dir, latency_ms, count(*)
		FROM intake_events WHERE id BETWEEN ? AND ? GROUP BY 1, 2, 3, 4`, lo, hi)
	if err != nil {
		return 0, err
	}
	type latKey struct {
		bucket  int64
		service string
		dir     int
		lb      int64
	}
	lat := map[latKey]int64{}
	for rows.Next() {
		var k latKey
		var ms, n int64
		if err := rows.Scan(&k.bucket, &k.service, &k.dir, &ms, &n); err != nil {
			rows.Close()
			return 0, err
		}
		k.lb = RollupLatBucket(ms)
		lat[k] += n
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for k, n := range lat {
		if err := upsertRollupLat(ctx, tx, TierHour, k.bucket, k.service, k.dir, k.lb, n); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func upsertRollupOp(ctx context.Context, tx execer, tier int, bucket int64, service, op string, status, dir int, n, sum, mx, first, last int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO intake_rollup (tier, bucket, service, op, status, dir, n, lat_sum, lat_max, first_ms, last_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT DO UPDATE SET n = n + excluded.n, lat_sum = lat_sum + excluded.lat_sum, lat_max = max(lat_max, excluded.lat_max),
			first_ms = min(first_ms, excluded.first_ms), last_ms = max(last_ms, excluded.last_ms)`,
		tier, bucket, service, op, status, dir, n, sum, mx, first, last)
	return err
}

func upsertRollupLat(ctx context.Context, tx execer, tier int, bucket int64, service string, dir int, lb, n int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO intake_rollup_lat (tier, bucket, service, dir, lb, n) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT DO UPDATE SET n = n + excluded.n`, tier, bucket, service, dir, lb, n)
	return err
}

// rollupMove moves one rolled-up event from its old (service, op) to the new
// one after a quarantine rewrite, in the tier that holds its bucket (the
// hourly tier, unless the bucket was already compacted).
func rollupMove(ctx context.Context, tx execer, old aggKey, newService, newOp string, tsMS, latMS int64) error {
	for tier := TierHour; tier <= TierMonth; tier++ {
		b := bucketStart(tier, tsMS)
		const where = ` WHERE tier = ? AND bucket = ? AND service = ? AND op = ? AND status = ? AND dir = ?`
		r, err := tx.ExecContext(ctx, `UPDATE intake_rollup SET n = n - 1, lat_sum = lat_sum - ?`+where+` AND n > 0`,
			latMS, tier, b, old.service, old.op, old.status, old.dir)
		if err != nil {
			return err
		}
		if k, _ := r.RowsAffected(); k == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_rollup`+where+` AND n <= 0`, tier, b, old.service, old.op, old.status, old.dir); err != nil {
			return err
		}
		if err := upsertRollupOp(ctx, tx, tier, b, newService, newOp, old.status, old.dir, 1, latMS, latMS, tsMS, tsMS); err != nil {
			return err
		}
		if newService == old.service {
			return nil
		}
		es, ec := 0, 0
		switch {
		case old.status == 0 || old.status >= 500:
			es = 1
		case old.status >= 400:
			ec = 1
		}
		const swhere = ` WHERE tier = ? AND bucket = ? AND service = ? AND source_id = ? AND policy_id = ? AND dir = ?`
		if _, err := tx.ExecContext(ctx, `UPDATE intake_rollup_src SET n = n - 1, err_server = err_server - ?, err_client = err_client - ?`+swhere,
			es, ec, tier, b, old.service, old.source, old.policyID, old.dir); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_rollup_src`+swhere+` AND n <= 0`, tier, b, old.service, old.source, old.policyID, old.dir); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_rollup_src (tier, bucket, service, source_id, policy_id, dir, n, err_server, err_client, first_ms, last_ms)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET n = n + 1, err_server = err_server + excluded.err_server, err_client = err_client + excluded.err_client,
				first_ms = min(first_ms, excluded.first_ms), last_ms = max(last_ms, excluded.last_ms)`,
			tier, b, newService, old.source, old.policyID, old.dir, es, ec, tsMS, tsMS); err != nil {
			return err
		}
		lb := RollupLatBucket(latMS)
		const lwhere = ` WHERE tier = ? AND bucket = ? AND service = ? AND dir = ? AND lb = ?`
		if _, err := tx.ExecContext(ctx, `UPDATE intake_rollup_lat SET n = n - 1`+lwhere, tier, b, old.service, old.dir, lb); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_rollup_lat`+lwhere+` AND n <= 0`, tier, b, old.service, old.dir, lb); err != nil {
			return err
		}
		return upsertRollupLat(ctx, tx, tier, b, newService, old.dir, lb, 1)
	}
	return nil
}

// CompactResult reports a compaction run.
type CompactResult struct {
	// Days and Months are the periods merged into a coarser tier; Rows the
	// rollup rows removed by the merge (net).
	Days, Months int
	Rows         int64
}

// CompactRollups merges the hourly rows of the days that ended before
// now-hourly into daily rows, and the daily rows of the months that ended
// before now-daily into monthly rows. One period per transaction.
func (s *Store) CompactRollups(ctx context.Context, now time.Time, hourly, daily time.Duration) (CompactResult, error) {
	var res CompactResult
	dayCut := bucketStart(TierDay, now.Add(-hourly).UnixMilli())
	for {
		first, err := s.minBucket(ctx, TierHour, dayCut)
		if err != nil {
			return res, err
		}
		if first < 0 {
			break
		}
		day := bucketStart(TierDay, first*1000)
		n, err := s.mergeTier(ctx, TierHour, TierDay, day, day+86400)
		if err != nil {
			return res, err
		}
		res.Days++
		res.Rows += n
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}
	monthCut := bucketStart(TierMonth, now.Add(-daily).UnixMilli())
	for {
		first, err := s.minBucket(ctx, TierDay, monthCut)
		if err != nil {
			return res, err
		}
		if first < 0 {
			break
		}
		month := bucketStart(TierMonth, first*1000)
		t := time.Unix(month, 0).UTC()
		end := time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC).Unix()
		n, err := s.mergeTier(ctx, TierDay, TierMonth, month, end)
		if err != nil {
			return res, err
		}
		res.Months++
		res.Rows += n
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}
	return res, nil
}

// minBucket returns the oldest bucket of tier before cut in any rollup
// table, or -1.
func (s *Store) minBucket(ctx context.Context, tier int, cut int64) (int64, error) {
	best := int64(-1)
	for _, t := range []string{"intake_rollup", "intake_rollup_src", "intake_rollup_lat"} {
		var mn sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT min(bucket) FROM `+t+` WHERE tier = ? AND bucket < ?`, tier, cut).Scan(&mn); err != nil {
			return 0, err
		}
		if mn.Valid && (best < 0 || mn.Int64 < best) {
			best = mn.Int64
		}
	}
	return best, nil
}

// mergeTier moves the rows of tier from in [lo, hi) into one row per key of
// tier to with bucket lo, in one transaction. It returns the net number of
// rows removed.
func (s *Store) mergeTier(ctx context.Context, from, to int, lo, hi int64) (int64, error) {
	var removed int64
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		count := func() (int64, error) {
			var n int64
			err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM intake_rollup WHERE tier IN (?, ?) AND bucket >= ? AND bucket < ?)
				+ (SELECT count(*) FROM intake_rollup_src WHERE tier IN (?, ?) AND bucket >= ? AND bucket < ?)
				+ (SELECT count(*) FROM intake_rollup_lat WHERE tier IN (?, ?) AND bucket >= ? AND bucket < ?)`,
				from, to, lo, hi, from, to, lo, hi, from, to, lo, hi).Scan(&n)
			return n, err
		}
		before, err := count()
		if err != nil {
			return err
		}
		stmts := []string{
			`INSERT INTO intake_rollup (tier, bucket, service, op, status, dir, n, lat_sum, lat_max, first_ms, last_ms)
			SELECT ?, ?, service, op, status, dir, sum(n), sum(lat_sum), max(lat_max), min(first_ms), max(last_ms)
			FROM intake_rollup WHERE tier = ? AND bucket >= ? AND bucket < ? GROUP BY service, op, status, dir
			ON CONFLICT DO UPDATE SET n = n + excluded.n, lat_sum = lat_sum + excluded.lat_sum, lat_max = max(lat_max, excluded.lat_max),
				first_ms = min(first_ms, excluded.first_ms), last_ms = max(last_ms, excluded.last_ms)`,
			`INSERT INTO intake_rollup_src (tier, bucket, service, source_id, policy_id, dir, n, err_server, err_client, first_ms, last_ms)
			SELECT ?, ?, service, source_id, policy_id, dir, sum(n), sum(err_server), sum(err_client), min(first_ms), max(last_ms)
			FROM intake_rollup_src WHERE tier = ? AND bucket >= ? AND bucket < ? GROUP BY service, source_id, policy_id, dir
			ON CONFLICT DO UPDATE SET n = n + excluded.n, err_server = err_server + excluded.err_server, err_client = err_client + excluded.err_client,
				first_ms = min(first_ms, excluded.first_ms), last_ms = max(last_ms, excluded.last_ms)`,
			`INSERT INTO intake_rollup_lat (tier, bucket, service, dir, lb, n)
			SELECT ?, ?, service, dir, lb, sum(n) FROM intake_rollup_lat WHERE tier = ? AND bucket >= ? AND bucket < ? GROUP BY service, dir, lb
			ON CONFLICT DO UPDATE SET n = n + excluded.n`,
		}
		for _, q := range stmts {
			// (An upsert after a SELECT needs a clause between FROM and ON
			// CONFLICT, SQLite parsing rule: the WHERE and GROUP BY are it.)
			if _, err := tx.ExecContext(ctx, q, to, lo, from, lo, hi); err != nil {
				return err
			}
		}
		for _, t := range []string{"intake_rollup", "intake_rollup_src", "intake_rollup_lat"} {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE tier = ? AND bucket >= ? AND bucket < ?`, from, lo, hi); err != nil {
				return err
			}
		}
		after, err := count()
		removed = before - after
		return err
	})
	return removed, err
}

// TrafficQuery selects rolled-up traffic. Zero fields do not filter.
type TrafficQuery struct {
	Service, Op string
	// Dir is "inbound" or "outbound".
	Dir string
	// From (inclusive) and To (exclusive) bound the bucket start.
	From, To time.Time
	// Step is the tier of the answer: TierHour, TierDay or TierMonth. Rows
	// of a coarser tier keep their own bucket (the resolution of old data
	// is the tier it was compacted to).
	Step int
}

// TrafficPoint is the traffic of one bucket.
type TrafficPoint struct {
	Bucket       time.Time `json:"bucket"`
	Tier         string    `json:"tier"`
	Calls        int64     `json:"calls"`
	ServerErrors int64     `json:"server_errors"`
	ClientErrors int64     `json:"client_errors"`
	LatencyAvgMS int64     `json:"latency_avg_ms"`
	LatencyP50MS int64     `json:"latency_p50_ms"`
	LatencyP95MS int64     `json:"latency_p95_ms"`
	LatencyMaxMS int64     `json:"latency_max_ms"`
}

// TierName is the API name of a tier.
func TierName(t int) string {
	switch t {
	case TierHour:
		return "hour"
	case TierDay:
		return "day"
	}
	return "month"
}

// Traffic returns the rolled-up traffic matching q, one point per bucket
// (ascending). Events not rolled up yet (the last minutes) are not included:
// run RollupPending first for an exact answer up to now.
func (s *Store) Traffic(ctx context.Context, q TrafficQuery) ([]TrafficPoint, error) {
	cond := ` WHERE bucket >= ? AND bucket < ?`
	from, to := int64(math.MinInt64/2), int64(math.MaxInt64/2)
	if !q.From.IsZero() {
		from = q.From.Unix()
	}
	if !q.To.IsZero() {
		to = q.To.Unix()
	}
	args := []any{from, to}
	if q.Service != "" {
		cond += ` AND service = ?`
		args = append(args, q.Service)
	}
	switch q.Dir {
	case "inbound":
		cond += ` AND dir = 0`
	case "outbound":
		cond += ` AND dir = 1`
	}
	type acc struct {
		tier               int
		n, es, ec, sum, mx int64
		hist               map[int64]int64
	}
	points := map[int64]*acc{}
	get := func(tier int, bucket int64) *acc {
		b := bucket
		if tier < q.Step {
			b = bucketStart(q.Step, bucket*1000)
			tier = q.Step
		}
		a := points[b]
		if a == nil {
			a = &acc{tier: tier, hist: map[int64]int64{}}
			points[b] = a
		}
		a.tier = max(a.tier, tier)
		return a
	}
	opCond, opArgs := cond, append([]any(nil), args...)
	if q.Op != "" {
		opCond += ` AND op = ?`
		opArgs = append(opArgs, q.Op)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT tier, bucket, sum(n), sum(lat_sum), max(lat_max),
		sum(CASE WHEN status = 0 OR status >= 500 THEN n ELSE 0 END), sum(CASE WHEN status >= 400 AND status < 500 THEN n ELSE 0 END)
		FROM intake_rollup`+opCond+` GROUP BY tier, bucket`, opArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var tier int
		var bucket, n, sum, mx, es, ec int64
		if err := rows.Scan(&tier, &bucket, &n, &sum, &mx, &es, &ec); err != nil {
			rows.Close()
			return nil, err
		}
		a := get(tier, bucket)
		a.n += n
		a.sum += sum
		a.mx = max(a.mx, mx)
		a.es += es
		a.ec += ec
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// The latency histogram is per service, not per operation.
	if q.Op == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT tier, bucket, lb, sum(n) FROM intake_rollup_lat`+cond+` GROUP BY tier, bucket, lb`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var tier int
			var bucket, lb, n int64
			if err := rows.Scan(&tier, &bucket, &lb, &n); err != nil {
				rows.Close()
				return nil, err
			}
			get(tier, bucket).hist[lb] += n
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	out := make([]TrafficPoint, 0, len(points))
	for b, a := range points {
		p := TrafficPoint{Bucket: time.Unix(b, 0).UTC(), Tier: TierName(a.tier), Calls: a.n, ServerErrors: a.es, ClientErrors: a.ec, LatencyMaxMS: a.mx}
		if a.n > 0 {
			p.LatencyAvgMS = a.sum / a.n
		}
		p.LatencyP50MS, p.LatencyP95MS = histQuantile(a.hist, 0.5), histQuantile(a.hist, 0.95)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket.Before(out[j].Bucket) })
	return out, nil
}

// histQuantile returns the representative value of the bucket holding the
// q-quantile (lower rank) of a rollup latency histogram.
func histQuantile(h map[int64]int64, q float64) int64 {
	if len(h) == 0 {
		return 0
	}
	keys := make([]int64, 0, len(h))
	var total int64
	for k, n := range h {
		keys = append(keys, k)
		total += n
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	rank := int64(math.Ceil(q * float64(total)))
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for _, k := range keys {
		seen += h[k]
		if seen >= rank {
			return RollupLatValue(k)
		}
	}
	return RollupLatValue(keys[len(keys)-1])
}

// HostStatsRange is HostStats over the events whose time falls in the
// buckets [from, to), from the rollups (any age, bucket resolution).
func (s *Store) HostStatsRange(ctx context.Context, from, to time.Time) ([]HostStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service, source_id, policy_id, sum(n), sum(err_server), sum(err_client), min(first_ms), max(last_ms)
		FROM intake_rollup_src WHERE dir = 1 AND bucket >= ? AND bucket < ?
		GROUP BY service, source_id, policy_id ORDER BY service, source_id, policy_id`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostStat
	for rows.Next() {
		var h HostStat
		var first, last int64
		if err := rows.Scan(&h.Service, &h.SourceID, &h.PolicyID, &h.Count, &h.ServerErrors, &h.ClientErrors, &first, &last); err != nil {
			return nil, err
		}
		h.FirstTS, h.LastTS = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostLatencyP50Range is HostLatencyP50 over the buckets [from, to), from
// the rollup histogram (about 9% error).
func (s *Store) HostLatencyP50Range(ctx context.Context, from, to time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service, lb, sum(n) FROM intake_rollup_lat WHERE dir = 1 AND bucket >= ? AND bucket < ?
		GROUP BY service, lb`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hist := map[string]map[int64]int64{}
	for rows.Next() {
		var svc string
		var lb, n int64
		if err := rows.Scan(&svc, &lb, &n); err != nil {
			return nil, err
		}
		if hist[svc] == nil {
			hist[svc] = map[int64]int64{}
		}
		hist[svc][lb] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(hist))
	for svc, h := range hist {
		out[svc] = histQuantile(h, 0.5)
	}
	return out, nil
}

// OpSummariesRange is OpSummaries over the buckets [from, to), from the
// rollups: it answers for periods whose raw events were purged.
func (s *Store) OpSummariesRange(ctx context.Context, from, to time.Time) ([]OpSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service, op, min(dir), status, sum(n), min(first_ms), max(last_ms)
		FROM intake_rollup WHERE bucket >= ? AND bucket < ? GROUP BY service, op, status ORDER BY service, op, status`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpSummary
	for rows.Next() {
		var o OpSummary
		var dir int
		var first, last int64
		if err := rows.Scan(&o.Service, &o.Op, &dir, &o.Status, &o.Count, &first, &last); err != nil {
			return nil, err
		}
		o.Dir = "inbound"
		if dir == 1 {
			o.Dir = "outbound"
		}
		o.FirstTS, o.LastTS = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}

// RollupTierStats counts the rollup rows and the oldest bucket per tier.
type RollupTierStats struct {
	Tier   string    `json:"tier"`
	Rows   int64     `json:"rows"`
	Oldest time.Time `json:"oldest"`
}

// RollupStats describes the rollup tiers (for /store/usage).
func (s *Store) RollupStats(ctx context.Context) ([]RollupTierStats, error) {
	var out []RollupTierStats
	for tier := TierHour; tier <= TierMonth; tier++ {
		var n int64
		var mn sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT count(*), min(bucket) FROM intake_rollup WHERE tier = ?`, tier).Scan(&n, &mn); err != nil {
			return nil, err
		}
		st := RollupTierStats{Tier: TierName(tier), Rows: n}
		if mn.Valid {
			st.Oldest = time.Unix(mn.Int64, 0).UTC()
		}
		out = append(out, st)
	}
	return out, nil
}
