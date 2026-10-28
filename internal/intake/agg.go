package intake

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

// Aggregates of the stored events, maintained at ingest (schema version 2).
//
// intake_agg counts the events by (service, op, status, source, policy,
// direction) with the first and last event time; intake_agg_lat is the
// histogram of the outbound latencies by service (latBucket). They answer the
// services and hosts lists without scanning intake_events, which on a large
// store (millions of rows) took seconds per request.
//
// They stay exact:
//   - the writer adds every batch in the transaction that inserts it;
//   - the retention purge subtracts each chunk before deleting it;
//   - a quarantine rewrite moves the event from its old key to the new one.
//
// A database created before version 2 already holds events: the migration
// records the id range they occupy (intake_agg_state: next..hi) and
// backfillAggregates adds them in small chunks in the background. Until the
// backfill is done the readers fall back to the event scans, and purge and
// rewrites only touch the events already aggregated (id < next or id > hi).

type aggKey struct {
	service, op      string
	status           int
	source, policyID string
	dir              int
}

type aggVal struct{ n, first, last int64 }

type latKey struct {
	service string
	lat     int64
}

// aggDelta accumulates changes to the aggregates within a transaction.
type aggDelta struct {
	rows map[aggKey]*aggVal
	lat  map[latKey]int64
}

func newAggDelta() *aggDelta {
	return &aggDelta{rows: map[aggKey]*aggVal{}, lat: map[latKey]int64{}}
}

// latBucket quantizes a latency for the histogram: exact below 100 ms, then
// two significant digits (relative error below 10%, a few hundred buckets
// per service at most).
func latBucket(ms int64) int64 {
	if ms < 100 {
		if ms < 0 {
			return 0
		}
		return ms
	}
	p := int64(math.Pow10(int(math.Floor(math.Log10(float64(ms)))) - 1))
	return ms / p * p
}

// add records n events (negative to remove) of key k with event times
// first..last and, for outbound events, n latencies of bucket lat.
func (d *aggDelta) add(k aggKey, n, first, last int64) {
	v := d.rows[k]
	if v == nil {
		v = &aggVal{first: first, last: last}
		d.rows[k] = v
	}
	v.n += n
	v.first = min(v.first, first)
	v.last = max(v.last, last)
}

func (d *aggDelta) addLat(service string, latMS, n int64) {
	d.lat[latKey{service, latBucket(latMS)}] += n
}

func (d *aggDelta) empty() bool { return len(d.rows) == 0 && len(d.lat) == 0 }

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// apply writes the delta in tx. Rows that drop to zero are deleted.
func (d *aggDelta) apply(ctx context.Context, tx execer) error {
	for k, v := range d.rows {
		switch {
		case v.n > 0:
			if _, err := tx.ExecContext(ctx, `INSERT INTO intake_agg (service, op, status, source_id, policy_id, dir, n, first_ms, last_ms)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT DO UPDATE SET n = n + excluded.n, first_ms = min(first_ms, excluded.first_ms), last_ms = max(last_ms, excluded.last_ms)`,
				k.service, k.op, k.status, k.source, k.policyID, k.dir, v.n, v.first, v.last); err != nil {
				return err
			}
		case v.n < 0:
			const where = ` WHERE service = ? AND op = ? AND status = ? AND source_id = ? AND policy_id = ? AND dir = ?`
			if _, err := tx.ExecContext(ctx, `UPDATE intake_agg SET n = n + ?`+where, v.n, k.service, k.op, k.status, k.source, k.policyID, k.dir); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM intake_agg`+where+` AND n <= 0`, k.service, k.op, k.status, k.source, k.policyID, k.dir); err != nil {
				return err
			}
		}
	}
	for k, n := range d.lat {
		switch {
		case n > 0:
			if _, err := tx.ExecContext(ctx, `INSERT INTO intake_agg_lat (service, lat, n) VALUES (?, ?, ?)
				ON CONFLICT DO UPDATE SET n = n + excluded.n`, k.service, k.lat, n); err != nil {
				return err
			}
		case n < 0:
			if _, err := tx.ExecContext(ctx, `UPDATE intake_agg_lat SET n = n + ? WHERE service = ? AND lat = ?`, n, k.service, k.lat); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM intake_agg_lat WHERE service = ? AND lat = ? AND n <= 0`, k.service, k.lat); err != nil {
				return err
			}
		}
	}
	return nil
}

// addRange adds (sign +1) or removes (sign -1) the stored events lo <= id <= hi.
func (d *aggDelta) addRange(ctx context.Context, tx execer, lo, hi, sign int64) error {
	if lo > hi {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT service, op, coalesce(status, 0), source_id, policy_id, dir, count(*), min(ts_ms), max(ts_ms)
		FROM intake_events WHERE id BETWEEN ? AND ? GROUP BY service, op, status, source_id, policy_id, dir`, lo, hi)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k aggKey
		var n, first, last int64
		if err := rows.Scan(&k.service, &k.op, &k.status, &k.source, &k.policyID, &k.dir, &n, &first, &last); err != nil {
			rows.Close()
			return err
		}
		d.add(k, sign*n, first, last)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT service, latency_ms, count(*) FROM intake_events WHERE dir = 1 AND id BETWEEN ? AND ?
		GROUP BY service, latency_ms`, lo, hi)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var svc string
		var ms, n int64
		if err := rows.Scan(&svc, &ms, &n); err != nil {
			return err
		}
		d.addLat(svc, ms, sign*n)
	}
	return rows.Err()
}

// aggCursor is the backfill state: the events next <= id <= hi are not in
// the aggregates yet.
type aggCursor struct{ next, hi int64 }

func (c aggCursor) done() bool { return c.next > c.hi }

// covers reports whether event id is already counted in the aggregates.
func (c aggCursor) covers(id int64) bool { return id > c.hi || id < c.next }

func readAggCursor(ctx context.Context, q execer) (aggCursor, error) {
	var c aggCursor
	rows, err := q.QueryContext(ctx, `SELECT k, v FROM intake_agg_state`)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err != nil {
			return c, err
		}
		switch k {
		case "next":
			c.next, seen = v, seen+1
		case "hi":
			c.hi, seen = v, seen+1
		}
	}
	if err := rows.Err(); err != nil {
		return c, err
	}
	if seen != 2 {
		return c, errors.New("intake: aggregate state missing")
	}
	return c, nil
}

// subtractRange removes the aggregated events among lo <= id <= hi (purge).
func (d *aggDelta) subtractRange(ctx context.Context, tx execer, c aggCursor, lo, hi int64) error {
	if err := d.addRange(ctx, tx, lo, min(hi, c.next-1), -1); err != nil {
		return err
	}
	return d.addRange(ctx, tx, max(lo, c.hi+1), hi, -1)
}

// aggBackfillChunk is the number of event ids aggregated per transaction.
const aggBackfillChunk = 20_000

// backfillStep aggregates the next chunk of old events. It reports whether
// the backfill is complete.
func (s *Store) backfillStep(ctx context.Context) (bool, error) {
	done := false
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		c, err := readAggCursor(ctx, tx)
		if err != nil {
			return err
		}
		if c.done() {
			done = true
			return nil
		}
		end := min(c.next+aggBackfillChunk-1, c.hi)
		d := newAggDelta()
		if err := d.addRange(ctx, tx, c.next, end, 1); err != nil {
			return err
		}
		if err := d.apply(ctx, tx); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE intake_agg_state SET v = ? WHERE k = 'next'`, end+1)
		done = end >= c.hi
		return err
	})
	if done && err == nil {
		s.aggReady.Store(true)
	}
	return done, err
}

// BackfillAggregates aggregates the events stored before the aggregates
// existed, chunk by chunk, until done or ctx ends.
func (s *Store) BackfillAggregates(ctx context.Context, pause time.Duration) error {
	for {
		t0 := time.Now()
		done, err := s.backfillStep(ctx)
		if err != nil || done {
			return err
		}
		if pause > 0 {
			// At least as long as the chunk: half of the writer's time at most.
			t := time.NewTimer(max(pause, time.Since(t0)))
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		} else if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// AggregatesReady reports whether the aggregates cover every stored event
// (the backfill of an older database is complete).
func (s *Store) AggregatesReady(ctx context.Context) bool {
	if s.aggReady.Load() {
		return true
	}
	c, err := readAggCursor(ctx, s.db)
	if err != nil || !c.done() {
		return false
	}
	s.aggReady.Store(true)
	return true
}

// ServiceSources returns, for each stored service, the sources whose events
// carry it (from the aggregates once they are complete).
func (s *Store) ServiceSources(ctx context.Context) (map[string][]string, error) {
	query := `SELECT DISTINCT service, source_id FROM intake_events ORDER BY service, source_id`
	if s.AggregatesReady(ctx) {
		query = `SELECT DISTINCT service, source_id FROM intake_agg ORDER BY service, source_id`
	}
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var svc, src string
		if err := rows.Scan(&svc, &src); err != nil {
			return nil, err
		}
		out[svc] = append(out[svc], src)
	}
	return out, rows.Err()
}

// backfillAggregates runs the backfill in the background (Intake.New).
func (in *Intake) backfillAggregates() {
	if in.store.AggregatesReady(in.bgCtx) {
		return
	}
	in.log.Info("intake: aggregating the events stored before this version (services and hosts lists use the event scan until done)")
	start := time.Now()
	if err := in.store.BackfillAggregates(in.bgCtx, 10*time.Millisecond); err != nil {
		if in.bgCtx.Err() == nil {
			in.log.Error("intake: aggregate backfill failed (it resumes at the next start)", "error", err)
		}
		return
	}
	in.log.Info("intake: aggregate backfill done", "duration", time.Since(start).Round(time.Millisecond).String())
}
