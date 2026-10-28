package intake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Store is the read side of the accepted-event storage, for the analyzers
// (contract inference, drift, rule miner, exporters) and the admin API.
// It is safe for concurrent use; reads do not block ingestion (WAL).
type Store struct {
	db *store.DB
	// aggReady caches AggregatesReady once true (agg.go).
	aggReady atomic.Bool
}

// NewStore returns a Store on a database opened with store.Open (so that the
// intake migrations were applied; this package registers them in init).
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// StoredEvent is an accepted event with its storage metadata.
type StoredEvent struct {
	ID         int64
	ReceivedAt time.Time
	Event      *event.Event
}

// Query selects stored events. Zero fields do not filter.
type Query struct {
	Service  string
	Op       string
	Dir      string // "inbound" or "outbound"
	PolicyID string
	SourceID string
	// SourceIDs restricts the events to these sources (the sources of one
	// group: group-scoped views). A non-nil empty slice matches nothing.
	SourceIDs []string
	// Status filters on the exact status; NetErrorOnly selects exchanges
	// that ended in a network error (no status).
	Status       int
	NetErrorOnly bool
	// From (inclusive) and To (exclusive) bound the event time.
	From, To time.Time
	TraceID  string
	Subject  string
	// AfterID is the keyset cursor: only events with a greater id.
	AfterID int64
	// Limit bounds the number of events returned (0 = no limit).
	Limit int
	// ByTime orders by event time (then id) instead of by id. With ByTime
	// and a full (Service, Op, Status) the order comes straight from the
	// index; AfterID must not be used.
	ByTime bool
	// SampleEvery > 1 keeps about one event in SampleEvery, chosen by a hash
	// of the id: the test runs on the index entries, so the rows left out
	// are never read (sampling a large group without decoding all of it).
	SampleEvery int64
	// AnyOrder drops the ORDER BY: rows come in the order of the index the
	// planner picks, and a Limit stops the scan after that many rows (a
	// sample; ordering by id first sorts every matching row).
	AnyOrder bool
}

func (q *Query) where() (string, []any) {
	var cond []string
	var args []any
	add := func(c string, a ...any) {
		cond = append(cond, c)
		args = append(args, a...)
	}
	if q.Service != "" {
		add("service = ?", q.Service)
	}
	if q.Op != "" {
		add("op = ?", q.Op)
	}
	switch q.Dir {
	case event.Inbound:
		add("dir = 0")
	case event.Outbound:
		add("dir = 1")
	}
	if q.PolicyID != "" {
		add("policy_id = ?", q.PolicyID)
	}
	if q.SourceID != "" {
		add("source_id = ?", q.SourceID)
	}
	if q.SourceIDs != nil {
		if len(q.SourceIDs) == 0 {
			add("0")
		} else {
			ph := strings.TrimSuffix(strings.Repeat("?,", len(q.SourceIDs)), ",")
			a := make([]any, len(q.SourceIDs))
			for i, id := range q.SourceIDs {
				a[i] = id
			}
			add("source_id IN ("+ph+")", a...)
		}
	}
	if q.NetErrorOnly {
		add("status IS NULL")
	} else if q.Status != 0 {
		add("status = ?", q.Status)
	}
	if !q.From.IsZero() {
		add("ts_ms >= ?", q.From.UnixMilli())
	}
	if !q.To.IsZero() {
		add("ts_ms < ?", q.To.UnixMilli())
	}
	if q.TraceID != "" {
		add("trace_id = ?", q.TraceID)
	}
	if q.Subject != "" {
		add("subject = ?", q.Subject)
	}
	if q.AfterID > 0 {
		add("id > ?", q.AfterID)
	}
	if q.SampleEvery > 1 {
		add("(id * 2654435761 % 4294967291) % ? = 0", q.SampleEvery)
	}
	if len(cond) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(cond, " AND "), args
}

// ErrStop can be returned by a callback to stop a scan without an error.
var ErrStop = errors.New("intake: stop scan")

// Scan calls fn for each stored event matching q. Returning [ErrStop] from fn
// ends the scan successfully.
func (s *Store) Scan(ctx context.Context, q Query, fn func(*StoredEvent) error) error {
	w, args := q.where()
	order := " ORDER BY id"
	switch {
	case q.AnyOrder:
		order = ""
	case q.ByTime:
		order = " ORDER BY ts_ms, id"
	}
	sqlText := "SELECT id, received_ms, body FROM intake_events" + w + order
	if q.Limit > 0 {
		sqlText += fmt.Sprintf(" LIMIT %d", q.Limit)
	}
	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rcv int64
		var body []byte
		if err := rows.Scan(&id, &rcv, &body); err != nil {
			return err
		}
		ev, derr := event.Decode(body)
		if derr != nil {
			return fmt.Errorf("intake: stored event %d is not canonical: %w", id, derr)
		}
		if err := fn(&StoredEvent{ID: id, ReceivedAt: time.UnixMilli(rcv).UTC(), Event: ev}); err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}
			return err
		}
	}
	return rows.Err()
}

// Get returns the stored event with the given id.
func (s *Store) Get(ctx context.Context, id int64) (*StoredEvent, error) {
	var rcv int64
	var body []byte
	err := s.db.QueryRowContext(ctx, `SELECT received_ms, body FROM intake_events WHERE id = ?`, id).Scan(&rcv, &body)
	if err != nil {
		return nil, err
	}
	ev, derr := event.Decode(body)
	if derr != nil {
		return nil, fmt.Errorf("intake: stored event %d is not canonical: %w", id, derr)
	}
	return &StoredEvent{ID: id, ReceivedAt: time.UnixMilli(rcv).UTC(), Event: ev}, nil
}

// Count returns the number of stored events.
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM intake_events`).Scan(&n)
	return n, err
}

// OpSummary counts the stored events of one (service, op, status) group:
// the unit of contract inference.
type OpSummary struct {
	Service string
	Op      string
	Dir     string
	// Status is 0 for exchanges that ended in a network error.
	Status  int
	Count   int64
	FirstTS time.Time
	LastTS  time.Time
}

// OpSummaries groups events by (service, op, status) over an event-time
// window (zero times are open ends), using the covering index.
//
// Without a window (both ends zero) it reads the ingest aggregates (agg.go):
// constant time in the number of stored events.
func (s *Store) OpSummaries(ctx context.Context, from, to time.Time) ([]OpSummary, error) {
	return s.OpSummariesFor(ctx, from, to, nil)
}

// OpSummariesFor is OpSummaries restricted to the events of the given
// sources (nil: every source; the sources of one group for group-scoped
// contracts and lists).
func (s *Store) OpSummariesFor(ctx context.Context, from, to time.Time, sources []string) ([]OpSummary, error) {
	q := Query{From: from, To: to, SourceIDs: sources}
	w, args := q.where()
	query := `SELECT service, op, min(dir), coalesce(status, 0), count(*), min(ts_ms), max(ts_ms)
		FROM intake_events` + w + ` GROUP BY service, op, status ORDER BY service, op, status`
	if from.IsZero() && to.IsZero() && s.AggregatesReady(ctx) {
		aq := Query{SourceIDs: sources}
		aw, aargs := aq.where()
		query, args = `SELECT service, op, min(dir), status, sum(n), min(first_ms), max(last_ms)
		FROM intake_agg`+aw+` GROUP BY service, op, status ORDER BY service, op, status`, aargs
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
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
		o.Dir = event.Inbound
		if dir == 1 {
			o.Dir = event.Outbound
		}
		o.FirstTS, o.LastTS = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}

// HostStat aggregates the stored outbound events of one (service, source,
// policy): the unit of the hosts registry (admin-api listHosts, spec v1.5).
// Service is a declared outbound service name, a host pattern
// ("host:{*}.tracking.example"), host:unlisted or host:invalid.
type HostStat struct {
	Service  string
	SourceID string
	PolicyID string
	Count    int64
	// ServerErrors counts responses with status >= 500 and network errors;
	// ClientErrors responses with status 400-499.
	ServerErrors int64
	ClientErrors int64
	FirstTS      time.Time
	LastTS       time.Time
}

// HostStats groups the outbound events by (service, source, policy).
// It reads the ingest aggregates once they cover every stored event.
func (s *Store) HostStats(ctx context.Context) ([]HostStat, error) {
	query := `SELECT service, source_id, policy_id, count(*),
		sum(CASE WHEN net_error IS NOT NULL OR status >= 500 THEN 1 ELSE 0 END),
		sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END),
		min(ts_ms), max(ts_ms)
		FROM intake_events WHERE dir = 1 GROUP BY service, source_id, policy_id ORDER BY service, source_id, policy_id`
	if s.AggregatesReady(ctx) {
		query = `SELECT service, source_id, policy_id, sum(n),
		sum(CASE WHEN status = 0 OR status >= 500 THEN n ELSE 0 END),
		sum(CASE WHEN status >= 400 AND status < 500 THEN n ELSE 0 END),
		min(first_ms), max(last_ms)
		FROM intake_agg WHERE dir = 1 GROUP BY service, source_id, policy_id ORDER BY service, source_id, policy_id`
	}
	rows, err := s.db.QueryContext(ctx, query)
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

// HostLatencyP50 returns the median latency in milliseconds of the outbound
// events of each service (the lower median for an even count). From the
// ingest aggregates the value is the histogram bucket (latBucket: exact below
// 100 ms, two significant digits above).
func (s *Store) HostLatencyP50(ctx context.Context) (map[string]int64, error) {
	query := `SELECT service, latency_ms, count(*) FROM intake_events WHERE dir = 1
		GROUP BY service, latency_ms ORDER BY service, latency_ms`
	if s.AggregatesReady(ctx) {
		query = `SELECT service, lat, n FROM intake_agg_lat ORDER BY service, lat`
	}
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type bucket struct{ ms, n int64 }
	hist := map[string][]bucket{}
	for rows.Next() {
		var svc string
		var b bucket
		if err := rows.Scan(&svc, &b.ms, &b.n); err != nil {
			return nil, err
		}
		hist[svc] = append(hist[svc], b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(hist))
	for svc, bs := range hist {
		var total int64
		for _, b := range bs {
			total += b.n
		}
		rank := (total + 1) / 2
		var seen int64
		for _, b := range bs {
			seen += b.n
			if seen >= rank {
				out[svc] = b.ms
				break
			}
		}
	}
	return out, nil
}

// TokenHit is one occurrence of an HMAC token.
type TokenHit struct {
	EventID int64
	TS      time.Time
	// Field says where the token was seen: "subject", "req.path[1]",
	// "req.query.orderId", "resp.body$.items[*].id", ...
	Field string
}

func hourOf(t time.Time) int64 { return t.Unix() / 3600 }

// TokenHits returns the occurrences of a token in events received between
// from and to (zero = open), ordered by reception hour and event id.
func (s *Store) TokenHits(ctx context.Context, token string, from, to time.Time) ([]TokenHit, error) {
	lo, hi, err := s.hourRange(ctx, from, to)
	if err != nil || lo > hi {
		return nil, err
	}
	var out []TokenHit
	// One probe per hour partition: the primary key starts with the hour.
	for h := lo; h <= hi; h++ {
		rows, err := s.db.QueryContext(ctx, `SELECT t.event_id, t.ts_ms, coalesce(f.field, '')
			FROM intake_tokens t LEFT JOIN intake_fields f ON f.id = t.field
			WHERE t.hour = ? AND t.token = ? ORDER BY t.event_id`, h, token)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hit TokenHit
			var ts int64
			if err := rows.Scan(&hit.EventID, &ts, &hit.Field); err != nil {
				rows.Close()
				return nil, err
			}
			hit.TS = time.UnixMilli(ts).UTC()
			out = append(out, hit)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// hourRange clamps the requested window to the hours present in the index.
func (s *Store) hourRange(ctx context.Context, from, to time.Time) (lo, hi int64, err error) {
	var mn, mx sql.NullInt64
	if err = s.db.QueryRowContext(ctx, `SELECT min(hour), max(hour) FROM intake_tokens`).Scan(&mn, &mx); err != nil {
		return 0, 0, err
	}
	if !mn.Valid {
		return 1, 0, nil
	}
	lo, hi = mn.Int64, mx.Int64
	if !from.IsZero() && hourOf(from) > lo {
		lo = hourOf(from)
	}
	if !to.IsZero() && hourOf(to) < hi {
		hi = hourOf(to)
	}
	return lo, hi, nil
}

// ScanTokens streams the token index of events received in [from, to)
// ordered by (hour, token, event id): all occurrences of a token within an
// hour are adjacent, which is the access pattern of the rule miner.
func (s *Store) ScanTokens(ctx context.Context, from, to time.Time, fn func(token string, hit TokenHit) error) error {
	lo, hi, err := s.hourRange(ctx, from, to)
	if err != nil {
		return err
	}
	for h := lo; h <= hi; h++ {
		rows, err := s.db.QueryContext(ctx, `SELECT t.token, t.event_id, t.ts_ms, coalesce(f.field, '')
			FROM intake_tokens t LEFT JOIN intake_fields f ON f.id = t.field
			WHERE t.hour = ? ORDER BY t.token, t.event_id`, h)
		if err != nil {
			return err
		}
		for rows.Next() {
			var tok string
			var hit TokenHit
			var ts int64
			if err := rows.Scan(&tok, &hit.EventID, &ts, &hit.Field); err != nil {
				rows.Close()
				return err
			}
			hit.TS = time.UnixMilli(ts).UTC()
			if err := fn(tok, hit); err != nil {
				rows.Close()
				if errors.Is(err, ErrStop) {
					return nil
				}
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

// PurgeResult reports a retention run.
type PurgeResult struct {
	Events int64
	Tokens int64
	// RolledUp is the number of events counted into the rollups first.
	RolledUp int64
	// Reclaimed is the number of bytes handed back to the file system after
	// the deletion (incremental auto_vacuum); ReclaimNote says why nothing
	// was reclaimed when the database cannot ("legacy database: run tt compact").
	Reclaimed   int64
	ReclaimNote string
}

// PurgeBefore deletes the events received before cutoff and the matching
// token index partitions (whole hours before the hour of cutoff), in small
// transactions so that ingestion is not starved. Deleted pages are
// overwritten (secure_delete is on).
func (s *Store) PurgeBefore(ctx context.Context, cutoff time.Time) (PurgeResult, error) {
	return s.PurgeBeforeProgress(ctx, cutoff, nil)
}

// PurgeProgress is reported by PurgeBeforeProgress after every chunk.
type PurgeProgress struct {
	// Phase is "events", "tokens", "sketches" or "reclaim".
	Phase string
	// Events and Tokens are the rows deleted so far; EventsEstimated is the
	// number of events to delete (an estimate: ids may have gaps).
	Events, Tokens, EventsEstimated int64
}

// PurgeBeforeProgress is PurgeBefore reporting its progress to fn (may be
// nil) after every chunk of deleted events and every token partition.
func (s *Store) PurgeBeforeProgress(ctx context.Context, cutoff time.Time, fn func(PurgeProgress)) (PurgeResult, error) {
	var res PurgeResult
	// Count the events into the time-bucketed rollups before any is deleted
	// (rollup.go), and never delete past the rollup cursor.
	ru, err := s.RollupPending(ctx)
	if err != nil {
		return res, fmt.Errorf("intake: rollup before purge: %w", err)
	}
	res.RolledUp = ru.Events
	bound, err := s.boundaryID(ctx, cutoff.UnixMilli())
	if err != nil {
		return res, err
	}
	bound = min(bound, ru.Cursor-1)
	report := func(phase string, est int64) {
		if fn != nil {
			fn(PurgeProgress{Phase: phase, Events: res.Events, Tokens: res.Tokens, EventsEstimated: est})
		}
	}
	var est int64
	if bound > 0 {
		var first sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT min(id) FROM intake_events`).Scan(&first); err != nil {
			return res, err
		}
		if first.Valid && bound >= first.Int64 {
			est = bound - first.Int64 + 1
		}
	}
	report("events", est)
	const chunk = 1000 // events per transaction (each also deletes 4 index entries): short write locks
	for bound > 0 {
		var lo sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT min(id) FROM intake_events`).Scan(&lo); err != nil {
			return res, err
		}
		if !lo.Valid || lo.Int64 > bound {
			break
		}
		upTo := lo.Int64 + chunk - 1
		if upTo > bound {
			upTo = bound
		}
		// Subtract the chunk from the ingest aggregates in the same
		// transaction; the time it takes sets the pause after it.
		t0 := time.Now()
		var n int64
		err := s.db.InTx(ctx, func(tx *sql.Tx) error {
			c, err := readAggCursor(ctx, tx)
			if err != nil {
				return err
			}
			d := newAggDelta()
			if err := d.subtractRange(ctx, tx, c, lo.Int64, upTo); err != nil {
				return err
			}
			if err := d.apply(ctx, tx); err != nil {
				return err
			}
			r, err := tx.ExecContext(ctx, `DELETE FROM intake_events WHERE id <= ?`, upTo)
			if err != nil {
				return err
			}
			n, _ = r.RowsAffected()
			return nil
		})
		if err != nil {
			return res, err
		}
		res.Events += n
		report("events", est)
		if err := purgePauseFor(ctx, time.Since(t0)); err != nil {
			return res, err
		}
	}
	cutHour := hourOf(cutoff)
	var mn sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT min(hour) FROM intake_tokens`).Scan(&mn); err != nil {
		return res, err
	}
	if mn.Valid {
		for h := mn.Int64; h < cutHour; h++ {
			n, err := s.purgeTokenHour(ctx, h)
			res.Tokens += n
			if err != nil {
				return res, err
			}
			report("tokens", est)
		}
	}
	report("sketches", est)
	day := cutoff.Unix() / 86400
	if _, err := s.db.ExecContext(ctx, `DELETE FROM intake_sketch WHERE kind <> ? AND day < ?`, int(obsDisc), day-1); err != nil {
		return res, err
	}
	// Deleted rows only become free pages: hand them back to the file system
	// (a few thousand pages per short transaction, so ingestion goes on).
	if res.Events > 0 || res.Tokens > 0 {
		report("reclaim", est)
		freed, err := s.db.Reclaim(ctx)
		res.Reclaimed = freed
		switch {
		case errors.Is(err, store.ErrNoIncrementalVacuum):
			res.ReclaimNote = "legacy database (auto_vacuum off): the file keeps its size; stop the core and run \"tt compact\" once"
		case err != nil && ctx.Err() != nil:
			return res, ctx.Err()
		case err != nil:
			res.ReclaimNote = "reclaim failed: " + err.Error()
		}
	}
	return res, nil
}

// boundaryID returns the largest id whose received_ms is before cutoffMS, or
// 0. received_ms never decreases with the id, so a binary search over the
// primary key finds it.
func (s *Store) boundaryID(ctx context.Context, cutoffMS int64) (int64, error) {
	var lo, hi sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT min(id), max(id) FROM intake_events`).Scan(&lo, &hi); err != nil {
		return 0, err
	}
	if !lo.Valid {
		return 0, nil
	}
	rcvAt := func(id int64) (int64, bool, error) {
		// First row at or after id (ids may have gaps after rewrites/purges).
		var r int64
		err := s.db.QueryRowContext(ctx, `SELECT received_ms FROM intake_events WHERE id >= ? ORDER BY id LIMIT 1`, id).Scan(&r)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return r, err == nil, err
	}
	// Invariant: ids <= a are old (or a is the start), ids > b are new.
	a, b := lo.Int64-1, hi.Int64
	best := int64(0)
	for a < b {
		mid := a + (b-a+1)/2
		r, ok, err := rcvAt(mid)
		if err != nil {
			return 0, err
		}
		if ok && r < cutoffMS {
			best = mid
			a = mid
		} else {
			b = mid - 1
		}
	}
	if best == 0 {
		return 0, nil
	}
	// Extend to the last row with the same old timestamp class.
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT max(id) FROM intake_events WHERE id <= ? AND received_ms < ?`, best, cutoffMS).Scan(&id)
	if err != nil {
		return 0, nil
	}
	return id, nil
}
