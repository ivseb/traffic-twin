package intake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// EventMeta is the part of a stored event kept in its own columns: what an
// aggregate over many events usually needs, without reading and decoding
// the body (several times cheaper, and no per-event allocation of a tree).
type EventMeta struct {
	ID         int64
	ReceivedAt time.Time
	Time       time.Time
	Dir        string
	Service    string
	Op         string
	Status     int // 0 with a network error
	NetError   string
	LatencyMS  int64
	Subject    string
	SourceID   string
	PolicyID   string
	TraceID    string
}

// MetaScanner is implemented by event sources that can stream EventMeta
// (*Store does); analyzers use it when they do not need the bodies.
type MetaScanner interface {
	ScanMeta(ctx context.Context, q Query, fn func(*EventMeta) error) error
}

// ScanMeta is Scan without the bodies: fn receives the scalar columns of
// each matching event (the same selection, order and limit as Scan). The
// EventMeta passed to fn is reused between calls.
func (s *Store) ScanMeta(ctx context.Context, q Query, fn func(*EventMeta) error) error {
	w, args := q.where()
	order := " ORDER BY id"
	switch {
	case q.AnyOrder:
		order = ""
	case q.ByTime:
		order = " ORDER BY ts_ms, id"
	}
	sqlText := `SELECT id, received_ms, ts_ms, dir, service, op, coalesce(status, 0), coalesce(net_error, ''), latency_ms,
		coalesce(subject, ''), source_id, policy_id, coalesce(trace_id, '') FROM intake_events` + w + order
	if q.Limit > 0 {
		sqlText += fmt.Sprintf(" LIMIT %d", q.Limit)
	}
	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var m EventMeta
	for rows.Next() {
		var rcv, ts int64
		var dir int
		if err := rows.Scan(&m.ID, &rcv, &ts, &dir, &m.Service, &m.Op, &m.Status, &m.NetError, &m.LatencyMS,
			&m.Subject, &m.SourceID, &m.PolicyID, &m.TraceID); err != nil {
			return err
		}
		m.ReceivedAt, m.Time = time.UnixMilli(rcv).UTC(), time.UnixMilli(ts).UTC()
		m.Dir = event.Inbound
		if dir == 1 {
			m.Dir = event.Outbound
		}
		if err := fn(&m); err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}
			return err
		}
	}
	return rows.Err()
}

// NewestSince returns the event time from which the window ending at to
// holds at most n events (the time of the n-th newest event before to), and
// false when the whole window [from, to) holds n events or fewer. It walks
// the time index only.
func (s *Store) NewestSince(ctx context.Context, from, to time.Time, n int) (time.Time, bool, error) {
	if n <= 0 {
		return time.Time{}, false, nil
	}
	var ts sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT ts_ms FROM intake_events WHERE ts_ms >= ? AND ts_ms < ? ORDER BY ts_ms DESC LIMIT 1 OFFSET ?`,
		from.UnixMilli(), to.UnixMilli(), n).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !ts.Valid) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	// Events at exactly that millisecond are left out with it: strictly
	// fewer than n remain.
	return time.UnixMilli(ts.Int64 + 1).UTC(), true, nil
}

// OpSummariesOf is OpSummaries for one service: the groups come from the
// (service, op, status, ts_ms) index alone, without visiting the rows of the
// other services nor the table (contract snapshot of one service: the
// window of every other service used to be read for each of them).
func (s *Store) OpSummariesOf(ctx context.Context, service string, from, to time.Time) ([]OpSummary, error) {
	return s.OpSummariesOfFor(ctx, service, from, to, nil)
}

// OpSummariesOfFor is OpSummariesOf restricted to the events of the given
// sources (nil: every source).
//
// Without a window and with sources (a group's live contract: the rule
// editor catalog, the contracts preview) it reads the ingest aggregates:
// filtering the index by source visits the rows of every other group's
// events of the same service name (seconds on a store of millions).
func (s *Store) OpSummariesOfFor(ctx context.Context, service string, from, to time.Time, sources []string) ([]OpSummary, error) {
	if sources != nil && from.IsZero() && to.IsZero() && s.AggregatesReady(ctx) {
		all, err := s.opSummariesAgg(ctx, service, sources)
		if err == nil {
			return all, nil
		}
	}
	q := Query{Service: service, From: from, To: to, SourceIDs: sources}
	w, args := q.where()
	rows, err := s.db.QueryContext(ctx, `SELECT op, coalesce(status, 0), count(*), min(ts_ms), max(ts_ms)
		FROM intake_events`+w+` GROUP BY op, status ORDER BY op, status`, args...)
	if err != nil {
		return nil, err
	}
	var out []OpSummary
	for rows.Next() {
		o := OpSummary{Service: service}
		var first, last int64
		if err := rows.Scan(&o.Op, &o.Status, &o.Count, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		o.FirstTS, o.LastTS = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// The direction is a property of the operation (a service is captured
	// inbound or outbound): one row of each operation tells it.
	dirs := map[string]string{}
	for i := range out {
		d, ok := dirs[out[i].Op]
		if !ok {
			var dir int
			if err := s.db.QueryRowContext(ctx, `SELECT dir FROM intake_events WHERE service = ? AND op = ? LIMIT 1`, service, out[i].Op).Scan(&dir); err != nil {
				return nil, err
			}
			d = event.Inbound
			if dir == 1 {
				d = event.Outbound
			}
			dirs[out[i].Op] = d
		}
		out[i].Dir = d
	}
	return out, nil
}

// CountWindow returns the number of events with event time in [from, to)
// (zero times are open ends), of one service when service is not empty:
// a walk of an index, no row is read.
func (s *Store) CountWindow(ctx context.Context, from, to time.Time, service string) (int, error) {
	q := Query{From: from, To: to, Service: service}
	w, args := q.where()
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM intake_events`+w, args...).Scan(&n)
	return n, err
}

// opSummariesAgg is OpSummariesOfFor over the ingest aggregates (agg.go).
func (s *Store) opSummariesAgg(ctx context.Context, service string, sources []string) ([]OpSummary, error) {
	aq := Query{Service: service, SourceIDs: sources}
	aw, aargs := aq.where()
	rows, err := s.db.QueryContext(ctx, `SELECT op, min(dir), status, sum(n), min(first_ms), max(last_ms)
		FROM intake_agg`+aw+` GROUP BY op, status ORDER BY op, status`, aargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpSummary
	for rows.Next() {
		o := OpSummary{Service: service, Dir: event.Inbound}
		var dir int
		var first, last int64
		if err := rows.Scan(&o.Op, &dir, &o.Status, &o.Count, &first, &last); err != nil {
			return nil, err
		}
		if dir == 1 {
			o.Dir = event.Outbound
		}
		o.FirstTS, o.LastTS = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}
