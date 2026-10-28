package intake

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func float64bits(f float64) uint64     { return math.Float64bits(f) }
func float64frombits(b uint64) float64 { return math.Float64frombits(b) }

// reasonAccepted is the pseudo-reason under which accepted events are stored.
const reasonAccepted = "accepted"

type srcCounters struct {
	id       string
	warnedAt [numReasons]atomic.Int64 // unix ms of the last log line per reason
	accepted atomic.Uint64
	rejected [numReasons]atomic.Uint64
	requests atomic.Uint64
	bytes    atomic.Uint64
	lastSeen atomic.Int64 // unix ms
	dirty    atomic.Bool
	inflight atomic.Int32
	recent   recentRejects
}

type globalCounters struct {
	requests      atomic.Uint64
	throttled     atomic.Uint64 // 429
	unavailable   atomic.Uint64 // 503
	badRequests   atomic.Uint64 // 4xx other than 429
	stored        atomic.Uint64
	storageErrors atomic.Uint64
}

type statsRegistry struct {
	mu     sync.RWMutex
	src    map[string]*srcCounters
	global globalCounters
}

func newStats() *statsRegistry { return &statsRegistry{src: map[string]*srcCounters{}} }

func (s *statsRegistry) source(id string) *srcCounters {
	s.mu.RLock()
	c := s.src[id]
	s.mu.RUnlock()
	if c != nil {
		return c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c = s.src[id]; c == nil {
		c = &srcCounters{id: id}
		s.src[id] = c
	}
	return c
}

// SourceStats are the counters of one source, as shown in Fleet health.
type SourceStats struct {
	SourceID string
	// Accepted counts events that passed every check and were queued.
	Accepted uint64
	// Rejected counts dropped events by reason name (see AllReasons).
	Rejected      map[string]uint64
	RejectedTotal uint64
	// Requests and Bytes count OTLP requests and uncompressed request bytes.
	Requests uint64
	Bytes    uint64
	LastSeen time.Time
}

func (c *srcCounters) snapshot(id string) SourceStats {
	st := SourceStats{SourceID: id, Accepted: c.accepted.Load(), Rejected: map[string]uint64{}, Requests: c.requests.Load(), Bytes: c.bytes.Load()}
	for r := ReasonNone + 1; r < numReasons; r++ {
		if n := c.rejected[r].Load(); n > 0 {
			st.Rejected[r.String()] = n
			st.RejectedTotal += n
		}
	}
	if ms := c.lastSeen.Load(); ms > 0 {
		st.LastSeen = time.UnixMilli(ms).UTC()
	}
	return st
}

// SourceStats returns the counters of a source (zero values if unseen).
func (in *Intake) SourceStats(id string) SourceStats {
	in.stats.mu.RLock()
	c := in.stats.src[id]
	in.stats.mu.RUnlock()
	if c == nil {
		return SourceStats{SourceID: id, Rejected: map[string]uint64{}}
	}
	return c.snapshot(id)
}

// AllSourceStats returns the counters of every source seen, sorted by id.
func (in *Intake) AllSourceStats() []SourceStats {
	in.stats.mu.RLock()
	out := make([]SourceStats, 0, len(in.stats.src))
	for id, c := range in.stats.src {
		out = append(out, c.snapshot(id))
	}
	in.stats.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].SourceID < out[j].SourceID })
	return out
}

// Totals are process-wide counters.
type Totals struct {
	Requests      uint64
	Throttled     uint64 // answered 429
	Unavailable   uint64 // answered 503
	BadRequests   uint64 // other 4xx
	Stored        uint64 // events committed to the database
	StorageErrors uint64 // accepted events lost to database failures
	QueuedEvents  int64
	QueuedBytes   int64
	Monitors      int64
	// WriterRate is the recent database write rate in events per second.
	WriterRate float64
}

// Totals returns the process-wide counters.
func (in *Intake) Totals() Totals {
	g := &in.stats.global
	return Totals{
		Requests: g.requests.Load(), Throttled: g.throttled.Load(), Unavailable: g.unavailable.Load(), BadRequests: g.badRequests.Load(),
		Stored: g.stored.Load(), StorageErrors: g.storageErrors.Load(),
		QueuedEvents: in.queued.Load(), QueuedBytes: in.queuedBytes.Load(), Monitors: in.monitors.count.Load() + in.monitors.discCount.Load(),
		WriterRate: float64frombits(in.writer.rate.Load()),
	}
}

func (s *statsRegistry) load(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := db.QueryContext(ctx, `SELECT source_id, reason, n FROM intake_source_counts`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, reason string
		var n uint64
		if err := rows.Scan(&id, &reason, &n); err != nil {
			return err
		}
		c := s.source(id)
		if reason == reasonAccepted {
			c.accepted.Store(n)
			continue
		}
		for r := ReasonNone + 1; r < numReasons; r++ {
			if r.String() == reason {
				c.rejected[r].Store(n)
			}
		}
	}
	return rows.Err()
}

// flush persists the counters of sources that changed.
func (s *statsRegistry) flush(ctx context.Context, tx *sql.Tx) error {
	s.mu.RLock()
	ids := make([]string, 0, len(s.src))
	for id, c := range s.src {
		if c.dirty.Swap(false) {
			ids = append(ids, id)
		}
	}
	s.mu.RUnlock()
	for _, id := range ids {
		c := s.source(id)
		up := func(reason string, n uint64) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO intake_source_counts (source_id, reason, n) VALUES (?, ?, ?)
				ON CONFLICT (source_id, reason) DO UPDATE SET n = excluded.n`, id, reason, n)
			return err
		}
		if err := up(reasonAccepted, c.accepted.Load()); err != nil {
			return err
		}
		for r := ReasonNone + 1; r < numReasons; r++ {
			if n := c.rejected[r].Load(); n > 0 {
				if err := up(r.String(), n); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// RecentRejection is the rejections of one reason within a window: how many,
// and when the first and the last of them happened.
type RecentRejection struct {
	Reason string
	Count  uint64
	First  time.Time
	Last   time.Time
}

// recentWindow is the longest window RecentRejections can answer: one bucket
// per minute.
const recentWindow = 60 * time.Minute

type rejBucket struct {
	minute      int64
	n           uint64
	first, last int64 // unix ms
}

// recentRejects keeps the rejections of the last hour in per-minute buckets
// (memory only: the cumulative totals are the persistent counters).
type recentRejects struct {
	mu sync.Mutex
	by map[Reason]*[60]rejBucket
}

func (r *recentRejects) add(reason Reason, now time.Time) {
	ms := now.UnixMilli()
	minute := ms / 60000
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.by == nil {
		r.by = map[Reason]*[60]rejBucket{}
	}
	ring := r.by[reason]
	if ring == nil {
		ring = new([60]rejBucket)
		r.by[reason] = ring
	}
	b := &ring[minute%60]
	if b.minute != minute {
		*b = rejBucket{minute: minute, first: ms}
	}
	b.n++
	b.last = ms
}

func (r *recentRejects) snapshot(window time.Duration, now time.Time) []RecentRejection {
	if window <= 0 || window > recentWindow {
		window = recentWindow
	}
	cutoff := now.Add(-window).UnixMilli()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []RecentRejection
	for reason, ring := range r.by {
		var rr RecentRejection
		for i := range ring {
			b := ring[i]
			if b.n == 0 || b.last < cutoff {
				continue
			}
			rr.Count += b.n
			if f := time.UnixMilli(b.first).UTC(); rr.First.IsZero() || f.Before(rr.First) {
				rr.First = f
			}
			if l := time.UnixMilli(b.last).UTC(); l.After(rr.Last) {
				rr.Last = l
			}
		}
		if rr.Count > 0 {
			rr.Reason = reason.String()
			out = append(out, rr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// RecentRejections returns, per reason, the events of the source rejected
// within the last window (at most one hour), largest first, with the time of
// the first and the last: a view of what is going wrong now, as opposed to
// SourceStats.Rejected, the totals since the source first appeared.
func (in *Intake) RecentRejections(id string, window time.Duration) []RecentRejection {
	in.stats.mu.RLock()
	c := in.stats.src[id]
	in.stats.mu.RUnlock()
	if c == nil {
		return nil
	}
	return c.recent.snapshot(window, in.now())
}
