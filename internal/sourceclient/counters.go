package sourceclient

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Counters are the monotonic counters of a source (Heartbeat.counters).
// All fields are safe for concurrent use.
type Counters struct {
	ExchangesSeen      atomic.Int64
	ExchangesSampled   atomic.Int64
	EventsSent         atomic.Int64
	EventsDroppedQueue atomic.Int64
	EventsRejected     atomic.Int64
	SendErrors         atomic.Int64
	SanitizerErrors    atomic.Int64
}

// Snapshot returns the current values.
func (c *Counters) Snapshot() CounterSnapshot {
	return CounterSnapshot{
		ExchangesSeen:      c.ExchangesSeen.Load(),
		ExchangesSampled:   c.ExchangesSampled.Load(),
		EventsSent:         c.EventsSent.Load(),
		EventsDroppedQueue: c.EventsDroppedQueue.Load(),
		EventsRejected:     c.EventsRejected.Load(),
		SendErrors:         c.SendErrors.Load(),
		SanitizerErrors:    c.SanitizerErrors.Load(),
	}
}

// overheadRing keeps the last overheadSamples per-exchange durations
// (nanoseconds) without locks on the write path.
const overheadSamples = 2048

type overheadRing struct {
	n   atomic.Uint64
	buf [overheadSamples]atomic.Int64
}

func (r *overheadRing) observe(d time.Duration) {
	i := r.n.Add(1) - 1
	r.buf[i%overheadSamples].Store(int64(d))
}

// percentiles returns p50 and p99 in microseconds over the retained samples.
func (r *overheadRing) percentiles() (p50, p99 int64, ok bool) {
	n := r.n.Load()
	if n == 0 {
		return 0, 0, false
	}
	if n > overheadSamples {
		n = overheadSamples
	}
	s := make([]int64, n)
	for i := range s {
		s[i] = r.buf[i].Load()
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(q float64) int64 {
		idx := int(q * float64(len(s)-1))
		return s[idx] / int64(time.Microsecond)
	}
	return at(0.50), at(0.99), true
}

// errorLog keeps the last error codes (codes only, never payload values).
type errorLog struct {
	mu   sync.Mutex
	list []LastError
}

const maxLastErrors = 20

func (l *errorLog) add(code string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, LastError{Code: code, At: at.UTC()})
	if len(l.list) > maxLastErrors {
		l.list = l.list[len(l.list)-maxLastErrors:]
	}
}

func (l *errorLog) snapshot() []LastError {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LastError(nil), l.list...)
}

// rateWindow counts events per minute over a sliding window of 60 one-second
// buckets.
type rateWindow struct {
	mu    sync.Mutex
	stamp [60]int64
	count [60]int64
}

func (w *rateWindow) add(now time.Time, n int64) {
	sec := now.Unix()
	i := int(sec % 60)
	w.mu.Lock()
	if w.stamp[i] != sec {
		w.stamp[i], w.count[i] = sec, 0
	}
	w.count[i] += n
	w.mu.Unlock()
}

func (w *rateWindow) perMinute(now time.Time) int64 {
	sec := now.Unix()
	var total int64
	w.mu.Lock()
	for i := range w.stamp {
		if sec-w.stamp[i] < 60 && sec >= w.stamp[i] {
			total += w.count[i]
		}
	}
	w.mu.Unlock()
	return total
}
