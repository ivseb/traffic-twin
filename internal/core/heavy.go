package core

import (
	"context"
	"sync"
)

// Heavy jobs.
//
// Mining, archetypes, world generation, pack builds, contract snapshots,
// exports and the "prepare the mock" chain each read up to millions of
// events and hold a large part of them in memory. On the lab core (4 GiB,
// 2026-10-25) one mining run of 1.95 M events took the RSS to 4 GB; a
// second run requested while the first was running, or any other heavy job
// next to it, got tt-core killed by the kernel (intake included). The heavy
// gate admits a fixed number of them at once (heavySlots: one below 16 GiB
// of memory) in arrival order; the others wait, as jobs in status "queued"
// (GET /api/v1/jobs), instead of adding their peak to the running one.

// heavyGate is a FIFO semaphore of the heavy jobs.
type heavyGate struct {
	mu      sync.Mutex
	slots   int
	running int
	queue   []chan struct{} // waiters, oldest first; closed when admitted
}

func newHeavyGate(slots int) *heavyGate {
	return &heavyGate{slots: max(1, slots)}
}

// heavySlots is the number of heavy jobs that may run at once: one below
// 16 GiB of memory (or when the limit is unknown), then one per 8 GiB, at
// most 4.
func heavySlots(limit uint64) int {
	if limit < 16<<30 {
		return 1
	}
	return min(int(limit/(8<<30)), 4)
}

// acquire waits for a slot, in arrival order. queued, when not nil, is
// called once when the caller has to wait. It returns the release function
// (idempotent), or ctx's error when ctx ends first.
func (g *heavyGate) acquire(ctx context.Context, queued func()) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	g.mu.Lock()
	if g.running < g.slots && len(g.queue) == 0 {
		g.running++
		g.mu.Unlock()
		return g.releaser(), nil
	}
	ch := make(chan struct{})
	g.queue = append(g.queue, ch)
	g.mu.Unlock()
	if queued != nil {
		queued()
	}
	select {
	case <-ch:
		return g.releaser(), nil
	case <-ctx.Done():
		g.mu.Lock()
		for i, w := range g.queue {
			if w == ch {
				g.queue = append(g.queue[:i], g.queue[i+1:]...)
				g.mu.Unlock()
				return nil, ctx.Err()
			}
		}
		g.mu.Unlock()
		// Admitted while ctx ended: give the slot back.
		g.releaser()()
		return nil, ctx.Err()
	}
}

func (g *heavyGate) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if len(g.queue) > 0 {
				// The slot passes to the oldest waiter.
				ch := g.queue[0]
				g.queue = g.queue[1:]
				close(ch)
				return
			}
			g.running--
		})
	}
}

// capacity is the number of slots.
func (g *heavyGate) capacity() int {
	if g == nil {
		return 0
	}
	return g.slots
}

// stats returns the running and the waiting heavy jobs.
func (g *heavyGate) stats() (running, waiting int) {
	if g == nil {
		return 0, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.running, len(g.queue)
}

// Miner window sizing.
//
// minerBytesPerEvent is the peak memory of a mining run per event of its
// window under the Go soft limit (test/perf/ttperf -scale lab -only memory:
// MEASURED below), with a margin; minerMemShare is the share of the
// memory limit one run may take (the heavy gate runs one heavy job per
// slot; intake, SQLite and the other components keep the rest).
const (
	minerBytesPerEvent = 1500
	minerMemShare      = 0.5
)

// autoMinerEvents is the largest miner window (events) that fits in the
// memory limit with slots heavy jobs at once, between 100 000 and
// 5 000 000; 1 000 000 without a known limit.
func autoMinerEvents(limit uint64, slots int) int {
	if limit == 0 {
		return 1_000_000
	}
	n := int(float64(limit) * minerMemShare / float64(max(1, slots)) / minerBytesPerEvent)
	return min(max(n, 100_000), 5_000_000)
}
