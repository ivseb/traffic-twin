package miner

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// maxLogBytesPerEvent bounds the live memory of the object-centric log per
// event. The miner window is sized on it (core/heavy.go: ~1.5 KB per event
// at the peak of a run, garbage of the collector pacing included): the lab
// core was OOM-killed mining 1.95 M events on 4 GiB. The
// simulated shop measures ~620 B per event (~720 B with the trace ids as
// strings and the spare capacity of the per-event slices); the transient
// maps of the trace trees, now sorted arrays, cost ~150 B more at the peak.
const maxLogBytesPerEvent = 800

// TestLogMemoryPerEvent measures the live heap of a loaded log.
func TestLogMemoryPerEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	f := ingestSim(t, runSim(simConfig{Seed: 7, Customers: 1000, Days: 8, Start: simStart}), t.TempDir())
	defer f.close()
	live := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	// The log's size: the live heap with it minus the live heap once it is
	// dropped (what the fixture frees meanwhile does not count).
	l, err := Load(context.Background(), f.store, time.Time{}, time.Time{}, "", f.doms, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := l.Events()
	with := live()
	runtime.KeepAlive(l)
	l = nil
	without := live()
	if n < 20_000 {
		t.Fatalf("only %d events", n)
	}
	per := (float64(with) - float64(without)) / float64(n)
	t.Logf("%d events, %.0f bytes per event", n, per)
	if per > maxLogBytesPerEvent {
		t.Fatalf("log costs %.0f bytes per event, budget %d", per, maxLogBytesPerEvent)
	}
}
