package server

import (
	"fmt"
	"testing"
	"time"
)

// A full table is swept at most once per sweepEvery: a flood of new
// clients costs one map lookup each, not a walk of the whole table.
func TestFullTableSweepsAtMostOncePerInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newRateLimiter(60, 5)
	l.now = func() time.Time { return now }
	l.max = 1000
	for i := 0; i < l.max; i++ {
		l.allow(fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	sweeps := 0
	for i := 0; i < 500; i++ {
		before := l.swept
		if ok, _ := l.allow(fmt.Sprintf("10.9.%d.%d", i/250, i%250)); ok {
			t.Fatal("full table of active clients must fail closed")
		}
		if l.swept != before {
			sweeps++
		}
	}
	if sweeps != 1 {
		t.Fatalf("%d sweeps for 500 refused clients within the same second, want 1", sweeps)
	}
	// Later, once the old clients are idle, a sweep makes room again.
	now = now.Add(time.Hour)
	if ok, _ := l.allow("10.9.9.9"); !ok {
		t.Fatal("idle clients not swept after the interval")
	}
}

func BenchmarkAllowFullTable(b *testing.B) {
	l := newRateLimiter(60, 5)
	for i := 0; i < l.max; i++ {
		l.allow(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.allow(fmt.Sprintf("172.16.%d.%d", (i/256)%256, i%256))
	}
}
