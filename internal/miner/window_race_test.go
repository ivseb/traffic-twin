package miner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/intake"
)

// lateArrivals is the store as a run sees it while events keep arriving: the
// count of the window (NewestSince) says it fits, the scan then finds more
// (lab, 1200 events per minute: the run failed with ErrTooManyEvents).
type lateArrivals struct{ *intake.Store }

func (lateArrivals) NewestSince(_ context.Context, from, _ time.Time, _ int) (time.Time, bool, error) {
	return from, false, nil
}

func TestNarrowedWindowToleratesLateArrivals(t *testing.T) {
	fix, _ := demoFixture(t)
	cfg := DefaultConfig()
	cfg.MaxEvents = 5000
	res, err := Mine(context.Background(), lateArrivals{fix.store}, time.Time{}, time.Time{}, fix.doms, cfg)
	if err != nil {
		t.Fatalf("a narrowed window must not fail on late arrivals: %v", err)
	}
	if !res.Clamped {
		t.Fatal("the run left events out: it must say the window was narrowed")
	}
	// Without a window limiter the hard limit still protects the memory.
	if _, err := Mine(context.Background(), scanOnly{fix.store}, time.Time{}, time.Time{}, fix.doms, cfg); !errors.Is(err, ErrTooManyEvents) {
		t.Fatalf("a source that cannot narrow the window must still fail over MaxEvents: %v", err)
	}
}
