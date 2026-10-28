package miner

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A window with more events than MaxEvents is narrowed to its newest
// events: the run succeeds within the memory bound instead of loading
// MaxEvents events and failing with ErrTooManyEvents.
func TestMineClampsWindowToMaxEvents(t *testing.T) {
	f := ingestSim(t, runSim(simConfig{Seed: 3, Customers: 80, Days: 2, Start: simStart}), t.TempDir())
	t.Cleanup(f.close)
	ctx := context.Background()
	total, err := f.store.Count(ctx)
	if err != nil || total < 100 {
		t.Fatalf("events: %d %v", total, err)
	}
	from, to := simStart.Add(-time.Hour), simStart.Add(10*24*time.Hour)
	cfg := DefaultConfig()
	cfg.MaxEvents = int(total / 3)
	res, err := Mine(ctx, f.store, from, to, f.doms, cfg)
	if err != nil {
		t.Fatalf("mine: %v", err)
	}
	if !res.Clamped || res.Events > cfg.MaxEvents || res.Events < cfg.MaxEvents/2 {
		t.Fatalf("clamped %v, %d events (max %d of %d)", res.Clamped, res.Events, cfg.MaxEvents, total)
	}
	if res.Window.From == from.UTC().Format(time.RFC3339) {
		t.Fatalf("window start not moved: %+v", res.Window)
	}
	// A source without the limiter keeps the old contract.
	_, err = Mine(ctx, scanOnly{f.store}, from, to, f.doms, cfg)
	if !errors.Is(err, ErrTooManyEvents) {
		t.Fatalf("plain source: %v", err)
	}
	// Under the bound nothing changes.
	cfg.MaxEvents = int(total) + 1
	res, err = Mine(ctx, f.store, from, to, f.doms, cfg)
	if err != nil || res.Clamped || res.Events != int(total) {
		t.Fatalf("unclamped: %v %v %d", err, res.Clamped, res.Events)
	}
}

type scanOnly struct{ EventSource }
