package miner

import (
	"context"
	"testing"
	"time"
)

func mineSim(t *testing.T, cfg simConfig) (*simFixture, *Result) {
	t.Helper()
	f := ingestSim(t, runSim(cfg), t.TempDir())
	t.Cleanup(f.close)
	res, err := Mine(context.Background(), f.store, time.Time{}, time.Time{}, f.doms, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Document(time.Time{}, nil).Validate(); err != nil {
		t.Fatal(err)
	}
	return f, res
}

// Without the nightly job the deliveries are spread over the clock: no batch
// rule, the causal rules remain (and the outcomes are still right).
func TestNoBatchWithoutNightlyJob(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	_, res := mineSim(t, simConfig{Seed: 9, Customers: 800, Days: 7, Start: simStart, NoBatch: true})
	causal := 0
	for _, mm := range res.Rules {
		if mm.Rule.Batch != nil {
			t.Errorf("spurious batch rule: %+v", mm.Rule.Batch)
		}
		if c := mm.Rule.Causal; c != nil {
			causal++
			for _, o := range c.Outcomes {
				want := map[string]float64{"happy": 0.93, "cancelled": 0.04, "never": 0.03}[o.Name]
				if !within(o.P, want, 0.03) {
					t.Errorf("%s outcome %s p=%.3f", c.Cause.Op, o.Name, o.P)
				}
			}
		}
	}
	if causal != 2 {
		t.Errorf("causal rules: %d, want 2", causal)
	}
}

// Too few subjects: nothing passes the k threshold, nothing is proposed.
func TestKAnonymityThreshold(t *testing.T) {
	_, res := mineSim(t, simConfig{Seed: 3, Customers: 40, Days: 3, Start: simStart})
	if len(res.Rules) != 0 {
		t.Errorf("rules proposed with fewer than k_min subjects: %d", len(res.Rules))
	}
	for _, k := range res.Keys {
		if k.Subjects < DefaultConfig().KMin || k.Matches < DefaultConfig().KMin {
			t.Errorf("key below k: %s", keyString(k))
		}
	}
}

// Another seed: the findings do not depend on one lucky draw.
func TestEvalOtherSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	_, res := mineSim(t, simConfig{Seed: 2026, Customers: 1000, Days: 8, Start: simStart})
	kinds := map[string]int{}
	for _, mm := range res.Rules {
		kinds[mm.Rule.Kind()]++
		if b := mm.Rule.Batch; b != nil && (b.Schedule != "0 2 * * *" || !within(b.Fraction, 0.6, 0.05)) {
			t.Errorf("batch: %s fraction %.2f", b.Schedule, b.Fraction)
		}
		if c := mm.Rule.Causal; c != nil {
			for _, o := range c.Outcomes {
				want := map[string]float64{"happy": 0.93, "cancelled": 0.04, "never": 0.03}[o.Name]
				if !within(o.P, want, 0.03) {
					t.Errorf("%s outcome %s p=%.3f", c.Cause.Op, o.Name, o.P)
				}
			}
		}
	}
	if kinds[KindCausal] != 2 || kinds[KindBatch] != 1 {
		t.Errorf("rules: %v", kinds)
	}
}

// Without the policies the domains are guessed from field names and shared
// tokens: the same entities and rules come out.
func TestMineWithoutPolicyDomains(t *testing.T) {
	fix, ref := demoFixture(t)
	res, err := Mine(context.Background(), fix.store, time.Time{}, time.Time{}, nil, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entities) != 2 || res.Entities[0].Name != "order" || res.Entities[1].Name != "shipment" {
		t.Fatalf("entities: %+v", res.Entities)
	}
	if len(res.Rules) != len(ref.Rules) {
		t.Fatalf("rules: %d, with policies %d", len(res.Rules), len(ref.Rules))
	}
	for i := range res.Rules {
		if res.Rules[i].Signature != ref.Rules[i].Signature || res.Rules[i].Structure != ref.Rules[i].Structure {
			t.Errorf("rule %d differs: %s", i, res.Rules[i].Signature)
		}
	}
}
