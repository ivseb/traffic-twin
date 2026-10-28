package miner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// N1 of the lab: an application restart leaves objects whose creation was
// never captured. The miner must treat them as pre-existing (not as evidence
// against the entity), and an approved rule must go stale only after several
// consecutive bad runs, with a stated reason.

func mineDropped(t *testing.T, p float64, cfg Config) *Result {
	t.Helper()
	s := runSim(simConfig{Seed: 42, Customers: 1000, Days: 8, Start: simStart, DropCreate: p, DropMode: "unlinked"})
	f := ingestSim(t, s, t.TempDir())
	t.Cleanup(f.close)
	res, err := Mine(context.Background(), f.store, time.Time{}, time.Time{}, f.doms, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func entityDiag(res *Result, name string) *EntityDiag {
	for i := range res.Diag.Entities {
		if res.Diag.Entities[i].Name == name {
			return &res.Diag.Entities[i]
		}
	}
	return nil
}

func causalSigs(res *Result) []string {
	var out []string
	for _, mm := range res.Rules {
		if mm.Rule.Causal != nil {
			out = append(out, mm.Signature)
		}
	}
	return out
}

func TestMinerSurvivesMissingCreations(t *testing.T) {
	_, base := demoFixture(t)
	want := causalSigs(base)
	if len(want) != 2 {
		t.Fatalf("baseline causal rules: %v", want)
	}
	for _, p := range []float64{0.12, 0.30} {
		res := mineDropped(t, p, DefaultConfig())
		d := entityDiag(res, "shipment")
		if d == nil || !d.Accepted {
			t.Fatalf("drop %.0f%%: shipment entity not accepted: %+v", p*100, d)
		}
		// The scenario is real: with the old threshold (0.9 of the raw share)
		// the entity would have been dropped.
		if d.BirthShare >= 0.9 || d.BirthShare < 1-p-0.06 {
			t.Errorf("drop %.0f%%: birth share %.3f does not reflect the loss", p*100, d.BirthShare)
		}
		if d.PreExisting == 0 || d.Born >= d.Objects {
			t.Errorf("drop %.0f%%: pre-existing objects not reported: %+v", p*100, d)
		}
		if got := causalSigs(res); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("drop %.0f%%: causal rules %v, want %v", p*100, got, want)
		}
		if err := res.Document(time.Time{}, nil).Validate(); err != nil {
			t.Errorf("drop %.0f%%: %v", p*100, err)
		}
		for _, mm := range res.Rules {
			if c := mm.Rule.Causal; c != nil && len(c.Outcomes) == 0 {
				t.Errorf("drop %.0f%%: rule without outcomes", p*100)
			}
		}
	}
}

func TestEntityAcceptanceIsConfigurable(t *testing.T) {
	strict := DefaultConfig()
	strict.MinBirthShare = 0.95
	res := mineDropped(t, 0.12, strict)
	d := entityDiag(res, "shipment")
	if d == nil || d.Accepted {
		t.Fatalf("shipment must be dropped at 0.95: %+v", d)
	}
	if !strings.Contains(d.Reason, "birth share") || !strings.Contains(d.Reason, "< 0.95") {
		t.Errorf("reason: %q", d.Reason)
	}
	for _, e := range res.Entities {
		if e.Name == "shipment" {
			t.Errorf("dropped entity listed in the document")
		}
	}
	found := false
	for _, r := range res.Diag.Rules {
		if r.Decision == DecisionNotMined && strings.Contains(r.Signature, "|shipment") && strings.Contains(r.Reason, "entity shipment not accepted") {
			found = true
		}
	}
	if !found {
		t.Errorf("no per-rule diagnostic for the dropped entity: %+v", res.Diag.Rules)
	}
}

func TestWilsonSupport(t *testing.T) {
	if got := wilsonLow(2915, 3302); got < 0.87 || got > 0.89 {
		t.Errorf("wilson(2915,3302) = %.3f", got)
	}
	// A tiny sample cannot pass by luck: 20 of 20 is 0.84, 20 of 30 is far below 0.6.
	if got := wilsonLow(20, 20); got < 0.8 {
		t.Errorf("wilson(20,20) = %.3f", got)
	}
	if got := wilsonLow(20, 30); got >= 0.6 {
		t.Errorf("wilson(20,30) = %.3f", got)
	}
	if wilsonLow(0, 0) != 0 {
		t.Errorf("empty sample")
	}
}

// The approved rules of the lab: a stricter threshold makes the entity vanish for a
// stricter configuration; staleness takes StaleRuns consecutive runs and
// carries the reason.
func TestStaleNeedsConsecutiveRuns(t *testing.T) {
	_, base := demoFixture(t)
	ctx := context.Background()
	sink := &memSink{}
	rp := NewRepo(openDB(t), DefaultConfig(), sink)
	t0 := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	if _, err := rp.Apply(ctx, copyResult(t, base), t0, t0); err != nil {
		t.Fatal(err)
	}
	approved := map[string]string{}
	for _, r := range mustList(t, rp, "") {
		if _, err := rp.Approve(ctx, r.Rule.ID(), "usr_alice", t0); err != nil {
			t.Fatal(err)
		}
		approved[r.Signature] = r.Rule.ID()
	}
	if len(approved) != 3 {
		t.Fatalf("approved %v", approved)
	}
	shipID := approved[findSig(base, "causal|shipping-ext|POST /v1/shipments").Signature]

	strict := DefaultConfig()
	strict.MinBirthShare = 0.95
	bad := mineDropped(t, 0.12, strict)

	status := func(id string) *StoredRule { return mustGet(t, rp, id) }
	hour := 0
	apply := func(res *Result) RunReport {
		t.Helper()
		hour++
		rep, err := rp.Apply(ctx, res, t0, t0.Add(time.Duration(hour)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	badRun := func(wantStrikes int) RunReport {
		t.Helper()
		rep := apply(bad)
		st := status(shipID)
		if wantStrikes < 3 {
			if len(rep.Stale) != 0 || st.Rule.Status() != StatusApproved || st.Strikes != wantStrikes ||
				!strings.Contains(st.StaleReason, "entity shipment: birth share") {
				t.Fatalf("strike %d: stale=%v %s strikes=%d reason=%q", wantStrikes, rep.Stale, st.Rule.Status(), st.Strikes, st.StaleReason)
			}
			var d *RuleDiag
			for i := range rep.Diagnostics.Rules {
				if rep.Diagnostics.Rules[i].RuleID == shipID {
					d = &rep.Diagnostics.Rules[i]
				}
			}
			if d == nil || d.Decision != DecisionWatch || d.Strikes != wantStrikes || d.StaleRuns != 3 {
				t.Fatalf("strike %d: diagnostic %+v", wantStrikes, d)
			}
		}
		return rep
	}

	badRun(1)
	// A good run in between forgets the strike.
	apply(copyResult(t, base))
	if st := status(shipID); st.Strikes != 0 || st.StaleReason != "" || st.Rule.Status() != StatusApproved {
		t.Fatalf("good run did not reset: strikes=%d reason=%q", st.Strikes, st.StaleReason)
	}
	badRun(1)
	badRun(2)
	rep := badRun(3)
	st := status(shipID)
	if len(rep.Stale) != 3 || st.Rule.Status() != StatusStale {
		t.Fatalf("third consecutive strike: %+v %s", rep.Stale, st.Rule.Status())
	}
	if !strings.Contains(st.StaleReason, "entity shipment: birth share") || !strings.HasSuffix(st.StaleReason, "for 3 runs") {
		t.Errorf("stale reason: %q", st.StaleReason)
	}
	noticed := false
	for _, n := range sink.ns {
		if n.RuleID == shipID && n.Reason == "not_observed" && n.Detail == st.StaleReason {
			noticed = true
		}
	}
	if !noticed {
		t.Errorf("no notice with the reason: %+v", sink.ns)
	}
	// Every rule that depends on the dropped entity says why.
	for sig, id := range approved {
		x := status(id)
		if x.Rule.Status() != StatusStale || x.StaleReason == "" || !strings.HasSuffix(x.StaleReason, "for 3 runs") ||
			!strings.Contains(x.StaleReason, "shipment") {
			t.Errorf("rule %s (%s): %s %q", id, sig, x.Rule.Status(), x.StaleReason)
		}
	}
	// Re-approval (after traffic that supports the rule again) clears the history.
	apply(copyResult(t, base))
	if _, err := rp.Approve(ctx, shipID, "usr_alice", t0); err != nil {
		t.Fatal(err)
	}
	if st := status(shipID); st.Strikes != 0 || st.StaleReason != "" {
		t.Errorf("approve kept the history: %d %q", st.Strikes, st.StaleReason)
	}
}

func TestInsufficientRunJudgesNothing(t *testing.T) {
	_, base := demoFixture(t)
	ctx := context.Background()
	rp := NewRepo(openDB(t), DefaultConfig(), nil)
	t0 := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	if _, err := rp.Apply(ctx, copyResult(t, base), t0, t0); err != nil {
		t.Fatal(err)
	}
	shipID := ""
	for _, r := range mustList(t, rp, "") {
		if _, err := rp.Approve(ctx, r.Rule.ID(), "usr_alice", t0); err != nil {
			t.Fatal(err)
		}
		if r.Signature == findSig(base, "causal|shipping-ext|POST /v1/shipments").Signature {
			shipID = r.Rule.ID()
		}
	}
	short := copyResult(t, base)
	short.Observed = 10 * time.Minute
	short.Rules = nil
	for i := 0; i < 5; i++ {
		rep, err := rp.Apply(ctx, short, t0, t0.Add(time.Duration(i+1)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Stale) != 0 {
			t.Fatalf("stale on a run with too little traffic: %+v", rep)
		}
	}
	if st := mustGet(t, rp, shipID); st.Rule.Status() != StatusApproved || st.Strikes != 0 {
		t.Errorf("%s strikes=%d", st.Rule.Status(), st.Strikes)
	}
}

// The creation exchange itself is missing for part of the orders (restart,
// retention cutoff): those orders are only known from reads.
func TestMinerSurvivesLostCreations(t *testing.T) {
	_, base := demoFixture(t)
	want := causalSigs(base)
	for _, p := range []float64{0.12, 0.30} {
		s := runSim(simConfig{Seed: 42, Customers: 1000, Days: 8, Start: simStart, DropCreate: p, DropMode: "lost"})
		f := ingestSim(t, s, t.TempDir())
		res, err := Mine(context.Background(), f.store, time.Time{}, time.Time{}, f.doms, DefaultConfig())
		f.close()
		if err != nil {
			t.Fatal(err)
		}
		if got := causalSigs(res); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("lost %.0f%%: causal rules %v, want %v", p*100, got, want)
		}
		d := entityDiag(res, "order")
		if d == nil || !d.Accepted || d.PreExisting == 0 {
			t.Errorf("lost %.0f%%: order diagnostic %+v", p*100, d)
		}
		for _, mm := range res.Rules {
			if b := findSig(base, mm.Signature); b == nil || mm.Confidence < b.Confidence-0.05 {
				t.Errorf("lost %.0f%%: %s confidence %.2f", p*100, mm.Signature, mm.Confidence)
			}
		}
	}
}
