package core

import (
	"encoding/json"
	"testing"

	"github.com/ivseb/traffic-twin/internal/miner"
)

// The result of a mining job is bounded: at most maxJobDiagnostics
// diagnostics of each kind (with the totals), and the status without its
// own copy of them.
func TestMineResultBounded(t *testing.T) {
	rep := miner.RunReport{RunID: 7, Events: 1_950_000}
	for range 5000 {
		rep.Diagnostics.Rules = append(rep.Diagnostics.Rules, miner.RuleDiag{Signature: "causal|svc|POST /x|order", Decision: miner.DecisionNotMined})
		rep.Diagnostics.Entities = append(rep.Diagnostics.Entities, miner.EntityDiag{Name: "order", Op: "svc POST /x"})
	}
	st := &miner.Status{Entities: rep.Diagnostics.Entities, RuleDiagnostics: rep.Diagnostics.Rules}
	res := mineResult(rep, st)
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Rules      []json.RawMessage `json:"rule_diagnostics"`
		RulesTotal int               `json:"rule_diagnostics_total"`
		Ents       []json.RawMessage `json:"entities"`
		EntsTotal  int               `json:"entities_total"`
		Status     struct {
			Rules []json.RawMessage `json:"rule_diagnostics"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != maxJobDiagnostics || out.RulesTotal != 5000 || len(out.Ents) != maxJobDiagnostics || out.EntsTotal != 5000 {
		t.Fatalf("rules %d/%d entities %d/%d", len(out.Rules), out.RulesTotal, len(out.Ents), out.EntsTotal)
	}
	if len(out.Status.Rules) != 0 {
		t.Fatalf("status repeats %d diagnostics", len(out.Status.Rules))
	}
	if len(b) > 100<<10 {
		t.Fatalf("result of %d KB", len(b)>>10)
	}
	// A small run keeps everything, without totals.
	small := mineResult(miner.RunReport{Diagnostics: miner.Diagnostics{Rules: rep.Diagnostics.Rules[:3]}}, nil)
	if _, ok := small["rule_diagnostics_total"]; ok || len(small["rule_diagnostics"].([]miner.RuleDiag)) != 3 {
		t.Fatalf("small: %v", small)
	}
}
