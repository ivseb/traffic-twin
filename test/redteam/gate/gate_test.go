// Package gate_rt red-teams the publication gate (internal/gate), the last
// barrier before a value can reach a pack. Invented data only.
package gate_rt

import (
	"context"
	"testing"

	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
)

// noMatch is a keyguard stub that never reports a real-token hit, so any
// finding here comes from provenance / k-checks, not reverse-HMAC.
type noMatch struct{}

func (noMatch) Match(_ context.Context, _ []client.PolicyRef, cands []client.Candidate) (*client.MatchResult, error) {
	return &client.MatchResult{Matches: make([]bool, len(cands))}, nil
}

func baseInput(files map[string][]byte) *gate.Input {
	return &gate.Input{
		PackID:   "pk-rt",
		KMin:     5,
		Files:    files,
		Prov:     gate.Provenance{Synthetic: map[string]bool{}, Declared: map[string]int64{}, Text: map[string]bool{}},
		Policies: []client.PolicyRef{{ID: "p-shop", Version: 1}},
		Matcher:  noMatch{},
	}
}

func check(t *testing.T, r *gate.Result, id string) gate.Check {
	t.Helper()
	for _, c := range r.Report.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q not in report", id)
	return gate.Check{}
}

// An observed value that is not tagged synthetic or declared must be caught
// by the provenance check (ARCHITECTURE 9, core promise).
func TestRT_Gate_Holds_UntaggedWorldValueRejected(t *testing.T) {
	world := `{"type":"meta","format":"tt.world/v1","seed":"s","archetype":"a1"}
{"type":"customer","id":"CUST-SYN-0001","archetype":"a1","profile":{"name":"NOTSYNTHETIC-LEAK"}}`
	in := baseInput(map[string][]byte{"world.jsonl": []byte(world)})
	in.Archetypes = []gate.ArchetypeSize{{ID: "a1", Size: 50}}
	r, err := gate.Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, r, "provenance")
	if c.Status == "pass" {
		t.Fatalf("provenance passed an untagged observed value: %+v", r.Report)
	}
	if r.Report.Verdict != "fail" {
		t.Fatalf("verdict should be fail, got %q", r.Report.Verdict)
	}
}

// An archetype with fewer than k_min real subjects must fail the k check
// (G7, pack.md 7).
func TestRT_Gate_Holds_SubKArchetypeRejected(t *testing.T) {
	world := `{"type":"meta","format":"tt.world/v1","seed":"s","archetype":"a1"}`
	in := baseInput(map[string][]byte{"world.jsonl": []byte(world)})
	in.Archetypes = []gate.ArchetypeSize{{ID: "a1", Size: 3}} // < k_min (5)
	r, err := gate.Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if check(t, r, "k-thresholds").Status == "pass" {
		t.Fatalf("k-thresholds passed a sub-k archetype: %+v", r.Report)
	}
}

// A declared (observed keep) value that reaches a contract enum with fewer
// than k_min subjects must fail the k check (M5).
func TestRT_Gate_Holds_SubKEnumRejected(t *testing.T) {
	contract := `{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
"components":{"schemas":{"S":{"type":"string","enum":["RAREVALUE"]}}}}`
	in := baseInput(map[string][]byte{"contracts/shop.openapi.json": []byte(contract)})
	in.Prov.Declared["RAREVALUE"] = 2 // observed, but only 2 subjects < k_min 5
	r, err := gate.Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if check(t, r, "k-thresholds").Status == "pass" {
		t.Fatalf("k-thresholds passed a sub-k enum value: %+v", r.Report)
	}
}

// k_min < 2 must be refused outright (G7).
func TestRT_Gate_Holds_KMinFloor(t *testing.T) {
	in := baseInput(map[string][]byte{"world.jsonl": []byte(`{"type":"meta","format":"tt.world/v1","seed":"s"}`)})
	in.KMin = 1
	if _, err := gate.Run(context.Background(), in); err == nil {
		t.Fatal("k_min=1 was accepted")
	}
}
