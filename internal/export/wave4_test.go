package export

import (
	"context"
	"encoding/json"
	"testing"
)

// The rules v1.9 members the stubs cannot reproduce are reported as
// losses; target_all and preconditions leave the exported effects.
func TestWave4Losses(t *testing.T) {
	in, err := DirSource{Dir: fixture}.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	baseKinds := map[string]int{}
	for _, n := range buildModel(in, nil).notes {
		baseKinds[n.Kind] += n.Count
	}
	in.Rules.Attributes = []NamedPart{{Name: "segment"}}
	in.Rules.Aggregates = []OpPart{{Service: "shop-api", Op: "GET /me"}}
	in.Rules.Lists = []OpPart{{Service: "shop-api", Op: "GET /catalog"}}
	var causal *Rule
	for i := range in.Rules.Rules {
		if in.Rules.Rules[i].Kind == "causal" && in.Rules.Rules[i].Status == "approved" {
			causal = &in.Rules.Rules[i]
		}
	}
	causal.Cause.When.Match = []json.RawMessage{json.RawMessage(`{"customer":"segment","in":["GOLD"]}`)}
	causal.Outcomes[0].When = []json.RawMessage{json.RawMessage(`{"customer":"segment","in":["GOLD"]}`)}
	causal.Effects = append(causal.Effects,
		Effect{ID: "all-flagged", Entity: causal.Effects[0].Entity, TargetAll: true, Set: map[string]any{"flagged": true}},
		Effect{ID: "until", Respond: map[string]any{"service": "shop-api", "op": "POST /checkout", "status": 409, "until": true}})
	causal.Outcomes[0].Effects = append(causal.Outcomes[0].Effects, "all-flagged", "until")
	m := buildModel(in, nil)
	kinds := map[string]int{}
	for _, n := range m.notes {
		kinds[n.Kind] += n.Count
	}
	for k, want := range map[string]int{"conditional-outcome": 2, "customer-attribute": 1, "aggregate": 1, "list-paging": 1, "update-effect": 1, "response-effect": 1} {
		if kinds[k]-baseKinds[k] < want {
			t.Errorf("loss %s: %d, want %d (%v)", k, kinds[k], want, kinds)
		}
	}
	for _, r := range m.rules {
		for _, e := range r.Effects {
			if e.TargetAll || e.Respond != nil {
				t.Fatalf("effect %s was exported", e.ID)
			}
		}
	}
}

// Derived values (rules v1.10) are not computed by the stubs: reported as a
// loss and left out of the exported state.
func TestDerivedValuesLoss(t *testing.T) {
	in, err := DirSource{Dir: fixture}.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var causal *Rule
	for i := range in.Rules.Rules {
		if in.Rules.Rules[i].Kind == "causal" && in.Rules.Rules[i].Status == "approved" {
			causal = &in.Rules.Rules[i]
		}
	}
	for i := range causal.Effects {
		if causal.Effects[i].Create != nil {
			causal.Effects[i].Create["due"] = map[string]any{"$derive": map[string]any{"fn": "date", "offset": "+30d"}}
		}
	}
	kinds := map[string]int{}
	for _, n := range buildModel(in, nil).notes {
		kinds[n.Kind] += n.Count
	}
	if kinds["derived-value"] < 1 {
		t.Fatalf("no derived-value loss: %v", kinds)
	}
	if v, ok := subst(map[string]any{"$derive": map[string]any{"fn": "copy"}}, nil, nil, "", ""); ok || v != nil {
		t.Fatalf("subst of a derived value: %v %v", v, ok)
	}
}
