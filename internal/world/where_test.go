package world

import (
	"strings"
	"testing"
)

// A guarded effect (rules v1.7, where) applies only while the entity is in
// the state it starts from: guarded on a state the shipment never has at
// that point, the step never happens, nor the history row.
func TestWhereGuardsAnEffect(t *testing.T) {
	in := demoInput(t, 7, 200)
	base, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(base.World), `"effect_id":"shipment-in-transit"`) {
		t.Fatal("the demo world has no in-transit step to guard")
	}
	in = demoInput(t, 7, 200)
	for i := range in.Rules.Causal {
		for j := range in.Rules.Causal[i].Effects {
			if e := &in.Rules.Causal[i].Effects[j]; e.ID == "shipment-in-transit" {
				e.Where = map[string]any{"status": "PENDING"}
			}
		}
	}
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(out.World), "\n") {
		if strings.Contains(l, `"type":"history"`) && strings.Contains(l, `"effect_id":"shipment-in-transit"`) {
			t.Fatalf("a guarded step was applied: %s", l)
		}
	}
}
