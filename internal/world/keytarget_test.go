package world

import (
	"bytes"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// An effect on a keyed record (rules v1.8, target_key) applies in the mock
// only: keyed records are not in the world, the rule stays usable and the
// world is the same as without the effect.
func TestTargetKeyEffectIgnored(t *testing.T) {
	base, err := Generate(demoInput(t, 7, 200))
	if err != nil {
		t.Fatal(err)
	}
	in := demoInput(t, 7, 200)
	r := &in.Rules.Causal[0]
	tk := map[string]string{}
	r.Effects = append(r.Effects, pack.Effect{ID: "profile-touched", Entity: r.Effects[0].Entity, TargetKey: &tk,
		Set: map[string]any{"seen": true}, After: pack.Delay{}})
	for i := range r.Outcomes {
		r.Outcomes[i].Effects = append(r.Outcomes[i].Effects, "profile-touched")
	}
	out, err := Generate(in)
	if err != nil {
		t.Fatalf("a rule with a target_key effect is still usable: %v", err)
	}
	if !bytes.Equal(base.World, out.World) {
		t.Fatal("the target_key effect changed the world")
	}
}
