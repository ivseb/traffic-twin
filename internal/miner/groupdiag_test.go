package miner

import (
	"context"
	"strings"
	"testing"
)

// Usability test 5: the console kept asking for an approval ("the status
// must be keep") although the states already left as codes.
func TestGroupDiagSaysStatesAreObserved(t *testing.T) {
	_, res := demoFixture(t)
	if len(res.Diag.Groups) != 1 {
		t.Fatalf("groups: %+v", res.Diag.Groups)
	}
	g := res.Diag.Groups[0]
	if g.Events != res.Events || g.Events == 0 || g.ObservedSeconds == 0 {
		t.Errorf("the group's own figures: %+v (run: %d events)", g, res.Events)
	}
	if !g.StatesObserved || len(g.StateFields) == 0 || g.Lifecycles == 0 || len(g.ClearFields) == 0 {
		t.Errorf("states in clear not reported: %+v", g)
	}
	for _, d := range res.Diag.Rules {
		if d.Kind == KindCausal && d.Entity != "" && d.Values != ValuesInClear {
			t.Errorf("candidate %s %s: values %q, the demo keeps its fields in clear", d.Service, d.Op, d.Values)
		}
	}
}

func TestStatusExposesGroupsAndNoEffectNeverAsksForApprovalWhenInClear(t *testing.T) {
	s, _, _ := newTestService(t)
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := getStatus(t, s)
	if len(st.Groups) != 1 || st.Groups[0].Events != st.Events || !st.Groups[0].StatesObserved {
		t.Fatalf("status groups: %+v (events %d)", st.Groups, st.Events)
	}
	// Values in clear: an object without lifecycle is not a policy problem.
	e := &entity{clearFields: []string{"status"}}
	if v, f := valuesOf(e); v != ValuesInClear || len(f) != 1 {
		t.Errorf("valuesOf in clear: %s %v", v, f)
	}
	if txt := noEffectText(e); !strings.Contains(txt, "in clear") || strings.Contains(txt, "no field of the object is in clear") {
		t.Errorf("text: %q", txt)
	}
	// Nothing in clear: only then an approval may be what is missing.
	e = &entity{}
	if v, _ := valuesOf(e); v != ValuesDropped {
		t.Errorf("valuesOf dropped: %s", v)
	}
	if txt := noEffectText(e); !strings.Contains(txt, "no field of the object is in clear") {
		t.Errorf("text: %q", txt)
	}
}
