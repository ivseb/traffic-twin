package core

import (
	"encoding/json"
	"testing"

	"github.com/ivseb/traffic-twin/internal/groupscope"
)

// Usability test 5: "events examined" showed the whole console's number (the
// same for every team). Under a group selection the status carries the
// selected groups' own.
func TestFilterStatusScopesTheCoverageToTheGroup(t *testing.T) {
	body := []byte(`{"state":"ok","events":1252698,"subjects":300,"observed_hours":5.5,
		"groups":[{"group":"deliveries","events":4000,"subjects":80,"observed_s":3600,"states_observed":true},
		          {"group":"library","events":1248698,"subjects":220,"observed_s":19800,"states_observed":false}],
		"entities":[],"rule_diagnostics":[]}`)
	out, ok := filterStatus(body, map[string][]string{}, groupscope.Set{"deliveries"})
	if !ok {
		t.Fatal("not filtered")
	}
	var st struct {
		Events        int     `json:"events"`
		EventsTotal   int     `json:"events_total"`
		Subjects      int     `json:"subjects"`
		ObservedHours float64 `json:"observed_hours"`
		Groups        []struct {
			Group          string `json:"group"`
			StatesObserved bool   `json:"states_observed"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		t.Fatal(err)
	}
	if st.Events != 4000 || st.EventsTotal != 1252698 || st.Subjects != 80 || st.ObservedHours != 1 {
		t.Errorf("scoped figures: %+v", st)
	}
	if len(st.Groups) != 1 || st.Groups[0].Group != "deliveries" || !st.Groups[0].StatesObserved {
		t.Errorf("groups: %+v", st.Groups)
	}
	// Every group: the console's numbers, all groups listed.
	out, _ = filterStatus(body, nil, nil)
	st.Groups = nil
	if err := json.Unmarshal(out, &st); err != nil || st.Events != 1252698 || len(st.Groups) != 2 {
		t.Errorf("all groups: %+v %v", st, err)
	}
	// A status stored before the per-group figures keeps the totals.
	old := []byte(`{"state":"ok","events":10,"groups":[],"entities":[],"rule_diagnostics":[]}`)
	out, _ = filterStatus(old, map[string][]string{}, groupscope.Set{"deliveries"})
	if err := json.Unmarshal(out, &st); err != nil || st.Events != 10 {
		t.Errorf("old status: %+v %v", st, err)
	}
}
