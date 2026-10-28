package packwriter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/world"
)

func decodeDoc(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Usability test 5: a pack built in the first minutes answered PICKED_UP at
// once and a generic 402, with no warning. The build now reports what it
// rests on too little traffic for, with the counts.
func TestObservationWarningsOfAPoorPack(t *testing.T) {
	t0 := time.Date(2026, 10, 25, 16, 20, 0, 0, time.UTC)
	rules := &world.Rules{Doc: decodeDoc(t, `{"rules":[
		{"id":"r-0018","kind":"causal","status":"approved","cause":{"service":"couriers-ext","op":"POST /v1/assignments"},
		 "evidence":{"counts":{"causes":38,"outcomes":{"happy":36,"cancelled":2}}}},
		{"id":"r-0019","kind":"causal","status":"approved","cause":{"service":"couriers-ext","op":"POST /v1/assignments"},
		 "evidence":{"counts":{"causes":4000,"outcomes":{"happy":3900,"cancelled":100}}}},
		{"id":"r-0020","kind":"batch","status":"approved","evidence":{"counts":{"runs":1}}}]}`)}
	contracts := []world.Contract{{Service: "payments-ext", Doc: []byte(`{"openapi":"3.1.0","paths":{
		"/v1/payments":{"post":{"x-tt-observed":{"calls":412}},"parameters":[]},
		"/v1/refunds":{"post":{"x-tt-observed":{"calls":57}}},
		"/v1/rare":{"get":{"x-tt-observed":{"first_seen":"2026-10-25"}}}}}`)}}

	ws := observationWarnings(contracts, rules, 20, [2]time.Time{t0, t0.Add(18 * time.Minute)})
	type key struct{ scope, rule, op, outcome string }
	got := map[key]gate.PackWarning{}
	for _, w := range ws {
		if w.Code != gate.WarnFewObservations {
			t.Errorf("code %q", w.Code)
		}
		got[key{w.Scope, w.Rule, w.Op, w.Outcome}] = w
	}
	if w, ok := got[key{"pack", "", "", ""}]; !ok || *w.Observed != 18 || w.Needed != 60 || w.Unit != "minutes" {
		t.Errorf("pack warning: %+v", w)
	}
	if w, ok := got[key{"rule", "r-0018", "POST /v1/assignments", ""}]; !ok || *w.Observed != 38 || w.Needed != FewObservations || w.Service != "couriers-ext" {
		t.Errorf("rule warning: %+v", w)
	}
	if _, ok := got[key{"rule", "r-0019", "POST /v1/assignments", ""}]; ok {
		t.Error("a well observed rule is warned about")
	}
	if w, ok := got[key{"outcome", "r-0018", "POST /v1/assignments", "cancelled"}]; !ok || *w.Observed != 2 || w.Needed != 20 {
		t.Errorf("outcome warning: %+v", w)
	}
	if _, ok := got[key{"outcome", "r-0018", "POST /v1/assignments", "happy"}]; ok {
		t.Error("an outcome seen 36 times (>= k) is warned about")
	}
	if w, ok := got[key{"rule", "r-0020", "", ""}]; !ok || w.Unit != "runs" {
		t.Errorf("batch warning: %+v", w)
	}
	if w, ok := got[key{"endpoint", "", "POST /v1/refunds", ""}]; !ok || *w.Observed != 57 || w.Service != "payments-ext" {
		t.Errorf("endpoint warning: %+v", w)
	}
	if w, ok := got[key{"endpoint", "", "GET /v1/rare", ""}]; !ok || !w.BelowK || w.Observed != nil {
		t.Errorf("endpoint below k: %+v", w)
	}
	if _, ok := got[key{"endpoint", "", "POST /v1/payments", ""}]; ok {
		t.Error("an endpoint seen 412 times is warned about")
	}

	// A rich pack has no warning.
	rich := &world.Rules{Doc: decodeDoc(t, `{"rules":[{"id":"r-0001","kind":"causal","status":"approved","cause":{"service":"s","op":"GET /x"},
		"evidence":{"counts":{"causes":5000,"outcomes":{"ok":5000}}}}]}`)}
	if ws := observationWarnings([]world.Contract{{Service: "s", Doc: []byte(`{"paths":{"/x":{"get":{"x-tt-observed":{"calls":5000}}}}}`)}},
		rich, 20, [2]time.Time{t0, t0.Add(24 * time.Hour)}); len(ws) != 0 {
		t.Errorf("a pack on a day of traffic: %+v", ws)
	}
	capped, total := capWarnings(make([]gate.PackWarning, maxPackWarnings+30))
	if len(capped) != maxPackWarnings || total != maxPackWarnings+30 {
		t.Errorf("cap: %d of %d", len(capped), total)
	}
}
