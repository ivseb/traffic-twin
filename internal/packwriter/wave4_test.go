package packwriter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/world"
)

// Rules v1.9 reach the pack: the customer attributes in the rules and in
// the world's profiles, an aggregate and a conditional outcome pass the
// gate and the pack loads.
func TestWave4PackPassesAndLoads(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(demoFile(t, "rules.json"), &doc); err != nil {
		t.Fatal(err)
	}
	doc["attributes"] = []any{map[string]any{"name": "segment", "values": map[string]any{"GOLD": 0.3, "STANDARD": 0.7}, "subjects": 40,
		"fields": []any{map[string]any{"service": "shop-api", "op": "GET /orders/{id}", "at": map[string]any{"from": "resp.body", "path": "$.segment"}}}}}
	doc["aggregates"] = []any{map[string]any{"service": "shop-api", "op": "GET /orders/{id}", "at": map[string]any{"from": "resp.body", "path": "$.orders"},
		"count": map[string]any{"entity": "order"}, "subjects": 40}}
	for _, x := range doc["rules"].([]any) {
		r := x.(map[string]any)
		if r["kind"] == "causal" && r["status"] == "approved" {
			ocs := r["outcomes"].([]any)
			ocs[len(ocs)-1].(map[string]any)["when"] = []any{map[string]any{"customer": "segment", "in": []any{"GOLD"}}}
			break
		}
	}
	b, _ := json.Marshal(doc)
	r, err := world.ParseRules(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := demoWorldInput(t, 42, 40)
	in.Rules = r
	out, err := world.Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.World), `"segment":"`) {
		t.Fatal("the world's profiles have no attribute")
	}
	a := demoAssembly(t, 42)
	a.Rules, a.World = r, out
	a.Presets = world.DerivePresets(r, out.Customers, a.Faults.Hints(), "it")
	kg := newFakeKeyguard()
	res, files := runGate(t, kg, a)
	if !res.Passed() {
		for _, c := range res.Report.Checks {
			t.Logf("%s %s %+v", c.ID, c.Status, c.Findings)
		}
		t.Fatal("a v1.9 pack did not pass the gate")
	}
	if !strings.Contains(string(files[RulesPath]), `"attributes"`) || !strings.Contains(string(files[RulesPath]), `"aggregates"`) {
		t.Fatal("the v1.9 members are not in the pack's rules")
	}
	unsigned, err := Archive(files)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := kg.SignPack(context.Background(), unsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{o: Options{Keyguard: kg, Now: func() time.Time { return testT0.Add(4 * time.Hour) }}}
	if err := s.Verify(context.Background(), files, pr.Signature.SigFile()); err != nil {
		t.Fatalf("pack.Load: %v", err)
	}
}
