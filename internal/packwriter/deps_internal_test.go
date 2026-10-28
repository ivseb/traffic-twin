package packwriter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/world"
)

func TestFilterContractDropsCombinationsBelowK(t *testing.T) {
	doc := `{"type":"object","properties":{"category":{"type":"string"},"macro":{"type":"string"}},
	"x-tt-dependencies":[
	 {"fields":["category","macro"],"combinations":[
	   {"at_least":100,"values":["Forni","Grandi elettrodomestici"]},
	   {"at_least":20,"values":["Tagliaerba","Giardino"]}]},
	 {"fields":["category","price"],"combinations":[{"at_least":20,"values":["Tagliaerba",{"min":10}]}]}]}`
	var v map[string]any
	if err := world.DecodeGeneric([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	declared := map[string]int64{"Forni": 50, "Grandi elettrodomestici": 50, "Tagliaerba": 5, "Giardino": 50}
	filterContract(v, declared, nil, 20, false)
	b, err := world.CanonicalFile(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "Tagliaerba") || !strings.Contains(s, `"partial":true`) || strings.Contains(s, `"price"`) {
		t.Fatalf("filtered: %s", s)
	}
	if !strings.Contains(s, `"Forni","Grandi elettrodomestici"`) {
		t.Fatalf("kept combination missing: %s", s)
	}
}

// withCatalogue gives the order of the demo shop two dependent fields, as the
// inference would publish them (declared values, combinations with subjects).
func withCatalogue(t *testing.T, a *Assembly, subjects int64) {
	t.Helper()
	for i := range a.Contracts {
		c := &a.Contracts[i]
		if c.Service != "shop-api" {
			continue
		}
		var doc map[string]any
		if err := world.DecodeGeneric(c.Doc, &doc); err != nil {
			t.Fatal(err)
		}
		ord := doc["components"].(map[string]any)["schemas"].(map[string]any)["Order"].(map[string]any)
		props := ord["properties"].(map[string]any)
		props["macro"] = map[string]any{"type": "string", "enum": []any{"Grandi elettrodomestici", "Telefonia"}}
		props["category"] = map[string]any{"type": "string", "enum": []any{"Forni", "Smartphone"}}
		ord["x-tt-dependencies"] = []any{map[string]any{"fields": []any{"category", "macro"}, "combinations": []any{
			map[string]any{"values": []any{"Forni", "Grandi elettrodomestici"}, "at_least": 100},
			map[string]any{"values": []any{"Smartphone", "Telefonia"}, "at_least": 20}}}}
		b, err := world.CanonicalFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		c.Doc = b
		if c.Declared == nil {
			c.Declared = map[string]int64{}
		}
		for _, v := range []string{"Grandi elettrodomestici", "Telefonia", "Forni", "Smartphone"} {
			c.Declared[v] = 100
		}
		c.Combos = map[string]int64{
			"category\x1fmacro\x1eForni\x1fGrandi elettrodomestici": 20,
			"category\x1fmacro\x1eSmartphone\x1fTelefonia":          subjects,
		}
	}
}

// A rule written by hand (origin manual, response effect) goes through the
// world, the gate and the pack reader like a mined one.
func TestPackCarriesManualRules(t *testing.T) {
	var doc map[string]any
	if err := world.DecodeGeneric(demoFile(t, "rules.json"), &doc); err != nil {
		t.Fatal(err)
	}
	var manual map[string]any
	if err := world.DecodeGeneric([]byte(`{"id":"r-0101","kind":"causal","status":"approved","origin":"manual","title":"Dopo un ordine la prima lettura risponde 404",
	  "cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201]},"bind":{"order":{"from":"resp.body","path":"$.id"}}},
	  "effects":[{"id":"first-read-missing","respond":{"service":"shop-api","op":"GET /orders/{id}","status":404,"times":1},"after":"0s"},
	             {"id":"carrier-flaky","respond":{"service":"shipping-ext","op":"GET /v1/shipments","status":503,"p":0.25},"after":"10m"}],
	  "outcomes":[{"name":"always","p":1,"effects":["first-read-missing","carrier-flaky"]}],
	  "evidence":{"counts":{"causes":0,"distinct_subjects":0,"outcomes":{"always":0}}}}`), &manual); err != nil {
		t.Fatal(err)
	}
	doc["rules"] = append(doc["rules"].([]any), manual)
	b, err := world.CanonicalFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := world.ParseRules(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := demoAssembly(t, 42)
	in := demoWorldInput(t, 42, 40)
	in.Rules = rules
	out, err := world.Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	a.Rules, a.World = rules, out
	kg := newFakeKeyguard()
	res, files := runGate(t, kg, a)
	if !res.Passed() {
		t.Fatalf("pack with a manual rule failed: %+v", res.Report.Checks)
	}
	if !strings.Contains(string(files[RulesPath]), `"origin":"manual"`) || !strings.Contains(string(files[RulesPath]), `"respond"`) {
		t.Fatalf("rules.json: %s", files[RulesPath])
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

func TestPackCarriesAndChecksFieldDependencies(t *testing.T) {
	kg := newFakeKeyguard()
	a := demoAssembly(t, 42)
	withCatalogue(t, a, 20)
	res, files := runGate(t, kg, a)
	if !res.Passed() {
		t.Fatalf("pack with dependencies failed: %+v", res.Report.Checks)
	}
	if !strings.Contains(string(files["contracts/shop-api.openapi.json"]), `"x-tt-dependencies"`) {
		t.Fatal("the pack lost the dependencies")
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

	// A combination seen for fewer than k subjects never passes.
	a = demoAssembly(t, 42)
	withCatalogue(t, a, 4)
	res, _ = runGate(t, kg, a)
	if res.Passed() || checkStatus(res)[gate.CheckK] != "fail" {
		t.Fatalf("combination below k passed: %v", checkStatus(res))
	}
}
