package gate

import (
	"context"
	"strings"
	"testing"
)

// A contract with field dependencies (invented catalogue).
const depsContract = `{"openapi":"3.1.0","paths":{"/products/{id}":{"get":{"operationId":"getProduct","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
"type":"object","properties":{"category":{"type":"string","enum":["Forni","Smartphone"]},"macro":{"type":"string","enum":["Grandi elettrodomestici","Telefonia"]},"price":{"type":"number"}},
"x-tt-dependencies":[
 {"fields":["category","macro"],"combinations":[{"at_least":100,"values":["Forni","Grandi elettrodomestici"]},{"at_least":20,"values":["Smartphone","Telefonia"]}]},
 {"fields":["category","price"],"combinations":[{"at_least":20,"values":["Forni",{"max":500,"min":200}]}]}]
}}}}}}}}}`

func depsInput() *Input {
	in := input(okWorld, &fakeMatcher{})
	in.Files["contracts/shop-api.openapi.json"] = []byte(depsContract)
	for _, v := range []string{"Forni", "Smartphone", "Grandi elettrodomestici", "Telefonia"} {
		in.Prov.Declared[v] = 40
	}
	in.Combos = map[string]int64{
		comboKey([]string{"category", "macro"}, []string{"Forni", "Grandi elettrodomestici"}): 20,
		comboKey([]string{"category", "macro"}, []string{"Smartphone", "Telefonia"}):          20,
		comboKey([]string{"category", "price"}, []string{"Forni", "200..500"}):                20,
	}
	return in
}

func findingsOf(r *Result, id string) []Finding {
	for _, c := range r.Report.Checks {
		if c.ID == id {
			return c.Findings
		}
	}
	return nil
}

func TestGateChecksFieldDependencies(t *testing.T) {
	ctx := context.Background()
	res, err := Run(ctx, depsInput())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("clean dependencies failed: %+v", res.Report.Checks)
	}

	// A combination seen for fewer than k subjects.
	in := depsInput()
	in.Combos[comboKey([]string{"category", "macro"}, []string{"Smartphone", "Telefonia"})] = 5
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "fail" {
		t.Fatalf("combination below k passed: %v", st)
	}
	// A combination that was never observed (not in the inference output).
	in = depsInput()
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(depsContract, `["Smartphone","Telefonia"]`, `["Forni","Telefonia"]`, 1))
	res, _ = Run(ctx, in)
	fs := findingsOf(res, CheckK)
	if len(fs) == 0 || !strings.Contains(fs[0].Pointer, "x-tt-dependencies/0/combinations/1") {
		t.Fatalf("unobserved combination: %+v", fs)
	}
	for _, f := range fs {
		if strings.Contains(f.Pointer+f.Reason, "Forni") {
			t.Fatal("a finding leaks the value")
		}
	}
	// A size class below k.
	in = depsInput()
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(depsContract, `"at_least":20,"values":["Smartphone"`, `"at_least":3,"values":["Smartphone"`, 1))
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckK] != "fail" {
		t.Fatalf("size class below k passed: %v", st)
	}
	// A value that is not a declared keep value (a real one copied by mistake).
	in = depsInput()
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(depsContract, `["Forni","Grandi elettrodomestici"]`, `["Forni","mario.rossi@gmail.com"]`, 1))
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckProvenance] != "fail" || st[CheckPII] != "fail" {
		t.Fatalf("undeclared value: %v", st)
	}
	// A field name that is not a property of the contract.
	in = depsInput()
	in.Files["contracts/shop-api.openapi.json"] = []byte(strings.Replace(depsContract, `"fields":["category","price"]`, `"fields":["category","ORD-2026-000184"]`, 1))
	res, _ = Run(ctx, in)
	if st := status(res); st[CheckProvenance] != "fail" {
		t.Fatalf("unknown field: %v", st)
	}
}
