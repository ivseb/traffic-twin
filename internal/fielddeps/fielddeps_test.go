package fielddeps

import (
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"
)

const shopSchema = `{
  "type": "object",
  "properties": {"macro": {"type": "string"}, "category": {"type": "string"}, "price": {"type": "number"}},
  "x-tt-dependencies": [
    {"fields": ["macro", "category"], "combinations": [
      {"values": ["Grandi elettrodomestici", "Forni"], "at_least": 100},
      {"values": ["Grandi elettrodomestici", "Frigoriferi"], "at_least": 20},
      {"values": ["Telefonia", "Smartphone"], "at_least": 1000}
    ]},
    {"fields": ["category", "price"], "combinations": [
      {"values": ["Forni", {"min": 200, "max": 500}], "at_least": 20},
      {"values": ["Frigoriferi", {"min": 500}], "at_least": 20},
      {"values": ["Smartphone", {"max": 200}], "at_least": 20},
      {"values": ["Smartphone", {"min": 200, "max": 500}], "at_least": 20}
    ]}
  ]
}`

func parseSchema(t *testing.T) []Dep {
	t.Helper()
	var s map[string]any
	dec := json.NewDecoder(strings.NewReader(shopSchema))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	deps := Parse(s)
	if len(deps) != 2 || len(deps[0].Combos) != 3 || len(deps[1].Combos) != 4 {
		t.Fatalf("parse: %+v", deps)
	}
	return deps
}

func make_(r *rand.Rand) func(string, Value) any {
	return func(_ string, v Value) any {
		if v.Band {
			return json.Number(jsonFloat(BandNumber(v, false, r.Float64())))
		}
		return v.Lit
	}
}

func jsonFloat(f float64) string { b, _ := json.Marshal(f); return string(b) }

func TestEnforceNeverLeavesAnUnobservedCombination(t *testing.T) {
	deps := parseSchema(t)
	r := rand.New(rand.NewPCG(1, 2))
	macros := []any{"Grandi elettrodomestici", "Telefonia"}
	cats := []any{"Forni", "Frigoriferi", "Smartphone"}
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		obj := map[string]any{"macro": macros[r.IntN(2)], "category": cats[r.IntN(3)], "price": json.Number(jsonFloat(float64(r.IntN(1000))))}
		ok := Enforce(deps, obj, Options{Choose: func(n int) int { return r.IntN(n) }, Make: make_(r)})
		if !ok || !Holds(deps, obj) {
			t.Fatalf("draw %d: %v (ok=%v)", i, obj, ok)
		}
		seen[obj["macro"].(string)+"/"+obj["category"].(string)] = true
	}
	// Every observed combination comes out, and only those.
	if len(seen) != 3 {
		t.Fatalf("combinations drawn: %v", seen)
	}
}

func TestEnforceKeepsFixedFields(t *testing.T) {
	deps := parseSchema(t)
	for i := 0; i < 200; i++ {
		r := rand.New(rand.NewPCG(uint64(i), 9))
		obj := map[string]any{"macro": "Telefonia", "category": "Forni"}
		ok := Enforce(deps, obj, Options{Fixed: func(f string) bool { return f == "macro" }, Choose: func(n int) int { return r.IntN(n) }, Make: make_(r)})
		if !ok || obj["macro"] != "Telefonia" || obj["category"] != "Smartphone" {
			t.Fatalf("got %v", obj)
		}
	}
	// Two fixed values never seen together: nothing to change, reported.
	obj := map[string]any{"macro": "Telefonia", "category": "Forni"}
	if Enforce(deps, obj, Options{Fixed: func(string) bool { return true }, Make: make_(rand.New(rand.NewPCG(1, 1)))}) {
		t.Fatal("an impossible fixed pair must be reported")
	}
	// A free optional field is dropped when nothing else works: price 50
	// is fixed, Frigoriferi needs >= 500, so category (optional) goes.
	obj = map[string]any{"category": "Frigoriferi", "price": json.Number("50"), "macro": "Grandi elettrodomestici"}
	ok := Enforce(deps, obj, Options{Fixed: func(f string) bool { return f == "price" || f == "macro" }, Make: make_(rand.New(rand.NewPCG(1, 1)))})
	if !ok || !Holds(deps, obj) {
		t.Fatalf("got %v ok=%v", obj, ok)
	}
}

func TestBandsAndAbsentFields(t *testing.T) {
	deps := parseSchema(t)
	// price missing: the second dependency says nothing.
	if !Holds(deps, map[string]any{"macro": "Telefonia", "category": "Smartphone"}) {
		t.Fatal("absent field")
	}
	if Holds(deps, map[string]any{"category": "Frigoriferi", "price": json.Number("100")}) {
		t.Fatal("price 100 is not in the band of Frigoriferi")
	}
	if !Holds(deps, map[string]any{"category": "Frigoriferi", "price": 900.0}) {
		t.Fatal("open band")
	}
	v := Value{Band: true, Min: ptr(10), Max: ptr(20)}
	for f := 0.0; f < 1; f += 0.01 {
		if x := BandNumber(v, true, f); x < 10 || x >= 20 {
			t.Fatalf("integer %v", x)
		}
		if x := BandNumber(v, false, f); x < 10 || x >= 20 {
			t.Fatalf("number %v", x)
		}
	}
}

func ptr(f float64) *float64 { return &f }
