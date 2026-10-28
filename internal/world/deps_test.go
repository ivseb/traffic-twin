package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/fielddeps"
)

// Invented catalogue: macro-category -> categories, with price bands.
const worldDeps = `[
  {"fields":["category","macro"],"combinations":[
    {"values":["Forni","Grandi elettrodomestici"],"at_least":100},
    {"values":["Frigoriferi","Grandi elettrodomestici"],"at_least":100},
    {"values":["Accessori","Telefonia"],"at_least":20},
    {"values":["Smartphone","Telefonia"],"at_least":1000}]},
  {"fields":["category","price"],"combinations":[
    {"values":["Forni",{"min":200,"max":500}],"at_least":20},
    {"values":["Frigoriferi",{"min":500}],"at_least":20},
    {"values":["Accessori",{"max":50}],"at_least":20},
    {"values":["Smartphone",{"min":100,"max":1000}],"at_least":20}]}]`

// catalogueContracts adds dependent fields to the order request of the demo
// shop (the order state copies the request).
func catalogueContracts(t *testing.T) []Contract {
	cs := demoContracts(t)
	var doc map[string]any
	if err := json.Unmarshal(cs[0].Doc, &doc); err != nil {
		t.Fatal(err)
	}
	req := doc["components"].(map[string]any)["schemas"].(map[string]any)["OrderRequest"].(map[string]any)
	props := req["properties"].(map[string]any)
	enum := func(vals ...string) map[string]any {
		l := make([]any, len(vals))
		for i, v := range vals {
			l[i] = v
		}
		return map[string]any{"type": "string", "x-tt-value": map[string]any{"kind": "enum", "enum": l}}
	}
	props["macro"] = enum("Grandi elettrodomestici", "Telefonia")
	props["category"] = enum("Accessori", "Forni", "Frigoriferi", "Smartphone")
	props["price"] = map[string]any{"type": "number", "x-tt-value": map[string]any{"kind": "bucket", "bounds": []any{50, 100, 200, 500, 1000}}}
	req["required"] = append(req["required"].([]any), "macro", "category", "price")
	var deps any
	_ = json.Unmarshal([]byte(worldDeps), &deps)
	req["x-tt-dependencies"] = deps
	b, _ := json.Marshal(doc)
	cs[0].Doc = b
	return cs
}

func TestWorldNeverEmitsUnobservedCombinations(t *testing.T) {
	var s map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"x-tt-dependencies":` + worldDeps + `}`))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	deps := fielddeps.Parse(s)
	for _, seed := range []uint64{1, 2, 3} {
		in := demoInput(t, seed, 400)
		in.Contracts = catalogueContracts(t)
		out, err := Generate(in)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		orders := 0
		sc := bufio.NewScanner(bytes.NewReader(out.World))
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var row map[string]any
			d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			d.UseNumber()
			if err := d.Decode(&row); err != nil {
				t.Fatal(err)
			}
			if row["entity"] != "order" {
				continue
			}
			st, _ := row["state"].(map[string]any)
			if st == nil || st["macro"] == nil {
				continue
			}
			orders++
			if !fielddeps.Holds(deps, st) {
				t.Fatalf("seed %d: unobserved combination in %s", seed, sc.Bytes())
			}
			seen[st["macro"].(string)+"/"+st["category"].(string)] = true
		}
		if orders < 100 {
			t.Fatalf("seed %d: only %d orders", seed, orders)
		}
		// Every observed combination is drawn, and nothing else.
		if len(seen) != 4 {
			t.Fatalf("seed %d: combinations %v", seed, seen)
		}
	}
}
