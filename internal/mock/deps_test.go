package mock

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/fielddeps"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// Invented catalogue: macro-category -> categories, price bands.
const depsJSON = `[
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

// withCatalogue adds dependent fields to the order of shop-api and a
// GET /products/{id} operation whose answer is generated from the schema.
func withCatalogue(sp *packtest.Spec) {
	var doc map[string]any
	if err := json.Unmarshal(sp.Files["contracts/shop-api.openapi.json"], &doc); err != nil {
		panic(err)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	enum := func(vals ...string) map[string]any {
		l := make([]any, len(vals))
		for i, v := range vals {
			l[i] = v
		}
		return map[string]any{"type": "string", "enum": l}
	}
	macro := enum("Grandi elettrodomestici", "Telefonia")
	category := enum("Accessori", "Forni", "Frigoriferi", "Smartphone")
	price := map[string]any{"type": "number", "x-tt-value": map[string]any{"kind": "bucket", "bounds": []any{50, 100, 200, 500, 1000}}}
	var deps any
	_ = json.Unmarshal([]byte(depsJSON), &deps)

	req := schemas["OrderRequest"].(map[string]any)
	req["properties"].(map[string]any)["macro"] = macro
	ord := schemas["Order"].(map[string]any)
	op := ord["properties"].(map[string]any)
	op["macro"], op["category"], op["price"] = macro, category, price
	ord["required"] = append(ord["required"].([]any), "macro", "category", "price")
	ord["x-tt-dependencies"] = deps

	schemas["Product"] = map[string]any{"type": "object", "required": []any{"macro", "category", "price"},
		"properties": map[string]any{"macro": macro, "category": category, "price": price}, "x-tt-dependencies": deps}
	doc["paths"].(map[string]any)["/products/{id}"] = map[string]any{"get": map[string]any{"operationId": "getProduct",
		"parameters": []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
		"responses": map[string]any{"200": map[string]any{"description": "ok", "content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/Product"}}}}}}}
	b, _ := json.Marshal(doc)
	sp.Files["contracts/shop-api.openapi.json"] = packtest.Canon(string(b))
}

func parsedDeps(t *testing.T) []fielddeps.Dep {
	var s map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"x-tt-dependencies":` + depsJSON + `}`))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return fielddeps.Parse(s)
}

func TestMockNeverEmitsUnobservedCombinations(t *testing.T) {
	e := newEnv(t, withSpec(withCatalogue))
	deps := parsedDeps(t)
	sid := e.newSession(map[string]any{"seed": 7})
	seen := map[string]bool{}
	// Generated from the schema alone: many draws, one per product id.
	for i := 0; i < 300; i++ {
		r := e.req("GET", fmt.Sprintf("/__svc/shop-api/products/P-%d", i), nil, sess(sid))
		if r.status != 200 {
			t.Fatalf("product: %d %s", r.status, r.body)
		}
		v := r.json()
		if !fielddeps.Holds(deps, v) {
			t.Fatalf("unobserved combination: %s", r.body)
		}
		seen[v["macro"].(string)+"/"+v["category"].(string)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("draws never vary: %v", seen)
	}
	// The macro comes from the request (entity state): the category and the
	// price band are chosen to agree with it.
	for i, m := range []string{"Telefonia", "Grandi elettrodomestici", "Telefonia", "Grandi elettrodomestici"} {
		body := map[string]any{"items": []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 1}}, "email": fmt.Sprintf("u%d@example.com", i), "macro": m}
		r := e.req("POST", "/__svc/shop-api/orders", body, sess(sid))
		if r.status != 201 {
			t.Fatalf("order: %d %s", r.status, r.body)
		}
		v := r.json()
		if v["macro"] != m || !fielddeps.Holds(deps, v) {
			t.Fatalf("order %d: %s", i, r.body)
		}
		// Read back: same coherent values.
		g := e.req("GET", "/__svc/shop-api/orders/"+v["id"].(string), nil, sess(sid))
		if gv := g.json(); g.status != 200 || !fielddeps.Holds(deps, gv) || gv["macro"] != m {
			t.Fatalf("read back: %d %s", g.status, g.body)
		}
	}
	// World orders carry neither field: both generated, still coherent.
	g := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0042", nil, nil)
	if g.status != 200 || !fielddeps.Holds(deps, g.json()) {
		t.Fatalf("world order: %d %s", g.status, g.body)
	}
}
