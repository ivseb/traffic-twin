package mock

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// A manual rule with derived values (rules 1.10, 3.15) and a respond effect
// with an error body typed by a person (C15).
const derivedRule = `{"id":"r-0102","kind":"causal","status":"approved","origin":"manual","title":"Totale calcolato",
  "cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201]},"bind":{"order":{"from":"resp.body","path":"$.id"}}},
  "effects":[
    {"id":"priced","entity":"order","target_id":"${order}","set":{
      "total":{"$derive":{"fn":"round","args":[{"$derive":{"fn":"mul","args":[{"$derive":{"fn":"sum","args":["${field:items[*].qty}"]}},9.95]}}]}},
      "note":{"$derive":{"fn":"date","offset":"+30d","format":"date"}},
      "phone":{"$derive":{"fn":"copy","args":["${order}"]}},
      "email":{"$derive":{"fn":"template","template":"'syn'NNNN@'example'.'com'"}}},"after":"1h"},
    {"id":"locked","respond":{"service":"shop-api","op":"GET /orders/{id}","status":409,"times":1,
      "body":{"error":{"code":"E-LOCKED","message":"Ordine in lavorazione, riprova"}}},"after":"0s"}],
  "outcomes":[{"name":"always","p":1,"effects":["priced","locked"]}],
  "evidence":{"counts":{"causes":0,"distinct_subjects":0,"outcomes":{"always":0}}}}`

func withRule(t *testing.T, src string) func(*packtest.Spec) {
	var r miner.Rule
	if err := json.Unmarshal([]byte(src), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(nil); err != nil {
		t.Fatal(err)
	}
	return func(sp *packtest.Spec) {
		var doc map[string]any
		if err := json.Unmarshal(sp.Files["rules.json"], &doc); err != nil {
			panic(err)
		}
		b, _ := json.Marshal(r)
		var m any
		_ = json.Unmarshal(b, &m)
		doc["rules"] = append(doc["rules"].([]any), m)
		sp.Manifest["rules"].(map[string]any)["approved"] = append(sp.Manifest["rules"].(map[string]any)["approved"].([]any), r.ID())
		b, _ = json.Marshal(doc)
		sp.Files["rules.json"] = packtest.Canon(string(b))
	}
}

func TestDerivedValuesAndErrorBody(t *testing.T) {
	e := newEnv(t, exact(), withSpec(withRule(t, derivedRule)))
	sid := e.newSession(map[string]any{"seed": 3})
	r := e.req("POST", "/__svc/shop-api/orders", map[string]any{
		"items": []any{map[string]any{"sku": "SKU-A", "qty": 2}, map[string]any{"sku": "SKU-B", "qty": 3}},
		"email": "x@example.com"}, sess(sid))
	if r.status != 201 {
		t.Fatalf("order: %d %s", r.status, r.body)
	}
	id := r.json()["id"].(string)

	// the respond effect answers once with the typed body
	r = e.req("GET", "/__svc/shop-api/orders/"+id, nil, sess(sid))
	if r.status != 409 || !strings.Contains(string(r.body), `"code":"E-LOCKED"`) {
		t.Fatalf("typed error body: %d %s", r.status, r.body)
	}
	e.advance(sid, "1h")
	r = e.req("GET", "/__svc/shop-api/orders/"+id, nil, sess(sid))
	if r.status != 200 {
		t.Fatalf("read: %d %s", r.status, r.body)
	}
	o := r.json()
	if o["total"].(json.Number).String() != "49.75" {
		t.Fatalf("total = %v", o["total"])
	}
	clock := e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()["now"].(string)
	if note := o["note"].(string); len(note) != 10 || note <= clock[:10] {
		t.Fatalf("note %q is not clock + 30d (clock %s)", note, clock)
	}
	if o["phone"] != id {
		t.Fatalf("copy of a variable: %v", o["phone"])
	}
	if em := o["email"].(string); !strings.HasPrefix(em, "syn") || !strings.HasSuffix(em, "@example.com") || len(em) != len("syn0000@example.com") {
		t.Fatalf("template: %q", em)
	}
}

func TestFaultRuleBodyAndExample(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(map[string]any{"seed": 1})
	put := func(rules []any) resp {
		return e.ctl("PUT", "/sessions/"+sid+"/faults", map[string]any{"mode": "custom", "rules": rules})
	}
	if r := put([]any{map[string]any{"service": "shop-api", "op": "GET /orders/{id}", "status": 404, "p": 1, "example": "no-such-example"}}); r.status != 400 || !strings.Contains(string(r.body), "/rules/0/example") {
		t.Fatalf("unknown example: %d %s", r.status, r.body)
	}
	if r := put([]any{map[string]any{"service": "shop-api", "op": "GET /orders/{id}", "latency_ms": 5, "p": 1, "body": map[string]any{"a": 1}}}); r.status != 400 {
		t.Fatalf("body without status: %d %s", r.status, r.body)
	}
	if r := put([]any{map[string]any{"service": "shop-api", "op": "GET /orders/{id}", "status": 503, "p": 1, "times": 1,
		"body": map[string]any{"error": map[string]any{"code": "E-MAINT", "message": "Manutenzione"}}}}); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	r := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0001", nil, sess(sid))
	if r.status != 503 || !strings.Contains(string(r.body), "E-MAINT") {
		t.Fatalf("fault body: %d %s", r.status, r.body)
	}
	if r := put([]any{map[string]any{"service": "shop-api", "op": "GET /orders/{id}", "status": 404, "p": 1, "example": "order-not-found"}}); r.status != 200 {
		t.Fatalf("put example: %d %s", r.status, r.body)
	}
	r = e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0001", nil, sess(sid))
	if r.status != 404 || !strings.Contains(string(r.body), "ORDER_NOT_FOUND") {
		t.Fatalf("fault example: %d %s", r.status, r.body)
	}
}
