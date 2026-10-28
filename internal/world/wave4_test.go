package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack"
)

type worldLines struct {
	customers []map[string]any
	entities  []map[string]any
	history   []map[string]any
	other     [][]byte
}

func splitWorld(t *testing.T, b []byte) worldLines {
	t.Helper()
	var w worldLines
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		switch m["type"] {
		case "customer":
			w.customers = append(w.customers, m)
			continue
		case "entity":
			w.entities = append(w.entities, m)
		case "history":
			w.history = append(w.history, m)
		}
		w.other = append(w.other, append([]byte(nil), sc.Bytes()...))
	}
	return w
}

func withSegment(in *Input) {
	in.Rules.Attributes = []pack.Attribute{{Name: "segment", Values: map[string]float64{"GOLD": 0.25, "STANDARD": 0.75}, Subjects: 40,
		Fields: []pack.AttrField{{Service: "shop-api", Op: "GET /orders/{id}", At: pack.Ref{From: "resp.body", Path: "$.segment"}}}}}
}

// Every customer gets an attribute value from its shares, deterministically;
// everything else in the world stays the same.
func TestWave4WorldAttributes(t *testing.T) {
	base, err := Generate(demoInput(t, 7, 200))
	if err != nil {
		t.Fatal(err)
	}
	in := demoInput(t, 7, 200)
	withSegment(in)
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	wb, wo := splitWorld(t, base.World), splitWorld(t, out.World)
	if !bytes.Equal(bytes.Join(wb.other, nil), bytes.Join(wo.other, nil)) {
		t.Fatal("the attributes changed lines other than the customers")
	}
	gold := 0
	for i, c := range wo.customers {
		p := c["profile"].(map[string]any)
		seg := p["segment"]
		if seg != "GOLD" && seg != "STANDARD" {
			t.Fatalf("customer %v: segment %v", c["id"], seg)
		}
		if seg == "GOLD" {
			gold++
		}
		if p["name"] != wb.customers[i]["profile"].(map[string]any)["name"] {
			t.Fatal("the attributes changed the people")
		}
	}
	if gold < 25 || gold > 80 {
		t.Fatalf("GOLD should be about a quarter of 200 customers, got %d", gold)
	}
	again, _ := Generate(func() *Input { in := demoInput(t, 7, 200); withSegment(in); return in }())
	if !bytes.Equal(again.World, out.World) {
		t.Fatal("not deterministic")
	}
}

// Request conditions are not evaluated by the generator: the joint p keep
// the marginal distribution and the world is the same; a customer
// condition restricts the outcome to the customers it holds for.
func TestWave4WorldConditions(t *testing.T) {
	base, err := Generate(demoInput(t, 7, 200))
	if err != nil {
		t.Fatal(err)
	}
	in := demoInput(t, 7, 200)
	in.Rules.Causal[0].Outcomes[1].When = []pack.Match{{At: &pack.Ref{From: "req.headers", Name: "x-channel"}, In: []any{"APP"}}}
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base.World, out.World) {
		t.Fatal("a request condition changed the world")
	}

	in = demoInput(t, 7, 200)
	withSegment(in)
	r := &in.Rules.Causal[0]
	r.Outcomes[1].When = []pack.Match{{Customer: "segment", In: []any{"GOLD"}}} // cancelled: GOLD customers only
	out, err = Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	w := splitWorld(t, out.World)
	seg := map[string]string{}
	for _, c := range w.customers {
		seg[c["id"].(string)] = c["profile"].(map[string]any)["segment"].(string)
	}
	owner := map[string]string{}
	for _, e := range w.entities {
		if o, ok := e["customer_id"].(string); ok {
			owner[e["id"].(string)] = o
		}
	}
	cancelled := 0
	for _, h := range w.history {
		if h["rule_id"] == r.ID && h["outcome"] == "cancelled" {
			cancelled++
			if o := owner[h["id"].(string)]; o != "" && seg[o] != "GOLD" {
				t.Fatalf("a cancelled shipment of a %s customer", seg[o])
			}
		}
	}
	if cancelled == 0 {
		t.Fatal("no cancelled outcome at all: the test proves nothing")
	}
	// A cause condition on the customer: STANDARD customers never fire it.
	in = demoInput(t, 7, 200)
	withSegment(in)
	in.Rules.Causal[0].Cause.When.Match = []pack.Match{{Customer: "segment", In: []any{"GOLD"}}}
	out, err = Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	w = splitWorld(t, out.World)
	for _, c := range w.customers {
		seg[c["id"].(string)] = c["profile"].(map[string]any)["segment"].(string)
	}
	owner = map[string]string{}
	for _, e := range w.entities {
		if o, ok := e["customer_id"].(string); ok {
			owner[e["id"].(string)] = o
		}
	}
	fired := 0
	for _, h := range w.history {
		if h["rule_id"] == in.Rules.Causal[0].ID {
			fired++
			if o := owner[h["id"].(string)]; o != "" && seg[o] == "STANDARD" {
				t.Fatal("the rule fired for a STANDARD customer")
			}
		}
	}
	if fired == 0 {
		t.Fatal("the rule never fired for GOLD customers")
	}
}

// target_all changes every entity of the customer that matches where.
func TestWave4WorldTargetAll(t *testing.T) {
	in := demoInput(t, 7, 50)
	r := &in.Rules.Causal[0]
	r.Effects = append(r.Effects, pack.Effect{ID: "orders-flagged", Entity: "order", TargetAll: true,
		Where: map[string]any{"status": "CONFIRMED"}, Set: map[string]any{"flagged": true}})
	for i := range r.Outcomes {
		r.Outcomes[i].Effects = append(r.Outcomes[i].Effects, "orders-flagged")
	}
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	w := splitWorld(t, out.World)
	n := 0
	for _, e := range w.entities {
		if e["entity"] != "order" {
			continue
		}
		st := e["state"].(map[string]any)
		if st["status"] == "CONFIRMED" {
			if st["flagged"] != true {
				t.Fatalf("an order of the customer was not flagged: %v", e)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no order: the test proves nothing")
	}
}

// A pack of some services keeps only the v1.9 members of those services; a
// rule that names an attribute left out is excluded.
func TestWave4ScopeExtras(t *testing.T) {
	doc := `{"format":"tt.rules/v1",
	 "attributes":[
	   {"name":"segment","values":{"A":0.5,"B":0.5},"subjects":40,"fields":[
	     {"service":"shop-api","op":"GET /orders/{id}","at":{"from":"resp.body","path":"$.segment"}},
	     {"service":"shipping-ext","op":"GET /v1/shipments","at":{"from":"resp.body","path":"$.segment"}}]},
	   {"name":"tier","values":{"X":0.5,"Y":0.5},"subjects":40,"fields":[
	     {"service":"shipping-ext","op":"GET /v1/shipments","at":{"from":"resp.body","path":"$.tier"}}]}],
	 "aggregates":[{"service":"shipping-ext","op":"GET /v1/shipments","at":{"from":"resp.body","path":"$.n"},"count":{"entity":"order"}}],
	 "lists":[{"service":"shipping-ext","op":"GET /v1/shipments","at":{"from":"resp.body","path":"$.items[*]"},"list":{}}],
	 "entities":[{"name":"order","service":"shop-api","id_domain":"order","id_field":"id","id_prefix":"ORD-SYN-"}],
	 "rules":[
	  {"id":"r-0001","kind":"batch","status":"approved","title":"t","schedule":"0 2 * * *","entity":"order","set":{"status":"X"},"fraction":1},
	  {"id":"r-0002","kind":"causal","status":"approved","title":"t","cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201],"match":[{"customer":"tier","in":["X"]}]}},
	   "effects":[{"id":"e","entity":"order","create":{"status":"X"},"after":"0s"}],"outcomes":[{"name":"a","p":1,"effects":["e"]}]}]}`
	r, err := ParseRules([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, info := r.Scope([]string{"shop-api"})
	if len(s.Attributes) != 1 || s.Attributes[0].Name != "segment" || len(s.Attributes[0].Fields) != 1 {
		t.Fatalf("attributes in scope: %+v", s.Attributes)
	}
	if _, ok := s.Doc["aggregates"]; ok {
		t.Fatal("an aggregate of another service is in scope")
	}
	if _, ok := s.Doc["lists"]; ok {
		t.Fatal("a list of another service is in scope")
	}
	attrs := s.Doc["attributes"].([]any)
	if len(attrs) != 1 || len(attrs[0].(map[string]any)["fields"].([]any)) != 1 {
		t.Fatalf("document attributes: %v", attrs)
	}
	if m := info.Excluded["r-0002"]; len(m) != 1 || m[0] != "attribute:tier" {
		t.Fatalf("a rule naming an attribute left out must be excluded: %v", info.Excluded)
	}
}
