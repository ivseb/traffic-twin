package derive

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func setPath(m map[string]any, p string, v any) {
	parts := strings.Split(p, ".")
	for _, k := range parts[:len(parts)-1] {
		n, ok := m[k].(map[string]any)
		if !ok {
			n = map[string]any{}
			m[k] = n
		}
		m = n
	}
	m[parts[len(parts)-1]] = v
}

var now = time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)

func TestEval(t *testing.T) {
	state := obj(t, `{"limit":1000,"used":250.5,"items":[{"price":10.1,"qty":2},{"price":20.2,"qty":1}],"start":"2026-01-31","orderId":"ORD-2026-000184"}`)
	vars := map[string]any{"amount": json.Number("99.9"), "ref": "ABC"}
	env := Env{Var: func(n string) (any, bool) { v, ok := vars[n]; return v, ok }, Object: state, Now: now, Scope: "r-1/e/f",
		Effect: func(id string) (string, bool) { return "SHP-SYN-0001", id == "made" }}
	cases := []struct{ expr, want string }{
		{`{"fn":"copy","args":["${amount}"]}`, `"99.9"`},
		{`{"fn":"copy","args":["${field:orderId}"]}`, `"ORD-2026-000184"`},
		{`{"fn":"copy","args":["fixed text"]}`, `"fixed text"`},
		{`{"fn":"sum","args":["${field:items[*].price}"]}`, `"30.3"`},
		{`{"fn":"count","args":["${field:items}"]}`, `"2"`},
		{`{"fn":"count","args":["${field:items[*].qty}"]}`, `"2"`},
		{`{"fn":"sub","args":["${field:limit}","${field:used}"]}`, `"749.5"`},
		{`{"fn":"sub","args":["${field:limit}",{"$derive":{"fn":"sum","args":["${field:items[*].price}"]}}]}`, `"969.7"`},
		{`{"fn":"mul","args":["${amount}",0.22]}`, `"21.978"`},
		{`{"fn":"round","args":[{"$derive":{"fn":"mul","args":["${amount}",0.22]}}]}`, `"21.98"`},
		{`{"fn":"div","args":["${field:limit}",3]}`, `"333.333333333"`},
		{`{"fn":"min","args":["${field:limit}",500]}`, `"500"`},
		{`{"fn":"date","offset":"+30d","format":"date"}`, `"2026-11-26"`},
		{`{"fn":"date","offset":"-1h"}`, `"2026-10-27T09:00:00Z"`},
		{`{"fn":"date","args":["${field:start}"],"offset":"+1d","format":"date"}`, `"2026-02-01"`},
		{`{"fn":"copy","args":["${effect:made}"]}`, `"SHP-SYN-0001"`},
	}
	for _, c := range cases {
		e, err := Parse(map[string]any{Key: obj(t, c.expr)})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		v, err := e.Eval(env)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		got, _ := json.Marshal(v)
		if s := string(got); s != c.want && `"`+s+`"` != c.want {
			t.Fatalf("%s = %s, want %s", c.expr, got, c.want)
		}
	}
	// template: an id format copying a segment of a field, numbered per scope
	e, err := Parse(map[string]any{Key: obj(t, `{"fn":"template","template":"'INV'-{orderId#-1|trim0}-NNNN"}`)})
	if err != nil {
		t.Fatal(err)
	}
	seq := map[string]uint64{}
	env.Seq = func(s string) uint64 { seq[s]++; return seq[s] }
	a, _ := e.Eval(env)
	b, _ := e.Eval(env)
	if !strings.HasPrefix(a.(string), "INV-184-") || a == b {
		t.Fatalf("template: %v %v", a, b)
	}
}

func TestParseErrors(t *testing.T) {
	bad := map[string]string{
		`{"fn":"pow","args":[1,2]}`:                      "unknown function",
		`{"fn":"sub","args":[1]}`:                        "takes 2",
		`{"fn":"sum","args":["${nope:x}"]}`:              "unknown reference",
		`{"fn":"add","args":["text",1]}`:                 "only an argument of copy",
		`{"fn":"date","offset":"30 days"}`:               "offset must",
		`{"fn":"date","format":"time"}`:                  "date format",
		`{"fn":"template","template":"NN?"}`:             "",
		`{"fn":"copy","args":[1],"extra":true}`:          "unknown field",
		`{"fn":"round","args":[1],"digits":9}`:           "0 to 6",
		`{"fn":"copy","args":["${a}"],"offset":"+1d"}`:   "only for date",
		`{"fn":"add","args":[1,{"$derive":{"fn":"x"}}]}`: "unknown function",
		`{"fn":"copy","args":[{"$derive":{"fn":"copy","args":[{"$derive":{"fn":"copy","args":[{"$derive":{"fn":"copy","args":[{"$derive":{"fn":"copy","args":[{"$derive":{"fn":"copy","args":[1]}}]}}]}}]}}]}}]}`: "nested",
	}
	for expr, want := range bad {
		_, err := Parse(map[string]any{Key: obj(t, expr)})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v (want %q)", expr, err, want)
		}
	}
	if _, err := Parse(map[string]any{Key: obj(t, `{"fn":"copy","args":[1]}`), "x": 1}); err == nil {
		t.Fatal("extra key accepted")
	}
}

func TestResolveOrderAndReferences(t *testing.T) {
	values := obj(t, `{"status":"OPEN","total":{"$derive":{"fn":"sum","args":["${field:items[*].price}"]}},
		"vat":{"$derive":{"fn":"round","args":[{"$derive":{"fn":"mul","args":["${field:total}",0.22]}}]}},
		"due":{"$derive":{"fn":"date","offset":"+15d","format":"date"}},
		"missing":{"$derive":{"fn":"copy","args":["${nobind}"]}}}`)
	state := obj(t, `{"items":[{"price":10},{"price":5.5}]}`)
	lit := func(v any) (any, bool) { return v, true }
	out := Resolve(values, state, Env{Now: now, Var: func(string) (any, bool) { return nil, false }}, lit, setPath)
	b, _ := json.Marshal(out)
	if string(b) != `{"due":"2026-11-11","status":"OPEN","total":15.5,"vat":3.41}` {
		t.Fatalf("%s", b)
	}
	if _, ok := state["total"]; ok {
		t.Fatal("state was changed")
	}
	e, _ := Parse(values["vat"])
	if r := e.References(); len(r.Fields) != 1 || r.Fields[0] != "total" || e.ResultType() != "number" {
		t.Fatalf("%+v", r)
	}
}
