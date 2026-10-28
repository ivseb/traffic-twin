package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/fielddeps"
)

// catalog is an invented shop catalogue: macro-category -> categories.
var catalog = map[string][]string{
	"Grandi elettrodomestici": {"Forni", "Frigoriferi", "Lavatrici"},
	"Telefonia":               {"Smartphone", "Accessori"},
	"Giardino":                {"Tagliaerba"},
}

var macros = []string{"Grandi elettrodomestici", "Telefonia", "Giardino"}

// productEvents builds GET /products/{id} responses: macro and category
// always agree; "Tagliaerba" is sold to only rareSubjects subjects; sku is a
// hmac token (never a dependency) and colour a keep value with many values.
func productEvents(t *testing.T, n, subjects, rareSubjects int) []*event.Event {
	var evs []*event.Event
	for i := 0; i < n; i++ {
		macro := macros[i%2] // the two big macros
		subj := 1000 + i%subjects
		if i%10 == 9 {
			macro = "Giardino"
			subj = 1000 + i%rareSubjects
		}
		cats := catalog[macro]
		cat := cats[(i/3)%len(cats)]
		band := "num:0-100"
		if macro == "Grandi elettrodomestici" {
			band = "num:>=250"
		}
		body := fmt.Sprintf(`{"category":"keep:%s","colour":"keep:c%03d","macro":"keep:%s","price":"%s","sku":"%s"}`, cat, i%200, macro, band, tok(7000+i))
		evs = append(evs, mkEv(t, evSpec{service: "shop-api", op: "GET /products/{id}", dir: event.Inbound, status: 200,
			subject: tok(subj), path: "/products/" + tok(9000+i), at: t0.Add(time.Duration(i) * time.Second), resBody: body}))
	}
	return evs
}

func TestDependenciesInferred(t *testing.T) {
	cfg := DefaultConfig()
	c := inferAll(t, cfg, nil, productEvents(t, 3000, 300, 5))
	s := c.Op("GET /products/{id}").Response(200).Body[0].Schema
	var mc *Dependency
	for _, d := range s.Deps {
		for _, f := range d.Fields {
			if f == "sku" || f == "colour" {
				t.Fatalf("a hmac or high-cardinality field took part: %+v", d)
			}
		}
		if strings.Join(d.Fields, ",") == "category,macro" {
			mc = d
		}
	}
	if mc == nil {
		t.Fatalf("no category/macro dependency: %+v", s.Deps)
	}
	got := map[string]bool{}
	for _, co := range mc.Combos {
		if co.Subjects < cfg.KMin || co.AtLeast < int64(cfg.KMin) {
			t.Fatalf("combination below k published: %+v", co)
		}
		got[co.Values[1].Value+"/"+co.Values[0].Value] = true
	}
	// Every combination of the big macros, none of the rare one (5 subjects < k).
	for _, m := range macros[:2] {
		for _, cat := range catalog[m] {
			if !got[m+"/"+cat] {
				t.Errorf("missing %s/%s", m, cat)
			}
		}
	}
	if got["Giardino/Tagliaerba"] || len(got) != 5 {
		t.Fatalf("combinations: %v", got)
	}
	if !mc.Partial {
		t.Error("the hidden rare combination must mark the dependency partial")
	}
	// The price band depends on the macro too.
	found := false
	for _, d := range s.Deps {
		if strings.Join(d.Fields, ",") == "macro,price" || strings.Join(d.Fields, ",") == "category,price" {
			found = true
		}
	}
	if !found {
		t.Errorf("no dependency with the price band: %+v", s.Deps)
	}

	// Render: x-tt-dependencies with size classes, never exact counts.
	b, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"x-tt-dependencies"`) || strings.Contains(string(b), "Tagliaerba") {
		t.Fatalf("render: %.3000s", b)
	}
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	sch := doc["paths"].(map[string]any)["/products/{id}"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	deps := fielddeps.Parse(sch["schema"].(map[string]any))
	if len(deps) == 0 {
		t.Fatal("rendered dependencies do not parse")
	}
	// Examples hold observed combinations only.
	for name, ex := range sch["examples"].(map[string]any) {
		v := ex.(map[string]any)["value"].(map[string]any)
		if !fielddeps.Holds(deps, v) {
			t.Errorf("example %s breaks a dependency: %v", name, v)
		}
	}
	// The gate's view.
	if combos := c.Combos(); len(combos) < 5 {
		t.Fatalf("combos for the gate: %v", combos)
	}
}

func TestDependenciesNeedKSubjects(t *testing.T) {
	// 3000 objects but only 10 subjects: nothing reaches k = 20.
	c := inferAll(t, DefaultConfig(), nil, productEvents(t, 3000, 10, 5))
	if s := c.Op("GET /products/{id}").Response(200).Body[0].Schema; len(s.Deps) != 0 {
		t.Fatalf("published below k: %+v", s.Deps)
	}
}

func TestDependenciesIndependentFieldsSayNothing(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 2000; i++ {
		body := fmt.Sprintf(`{"channel":"keep:%s","size":"keep:%s"}`, []string{"web", "app"}[(i/3)%2], []string{"S", "M", "L"}[i%3])
		evs = append(evs, mkEv(t, evSpec{service: "shop-api", op: "GET /x", dir: event.Inbound, status: 200,
			subject: tok(1000 + i%200), path: "/x", at: t0.Add(time.Duration(i) * time.Second), resBody: body}))
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	if s := c.Op("GET /x").Response(200).Body[0].Schema; len(s.Deps) != 0 {
		t.Fatalf("every pair seen: no dependency expected, got %+v", s.Deps)
	}
}

func TestJointAccumulatorIsBounded(t *testing.T) {
	// 10 low-cardinality fields with 40 values each: at most maxJointFields
	// fields tracked, and a pair over maxJointCombos is dropped with its memory.
	a := newNode()
	cfg := DefaultConfig()
	for i := 0; i < 5000; i++ {
		var members []string
		for f := 0; f < 10; f++ {
			members = append(members, fmt.Sprintf(`"f%d":"keep:v%d"`, f, (i*(f+1)+i/7)%40))
		}
		v := mustBody(t, "{"+strings.Join(members, ",")+"}")
		subj := tok(i % 500)
		a.observe(v, &obsCtx{cfg: &cfg, subject: func() string { return subj }}, 1)
	}
	if len(a.joint.fields) != maxJointFields {
		t.Fatalf("fields tracked: %d", len(a.joint.fields))
	}
	for k, p := range a.joint.pairs {
		if !p.over && len(p.combos) > maxJointCombos {
			t.Fatalf("pair %v holds %d combinations", k, len(p.combos))
		}
		if p.over && p.combos != nil {
			t.Fatalf("pair %v over the bound kept its memory", k)
		}
		for _, co := range p.combos {
			if len(co.subj) > cfg.KMin {
				t.Fatalf("subjects not capped: %d", len(co.subj))
			}
		}
	}
}

func TestAtLeast(t *testing.T) {
	for _, c := range []struct {
		n    int64
		k    int
		want int64
	}{{20, 20, 20}, {35, 20, 20}, {150, 20, 100}, {999, 20, 100}, {1000, 20, 1000}, {123456, 20, 100000}, {7, 5, 5}} {
		if got := AtLeast(c.n, c.k); got != c.want {
			t.Errorf("AtLeast(%d,%d) = %d, want %d", c.n, c.k, got, c.want)
		}
	}
}
