package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Verify checks the integrity rules of a world (docs/spec/pack.md 5) against
// the rules it was generated with: line order, references of relations and
// customer_id, pending rows citing approved rules, branches and effects, and
// set effects on entities that exist or are created earlier. It returns
// the problems found (line numbers, never values).
func Verify(world []byte, r *Rules) []string {
	var probs []string
	bad := func(line int, f string, a ...any) {
		if len(probs) < 100 {
			probs = append(probs, fmt.Sprintf("line %d: ", line)+fmt.Sprintf(f, a...))
		}
	}
	type row struct {
		Type       string            `json:"type"`
		ID         string            `json:"id"`
		Entity     string            `json:"entity"`
		CustomerID *string           `json:"customer_id"`
		State      map[string]any    `json:"state"`
		RuleID     string            `json:"rule_id"`
		Outcome    string            `json:"outcome"`
		EffectID   string            `json:"effect_id"`
		Due        int64             `json:"due_offset_s"`
		Seq        int               `json:"seq"`
		EffectIDs  map[string]string `json:"effect_ids"`
	}
	order := map[string]int{"meta": 0, "customer": 1, "entity": 2, "history": 3, "pending": 4}
	custs := map[string]bool{}
	ents := map[string]bool{}
	var entRows []struct {
		line int
		r    row
	}
	var pend []struct {
		line int
		r    row
	}
	last, lastKey := -1, ""
	sc := bufio.NewScanner(bytes.NewReader(world))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	n := 0
	for sc.Scan() {
		n++
		var x row
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			bad(n, "not JSON")
			continue
		}
		o, ok := order[x.Type]
		if !ok {
			bad(n, "unknown type")
			continue
		}
		if o < last || (n == 1) != (x.Type == "meta") {
			bad(n, "line out of order")
		}
		var k string
		switch x.Type {
		case "customer":
			k = x.ID
			custs[x.ID] = true
		case "entity":
			k = x.Entity + "\x00" + x.ID
			ents[x.Entity+"\x00"+x.ID] = true
			entRows = append(entRows, struct {
				line int
				r    row
			}{n, x})
		case "pending":
			pend = append(pend, struct {
				line int
				r    row
			}{n, x})
		}
		if o == last && k != "" && k <= lastKey {
			bad(n, "not sorted")
		}
		last, lastKey = o, k
	}
	pendCreates := map[string]bool{}
	causal := map[string]int{}
	for i, c := range r.Causal {
		causal[c.ID] = i
	}
	for i, p := range pend {
		if p.r.Seq != i+1 {
			bad(p.line, "pending seq is not 1..n")
		}
		if i > 0 && p.r.Due < pend[i-1].r.Due {
			bad(p.line, "pending rows not ordered by due_offset_s")
		}
		if p.r.Due < 1 {
			bad(p.line, "due_offset_s < 1")
		}
		ci, ok := causal[p.r.RuleID]
		if !ok {
			bad(p.line, "pending row cites a rule that is not approved")
			continue
		}
		c := &r.Causal[ci]
		inBranch := false
		for _, o := range c.Outcomes {
			if o.Name == p.r.Outcome {
				for _, e := range o.Effects {
					inBranch = inBranch || e == p.r.EffectID
				}
			}
		}
		if !inBranch {
			bad(p.line, "pending effect is not in its branch")
			continue
		}
		var eff *struct{ create bool }
		for _, e := range c.Effects {
			if e.ID == p.r.EffectID {
				eff = &struct{ create bool }{e.Create != nil}
			}
		}
		k := p.r.Entity + "\x00" + p.r.ID
		if eff.create {
			pendCreates[k] = true
		} else if !ents[k] && !pendCreates[k] {
			bad(p.line, "pending set on an entity that does not exist")
		}
		if p.r.CustomerID != nil && !custs[*p.r.CustomerID] {
			bad(p.line, "customer_id cites no customer")
		}
	}
	for _, e := range entRows {
		if e.r.CustomerID != nil && !custs[*e.r.CustomerID] {
			bad(e.line, "customer_id cites no customer")
		}
		ent := r.Entity(e.r.Entity)
		if ent == nil {
			bad(e.line, "unknown entity type")
			continue
		}
		for _, rel := range ent.Relations {
			v := getPath(e.r.State, "$."+rel.Field)
			var ids []any
			if rel.Many {
				ids, _ = v.([]any)
			} else if v != nil {
				ids = []any{v}
			}
			for _, id := range ids {
				s, ok := id.(string)
				k := rel.Entity + "\x00" + s
				if !ok || (!ents[k] && !pendCreates[k]) {
					bad(e.line, "relation %s is broken", strings.ReplaceAll(rel.Field, "\x00", ""))
				}
			}
		}
	}
	return probs
}
