package gate

import (
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// kCheck verifies docs/spec/pack.md 7: archetypes with at least k_min real
// subjects, x-tt-value.enum (and schema enum) values and published rule
// outcomes concerning at least k_min distinct subjects, and no published
// count (x-tt-observed, evidence.counts, evidence.keys[].matches) below
// k_min except zero.
func kCheck(files []*parsed, c *packContext, in *Input) Check {
	var f findings
	k := int64(in.KMin)
	small := func(n float64) bool { return n != 0 && n < float64(k) }
	for _, a := range in.Archetypes {
		if int64(a.Size) < k {
			f.add("world.jsonl", "", "an archetype has fewer than k_min real subjects")
		}
	}
	num := func(v ttjson.Value) (float64, bool) {
		if v.Kind != ttjson.Number {
			return 0, false
		}
		return ttjson.ParseFloat([]byte(v.Str)), true
	}
	for _, p := range files {
		if p.bad {
			continue
		}
		switch p.kind {
		case "contract":
			depsK(p, in, &f)
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				if isKey {
					return
				}
				if v.Kind == ttjson.String && last(keys) == "[]" && len(keys) > 1 && keys[len(keys)-2] == "enum" {
					n, declared := in.Prov.Declared[v.Str]
					if (declared || !c.ruleLiterals[v.Str]) && n < k {
						f.add(p.path, ptr, "enum value concerns fewer than k_min distinct subjects")
					}
				}
				if v.Kind == ttjson.String && has(keys, exampleKeys) {
					if n, ok := in.Prov.Declared[v.Str]; ok && n < k && !in.Prov.Synthetic[v.Str] {
						f.add(p.path, ptr, "example value concerns fewer than k_min distinct subjects")
					}
				}
				if n, ok := num(v); ok && len(keys) >= 2 && keys[len(keys)-2] == "x-tt-observed" && last(keys) == "calls" && small(n) {
					f.add(p.path, ptr, "published count below k_min")
				}
			})
		case "rules":
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				// rules v1.9: the clear values of customer attributes and of
				// conditions are published values too.
				if v.Kind == ttjson.String && ((isKey && attrValueKeys(keys)) || (!isKey && conditionValue(keys))) && rareDeclared(in, v.Str, k) {
					f.add(p.path, ptr, "rule value concerns fewer than k_min distinct subjects")
				}
				if isKey {
					return
				}
				if v.Kind == ttjson.String && has(keys, fieldValueKeys) && rareDeclared(in, v.Str, k) {
					f.add(p.path, ptr, "rule value concerns fewer than k_min distinct subjects")
				}
				n, ok := num(v)
				if !ok {
					return
				}
				inCounts := has(keys, map[string]bool{"counts": true}) && has(keys, map[string]bool{"evidence": true})
				isMatches := last(keys) == "matches" && has(keys, map[string]bool{"keys": true})
				// rules v1.9: the subjects behind an attribute or an aggregate.
				isSubjects := len(keys) == 3 && (keys[0] == "attributes" || keys[0] == "aggregates") && last(keys) == "subjects"
				if (inCounts || isMatches || isSubjects) && small(n) {
					f.add(p.path, ptr, "published count below k_min")
				}
			})
			rules, _ := p.doc.Get("rules")
			for i, r := range rules.Arr {
				id, _ := r.Get("id")
				ocs, _ := r.Get("outcomes")
				for j, o := range ocs.Arr {
					name, _ := o.Get("name")
					pv, _ := o.Get("p")
					if pp, _ := num(pv); pp == 0 {
						continue
					}
					if n, ok := in.OutcomeSubjects[id.Str][name.Str]; ok && n > 0 && n < k {
						f.add(p.path, "/rules/"+itoa(int64(i))+"/outcomes/"+itoa(int64(j)), "rule outcome concerns fewer than k_min distinct subjects")
					}
				}
			}
		case "world", "scenarios":
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				// A keep value seen for fewer than k_min subjects (contract.k_min
				// may be below gate.k_min) never reaches the world (r4).
				if !isKey && v.Kind == ttjson.String && p.kind == "world" && rareDeclared(in, v.Str, k) {
					f.add(p.path, ptr, "world value concerns fewer than k_min distinct subjects")
				}
				if !isKey && v.Kind == ttjson.String && last(keys) == "archetype" {
					if n, ok := c.archetypes[v.Str]; !ok || int64(n) < k {
						f.add(p.path, ptr, "archetype without k_min real subjects")
					}
				}
			})
		}
	}
	return f.check(CheckK, "tt-core")
}

// rareDeclared: s is an observed keep value seen for fewer than k distinct
// subjects, and no generator produced it.
func rareDeclared(in *Input, s string, k int64) bool {
	n, ok := in.Prov.Declared[s]
	return ok && n < k && !in.Prov.Synthetic[s]
}
