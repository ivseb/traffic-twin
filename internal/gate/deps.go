package gate

import (
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Field dependencies of the contracts (x-tt-dependencies, pack.md 4.2):
// every combination names sibling properties of the same schema (structure),
// and its values are declared keep values or numeric bands. The k check
// verifies that each combination concerns at least k_min distinct subjects
// (Input.Combos) and that no published size class is below k_min.

const depsKey = "x-tt-dependencies"

var depsKeys = map[string]bool{depsKey: true}

// comboKey is the key of a combination as contract.ComboKey builds it.
func comboKey(fields, values []string) string {
	return strings.Join(fields, "\x1f") + "\x1e" + strings.Join(values, "\x1f")
}

// depLexeme renders one combination value like contract.DepValueLexeme.
func depLexeme(v ttjson.Value) (string, bool) {
	switch v.Kind {
	case ttjson.String, ttjson.Number:
		return v.Str, true
	case ttjson.Object:
		lo, hi := "", ""
		for _, m := range v.Obj {
			if m.Value.Kind != ttjson.Number {
				return "", false
			}
			switch m.Key {
			case "min":
				lo = m.Value.Str
			case "max":
				hi = m.Value.Str
			default:
				return "", false
			}
		}
		if lo == "" && hi == "" {
			return "", false
		}
		return lo + ".." + hi, true
	}
	return "", false
}

// eachCombination calls fn for every combination of every x-tt-dependencies
// array of a contract, with the pointer of the combination.
func eachCombination(p *parsed, fn func(fields []string, combo ttjson.Value, ptr string)) {
	walk(p.doc, "", nil, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
		if isKey || v.Kind != ttjson.Array || last(keys) != depsKey {
			return
		}
		for i, d := range v.Arr {
			dptr := ptr + "/" + itoa(int64(i))
			fv, _ := d.Get("fields")
			var fields []string
			for _, f := range fv.Arr {
				fields = append(fields, f.Str)
			}
			for mi, m := range d.Obj {
				if m.Key != "combinations" {
					continue
				}
				for j, c := range m.Value.Arr {
					fn(fields, c, dptr+"/combinations\x00"+itoa(int64(mi))+"/"+itoa(int64(j)))
				}
			}
		}
	})
}

// depsK adds the k findings of the dependencies of contract p.
func depsK(p *parsed, in *Input, f *findings) {
	k := int64(in.KMin)
	eachCombination(p, func(fields []string, c ttjson.Value, ptr string) {
		vals, _ := c.Get("values")
		if len(vals.Arr) != len(fields) || len(fields) < 2 {
			f.add(p.path, ptr, "malformed field combination")
			return
		}
		lex := make([]string, 0, len(vals.Arr))
		for _, v := range vals.Arr {
			l, ok := depLexeme(v)
			if !ok {
				f.add(p.path, ptr, "malformed field combination")
				return
			}
			if v.Kind == ttjson.String {
				if n, declared := in.Prov.Declared[v.Str]; declared && n < k {
					f.add(p.path, ptr, "combination value concerns fewer than k_min distinct subjects")
				}
			}
			lex = append(lex, l)
		}
		if al, ok := c.Get("at_least"); !ok || al.Kind != ttjson.Number || ttjson.ParseFloat([]byte(al.Str)) < float64(k) {
			f.add(p.path, ptr, "published count below k_min")
		} else if !sizeClass(al.Str, k) {
			f.add(p.path, ptr, "published size class is not k_min or a power of ten")
		}
		if in.Combos != nil {
			if n := in.Combos[comboKey(fields, lex)]; n < k {
				f.add(p.path, ptr, "field combination concerns fewer than k_min distinct subjects")
			}
		}
	})
}

// depsProvenance classifies a string under x-tt-dependencies: a field name
// must be a property of the contract, a value a declared keep value (or a
// literal of an approved rule). It returns false when keys are not under
// the extension.
func depsProvenance(s string, keys []string, c *packContext, declared func(string) bool) (handled, ok bool) {
	if !has(keys, depsKeys) {
		return false, false
	}
	if len(keys) >= 2 && last(keys) == "[]" && keys[len(keys)-2] == "fields" {
		return true, c.contractKeys[s]
	}
	if len(keys) >= 2 && last(keys) == "[]" && keys[len(keys)-2] == "values" {
		return true, declared(s) || c.ruleLiterals[s]
	}
	return true, false
}

// sizeClass: lex is a size class of pack.md 4.2 for k: k itself or a power
// of ten not below k, written as a plain integer. Anything else could be an
// exact count (r4).
func sizeClass(lex string, k int64) bool {
	if lex == strconv.FormatInt(k, 10) {
		return true
	}
	if len(lex) < 2 || lex[0] != '1' || strings.Trim(lex[1:], "0") != "" {
		return false
	}
	n, err := strconv.ParseInt(lex, 10, 64)
	return err == nil && n >= k
}
