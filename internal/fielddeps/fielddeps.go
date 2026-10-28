// Package fielddeps reads and enforces the field dependencies of a contract
// (x-tt-dependencies, docs/spec/pack.md section 4.2): for low-cardinality
// properties of the same object (keep values and bucket bands), the
// combinations of values that were observed together for at least k_min
// distinct subjects. A macro-category "Grandi elettrodomestici" goes with
// the categories "Forni" and "Frigoriferi", never with "Smartphone".
//
// The world generator, the mock and the synthetic examples use Enforce so
// that every object they produce holds an observed combination
// (conditional sampling): the fields the caller must keep (values copied
// from a request or set by a rule) are fixed, the others are chosen among
// the combinations compatible with them.
package fielddeps

import (
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
)

// Extension is the name of the OpenAPI extension on object schemas.
const Extension = "x-tt-dependencies"

// Value is one value of a combination: a literal (string, number, boolean)
// or a numeric band [Min, Max) (an open end is nil).
type Value struct {
	Lit      any
	Band     bool
	Min, Max *float64
}

// Key identifies the value: two values with the same key are the same.
func (v Value) Key() string {
	if v.Band {
		k := "b:"
		if v.Min != nil {
			k += strconv.FormatFloat(*v.Min, 'g', -1, 64)
		}
		k += ":"
		if v.Max != nil {
			k += strconv.FormatFloat(*v.Max, 'g', -1, 64)
		}
		return k
	}
	switch x := v.Lit.(type) {
	case string:
		return "s:" + x
	case bool:
		return "t:" + strconv.FormatBool(x)
	}
	if f, ok := AsFloat(v.Lit); ok {
		return "n:" + strconv.FormatFloat(f, 'g', -1, 64)
	}
	return "?"
}

// Matches reports whether the JSON value x is this value (for a band: a
// number inside it).
func (v Value) Matches(x any) bool {
	if v.Band {
		f, ok := AsFloat(x)
		if !ok {
			return false
		}
		return (v.Min == nil || f >= *v.Min) && (v.Max == nil || f < *v.Max)
	}
	switch l := v.Lit.(type) {
	case string:
		s, ok := x.(string)
		return ok && s == l
	case bool:
		b, ok := x.(bool)
		return ok && b == l
	}
	if _, isStr := x.(string); isStr {
		return false
	}
	a, ok1 := AsFloat(v.Lit)
	b, ok2 := AsFloat(x)
	return ok1 && ok2 && a == b
}

// AsFloat reads a JSON number in any of the forms the decoders produce
// (json.Number, float64, ints, or a named string type holding a lexeme).
func AsFloat(x any) (float64, bool) {
	switch n := x.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string, bool, nil:
		return 0, false
	}
	rv := reflect.ValueOf(x)
	if rv.Kind() == reflect.String {
		f, err := strconv.ParseFloat(rv.String(), 64)
		return f, err == nil
	}
	return 0, false
}

// Dep is one dependency: the fields (two in v1) and the observed
// combinations, one value per field, each with its weight (at_least).
type Dep struct {
	Fields  []string
	Combos  [][]Value
	Weights []float64
	Partial bool
}

// Parse reads the dependencies of an object schema (generic JSON as decoded
// by encoding/json, numbers as json.Number or float64). Malformed entries
// are skipped.
func Parse(schema map[string]any) []Dep {
	raw, _ := schema[Extension].([]any)
	var out []Dep
	for _, x := range raw {
		m, _ := x.(map[string]any)
		fl, _ := m["fields"].([]any)
		d := Dep{}
		for _, f := range fl {
			if s, ok := f.(string); ok && s != "" {
				d.Fields = append(d.Fields, s)
			}
		}
		if len(d.Fields) < 2 || len(d.Fields) != len(fl) {
			continue
		}
		d.Partial, _ = m["partial"].(bool)
		cs, _ := m["combinations"].([]any)
		for _, c := range cs {
			cm, _ := c.(map[string]any)
			vals, _ := cm["values"].([]any)
			if len(vals) != len(d.Fields) {
				continue
			}
			combo := make([]Value, 0, len(vals))
			ok := true
			for _, v := range vals {
				pv, good := parseValue(v)
				if !good {
					ok = false
					break
				}
				combo = append(combo, pv)
			}
			if !ok {
				continue
			}
			w, _ := AsFloat(cm["at_least"])
			if w <= 0 {
				w = 1
			}
			d.Combos = append(d.Combos, combo)
			d.Weights = append(d.Weights, w)
		}
		if len(d.Combos) > 0 {
			out = append(out, d)
		}
	}
	return out
}

func parseValue(v any) (Value, bool) {
	switch x := v.(type) {
	case string, bool:
		return Value{Lit: x}, true
	case map[string]any:
		b := Value{Band: true}
		if f, ok := AsFloat(x["min"]); ok {
			b.Min = &f
		}
		if f, ok := AsFloat(x["max"]); ok {
			b.Max = &f
		}
		if b.Min == nil && b.Max == nil {
			return Value{}, false
		}
		return b, true
	}
	if _, ok := AsFloat(v); ok {
		return Value{Lit: v}, true
	}
	return Value{}, false
}

// active returns the dependencies whose fields are all present in obj.
func active(deps []Dep, obj map[string]any) []Dep {
	var out []Dep
	for _, d := range deps {
		all := true
		for _, f := range d.Fields {
			if _, ok := obj[f]; !ok {
				all = false
				break
			}
		}
		if all {
			out = append(out, d)
		}
	}
	return out
}

// Holds reports whether obj satisfies every dependency whose fields are all
// present (a dependency with a missing field says nothing).
func Holds(deps []Dep, obj map[string]any) bool {
	for _, d := range active(deps, obj) {
		if !holdsOne(d, obj) {
			return false
		}
	}
	return true
}

func holdsOne(d Dep, obj map[string]any) bool {
	for _, c := range d.Combos {
		ok := true
		for i, f := range d.Fields {
			if !c[i].Matches(obj[f]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Options tell Enforce what it may change and how.
type Options struct {
	// Fixed reports the fields whose value must be kept (nil: none).
	Fixed func(field string) bool
	// Required reports the fields that must stay present (nil: none);
	// Enforce may drop a free optional field when nothing else works.
	Required func(field string) bool
	// Choose returns an index in [0, n): random for the world,
	// deterministic for the mock and the examples (nil: always 0).
	Choose func(n int) int
	// Make turns a chosen value into the JSON value to store (a band into a
	// number inside it). Required.
	Make func(field string, v Value) any
	// Fresh makes free fields ignore their current value (it was a
	// placeholder): every combination can be drawn, not only those that
	// agree with what was generated first.
	Fresh bool
}

// maxSteps bounds the search of one Enforce.
const maxSteps = 4096

type cand struct {
	v     Value
	keep  bool // the current value of the object, kept as it is
	field string
}

// solve finds values for the free fields of the active dependencies so that
// every one holds; it returns the changes (only fields whose value changes).
func solve(deps []Dep, obj map[string]any, o Options) (map[string]Value, bool) {
	act := active(deps, obj)
	if len(act) == 0 {
		return nil, true
	}
	fixed := func(f string) bool { return o.Fixed != nil && o.Fixed(f) }
	choose := func(n int) int {
		if o.Choose == nil || n <= 1 {
			return 0
		}
		i := o.Choose(n)
		if i < 0 || i >= n {
			return 0
		}
		return i
	}
	varSet := map[string]bool{}
	for _, d := range act {
		for _, f := range d.Fields {
			varSet[f] = true
		}
	}
	vars := make([]string, 0, len(varSet))
	for f := range varSet {
		vars = append(vars, f)
	}
	sort.Strings(vars)
	// Domains: a fixed field keeps its value; a free field may keep its
	// current value when it is one of the candidates, else any candidate
	// (in an order rotated by Choose, so that draws differ).
	dom := map[string][]cand{}
	for _, f := range vars {
		if fixed(f) {
			dom[f] = []cand{{keep: true, field: f}}
			continue
		}
		seen := map[string]bool{}
		var list []cand
		var cur *cand
		for _, d := range act {
			for i, df := range d.Fields {
				if df != f {
					continue
				}
				for _, c := range d.Combos {
					k := c[i].Key()
					if seen[k] {
						continue
					}
					seen[k] = true
					if !o.Fresh && cur == nil && c[i].Matches(obj[f]) {
						cur = &cand{keep: true, field: f}
						continue
					}
					list = append(list, cand{v: c[i], field: f})
				}
			}
		}
		if n := len(list); n > 1 {
			r := choose(n)
			list = append(list[r:], list[:r]...)
		}
		if cur != nil {
			list = append([]cand{*cur}, list...)
		}
		dom[f] = list
	}
	byVar := map[string][]int{}
	for i, d := range act {
		for _, f := range d.Fields {
			byVar[f] = append(byVar[f], i)
		}
	}
	assign := map[string]cand{}
	matches := func(v Value, c cand) bool {
		if c.keep {
			return v.Matches(obj[c.field])
		}
		return v.Key() == c.v.Key()
	}
	consistent := func(d Dep) bool {
		for _, combo := range d.Combos {
			ok := true
			for i, f := range d.Fields {
				if a, set := assign[f]; set && !matches(combo[i], a) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}
	steps := 0
	var dfs func(i int) bool
	dfs = func(i int) bool {
		if i == len(vars) {
			return true
		}
		f := vars[i]
		for _, c := range dom[f] {
			if steps++; steps > maxSteps {
				return false
			}
			assign[f] = c
			good := true
			for _, di := range byVar[f] {
				if !consistent(act[di]) {
					good = false
					break
				}
			}
			if good && dfs(i+1) {
				return true
			}
		}
		delete(assign, f)
		return false
	}
	if !dfs(0) {
		return nil, false
	}
	out := map[string]Value{}
	for f, c := range assign {
		if !c.keep {
			out[f] = c.v
		}
	}
	return out, true
}

// Enforce changes the free fields of obj so that every dependency whose
// fields are present holds. When no assignment exists (the fixed values
// themselves were never observed together, or a k-filtered combination is
// missing), it drops free optional fields of the dependencies, one at a
// time, and tries again. It returns false when obj still breaks a
// dependency (only fixed or required fields left to blame).
func Enforce(deps []Dep, obj map[string]any, o Options) bool {
	if len(deps) == 0 || obj == nil {
		return true
	}
	for attempt := 0; attempt < 16; attempt++ {
		ch, ok := solve(deps, obj, o)
		if ok {
			keys := make([]string, 0, len(ch))
			for f := range ch {
				keys = append(keys, f)
			}
			sort.Strings(keys)
			for _, f := range keys {
				obj[f] = o.Make(f, ch[f])
			}
			return true
		}
		// Drop the last free optional field of an unsatisfied dependency.
		var cands []string
		for _, d := range active(deps, obj) {
			for _, f := range d.Fields {
				if (o.Fixed == nil || !o.Fixed(f)) && (o.Required == nil || !o.Required(f)) {
					cands = append(cands, f)
				}
			}
		}
		if len(cands) == 0 {
			return false
		}
		sort.Strings(cands)
		delete(obj, cands[len(cands)-1])
	}
	return Holds(deps, obj)
}

// BandNumber returns a number inside a band: the lower bound when it is
// closed, otherwise just below the upper bound; integer rounds inside.
func BandNumber(v Value, integer bool, frac float64) float64 {
	switch {
	case v.Min != nil && v.Max != nil:
		lo, hi := *v.Min, *v.Max
		x := lo + (hi-lo)*clamp01(frac)
		if integer {
			x = math.Ceil(lo) + math.Floor((math.Ceil(hi)-1-math.Ceil(lo))*clamp01(frac)+0.5)
			if x >= hi {
				x = math.Ceil(lo)
			}
			return x
		}
		x = math.Floor(x*100) / 100
		if x < lo {
			x = lo
		}
		return x
	case v.Min != nil:
		if integer {
			return math.Ceil(*v.Min)
		}
		return *v.Min
	case v.Max != nil:
		if integer {
			return math.Ceil(*v.Max) - 1
		}
		return *v.Max - 1
	}
	return 0
}

func clamp01(f float64) float64 {
	if f < 0 || math.IsNaN(f) {
		return 0
	}
	if f >= 1 {
		return 0.999999
	}
	return f
}
