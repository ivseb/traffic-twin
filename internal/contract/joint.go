package contract

import (
	"math"
	"sort"
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Field dependencies (x-tt-dependencies, docs/spec/pack.md section 4.2):
// which values of two low-cardinality properties of the same object were
// seen together (macroCategory "Grandi elettrodomestici" with category
// "Forni"). Only keep values and bucket bands take part: never hmac tokens,
// shapes or times. A combination is published only when it was seen for at
// least KMin distinct subjects, like an enum value.
//
// Cost, per object schema node: at most maxJointFields tracked properties
// (the first ones seen), so at most 15 pairs; at most maxJointCombos
// combinations per pair (a pair above it is high-cardinality and dropped
// at once, with its memory); per combination a counter and at most KMin
// 8-byte subject hashes. Worst case about 15 x 128 x 20 hashes (~0.3 MB
// plus map overhead) per object node, typically a few KB; CPU is
// O(p^2) per object instance with p <= maxJointFields qualifying members.
// It runs in the same streaming pass as the rest of the inference.
const (
	maxJointFields = 6
	maxJointCombos = 128
)

type jointAcc struct {
	fields []string
	pairs  map[[2]int]*pairAcc
}

type pairAcc struct {
	combos map[string]*comboAcc
	over   bool
}

type comboAcc struct {
	a, b string // value keys: "s:<keep>", "n:<lexeme>", "b:<num: token>"
	n    int64
	subj map[uint64]struct{}
}

// jointKey returns the key of a member value that can take part in a
// dependency, "" otherwise.
func jointKey(v *event.Value) string {
	switch v.Kind {
	case event.Number:
		return "n:" + v.S
	case event.String:
		switch event.ClassifyToken(v.S) {
		case event.TokKeep:
			k, _ := event.KeepValue(v.S)
			return "s:" + k
		case event.TokNum:
			return "b:" + v.S
		}
	}
	return ""
}

func (a *accNode) observeJoint(v *event.Value, c *obsCtx) {
	if len(v.O) < 2 {
		return
	}
	type member struct {
		idx int
		key string
	}
	var ms []member
	for i := range v.O {
		m := &v.O[i]
		if m.K == "{trunc}" || m.K == "{*}" {
			continue
		}
		k := jointKey(&m.V)
		if k == "" {
			continue
		}
		if a.joint == nil {
			a.joint = &jointAcc{pairs: map[[2]int]*pairAcc{}}
		}
		idx := -1
		for j, f := range a.joint.fields {
			if f == m.K {
				idx = j
				break
			}
		}
		if idx < 0 {
			if len(a.joint.fields) >= maxJointFields {
				continue
			}
			a.joint.fields = append(a.joint.fields, m.K)
			idx = len(a.joint.fields) - 1
		}
		ms = append(ms, member{idx, k})
		if len(ms) >= maxJointFields {
			break
		}
	}
	if len(ms) < 2 {
		return
	}
	sh, hasSubj := c.subjectHash()
	for i := 0; i < len(ms); i++ {
		for j := i + 1; j < len(ms); j++ {
			x, y := ms[i], ms[j]
			if x.idx == y.idx {
				continue
			}
			if x.idx > y.idx {
				x, y = y, x
			}
			pk := [2]int{x.idx, y.idx}
			pa := a.joint.pairs[pk]
			if pa == nil {
				pa = &pairAcc{combos: map[string]*comboAcc{}}
				a.joint.pairs[pk] = pa
			}
			if pa.over {
				continue
			}
			ck := x.key + "\x00" + y.key
			co := pa.combos[ck]
			if co == nil {
				if len(pa.combos) >= maxJointCombos {
					pa.over, pa.combos = true, nil
					continue
				}
				co = &comboAcc{a: x.key, b: y.key}
				pa.combos[ck] = co
			}
			co.n++
			if hasSubj && len(co.subj) < c.cfg.KMin {
				if co.subj == nil {
					co.subj = map[uint64]struct{}{}
				}
				co.subj[sh] = struct{}{}
			}
		}
	}
}

// depValue turns a value key into the model value.
func depValue(key string) DepValue {
	switch key[:2] {
	case "s:":
		return DepValue{Type: "string", Value: key[2:]}
	case "b:":
		return DepValue{Type: "band", Value: key[2:]}
	}
	lex := key[2:]
	if isIntLexeme(lex) {
		return DepValue{Type: "integer", Value: lex}
	}
	return DepValue{Type: "number", Value: lex}
}

// allowedValues lists the value keys of a property that may appear in a
// published combination: its published enum values, or its bands seen for
// at least KMin subjects. ok is false when the property cannot take part.
func (f *finalizer) allowedValues(ch *accNode, s *Schema) (map[string]bool, bool) {
	if s == nil {
		return nil, false
	}
	out := map[string]bool{}
	switch s.Kind {
	case "enum":
		for _, e := range s.PublishedEnum() {
			if e.Type == "string" {
				out["s:"+e.Value] = true
			} else {
				out["n:"+e.Value] = true
			}
		}
	case "bucket":
		if s.Unit != "" { // time buckets do not take part
			return nil, false
		}
		for tok, b := range ch.bands {
			if len(b.subj) >= f.cfg.KMin {
				out["b:"+tok] = true
			}
		}
	default:
		return nil, false
	}
	return out, len(out) > 0
}

// dependencies sets Schema.Deps from the joint accumulator of an object
// node: one dependency per pair of properties whose published combinations
// do not cover every pair of their published values (otherwise the fields
// are independent as far as the contract can tell, and nothing is said).
func (f *finalizer) dependencies(a *accNode, s *Schema) {
	j := a.joint
	if j == nil || len(j.pairs) == 0 {
		return
	}
	keys := make([][2]int, 0, len(j.pairs))
	for k := range j.pairs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(x, y int) bool {
		fx := j.fields[keys[x][0]] + "\x00" + j.fields[keys[x][1]]
		fy := j.fields[keys[y][0]] + "\x00" + j.fields[keys[y][1]]
		return fx < fy
	})
	for _, k := range keys {
		pa := j.pairs[k]
		if pa.over || len(pa.combos) == 0 {
			continue
		}
		fa, fb := j.fields[k[0]], j.fields[k[1]]
		pA, pB := s.Prop(fa), s.Prop(fb)
		if pA == nil || pB == nil || a.props[fa] == nil || a.props[fb] == nil {
			continue
		}
		va, okA := f.allowedValues(a.props[fa], pA.Schema)
		vb, okB := f.allowedValues(a.props[fb], pB.Schema)
		if !okA || !okB {
			continue
		}
		d := &Dependency{Fields: []string{fa, fb}}
		seenA, seenB := map[string]bool{}, map[string]bool{}
		for _, co := range pa.combos {
			if len(co.subj) < f.cfg.KMin || !va[co.a] || !vb[co.b] {
				d.Partial = true
				continue
			}
			seenA[co.a], seenB[co.b] = true, true
			d.Combos = append(d.Combos, Combo{Values: []DepValue{depValue(co.a), depValue(co.b)}, Count: co.n, Subjects: len(co.subj), AtLeast: AtLeast(co.n, f.cfg.KMin)})
		}
		if len(d.Combos) == 0 {
			continue
		}
		// Informative only when some published pair of values was not seen
		// together for k subjects.
		if len(d.Combos) >= len(va)*len(vb) {
			continue
		}
		sort.Slice(d.Combos, func(x, y int) bool {
			cx, cy := d.Combos[x].Values, d.Combos[y].Values
			if cx[0].Value != cy[0].Value {
				return cx[0].Value < cy[0].Value
			}
			return cx[1].Value < cy[1].Value
		})
		s.Deps = append(s.Deps, d)
	}
}

// AtLeast is the published size class of a combination seen n times: the
// power of ten at or below n, never below k (exact counts are not
// published; the class is a lower bound).
func AtLeast(n int64, k int) int64 {
	if n <= 0 {
		return 0
	}
	p := int64(math.Pow(10, math.Floor(math.Log10(float64(n)))))
	if p > n { // float rounding
		p /= 10
	}
	if p < int64(k) {
		return int64(k)
	}
	return p
}

// depJSON renders one value of a combination: the keep value, or the band
// as {"min", "max"} (an open end omitted).
func depJSON(v DepValue) any {
	switch v.Type {
	case "string":
		return v.Value
	case "band":
		kind, lo, hi, ok := parseBand(v.Value)
		if !ok {
			return nil
		}
		m := map[string]any{}
		canon := func(l string) any {
			if c, ok := event.CanonicalNumber(l); ok {
				return num(c)
			}
			return num(l)
		}
		switch kind {
		case "<":
			m["max"] = canon(lo)
		case ">=":
			m["min"] = canon(lo)
		default:
			m["min"], m["max"] = canon(lo), canon(hi)
		}
		return m
	}
	if c, ok := event.CanonicalNumber(v.Value); ok {
		return num(c)
	}
	return num(v.Value)
}

// renderDeps renders Schema.Deps as the x-tt-dependencies extension.
func renderDeps(s *Schema) []any {
	var out []any
	for _, d := range s.Deps {
		fields := make([]any, len(d.Fields))
		for i, f := range d.Fields {
			fields[i] = f
		}
		var combos []any
		for _, c := range d.Combos {
			vals := make([]any, len(c.Values))
			bad := false
			for i, v := range c.Values {
				if vals[i] = depJSON(v); vals[i] == nil {
					bad = true
				}
			}
			if bad {
				continue
			}
			combos = append(combos, map[string]any{"values": vals, "at_least": c.AtLeast})
		}
		if len(combos) == 0 {
			continue
		}
		m := map[string]any{"fields": fields, "combinations": combos}
		if d.Partial {
			m["partial"] = true
		}
		out = append(out, m)
	}
	return out
}

// ComboKey is the key of a published combination for the gate (pack
// k-thresholds): the fields and the rendered values, in order.
func ComboKey(fields []string, values []string) string {
	return strings.Join(fields, "\x1f") + "\x1e" + strings.Join(values, "\x1f")
}

// DepValueLexeme is the lexeme of a combination value as the gate sees it
// in the rendered contract: the string, the canonical number, or the band
// as "min..max" (an open end empty).
func DepValueLexeme(v DepValue) string {
	switch v.Type {
	case "string":
		return v.Value
	case "band":
		kind, lo, hi, _ := parseBand(v.Value)
		c := func(l string) string {
			if x, ok := event.CanonicalNumber(l); ok {
				return x
			}
			return l
		}
		switch kind {
		case "<":
			return ".." + c(lo)
		case ">=":
			return c(lo) + ".."
		}
		return c(lo) + ".." + c(hi)
	}
	if x, ok := event.CanonicalNumber(v.Value); ok {
		return x
	}
	return v.Value
}

// Combos lists the published combinations of a contract with their
// distinct subjects (capped at KMin), keyed by ComboKey, for the gate.
func (c *Contract) Combos() map[string]int64 {
	out := map[string]int64{}
	var walk func(s *Schema)
	walk = func(s *Schema) {
		if s == nil {
			return
		}
		for _, d := range s.Deps {
			for _, co := range d.Combos {
				vals := make([]string, len(co.Values))
				for i, v := range co.Values {
					vals[i] = DepValueLexeme(v)
				}
				key := ComboKey(d.Fields, vals)
				if n := int64(co.Subjects); n > out[key] {
					out[key] = n
				}
			}
		}
		for _, p := range s.Props {
			walk(p.Schema)
		}
		walk(s.Additional)
		walk(s.Items)
	}
	for _, op := range c.Ops {
		for _, m := range op.Body {
			walk(m.Schema)
		}
		for _, r := range op.Responses {
			for _, m := range r.Body {
				walk(m.Schema)
			}
		}
	}
	return out
}
