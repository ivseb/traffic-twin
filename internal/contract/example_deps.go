package contract

import (
	"sort"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/fielddeps"
)

// exampleDeps makes an example object hold an observed combination of its
// dependent fields (x-tt-dependencies): forced values stay, the others take
// the most frequent combination compatible with them.
func exampleDeps(s *Schema, m map[string]any, force map[string]string) {
	if len(s.Deps) == 0 {
		return
	}
	fielddeps.Enforce(FieldDeps(s.Deps), m, fielddeps.Options{
		Fixed:    func(f string) bool { _, ok := force[f]; return ok },
		Required: func(f string) bool { p := s.Prop(f); return p != nil && p.Required },
		Make: func(f string, v fielddeps.Value) any {
			if !v.Band {
				return v.Lit
			}
			integer := false
			if p := s.Prop(f); p != nil && p.Schema != nil && p.Schema.primary() == "integer" {
				integer = true
			}
			x := fielddeps.BandNumber(v, integer, 0)
			if integer {
				return num(strconv.FormatFloat(x, 'f', 0, 64))
			}
			return num(strconv.FormatFloat(x, 'f', -1, 64))
		},
	})
}

// FieldDeps converts model dependencies to the shared solver's form, the
// most frequent combinations first.
func FieldDeps(ds []*Dependency) []fielddeps.Dep {
	out := make([]fielddeps.Dep, 0, len(ds))
	for _, d := range ds {
		cs := append([]Combo(nil), d.Combos...)
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].Count > cs[j].Count })
		fd := fielddeps.Dep{Fields: d.Fields, Partial: d.Partial}
		for _, c := range cs {
			vals := make([]fielddeps.Value, len(c.Values))
			for i, v := range c.Values {
				vals[i] = solverValue(v)
			}
			fd.Combos = append(fd.Combos, vals)
			fd.Weights = append(fd.Weights, float64(c.AtLeast))
		}
		out = append(out, fd)
	}
	return out
}

func solverValue(v DepValue) fielddeps.Value {
	switch v.Type {
	case "string":
		return fielddeps.Value{Lit: v.Value}
	case "band":
		kind, lo, hi, _ := parseBand(v.Value)
		f := func(l string) *float64 {
			x, err := strconv.ParseFloat(l, 64)
			if err != nil {
				return nil
			}
			return &x
		}
		switch kind {
		case "<":
			return fielddeps.Value{Band: true, Max: f(lo)}
		case ">=":
			return fielddeps.Value{Band: true, Min: f(lo)}
		}
		return fielddeps.Value{Band: true, Min: f(lo), Max: f(hi)}
	}
	return fielddeps.Value{Lit: num(v.Value)}
}
