package world

import (
	"sort"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Rules v1.9 in the generator (docs/spec/rules.md 6.1).
//
//   - Customer attributes: every synthetic customer gets a value of each
//     attribute, drawn from its shares on a stream of its own (a world
//     without attributes stays byte-identical), written in its profile.
//   - Conditions: the generator has no request, so only the customer
//     conditions are evaluated; a request condition counts as holding.
//     The outcome is drawn over the joint p of the outcomes whose customer
//     conditions hold: across the requests, the marginal distribution of
//     the outcomes is kept.
//   - target_all: applied to every entity of the type owned by the
//     customer of the cause that matches where; an effect due after t0
//     becomes one pending line per entity the customer owns at the cause.
//   - Preconditions, aggregates and list operations change answers, not
//     the world: ignored.

// attrStream is the RNG stream of the customer attributes.
const attrStream = 6

// assignAttributes draws the attributes of every customer.
func (g *generator) assignAttributes(custs []*customer) {
	attrs := g.in.Rules.Attributes
	if len(attrs) == 0 {
		return
	}
	r := newRNG(g.in.Seed, attrStream)
	names := make([]int, len(attrs))
	for i := range names {
		names[i] = i
	}
	sort.Slice(names, func(i, j int) bool { return attrs[names[i]].Name < attrs[names[j]].Name })
	for _, c := range custs {
		c.attrs = map[string]string{}
		for _, i := range names {
			a := attrs[i]
			vals := sortedKeys(a.Values)
			w := make([]float64, len(vals))
			for k, v := range vals {
				w[k] = a.Values[v]
			}
			if len(vals) == 0 {
				continue
			}
			c.attrs[a.Name] = vals[r.weighted(w)]
		}
		g.custAttrs[c.id] = c.attrs
	}
}

// customerHolds reports whether the customer conditions of ms hold for the
// owner (request conditions are not evaluated: no request in the world).
func (g *generator) customerHolds(ms []pack.Match, owner *string) bool {
	for _, m := range ms {
		if m.Customer == "" {
			continue
		}
		var v string
		ok := false
		if owner != nil {
			v, ok = g.custAttrs[*owner][m.Customer]
		}
		if !pack.MatchValue(m, v, ok) {
			return false
		}
	}
	return true
}

// outcomeWeights are the weights of the outcome draw: p, zero for the
// outcomes whose customer conditions do not hold.
func (g *generator) outcomeWeights(r *pack.CausalRule, owner *string) ([]float64, bool) {
	ps := make([]float64, len(r.Outcomes))
	some := false
	for i, o := range r.Outcomes {
		if o.When != nil && !g.customerHolds(o.When, owner) {
			continue
		}
		ps[i] = o.P
		some = some || o.P > 0
	}
	return ps, some
}

// applyAll applies a target_all effect: every entity of the type owned by
// the customer of the cause (only id when given: a pending line) that
// matches where.
func (g *generator) applyAll(f *firing, e *pack.Effect, t time.Time, only string) {
	if f.owner == nil {
		return
	}
	ent := g.in.Rules.Entity(e.Entity)
	ids := append([]string(nil), g.owned[key(ent.Name, *f.owner)]...)
	for _, id := range ids {
		if only != "" && id != only {
			continue
		}
		in := g.insts[key(ent.Name, id)]
		if in == nil {
			continue
		}
		match := true
		for _, k := range sortedKeys(e.Where) {
			if !jsonEqual(getPath(in.state, "$."+k), e.Where[k]) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if e.Remove {
			g.remove(ent, id)
			continue
		}
		changed := false
		vals := g.setValues(f, e, in, t)
		for _, k := range sortedKeys(vals) {
			v := vals[k]
			if !jsonEqual(getPath(in.state, "$."+k), v) {
				setPath(in.state, k, v)
				changed = true
			}
		}
		if changed {
			g.derive(in, t, false)
			g.record(in, t, f.rule.ID, f.outcome, e.ID)
		}
	}
}
