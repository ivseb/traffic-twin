package world

import (
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// entCond is a conditional property of an entity (x-tt-when in the contract):
// it exists only while the entity's sibling property disc holds one of in.
type entCond struct {
	name string
	disc string
	in   []string
	sch  map[string]any
	doc  *openapi
}

// entityConds lists the conditional top-level properties of an entity, from
// the schemas of its creation response and single reads.
func (g *generator) entityConds(e *pack.Entity) []entCond {
	var out []entCond
	seen := map[string]bool{}
	add := func(svc, op, at string) {
		o := g.docs[svc]
		if o == nil {
			return
		}
		s := o.schemaAt(o.responseSchema(op), at)
		props, _ := o.resolve(s)["properties"].(map[string]any)
		for _, name := range sortedKeys(props) {
			ps, _ := props[name].(map[string]any)
			when, _ := o.resolve(ps)["x-tt-when"].(map[string]any)
			if seen[name] || len(when) != 1 {
				continue
			}
			for disc, raw := range when {
				vals, _ := raw.([]any)
				c := entCond{name: name, disc: disc, sch: ps, doc: o}
				for _, v := range vals {
					if sv, ok := v.(string); ok {
						c.in = append(c.in, sv)
					}
				}
				if len(c.in) > 0 {
					seen[name] = true
					out = append(out, c)
				}
			}
		}
	}
	if e.CreatedBy != nil {
		add(e.Service, e.CreatedBy.Op, "$")
	}
	for _, rb := range e.ReadBy {
		svc := e.Service
		if rb.Service != "" {
			svc = rb.Service
		}
		add(svc, rb.Op, rb.At.Path)
	}
	return out
}

// applyConds keeps the conditional properties of an entity coherent with its
// state: a CANCELLED shipment carries cancelReason (a synthetic value from
// the contract), a shipment in any other state does not.
func (g *generator) applyConds(in *inst, at time.Time) {
	conds := g.entConds[in.entity]
	if len(conds) == 0 {
		return
	}
	sy := &synth{g: g, now: at}
	for _, c := range conds {
		dv, _ := in.state[c.disc].(string)
		want := false
		for _, v := range c.in {
			if v == dv {
				want = true
			}
		}
		_, has := in.state[c.name]
		switch {
		case want && !has:
			if v, ok := sy.value(c.doc, c.sch, c.name, 1); ok {
				in.state[c.name] = v
			}
		case !want && has:
			delete(in.state, c.name)
		}
	}
}
