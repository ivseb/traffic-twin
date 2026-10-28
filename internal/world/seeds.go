package world

import (
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/pack"
)

// Seeds (rules v1.6, docs/spec/rules.md 2.8): the objects every customer
// has before the window (contracts, consents, addresses read by their
// owner, never created by a write in the traffic). Before the simulation
// each synthetic customer gets, for each entity with a seed, a number of
// objects drawn from the seed's buckets (uniformly within the bucket; an
// open bucket "11+" up to twice its floor); each object is built from the
// schema of the entity's reads, takes the seed's clear values with their
// shares, refers only to entities the customer already has (relations are
// never invented) and gets an id of the entity (prefix, or the id format of
// its domain). The seeds use their own random stream: a world whose rules
// have no seed is the same, byte for byte, as before.

// maxSeedObjects bounds the objects of one entity per customer.
const maxSeedObjects = 50

// seedOrder lists the entities with a seed, the targets of their relations
// first (an address before the contracts that cite it).
func (g *generator) seedOrder() []*pack.Entity {
	var all []*pack.Entity
	for i := range g.in.Rules.Entities {
		if e := &g.in.Rules.Entities[i]; e.Seed != nil && e.Key == nil {
			all = append(all, e)
		}
	}
	done := map[string]bool{}
	var out []*pack.Entity
	var visit func(e *pack.Entity, depth int)
	visit = func(e *pack.Entity, depth int) {
		if done[e.Name] || depth > 32 {
			return
		}
		done[e.Name] = true
		for _, r := range e.Relations {
			for _, x := range all {
				if x.Name == r.Entity {
					visit(x, depth+1)
				}
			}
		}
		out = append(out, e)
	}
	for _, e := range all {
		visit(e, 0)
	}
	return out
}

// seed creates the pre-existing objects of every customer (see above).
func (g *generator) seed(custs []*customer) {
	ents := g.seedOrder()
	if len(ents) == 0 {
		return
	}
	main := g.r
	g.r = newRNG(g.in.Seed, 5)
	defer func() { g.r = main }()
	for _, c := range custs {
		for _, e := range ents {
			n := g.seedCount(e.Seed)
			for k := 0; k < n; k++ {
				g.seedObject(c, e)
			}
		}
	}
}

func (g *generator) seedCount(s *pack.Seed) int {
	w := make([]float64, len(s.PerCustomer))
	for i, b := range s.PerCustomer {
		w[i] = b.Share
	}
	b := s.PerCustomer[g.r.weighted(w)]
	lo, hi, ok := b.Range()
	if !ok {
		return 0
	}
	if hi < 0 {
		hi = 2 * lo
	}
	n := int(g.r.between(int64(lo), int64(hi)))
	return min(n, maxSeedObjects)
}

// seedSchema is the object schema of an entity's reads: the first single
// read, else the items of the first list.
func (g *generator) seedSchema(e *pack.Entity) (*openapi, map[string]any) {
	for pass := 0; pass < 2; pass++ {
		for _, rb := range e.ReadBy {
			list := len(rb.At.Path) >= 3 && rb.At.Path[len(rb.At.Path)-3:] == "[*]"
			if (pass == 0) == list {
				continue
			}
			svc := e.Service
			if rb.Service != "" {
				svc = rb.Service
			}
			o := g.docs[svc]
			if o == nil {
				continue
			}
			if s := o.schemaAt(o.responseSchema(rb.Op), rb.At.Path); s != nil {
				return o, s
			}
		}
	}
	return nil, nil
}

func (g *generator) seedObject(c *customer, e *pack.Entity) {
	at := g.start
	state := map[string]any{}
	if o, sch := g.seedSchema(e); o != nil {
		// relative dates (pack.md 4.4) count from t0: the object exists
		// when the window ends and the mock starts
		sy := &synth{g: g, cust: c, now: at, relNow: g.t0}
		if v, ok := sy.value(o, sch, "", 0); ok {
			if m, ok := v.(map[string]any); ok {
				state = m
			}
		}
		g.fixRefs(o, sch, state, e, c)
	}
	for _, f := range sortedKeys(e.Seed.Values) {
		vals := e.Seed.Values[f]
		names := sortedKeys(vals)
		w := make([]float64, len(names))
		for i, v := range names {
			w[i] = vals[v]
		}
		setPath(state, f, names[g.r.weighted(w)])
	}
	delete(state, e.IDField)
	id := g.newID(e, idfmt.MapRef(state))
	state[e.IDField] = id
	owner := c.id
	in := &inst{entity: e.Name, id: id, owner: &owner, state: state}
	g.derive(in, at, true)
	g.insts[key(e.Name, id)] = in
	g.owned[key(e.Name, owner)] = append(g.owned[key(e.Name, owner)], id)
	g.record(in, at, "", "", "")
}

// remove applies a remove effect (rules v1.6): the entity leaves the world.
// Its history stays (what it went through before); its row and its place
// among the customer's objects go.
func (g *generator) remove(ent *pack.Entity, id string) {
	in := g.insts[key(ent.Name, id)]
	if in == nil {
		return
	}
	delete(g.insts, key(ent.Name, id))
	if in.owner != nil {
		k := key(ent.Name, *in.owner)
		ids := g.owned[k]
		for i, x := range ids {
			if x == id {
				g.owned[k] = append(ids[:i:i], ids[i+1:]...)
				break
			}
		}
	}
}
