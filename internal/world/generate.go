package world

import (
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/derive"
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/pack"
)

// Limits of one generation.
const (
	MaxCustomers  = 100000
	DefaultWindow = 14 * 24 * time.Hour
	maxWindow     = 366 * 24 * time.Hour
	maxEntities   = 2_000_000
	customerPfx   = "CUS-SYN-"
)

// Params are the knobs of a generation. Together with the inputs they
// determine the world byte for byte.
type Params struct {
	Seed      uint64
	Customers int
	// T0 is the instant of the world (truncated to the second, UTC).
	T0 time.Time
	// Window is how far before T0 the simulation starts (default 14 days).
	Window time.Duration
	// Locale of the invented names: "it" (default) or "en".
	Locale string
}

// Input is everything the generator reads.
type Input struct {
	Params
	Rules     *Rules
	Contracts []Contract
	// Archetypes, optional: customers are drawn from them (by size) and
	// follow their activity features. Without, customers have archetype null.
	Archetypes []Archetype
	// Report tells the approved rules of the scope left out (InputsIn);
	// optional, not an input of the generator.
	Report *ScopeReport
}

// Output is a generated world.
type Output struct {
	// World is world.jsonl (canonical JSON lines).
	World []byte
	// Synthetic lists every string the generator invented (sorted, unique):
	// the provenance tags of world.jsonl for the gate.
	Synthetic []string
	// Customers are the customer ids with their archetype ("" for none).
	Customers []CustomerInfo
	Entities  int
	History   int
	Pending   int
}

// CustomerInfo is one generated customer.
type CustomerInfo struct {
	ID        string `json:"id"`
	Archetype string `json:"archetype,omitempty"`
}

type customer struct {
	id   string
	arch *Archetype
	p    person
	name string
	// attrs are the customer attributes (rules v1.9), drawn after the
	// customers so that a world without them stays the same.
	attrs map[string]string
}

type inst struct {
	entity, id string
	owner      *string
	state      map[string]any
	seq        int
}

type histRow struct {
	entity, id            string
	at                    time.Time
	seq                   int
	rule, outcome, effect string
	state                 map[string]any
}

type pendRow struct {
	due                        time.Time
	order                      int64
	rule, outcome, effect, ent string
	id                         string
	owner                      *string
	vars                       map[string]any
	effectIDs                  map[string]string
	create                     bool
}

type firing struct {
	rule    *pack.CausalRule
	outcome string
	owner   *string
	vars    map[string]any
	ids     map[string]string // effect id -> entity id (static)
	byID    map[string]*pack.Effect
}

type item struct {
	at    time.Time
	class int // 0 effect, 1 batch, 2 customer call
	order int64
	run   func(t time.Time)
}

type queue []*item

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}
	if q[i].class != q[j].class {
		return q[i].class < q[j].class
	}
	return q[i].order < q[j].order
}
func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(x any)   { *q = append(*q, x.(*item)) }
func (q *queue) Pop() any {
	old := *q
	it := old[len(old)-1]
	*q = old[:len(old)-1]
	return it
}

type generator struct {
	in        *Input
	r         *rng
	t0, start time.Time
	docs      map[string]*openapi
	external  map[string]bool
	tags      map[string]struct{}
	// deriveSeq numbers the template values of derived fields per scope.
	deriveSeq map[string]uint64
	counters  map[string]int
	idCount   map[string]int      // opaque id counters per domain
	insts     map[string]*inst    // entity \x00 id
	owned     map[string][]string // entity \x00 owner -> ids in creation order
	hist      []histRow
	pend      []pendRow
	q         queue
	order     int64
	entProps  map[string]map[string]bool
	entConds  map[string][]entCond
	// domainEnt maps an HMAC domain to an entity: the entity of the same
	// service first (two teams can each have an entity of domain order,
	// docs/spec/rules.md 2.7), else the first entity of the domain.
	domainEnt map[string]string
	created   int
	fmtFull   string
	// fmts are the id formats by id domain (x-tt-value.id_format of the
	// contracts, docs/spec/pack.md 4.3).
	fmts map[string]*idfmt.Template
	// custAttrs are the attributes of each customer (rules v1.9).
	custAttrs map[string]map[string]string
}

func (g *generator) tag(s string) string {
	g.tags[s] = struct{}{}
	return s
}

func (g *generator) nextOrder() int64 { g.order++; return g.order }

// newID is the next id of an entity: prefix and counter, or the id format
// of its domain (ref gives the fields the format copies).
func (g *generator) newID(ent *pack.Entity, ref idfmt.Ref) string {
	g.counters[ent.Name]++
	if t := g.fmts[ent.IDDomain]; t != nil {
		if float64(g.counters[ent.Name]) > t.Capacity() {
			g.fmtFull = ent.IDDomain
		}
		return g.tag(t.ID(uint64(g.counters[ent.Name]), ent.IDDomain, ref))
	}
	return g.tag(fmt.Sprintf("%s%04d", ent.IDPrefix, g.counters[ent.Name]))
}

// opaqueID is an id of a domain no entity owns.
func (g *generator) opaqueID(domain string) string {
	g.idCount[domain]++
	if t := g.fmts[domain]; t != nil {
		return t.ID(uint64(g.idCount[domain]), domain, nil)
	}
	p := strings.ToUpper(domain)
	var b strings.Builder
	for _, c := range p {
		if c >= 'A' && c <= 'Z' && b.Len() < 5 {
			b.WriteRune(c)
		}
	}
	for b.Len() < 2 {
		b.WriteByte('X')
	}
	return fmt.Sprintf("%s-SYN-%04d", b.String(), g.idCount[domain])
}

func key(ent, id string) string { return ent + "\x00" + id }

// Generate builds a world. It is deterministic: the same input gives the
// same bytes.
func Generate(in *Input) (*Output, error) {
	if in.Rules == nil {
		return nil, errors.New("world: no rules")
	}
	if in.Customers < 0 || in.Customers > MaxCustomers {
		return nil, errors.New("world: customers out of range")
	}
	if in.T0.IsZero() {
		return nil, errors.New("world: t0 is required")
	}
	win := in.Window
	if win <= 0 {
		win = DefaultWindow
	}
	if win > maxWindow {
		return nil, errors.New("world: window too long")
	}
	g := &generator{
		in: in, r: newRNG(in.Seed, 1), t0: in.T0.UTC().Truncate(time.Second),
		docs: map[string]*openapi{}, external: map[string]bool{}, tags: map[string]struct{}{},
		counters: map[string]int{}, idCount: map[string]int{}, insts: map[string]*inst{}, owned: map[string][]string{},
		entProps: map[string]map[string]bool{}, entConds: map[string][]entCond{}, domainEnt: map[string]string{}, fmts: map[string]*idfmt.Template{},
		custAttrs: map[string]map[string]string{},
	}
	g.start = g.t0.Add(-win)
	for _, c := range in.Contracts {
		var doc map[string]any
		if err := decodeUseNumber(c.Doc, &doc); err != nil {
			return nil, fmt.Errorf("world: contract %s: %w", c.Service, err)
		}
		g.docs[c.Service] = &openapi{doc: doc}
		g.external[c.Service] = c.External
		for d, f := range idfmt.Collect(doc) {
			if t, err := idfmt.Parse(f); err == nil && g.fmts[d] == nil {
				g.fmts[d] = t
			}
		}
	}
	for i := range in.Rules.Entities {
		e := &in.Rules.Entities[i]
		if _, ok := g.domainEnt[e.IDDomain]; !ok {
			g.domainEnt[e.IDDomain] = e.Name
		}
		g.domainEnt[e.Service+"\x00"+e.IDDomain] = e.Name
		g.entProps[e.Name] = g.entitySchemaProps(e)
		g.entConds[e.Name] = g.entityConds(e)
	}
	custs := g.customers()
	g.assignAttributes(custs)
	g.seed(custs)
	g.scheduleCalls(custs)
	g.scheduleBatches()
	for g.q.Len() > 0 {
		it := heap.Pop(&g.q).(*item)
		if !it.at.Before(g.t0) {
			break
		}
		it.run(it.at)
		if len(g.insts) > maxEntities {
			return nil, errors.New("world: too many entities")
		}
	}
	if g.fmtFull != "" {
		return nil, fmt.Errorf("world: the id format of domain %s gives fewer ids than the world needs: add random characters", g.fmtFull)
	}
	return g.output(custs)
}

// entitySchemaProps returns the properties the contract declares for an
// entity (creation response and single reads), for derived fields.
func (g *generator) entitySchemaProps(e *pack.Entity) map[string]bool {
	out := map[string]bool{}
	add := func(svc, op, at string) {
		o := g.docs[svc]
		if o == nil {
			return
		}
		s := o.schemaAt(o.responseSchema(op), at)
		for k := range o.props(s) {
			out[k] = true
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

func (g *generator) customers() []*customer {
	ppl := newPeople(g.in.Locale, newRNG(g.in.Seed, 2))
	ar := newRNG(g.in.Seed, 3)
	var w []float64
	for _, a := range g.in.Archetypes {
		w = append(w, float64(a.Size))
	}
	out := make([]*customer, 0, g.in.Customers)
	for i := 1; i <= g.in.Customers; i++ {
		c := &customer{id: g.tag(fmt.Sprintf("%s%04d", customerPfx, i)), p: ppl.next()}
		c.name = g.tag(c.p.name())
		g.tag(c.p.email)
		g.tag(c.p.phone)
		g.tag(c.p.first)
		g.tag(c.p.last)
		if len(g.in.Archetypes) > 0 {
			c.arch = &g.in.Archetypes[ar.weighted(w)]
		}
		out = append(out, c)
	}
	return out
}

// customerOps are the creation operations customers call: created_by of
// entities of services that are not external, restricted to the endpoint
// mix of the archetype when it has one.
func (g *generator) customerOps(c *customer) ([]*pack.Entity, []float64) {
	var ents []*pack.Entity
	var w []float64
	for i := range g.in.Rules.Entities {
		e := &g.in.Rules.Entities[i]
		if e.CreatedBy == nil || g.external[e.Service] {
			continue
		}
		weight := 1.0
		if c.arch != nil && len(c.arch.Features.EndpointMix) > 0 {
			weight = c.arch.Features.EndpointMix[e.Service+" "+e.CreatedBy.Op]
			if weight <= 0 {
				continue
			}
		}
		ents = append(ents, e)
		w = append(w, weight)
	}
	return ents, w
}

func bucketRange(b string) (int64, int64) {
	switch b {
	case "0":
		return 0, 0
	case "1-2":
		return 1, 2
	case "3-5":
		return 3, 5
	case "6-10":
		return 6, 10
	case "11+":
		return 11, 15
	}
	return 1, 4
}

func hoursRange(b string) (int, int) {
	if a, z, ok := strings.Cut(b, "-"); ok {
		lo, e1 := strconv.Atoi(a)
		hi, e2 := strconv.Atoi(z)
		if e1 == nil && e2 == nil && lo >= 0 && hi <= 24 && lo < hi {
			return lo, hi
		}
	}
	return 0, 24
}

func (g *generator) scheduleCalls(custs []*customer) {
	cr := newRNG(g.in.Seed, 4)
	win := g.t0.Sub(g.start)
	days := int64(win / (24 * time.Hour))
	if days < 1 {
		days = 1
	}
	for _, c := range custs {
		ents, w := g.customerOps(c)
		if len(ents) == 0 {
			continue
		}
		lo, hi := int64(1), int64(4)
		hlo, hhi := 0, 24
		if c.arch != nil {
			lo, hi = bucketRange(c.arch.Features.OrdersPerMonth)
			hlo, hhi = hoursRange(c.arch.Features.ActiveHours)
		}
		n := cr.between(lo, hi)
		if c.arch != nil {
			n = int64(math.Round(float64(n) * float64(win) / float64(30*24*time.Hour)))
			if n == 0 && hi > 0 {
				n = 1
			}
		}
		for k := int64(0); k < n; k++ {
			day := g.start.Truncate(24 * time.Hour).Add(time.Duration(cr.intn(days+1)) * 24 * time.Hour)
			secs := int64(hlo)*3600 + cr.intn(int64(hhi-hlo)*3600)
			at := day.Add(time.Duration(secs) * time.Second)
			if at.Before(g.start) || !at.Before(g.t0) {
				at = g.start.Add(time.Duration(cr.intn(int64(win/time.Second))) * time.Second)
			}
			ent := ents[cr.weighted(w)]
			cc := c
			heap.Push(&g.q, &item{at: at, class: 2, order: g.nextOrder(), run: func(t time.Time) { g.call(cc, ent, t) }})
		}
	}
}

func (g *generator) scheduleBatches() {
	for i := range g.in.Rules.Batch {
		b := &g.in.Rules.Batch[i]
		c, _ := parseCron(b.Schedule)
		for _, t := range c.ticks(g.start, g.t0) {
			heap.Push(&g.q, &item{at: t, class: 1, order: g.nextOrder(), run: func(t time.Time) { g.batch(b, t) }})
		}
	}
}

func (g *generator) record(in *inst, at time.Time, rule, outcome, effect string) {
	in.seq++
	g.hist = append(g.hist, histRow{entity: in.entity, id: in.id, at: at, seq: in.seq, rule: rule, outcome: outcome, effect: effect, state: deepCopy(in.state).(map[string]any)})
}

func (g *generator) derive(in *inst, at time.Time, creating bool) {
	props := g.entProps[in.entity]
	ts := g.tag(fmtTime(at))
	for _, n := range []string{"createdAt", "created_at"} {
		if creating && props[n] {
			if _, ok := in.state[n]; !ok {
				in.state[n] = ts
			}
		}
	}
	for _, n := range []string{"customerId", "customer_id"} {
		if creating && props[n] && in.owner != nil {
			if _, ok := in.state[n]; !ok {
				in.state[n] = *in.owner
			}
		}
	}
	for _, n := range []string{"updatedAt", "updated_at"} {
		if props[n] {
			in.state[n] = ts
		}
	}
	g.applyConds(in, at)
}

// call simulates a customer calling the creation operation of ent.
func (g *generator) call(c *customer, ent *pack.Entity, t time.Time) {
	o := g.docs[ent.Service]
	sy := &synth{g: g, cust: c, now: t}
	var req map[string]any
	if o != nil {
		if v, ok := sy.value(o, o.requestSchema(ent.CreatedBy.Op), "", 0); ok {
			req, _ = v.(map[string]any)
		}
	}
	if req == nil {
		req = map[string]any{}
	}
	g.fixRefs(o, o.requestSchemaOrNil(ent.CreatedBy.Op), req, ent, c)
	state := map[string]any{}
	if st := ent.CreatedBy.State; st != nil && st.From == "req.body" {
		if v, ok := getPath(req, st.Path).(map[string]any); ok {
			state = deepCopy(v).(map[string]any)
		}
	}
	for _, k := range sortedKeys(ent.CreatedBy.Defaults) {
		v := ent.CreatedBy.Defaults[k]
		if s, ok := v.(string); ok && strings.HasPrefix(s, "${") {
			continue
		}
		setPath(state, k, deepCopy(v))
	}
	id := g.newID(ent, idfmt.MapRef(state))
	state[ent.IDField] = id
	owner := c.id
	in := &inst{entity: ent.Name, id: id, owner: &owner, state: state}
	g.derive(in, t, true)
	g.insts[key(ent.Name, id)] = in
	g.owned[key(ent.Name, owner)] = append(g.owned[key(ent.Name, owner)], id)
	g.record(in, t, "", "", "")
	status := 0
	if o != nil {
		status, _ = o.successStatus(ent.CreatedBy.Op)
	}
	for i := range g.in.Rules.Causal {
		r := &g.in.Rules.Causal[i]
		if r.Cause.Service != ent.Service || r.Cause.Op != ent.CreatedBy.Op {
			continue
		}
		if status != 0 && !containsInt(r.Cause.When.Status, status) {
			continue
		}
		if r.Cause.When.Match != nil && !g.customerHolds(r.Cause.When.Match, &owner) {
			continue // rules v1.9: a customer condition of the cause fails
		}
		vars := map[string]any{}
		for _, name := range sortedKeys(r.Cause.Bind) {
			ref := r.Cause.Bind[name]
			var v any
			switch ref.From {
			case "resp.body":
				v = getPath(in.state, ref.Path)
			case "req.body":
				v = getPath(req, ref.Path)
			}
			if v != nil {
				vars[name] = v
			}
		}
		g.fire(r, &owner, vars, t)
	}
}

// fixRefs makes id fields of a synthetic request refer to existing world
// entities (relations are never invented, docs/spec/rules.md 2.2): a field
// whose x-tt-value domain belongs to an entity takes the id of an entity of
// that type owned by the customer, or is removed.
func (g *generator) fixRefs(o *openapi, sch map[string]any, req map[string]any, ent *pack.Entity, c *customer) {
	if o == nil || sch == nil {
		return
	}
	props, _ := sch["properties"].(map[string]any)
	rel := map[string]string{}
	for _, r := range ent.Relations {
		rel[r.Field] = r.Entity
	}
	for _, name := range sortedKeys(req) {
		ps := o.resolve(mapOf(props[name]))
		target := rel[name]
		if xv := mapOf(ps["x-tt-value"]); target == "" && xv["kind"] == "id" {
			d, _ := xv["domain"].(string)
			if target = g.domainEnt[ent.Service+"\x00"+d]; target == "" {
				target = g.domainEnt[d]
			}
		}
		if target == "" {
			continue
		}
		cands := g.owned[key(target, c.id)]
		if len(cands) == 0 {
			delete(req, name)
			continue
		}
		req[name] = cands[g.r.intn(int64(len(cands)))]
	}
}

func (o *openapi) requestSchemaOrNil(op string) map[string]any {
	if o == nil {
		return nil
	}
	return o.requestSchema(op)
}

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

func containsInt(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// fire runs a causal rule at t: outcome draw, interval delays, then the
// effects of the branch (immediate now, later ones queued, after t0 pending).
func (g *generator) fire(r *pack.CausalRule, owner *string, vars map[string]any, t time.Time) {
	ps := make([]float64, len(r.Outcomes))
	conditional := false
	for i, o := range r.Outcomes {
		ps[i] = o.P
		conditional = conditional || o.When != nil
	}
	if conditional {
		// rules v1.9: only the outcomes whose customer conditions hold.
		var ok bool
		if ps, ok = g.outcomeWeights(r, owner); !ok {
			return
		}
	}
	oc := r.Outcomes[g.r.weighted(ps)]
	f := &firing{rule: r, outcome: oc.Name, owner: owner, vars: vars, ids: map[string]string{}, byID: map[string]*pack.Effect{}}
	inBranch := map[string]bool{}
	for _, id := range oc.Effects {
		inBranch[id] = true
	}
	delay := map[string]time.Duration{}
	var branch []*pack.Effect
	for i := range r.Effects {
		e := &r.Effects[i]
		f.byID[e.ID] = e
		if !inBranch[e.ID] {
			continue
		}
		branch = append(branch, e)
		d := e.After.Min
		if e.After.Range {
			d = time.Duration(g.r.between(int64(e.After.Min/time.Second), int64(e.After.Max/time.Second))) * time.Second
		}
		delay[e.ID] = d
	}
	at := map[string]time.Time{}
	var timeOf func(e *pack.Effect, depth int) time.Time
	timeOf = func(e *pack.Effect, depth int) time.Time {
		if v, ok := at[e.ID]; ok {
			return v
		}
		base := t
		if p := f.byID[e.AfterEffect]; p != nil && inBranch[p.ID] && depth < 64 {
			base = timeOf(p, depth+1)
		}
		at[e.ID] = base.Add(delay[e.ID])
		return at[e.ID]
	}
	for _, e := range branch {
		timeOf(e, 0)
	}
	branch = topoOrder(branch, f.byID)
	sort.SliceStable(branch, func(i, j int) bool { return at[branch[i].ID].Before(at[branch[j].ID]) })
	// Static ids: creates get their id now (assigned in advance for pending
	// rows), targets follow their effect, target_id its variable.
	for _, e := range branch {
		ent := g.in.Rules.Entity(e.Entity)
		switch {
		case e.Create != nil:
			f.ids[e.ID] = g.newID(ent, g.createRef(f, e))
		case e.Target != "":
			if id, ok := f.ids[e.Target]; ok {
				f.ids[e.ID] = id
			}
		case e.TargetID != "":
			name, _ := refVar(e.TargetID)
			if s, ok := vars[name].(string); ok {
				f.ids[e.ID] = s
			}
		}
	}
	for _, e := range branch {
		e := e
		when := at[e.ID]
		if e.TargetAll {
			// rules v1.9: every entity of the customer that matches where.
			switch {
			case when.Equal(t):
				g.applyAll(f, e, t, "")
			case when.Before(g.t0):
				heap.Push(&g.q, &item{at: when, class: 0, order: g.nextOrder(), run: func(tt time.Time) { g.applyAll(f, e, tt, "") }})
			case owner != nil:
				for _, id := range g.owned[key(e.Entity, *owner)] {
					pr := pendRow{due: when, order: g.nextOrder(), rule: r.ID, outcome: oc.Name, effect: e.ID, ent: e.Entity, id: id, owner: owner}
					for _, k := range sortedKeys(e.Set) {
						s, _ := e.Set[k].(string)
						if name, ok := refVar(s); ok {
							if v, ok := vars[name]; ok {
								if pr.vars == nil {
									pr.vars = map[string]any{}
								}
								pr.vars[name] = v
							}
						}
					}
					g.pend = append(g.pend, pr)
				}
			}
			continue
		}
		switch {
		case when.Equal(t):
			g.apply(f, e, t)
		case when.Before(g.t0):
			heap.Push(&g.q, &item{at: when, class: 0, order: g.nextOrder(), run: func(tt time.Time) { g.apply(f, e, tt) }})
		default:
			if _, ok := f.ids[e.ID]; !ok {
				continue
			}
			pr := pendRow{due: when, order: g.nextOrder(), rule: r.ID, outcome: oc.Name, effect: e.ID, ent: e.Entity,
				id: f.ids[e.ID], owner: owner, create: e.Create != nil}
			vals := e.Create
			if vals == nil {
				vals = e.Set
			}
			for _, k := range sortedKeys(vals) {
				s, _ := vals[k].(string)
				if name, ok := refVar(s); ok {
					if v, ok := vars[name]; ok {
						if pr.vars == nil {
							pr.vars = map[string]any{}
						}
						pr.vars[name] = v
					}
				} else if x, ok := refEffect(s); ok {
					if id, ok := f.ids[x]; ok {
						if pr.effectIDs == nil {
							pr.effectIDs = map[string]string{}
						}
						pr.effectIDs[x] = id
					}
				}
			}
			g.pend = append(g.pend, pr)
		}
	}
}

// topoOrder orders effects so that every effect comes after those it
// depends on (after_effect, target, ${effect:...}), stable on file order.
func topoOrder(effs []*pack.Effect, byID map[string]*pack.Effect) []*pack.Effect {
	in := map[string]bool{}
	for _, e := range effs {
		in[e.ID] = true
	}
	done := map[string]bool{}
	var out []*pack.Effect
	var visit func(e *pack.Effect, depth int)
	visit = func(e *pack.Effect, depth int) {
		if done[e.ID] || depth > 64 {
			return
		}
		done[e.ID] = true
		deps := []string{e.AfterEffect, e.Target}
		for _, m := range []map[string]any{e.Create, e.Set} {
			for _, k := range sortedKeys(m) {
				if s, ok := m[k].(string); ok {
					if x, ok := refEffect(s); ok {
						deps = append(deps, x)
					}
				}
			}
		}
		for _, d := range deps {
			if p := byID[d]; p != nil && in[d] {
				visit(p, depth+1)
			}
		}
		out = append(out, e)
	}
	for _, e := range effs {
		visit(e, 0)
	}
	return out
}

func (g *generator) resolve(f *firing, v any) (any, bool) {
	s, ok := v.(string)
	if !ok {
		return deepCopy(v), true
	}
	if name, ok := refVar(s); ok {
		x, ok := f.vars[name]
		return x, ok
	}
	if x, ok := refEffect(s); ok {
		id, ok := f.ids[x]
		return id, ok
	}
	return s, true
}

// deriveEnv is what the derived values of an effect read (rules 1.10, 3.15),
// as in the mock; template values are numbered in the scope "world/...", so
// the mock (scope "derive/...") does not repeat them.
func (g *generator) deriveEnv(f *firing, e *pack.Effect, t time.Time) derive.Env {
	return derive.Env{
		Var:    func(n string) (any, bool) { v, ok := f.vars[n]; return deepCopy(v), ok },
		Effect: func(id string) (string, bool) { v, ok := f.ids[id]; return v, ok },
		Now:    t,
		Scope:  "world/derive/" + f.rule.ID + "/" + e.ID,
		Seq: func(scope string) uint64 {
			if g.deriveSeq == nil {
				g.deriveSeq = map[string]uint64{}
			}
			g.deriveSeq[scope]++
			return g.deriveSeq[scope]
		},
	}
}

// tagDerived registers the strings a derived value generates (dates,
// templates) as synthetic; a copy keeps the provenance of what it copies.
func (g *generator) tagDerived(src, v any) any {
	if str, ok := v.(string); ok && derive.Is(src) {
		if e, err := derive.Parse(src); err == nil && (e.Fn == derive.FnDate || e.Fn == derive.FnTemplate) {
			return g.tag(str)
		}
	}
	return v
}

// setValues computes the set values of an effect on one entity:
// ${not:field} (rules v1.7) toggles the current boolean; derived values
// (rules v1.10) are computed after the literal ones.
func (g *generator) setValues(f *firing, e *pack.Effect, in *inst, t time.Time) map[string]any {
	lit := func(v any) (any, bool) {
		if s, isStr := v.(string); isStr && strings.HasPrefix(s, "${not:") && strings.HasSuffix(s, "}") {
			b, isBool := getPath(in.state, "$."+s[len("${not:"):len(s)-1]).(bool)
			return !b, isBool
		}
		return g.resolve(f, v)
	}
	vals := derive.Resolve(e.Set, in.state, g.deriveEnv(f, e, t), lit, setPath)
	for k, v := range vals {
		vals[k] = g.tagDerived(e.Set[k], v)
	}
	return vals
}

func (g *generator) apply(f *firing, e *pack.Effect, t time.Time) {
	ent := g.in.Rules.Entity(e.Entity)
	id, ok := f.ids[e.ID]
	if !ok {
		return
	}
	if e.Remove {
		g.remove(ent, id)
		return
	}
	if e.Create != nil {
		state := map[string]any{}
		vals := derive.Resolve(e.Create, state, g.deriveEnv(f, e, t), func(v any) (any, bool) { return g.resolve(f, v) }, setPath)
		for _, k := range sortedKeys(vals) {
			setPath(state, k, g.tagDerived(e.Create[k], vals[k]))
		}
		state[ent.IDField] = id
		in := &inst{entity: ent.Name, id: id, owner: f.owner, state: state}
		g.derive(in, t, true)
		g.insts[key(ent.Name, id)] = in
		if f.owner != nil {
			g.owned[key(ent.Name, *f.owner)] = append(g.owned[key(ent.Name, *f.owner)], id)
		}
		g.record(in, t, f.rule.ID, f.outcome, e.ID)
		return
	}
	in := g.insts[key(ent.Name, id)]
	if in == nil {
		return
	}
	for _, k := range sortedKeys(e.Where) {
		// rules v1.7: the entity left the state the effect starts from.
		if !jsonEqual(getPath(in.state, "$."+k), e.Where[k]) {
			return
		}
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

func (g *generator) batch(b *pack.BatchRule, t time.Time) {
	var cands []*inst
	for _, in := range g.insts {
		if in.entity != b.Entity {
			continue
		}
		match := true
		for _, k := range sortedKeys(b.Where) {
			if !jsonEqual(getPath(in.state, "$."+k), b.Where[k]) {
				match = false
				break
			}
		}
		if match {
			cands = append(cands, in)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].id < cands[j].id })
	m := int(math.Round(b.Fraction * float64(len(cands))))
	for i := 0; i < m; i++ {
		j := i + int(g.r.intn(int64(len(cands)-i)))
		cands[i], cands[j] = cands[j], cands[i]
	}
	chosen := cands[:m]
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].id < chosen[j].id })
	for _, in := range chosen {
		changed := false
		for _, k := range sortedKeys(b.Set) {
			if !jsonEqual(getPath(in.state, "$."+k), b.Set[k]) {
				setPath(in.state, k, deepCopy(b.Set[k]))
				changed = true
			}
		}
		if changed {
			g.derive(in, t, false)
			g.record(in, t, b.ID, "", "")
		}
	}
}

func (g *generator) output(custs []*customer) (*Output, error) {
	var lines [][]byte
	add := func(v any) error {
		b, err := canonicalJSON(v)
		if err != nil {
			return err
		}
		lines = append(lines, b)
		return nil
	}
	if err := add(map[string]any{"format": "tt.world/v1", "seed": json.Number(strconv.FormatUint(g.in.Seed, 10)), "t0": g.tag(fmtTime(g.t0)), "type": "meta"}); err != nil {
		return nil, err
	}
	out := &Output{}
	for _, c := range custs {
		var arch any
		info := CustomerInfo{ID: c.id}
		if c.arch != nil {
			arch = c.arch.ID
			info.Archetype = c.arch.ID
		}
		out.Customers = append(out.Customers, info)
		profile := map[string]any{"email": c.p.email, "name": c.name}
		for k, v := range c.attrs {
			profile[k] = v // rules v1.9: a clear value of the rules
		}
		if err := add(map[string]any{"archetype": arch, "id": c.id, "profile": profile, "type": "customer"}); err != nil {
			return nil, err
		}
	}
	insts := make([]*inst, 0, len(g.insts))
	for _, in := range g.insts {
		insts = append(insts, in)
	}
	sort.Slice(insts, func(i, j int) bool {
		if insts[i].entity != insts[j].entity {
			return insts[i].entity < insts[j].entity
		}
		return insts[i].id < insts[j].id
	})
	for _, in := range insts {
		var owner any
		if in.owner != nil {
			owner = *in.owner
		}
		if err := add(map[string]any{"customer_id": owner, "entity": in.entity, "id": in.id, "state": in.state, "type": "entity"}); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(g.hist, func(i, j int) bool {
		a, b := g.hist[i], g.hist[j]
		if a.entity != b.entity {
			return a.entity < b.entity
		}
		if a.id != b.id {
			return a.id < b.id
		}
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		return a.seq < b.seq
	})
	for _, h := range g.hist {
		row := map[string]any{"at": g.tag(fmtTime(h.at)), "entity": h.entity, "id": h.id, "seq": json.Number(strconv.Itoa(h.seq)), "state": h.state, "type": "history"}
		if h.rule != "" {
			row["rule_id"] = h.rule
		}
		if h.effect != "" {
			row["effect_id"] = h.effect
			row["outcome"] = h.outcome
		}
		if err := add(row); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(g.pend, func(i, j int) bool {
		if !g.pend[i].due.Equal(g.pend[j].due) {
			return g.pend[i].due.Before(g.pend[j].due)
		}
		return g.pend[i].order < g.pend[j].order
	})
	created := map[string]bool{}
	seq := 0
	for _, p := range g.pend {
		k := key(p.ent, p.id)
		if !p.create && g.insts[k] == nil && !created[k] {
			continue // target never existed: not applicable
		}
		if p.create {
			created[k] = true
		}
		seq++
		off := int64(math.Ceil(p.due.Sub(g.t0).Seconds()))
		if off < 1 {
			off = 1
		}
		var owner any
		if p.owner != nil {
			owner = *p.owner
		}
		row := map[string]any{"customer_id": owner, "due_offset_s": json.Number(strconv.FormatInt(off, 10)), "effect_id": p.effect,
			"entity": p.ent, "id": p.id, "outcome": p.outcome, "rule_id": p.rule, "seq": json.Number(strconv.Itoa(seq)), "type": "pending"}
		if len(p.vars) > 0 {
			row["vars"] = p.vars
		}
		if len(p.effectIDs) > 0 {
			ids := map[string]any{}
			for k, v := range p.effectIDs {
				ids[k] = v
			}
			row["effect_ids"] = ids
		}
		if err := add(row); err != nil {
			return nil, err
		}
	}
	for _, l := range lines {
		out.World = append(out.World, l...)
		out.World = append(out.World, '\n')
	}
	out.Entities, out.History, out.Pending = len(insts), len(g.hist), seq
	out.Synthetic = make([]string, 0, len(g.tags))
	for s := range g.tags {
		out.Synthetic = append(out.Synthetic, s)
	}
	sort.Strings(out.Synthetic)
	return out, nil
}

// createRef gives the id format of a created entity the fields of its
// create values known before the effect runs: literals and variables of
// the cause.
func (g *generator) createRef(f *firing, e *pack.Effect) idfmt.Ref {
	return func(field string) (string, bool) {
		v, ok := e.Create[field]
		if !ok {
			return "", false
		}
		if s, isStr := v.(string); isStr {
			if name, ok := refVar(s); ok {
				return idfmt.ValueString(f.vars[name])
			}
			if strings.HasPrefix(s, "${") {
				return "", false
			}
		}
		return idfmt.ValueString(v)
	}
}
