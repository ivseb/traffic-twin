package export

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Behaviour model (entities, chains, lookups)

type view struct {
	Name      string // unique example name
	State     string // scenario state name ("Started" for the first one)
	Effect    string // effect id ("" for an initial, not yet existing step)
	Status    int
	Media     string
	Body      any
	Absent    bool
	Projected bool
	After     Delay
	HasAfter  bool
}

// lookup is one way an entity instance (or a customer collection) is exposed
// through one operation.
type lookup struct {
	Service  string
	Op       *operation
	Kind     string // "query" or "path"
	Param    string
	Key      string
	Scenario string // empty for static lookups
	RuleID   string
	Subject  string
	EntityID string
	Entity   string
	Outcome  string
	Advance  bool
	List     bool
	Views    []view
	// Owner is the customer that owns what the lookup exposes; Foreign is the
	// answer for any other customer (scope: owner), nil when unscoped.
	Owner   string
	Foreign *view
}

func (l *lookup) stateful() bool { return l.Scenario != "" && len(l.Views) > 1 }

type chainStep struct {
	Effect    string
	State     map[string]any // nil = entity not there yet
	Absent    bool
	Projected bool
	After     Delay
}

type chain struct {
	Rule     *Rule
	Entity   *Entity
	Subject  string
	EntityID string
	Outcome  string
	Owner    string
	Steps    []chainStep
}

func (c *chain) scenario() string { return c.Rule.ID + "-" + c.Subject }

type presetPlan struct {
	P        Preset
	Customer string
	Chains   []*chain
	Missing  []string
}

type model struct {
	in       *Input
	ops      map[string]*operation // service + "|" + key
	opsBySvc map[string][]*operation
	ents     map[string]*Entity
	rules    []*Rule // approved only
	chains   []*chain
	lookups  map[string][]*lookup // by service
	faults   map[string]FaultOps  // service + "|" + op
	ownerOf  map[string]string    // entity|id -> customer
	notes    []Loss               // target independent losses
	links    map[string]int       // "entity.field->entity" -> checked values
	presets  []presetPlan
	stats    modelStats
}

type modelStats struct {
	ApprovedRules, CausalRules, BatchRules int
	Chains, StaticLookups, StatefulLookups int
	RangeDelays, FixedDelays               int
}

var varRef = regexp.MustCompile(`^\$\{([A-Za-z][A-Za-z0-9_:-]{0,63})\}$`)

func (m *model) note(kind, element, detail string, count int) {
	m.notes = append(m.notes, Loss{Kind: kind, Element: element, Detail: detail, Count: count})
}

// withoutResponses drops the response effects of a rule (rules v1.4: "the
// next call answers 404", "errors with frequency p"): the targets have no
// per-session override, so the loss is reported and the rest is exported.
func (m *model) withoutResponses(r *Rule) *Rule {
	drop := map[string]bool{}
	removes, keyed, all := 0, 0, 0
	derived := 0
	for _, e := range r.Effects {
		for _, vals := range []map[string]any{e.Create, e.Set} {
			for _, v := range vals {
				if isDerived(v) {
					derived++
				}
			}
		}
	}
	if derived > 0 {
		// rules v1.10: the stubs do not compute; the fields are left out.
		m.note("derived-value", "rule:"+r.ID, fmt.Sprintf("%d derived values ($derive) are not exported: the stubs leave those fields out", derived), derived)
	}
	for _, e := range r.Effects {
		switch {
		case e.TargetAll:
			drop[e.ID] = true
			all++
		case e.Respond != nil:
			drop[e.ID] = true
		case e.Remove:
			drop[e.ID] = true
			removes++
		case e.TargetKey != nil:
			drop[e.ID] = true
			keyed++
		}
	}
	if len(drop) == 0 {
		return r
	}
	if keyed > 0 {
		// rules v1.8: the stubs keep no keyed record per session.
		m.note("keyed-effect", "rule:"+r.ID, fmt.Sprintf("%d effects on keyed records (target_key) are not exported: the stubs answer as observed", keyed), keyed)
	}
	if all > 0 {
		// rules v1.9: the stubs keep no per-session objects of a customer.
		m.note("update-effect", "rule:"+r.ID, fmt.Sprintf("%d effects on all the objects of the customer (target_all) are not exported: the stubs answer as observed", all), all)
	}
	if n := len(drop) - removes - keyed - all; n > 0 {
		m.note("response-effect", "rule:"+r.ID, fmt.Sprintf("%d response effects (respond) are not exported: the stubs answer as observed", n), n)
	}
	if removes > 0 {
		// rules v1.6: the stubs have no per-session removal.
		m.note("remove-effect", "rule:"+r.ID, fmt.Sprintf("%d remove effects are not exported: removed objects stay in the stubs' answers", removes), removes)
	}
	out := *r
	out.Effects = nil
	for _, e := range r.Effects {
		if !drop[e.ID] {
			out.Effects = append(out.Effects, e)
		}
	}
	out.Outcomes = nil
	for _, o := range r.Outcomes {
		oc := o
		oc.Effects = nil
		for _, id := range o.Effects {
			if !drop[id] {
				oc.Effects = append(oc.Effects, id)
			}
		}
		out.Outcomes = append(out.Outcomes, oc)
	}
	return &out
}

func buildModel(in *Input, services map[string]bool) *model {
	m := &model{
		in: in, ops: map[string]*operation{}, opsBySvc: map[string][]*operation{},
		ents: map[string]*Entity{}, lookups: map[string][]*lookup{}, faults: map[string]FaultOps{},
		ownerOf: map[string]string{}, links: map[string]int{},
	}
	for _, s := range in.Services {
		if services != nil && !services[s.Name] {
			continue
		}
		ops := indexOps(s)
		m.opsBySvc[s.Name] = ops
		for _, o := range ops {
			m.ops[s.Name+"|"+o.Key] = o
		}
	}
	for i := range in.Rules.Entities {
		e := &in.Rules.Entities[i]
		e.ReadBy = shareHiddenWhen(e.ReadBy)
		m.ents[e.Name] = e
	}
	for _, f := range in.Faults.Ops {
		m.faults[f.Service+"|"+f.Op] = f
	}
	for _, we := range in.World.Entities {
		if we.CustomerID != "" {
			m.ownerOf[we.Entity+"|"+we.ID] = we.CustomerID
		}
	}
	for _, p := range in.World.Pending {
		if _, ok := m.ownerOf[p.Entity+"|"+p.ID]; !ok && p.CustomerID != "" {
			m.ownerOf[p.Entity+"|"+p.ID] = p.CustomerID
		}
	}
	for i := range in.Rules.Rules {
		r := &in.Rules.Rules[i]
		if r.Status == "approved" {
			m.conditionLosses(r)
			m.rules = append(m.rules, m.withoutResponses(r))
		}
	}
	m.readLosses()
	sort.Slice(m.rules, func(i, j int) bool { return m.rules[i].ID < m.rules[j].ID })
	m.stats.ApprovedRules = len(m.rules)

	taken := map[string]bool{} // entity instances covered by a chain: entity|id
	for _, r := range m.rules {
		switch r.Kind {
		case "causal":
			m.stats.CausalRules++
			if n := m.updateEffects(r); n > 0 {
				// rules v1.7: a write that changes an existing object never
				// runs in the world the stubs are built from.
				m.note("update-effect", "rule:"+r.ID, fmt.Sprintf("%d effects of %s on existing objects are not exported: the stubs answer as observed", n, r.Cause.Op), n)
			}
			m.buildChains(r, taken)
		case "batch":
			m.stats.BatchRules++
			m.note("batch-schedule", "rule:"+r.ID,
				fmt.Sprintf("batch rule %q (cron %q, fraction %v) needs a virtual clock with calendar: not exported; entities keep the states described by their scenarios", r.Title, r.Schedule, r.Fraction), 1)
		}
	}
	m.buildLookups(taken)
	m.checkRelations()
	m.buildPresets()
	return m
}

// updateEffects counts the set effects of a rule whose cause creates no
// entity (an update of an existing object, rules v1.7): the world, and so
// the stubs, never run them.
func (m *model) updateEffects(r *Rule) int {
	if r.Cause == nil {
		return 0
	}
	for _, e := range m.ents {
		if e.CreatedBy != nil && e.CreatedBy.Op == r.Cause.Op && e.Service == r.Cause.Service {
			return 0
		}
	}
	n := 0
	for _, e := range r.Effects {
		if e.TargetID != "" && e.Set != nil {
			n++
		}
	}
	return n
}

// causeEntity finds the entity created by the operation that is the cause of
// the rule and bound to the given variable.
func (m *model) causeEntity(r *Rule, v string) *Entity {
	if r.Cause == nil {
		return nil
	}
	b, ok := r.Cause.Bind[v]
	if !ok {
		return nil
	}
	for _, n := range sortedKeys(m.ents) {
		e := m.ents[n]
		if e.CreatedBy != nil && e.CreatedBy.Op == r.Cause.Op && e.Service == r.Cause.Service && e.CreatedBy.ID == b {
			return e
		}
	}
	return nil
}

// subst resolves "${var}" and "${effect:id}" (whole-string references only).
// isDerived reports whether a create/set value is a derived value (rules
// v1.10, {"$derive": ...}).
func isDerived(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m["$derive"]
	return ok
}

func subst(v any, vars, effIDs map[string]any, subjectVar, subject string) (any, bool) {
	if isDerived(v) {
		return nil, false
	}
	s, ok := v.(string)
	if !ok {
		return v, true
	}
	mm := varRef.FindStringSubmatch(s)
	if mm == nil {
		return v, true
	}
	name := mm[1]
	if strings.HasPrefix(name, "effect:") {
		x, ok := effIDs[strings.TrimPrefix(name, "effect:")]
		return x, ok
	}
	if x, ok := vars[name]; ok {
		return x, true
	}
	if name == subjectVar && subject != "" {
		return subject, true
	}
	return nil, false
}

func (m *model) buildChains(r *Rule, taken map[string]bool) {
	effects := map[string]Effect{}
	for _, e := range r.Effects {
		effects[e.ID] = e
	}
	var subjectKey, subjectVar string
	for _, e := range r.Effects {
		for _, k := range sortedKeys(e.Create) {
			if s, ok := e.Create[k].(string); ok {
				if mm := varRef.FindStringSubmatch(s); mm != nil && !strings.HasPrefix(mm[1], "effect:") {
					subjectKey, subjectVar = k, mm[1]
					break
				}
			}
		}
		if subjectKey != "" {
			break
		}
	}
	causeEnt := m.causeEntity(r, subjectVar)
	for _, e := range r.Effects {
		if e.After.IsRange {
			m.stats.RangeDelays++
		} else {
			m.stats.FixedDelays++
		}
	}
	var immediate func(id string, depth int) bool
	immediate = func(id string, depth int) bool {
		e, ok := effects[id]
		if !ok || depth > 16 || !e.After.Zero() {
			return false
		}
		return e.AfterEffect == "" || immediate(e.AfterEffect, depth+1)
	}

	type inst struct {
		entity, id string
		hist       []WorldHistory
		pend       []WorldPending
	}
	groups := map[string]*inst{}
	get := func(entity, id string) *inst {
		k := entity + "|" + id
		g := groups[k]
		if g == nil {
			g = &inst{entity: entity, id: id}
			groups[k] = g
		}
		return g
	}
	for _, h := range m.in.World.History {
		if h.RuleID == r.ID {
			g := get(h.Entity, h.ID)
			g.hist = append(g.hist, h)
		}
	}
	for _, p := range m.in.World.Pending {
		if p.RuleID == r.ID {
			g := get(p.Entity, p.ID)
			g.pend = append(g.pend, p)
		}
	}
	subjects := map[string]bool{}
	skipped := map[string]int{}
	for _, k := range sortedKeys(groups) {
		g := groups[k]
		ent := m.ents[g.entity]
		if ent == nil {
			continue
		}
		sort.SliceStable(g.hist, func(i, j int) bool {
			if g.hist[i].At != g.hist[j].At {
				return g.hist[i].At < g.hist[j].At
			}
			return g.hist[i].Seq < g.hist[j].Seq
		})
		sort.SliceStable(g.pend, func(i, j int) bool {
			if g.pend[i].DueOffsetS != g.pend[j].DueOffsetS {
				return g.pend[i].DueOffsetS < g.pend[j].DueOffsetS
			}
			return g.pend[i].Seq < g.pend[j].Seq
		})
		first := ""
		if len(g.hist) > 0 {
			first = g.hist[0].EffectID
		} else if len(g.pend) > 0 {
			first = g.pend[0].EffectID
		}
		if effects[first].Create == nil {
			skipped[first]++ // update of an existing entity (target_id): not a chain
			continue
		}
		c := &chain{Rule: r, Entity: ent, EntityID: g.id, Owner: m.ownerOf[g.entity+"|"+g.id]}
		if !immediate(first, 0) {
			c.Steps = append(c.Steps, chainStep{Absent: true})
		}
		var last map[string]any
		var done []string
		hasOutcome := false
		for _, h := range g.hist {
			st := copyMap(h.State)
			c.Steps = append(c.Steps, chainStep{Effect: h.EffectID, State: st, After: effects[h.EffectID].After})
			done = append(done, h.EffectID)
			last = st
			if h.Outcome != "" {
				hasOutcome = true
				c.Outcome = h.Outcome
			}
			if c.Subject == "" && subjectKey != "" {
				if v, ok := getPath(st, subjectKey); ok {
					c.Subject = stringify(v)
				}
			}
		}
		if c.Subject == "" {
			c.Subject = g.id
		}
		for _, p := range g.pend {
			e := effects[p.EffectID]
			var st map[string]any
			if e.Create != nil {
				st = map[string]any{}
				for _, key := range sortedKeys(e.Create) {
					if val, ok := subst(e.Create[key], p.Vars, p.EffectIDs, subjectVar, c.Subject); ok {
						setPath(st, key, val)
					}
				}
				setPath(st, ent.IDField, p.ID)
			} else {
				if last == nil {
					continue
				}
				st = copyMap(last)
				for _, key := range sortedKeys(e.Set) {
					if val, ok := subst(e.Set[key], p.Vars, p.EffectIDs, subjectVar, c.Subject); ok {
						setPath(st, key, val)
					}
				}
			}
			c.Steps = append(c.Steps, chainStep{Effect: p.EffectID, State: st, Projected: true, After: e.After})
			done = append(done, p.EffectID)
			last = st
			hasOutcome = true
			if c.Outcome == "" {
				c.Outcome = p.Outcome
			}
		}
		if !hasOutcome {
			// Pre-1.2 world: no outcome in history, no pending rows. Infer the
			// most probable branch and project its remaining effects.
			var best *Outcome
			for i := range r.Outcomes {
				o := &r.Outcomes[i]
				if equalPrefix(o.Effects, done) && (best == nil || o.P > best.P || (o.P == best.P && o.Name < best.Name)) {
					best = o
				}
			}
			if best != nil {
				c.Outcome = best.Name
				for _, eid := range best.Effects[len(done):] {
					e := effects[eid]
					if e.Set == nil || last == nil {
						continue
					}
					ns := copyMap(last)
					for _, sk := range sortedKeys(e.Set) {
						if val, ok := subst(e.Set[sk], nil, nil, subjectVar, c.Subject); ok {
							setPath(ns, sk, val)
						}
					}
					c.Steps = append(c.Steps, chainStep{Effect: eid, State: ns, Projected: true, After: e.After})
					last = ns
				}
			} else {
				m.note("outcome-unmatched", "rule:"+r.ID,
					fmt.Sprintf("history of %s %s matches no outcome: only the observed steps are exported", ent.Name, g.id), 1)
			}
		}
		taken[g.entity+"|"+g.id] = true
		subjects[c.Subject] = true
		m.chains = append(m.chains, c)
	}
	for _, id := range sortedKeys(skipped) {
		m.note("state", "rule:"+r.ID+"/effect:"+id,
			fmt.Sprintf("effect updates an existing entity (target_id): not exported as a scenario step; %d entities are served as their snapshot at t0", skipped[id]), skipped[id])
	}

	// Subjects of the cause entity that never got an effect (pre-1.2 style
	// "never-shipped" with no effects).
	if causeEnt != nil && subjectKey != "" {
		var empty *Outcome
		for i := range r.Outcomes {
			if len(r.Outcomes[i].Effects) == 0 && (empty == nil || r.Outcomes[i].P > empty.P) {
				empty = &r.Outcomes[i]
			}
		}
		if empty != nil {
			var ids []string
			for _, we := range m.in.World.Entities {
				if we.Entity == causeEnt.Name && !subjects[we.ID] {
					ids = append(ids, we.ID)
				}
			}
			sort.Strings(ids)
			for _, id := range ids {
				m.chains = append(m.chains, &chain{
					Rule: r, Entity: m.entityOfEffects(r), Subject: id, Outcome: empty.Name,
					Owner: m.ownerOf[causeEnt.Name+"|"+id], Steps: []chainStep{{Absent: true}},
				})
			}
		}
	}
	seen := map[string]bool{}
	for _, c := range m.chains {
		if c.Rule == r {
			seen[c.Outcome] = true
		}
	}
	for _, o := range r.Outcomes {
		if !seen[o.Name] {
			m.note("coverage", "rule:"+r.ID+"/outcome:"+o.Name,
				fmt.Sprintf("outcome %q (p=%v) has no synthetic subject in the world: no stub or example is generated for it", o.Name, o.P), 1)
		}
	}
}

func (m *model) entityOfEffects(r *Rule) *Entity {
	for _, e := range r.Effects {
		if ent := m.ents[e.Entity]; ent != nil {
			return ent
		}
	}
	return nil
}

func equalPrefix(full, prefix []string) bool {
	if len(prefix) > len(full) {
		return false
	}
	for i := range prefix {
		if full[i] != prefix[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Views

// shapeAt builds the response body that exposes items at the given reference.
// list reports whether the shape is a collection (an empty collection is a
// valid "absent" view); for single shapes an absent view has no body.
func shapeAt(at Ref, items []map[string]any) (body any, list bool, ok bool) {
	p := strings.TrimPrefix(at.Path, "$")
	list = strings.HasSuffix(p, "[*]")
	p = strings.TrimSuffix(p, "[*]")
	var keys []string
	for _, k := range strings.Split(strings.TrimPrefix(p, "."), ".") {
		if k != "" {
			keys = append(keys, k)
		}
	}
	var leaf any
	if list {
		arr := make([]any, 0, len(items))
		for _, it := range items {
			arr = append(arr, deepCopy(it))
		}
		leaf = arr
	} else {
		if len(items) == 0 {
			return nil, false, false
		}
		leaf = deepCopy(items[0])
	}
	for i := len(keys) - 1; i >= 0; i-- {
		leaf = map[string]any{keys[i]: leaf}
	}
	return leaf, list, true
}

func orJSON(s string) string {
	if s == "" {
		return "application/json"
	}
	return s
}

// hidden reports whether an entity state matches every hidden_when value.
func hidden(h map[string]any, st map[string]any) bool {
	if len(h) == 0 || st == nil {
		return false
	}
	for k, want := range h {
		got, ok := getPath(st, k)
		if !ok || stringify(got) != stringify(want) {
			return false
		}
	}
	return true
}

// fillList writes count and total into the envelope of a list body.
func fillList(body any, ls *ListShape, count, total int) {
	root, ok := body.(map[string]any)
	if !ok || ls == nil {
		return
	}
	if ls.Count != "" {
		setPath(root, strings.TrimPrefix(strings.TrimPrefix(ls.Count, "$"), "."), count)
	}
	if ls.Total != "" {
		setPath(root, strings.TrimPrefix(strings.TrimPrefix(ls.Total, "$"), "."), total)
	}
}

// errorView builds an answer for a status taken from the contract: the named
// example, else the first example of that status, else the mock error envelope
// (mock.md section 3).
func errorView(op *operation, status int, name, exName, code string) view {
	if exName != "" {
		if st, ex, mt, ok := op.findExample(exName); ok {
			return view{Name: name, Status: st, Media: orJSON(mt), Body: deepCopy(ex.Value), Absent: true}
		}
	}
	if r := op.response(status); r != nil && len(r.Examples) > 0 {
		return view{Name: name, Status: status, Media: orJSON(r.Media), Body: deepCopy(r.Examples[0].Value), Absent: true}
	}
	return view{Name: name, Status: status, Media: "application/json", Absent: true,
		Body: map[string]any{"code": code, "message": "not available to this customer"}}
}

func absentView(op *operation, rb ReadBy, name string) view {
	body, list, ok := shapeAt(rb.At, nil)
	if ok && list {
		fillList(body, rb.List, 0, 0)
		st, media := 200, "application/json"
		if sr := op.successResponse(); sr != nil {
			st, media = sr.Status, orJSON(sr.Media)
		}
		return view{Name: name, Status: st, Media: media, Body: body, Absent: true}
	}
	return errorView(op, 404, name, rb.NotFoundExample, "not_found")
}

func presentView(op *operation, rb ReadBy, name string, items []map[string]any, total int) (view, bool) {
	items = op.coherent(rb.At, items)
	body, list, ok := shapeAt(rb.At, items)
	if !ok {
		return view{}, false
	}
	if list {
		fillList(body, rb.List, len(items), total)
	}
	st, media := 200, "application/json"
	if sr := op.successResponse(); sr != nil {
		st, media = sr.Status, orJSON(sr.Media)
	}
	return view{Name: name, Status: st, Media: media, Body: body}, true
}

// foreignView is the answer given to another customer (scope: owner).
func foreignView(op *operation, rb ReadBy, name string) *view {
	status, code := 404, "not_found"
	if rb.Foreign == "forbidden" {
		status, code = 403, "forbidden"
	}
	ex := rb.ForeignExample
	if ex == "" && status == 404 {
		ex = rb.NotFoundExample
	}
	v := errorView(op, status, name, ex, code)
	v.Status = status
	if ex != "" {
		if st, _, _, ok := op.findExample(ex); ok {
			v.Status = st
		}
	}
	return &v
}

// ---------------------------------------------------------------------------
// Lookups

type lookupKey struct{ svc, op, param, key string }

func kindOf(by *Ref) string {
	if by.From == "req.path" {
		return "path"
	}
	return "query"
}

func (m *model) buildLookups(taken map[string]bool) {
	seen := map[lookupKey]bool{}
	warned := map[string]bool{}
	warnOnce := func(id, kind, el, detail string) {
		if !warned[id] {
			warned[id] = true
			m.note(kind, el, detail, 1)
		}
	}
	// resolve finds the operation of a read_by and checks the selection is one
	// the exporters can express.
	resolve := func(ent *Entity, rb ReadBy) (*operation, bool) {
		svc := ent.Service
		if rb.Service != "" {
			svc = rb.Service
		}
		if _, known := m.opsBySvc[svc]; !known {
			return nil, false
		}
		op := m.ops[svc+"|"+rb.Op]
		el := "entity:" + ent.Name + "/" + rb.Op
		if op == nil {
			warnOnce(el, "contract-gap", el, "read_by operation is not in the contract: entity not exposed through it")
			return nil, false
		}
		if rb.By == nil {
			warnOnce(el, "selection", el, "list of the session's customer (no `by`) needs a session customer: not exported")
			return nil, false
		}
		if rb.By.From != "req.query" && rb.By.From != "req.path" {
			warnOnce(el, "selection", el, "selection by "+rb.By.From+" is not supported: entity not exposed through it")
			return nil, false
		}
		if rb.By.From == "req.query" && rb.By.Field == "" && !rb.By.Owner {
			return nil, false
		}
		return op, true
	}
	keyOf := func(rb ReadBy, state map[string]any, entityID string) (string, bool) {
		if rb.By.Field != "" {
			v, ok := getPath(state, rb.By.Field)
			if !ok {
				return "", false
			}
			return stringify(v), true
		}
		if rb.By.From == "req.path" {
			return entityID, entityID != ""
		}
		return "", false
	}
	scoped := func(rb ReadBy) bool { return rb.Scope == "owner" }

	// Stateful chains first (they win key collisions with static data).
	svcAdv := map[string]bool{} // scenario|service -> advance taken
	chainSvcs := map[string]map[string]bool{}
	for _, c := range m.chains {
		if c.Entity == nil {
			continue
		}
		scenario := c.scenario()
		for _, rb := range c.Entity.ReadBy {
			if rb.By != nil && rb.By.Owner {
				continue // customer collections are snapshots, see below
			}
			op, ok := resolve(c.Entity, rb)
			if !ok {
				continue
			}
			var anyState map[string]any
			for _, s := range c.Steps {
				if s.State != nil {
					anyState = s.State
					break
				}
			}
			var key string
			if anyState != nil {
				k, ok := keyOf(rb, anyState, c.EntityID)
				if !ok {
					continue
				}
				key = k
			} else if rb.By.Field != "" && rb.By.Field == m.subjectField(c.Rule) {
				key = c.Subject
			} else {
				continue
			}
			lk := lookupKey{op.Service, op.Key, rb.By.Name, key}
			if seen[lk] {
				m.note("key-collision", "rule:"+c.Rule.ID, fmt.Sprintf("%s selected by %s is already exposed for another subject with the same key: skipped", op.Key, rb.By.Name), 1)
				continue
			}
			seen[lk] = true
			advKey := scenario + "|" + op.Service
			l := &lookup{
				Service: op.Service, Op: op, Kind: kindOf(rb.By), Param: rb.By.Name, Key: key,
				Scenario: scenario, RuleID: c.Rule.ID, Subject: c.Subject, EntityID: c.EntityID,
				Entity: c.Entity.Name, Outcome: c.Outcome, Advance: !svcAdv[advKey],
			}
			svcAdv[advKey] = true
			if chainSvcs[scenario] == nil {
				chainSvcs[scenario] = map[string]bool{}
			}
			chainSvcs[scenario][op.Service] = true
			if scoped(rb) && c.Owner != "" {
				l.Owner = c.Owner
				l.Foreign = foreignView(op, rb, safeName(scenario+"--foreign"))
			}
			used := map[string]int{}
			for i, s := range c.Steps {
				state := "Started"
				if i > 0 {
					state = s.Effect
				}
				used[state]++
				if used[state] > 1 {
					state = fmt.Sprintf("%s-%d", state, used[state])
				}
				name := safeName(scenario + "--" + state)
				if len(c.Steps) == 1 && c.Outcome != "" {
					name = safeName(scenario + "--" + c.Outcome)
				}
				var v view
				if s.Absent || s.State == nil || hidden(rb.HiddenWhen, s.State) {
					v = absentView(op, rb, name)
				} else {
					var ok bool
					if v, ok = presentView(op, rb, name, []map[string]any{s.State}, 1); !ok {
						v = absentView(op, rb, name)
					}
				}
				v.State, v.Effect, v.Projected = state, s.Effect, s.Projected
				v.After, v.HasAfter = s.After, s.Effect != ""
				l.Views = append(l.Views, v)
			}
			m.lookups[op.Service] = append(m.lookups[op.Service], l)
			m.stats.Chains++
		}
	}
	for _, sc := range sortedKeys(chainSvcs) {
		if len(chainSvcs[sc]) > 1 {
			m.note("state", "scenario:"+sc, "the chain is exposed by several services ("+strings.Join(sortedKeys(chainSvcs[sc]), ", ")+"): each service keeps its own position, they do not advance together", 1)
		}
	}

	// Static lookups: entity rows that no chain describes.
	type group struct {
		l      *lookup
		rb     ReadBy
		items  []map[string]any
		ids    []string
		hidden int
	}
	statics := map[lookupKey]*group{}
	var order []lookupKey
	for _, we := range m.in.World.Entities {
		if taken[we.Entity+"|"+we.ID] {
			continue
		}
		ent := m.ents[we.Entity]
		if ent == nil {
			continue
		}
		for _, rb := range ent.ReadBy {
			if rb.By != nil && rb.By.Owner {
				continue
			}
			op, ok := resolve(ent, rb)
			if !ok {
				continue
			}
			key, ok := keyOf(rb, we.State, we.ID)
			if !ok {
				continue
			}
			lk := lookupKey{op.Service, op.Key, rb.By.Name, key}
			if seen[lk] {
				continue
			}
			g := statics[lk]
			if g == nil {
				g = &group{rb: rb, l: &lookup{Service: op.Service, Op: op, Kind: kindOf(rb.By), Param: rb.By.Name, Key: key, Entity: ent.Name, EntityID: we.ID}}
				statics[lk] = g
				order = append(order, lk)
			}
			if hidden(rb.HiddenWhen, we.State) {
				g.hidden++
				continue
			}
			g.items = append(g.items, we.State)
			g.ids = append(g.ids, we.ID)
			if scoped(rb) {
				if c := m.ownerOf[we.Entity+"|"+we.ID]; c != "" {
					g.l.Owner = c
				}
			}
		}
	}
	for _, lk := range order {
		g := statics[lk]
		name := safeName(g.l.Entity + "-" + g.l.Key)
		_, list, _ := shapeAt(g.rb.At, nil)
		g.l.List = list
		if len(g.items) == 0 {
			g.l.Views = []view{absentView(g.l.Op, g.rb, name)}
			g.l.Owner = ""
		} else {
			idx := make([]int, len(g.items))
			for i := range idx {
				idx[i] = i
			}
			sort.Slice(idx, func(a, b int) bool { return g.ids[idx[a]] < g.ids[idx[b]] })
			items := make([]map[string]any, len(idx))
			for i, j := range idx {
				items[i] = g.items[j]
			}
			if !list && len(items) > 1 {
				m.note("key-collision", "entity:"+g.l.Entity, fmt.Sprintf("%s selects a single %s but %d instances share the key: first one kept", g.l.Op.Key, g.l.Entity, len(items)), len(items)-1)
			}
			v, ok := presentView(g.l.Op, g.rb, name, items, len(items))
			if !ok {
				continue
			}
			g.l.Views = []view{v}
			if !list && g.l.Owner != "" {
				g.l.Foreign = foreignView(g.l.Op, g.rb, safeName(name+"--foreign"))
			} else {
				g.l.Owner = ""
			}
		}
		if scoped(g.rb) && list {
			warnOnce("scope|"+g.l.Op.Key, "scope", "op:"+g.l.Service+" "+g.l.Op.Key,
				"entities of other customers are dropped from this list only when a session customer is known: the export serves every customer's entities")
		}
		g.l.Views[0].Name = name
		m.lookups[g.l.Service] = append(m.lookups[g.l.Service], g.l)
		m.stats.StaticLookups++
	}

	// Customer collections (by.owner): one snapshot list per customer.
	for _, en := range sortedKeys(m.ents) {
		ent := m.ents[en]
		for _, rb := range ent.ReadBy {
			if rb.By == nil || !rb.By.Owner {
				continue
			}
			op, ok := resolve(ent, rb)
			if !ok {
				continue
			}
			byCust := map[string][]WorldEntity{}
			for _, we := range m.in.World.Entities {
				if we.Entity == ent.Name && we.CustomerID != "" && !hidden(rb.HiddenWhen, we.State) {
					byCust[we.CustomerID] = append(byCust[we.CustomerID], we)
				}
			}
			for _, cust := range sortedKeys(byCust) {
				lk := lookupKey{op.Service, op.Key, rb.By.Name, cust}
				if seen[lk] {
					continue
				}
				seen[lk] = true
				items, total := listItems(byCust[cust], rb.List)
				name := safeName(ent.Name + "-owner-" + cust)
				v, ok := presentView(op, rb, name, items, total)
				if !ok {
					continue
				}
				v.Name = name
				if root, ok := v.Body.(map[string]any); ok {
					for _, f := range []string{"customerId", "customer_id"} {
						if _, has := root[f]; !has && op.hasProp(f) {
							root[f] = cust
						}
					}
					if rb.List != nil && rb.List.NextCursor != "" && total > len(items) {
						setPath(root, strings.TrimPrefix(strings.TrimPrefix(rb.List.NextCursor, "$"), "."), fmt.Sprintf("c%d", len(items)))
					}
				}
				l := &lookup{Service: op.Service, Op: op, Kind: kindOf(rb.By), Param: rb.By.Name, Key: cust,
					Entity: ent.Name, List: true, Views: []view{v}}
				if scoped(rb) {
					l.Owner = cust
					l.Foreign = foreignView(op, rb, safeName(name+"--foreign"))
				}
				m.lookups[op.Service] = append(m.lookups[op.Service], l)
				m.stats.StaticLookups++
			}
			if rb.List != nil && (rb.List.Limit != nil || rb.List.Offset != nil || rb.List.Page != nil || rb.List.Cursor != nil) {
				m.note("selection", "op:"+op.Service+" "+op.Key, "pagination parameters (limit/offset/page/cursor) are not honoured: every request gets the first page", 1)
			}
			m.note("state", "entity:"+ent.Name+"/"+rb.Op, "customer collections are snapshots of the world at t0: they do not follow scenario steps", 1)
		}
	}

	for svc := range m.lookups {
		ls := m.lookups[svc]
		sort.SliceStable(ls, func(i, j int) bool {
			a, b := ls[i], ls[j]
			if a.Op.Key != b.Op.Key {
				return a.Op.Key < b.Op.Key
			}
			if a.Param != b.Param {
				return a.Param < b.Param
			}
			return a.Key < b.Key
		})
		for _, l := range ls {
			if l.stateful() {
				m.stats.StatefulLookups++
			}
		}
	}
}

// listItems orders a customer's entities and cuts the first page.
func listItems(rows []WorldEntity, ls *ListShape) ([]map[string]any, int) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if ls != nil && ls.OrderBy != "" {
		desc := ls.Order == "desc"
		sort.SliceStable(rows, func(i, j int) bool {
			a, aok := getPath(rows[i].State, ls.OrderBy)
			b, bok := getPath(rows[j].State, ls.OrderBy)
			if aok != bok {
				return aok // missing values go last
			}
			if !aok {
				return false
			}
			c := compareValues(a, b)
			if c == 0 {
				return false
			}
			if desc {
				return c > 0
			}
			return c < 0
		})
	}
	total := len(rows)
	if ls != nil && ls.DefaultLimit > 0 && len(rows) > ls.DefaultLimit {
		rows = rows[:ls.DefaultLimit]
	}
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		out[i] = r.State
	}
	return out, total
}

func compareValues(a, b any) int {
	fa, aok := toFloat(a)
	fb, bok := toFloat(b)
	if aok && bok {
		switch {
		case fa < fb:
			return -1
		case fa > fb:
			return 1
		}
		return 0
	}
	return strings.Compare(stringify(a), stringify(b))
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case interface{ Float64() (float64, error) }:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

// subjectField is the entity field that carries the cause subject.
func (m *model) subjectField(r *Rule) string {
	for _, e := range r.Effects {
		for _, k := range sortedKeys(e.Create) {
			if s, ok := e.Create[k].(string); ok {
				if mm := varRef.FindStringSubmatch(s); mm != nil && !strings.HasPrefix(mm[1], "effect:") {
					return k
				}
			}
		}
	}
	return ""
}

// latencyOf returns the latency profile of an operation (faults.json wins over
// the contract's x-tt-latency-ms).
func (m *model) latencyOf(o *operation) *Latency {
	if f, ok := m.faults[o.Service+"|"+o.Key]; ok && f.Latency != nil {
		return f.Latency
	}
	return o.Latency
}

// checkRelations verifies that every relation value of the world points at an
// existing entity, so exported examples keep the links between objects
// (order.shipmentId -> shipment, shipment.orderId -> order).
func (m *model) checkRelations() {
	exists := map[string]bool{}
	for _, we := range m.in.World.Entities {
		exists[we.Entity+"|"+we.ID] = true
	}
	for _, p := range m.in.World.Pending {
		exists[p.Entity+"|"+p.ID] = true
	}
	dangling := map[string]int{}
	for _, we := range m.in.World.Entities {
		ent := m.ents[we.Entity]
		if ent == nil {
			continue
		}
		for _, rel := range ent.Relations {
			v, ok := getPath(we.State, rel.Field)
			if !ok || v == nil {
				continue
			}
			var ids []string
			if arr, ok := v.([]any); ok {
				for _, x := range arr {
					ids = append(ids, stringify(x))
				}
			} else {
				ids = []string{stringify(v)}
			}
			el := ent.Name + "." + rel.Field + "->" + rel.Entity
			for _, id := range ids {
				m.links[el]++
				if !exists[rel.Entity+"|"+id] {
					dangling[el]++
				}
			}
		}
	}
	for _, el := range sortedKeys(dangling) {
		m.note("integrity", "relation:"+el, "world values that point at no entity of the pack: exported as they are", dangling[el])
	}
}
