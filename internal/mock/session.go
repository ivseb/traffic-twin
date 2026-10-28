package mock

import (
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/derive"
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/pack"
)

// deriveRNG returns an independent deterministic stream for (seed, label).
func deriveRNG(seed uint64, label string) *rand.Rand {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	h := sha256.Sum256(append(b[:], label...))
	return rand.New(rand.NewPCG(binary.LittleEndian.Uint64(h[0:8]), binary.LittleEndian.Uint64(h[8:16])))
}

// entityRec is the live state of one entity of a session.
type entityRec struct {
	entity     string
	id         string
	customerID *string // owner
	state      map[string]any
	created    time.Time
	updated    time.Time
}

// instance is one firing of a causal rule (or the remains of one, for the
// pending lines of the world).
type instance struct {
	rule     *causalRule
	outcome  string
	vars     map[string]any
	customer *string           // owner of the entities the firing creates
	created  map[string]string // effect id -> id of the entity it created or changed
}

type queued struct {
	due  time.Time
	seq  int
	inst *instance
	eff  *pack.Effect
	// entityID is the entity of a pending line of the world (assigned in
	// advance for a create effect); empty for effects queued in the session.
	entityID string
	world    bool
}

type effectQueue []*queued

func (q effectQueue) Len() int { return len(q) }
func (q effectQueue) Less(i, j int) bool {
	if !q[i].due.Equal(q[j].due) {
		return q[i].due.Before(q[j].due)
	}
	return q[i].seq < q[j].seq
}
func (q effectQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *effectQueue) Push(x any)   { *q = append(*q, x.(*queued)) }
func (q *effectQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[:n-1]
	return x
}

type forcedEntry struct {
	outcome   string
	remaining int
}

// session is an isolated world: entities, virtual clock, queue, RNG streams,
// faults and journal. All access is serialised by mu.
type session struct {
	mu sync.Mutex
	m  *Mock

	id       string
	seed     uint64 // seed of the baseline
	customer *string
	t0       time.Time
	now      time.Time

	// baseline restored by reset
	baseCustomer *string
	scenario     string // preset of the baseline, "" when none
	createFaults FaultsConfig
	initFaults   FaultsConfig
	baseForced   []forcedRule

	faults     FaultsConfig
	faultUsed  []int
	rngFault   *rand.Rand
	rngOutcome *rand.Rand
	rngRespond *rand.Rand
	// responses are the response effects applied so far (rules v1.4).
	responses []*ruleResponse
	// counted are the calls counted by the response effects with a limit
	// (rules v1.8), per rule and effect.
	counted map[string][]countedCall
	// Rules v1.9: the preconditions lifted in the session, the values of
	// the customer attributes drawn for it, the successful calls of the
	// operations that move a delta aggregate, and the entity overlay the
	// last body was built from (wave4.go).
	lifted    map[string]bool
	attrCache map[string]string
	calls     map[string]int
	lastOV    optVal

	ents     map[string]map[string]*entityRec
	counters map[string]int
	// deriveSeq numbers the template values of derived fields per scope.
	deriveSeq map[string]uint64
	// s3 holds the objects of the S3-compatible API (s3.go); pageRuns the
	// third-party page visits (pages.go).
	s3       *s3Store
	pageRuns map[string]*pageRun
	// pageAuto completes a page at once with a button (control API).
	pageAuto map[string]string
	// pageLinked are the objects and return URLs of the answers that
	// carried a page URL (pages.go), by link id and by page and reference.
	pageLinked map[string]*pageLinkRec
	// reserved are the ids of the world (entity\x00id) of entities with an
	// id format: nextID never gives them again.
	reserved map[string]bool
	// byIdentity: the session was chosen by the caller's identity
	// (docs/spec/mock.md 2.6); its id is a hash, never the identity.
	byIdentity bool
	// static are the objects created by operations without entity (static
	// mode, staticPrepare).
	static staticObjects
	// removed are the entities a remove effect deleted (entity\x00id,
	// rules v1.6): their reads by id may answer removed_status.
	removed  map[string]bool
	queue    effectQueue
	qseq     int
	forced   map[string][]*forcedEntry
	batchNxt map[string]time.Time

	journal []*journalEntry
	jsizes  []int64 // JSON size of each journal entry
	jbytes  int64
	jseq    int
	// lastUsed is the wall time (unix ns) of the last call or control
	// request (idle eviction).
	lastUsed atomic.Int64
}

// forcedRule is one forced outcome of a baseline.
type forcedRule struct {
	rule, outcome string
	times         int
}

// sessionInit is the baseline a session is created with.
type sessionInit struct {
	id           string
	seed         uint64
	customer     *string
	t0           time.Time
	createFaults FaultsConfig // faults as given at creation (or the default)
	baseFaults   FaultsConfig // faults of the baseline (a preset may bring its own)
	preset       *pack.Scenario
}

func newSession(m *Mock, in sessionInit) *session {
	s := &session{m: m, id: in.id, seed: in.seed, t0: in.t0,
		createFaults: cloneFaults(in.createFaults), initFaults: cloneFaults(in.baseFaults)}
	s.lastUsed.Store(m.cfg.Wall().UnixNano())
	s.baseCustomer = copyStr(in.customer)
	if in.preset != nil {
		s.scenario = in.preset.ID
		s.baseForced = presetForced(in.preset)
	}
	s.reset()
	return s
}

func presetForced(p *pack.Scenario) []forcedRule {
	var out []forcedRule
	for _, o := range p.Outcomes {
		n := 1
		if o.Times != nil {
			n = *o.Times
		}
		out = append(out, forcedRule{rule: o.Rule, outcome: o.Outcome, times: n})
	}
	return out
}

func faultsFromPack(f *pack.SessionFaults) FaultsConfig {
	out := FaultsConfig{Mode: f.Mode}
	for _, r := range f.Rules {
		out.Rules = append(out.Rules, FaultRule{Service: r.Service, Op: r.Op, Status: r.Status, NetError: r.NetError, LatencyMs: r.LatencyMs, P: r.P, Times: r.Times,
			Example: r.Example, Body: r.Body})
	}
	return out
}

func copyStr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// applyPreset resets the session to the baseline given by a preset, which
// becomes the new baseline (docs/spec/mock.md section 5.4).
func (s *session) applyPreset(p *pack.Scenario) {
	if p.Seed != nil {
		s.seed = *p.Seed
	}
	if c := s.m.model.presetCustomer(p); c != nil {
		s.baseCustomer = c
	}
	s.initFaults = cloneFaults(s.createFaults)
	if p.Faults != nil {
		s.initFaults = faultsFromPack(p.Faults)
	}
	s.baseForced = presetForced(p)
	s.scenario = p.ID
	s.reset()
}

// presetCustomer returns the customer a preset selects (nil when none).
func (m *model) presetCustomer(p *pack.Scenario) *string {
	switch {
	case p.Customer != "":
		c := p.Customer
		return &c
	case p.Archetype != "":
		for _, c := range m.custs { // sorted by id
			if c.Archetype != nil && *c.Archetype == p.Archetype {
				id := c.ID
				return &id
			}
		}
	}
	return nil
}

// reset restores the baseline: world state with its pending effects, clock,
// RNG streams, faults and forced outcomes; clears the journal.
func (s *session) reset() {
	s.customer = copyStr(s.baseCustomer)
	s.now = s.t0
	s.faults = cloneFaults(s.initFaults)
	s.faultUsed = make([]int, len(s.faults.Rules))
	s.rngFault = deriveRNG(s.seed, "faults")
	s.rngOutcome = deriveRNG(s.seed, "outcomes")
	s.rngRespond = deriveRNG(s.seed, "responses")
	s.responses = nil
	s.counted = nil
	s.lifted, s.attrCache, s.calls, s.lastOV = nil, nil, nil, optVal{}
	s.ents = map[string]map[string]*entityRec{}
	s.counters = map[string]int{}
	s.deriveSeq = nil
	s.s3 = nil
	s.pageRuns = nil
	s.pageAuto = nil
	s.pageLinked = nil
	s.static.reset()
	s.removed = nil
	s.queue = nil
	s.qseq = 0
	s.forced = map[string][]*forcedEntry{}
	for _, f := range s.baseForced {
		s.forceOutcome(f.rule, f.outcome, f.times)
	}
	s.batchNxt = map[string]time.Time{}
	s.journal, s.jsizes, s.jbytes = nil, nil, 0
	s.jseq = 0

	mod := s.m.model
	w := mod.pack.World
	for _, we := range w.Entities {
		rec := &entityRec{entity: we.Entity, id: we.ID, customerID: copyStr(we.CustomerID), state: cloneMap(we.State), created: s.t0, updated: s.t0}
		if ht, ok := mod.histTimes[we.Entity+"\x00"+we.ID]; ok {
			rec.created, rec.updated = ht[0], ht[1]
		}
		s.putEnt(rec)
	}
	maxN := map[string]int{}
	s.reserved = map[string]bool{}
	note := func(entity, id string) {
		ed := mod.entities[entity]
		if ed == nil {
			return
		}
		if mod.fmts[ed.def.IDDomain] != nil {
			// An id format: the world used the first ids of the sequence;
			// the session goes on after them and skips any id it meets.
			if k := entity + "\x00" + id; !s.reserved[k] {
				s.reserved[k] = true
				maxN[entity]++
			}
			return
		}
		if !strings.HasPrefix(id, ed.def.IDPrefix) {
			return
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(id, ed.def.IDPrefix)); err == nil && n > maxN[entity] {
			maxN[entity] = n
		}
	}
	for _, we := range w.Entities {
		note(we.Entity, we.ID)
	}
	for i, p := range w.Pending {
		note(p.Entity, p.ID)
		rule := mod.causalBy[p.RuleID]
		var eff *pack.Effect
		for j := range rule.r.Effects {
			if rule.r.Effects[j].ID == p.EffectID {
				eff = &rule.r.Effects[j]
			}
		}
		inst := &instance{rule: rule, outcome: p.Outcome, vars: map[string]any{}, customer: copyStr(p.CustomerID), created: map[string]string{}}
		for k, v := range p.Vars {
			inst.vars[k] = v
		}
		for k, v := range p.EffectIDs {
			inst.created[k] = v
		}
		heap.Push(&s.queue, &queued{due: s.t0.Add(time.Duration(p.DueOffsetS) * time.Second), seq: i - len(w.Pending), inst: inst, eff: eff, entityID: p.ID, world: true})
	}
	for _, name := range mod.entOrder {
		s.counters[name] = maxN[name] + 1
	}
}

func (s *session) putEnt(r *entityRec) {
	byID := s.ents[r.entity]
	if byID == nil {
		byID = map[string]*entityRec{}
		s.ents[r.entity] = byID
	}
	byID[r.id] = r
}

// nextID is the id of an entity the session creates: prefix and counter,
// or the id format of its domain (docs/spec/pack.md 4.3), which copies the
// fields it names from state.
func (s *session) nextID(entity string, state map[string]any) string {
	ed := s.m.model.entities[entity]
	if t := s.m.model.fmts[ed.def.IDDomain]; t != nil {
		for range 1000 {
			n := s.counters[entity]
			s.counters[entity] = n + 1
			id := t.ID(uint64(n), ed.def.IDDomain, idfmt.MapRef(state))
			if _, taken := s.ents[entity][id]; !taken && !s.reserved[entity+"\x00"+id] {
				return id
			}
		}
		// Every id met is taken (the format's space is used up): fall
		// back to a synthetic id rather than reuse one.
	}
	n := s.counters[entity]
	s.counters[entity] = n + 1
	return fmt.Sprintf("%s%04d", ed.def.IDPrefix, n)
}

// sortedEnts lists the entities of one type ordered by id.
func (s *session) sortedEnts(entity string) []*entityRec {
	byID := s.ents[entity]
	out := make([]*entityRec, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// ---- scenarios ----

func (s *session) forceOutcome(rule, outcome string, times int) {
	fl := s.forced[rule]
	if n := len(fl); n > 0 && fl[n-1].outcome == outcome {
		fl[n-1].remaining += times
		return
	}
	s.forced[rule] = append(fl, &forcedEntry{outcome: outcome, remaining: times})
}

type pendingScenario struct {
	Rule      string `json:"rule"`
	Outcome   string `json:"outcome"`
	Remaining int    `json:"remaining"`
}

func (s *session) pendingScenarios() []pendingScenario {
	out := []pendingScenario{}
	rules := make([]string, 0, len(s.forced))
	for r := range s.forced {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		for _, f := range s.forced[r] {
			out = append(out, pendingScenario{Rule: r, Outcome: f.outcome, Remaining: f.remaining})
		}
	}
	return out
}

// ---- rules: causes ----

type triggered struct {
	Rule    string `json:"rule"`
	Outcome string `json:"outcome"`
}

// fire evaluates the causal rules against a response the mock decided to give
// and queues the effects of the chosen outcome on the virtual clock. Effects
// whose instant is the cause's are applied at once; changed reports whether
// any effect changed the world.
func (s *session) fire(svc *service, opKey string, status int, ex *exchange) (out []triggered, changed bool) {
	for _, cr := range s.m.model.causal {
		if cr.svc != svc || cr.r.Cause.Op != opKey || !intIn(status, cr.r.Cause.When.Status) {
			continue
		}
		vars := map[string]any{}
		ok := true
		for _, name := range cr.bindKeys {
			v, found := evalRef(cr.binds[name], ex)
			if !found {
				ok = false
				break
			}
			vars[name] = v
		}
		if !ok || (cr.match != nil && !s.matchAll(cr.match, ex)) {
			continue
		}
		u := s.rngOutcome.Float64() // always drawn, so forcing a scenario never shifts the stream
		outcome := ""
		if fl := s.forced[cr.r.ID]; len(fl) > 0 {
			outcome = fl[0].outcome
			if fl[0].remaining--; fl[0].remaining <= 0 {
				s.forced[cr.r.ID] = fl[1:]
			}
		} else if cr.outWhen != nil {
			outcome = s.conditionalOutcome(cr, u, ex) // rules v1.9
		} else {
			cum := 0.0
			for _, o := range cr.r.Outcomes {
				cum += o.P
				if u < cum {
					outcome = o.Name
					break
				}
			}
			if outcome == "" {
				outcome = cr.r.Outcomes[len(cr.r.Outcomes)-1].Name
			}
		}
		inst := &instance{rule: cr, outcome: outcome, vars: vars, customer: copyStr(s.customer), created: map[string]string{}}
		s.schedule(inst)
		out = append(out, triggered{Rule: cr.r.ID, Outcome: outcome})
	}
	if len(out) > 0 {
		changed = len(s.runDue()) > 0
	}
	return out, changed
}

// schedule queues the effects of the chosen outcome. Range delays are drawn
// now, one per range effect in effects order, after the outcome draw.
func (s *session) schedule(inst *instance) {
	cr := inst.rule
	set := cr.inBranch[inst.outcome]
	delay := map[string]time.Duration{}
	for i := range cr.r.Effects {
		e := &cr.r.Effects[i]
		if !set[e.ID] {
			continue
		}
		d := e.After.Min
		if e.After.Range {
			span := int64((e.After.Max - e.After.Min) / time.Second)
			d += time.Duration(s.rngOutcome.Int64N(span+1)) * time.Second
		}
		delay[e.ID] = d
	}
	due := map[string]time.Time{}
	var dueOf func(id string) time.Time
	dueOf = func(id string) time.Time {
		if t, ok := due[id]; ok {
			return t
		}
		e := cr.effByID[id]
		base := s.now
		if e.AfterEffect != "" {
			base = dueOf(e.AfterEffect)
		}
		t := base.Add(delay[id])
		due[id] = t
		return t
	}
	for i := range cr.r.Effects {
		e := &cr.r.Effects[i]
		if !set[e.ID] {
			continue
		}
		heap.Push(&s.queue, &queued{due: dueOf(e.ID), seq: s.qseq, inst: inst, eff: e})
		s.qseq++
	}
}

func intIn(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---- clock ----

type appliedEffect struct {
	At      string `json:"at"`
	Rule    string `json:"rule"`
	Outcome string `json:"outcome,omitempty"`
	Effect  string `json:"effect"`
	Entity  string `json:"entity"`
	ID      string `json:"id"`
	// Respond names the operation ("service METHOD /path") whose answers a
	// response effect changed; Entity and ID are then empty.
	Respond string `json:"respond,omitempty"`
}

// nextDue is the instant of the earliest queued effect.
func (s *session) nextDue() (time.Time, bool) {
	if len(s.queue) == 0 {
		return time.Time{}, false
	}
	return s.queue[0].due, true
}

func (s *session) batchNext(b *batchRule) (time.Time, bool) {
	if t, ok := s.batchNxt[b.r.ID]; ok {
		return t, !t.IsZero()
	}
	t, ok := b.cron.next(s.t0)
	if !ok {
		t = time.Time{}
	}
	s.batchNxt[b.r.ID] = t
	return t, ok
}

// runDue applies every effect already due at the current instant.
func (s *session) runDue() []appliedEffect {
	applied, _, _ := s.advanceTo(s.now, 0)
	return applied
}

// advanceTo moves the clock to target applying, in time order, every queued
// effect and every batch run that falls within (now, target]. At the same
// instant: pending effects of the world, then effects queued in the session,
// then batch runs. It returns the first keep applied effects (all when keep
// is 0) and how many were applied in total: a long advance over a busy
// batch rule applies millions of them, and the answer must stay bounded.
func (s *session) advanceTo(target time.Time, keep int) ([]appliedEffect, int, error) {
	var applied []appliedEffect
	total := 0
	add := func(as ...appliedEffect) {
		total += len(as)
		if keep <= 0 {
			applied = append(applied, as...)
		} else if room := keep - len(applied); room > 0 {
			applied = append(applied, as[:min(room, len(as))]...)
		}
	}
	steps := 0
	for {
		effT, haveEff := s.nextDue()
		if haveEff && effT.After(target) {
			haveEff = false
		}
		var batT time.Time
		var batRule *batchRule
		for _, b := range s.m.model.batch {
			t, ok := s.batchNext(b)
			if !ok || t.After(target) {
				continue
			}
			if batRule == nil || t.Before(batT) {
				batT, batRule = t, b
			}
		}
		if !haveEff && batRule == nil {
			break
		}
		if steps++; steps > s.m.cfg.MaxAdvanceSteps {
			return applied, total, errTooManySteps
		}
		if haveEff && (batRule == nil || !effT.After(batT)) {
			q := heap.Pop(&s.queue).(*queued)
			if q.due.After(s.now) {
				s.now = q.due
			}
			if q.eff.TargetAll {
				add(s.applyAll(q)...) // rules v1.9
			} else if a, ok := s.applyEffect(q); ok {
				add(a)
			}
			continue
		}
		if batT.After(s.now) {
			s.now = batT
		}
		add(s.runBatch(batRule, batT)...)
		next, ok := batRule.cron.next(batT)
		if !ok {
			next = time.Time{}
		}
		s.batchNxt[batRule.r.ID] = next
	}
	if target.After(s.now) {
		s.now = target
	}
	return applied, total, nil
}

var errTooManySteps = fmt.Errorf("too many scheduled steps in one advance")

var (
	wholeVarRE    = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]{0,31})\}$`)
	wholeEffectRE = regexp.MustCompile(`^\$\{effect:([a-z][a-z0-9_-]{0,63})\}$`)
	// wholeNotRE is the opposite of a boolean of the target (rules v1.7).
	wholeNotRE = regexp.MustCompile(`^\$\{not:([A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7})\}$`)
)

// resolveValue turns a create/set value into its value for this firing:
// "${var}" and "${effect:id}" must be whole strings. ok is false when the
// reference cannot be resolved.
func resolveValue(v any, inst *instance) (any, bool) {
	str, isStr := v.(string)
	if !isStr {
		return cloneJSON(v), true
	}
	if m := wholeVarRE.FindStringSubmatch(str); m != nil {
		val, ok := inst.vars[m[1]]
		return cloneJSON(val), ok
	}
	if m := wholeEffectRE.FindStringSubmatch(str); m != nil {
		id, ok := inst.created[m[1]]
		return id, ok
	}
	return str, true
}

func (s *session) applyEffect(q *queued) (appliedEffect, bool) {
	e := q.eff
	inst := q.inst
	rid := inst.rule.r.ID
	mk := func(id string) appliedEffect {
		return appliedEffect{At: fmtTime(s.now), Rule: rid, Outcome: inst.outcome, Effect: e.ID, Entity: e.Entity, ID: id}
	}
	if e.Respond != nil {
		if e.Respond.Until {
			return s.liftUntil(q), true
		}
		if e.Respond.Limit != nil {
			return s.countCall(q), true
		}
		return s.installResponse(q), true
	}
	if e.TargetKey != nil {
		// rules v1.8: the record of a keyed entity.
		return s.applyKeyed(q)
	}
	if e.Create != nil {
		ed := s.m.model.entities[e.Entity]
		state := map[string]any{}
		vals := derive.Resolve(e.Create, state, s.deriveEnv(inst, e), func(v any) (any, bool) { return resolveValue(v, inst) }, setDotted)
		for _, k := range sortedKeys(vals) {
			setDotted(state, k, vals[k])
		}
		id := q.entityID
		if id == "" {
			id = s.nextID(e.Entity, state)
		}
		state[ed.def.IDField] = id
		s.putEnt(&entityRec{entity: e.Entity, id: id, customerID: copyStr(inst.customer), state: state, created: s.now, updated: s.now})
		inst.created[e.ID] = id
		return mk(id), true
	}
	id := q.entityID
	switch {
	case id != "":
	case e.TargetID != "":
		if v, ok := inst.vars[wholeVarRE.FindStringSubmatch(e.TargetID)[1]]; ok {
			id, _ = v.(string)
		}
	default:
		id = inst.created[e.Target]
	}
	rec := s.ents[e.Entity][id]
	if id == "" || rec == nil {
		return appliedEffect{}, false
	}
	return s.applyOn(q, rec)
}

// applyOn applies a target, target_id or target_key effect to its record.
func (s *session) applyOn(q *queued, rec *entityRec) (appliedEffect, bool) {
	e, inst, id := q.eff, q.inst, rec.id
	mk := func(id string) appliedEffect {
		return appliedEffect{At: fmtTime(s.now), Rule: inst.rule.r.ID, Outcome: inst.outcome, Effect: e.ID, Entity: e.Entity, ID: id}
	}
	if e.Where != nil && !s.matchWhere(rec, e.Where) {
		// rules v1.7: the entity left the state the effect starts from.
		return appliedEffect{}, false
	}
	inst.created[e.ID] = id
	if e.Remove {
		if !s.removeEntity(e.Entity, id) {
			return appliedEffect{}, false
		}
		return mk(id), true
	}
	changed := false
	// ${not:field} (rules v1.7) toggles the current boolean; derived values
	// (rules v1.10) are computed after the literal ones.
	lit := func(v any) (any, bool) {
		if str, isStr := v.(string); isStr {
			if m := wholeNotRE.FindStringSubmatch(str); m != nil {
				cur, _ := getDotted(rec.state, m[1])
				b, isBool := cur.(bool)
				return !b, isBool
			}
		}
		return resolveValue(v, inst)
	}
	vals := derive.Resolve(e.Set, rec.state, s.deriveEnv(inst, e), lit, setDotted)
	for _, k := range sortedKeys(vals) {
		nv := vals[k]
		if cur, ok := getDotted(rec.state, k); ok && jsonEqual(cur, nv) {
			continue
		}
		setDotted(rec.state, k, nv)
		changed = true
	}
	if !changed {
		return appliedEffect{}, false
	}
	rec.updated = s.now
	return mk(id), true
}

// deriveEnv is what the derived values of an effect read (rules 1.10, 3.15):
// the cause's variables, the ids of the earlier effects, the virtual clock
// and a counter per rule, effect and field for templates.
func (s *session) deriveEnv(inst *instance, e *pack.Effect) derive.Env {
	return derive.Env{
		Var:    func(n string) (any, bool) { v, ok := inst.vars[n]; return cloneJSON(v), ok },
		Effect: func(id string) (string, bool) { v, ok := inst.created[id]; return v, ok },
		Now:    s.now,
		Scope:  "derive/" + inst.rule.r.ID + "/" + e.ID,
		Seq: func(scope string) uint64 {
			if s.deriveSeq == nil {
				s.deriveSeq = map[string]uint64{}
			}
			s.deriveSeq[scope]++
			return s.deriveSeq[scope]
		},
	}
}

func (s *session) matchWhere(rec *entityRec, where map[string]any) bool {
	for k, want := range where {
		got, ok := getDotted(rec.state, k)
		if !ok || !jsonEqual(got, want) {
			return false
		}
	}
	return true
}

// runBatch applies a batch rule at instant at: round(fraction x eligible)
// entities, picked by a seeded shuffle of the eligible ones in id order.
func (s *session) runBatch(b *batchRule, at time.Time) []appliedEffect {
	var elig []*entityRec
	for _, rec := range s.sortedEnts(b.r.Entity) {
		if s.matchWhere(rec, b.r.Where) {
			elig = append(elig, rec)
		}
	}
	n := int(math.Round(b.r.Fraction * float64(len(elig))))
	if n > len(elig) {
		n = len(elig)
	}
	if n == 0 {
		return nil
	}
	rng := deriveRNG(s.seed, "batch/"+b.r.ID+"/"+fmtTime(at))
	perm := rng.Perm(len(elig))[:n]
	sort.Ints(perm)
	var out []appliedEffect
	for _, i := range perm {
		rec := elig[i]
		for _, k := range sortedKeys(b.r.Set) {
			setDotted(rec.state, k, cloneJSON(b.r.Set[k]))
		}
		rec.updated = at
		out = append(out, appliedEffect{At: fmtTime(at), Rule: b.r.ID, Effect: "batch", Entity: rec.entity, ID: rec.id})
	}
	return out
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- entity listing (control API) ----

type pendingEffect struct {
	Rule    string `json:"rule"`
	Outcome string `json:"outcome"`
	Effect  string `json:"effect"`
	Due     string `json:"due"`
	Source  string `json:"source"`
}

type entityView struct {
	Entity         string          `json:"entity"`
	ID             string          `json:"id"`
	CustomerID     *string         `json:"customer_id"`
	State          map[string]any  `json:"state"`
	PendingEffects []pendingEffect `json:"pending_effects,omitempty"`
}

// pendingEntityID is the entity a queued effect will change, when known.
func (q *queued) pendingEntityID() string {
	switch {
	case q.entityID != "":
		return q.entityID
	case q.eff.TargetID != "":
		if v, ok := q.inst.vars[wholeVarRE.FindStringSubmatch(q.eff.TargetID)[1]]; ok {
			id, _ := v.(string)
			return id
		}
	case q.eff.Target != "":
		return q.inst.created[q.eff.Target]
	}
	return ""
}

func (s *session) listEntities(entity, id string) []entityView {
	names := make([]string, 0, len(s.ents))
	for n := range s.ents {
		if entity == "" || n == entity {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	pend := map[string][]pendingEffect{}
	qs := append(effectQueue(nil), s.queue...)
	sort.Slice(qs, func(i, j int) bool { return qs[i].Less2(qs[j]) })
	for _, q := range qs {
		if q.eff.Respond != nil {
			continue
		}
		eid := q.pendingEntityID()
		if eid == "" {
			continue
		}
		src := "session"
		if q.world {
			src = "world"
		}
		k := q.eff.Entity + "\x00" + eid
		pend[k] = append(pend[k], pendingEffect{Rule: q.inst.rule.r.ID, Outcome: q.inst.outcome, Effect: q.eff.ID, Due: fmtTime(q.due), Source: src})
	}
	out := []entityView{}
	for _, n := range names {
		for _, rec := range s.sortedEnts(n) {
			if id != "" && rec.id != id {
				continue
			}
			out = append(out, entityView{Entity: n, ID: rec.id, CustomerID: rec.customerID, State: cloneMap(rec.state), PendingEffects: pend[n+"\x00"+rec.id]})
		}
	}
	return out
}

func (q *queued) Less2(o *queued) bool {
	if !q.due.Equal(o.due) {
		return q.due.Before(o.due)
	}
	return q.seq < o.seq
}
