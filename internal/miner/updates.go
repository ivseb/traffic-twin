package miner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Updates (rules v1.7, C2 and C11). Most writes of a real application do
// not create anything: they change an object that already exists (a
// contract suspended, a consent given, a default address chosen, a
// notification read). A write is the cause of an update rule of entity E
// when its request cites the id of an object of E (path, query, body
// member, GraphQL variable) and the object's values, read before and after
// the write, change in a way the write explains:
//
//   - before is the last observation of the object before the write, after
//     the first one after it (outside the write's trace, before the next
//     call of the same operation or the next write that cites the object,
//     within the decision horizon), by any operation or service;
//   - a field of the object (a code, a boolean, a number or its bucket, an
//     id) takes a value the write explains, judged over the writes after
//     which it could change (its value before was another): always the
//     same value (set a literal), the value of a clear member of the
//     request (copy it: ${bind}), the id the request carries in a member
//     (token equality proves value equality without seeing the values:
//     copy it), or for a boolean the opposite of its value before (a
//     toggle: ${not:field});
//   - the change is seen for at least KMin subjects, in at least MinShare of
//     the writes that could show it, with a Wilson lower bound of at least
//     MinBirthShare (the confidence of the rule); a literal or a toggle must
//     also be rare without the write (the objects' consecutive observations
//     with no such write in between change that way at most half as often),
//     so a lifecycle that moves on its own is never taken for an update;
//   - a change first seen after a read that still showed the old value
//     (caches, eventual consistency), for at least KMin subjects, is delayed:
//     a figurative after from its order of magnitude (decision D1).
//
// A read is a cause too (C11): a GET after which the object shows a changed
// field (read/unread) is the cause of that change. Transitions of the
// state field explained by a write are no longer spontaneous outcomes of
// the creation: mineCausal leaves them out and guards the remaining steps
// of the lifecycle with where (a later spontaneous step must not undo the
// state the write set).

// upObs is one observation of an object: a record of an answer, read in
// place (16 bytes each: a window holds millions of them).
type upObs struct {
	rec *record
	ev  int32
	own int32 // index of the object's id among rec.ids
}

func (o *upObs) start(l *Log) time.Time { return l.evs[o.ev].ts }  // start of the exchange
func (o *upObs) at(l *Log) time.Time    { return l.evs[o.ev].end } // when the answer showed it
func (o *upObs) rootOf(l *Log) int32    { return l.evs[o.ev].root }
func (o *upObs) locOf() int32 {
	if o.own < 0 {
		return -1 // a keyed record (rules v1.8): no id of its own
	}
	return o.rec.ids[o.own].loc
}

// val returns a field of the object: a clear value, a number bucket (Kind
// 'q') or an id (Kind 't', S the token).
func (o *upObs) val(l *Log, name string) (Value, bool) {
	if v, ok := o.rec.attr(name); ok {
		return v, true
	}
	if v, ok := o.rec.bucket(name); ok {
		return v, true
	}
	for k, f := range o.rec.ids {
		if f.name == name && k != int(o.own) {
			return Value{Kind: 't', S: l.toks[f.tok]}, true
		}
	}
	return Value{}, false
}

// each calls fn for every field of the object (see val).
func (o *upObs) each(l *Log, fn func(name string, v Value)) {
	for _, a := range o.rec.attrs {
		fn(a.name, a.val)
	}
	for _, a := range o.rec.times {
		if a.val.Kind == 'q' {
			fn(a.name, a.val)
		}
	}
	for k, f := range o.rec.ids {
		if k != int(o.own) {
			fn(f.name, Value{Kind: 't', S: l.toks[f.tok]})
		}
	}
}

// upInst is one call that cites an object of the entity in its request.
type upInst struct {
	ev, op, obj, loc int32
	subj             int32
	// klocs are the request locations of the key fields of a keyed record
	// with a key of several fields (rules v1.9), in the key's order.
	klocs []int32
}

// upItem is one judged change of a field: its value before and after one
// call, and when the new value was first seen.
type upItem struct {
	inst      int
	b, a      Value
	stale     bool          // a read after the call still showed b
	delay     time.Duration // estimated, for stale items only
	afterLoc  int32
	afterSeen bool
	// span is the time between the observation before and the one after
	// that gave a: the control compares pairs at least as long.
	span time.Duration
}

// upField is an accepted change of one field.
type upField struct {
	field      string
	value      any
	bind       string
	ref        Ref
	kind       string // literal, copy, id, toggle
	consistent int
	judged     int
	delayed    bool
	delays     []time.Duration
	state      string // the literal state set, when the field is the state field
}

// mineUpdates mines the update rules of the entities with an id (see
// above) and marks the state transitions they explain (m.caused).
func (m *miner) mineUpdates() []*Mined {
	var out []*Mined
	for i, e := range m.ents {
		if e.keyed != nil {
			out = append(out, m.mineKeyedUpdates(i)...) // rules v1.8
			continue
		}
		insts, cites := m.updateCauses(i)
		if len(insts) == 0 {
			continue
		}
		obs := m.updateObs(i)
		if len(obs) == 0 {
			continue
		}
		byOp := map[int32][]int{}
		for k, in := range insts {
			byOp[in.op] = append(byOp[in.op], k)
		}
		ops := make([]int32, 0, len(byOp))
		for op := range byOp {
			ops = append(ops, op)
		}
		sort.Slice(ops, func(a, b int) bool { return ops[a] < ops[b] })
		for _, op := range ops {
			if mm := m.updateRule(i, op, insts, byOp[op], obs, cites, nil); mm != nil {
				out = append(out, mm)
			}
		}
	}
	return out
}

// updateObs collects the observations of the objects of entity i, in time
// order.
func (m *miner) updateObs(i int) map[int32][]upObs {
	l := m.l
	out := map[int32][]upObs{}
	for ei := range l.evs {
		ev := &l.evs[ei]
		if !ev.ok() {
			continue
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side != sideResp {
				continue
			}
			ent, own, ok := m.recEntity(r)
			if !ok || ent != i {
				continue
			}
			oi := 0
			for k, f := range r.ids {
				if f.name == own.name {
					oi = k
				}
			}
			out[own.tok] = append(out[own.tok], upObs{rec: r, ev: int32(ei), own: int32(oi)})
		}
	}
	for o := range out {
		os := out[o]
		sort.SliceStable(os, func(a, b int) bool { return os[a].at(l).Before(os[b].at(l)) })
	}
	return out
}

// citation is a call that cites an object in its request.
type citation struct {
	ev, op int32
	write  bool
}

// updateCauses finds the successful calls (writes and reads, never the
// entity's own creation) that cite an object of entity i in their request,
// and per object every call citing it, in event order.
func (m *miner) updateCauses(i int) ([]upInst, map[int32][]citation) {
	l, e := m.l, m.ents[i]
	var insts []upInst
	cites := map[int32][]citation{}
	for wi := range l.evs {
		w := &l.evs[wi]
		op := &l.ops[w.op]
		if !w.ok() || (!op.write && !op.read) {
			continue
		}
		var tok, tloc int32 = -1, -1
		for _, t := range w.toks {
			lc := &l.locs[t.loc]
			if lc.side != sideReq || !lc.refOK || (lc.ref.Path != "" && !keyRefOK(lc.ref)) || m.entityOf(t.tok) != i {
				continue
			}
			if tok < 0 || (lc.ref.From == "req.path" && l.locs[tloc].ref.From != "req.path") {
				tok, tloc = t.tok, t.loc
			}
		}
		if tok < 0 {
			continue
		}
		cites[tok] = append(cites[tok], citation{int32(wi), w.op, op.write})
		if w.op == e.creatorOp {
			continue
		}
		insts = append(insts, upInst{ev: int32(wi), op: w.op, obj: tok, loc: tloc, subj: l.subjectOf(int32(wi))})
	}
	return insts, cites
}

// valKey is a comparable key of a value.
func valKey(v Value) string { return string(v.Kind) + v.S }

// valueMatch reports whether value a (of the object) is the request value
// rv: equal, or a number inside the bucket a.
func valueMatch(a, rv Value) bool {
	if a == rv {
		return true
	}
	if a.Kind == 'q' && rv.Kind == 'n' {
		return inBucket(rv.S, a.S)
	}
	return false
}

// inBucket reports whether number n lies in bucket tok (num:a-b, num:<b,
// num:>=b).
func inBucket(n, tok string) bool {
	x, err := strconv.ParseFloat(n, 64)
	if err != nil {
		return false
	}
	s := strings.TrimPrefix(tok, "num:")
	parse := func(p string) (float64, bool) {
		f, err := strconv.ParseFloat(p, 64)
		return f, err == nil
	}
	switch {
	case strings.HasPrefix(s, "<"):
		b, ok := parse(s[1:])
		return ok && x < b
	case strings.HasPrefix(s, ">="):
		b, ok := parse(s[2:])
		return ok && x >= b
	}
	if len(s) < 3 {
		return false
	}
	k := strings.Index(s[1:], "-")
	if k < 0 {
		return false
	}
	lo, ok1 := parse(s[:k+1])
	hi, ok2 := parse(s[k+2:])
	return ok1 && ok2 && x >= lo && x < hi
}

// literalOf is the value a set writes for an observed value.
func literalOf(v Value) (any, bool) {
	switch v.Kind {
	case 's', 'b', 'n', 'z':
		return v.Any(), true
	case 'q':
		return bucketValue(v.S)
	}
	return nil, false // an id is never a literal
}

// updateRule builds the update rule of operation op on entity i, nil when
// nothing changes the way the calls explain.
func (m *miner) updateRule(i int, op int32, all []upInst, idx []int, obs map[int32][]upObs, cites map[int32][]citation, kt *keyTarget) *Mined {
	l, e, cfg := m.l, m.ents[i], m.cfg
	o := l.ops[op]
	H := cfg.MinCoverage()
	sig := "causal|" + o.service + "|" + o.op + "|" + e.sig + "|update"
	insts := make([]upInst, len(idx))
	for k, x := range idx {
		insts[k] = all[x]
	}
	// Per field, the judged items.
	items := map[string][]upItem{}
	judgedInst := map[int]bool{}
	for k, in := range insts {
		w := &l.evs[in.ev]
		os := obs[in.obj]
		// Before: the last observation before the call, outside its trace.
		n := sort.Search(len(os), func(x int) bool { return os[x].at(l).After(w.ts) })
		bi := -1
		for x := n - 1; x >= 0; x-- {
			if os[x].rootOf(l) != w.root {
				bi = x
				break
			}
		}
		if bi < 0 {
			continue
		}
		// The end of the window: the next call of the operation or the next
		// write citing the object, at most the horizon.
		end := w.ts.Add(H)
		cs := cites[in.obj]
		c := sort.Search(len(cs), func(x int) bool { return cs[x].ev > in.ev })
		for ; c < len(cs); c++ {
			if cs[c].op == op || cs[c].write {
				if t := l.evs[cs[c].ev].ts; t.Before(end) {
					end = t
				}
				break
			}
		}
		var after []int
		for x := sort.Search(len(os), func(x int) bool { return !os[x].start(l).Before(w.end) }); x < len(os) && os[x].start(l).Before(end); x++ {
			if os[x].rootOf(l) != w.root {
				after = append(after, x)
			}
		}
		if len(after) == 0 {
			continue
		}
		before := &os[bi]
		bt := before.at(l)
		before.each(l, func(name string, bv Value) {
			if !reFieldPath.MatchString(name) {
				return
			}
			it := upItem{inst: k, b: bv}
			var lastOld time.Time
			for _, x := range after {
				v, ok := os[x].val(l, name)
				if !ok {
					continue
				}
				xs := os[x].start(l)
				if !it.afterSeen {
					it.afterSeen, it.a, it.afterLoc, it.span = true, v, os[x].locOf(), xs.Sub(bt)
					if v != bv {
						break
					}
					lastOld = xs
					continue
				}
				if v != bv {
					it.a, it.afterLoc, it.stale, it.span = v, os[x].locOf(), true, xs.Sub(bt)
					it.delay = mid(lastOld, xs).Sub(w.ts)
					break
				}
				lastOld = xs
			}
			if it.afterSeen {
				items[name] = append(items[name], it)
				judgedInst[k] = true
			}
		})
	}
	subjects := map[int32]bool{}
	statuses := map[int]int{}
	for _, in := range insts {
		if in.subj >= 0 {
			subjects[in.subj] = true
		}
		statuses[l.evs[in.ev].status]++
	}
	var fields []*upField
	var best *upField // the strongest rejected candidate, for the diagnostic
	bestWhy := ""
	for _, f := range sortedKeys(items) {
		fe, why := m.updateField(i, f, items[f], insts, obs, op)
		if fe != nil {
			fields = append(fields, fe)
		} else if why != "" && (best == nil || len(items[f]) > best.judged) {
			best, bestWhy = &upField{field: f, judged: len(items[f])}, why
		}
	}
	d := RuleDiag{Signature: sig, Kind: KindCausal, Service: o.service, Op: o.op, Entity: e.def.Name, Causes: len(insts), Subjects: len(subjects)}
	d.Values, d.ClearFields = valuesOf(e)
	if len(fields) == 0 {
		if best != nil && o.write {
			d.Decision, d.Code, d.Reason = DecisionNotMined, WhyNoEffect, bestWhy
			if strings.HasPrefix(bestWhy, "only") {
				d.Code = WhyFewSubjects
			}
			m.rdiag = append(m.rdiag, d)
		}
		return nil
	}
	if len(subjects) < cfg.KMin {
		return nil
	}
	// The target: the most frequent request location of the cited id.
	locN := map[int32]int{}
	for _, in := range insts {
		locN[in.loc]++
	}
	var tloc int32 = -1
	for lc, n := range locN {
		if tloc < 0 || n > locN[tloc] || (n == locN[tloc] && lc < tloc) {
			tloc = lc
		}
	}
	bind := bindName(e.def.Name)
	binds := map[string]Ref{}
	if kt != nil && len(kt.fields) > 0 {
		bind = freeBind(kt.fields[0], nil)
	}
	if kt == nil || len(kt.fields) > 0 {
		if tloc < 0 {
			return nil
		}
		binds[bind] = l.locs[tloc].ref
	}
	extra := keyBinds(l, kt, insts, binds) // rules v1.9: keys of several fields
	// target is the object of the cause: its id, or (rules v1.8) the key of
	// a keyed record.
	target := func(ef Effect) Effect {
		if kt == nil {
			ef.TargetID = "${" + bind + "}"
			return ef
		}
		tk := KeyTarget{}
		if len(kt.fields) > 0 {
			tk[kt.fields[0]] = "${" + bind + "}"
		}
		for f, b := range extra {
			tk[f] = "${" + b + "}"
		}
		ef.TargetKey = &tk
		return ef
	}
	rule := &CausalRule{Kind: KindCausal, Status: StatusDraft,
		Cause: Cause{Service: o.service, Op: o.op, Bind: binds}}
	for _, s := range sortedInts(statuses) {
		if statuses[s] >= cfg.KMin {
			rule.Cause.When.Status = append(rule.Cause.When.Status, s)
		}
	}
	if len(rule.Cause.When.Status) == 0 {
		return nil
	}
	now, later := map[string]any{}, map[string]any{}
	var delays []time.Duration
	conf := 1.0
	var names []string
	for _, fe := range fields {
		v := fe.value
		if fe.bind != "" {
			name := ""
			for k, r := range rule.Cause.Bind {
				if r == fe.ref {
					name = k
				}
			}
			if name == "" {
				name = freeBind(fe.bind, rule.Cause.Bind)
				rule.Cause.Bind[name] = fe.ref
			}
			v = "${" + name + "}"
		}
		if fe.delayed {
			later[fe.field] = v
			delays = append(delays, fe.delays...)
		} else {
			now[fe.field] = v
		}
		if c := wilsonLow(fe.consistent, fe.judged); c < conf {
			conf = c
		}
		names = append(names, fe.field)
	}
	mags := map[string]string{}
	var ids []string
	if len(now) > 0 {
		id := slug(e.def.Name) + "-updated"
		rule.Effects = append(rule.Effects, target(Effect{ID: id, Entity: e.def.Name, Set: now, After: Delay{Single: "0s"}}))
		mags[id] = MagSeconds
		ids = append(ids, id)
	}
	if len(later) > 0 {
		id := slug(e.def.Name) + "-updated-later"
		sort.Slice(delays, func(a, b int) bool { return delays[a] < delays[b] })
		mag := magnitude(delays[len(delays)/2])
		rule.Effects = append(rule.Effects, target(Effect{ID: id, Entity: e.def.Name, Set: later, After: delayFor(mag)}))
		mags[id] = mag
		ids = append(ids, id)
	}
	// rules v1.8 (C10): a value the call set that comes back on its own
	// after a while (a suspension, a lock, a validity window).
	for _, fe := range fields {
		rv := m.revertOf(fe, insts, obs, cites, op)
		if rv == nil {
			continue
		}
		from := slug(e.def.Name) + "-updated"
		if fe.delayed {
			from += "-later"
		}
		id := slug(e.def.Name) + "-" + slug(fe.field) + "-reverted"
		if !reIdent.MatchString(id) {
			continue
		}
		rule.Effects = append(rule.Effects, target(Effect{ID: id, Entity: e.def.Name, Set: map[string]any{fe.field: rv.value},
			Where: map[string]any{fe.field: fe.value}, AfterEffect: from, After: delayFor(rv.mag)}))
		mags[id] = rv.mag
		ids = append(ids, id)
	}
	for _, id := range ids {
		if !reIdent.MatchString(id) {
			return nil
		}
	}
	rule.Outcomes = []Outcome{{Name: "always", P: 1, Effects: ids}}
	km := len(judgedInst)
	rule.Evidence.Counts = CausalCounts{Causes: len(insts), DistinctSubjects: len(subjects), Outcomes: map[string]int{"always": len(insts)}, KeyMatches: &km}
	// Link key: the cited id in the request, the object in the answers
	// that showed the change.
	toN := map[int32]int{}
	for _, f := range sortedKeys(items) {
		for _, it := range items[f] {
			toN[it.afterLoc]++
		}
	}
	var to int32 = -1
	for lc, n := range toN {
		if to < 0 || n > toN[to] || (n == toN[to] && lc < to) {
			to = lc
		}
	}
	if to >= 0 && tloc >= 0 && kt == nil {
		rule.Evidence.Keys = dedupeKeys([]KeyRef{{Domain: e.dom, From: l.keyEnd(tloc), To: l.keyEnd(to), Matches: km}}, cfg.KMin)
	}
	rule.Evidence.Hints = &CausalHints{Magnitude: mags}
	verb := "aggiorna"
	if o.read {
		verb = "letta, aggiorna"
	}
	rule.Title = fmt.Sprintf("%s su %s %s %s: %s", o.op, o.service, verb, e.def.Name, strings.Join(names, ", "))
	if len([]rune(rule.Title)) > 200 {
		rule.Title = string([]rune(rule.Title)[:200])
	}
	// The transitions of the state field this write explains are not
	// spontaneous any more.
	for _, fe := range fields {
		if fe.state != "" {
			m.attribute(i, fe.state, insts)
		}
	}
	d.Decision, d.Code, d.Reason, d.Confidence = DecisionProposed, WhyMined, "mined", conf
	m.rdiag = append(m.rdiag, d)
	return &Mined{Rule: Rule{Causal: rule}, Signature: sig, Structure: causalStructure(rule), Confidence: conf}
}

// freeBind returns a bind name from base that rule binds do not use.
func freeBind(base string, used map[string]Ref) string {
	var b strings.Builder
	for _, c := range strings.ToLower(base) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9' && b.Len() > 0:
			b.WriteRune(c)
		case b.Len() > 0:
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		name = "value"
	}
	if len(name) > 28 {
		name = name[:28]
	}
	if _, dup := used[name]; !dup {
		return name
	}
	for k := 2; ; k++ {
		n := name + "_" + itoa(k)
		if _, dup := used[n]; !dup {
			return n
		}
	}
}

// accepted reports whether consistent of judged changes, seen for subj
// subjects, are enough for an update.
func (m *miner) updateOK(consistent, judged, subj int) (bool, string) {
	cfg := m.cfg
	switch {
	case judged == 0 || consistent == 0:
		return false, ""
	case subj < cfg.KMin:
		return false, fmt.Sprintf("only %d distinct subjects saw the change, at least %d needed", subj, cfg.KMin)
	case float64(consistent) < cfg.MinShare*float64(judged):
		return false, fmt.Sprintf("the change follows only %d of %d calls that could show it", consistent, judged)
	case wilsonLow(consistent, judged) < cfg.MinBirthShare:
		return false, fmt.Sprintf("the change follows %d of %d calls: lower bound %.2f < %.2f", consistent, judged, wilsonLow(consistent, judged), cfg.MinBirthShare)
	}
	return true, ""
}

// updateField classifies the changes of one field after the calls of op
// (see the top of the file): nil and a reason when none explains them.
func (m *miner) updateField(i int, f string, items []upItem, insts []upInst, obs map[int32][]upObs, op int32) (*upField, string) {
	l, cfg := m.l, m.cfg
	changedSubj := func(sel func(it *upItem) bool) int {
		s := map[int32]bool{}
		for k := range items {
			it := &items[k]
			if it.a != it.b && sel(it) {
				s[insts[it.inst].subj] = true
			}
		}
		delete(s, -1)
		return len(s)
	}
	anyChange := false
	for _, it := range items {
		anyChange = anyChange || it.a != it.b
	}
	if !anyChange {
		return nil, ""
	}
	present := func(n int) bool { return float64(n) >= cfg.MinShare*float64(len(items)) }
	finish := func(fe *upField, sel func(it *upItem) bool) *upField {
		stale, changed := 0, 0
		staleSubj := map[int32]bool{}
		for k := range items {
			it := &items[k]
			if it.a == it.b || !sel(it) {
				continue
			}
			changed++
			if it.stale {
				stale++
				fe.delays = append(fe.delays, it.delay)
				if s := insts[it.inst].subj; s >= 0 {
					staleSubj[s] = true
				}
			}
		}
		if len(staleSubj) >= cfg.KMin && float64(stale) >= (1-cfg.MinShare)*float64(changed) {
			fe.delayed = true
		} else {
			fe.delays = nil
		}
		return fe
	}
	why := ""
	note := func(w string) {
		if why == "" {
			why = w
		}
	}
	// 1. A clear member of the request.
	type cand struct {
		key                string
		ref                Ref
		consistent, judged int
		values             map[string]bool
		named              bool
	}
	var copies []*cand
	byKey := map[string]*cand{}
	presentN := map[string]int{}
	for _, it := range items {
		for _, rv := range l.reqVals[insts[it.inst].ev] {
			presentN[rv.name]++
		}
	}
	for _, it := range items {
		for _, rv := range l.reqVals[insts[it.inst].ev] {
			if !present(presentN[rv.name]) {
				continue
			}
			c := byKey[rv.name]
			if c == nil {
				c = &cand{key: rv.name, values: map[string]bool{}}
				if q, ok := strings.CutPrefix(rv.name, "?"); ok {
					c.ref = Ref{From: "req.query", Name: q}
				} else {
					c.ref = Ref{From: "req.body", Path: rv.name}
				}
				ps := splitTTPath(rv.name)
				last := strings.TrimPrefix(rv.name, "?")
				if len(ps) > 0 && !strings.HasPrefix(rv.name, "?") {
					last = ps[len(ps)-1]
				}
				c.named = strings.EqualFold(last, f)
				byKey[rv.name] = c
				copies = append(copies, c)
			}
			if valueMatch(it.b, rv.val) {
				continue // it could not change
			}
			c.judged++
			if valueMatch(it.a, rv.val) {
				c.consistent++
				c.values[valKey(it.a)] = true
			}
		}
	}
	sort.Slice(copies, func(a, b int) bool {
		ca, cb := copies[a], copies[b]
		if ca.consistent != cb.consistent {
			return ca.consistent > cb.consistent
		}
		if ca.named != cb.named {
			return ca.named
		}
		return ca.key < cb.key
	})
	for _, c := range copies {
		if !c.named && len(c.values) < 2 {
			continue
		}
		key := c.key
		sel := func(it *upItem) bool {
			for _, rv := range l.reqVals[insts[it.inst].ev] {
				if rv.name == key {
					return valueMatch(it.a, rv.val)
				}
			}
			return false
		}
		ok, w := m.updateOK(c.consistent, c.judged, changedSubj(sel))
		if !ok {
			note(w)
			continue
		}
		name := key
		if ps := splitTTPath(key); len(ps) > 0 && !strings.HasPrefix(key, "?") {
			name = ps[len(ps)-1]
		}
		return finish(&upField{field: f, kind: "copy", bind: strings.TrimPrefix(name, "?"), ref: c.ref, consistent: c.consistent, judged: c.judged}, sel), ""
	}
	// 2. An id the request carries: equal tokens are equal values.
	isTok := false
	for _, it := range items {
		isTok = isTok || it.a.Kind == 't'
	}
	if isTok {
		type tcand struct {
			loc                int32
			consistent, judged int
		}
		tc := map[int32]*tcand{}
		locN := map[int32]int{}
		for _, it := range items {
			seen := map[int32]bool{}
			for _, t := range l.evs[insts[it.inst].ev].toks {
				lc := &l.locs[t.loc]
				if lc.side != sideReq || !lc.refOK || (lc.ref.Path != "" && !keyRefOK(lc.ref)) || seen[t.loc] {
					continue
				}
				seen[t.loc] = true
				locN[t.loc]++
			}
		}
		for _, it := range items {
			seen := map[int32]bool{}
			for _, t := range l.evs[insts[it.inst].ev].toks {
				lc := &l.locs[t.loc]
				if lc.side != sideReq || seen[t.loc] || !present(locN[t.loc]) {
					continue
				}
				seen[t.loc] = true
				s := l.toks[t.tok]
				if it.b.Kind == 't' && it.b.S == s {
					continue
				}
				c := tc[t.loc]
				if c == nil {
					c = &tcand{loc: t.loc}
					tc[t.loc] = c
				}
				c.judged++
				if it.a.Kind == 't' && it.a.S == s {
					c.consistent++
				}
			}
		}
		var bestLoc int32 = -1
		for lc, c := range tc {
			if bestLoc < 0 || c.consistent > tc[bestLoc].consistent || (c.consistent == tc[bestLoc].consistent && lc < bestLoc) {
				bestLoc = lc
			}
		}
		if bestLoc >= 0 {
			c := tc[bestLoc]
			sel := func(it *upItem) bool {
				for _, t := range l.evs[insts[it.inst].ev].toks {
					if t.loc == bestLoc {
						return it.a.Kind == 't' && it.a.S == l.toks[t.tok]
					}
				}
				return false
			}
			ok, w := m.updateOK(c.consistent, c.judged, changedSubj(sel))
			if ok {
				ref := l.locs[bestLoc].ref
				return finish(&upField{field: f, kind: "id", bind: selectorField(ref), ref: ref, consistent: c.consistent, judged: c.judged}, sel), ""
			}
			note(w)
		}
		return nil, why // an id is never a literal
	}
	// 3. A toggle: a boolean that takes the opposite of its value.
	var tj, tcn, up, down int
	for _, it := range items {
		if it.b.Kind != 'b' || it.a.Kind != 'b' {
			continue
		}
		tj++
		if it.a != it.b {
			tcn++
			if it.a.S == "true" {
				up++
			} else {
				down++
			}
		}
	}
	if up > 0 && down > 0 {
		sel := func(it *upItem) bool { return it.b.Kind == 'b' && it.a.Kind == 'b' }
		ok, w := m.updateOK(tcn, tj, changedSubj(sel))
		if ok && m.updateControl(f, obs, insts, op, float64(tcn)/float64(tj), medianSpan(items, sel), func(p, n Value) (bool, bool) {
			return p.Kind == 'b' && n.Kind == 'b', p.Kind == 'b' && n.Kind == 'b' && p != n
		}) {
			return finish(&upField{field: f, kind: "toggle", value: "${not:" + f + "}", consistent: tcn, judged: tj}, sel), ""
		}
		note(w)
	}
	// 4. A literal: always the same value after the call.
	cnt := map[string]int{}
	vals := map[string]Value{}
	for _, it := range items {
		k := valKey(it.a)
		cnt[k]++
		vals[k] = it.a
	}
	top := argmax(cnt)
	c := vals[top]
	lit, ok := literalOf(c)
	if !ok {
		return nil, why
	}
	var cj, cc int
	for _, it := range items {
		if it.b == c {
			continue // already that value
		}
		cj++
		if it.a == c {
			cc++
		}
	}
	sel := func(it *upItem) bool { return it.a == c }
	okL, w := m.updateOK(cc, cj, changedSubj(sel))
	if !okL {
		note(w)
		return nil, why
	}
	span := medianSpan(items, func(it *upItem) bool { return it.b != c })
	if !m.updateControl(f, obs, insts, op, float64(cc)/float64(cj), span, func(p, n Value) (bool, bool) { return p != c, p != c && n == c }) {
		note(fmt.Sprintf("%s takes %v without the call as well: not caused by it", f, lit))
		return nil, why
	}
	fe := &upField{field: f, kind: "literal", value: lit, consistent: cc, judged: cj}
	if e := m.ents[i]; f == e.stateField && e.literalState() && (c.Kind == e.stateKind || (e.stateKind == 0 && c.Kind == 's')) {
		fe.state = c.S
	}
	return finish(fe, sel), ""
}

// medianSpan is the median span of the items sel selects.
func medianSpan(items []upItem, sel func(it *upItem) bool) time.Duration {
	var ds []time.Duration
	for k := range items {
		if sel(&items[k]) {
			ds = append(ds, items[k].span)
		}
	}
	if len(ds) == 0 {
		return 0
	}
	sort.Slice(ds, func(a, b int) bool { return ds[a] < ds[b] })
	return ds[len(ds)/2]
}

// updateControl compares a change after the calls with the same change
// between consecutive observations of the entity's objects with no such
// call in between (nor in the horizon before), at least as long as the
// calls' windows (span, their median): it holds when the change is at most
// half as frequent without the call. test tells whether a pair
// could change and whether it did. Without KMin such pairs only a write
// holds.
func (m *miner) updateControl(f string, obs map[int32][]upObs, insts []upInst, op int32, share float64, span time.Duration, test func(prev, next Value) (bool, bool)) bool {
	l, H := m.l, m.cfg.MinCoverage()
	calls := map[int32][]time.Time{}
	for _, in := range insts {
		calls[in.obj] = append(calls[in.obj], l.evs[in.ev].ts)
	}
	judged, hit := 0, 0
	for o, os := range obs {
		ts := calls[o]
		for k := 1; k < len(os); k++ {
			p, ok1 := os[k-1].val(l, f)
			n, ok2 := os[k].val(l, f)
			if !ok1 || !ok2 || os[k-1].rootOf(l) == os[k].rootOf(l) {
				continue
			}
			if os[k].start(l).Sub(os[k-1].at(l)) < span {
				continue // shorter than the calls' windows: less time to change on its own
			}
			lo, hi := os[k-1].at(l).Add(-H), os[k].start(l)
			affected := false
			for _, t := range ts {
				if !t.Before(lo) && t.Before(hi) {
					affected = true
					break
				}
			}
			if affected {
				continue
			}
			if j, h := test(p, n); j {
				judged++
				if h {
					hit++
				}
			}
		}
	}
	if judged < m.cfg.KMin {
		// Too few observations without the call to compare. A write is a
		// deliberate change; a read is taken for a cause only against them
		// (an object read at every turn moves on its own as well).
		return !m.l.ops[op].read
	}
	return float64(hit)/float64(judged) <= share/2
}

// attribute marks state st of entity i as set by a write when most of the
// observed transitions into it follow one of the calls (between the last
// observation of the old state, within the horizon, and the first of the
// new one).
func (m *miner) attribute(i int, st string, insts []upInst) {
	lf := m.lifes[i]
	if lf == nil {
		return
	}
	H := m.cfg.MinCoverage()
	calls := map[int32][]time.Time{}
	for _, in := range insts {
		calls[in.obj] = append(calls[in.obj], m.l.evs[in.ev].ts)
	}
	n, by := 0, 0
	for _, o := range lf.objs {
		h := m.hist[o]
		if h == nil {
			continue
		}
		for k := 1; k < len(h.segs); k++ {
			if h.segs[k].state != st {
				continue
			}
			n++
			lo, hi := h.segs[k-1].last.Add(-H), h.segs[k].first
			for _, t := range calls[o] {
				if !t.Before(lo) && !t.After(hi) {
					by++
					break
				}
			}
		}
	}
	if n > 0 && float64(by) >= m.cfg.MinShare*float64(n) {
		if m.caused == nil {
			m.caused = map[int]map[string]bool{}
		}
		if m.caused[i] == nil {
			m.caused[i] = map[string]bool{}
		}
		m.caused[i][st] = true
	}
}
