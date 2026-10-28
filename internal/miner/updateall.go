package miner

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Writes on all the objects of the user (rules v1.9, target_all). "Mark
// all as read", "archive all", "cancel all my reservations": a write whose
// request cites no object of entity E (it cites only the user, or nothing)
// after which several objects of E of the same user change a field F to
// the same value. For every successful write W (never E's creation) and
// every object of E of W's subject (an object observed only in answers to
// that subject):
//
//   - before is the object's last observation before W (outside W's trace),
//     after its first one after W, before the subject's next call of the
//     same operation, the next write citing the object, or the decision
//     horizon (as for the updates of updates.go);
//   - for a value v of F, the objects whose F was not v before are judged
//     and those with v after are consistent; a call is judged when it has a
//     judged object and consistent when at least MinShare of its judged
//     objects took v;
//   - the rule needs consistent calls from at least KMin subjects, at least
//     MinShare of the judged calls (Wilson lower bound at least
//     MinBirthShare), at least KMin consistent calls in which two objects or
//     more took v, and the change must be rare without the call (the
//     control of the update literals);
//   - when the value before is the same for at least MinShare of the judged
//     objects, the effect is guarded by where on it; a change first seen
//     after a read that still showed the old value, for at least KMin
//     subjects and 1 - MinShare of the changes, gets a figurative after.
//
// The effect: entity E, target_all, set F to v (one effect per field, id
// <entity>-<field>-all), outcome always. Signature
// causal|<service>|<op>|<domain>|update_all.

// mineUpdatesAll mines the writes on all the user's objects of the
// entities with an id.
func (m *miner) mineUpdatesAll() []*Mined {
	l := m.l
	var out []*Mined
	for i, e := range m.ents {
		if e.keyed != nil {
			continue
		}
		obs := m.updateObs(i)
		if len(obs) == 0 {
			continue
		}
		// The objects of each subject: observed only in answers to it.
		seenBy := map[int32]int32{}
		for o, os := range obs {
			var s int32 = -2
			for k := range os {
				sub := l.subjectOf(os[k].ev)
				if s == -2 {
					s = sub
				} else if sub != s {
					s = -1
				}
			}
			if s >= 0 {
				seenBy[o] = s
			}
		}
		objsOf := map[int32][]int32{}
		for o, s := range seenBy {
			objsOf[s] = append(objsOf[s], o)
		}
		for s := range objsOf {
			sortInt32(objsOf[s])
		}
		_, cites := m.updateCauses(i)
		byOp := map[int32][]int32{}
		for wi := range l.evs {
			w := &l.evs[wi]
			op := &l.ops[w.op]
			if !w.ok() || !op.write || w.op == e.creatorOp {
				continue
			}
			cited := false
			for _, t := range w.toks {
				if l.locs[t.loc].side == sideReq && m.entityOf(t.tok) == i {
					cited = true
					break
				}
			}
			if cited {
				continue
			}
			if s := l.subjectOf(int32(wi)); s >= 0 && len(objsOf[s]) > 0 {
				byOp[w.op] = append(byOp[w.op], int32(wi))
			}
		}
		ops := make([]int32, 0, len(byOp))
		for op := range byOp {
			ops = append(ops, op)
		}
		sort.Slice(ops, func(a, b int) bool { return ops[a] < ops[b] })
		for _, op := range ops {
			if mm := m.updateAllRule(i, op, byOp[op], obs, objsOf, cites); mm != nil {
				out = append(out, mm)
			}
		}
	}
	return out
}

// allItem is one object judged after one call.
type allItem struct {
	call     int // index in calls
	b, a     Value
	stale    bool
	delay    time.Duration
	span     time.Duration
	obj      int32
	afterLoc int32
}

// updateAllRule builds the rule of write op on all the objects of entity i.
func (m *miner) updateAllRule(i int, op int32, calls []int32, obs map[int32][]upObs, objsOf map[int32][]int32, cites map[int32][]citation) *Mined {
	l, e, cfg := m.l, m.ents[i], m.cfg
	o := l.ops[op]
	H := cfg.MinCoverage()
	// The subject's next call of the operation ends a window.
	nextOf := map[int32]time.Time{}
	lastBy := map[int32]int32{}
	for _, c := range calls {
		s := l.subjectOf(c)
		if p, ok := lastBy[s]; ok {
			nextOf[p] = l.evs[c].ts
		}
		lastBy[s] = c
	}
	items := map[string][]allItem{}
	for ci, c := range calls {
		w := &l.evs[c]
		s := l.subjectOf(c)
		for _, obj := range objsOf[s] {
			os := obs[obj]
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
			end := w.ts.Add(H)
			if t, ok := nextOf[c]; ok && t.Before(end) {
				end = t
			}
			cs := cites[obj]
			for k := sort.Search(len(cs), func(x int) bool { return cs[x].ev > c }); k < len(cs); k++ {
				if cs[k].write {
					if t := l.evs[cs[k].ev].ts; t.Before(end) {
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
			for _, a := range before.rec.attrs {
				name, bv := a.name, a.val
				if !reFieldPath.MatchString(name) {
					continue
				}
				it := allItem{call: ci, b: bv, obj: obj}
				seen := false
				var lastOld time.Time
				for _, x := range after {
					v, ok := os[x].val(l, name)
					if !ok {
						continue
					}
					xs := os[x].start(l)
					if !seen {
						seen, it.a, it.afterLoc, it.span = true, v, os[x].locOf(), xs.Sub(bt)
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
				if seen {
					items[name] = append(items[name], it)
				}
			}
		}
	}
	type accepted struct {
		field      string
		value      any
		where      any
		delayed    bool
		delays     []time.Duration
		consistent int
		judged     int
	}
	var fields []accepted
	for _, f := range sortedKeys(items) {
		its := items[f]
		// The value: the most frequent new value among the changes.
		cnt := map[string]int{}
		vals := map[string]Value{}
		for _, it := range its {
			if it.a != it.b {
				cnt[valKey(it.a)]++
				vals[valKey(it.a)] = it.a
			}
		}
		if len(cnt) == 0 {
			continue
		}
		v := vals[argmax(cnt)]
		lit, ok := literalOf(v)
		if !ok || v.Kind == 'q' || v.Kind == 'n' {
			continue // a code or a boolean: never an id, never a number
		}
		type callStat struct{ judged, hit int }
		per := map[int]*callStat{}
		befores := map[string]int{}
		bvals := map[string]Value{}
		judgedObjs := 0
		for _, it := range its {
			if it.b == v {
				continue
			}
			judgedObjs++
			befores[valKey(it.b)]++
			bvals[valKey(it.b)] = it.b
			cs := per[it.call]
			if cs == nil {
				cs = &callStat{}
				per[it.call] = cs
			}
			cs.judged++
			if it.a == v {
				cs.hit++
			}
		}
		judged, consistent, multi := 0, 0, 0
		subj := map[int32]bool{}
		for ci, cs := range per {
			judged++
			if cs.hit > 0 && float64(cs.hit) >= cfg.MinShare*float64(cs.judged) {
				consistent++
				subj[l.subjectOf(calls[ci])] = true
				if cs.hit >= 2 {
					multi++
				}
			}
		}
		if len(subj) < cfg.KMin || multi < cfg.KMin || float64(consistent) < cfg.MinShare*float64(judged) ||
			wilsonLow(consistent, judged) < cfg.MinBirthShare {
			continue
		}
		// Rare without the call: the control of the update literals, over
		// the calls as citations of each object.
		var insts []upInst
		for ci, c := range calls {
			for _, obj := range objsOf[l.subjectOf(c)] {
				insts = append(insts, upInst{ev: c, op: op, obj: obj, loc: -1, subj: l.subjectOf(calls[ci])})
			}
		}
		share := float64(consistent) / float64(judged)
		var spans []upItem
		for _, it := range its {
			if it.b != v {
				spans = append(spans, upItem{span: it.span})
			}
		}
		span := medianSpan(spans, func(*upItem) bool { return true })
		if !m.updateControl(f, obs, insts, op, share, span, func(p, n Value) (bool, bool) { return p != v, p != v && n == v }) {
			continue
		}
		acc := accepted{field: f, value: lit, consistent: consistent, judged: judged}
		if top := argmax(befores); befores[top] > 0 && float64(befores[top]) >= cfg.MinShare*float64(judgedObjs) {
			if bl, ok := literalOf(bvals[top]); ok && bvals[top].Kind != 'q' && bvals[top].Kind != 'n' {
				acc.where = bl
			}
		}
		stale, changed := 0, 0
		staleSubj := map[int32]bool{}
		var delays []time.Duration
		for _, it := range its {
			if it.a != v || it.b == v {
				continue
			}
			changed++
			if it.stale {
				stale++
				delays = append(delays, it.delay)
				staleSubj[l.subjectOf(calls[it.call])] = true
			}
		}
		if len(staleSubj) >= cfg.KMin && float64(stale) >= (1-cfg.MinShare)*float64(changed) {
			acc.delayed, acc.delays = true, delays
		}
		fields = append(fields, acc)
	}
	if len(fields) == 0 {
		return nil
	}
	sig := "causal|" + o.service + "|" + o.op + "|" + e.sig + "|update_all"
	statuses := map[int]int{}
	subjects := map[int32]bool{}
	for _, c := range calls {
		statuses[l.evs[c].status]++
		subjects[l.subjectOf(c)] = true
	}
	rule := &CausalRule{Kind: KindCausal, Status: StatusDraft, Cause: Cause{Service: o.service, Op: o.op}}
	for _, s := range sortedInts(statuses) {
		if statuses[s] >= cfg.KMin {
			rule.Cause.When.Status = append(rule.Cause.When.Status, s)
		}
	}
	if len(rule.Cause.When.Status) == 0 {
		return nil
	}
	mags := map[string]string{}
	var ids, names []string
	conf, km := 1.0, 0
	for _, fe := range fields {
		id := slug(e.def.Name) + "-" + slug(fe.field) + "-all"
		if !reIdent.MatchString(id) {
			return nil
		}
		ef := Effect{ID: id, Entity: e.def.Name, TargetAll: true, Set: map[string]any{fe.field: fe.value}, After: Delay{Single: "0s"}}
		mags[id] = MagSeconds
		if fe.where != nil {
			ef.Where = map[string]any{fe.field: fe.where}
		}
		if fe.delayed {
			sort.Slice(fe.delays, func(a, b int) bool { return fe.delays[a] < fe.delays[b] })
			mag := magnitude(fe.delays[len(fe.delays)/2])
			ef.After, mags[id] = delayFor(mag), mag
		}
		rule.Effects = append(rule.Effects, ef)
		ids = append(ids, id)
		names = append(names, fe.field)
		if c := wilsonLow(fe.consistent, fe.judged); c < conf {
			conf = c
		}
		km = max(km, fe.consistent)
	}
	rule.Outcomes = []Outcome{{Name: "always", P: 1, Effects: ids}}
	rule.Evidence.Counts = CausalCounts{Causes: len(calls), DistinctSubjects: len(subjects), Outcomes: map[string]int{"always": len(calls)}, KeyMatches: &km}
	rule.Evidence.Hints = &CausalHints{Magnitude: mags}
	rule.Title = fmt.Sprintf("%s su %s aggiorna tutti gli oggetti %s dell'utente: %s", o.op, o.service, e.def.Name, strings.Join(names, ", "))
	if len([]rune(rule.Title)) > 200 {
		rule.Title = string([]rune(rule.Title)[:200])
	}
	m.rdiag = append(m.rdiag, RuleDiag{Signature: sig, Kind: KindCausal, Service: o.service, Op: o.op, Entity: e.def.Name,
		Causes: len(calls), Subjects: len(subjects), Decision: DecisionProposed, Code: WhyMined, Reason: "mined", Confidence: conf})
	return &Mined{Rule: Rule{Causal: rule}, Signature: sig, Structure: causalStructure(rule), Confidence: conf}
}
