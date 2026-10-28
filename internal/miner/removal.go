package miner

import (
	"fmt"
	"sort"
	"strings"
)

// Removal (rules v1.6, C4). A write that cites the id of an entity (a
// DELETE /addresses/{id}, a POST /cart/items/{id}/remove) removes it when,
// afterwards, the object is gone for the user who wrote: the next list read
// of the entity by that user no longer returns it, or the next read by id
// answers 404 or 410. The write becomes the cause of a causal rule with one
// effect, `remove` on `target_id`, when the removal was confirmed for at
// least KMin subjects and in at least MinShare of the writes followed by a
// read that could tell (a write that cites an id and leaves the object in
// place, a product in an order, is never a removal). The status of the reads
// by id after the removal, when it is not 404, goes to the read's
// removed_status (410 Gone).

type removalObs struct {
	confirmed, present int
	subjects           map[int32]bool
	causes             int
	causeSubjects      map[int32]bool
	statuses           map[int]int
	gone               map[int]int // status of by-id reads after removal
	bindLoc            map[int32]int
}

// mineRemovals mines the removal rules of the entities with an id.
func (m *miner) mineRemovals() []*Mined {
	l := m.l
	var out []*Mined
	creators := map[int32]bool{}
	for _, e := range m.ents {
		if e.creatorOp >= 0 {
			creators[e.creatorOp] = true
		}
	}
	for i, e := range m.ents {
		if e.keyed != nil {
			continue
		}
		lists, byID := map[int32]bool{}, map[int32]*Ref{}
		for _, rb := range e.def.ReadBy {
			op, ok := l.opIdx[[2]string{rbService(e, rb), rb.Op}]
			if !ok {
				continue
			}
			switch {
			case strings.HasSuffix(rb.At.Path, "[*]"):
				lists[op] = true
			case rb.By != nil && rb.By.Field == "" && !rb.By.Owner:
				by := *rb.By
				byID[op] = &by
			}
		}
		if len(lists) == 0 && len(byID) == 0 {
			continue
		}
		obs := map[int32]*removalObs{}
		for wi := range l.evs {
			w := &l.evs[wi]
			op := &l.ops[w.op]
			if !op.write || !w.ok() || creators[w.op] {
				continue
			}
			var tok, tloc int32 = -1, -1
			for _, t := range w.toks {
				lc := &l.locs[t.loc]
				if lc.side == sideReq && lc.refOK && m.entityOf(t.tok) == i && (lc.ref.Path == "" || keyRefOK(lc.ref)) {
					tok, tloc = t.tok, t.loc
					break
				}
			}
			if tok < 0 {
				continue
			}
			s := l.subjectOf(int32(wi))
			ro := obs[w.op]
			if ro == nil {
				ro = &removalObs{subjects: map[int32]bool{}, causeSubjects: map[int32]bool{}, statuses: map[int]int{}, gone: map[int]int{}, bindLoc: map[int32]int{}}
				obs[w.op] = ro
			}
			ro.causes++
			ro.statuses[w.status]++
			ro.bindLoc[tloc]++
			if s >= 0 {
				ro.causeSubjects[s] = true
			}
			verdict, status := m.afterWrite(int32(wi), s, tok, i, lists, byID)
			switch verdict {
			case 1:
				ro.confirmed++
				if s >= 0 {
					ro.subjects[s] = true
				}
				if status != 0 {
					ro.gone[status]++
				}
			case -1:
				ro.present++
			}
		}
		ops := make([]int32, 0, len(obs))
		for op := range obs {
			ops = append(ops, op)
		}
		sort.Slice(ops, func(a, b int) bool { return ops[a] < ops[b] })
		for _, op := range ops {
			if mm := m.removalRule(i, op, obs[op]); mm != nil {
				out = append(out, mm)
			}
		}
	}
	return out
}

func rbService(e *entity, rb ReadBy) string {
	if rb.Service != "" {
		return rb.Service
	}
	return e.def.Service
}

// afterWrite looks at the first read after write w that could show object
// tok of entity i to subject s: 1 when the object is gone (absent from a
// list of the entity, or a by-id read that fails with 404 or 410, status
// set), -1 when it is still there, 0 when nothing could tell.
func (m *miner) afterWrite(w, s, tok int32, i int, lists map[int32]bool, byID map[int32]*Ref) (int, int) {
	l := m.l
	end := l.evs[w].end
	evs := m.subjectEvents(s)
	k := sort.Search(len(evs), func(x int) bool { return evs[x] > w })
	for _, j := range evs[k:] {
		ev := &l.evs[j]
		if ev.ts.Before(end) || ev.root == l.evs[w].root {
			continue
		}
		if by := byID[ev.op]; by != nil {
			if t, ok := m.selected(ev, by); ok && t == tok {
				switch {
				case ev.ok():
					return -1, 0
				case ev.status == 404 || ev.status == 410:
					return 1, ev.status
				}
				continue
			}
		}
		if lists[ev.op] && ev.ok() {
			seenEnt := false
			for ri := range ev.recs {
				r := &ev.recs[ri]
				if r.side != sideResp {
					continue
				}
				ent, own, ok := m.recEntity(r)
				if !ok || ent != i {
					continue
				}
				seenEnt = true
				if own.tok == tok {
					return -1, 0
				}
			}
			empty := false
			for _, a := range ev.arrays {
				if a.n == 0 {
					empty = true
				}
			}
			if seenEnt || empty {
				return 1, 0
			}
		}
	}
	return 0, 0
}

// removalRule builds the rule of a removal (see above), nil when the
// evidence is not enough.
func (m *miner) removalRule(i int, op int32, ro *removalObs) *Mined {
	l, e, cfg := m.l, m.ents[i], m.cfg
	o := l.ops[op]
	sig := "causal|" + o.service + "|" + o.op + "|" + e.sig + "|remove"
	d := RuleDiag{Signature: sig, Kind: KindCausal, Service: o.service, Op: o.op, Entity: e.def.Name, Causes: ro.causes, Subjects: len(ro.subjects)}
	d.Values, d.ClearFields = valuesOf(e)
	judged := ro.confirmed + ro.present
	switch {
	case judged == 0 || 2*ro.confirmed < judged:
		return nil // nothing could tell, or the object mostly stays: not even a diagnostic
	case len(ro.subjects) < cfg.KMin:
		d.Decision, d.Code = DecisionNotMined, WhyFewSubjects
		d.Reason = fmt.Sprintf("removal of %s confirmed for only %d distinct subjects, at least %d needed", e.def.Name, len(ro.subjects), cfg.KMin)
		m.rdiag = append(m.rdiag, d)
		return nil
	case float64(ro.confirmed) < cfg.MinShare*float64(judged):
		d.Decision, d.Code = DecisionNotMined, WhyNoEffect
		d.Reason = fmt.Sprintf("%s was still there after %d of %d writes followed by a read", e.def.Name, ro.present, judged)
		m.rdiag = append(m.rdiag, d)
		return nil
	}
	var best int32 = -1
	for lc, n := range ro.bindLoc {
		if best < 0 || n > ro.bindLoc[best] || (n == ro.bindLoc[best] && lc < best) {
			best = lc
		}
	}
	bind := bindName(e.def.Name)
	rule := &CausalRule{Kind: KindCausal, Status: StatusDraft,
		Cause: Cause{Service: o.service, Op: o.op, Bind: map[string]Ref{bind: l.locs[best].ref}}}
	for _, s := range sortedInts(ro.statuses) {
		if ro.statuses[s] >= cfg.KMin {
			rule.Cause.When.Status = append(rule.Cause.When.Status, s)
		}
	}
	if len(rule.Cause.When.Status) == 0 {
		return nil
	}
	id := slug(e.def.Name) + "-removed"
	if !reIdent.MatchString(id) {
		return nil
	}
	rule.Effects = []Effect{{ID: id, Entity: e.def.Name, TargetID: "${" + bind + "}", Remove: true, After: Delay{Single: "0s"}}}
	rule.Outcomes = []Outcome{{Name: "always", P: 1, Effects: []string{id}}}
	km := ro.confirmed
	rule.Evidence.Counts = CausalCounts{Causes: ro.causes, DistinctSubjects: len(ro.causeSubjects), Outcomes: map[string]int{"always": ro.causes}, KeyMatches: &km}
	rule.Evidence.Hints = &CausalHints{Magnitude: map[string]string{id: MagSeconds}}
	rule.Title = fmt.Sprintf("%s su %s rimuove %s", o.op, o.service, e.def.Name)
	if len([]rune(rule.Title)) > 200 {
		rule.Title = string([]rune(rule.Title)[:200])
	}
	// The status of the reads by id after a removal, when it is not 404.
	gone, total := 0, 0
	for _, n := range ro.gone {
		total += n
	}
	for st, n := range ro.gone {
		if st != 404 && n > gone && n >= cfg.KMin && float64(n) >= cfg.MinShare*float64(total) {
			for k := range e.def.ReadBy {
				rb := &e.def.ReadBy[k]
				if rb.By != nil && rb.By.Field == "" && !rb.By.Owner && !strings.HasSuffix(rb.At.Path, "[*]") {
					rb.RemovedStatus = st
				}
			}
			gone = n
		}
	}
	d.Decision, d.Code, d.Reason = DecisionProposed, WhyMined, "mined"
	d.Confidence = float64(ro.confirmed) / float64(judged)
	m.rdiag = append(m.rdiag, d)
	return &Mined{Rule: Rule{Causal: rule}, Signature: sig, Structure: causalStructure(rule), Confidence: d.Confidence}
}

// subjectEvents returns the events of subject s in event order (indexed on
// first use).
func (m *miner) subjectEvents(s int32) []int32 {
	if m.bySubject == nil {
		m.bySubject = map[int32][]int32{}
		for i := range m.l.evs {
			if x := m.l.subjectOf(int32(i)); x >= 0 {
				m.bySubject[x] = append(m.bySubject[x], int32(i))
			}
		}
	}
	return m.bySubject[s]
}
