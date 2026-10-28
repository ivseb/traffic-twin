package miner

import (
	"fmt"
	"sort"
)

// Preconditions (rules v1.9, C17). Checking out answers 409 until the cart
// has an item; reading the profile answers 404 until it is saved once;
// confirming answers 412 until the terms are accepted. One pattern: an
// error status S of an operation X that the user's calls answer until a
// successful write Y of the same user, and that succeed afterwards. For
// every operation X and every 4xx status S seen for at least KMin
// subjects, and every write Y (another operation, successful for at least
// KMin subjects), per subject:
//
//   - the calls of X before the subject's first successful Y (all of them
//     when the subject never wrote Y in the window) are "before", the calls
//     that start after that Y ended are "after";
//   - precision: the calls before that answer S are at least MinShare of
//     the calls before, with a Wilson lower bound of at least MinBirthShare;
//   - recall: the calls answering S that are before are at least MinShare
//     of all the calls answering S;
//   - the calls after succeed (2xx) in at least MinShare of the cases;
//   - at least KMin subjects have a call answering S before and a
//     successful call after.
//
// The best Y (recall + precision + share after) gives the rule: cause Y
// (its 2xx statuses seen at least KMin times), one response effect
// respond {X, S, until: true} after 0s, outcome always. An X and S already
// explained by a counter (C7, a limit rule of the run) is skipped; a
// removal (a 404 after a DELETE) has the opposite order and never passes.
// Signature causal|<Y service>|<Y op>|until|<X service>|<X op>|<S>.

// minePreconds mines the preconditions of the operations of the log;
// limits are the counter rules of the same run.
func (m *miner) minePreconds(limits []*Mined) []*Mined {
	l, cfg := m.l, m.cfg
	skip := map[string]bool{}
	for _, mm := range limits {
		skip[mm.Signature] = true
	}
	type opStat struct {
		subj map[int]map[int32]bool // status → subjects
	}
	stats := map[int32]*opStat{}
	okSubj := map[int32]map[int32]bool{} // write op → subjects with a success
	// first is, per write op and subject, the start and end of its first
	// success (event order is time order).
	first := map[int32]map[int32][2]int64{}
	for i := range l.evs {
		ev := &l.evs[i]
		s := l.subjectOf(int32(i))
		if s < 0 {
			continue
		}
		if ev.status >= 400 && ev.status < 500 {
			st := stats[ev.op]
			if st == nil {
				st = &opStat{subj: map[int]map[int32]bool{}}
				stats[ev.op] = st
			}
			if st.subj[ev.status] == nil {
				st.subj[ev.status] = map[int32]bool{}
			}
			st.subj[ev.status][s] = true
		}
		if ev.ok() && l.ops[ev.op].write {
			if okSubj[ev.op] == nil {
				okSubj[ev.op] = map[int32]bool{}
			}
			okSubj[ev.op][s] = true
			if first[ev.op] == nil {
				first[ev.op] = map[int32][2]int64{}
			}
			if _, ok := first[ev.op][s]; !ok {
				first[ev.op][s] = [2]int64{ev.ts.UnixNano(), ev.end.UnixNano()}
			}
		}
	}
	var writes []int32
	for op, ss := range okSubj {
		if len(ss) >= cfg.KMin {
			writes = append(writes, op)
		}
	}
	sort.Slice(writes, func(a, b int) bool { return writes[a] < writes[b] })
	if len(writes) == 0 {
		return nil
	}
	ops := make([]int32, 0, len(stats))
	for op := range stats {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(a, b int) bool { return ops[a] < ops[b] })
	var out []*Mined
	for _, x := range ops {
		var statuses []int
		for s, ss := range stats[x].subj {
			if len(ss) >= cfg.KMin {
				statuses = append(statuses, s)
			}
		}
		sort.Ints(statuses)
		for _, s := range statuses {
			o := l.ops[x]
			if skip[fmt.Sprintf("causal|%s|%s|limit|%d", o.service, o.op, s)] {
				continue
			}
			if mm := m.precondRule(x, s, writes, first); mm != nil {
				out = append(out, mm)
			}
		}
	}
	return out
}

type precondFit struct {
	y                           int32
	before, beforeS, totalS     int
	after, afterOK, subjects    int
	score, recall, prec, ashare float64
}

// precondRule finds the write that lifts status s of operation x.
func (m *miner) precondRule(x int32, s int, writes []int32, first map[int32]map[int32][2]int64) *Mined {
	l, cfg := m.l, m.cfg
	// The calls of x per subject, in event order.
	calls := map[int32][]int32{}
	for i := range l.evs {
		if l.evs[i].op != x {
			continue
		}
		if sub := l.subjectOf(int32(i)); sub >= 0 {
			calls[sub] = append(calls[sub], int32(i))
		}
	}
	subs := make([]int32, 0, len(calls))
	for sub := range calls {
		subs = append(subs, sub)
	}
	sort.Slice(subs, func(a, b int) bool { return subs[a] < subs[b] })
	var best *precondFit
	for _, y := range writes {
		if y == x {
			continue
		}
		f := &precondFit{y: y}
		for _, sub := range subs {
			// The end of the subject's first successful y.
			var firstEnd, firstStart int64 = -1, -1
			if fy, ok := first[y][sub]; ok {
				firstStart, firstEnd = fy[0], fy[1]
			}
			sawS, sawOK := false, false
			for _, e := range calls[sub] {
				ev := &l.evs[e]
				isS := ev.status == s
				if isS {
					f.totalS++
				}
				switch {
				case firstStart < 0 || ev.ts.UnixNano() < firstStart:
					f.before++
					if isS {
						f.beforeS++
						sawS = true
					}
				case ev.ts.UnixNano() > firstEnd:
					f.after++
					if ev.ok() {
						f.afterOK++
						sawOK = true
					}
				}
			}
			if sawS && sawOK {
				f.subjects++
			}
		}
		if f.before == 0 || f.after == 0 || f.totalS == 0 {
			continue
		}
		f.prec = float64(f.beforeS) / float64(f.before)
		f.recall = float64(f.beforeS) / float64(f.totalS)
		f.ashare = float64(f.afterOK) / float64(f.after)
		if f.prec < cfg.MinShare || wilsonLow(f.beforeS, f.before) < cfg.MinBirthShare || f.recall < cfg.MinShare ||
			f.ashare < cfg.MinShare || f.subjects < cfg.KMin {
			continue
		}
		f.score = f.prec + f.recall + f.ashare
		if best == nil || f.score > best.score+1e-9 {
			best = f
		}
	}
	if best == nil {
		return nil
	}
	xo, yo := l.ops[x], l.ops[best.y]
	sig := fmt.Sprintf("causal|%s|%s|until|%s|%s|%d", yo.service, yo.op, xo.service, xo.op, s)
	statuses := map[int]int{}
	subjects := map[int32]bool{}
	causes := 0
	for i := range l.evs {
		ev := &l.evs[i]
		if ev.op != best.y || !ev.ok() {
			continue
		}
		causes++
		statuses[ev.status]++
		if sub := l.subjectOf(int32(i)); sub >= 0 {
			subjects[sub] = true
		}
	}
	rule := &CausalRule{Kind: KindCausal, Status: StatusDraft, Cause: Cause{Service: yo.service, Op: yo.op}}
	for _, st := range sortedInts(statuses) {
		if statuses[st] >= cfg.KMin {
			rule.Cause.When.Status = append(rule.Cause.When.Status, st)
		}
	}
	if len(rule.Cause.When.Status) == 0 {
		return nil
	}
	id := fmt.Sprintf("until-%d", s)
	rule.Effects = []Effect{{ID: id, Respond: &Respond{Service: xo.service, Op: xo.op, Status: s, Until: true}, After: Delay{Single: "0s"}}}
	rule.Outcomes = []Outcome{{Name: "always", P: 1, Effects: []string{id}}}
	km := best.beforeS
	rule.Evidence.Counts = CausalCounts{Causes: causes, DistinctSubjects: len(subjects), Outcomes: map[string]int{"always": causes}, KeyMatches: &km}
	rule.Evidence.Hints = &CausalHints{Magnitude: map[string]string{id: MagSeconds}}
	rule.Title = fmt.Sprintf("%s su %s risponde %d finché l'utente non chiama %s su %s", xo.op, xo.service, s, yo.op, yo.service)
	if len([]rune(rule.Title)) > 200 {
		rule.Title = string([]rune(rule.Title)[:200])
	}
	conf := wilsonLow(best.beforeS, best.before)
	m.rdiag = append(m.rdiag, RuleDiag{Signature: sig, Kind: KindCausal, Service: yo.service, Op: yo.op, Causes: causes, Subjects: len(subjects),
		Decision: DecisionProposed, Code: WhyMined, Reason: "mined", Confidence: conf})
	return &Mined{Rule: Rule{Causal: rule}, Signature: sig, Structure: causalStructure(rule), Confidence: conf}
}
