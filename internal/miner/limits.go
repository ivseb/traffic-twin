package miner

import (
	"fmt"
	"sort"
	"time"
)

// Uniqueness and counters per key (rules v1.8, C7). A second creation with
// the same email answers 409; after three failed logins for a user the
// next answers 423; more than five quotes a minute answer 429. All are one
// pattern: an error status S of an operation that the calls before it with
// the same key explain. For every operation and every 4xx status S seen
// for at least KMin subjects, the miner tries
//
//   - a key: a request token present in at least MinShare of the calls (a
//     path or query parameter, a body member outside arrays) or the
//     subject;
//   - what counts: the successful calls, or the failed ones (other 4xx);
//   - a window: the whole window, 1m, 15m, 1h or 1d;
//
// and for each call the number of earlier counted calls with its key in
// the window before it (its ordinal). The limit n is the ordinal from
// which the calls answer S. The best candidate (recall + precision) is
// kept when the calls answering S at an ordinal of at least n are at least
// MinShare of the calls answering S (recall), the calls at such ordinals
// answer S in at least MinShare of the cases with a Wilson lower bound of
// at least MinBirthShare (precision), they come from at least KMin
// subjects, and at least KMin calls below n pass (a counter, not an
// operation that always fails). Ties prefer the whole window, then the
// shortest. A status that comes at random (5 % of the calls) never has the
// precision.
//
// The rule: cause the operation with the counted statuses, bound to the
// key when it is a token of the request; one response effect with a limit
// (n, window, key), the observed status, the contract's example for it
// (the first, contract inference owns the names). The window is figurative
// like the delays (decision D1): one of the five sizes, never a measure.
// Signature causal|<service>|<op>|limit|<status>.

// limitWindows are the windows tried, in order of preference on ties.
var limitWindows = []struct {
	d    time.Duration
	name string
}{{0, ""}, {time.Minute, "1m"}, {15 * time.Minute, "15m"}, {time.Hour, "1h"}, {24 * time.Hour, "1d"}}

// maxLimitN bounds the limits tried.
const maxLimitN = 50

type limitKey struct {
	loc int32 // request location of the key token; -1 for the subject
}

type limitFit struct {
	key           limitKey
	counted       string // "ok" or "fail"
	window        int    // index in limitWindows
	n             int
	hits, fp, tn  int
	totalS        int
	hitSubj       int
	score         float64
	countedStatus []int
}

// mineLimits mines the counters per key of the operations of the log.
func (m *miner) mineLimits() []*Mined {
	l, cfg := m.l, m.cfg
	byOp := map[int32][]int32{}
	for i := range l.evs {
		byOp[l.evs[i].op] = append(byOp[l.evs[i].op], int32(i))
	}
	ops := make([]int32, 0, len(byOp))
	for op, evs := range byOp {
		if len(evs) >= cfg.KMin {
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(a, b int) bool { return ops[a] < ops[b] })
	var out []*Mined
	for _, op := range ops {
		evs := byOp[op]
		sort.SliceStable(evs, func(a, b int) bool { return l.evs[evs[a]].ts.Before(l.evs[evs[b]].ts) })
		st := map[int]map[int32]bool{}
		for _, e := range evs {
			s := l.evs[e].status
			if s >= 400 && s < 500 {
				if st[s] == nil {
					st[s] = map[int32]bool{}
				}
				st[s][l.subjectOf(e)] = true
			}
		}
		statuses := make([]int, 0, len(st))
		for s, subj := range st {
			delete(subj, -1)
			if len(subj) >= cfg.KMin {
				statuses = append(statuses, s)
			}
		}
		sort.Ints(statuses)
		for _, s := range statuses {
			if mm := m.limitRule(op, evs, s); mm != nil {
				out = append(out, mm)
			}
		}
	}
	return out
}

// limitRule fits the counter of status s of operation op (see above).
func (m *miner) limitRule(op int32, evs []int32, s int) *Mined {
	l, cfg := m.l, m.cfg
	// Keys: the request token locations of most calls, and the subject.
	locN := map[int32]int{}
	for _, e := range evs {
		seen := map[int32]bool{}
		for _, t := range l.evs[e].toks {
			lc := &l.locs[t.loc]
			if lc.side != sideReq || !lc.refOK || (lc.ref.Path != "" && !keyRefOK(lc.ref)) || seen[t.loc] {
				continue
			}
			seen[t.loc] = true
			locN[t.loc]++
		}
	}
	var keys []limitKey
	for _, lc := range sortedLocs(locN) {
		if float64(locN[lc]) >= cfg.MinShare*float64(len(evs)) {
			keys = append(keys, limitKey{loc: lc})
		}
	}
	keys = append(keys, limitKey{loc: -1})
	statusN := map[int]int{}
	for _, e := range evs {
		statusN[l.evs[e].status]++
	}
	var best *limitFit
	for _, k := range keys {
		keyOf := make([]int32, len(evs))
		explained := make([]bool, len(evs))
		prev := map[int32]time.Time{}
		for x, e := range evs {
			keyOf[x] = -1
			if k.loc < 0 {
				keyOf[x] = l.subjectOf(e)
				continue
			}
			for _, t := range l.evs[e].toks {
				if t.loc == k.loc {
					keyOf[x] = t.tok
					break
				}
			}
		}
		for x, e := range evs {
			// A write of another operation citing an id of the call since
			// the previous call with the key explains the answer (a
			// removal, an update): not a counter.
			tk := keyOf[x]
			if tk < 0 {
				continue
			}
			if p, ok := prev[tk]; ok {
				for _, t := range l.evs[e].toks {
					if l.locs[t.loc].side == sideReq && m.writtenByOther(t.tok, op, p, l.evs[e].ts) {
						explained[x] = true
						break
					}
				}
			}
			prev[tk] = l.evs[e].ts
		}
		for _, counted := range []string{"ok", "fail"} {
			isCounted := func(st int) bool {
				if counted == "ok" {
					return st >= 200 && st < 300
				}
				return st >= 400 && st < 500 && st != s
			}
			var cs []int
			for st, n := range statusN {
				if isCounted(st) && n >= cfg.KMin {
					cs = append(cs, st)
				}
			}
			if len(cs) == 0 {
				continue
			}
			sort.Ints(cs)
			for wi, w := range limitWindows {
				fit := m.fitLimit(evs, keyOf, explained, s, cs, w.d)
				if fit == nil {
					continue
				}
				fit.key, fit.counted, fit.window, fit.countedStatus = k, counted, wi, cs
				if best == nil || fit.score > best.score+1e-9 {
					best = fit
				}
			}
		}
	}
	if best == nil {
		return nil
	}
	o := l.ops[op]
	sig := fmt.Sprintf("causal|%s|%s|limit|%d", o.service, o.op, s)
	rule := &CausalRule{Kind: KindCausal, Status: StatusDraft, Cause: Cause{Service: o.service, Op: o.op, When: When{Status: best.countedStatus}}}
	lm := &Limit{N: best.n, Window: limitWindows[best.window].name}
	keyText := "lo stesso utente"
	if best.key.loc >= 0 {
		ref := l.locs[best.key.loc].ref
		name := freeBind(selectorField(ref), nil)
		rule.Cause.Bind = map[string]Ref{name: ref}
		lm.Key = "${" + name + "}"
		keyText = "lo stesso " + selectorField(ref)
	}
	id := fmt.Sprintf("limit-%d", s)
	rule.Effects = []Effect{{ID: id, Respond: &Respond{Service: o.service, Op: o.op, Status: s, Limit: lm}, After: Delay{Single: "0s"}}}
	rule.Outcomes = []Outcome{{Name: "always", P: 1, Effects: []string{id}}}
	causes, subjects := 0, map[int32]bool{}
	for _, e := range evs {
		if intIn(l.evs[e].status, best.countedStatus) {
			causes++
			if sub := l.subjectOf(e); sub >= 0 {
				subjects[sub] = true
			}
		}
	}
	km := best.hits
	rule.Evidence.Counts = CausalCounts{Causes: causes, DistinctSubjects: len(subjects), Outcomes: map[string]int{"always": causes}, KeyMatches: &km}
	rule.Evidence.Hints = &CausalHints{Magnitude: map[string]string{id: MagSeconds}}
	switch {
	case best.n == 1 && lm.Window == "" && best.counted == "ok":
		rule.Title = fmt.Sprintf("%s su %s: una seconda chiamata riuscita con %s risponde %d", o.op, o.service, keyText, s)
	default:
		within := ""
		if lm.Window != "" {
			within = " in " + lm.Window
		}
		what := "riuscite"
		if best.counted == "fail" {
			what = "fallite"
		}
		rule.Title = fmt.Sprintf("%s su %s: dopo %d chiamate %s con %s%s risponde %d", o.op, o.service, best.n, what, keyText, within, s)
	}
	if len([]rune(rule.Title)) > 200 {
		rule.Title = string([]rune(rule.Title)[:200])
	}
	conf := wilsonLow(best.hits, best.hits+best.fp)
	m.rdiag = append(m.rdiag, RuleDiag{Signature: sig, Kind: KindCausal, Service: o.service, Op: o.op, Causes: causes, Subjects: len(subjects),
		Decision: DecisionProposed, Code: WhyMined, Reason: "mined", Confidence: conf})
	return &Mined{Rule: Rule{Causal: rule}, Signature: sig, Structure: causalStructure(rule), Confidence: conf}
}

// fitLimit computes the ordinals of the calls (counted calls with the same
// key in window w before each one) and the best limit n for status s; nil
// when none holds (see the top of the file).
func (m *miner) fitLimit(evs []int32, keyOf []int32, explained []bool, s int, counted []int, w time.Duration) *limitFit {
	l, cfg := m.l, m.cfg
	times := map[int32][]time.Time{}
	ord := make([]int, len(evs))
	for x, e := range evs {
		k := keyOf[x]
		if k < 0 {
			ord[x] = -1
			continue
		}
		ts := times[k]
		t := l.evs[e].ts
		lo := 0
		if w > 0 {
			lo = sort.Search(len(ts), func(i int) bool { return t.Sub(ts[i]) < w })
		}
		ord[x] = len(ts) - lo
		if intIn(l.evs[e].status, counted) {
			times[k] = append(ts, t)
		}
	}
	totalS := 0
	for x, e := range evs {
		if ord[x] >= 0 && !explained[x] && l.evs[e].status == s {
			totalS++
		}
	}
	if totalS < cfg.KMin {
		return nil
	}
	var best *limitFit
	for n := 1; n <= maxLimitN; n++ {
		f := &limitFit{n: n, totalS: totalS}
		subj := map[int32]bool{}
		for x, e := range evs {
			if ord[x] < 0 || explained[x] {
				continue
			}
			isS := l.evs[e].status == s
			switch {
			case ord[x] >= n && isS:
				f.hits++
				if sub := l.subjectOf(e); sub >= 0 {
					subj[sub] = true
				}
			case ord[x] >= n:
				f.fp++
			case !isS:
				f.tn++
			}
		}
		if f.hits == 0 {
			break // higher limits explain even less
		}
		f.hitSubj = len(subj)
		recall := float64(f.hits) / float64(totalS)
		prec := float64(f.hits) / float64(f.hits+f.fp)
		if recall < cfg.MinShare || prec < cfg.MinShare || wilsonLow(f.hits, f.hits+f.fp) < cfg.MinBirthShare ||
			f.hitSubj < cfg.KMin || f.tn < cfg.KMin {
			continue
		}
		f.score = recall + prec
		if best == nil || f.score > best.score+1e-9 {
			best = f
		}
	}
	return best
}

func sortedLocs(m map[int32]int) []int32 {
	out := make([]int32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// writtenByOther reports whether a successful write of an operation other
// than op cites tok in (lo, hi).
func (m *miner) writtenByOther(tok, op int32, lo, hi time.Time) bool {
	l := m.l
	os := l.occ[tok] // in event order, so in time order
	for k := sort.Search(len(os), func(x int) bool { return l.evs[os[x].ev].ts.After(lo) }); k < len(os); k++ {
		ev := &l.evs[os[k].ev]
		if !ev.ts.Before(hi) {
			break
		}
		if ev.op != op && ev.ok() && l.ops[ev.op].write {
			return true
		}
	}
	return false
}

func intIn(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
