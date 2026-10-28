package miner

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Lifecycles: the state of an entity is the keep-valued field of its
// records that changes over time for the same object (status). Reads only
// sample it, so a state can be skipped between two observations; the order
// of states is therefore learned as a declarative precedence constraint
// ("a is always observed before b, never after") over all objects, and the
// lifecycle is the transitive reduction of that order (a Hasse diagram).
// Transition instants are only estimated (between the last observation of
// the old state and the first of the new one, narrowed by a time bucket that
// changes with the state, like updatedAt): they serve the magnitude hints
// and the batch detection, never as published delays (decision D1).

type segment struct {
	state  string
	first  time.Time
	last   time.Time
	bucket time.Time // start of the transition time bucket, zero if unknown
	width  time.Duration
}

type history struct {
	segs   []segment
	born   bool
	bornAt time.Time
}

// stateAt returns the last state observed at or before t.
func (h *history) stateAt(t time.Time) (string, bool) {
	st, ok := "", false
	for _, s := range h.segs {
		if s.first.After(t) {
			break
		}
		st, ok = s.state, true
	}
	return st, ok
}

// entry estimates when segment k started: the midpoint of
// (last of k-1, first of k] narrowed by the bucket. ok is false when the
// object was not observed before k (and k is not its creation).
func (h *history) entry(k int) (lo, hi time.Time, ok bool) {
	if k == 0 {
		if h.born {
			return h.bornAt, h.bornAt, true
		}
		return time.Time{}, time.Time{}, false
	}
	lo, hi = h.segs[k-1].last, h.segs[k].first
	if b := h.segs[k].bucket; !b.IsZero() {
		blo, bhi := b, b.Add(h.segs[k].width)
		if blo.After(lo) {
			lo = blo
		}
		if bhi.Before(hi) {
			hi = bhi
		}
		if hi.Before(lo) {
			lo, hi = h.segs[k-1].last, h.segs[k].first
		}
	}
	return lo, hi, true
}

func mid(lo, hi time.Time) time.Time { return lo.Add(hi.Sub(lo) / 2) }

type lifecycle struct {
	ent      int
	states   []string
	initial  string
	prec     map[[2]string]int
	succ     map[string][]string
	pred     map[string][]string
	terminal map[string]bool
	objs     []int32
	fieldIdx map[string]map[int32][]int32
	// changeAttrs: per edge, other attributes set with a constant value.
	changeAttrs map[[2]string]map[string]any
	// back are the transitions to an earlier state of the order (cycles,
	// rules v1.8): b → a with a before b.
	back map[[2]string]*backEdge
}

type obsRec struct {
	t   time.Time
	rec *record
}

// findLifecycle builds the histories and the lifecycle of entity i.
func (m *miner) findLifecycle(i int) {
	l, e := m.l, m.ents[i]
	obs := map[int32][]obsRec{}
	for ei := range l.evs {
		ev := &l.evs[ei]
		if !ev.ok() {
			continue
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			ent, own, ok := m.recEntity(r)
			if !ok || ent != i {
				continue
			}
			obs[own.tok] = append(obs[own.tok], obsRec{ev.at(r.side), r})
		}
	}
	lf := &lifecycle{ent: i, prec: map[[2]string]int{}, succ: map[string][]string{}, pred: map[string][]string{},
		terminal: map[string]bool{}, fieldIdx: map[string]map[int32][]int32{}, changeAttrs: map[[2]string]map[string]any{}}
	for o := range obs {
		lf.objs = append(lf.objs, o)
	}
	sortInt32(lf.objs)
	m.lifes[i] = lf
	for _, o := range lf.objs {
		os := obs[o]
		sort.SliceStable(os, func(a, b int) bool { return os[a].t.Before(os[b].t) })
		obs[o] = os
	}

	// State field: the string attribute that changes for the most objects;
	// without one (rules v1.7), a boolean, then a number bucket.
	changing := map[byte]map[string]int{'s': {}, 'b': {}, 'q': {}}
	clear := map[string]bool{}
	for _, o := range lf.objs {
		vals := map[byte]map[string]map[string]bool{'s': {}, 'b': {}, 'q': {}}
		see := func(kind byte, name, v string) {
			if vals[kind][name] == nil {
				vals[kind][name] = map[string]bool{}
			}
			vals[kind][name][v] = true
		}
		for _, ob := range obs[o] {
			for _, a := range ob.rec.attrs {
				switch a.val.Kind {
				case 's':
					clear[a.name] = true
					see('s', a.name, a.val.S)
				case 'b':
					see('b', a.name, a.val.S)
				}
			}
			for _, a := range ob.rec.times {
				if a.val.Kind == 'q' {
					see('q', a.name, a.val.S)
				}
			}
		}
		for kind, byName := range vals {
			for name, v := range byName {
				if len(v) >= 2 {
					changing[kind][name]++
				}
			}
		}
	}
	// The fields of the object seen in clear (keep or code values): a missing
	// lifecycle with values in clear is not a policy problem.
	e.clearFields = sortedKeys(clear)
	if len(e.clearFields) > maxClearFields {
		e.clearFields = e.clearFields[:maxClearFields]
	}
	sf, kind := "", byte(0)
	for _, k := range []byte{'s', 'b', 'q'} {
		if c := argmax(changing[k]); c != "" && changing[k][c] >= m.cfg.KMin && reFieldPath.MatchString(c) {
			sf, kind = c, k
			break
		}
	}
	if sf == "" {
		// No lifecycle; histories still record creation for ownership.
		return
	}
	e.stateField, e.stateKind = sf, kind

	// Transition time field: a time bucket constant within a state and
	// changing with it.
	type tstat struct{ same, sameN, diff, diffN int }
	tst := map[string]*tstat{}
	for _, o := range lf.objs {
		os := obs[o]
		for k := 1; k < len(os); k++ {
			a, _ := stateIn(os[k-1].rec, sf, kind)
			b, _ := stateIn(os[k].rec, sf, kind)
			for _, ta := range os[k].rec.times {
				pv, ok := os[k-1].rec.time(ta.name)
				if !ok || ta.val.Kind != 's' {
					continue
				}
				s := tst[ta.name]
				if s == nil {
					s = &tstat{}
					tst[ta.name] = s
				}
				if a == b {
					s.sameN++
					if pv == ta.val.S {
						s.same++
					}
				} else {
					s.diffN++
					if pv != ta.val.S {
						s.diff++
					}
				}
			}
		}
	}
	for _, name := range sortedKeys(tst) {
		s := tst[name]
		if s.sameN >= m.cfg.KMin && s.diffN >= m.cfg.KMin && float64(s.same) >= 0.95*float64(s.sameN) &&
			float64(s.diff) >= 0.8*float64(s.diffN) {
			e.timeField = name
			break
		}
	}

	// Histories.
	for _, o := range lf.objs {
		h := &history{}
		if b := m.birth[o]; b.ev >= 0 {
			h.born, h.bornAt = true, l.evs[b.ev].end
		}
		for _, ob := range obs[o] {
			st, ok := stateIn(ob.rec, sf, kind)
			if !ok {
				continue
			}
			n := len(h.segs)
			if n > 0 && h.segs[n-1].state == st {
				h.segs[n-1].last = ob.t
				continue
			}
			seg := segment{state: st, first: ob.t, last: ob.t}
			if e.timeField != "" {
				if tok, ok := ob.rec.time(e.timeField); ok {
					seg.bucket, seg.width = parseTimeBucket(tok)
				}
			}
			h.segs = append(h.segs, seg)
		}
		if len(h.segs) > 0 {
			m.hist[o] = h
		}
	}

	// Precedence over first-seen orders.
	stateSet := map[string]bool{}
	firsts := map[string]int{}
	for _, o := range lf.objs {
		h := m.hist[o]
		if h == nil {
			continue
		}
		var order []string
		seen := map[string]bool{}
		for _, s := range h.segs {
			if !seen[s.state] {
				seen[s.state] = true
				order = append(order, s.state)
				stateSet[s.state] = true
			}
		}
		if h.born {
			firsts[order[0]]++
		}
		for a := 0; a < len(order); a++ {
			for b := a + 1; b < len(order); b++ {
				lf.prec[[2]string{order[a], order[b]}]++
			}
		}
	}
	lf.states = sortedKeys(stateSet)
	lf.initial = argmax(firsts)
	less := func(a, b string) bool {
		n, r := lf.prec[[2]string{a, b}], lf.prec[[2]string{b, a}]
		return n >= 3 && float64(r) <= 0.01*float64(n)
	}
	for _, a := range lf.states {
		for _, b := range lf.states {
			if a == b || !less(a, b) {
				continue
			}
			direct := true
			for _, c := range lf.states {
				if c != a && c != b && less(a, c) && less(c, b) {
					direct = false
					break
				}
			}
			if direct {
				lf.succ[a] = append(lf.succ[a], b)
				lf.pred[b] = append(lf.pred[b], a)
			}
		}
	}
	for _, s := range lf.states {
		if len(lf.succ[s]) == 0 {
			lf.terminal[s] = true
		}
	}
	m.backEdges(lf)

	// Attributes that take one constant value at each transition.
	type cv struct {
		n    int
		vals map[string]int
		v    map[string]Value
	}
	edgeN := map[[2]string]int{}
	chg := map[[2]string]map[string]*cv{}
	for _, o := range lf.objs {
		os := obs[o]
		known := map[string]Value{} // last value of each attribute, any record
		cur := ""
		for k := 0; k < len(os); k++ {
			bs, ok := stateIn(os[k].rec, sf, kind)
			if !ok {
				continue
			}
			a := cur
			cur = bs
			if a == "" || a == bs {
				for _, at := range os[k].rec.attrs {
					known[at.name] = at.val
				}
				continue
			}
			edge := [2]string{a, bs}
			edgeN[edge]++
			for _, at := range os[k].rec.attrs {
				if at.name == sf {
					continue
				}
				pv, seen := known[at.name]
				known[at.name] = at.val
				if seen && pv == at.val {
					continue
				}
				if chg[edge] == nil {
					chg[edge] = map[string]*cv{}
				}
				c := chg[edge][at.name]
				if c == nil {
					c = &cv{vals: map[string]int{}, v: map[string]Value{}}
					chg[edge][at.name] = c
				}
				c.n++
				k := string(at.val.Kind) + at.val.S
				c.vals[k]++
				c.v[k] = at.val
			}
		}
	}
	for edge, attrs := range chg {
		for name, c := range attrs {
			if len(c.vals) != 1 || float64(c.n) < m.cfg.MinShare*float64(edgeN[edge]) || !reFieldPath.MatchString(name) {
				continue
			}
			for k := range c.vals {
				if lf.changeAttrs[edge] == nil {
					lf.changeAttrs[edge] = map[string]any{}
				}
				lf.changeAttrs[edge][name] = c.v[k].Any()
			}
		}
	}
}

// stateIn returns the value of state field name in a record, of the kind
// of the entity's state: a code ('s'), a boolean ('b', "true"/"false") or a
// number bucket ('q', "num:50-100").
func stateIn(r *record, name string, kind byte) (string, bool) {
	if kind == 'q' {
		v, ok := r.bucket(name)
		return v.S, ok
	}
	if kind == 0 {
		kind = 's'
	}
	v, ok := r.attr(name)
	if !ok || v.Kind != kind {
		return "", false
	}
	return v.S, true
}

// stateValue is the value an effect writes for state st: the code, the
// boolean, or for a number bucket a number inside it (its lower bound;
// "num:<b" has none: ok is false).
func (e *entity) stateValue(st string) (any, bool) {
	switch e.stateKind {
	case 'b':
		return st == "true", true
	case 'q':
		return bucketValue(st)
	}
	return st, true
}

// literal is stateValue for a literal state (codes and booleans).
func (e *entity) literal(st string) any {
	v, _ := e.stateValue(st)
	return v
}

// literalState reports whether equality on the state is meaningful (where,
// hidden_when): codes and booleans, not number buckets.
func (e *entity) literalState() bool { return e.stateKind != 'q' }

// bucketValue is a number inside a bucket: "num:50-100" → 50, "num:>=250"
// → 250; "num:<0" gives none.
func bucketValue(tok string) (any, bool) {
	s := strings.TrimPrefix(tok, "num:")
	switch {
	case strings.HasPrefix(s, "<"):
		return nil, false
	case strings.HasPrefix(s, ">="):
		s = s[2:]
	default:
		if i := strings.Index(s[1:], "-"); i >= 0 {
			s = s[:i+1]
		}
	}
	if s == "" {
		return nil, false
	}
	if _, err := strconv.ParseFloat(s, 64); err != nil {
		return nil, false
	}
	return json.Number(s), true
}

// parseTimeBucket parses time:YYYY-MM-DD[THH] into its start and width.
func parseTimeBucket(tok string) (time.Time, time.Duration) {
	s := tok[len("time:"):]
	switch len(s) {
	case 13:
		if t, err := time.Parse("2006-01-02T15", s); err == nil {
			return t.UTC(), time.Hour
		}
	case 10:
		if t, err := time.Parse("2006-01-02", s); err == nil {
			return t.UTC(), 24 * time.Hour
		}
	}
	return time.Time{}, 0
}

// byField indexes the objects of the lifecycle's entity by the token of
// one of their fields (shipment.orderId → shipments).
func (lf *lifecycle) byField(m *miner, field string) map[int32][]int32 {
	if idx, ok := lf.fieldIdx[field]; ok {
		return idx
	}
	idx := map[int32][]int32{}
	seen := map[[2]int32]bool{}
	l := m.l
	for ei := range l.evs {
		ev := &l.evs[ei]
		if !ev.ok() {
			continue
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			ent, own, ok := m.recEntity(r)
			if !ok || ent != lf.ent {
				continue
			}
			f, ok := r.id(field)
			if !ok || seen[[2]int32{f.tok, own.tok}] {
				continue
			}
			seen[[2]int32{f.tok, own.tok}] = true
			idx[f.tok] = append(idx[f.tok], own.tok)
		}
	}
	lf.fieldIdx[field] = idx
	return idx
}

// chain returns the states from the initial state to s along the strongest
// predecessors of the lifecycle.
func (lf *lifecycle) chain(s string) []string {
	var rev []string
	seen := map[string]bool{}
	for cur := s; cur != ""; {
		if seen[cur] {
			return nil
		}
		seen[cur] = true
		rev = append(rev, cur)
		if cur == lf.initial {
			break
		}
		best, bn := "", -1
		for _, p := range lf.pred[cur] {
			if n := lf.prec[[2]string{p, cur}]; n > bn || (n == bn && p < best) {
				best, bn = p, n
			}
		}
		if best == "" {
			return nil // not reachable from the initial state
		}
		cur = best
	}
	out := make([]string, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

// edges returns the lifecycle edges reachable from the initial state, in
// breadth-first order (stable).
func (lf *lifecycle) edges() [][2]string {
	var out [][2]string
	seen := map[string]bool{lf.initial: true}
	queue := []string{lf.initial}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		next := append([]string(nil), lf.succ[s]...)
		sort.Slice(next, func(a, b int) bool {
			na, nb := lf.prec[[2]string{s, next[a]}], lf.prec[[2]string{s, next[b]}]
			if na != nb {
				return na > nb
			}
			return next[a] < next[b]
		})
		for _, t := range next {
			// Keep only the edge on the strongest chain into t.
			c := lf.chain(t)
			if len(c) < 2 || c[len(c)-2] != s {
				continue
			}
			out = append(out, [2]string{s, t})
			if !seen[t] {
				seen[t] = true
				queue = append(queue, t)
			}
		}
	}
	return out
}

// magnitude classifies a delay.
func magnitude(d time.Duration) string {
	switch {
	case d < time.Minute:
		return MagSeconds
	case d < time.Hour:
		return MagMinutes
	case d < 24*time.Hour:
		return MagHours
	}
	return MagDays
}

// delayFor proposes a figurative delay from a magnitude (never a measured
// value, decision D1).
func delayFor(mag string) Delay {
	switch mag {
	case MagSeconds:
		return Delay{Min: "1s", Max: "59s"}
	case MagMinutes:
		return Delay{Min: "1m", Max: "59m"}
	case MagHours:
		return Delay{Min: "1h", Max: "23h"}
	}
	return Delay{Min: "1d", Max: "7d"}
}

// edgeMagnitude estimates the order of magnitude of the time spent in a
// before moving to b, from objects observed in both states consecutively.
func (m *miner) edgeMagnitude(lf *lifecycle, a, b string) (string, int) {
	var ds []time.Duration
	for _, o := range lf.objs {
		h := m.hist[o]
		if h == nil {
			continue
		}
		for k := 1; k < len(h.segs); k++ {
			if h.segs[k-1].state != a || h.segs[k].state != b {
				continue
			}
			lo0, hi0, ok0 := h.entry(k - 1)
			lo1, hi1, ok1 := h.entry(k)
			if ok0 && ok1 {
				d := mid(lo1, hi1).Sub(mid(lo0, hi0))
				if d < 0 {
					d = 0
				}
				ds = append(ds, d)
			}
		}
	}
	if len(ds) == 0 {
		return "", 0
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return magnitude(ds[len(ds)/2]), len(ds)
}
