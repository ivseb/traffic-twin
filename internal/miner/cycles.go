package miner

import (
	"sort"
	"time"
)

// Lifecycles with cycles (rules v1.8, C10). The order of the states is
// learned as a precedence (lifecycle.go): a state seen again after a later
// one (ON → OFF → ON, a link that becomes valid again, a retry window that
// closes) is not an edge of that order. Such a return b → a (a comes
// before b in the order) is kept apart, per object history: how many
// objects make it, of how many subjects, how many with no write citing the
// object in between (writtenBetween) and how long b lasted. A return made
// on its own (no write in between for at least MinShare of the objects,
// for at least KMin subjects) becomes an effect of the creation rule:
// back to a, guarded by where on b, after the step into b, with a
// figurative after from the order of magnitude of the median time in b;
// the objects whose last transition is that return form an outcome of
// their own (`<a>-again`). A return made by writes is the update rule of
// that write (updates.go); one that comes back after an update is its
// revert (keyedupdates.go).

// backEdge counts the returns b → a of a lifecycle.
type backEdge struct {
	n, spont int
	subjects map[int32]bool
	ds       []time.Duration
}

// backEdges records the returns of the histories of lf (see above).
func (m *miner) backEdges(lf *lifecycle) {
	for _, o := range lf.objs {
		h := m.hist[o]
		if h == nil {
			continue
		}
		for k := 1; k < len(h.segs); k++ {
			b, a := h.segs[k-1].state, h.segs[k].state
			if !lf.precedes(a, b) {
				continue
			}
			key := [2]string{b, a}
			if lf.back == nil {
				lf.back = map[[2]string]*backEdge{}
			}
			be := lf.back[key]
			if be == nil {
				be = &backEdge{subjects: map[int32]bool{}}
				lf.back[key] = be
			}
			be.n++
			if !m.writtenBetween(o, h.segs[k-1].last, h.segs[k].first) {
				be.spont++
			}
			if s := m.owner[o]; s >= 0 {
				be.subjects[s] = true
			}
			lo0, hi0, ok0 := h.entry(k - 1)
			lo1, hi1, ok1 := h.entry(k)
			if ok0 && ok1 {
				d := mid(lo1, hi1).Sub(mid(lo0, hi0))
				if d < 0 {
					d = 0
				}
				be.ds = append(be.ds, d)
			}
		}
	}
}

// precedes reports whether state a comes before state b in the order of
// the lifecycle (b reachable from a).
func (lf *lifecycle) precedes(a, b string) bool {
	if a == b {
		return false
	}
	seen := map[string]bool{a: true}
	queue := []string{a}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, t := range lf.succ[s] {
			if t == b {
				return true
			}
			if !seen[t] {
				seen[t] = true
				queue = append(queue, t)
			}
		}
	}
	return false
}

// backKeys returns the returns of the lifecycle in a stable order.
func (lf *lifecycle) backKeys() [][2]string {
	out := make([][2]string, 0, len(lf.back))
	for k := range lf.back {
		out = append(out, k)
	}
	sort.Slice(out, func(x, y int) bool {
		if out[x][0] != out[y][0] {
			return out[x][0] < out[y][0]
		}
		return out[x][1] < out[y][1]
	})
	return out
}

// backEffect builds the effect of return key = (b, a) of the lifecycle of
// entity le (its target is set by the caller); ok is false when the return
// is not spontaneous enough, too rare, or b has no step into it.
func (m *miner) backEffect(lf *lifecycle, le int, key [2]string, edgeEffect map[[2]string]string, used map[string]bool) (Effect, bool) {
	be, cfg, e := lf.back[key], m.cfg, m.ents[le]
	b, a := key[0], key[1]
	if be == nil || len(be.subjects) < cfg.KMin || float64(be.spont) < cfg.MinShare*float64(be.n) || !e.literalState() {
		return Effect{}, false
	}
	pc := lf.chain(b)
	if len(pc) < 2 {
		return Effect{}, false
	}
	into := edgeEffect[[2]string{pc[len(pc)-2], pc[len(pc)-1]}]
	if into == "" {
		return Effect{}, false
	}
	sv, ok := e.stateValue(a)
	if !ok {
		return Effect{}, false
	}
	id := slug(e.def.Name) + "-" + slug(a) + "-again"
	if used[id] {
		id = slug(e.def.Name) + "-" + slug(a) + "-again-from-" + slug(b)
	}
	if used[id] || !reIdent.MatchString(id) {
		return Effect{}, false
	}
	return Effect{ID: id, Entity: e.def.Name, Set: map[string]any{e.stateField: sv}, Where: map[string]any{e.stateField: e.literal(b)},
		AfterEffect: into, After: delayFor(backMag(be))}, true
}

// backMag is the order of magnitude of the time spent in b before a
// return (hours when unknown).
func backMag(be *backEdge) string {
	if be == nil || len(be.ds) == 0 {
		return MagHours
	}
	ds := append([]time.Duration(nil), be.ds...)
	sort.Slice(ds, func(x, y int) bool { return ds[x] < ds[y] })
	return magnitude(ds[len(ds)/2])
}
