package miner

import (
	"sort"
	"strconv"
	"strings"
)

// Aggregates (rules v1.9, rules.md 2.12, C8): a number of a response (in
// clear or as a bucket) that is, for the user who reads it, the count of
// their objects of an entity (optionally in one clear state) or the sum of
// a clear numeric field of those objects, as their latest list read of the
// entity shows them with no write of theirs in between; or a counter that
// moves by a fixed step at every successful call of some writes. The mock
// computes it at read time.

// maxAggBack bounds how far back the latest list read is looked for.
const maxAggBack = 200

type numMember struct {
	path string
	val  Value // 'n' a number, 'q' a bucket
}

// numMembers are the numbers of an answer: the root, list envelopes and
// the state node (rules v1.9 also its buckets).
func (l *Log) numMembers(i int32) []numMember {
	ev := &l.evs[i]
	x := l.extra[i]
	if len(ev.nums) == 0 && (x == nil || len(x.nums) == 0) {
		has := false
		for _, a := range ev.respState.attrs {
			has = has || a.val.Kind == 'n'
		}
		if !has {
			return nil
		}
	}
	var out []numMember
	add := func(p string, v Value) {
		for _, o := range out {
			if o.path == p {
				return
			}
		}
		if reTTPath.MatchString(p) && !strings.Contains(p, "[*]") {
			out = append(out, numMember{p, v})
		}
	}
	for _, a := range ev.nums {
		add("$."+a.name, a.val)
	}
	for _, a := range ev.respState.attrs {
		if a.val.Kind == 'n' {
			add(ev.respState.path+"."+a.name, a.val)
		}
	}
	if x != nil {
		for _, a := range x.nums {
			add(ev.respState.path+"."+a.name, a.val)
		}
	}
	return out
}

// numEquals compares a member with a computed number.
func numEquals(v Value, n float64) bool {
	if v.Kind == 'q' {
		return numInBucket(n, v.S)
	}
	f, err := strconv.ParseFloat(v.S, 64)
	return err == nil && f == n
}

// listSnap is what a list read of an entity says of the user's objects.
type listSnap struct {
	n      int
	states map[string]int
	sums   map[string]float64
}

type aggList struct {
	ent   int
	op    int32
	items string
	count string // the list's own count member ("$.count"), skipped
}

type aggFormula struct {
	list  int // index in lists
	kind  byte
	state string // count/sum where the state equals it ("": all)
	field string // sum field
}

type aggTally struct {
	comparable, match int
	users             map[int32]bool
	vals              map[string]bool
}

func (m *miner) snapOf(i int32, al aggList) listSnap {
	e := m.ents[al.ent]
	sn := listSnap{states: map[string]int{}, sums: map[string]float64{}}
	ev := &m.l.evs[i]
	for ri := range ev.recs {
		r := &ev.recs[ri]
		if r.side != sideResp || r.path != al.items {
			continue
		}
		if ent, _, ok := m.recEntity(r); !ok || ent != al.ent {
			continue
		}
		sn.n++
		if e.stateField != "" && e.literalState() {
			if v, ok := stateIn(r, e.stateField, e.stateKind); ok {
				sn.states[v]++
			}
		}
		for _, a := range r.attrs {
			if a.val.Kind == 'n' && reFieldName.MatchString(a.name) {
				if f, err := strconv.ParseFloat(a.val.S, 64); err == nil {
					sn.sums[a.name] += f
				}
			}
		}
	}
	return sn
}

// mineAggregates finds the aggregates of the group.
func (m *miner) mineAggregates() []Aggregate {
	l, cfg := m.l, m.cfg
	var lists []aggList
	listOps := map[int32][]int{}
	for i, e := range m.ents {
		for _, rb := range e.def.ReadBy {
			if !strings.HasSuffix(rb.At.Path, "[*]") || (rb.By != nil && !rb.By.Owner) || rb.Key != nil {
				continue
			}
			svc := rb.Service
			if svc == "" {
				svc = e.def.Service
			}
			op, ok := l.opIdx[[2]string{svc, rb.Op}]
			if !ok {
				continue
			}
			al := aggList{ent: i, op: op, items: rb.At.Path}
			if rb.List != nil {
				al.count = rb.List.Count
			}
			listOps[op] = append(listOps[op], len(lists))
			lists = append(lists, al)
		}
	}
	tallies := map[aggMem]map[aggFormula]*aggTally{}
	formulas := map[aggMem][]aggFormula{}
	tally := func(mk aggMem, f aggFormula) *aggTally {
		if tallies[mk] == nil {
			tallies[mk] = map[aggFormula]*aggTally{}
		}
		t := tallies[mk][f]
		if t == nil {
			t = &aggTally{users: map[int32]bool{}, vals: map[string]bool{}}
			tallies[mk][f] = t
			formulas[mk] = append(formulas[mk], f)
		}
		return t
	}
	var mems []aggMem
	seenMem := map[aggMem]bool{}
	if len(lists) == 0 {
		return m.mineDeltas(map[aggMem]bool{})
	}
	for s := range l.subj {
		evs := m.subjectEvents(s)
		snaps := map[[2]int32]listSnap{} // per user: the lists a user's reads refer to
		for pos, i := range evs {
			ev := &l.evs[i]
			if !ev.ok() || !l.ops[ev.op].read {
				continue
			}
			nums := l.numMembers(i)
			if len(nums) == 0 {
				continue
			}
			for li, al := range lists {
				var src int32 = -1
				own := ev.op == al.op
				if own {
					src = i
				} else {
					for back := pos - 1; back >= 0 && pos-back <= maxAggBack; back-- {
						j := evs[back]
						pe := &l.evs[j]
						if pe.ok() && l.ops[pe.op].write {
							break
						}
						if pe.op == al.op && pe.ok() {
							src = j
							break
						}
					}
				}
				if src < 0 {
					continue
				}
				ck := [2]int32{src, int32(li)}
				sn, ok := snaps[ck]
				if !ok {
					sn = m.snapOf(src, al)
					snaps[ck] = sn
				}
				for _, nm := range nums {
					if own && (nm.path == al.count || isLenOf(ev, nm)) {
						continue
					}
					mk := aggMem{ev.op, nm.path}
					if !seenMem[mk] {
						seenMem[mk] = true
						mems = append(mems, mk)
					}
					cands := []aggFormula{{list: li, kind: 'c'}}
					for _, st := range sortedKeys(sn.states) {
						cands = append(cands, aggFormula{list: li, kind: 'c', state: st})
					}
					for _, f := range sortedKeys(sn.sums) {
						cands = append(cands, aggFormula{list: li, kind: 's', field: f})
					}
					for _, f := range cands {
						if own && f.kind == 'c' && f.state == "" {
							continue // the list's own length: list.count
						}
						var x float64
						switch {
						case f.kind == 'c' && f.state == "":
							x = float64(sn.n)
						case f.kind == 'c':
							x = float64(sn.states[f.state])
						default:
							x = sn.sums[f.field]
						}
						t := tally(mk, f)
						t.comparable++
						if numEquals(nm.val, x) {
							t.match++
							t.users[s] = true
							t.vals[nm.val.S] = true
						}
					}
				}
			}
		}
	}
	sort.Slice(mems, func(a, b int) bool {
		oa, ob := l.ops[mems[a].op], l.ops[mems[b].op]
		if oa.service+" "+oa.op != ob.service+" "+ob.op {
			return oa.service+" "+oa.op < ob.service+" "+ob.op
		}
		return mems[a].path < mems[b].path
	})
	var out []Aggregate
	done := map[aggMem]bool{}
	for _, mk := range mems {
		var best *aggFormula
		var bt *aggTally
		for k := range formulas[mk] {
			f := formulas[mk][k]
			t := tallies[mk][f]
			if float64(t.match) < cfg.MinShare*float64(t.comparable) || len(t.users) < cfg.KMin || len(t.vals) < 2 {
				continue
			}
			if bt == nil || t.match > bt.match {
				best, bt = &formulas[mk][k], t
			}
		}
		if best == nil {
			continue
		}
		o := l.ops[mk.op]
		al := lists[best.list]
		e := m.ents[al.ent]
		g := Aggregate{Service: o.service, Op: o.op, At: Ref{From: "resp.body", Path: mk.path}, Subjects: len(bt.users)}
		var where map[string]any
		if best.state != "" {
			where = map[string]any{e.stateField: stateValue(best.state, e.stateKind)}
		}
		if best.kind == 'c' {
			g.Count = &AggCount{Entity: e.def.Name, Where: where}
		} else {
			g.Sum = &AggSum{Entity: e.def.Name, Field: best.field, Where: where}
		}
		done[mk] = true
		out = append(out, g)
	}
	out = append(out, m.mineDeltas(done)...)
	if len(out) > maxDocAggregates {
		out = out[:maxDocAggregates]
	}
	return out
}

// isLenOf reports whether a member is the length of an array of the same
// answer (a list envelope count, not an aggregate).
func isLenOf(ev *evt, nm numMember) bool {
	if nm.val.Kind != 'n' {
		return false
	}
	for _, a := range ev.arrays {
		if nm.val.S == itoa(a.n) {
			return true
		}
	}
	return false
}

// stateValue types a state value for a where (boolean states as booleans).
func stateValue(s string, kind byte) any {
	if kind == 'b' {
		return s == "true"
	}
	return s
}

// aggMem is a numeric member of the answers of an operation.
type aggMem struct {
	op   int32
	path string
}

// mineDeltas finds counters: a number of a read that, between two reads
// of the same user, moves by a fixed step per successful call of a write
// (one write operation in between) and does not move without writes.
func (m *miner) mineDeltas(done map[aggMem]bool) []Aggregate {
	l, cfg := m.l, m.cfg
	type stepKey struct {
		w    int32
		step int
	}
	type dt struct {
		zero, zeroOK int
		pairs        map[int32]int
		steps        map[stepKey]int
		users        map[stepKey]map[int32]bool
		vals         map[string]bool
	}
	ts := map[aggMem]*dt{}
	type prevRead struct {
		pos int
		v   float64
	}
	for s := range l.subj {
		evs := m.subjectEvents(s)
		prev := map[aggMem]prevRead{}
		for pos, i := range evs {
			ev := &l.evs[i]
			if !ev.ok() || !l.ops[ev.op].read {
				continue
			}
			for _, nm := range l.numMembers(i) {
				mk := aggMem{ev.op, nm.path}
				if nm.val.Kind != 'n' || done[mk] || isLenOf(ev, nm) {
					continue
				}
				v, err := strconv.ParseFloat(nm.val.S, 64)
				if err != nil || v != float64(int64(v)) {
					continue
				}
				p, had := prev[mk]
				prev[mk] = prevRead{pos, v}
				if !had || pos-p.pos > maxAggBack {
					continue
				}
				t := ts[mk]
				if t == nil {
					t = &dt{pairs: map[int32]int{}, steps: map[stepKey]int{}, users: map[stepKey]map[int32]bool{}, vals: map[string]bool{}}
					ts[mk] = t
				}
				t.vals[nm.val.S] = true
				writes := map[int32]int{}
				for _, j := range evs[p.pos+1 : pos] {
					if we := &l.evs[j]; we.ok() && l.ops[we.op].write {
						writes[we.op]++
					}
				}
				d := int(v - p.v)
				switch len(writes) {
				case 0:
					t.zero++
					if d == 0 {
						t.zeroOK++
					}
				case 1:
					for w, c := range writes {
						t.pairs[w]++
						if d%c == 0 && d != 0 {
							k := stepKey{w, d / c}
							t.steps[k]++
							if t.users[k] == nil {
								t.users[k] = map[int32]bool{}
							}
							t.users[k][s] = true
						}
					}
				}
			}
		}
	}
	keys := make([]aggMem, 0, len(ts))
	for k := range ts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		oa, ob := l.ops[keys[a].op], l.ops[keys[b].op]
		if oa.service+" "+oa.op != ob.service+" "+ob.op {
			return oa.service+" "+oa.op < ob.service+" "+ob.op
		}
		return keys[a].path < keys[b].path
	})
	var out []Aggregate
	for _, mk := range keys {
		t := ts[mk]
		if len(t.vals) < 2 || (t.zero > 0 && float64(t.zeroOK) < cfg.MinShare*float64(t.zero)) {
			continue
		}
		o := l.ops[mk.op]
		g := Aggregate{Service: o.service, Op: o.op, At: Ref{From: "resp.body", Path: mk.path}}
		users := map[int32]bool{}
		for _, w := range sortedOps(t.pairs, l) {
			var best stepKey
			bn := 0
			for k, n := range t.steps {
				if k.w == w && (n > bn || (n == bn && k.step < best.step)) {
					best, bn = k, n
				}
			}
			if bn == 0 || float64(bn) < cfg.MinShare*float64(t.pairs[w]) || len(t.users[best]) < cfg.KMin || best.step < -1000 || best.step > 1000 {
				continue
			}
			wo := l.ops[w]
			dl := AggDelta{Op: wo.op, By: best.step}
			if wo.service != o.service {
				dl.Service = wo.service
			}
			g.Delta = append(g.Delta, dl)
			for u := range t.users[best] {
				users[u] = true
			}
		}
		if len(g.Delta) == 0 || len(g.Delta) > maxDeltas {
			continue
		}
		g.Subjects = len(users)
		out = append(out, g)
	}
	return out
}

// sortedOps lists the operations of a map in "service op" order.
func sortedOps(m map[int32]int, l *Log) []int32 {
	out := make([]int32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool {
		oa, ob := l.ops[out[a]], l.ops[out[b]]
		return oa.service+" "+oa.op < ob.service+" "+ob.op
	})
	return out
}
