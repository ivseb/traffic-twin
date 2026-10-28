package miner

import (
	"sort"
	"strconv"
	"time"
)

// Effects on keyed records and values that come back (rules v1.8).
//
// Keyed targets. Wave 2 learned the effects of a write on an object with
// an id; a keyed record (a profile, the consent of a document, rules.md
// 2.9) changed by a write that is not its upserted_by was left to a
// person. Its observations are the answers of its read (the state node of
// each answer, per subject and, for a key with a field, per token of the
// read's selector); its causes are the successful calls of the same
// subject that carry the key token in their request (any token location;
// for a singleton of the user, every call of the user), never its
// upserted_by writes nor the read itself. The changes are then judged
// exactly as for an object with an id (updates.go) and the effect targets
// the record with target_key (the key field bound to where the call
// carries it). Keys of several fields stay manual.
//
// Values that come back (C10). A literal an update sets (SUSPENDED, a
// lock, true) that the object later loses on its own, with no write citing
// it in between (the observations after the change, until the next call of
// the operation or the next write citing the object), becomes a second
// effect: set back to the value it takes (the same for at least MinShare
// of the returns), guarded by where on the value set, after the update,
// with a figurative after from the order of magnitude of the median time
// to return. It needs returns seen for at least KMin subjects, in at least
// MinShare (Wilson lower bound MinBirthShare) of the changes followed long
// enough to tell (observed still set at least that median time after the
// call, or returned).

// keyTarget describes the keyed record an update rule targets.
type keyTarget struct {
	fields []string // the key fields (none: the user's singleton)
}

// mineKeyedUpdates mines the update rules of keyed entity i. Rules v1.9:
// a key of several fields too, each field bound where the call carries
// the token of that field of the record (keyBinds).
func (m *miner) mineKeyedUpdates(i int) []*Mined {
	l, e := m.l, m.ents[i]
	c := e.keyed
	if c == nil {
		return nil
	}
	nf := len(c.fields)
	field := ""
	if nf > 0 {
		field = c.fields[0]
	}
	objOf := map[string]int32{}     // subject and key tokens → object
	keyOf := map[int32][]int32{}    // object → its key tokens, in field order
	byTok := map[[2]int32][]int32{} // (subject, key token) → objects
	obs := map[int32][]upObs{}
	for ei := range l.evs {
		ev := &l.evs[ei]
		if ev.op != c.readOp || !ev.ok() || len(ev.respState.attrs) == 0 {
			continue
		}
		s := l.subjectOf(int32(ei))
		if s < 0 {
			continue
		}
		tks := make([]int32, nf)
		whole := true
		for f, name := range c.fields {
			tks[f] = -1
			ref := c.readRefs[name]
			for _, t := range ev.toks {
				if lc := &l.locs[t.loc]; lc.side == sideReq && lc.refOK && lc.ref == ref {
					tks[f] = t.tok
					break
				}
			}
			whole = whole && tks[f] >= 0
		}
		if !whole {
			continue
		}
		k := recordKey(s, tks)
		o, ok := objOf[k]
		if !ok {
			o = int32(len(objOf))
			objOf[k] = o
			keyOf[o] = tks
			for _, t := range tks {
				byTok[[2]int32{s, t}] = append(byTok[[2]int32{s, t}], o)
			}
		}
		rec := &record{side: sideResp, path: ev.respState.path, attrs: ev.respState.attrs}
		obs[o] = append(obs[o], upObs{rec: rec, ev: int32(ei), own: -1})
	}
	if len(obs) == 0 {
		return nil
	}
	for o := range obs {
		os := obs[o]
		sort.SliceStable(os, func(a, b int) bool { return os[a].at(l).Before(os[b].at(l)) })
	}
	upserts := map[int32]bool{}
	for _, w := range c.writes {
		upserts[w.op] = true
	}
	var insts []upInst
	cites := map[int32][]citation{}
	for wi := range l.evs {
		w := &l.evs[wi]
		op := &l.ops[w.op]
		if !w.ok() || (!op.write && !op.read) || w.op == c.readOp {
			continue
		}
		s := l.subjectOf(int32(wi))
		if s < 0 {
			continue
		}
		var o, tloc int32 = -1, -1
		var klocs []int32
		if field == "" {
			if x, ok := objOf[recordKey(s, nil)]; ok {
				o = x
			}
		} else {
			o, klocs = matchRecord(l, w, s, keyOf, byTok)
			if o >= 0 {
				tloc = klocs[0]
			}
		}
		if o < 0 {
			continue
		}
		cites[o] = append(cites[o], citation{int32(wi), w.op, op.write || upserts[w.op]})
		if upserts[w.op] {
			continue // the record's own writes (rules.md 2.9)
		}
		in := upInst{ev: int32(wi), op: w.op, obj: o, loc: tloc, subj: s}
		if nf > 1 {
			in.klocs = klocs
		}
		insts = append(insts, in)
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
	var out []*Mined
	kt := &keyTarget{fields: c.fields}
	for _, op := range ops {
		n := len(m.rdiag)
		mm := m.updateRule(i, op, insts, byOp[op], obs, cites, kt)
		if mm == nil && field == "" {
			// Every call of the user is a candidate cause of its
			// singleton: the calls that explain nothing are not worth a
			// diagnostic each.
			m.rdiag = m.rdiag[:n]
		}
		if mm != nil {
			out = append(out, mm)
		}
	}
	return out
}

// revert is a value an update set that comes back on its own.
type revert struct {
	value any
	mag   string
}

// revertOf finds whether the literal field fe set by the calls insts of op
// comes back on its own (see the top of the file); nil when not.
func (m *miner) revertOf(fe *upField, insts []upInst, obs map[int32][]upObs, cites map[int32][]citation, op int32) *revert {
	if fe.kind != "literal" {
		return nil
	}
	var want Value
	switch v := fe.value.(type) {
	case string:
		want = Value{Kind: 's', S: v}
	case bool:
		want = Value{Kind: 'b', S: strconv.FormatBool(v)}
	default:
		return nil // a number set from a bucket is never compared for equality
	}
	l, cfg := m.l, m.cfg
	type ret struct {
		d    time.Duration
		x    Value
		subj int32
	}
	var rets []ret
	var holds []time.Duration
	for _, in := range insts {
		w := &l.evs[in.ev]
		os := obs[in.obj]
		var end time.Time
		cs := cites[in.obj]
		for c := sort.Search(len(cs), func(x int) bool { return cs[x].ev > in.ev }); c < len(cs); c++ {
			if cs[c].op == op || cs[c].write {
				end = l.evs[cs[c].ev].ts
				break
			}
		}
		seen, done := false, false
		var lastSet time.Time
		for x := sort.Search(len(os), func(x int) bool { return !os[x].start(l).Before(w.end) }); x < len(os); x++ {
			if !end.IsZero() && !os[x].start(l).Before(end) {
				break
			}
			if os[x].rootOf(l) == w.root {
				continue
			}
			v, ok := os[x].val(l, fe.field)
			if !ok {
				continue
			}
			if !seen {
				if v != want {
					break // the change was not seen first: nothing to follow
				}
				seen, lastSet = true, os[x].at(l)
				continue
			}
			if v == want {
				lastSet = os[x].at(l)
				continue
			}
			rets = append(rets, ret{d: mid(lastSet, os[x].start(l)).Sub(w.ts), x: v, subj: in.subj})
			done = true
			break
		}
		if seen && !done {
			holds = append(holds, lastSet.Sub(w.ts))
		}
	}
	if len(rets) < cfg.KMin {
		return nil
	}
	subj := map[int32]bool{}
	xs := map[string]int{}
	vals := map[string]Value{}
	ds := make([]time.Duration, 0, len(rets))
	for _, r := range rets {
		if r.subj >= 0 {
			subj[r.subj] = true
		}
		xs[valKey(r.x)]++
		vals[valKey(r.x)] = r.x
		ds = append(ds, r.d)
	}
	top := argmax(xs)
	if len(subj) < cfg.KMin || float64(xs[top]) < cfg.MinShare*float64(len(rets)) {
		return nil
	}
	x := vals[top]
	if x.Kind != want.Kind || x == want {
		return nil
	}
	sort.Slice(ds, func(a, b int) bool { return ds[a] < ds[b] })
	med := ds[len(ds)/2]
	judged := len(rets)
	for _, h := range holds {
		if h >= med {
			judged++
		}
	}
	if float64(len(rets)) < cfg.MinShare*float64(judged) || wilsonLow(len(rets), judged) < cfg.MinBirthShare {
		return nil
	}
	lit, ok := literalOf(x)
	if !ok {
		return nil
	}
	return &revert{value: lit, mag: magnitude(med)}
}
