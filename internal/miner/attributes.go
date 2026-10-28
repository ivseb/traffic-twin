package miner

import (
	"sort"
	"strings"
)

// Customer attributes (rules v1.9, rules.md 2.11, C14): a clear member of
// the responses that has one value per user, the same in every response
// (a segment, a plan, a language), with at least two values each seen for
// k_min users. The world gives each synthetic customer a value; the mock
// keeps one per session and writes it wherever the attribute appears;
// conditions (C6) can test it.

// readExtras is what the read-side analytics of one group found: the
// customer attributes with each user's value (used by the conditions).
type readExtras struct {
	attrs []minedAttr
	// byOp indexes the events of each operation (opEvents).
	byOp map[int32][]int32
}

// opEvents returns the events of an operation, in event order.
func (m *miner) opEvents(op int32) []int32 {
	if m.rx == nil {
		m.rx = &readExtras{}
	}
	if m.rx.byOp == nil {
		m.rx.byOp = map[int32][]int32{}
		for i := range m.l.evs {
			o := m.l.evs[i].op
			m.rx.byOp[o] = append(m.rx.byOp[o], int32(i))
		}
	}
	return m.rx.byOp[op]
}

// minedAttr is a mined attribute with the value of each user.
type minedAttr struct {
	def       Attribute
	bySubject map[int32]string
}

type attrKey struct {
	op     int32
	path   string // tt-path of the member: "$.segment", "$.data.me.plan"
	member string
}

type attrObs struct {
	n    int
	vals map[string]int
}

// mineAttributes finds the customer attributes of the group; taken holds
// the attribute names already given (all groups of the run), names are
// added to it.
func (m *miner) mineAttributes(taken map[string]bool) []minedAttr {
	l, cfg := m.l, m.cfg
	// Fields that are states of an entity with a lifecycle change over time:
	// never an attribute of the customer.
	excluded := map[string]bool{}
	for i, e := range m.ents {
		if e.stateField != "" && m.lifes[i] != nil && len(m.lifes[i].succ) > 0 {
			excluded[e.stateField] = true
		}
		excluded[e.idField] = true
	}
	obs := map[attrKey]map[int32]*attrObs{}
	for i := range l.evs {
		ev := &l.evs[i]
		if !ev.ok() || !l.ops[ev.op].read {
			continue
		}
		s := l.subjectOf(int32(i))
		if s < 0 {
			continue
		}
		for _, a := range ev.respState.attrs {
			if (a.val.Kind != 's' && a.val.Kind != 'b') || excluded[a.name] || !reFieldName.MatchString(a.name) || a.val.S == "" || len(a.val.S) > 64 {
				continue
			}
			k := attrKey{ev.op, ev.respState.path + "." + a.name, a.name}
			bs := obs[k]
			if bs == nil {
				bs = map[int32]*attrObs{}
				obs[k] = bs
			}
			o := bs[s]
			if o == nil {
				o = &attrObs{vals: map[string]int{}}
				bs[s] = o
			}
			o.n++
			o.vals[a.val.S]++
		}
	}
	// Candidates: per key, the single value of each user.
	// A primary candidate is seen at least twice for k users with one
	// value each; a secondary one (a member read once per user) only joins
	// a primary one whose values it repeats for k users.
	type cand struct {
		k       attrKey
		val     map[int32]string
		primary bool
	}
	var cands []cand
	keys := make([]attrKey, 0, len(obs))
	for k := range obs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		ka, kb := keys[a], keys[b]
		if ka.member != kb.member {
			return ka.member < kb.member
		}
		oa, ob := l.ops[ka.op], l.ops[kb.op]
		if oa.service+" "+oa.op != ob.service+" "+ob.op {
			return oa.service+" "+oa.op < ob.service+" "+ob.op
		}
		return ka.path < kb.path
	})
	for _, k := range keys {
		bs := obs[k]
		repeated, single := 0, 0
		val := map[int32]string{}
		for s, o := range bs {
			if len(o.vals) == 1 {
				for v := range o.vals {
					val[s] = v
				}
			}
			if o.n >= 2 {
				repeated++
				if len(o.vals) == 1 {
					single++
				}
			}
		}
		primary := repeated >= cfg.KMin && float64(single) >= cfg.MinShare*float64(repeated) && len(keptValues(val, cfg.KMin)) >= 2
		if !primary && (len(val) < cfg.KMin || float64(len(val)) < cfg.MinShare*float64(len(bs))) {
			continue
		}
		cands = append(cands, cand{k, val, primary})
	}
	// Same-named members of several operations are one attribute when the
	// users' values agree.
	parent := make([]int, len(cands))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			x = parent[x]
		}
		return x
	}
	for i := range cands {
		for j := i + 1; j < len(cands); j++ {
			if cands[i].k.member != cands[j].k.member {
				continue
			}
			both, agree := 0, 0
			for s, v := range cands[i].val {
				if w, ok := cands[j].val[s]; ok {
					both++
					if v == w {
						agree++
					}
				}
			}
			need := 1
			if !cands[i].primary || !cands[j].primary {
				need = cfg.KMin
			}
			if both >= need && float64(agree) >= cfg.MinShare*float64(both) {
				if a, b := find(i), find(j); a != b {
					parent[b] = a
				}
			}
		}
	}
	hasPrimary := map[int]bool{}
	for i := range cands {
		if cands[i].primary {
			hasPrimary[find(i)] = true
		}
	}
	var out []minedAttr
	for i := range cands {
		if find(i) != i || !hasPrimary[i] {
			continue
		}
		val := map[int32]string{}
		conflict := map[int32]bool{}
		var fields []AttrField
		for j := range cands {
			if find(j) != i {
				continue
			}
			o := l.ops[cands[j].k.op]
			fields = append(fields, AttrField{Service: o.service, Op: o.op, At: Ref{From: "resp.body", Path: cands[j].k.path}})
			for s, v := range cands[j].val {
				if w, ok := val[s]; ok && w != v {
					conflict[s] = true
				}
				val[s] = v
			}
		}
		for s := range conflict {
			delete(val, s)
		}
		kept := keptValues(val, cfg.KMin)
		if len(kept) < 2 || len(kept) > maxAttrValues {
			continue
		}
		total := 0
		for _, n := range kept {
			total += n
		}
		def := Attribute{Name: attrName(cands[i].k.member, taken), Values: map[string]float64{}, Subjects: total}
		for v, n := range kept {
			def.Values[v] = float64(n) / float64(total)
		}
		roundValueShares(def.Values)
		sort.Slice(fields, func(a, b int) bool {
			fa, fb := fields[a], fields[b]
			if fa.Service+" "+fa.Op != fb.Service+" "+fb.Op {
				return fa.Service+" "+fa.Op < fb.Service+" "+fb.Op
			}
			return fa.At.Path < fb.At.Path
		})
		if len(fields) > maxAttrFields {
			fields = fields[:maxAttrFields]
		}
		def.Fields = fields
		for s, v := range val {
			if _, ok := kept[v]; !ok {
				delete(val, s)
			}
		}
		out = append(out, minedAttr{def: def, bySubject: val})
	}
	return out
}

// keptValues counts the users of each value and keeps the values of at
// least k users.
func keptValues(val map[int32]string, k int) map[string]int {
	n := map[string]int{}
	for _, v := range val {
		n[v]++
	}
	for v, c := range n {
		if c < k {
			delete(n, v)
		}
	}
	return n
}

// roundValueShares rounds shares to 3 decimals keeping the sum at 1.
func roundValueShares(m map[string]float64) {
	keys := sortedKeys(m)
	if len(keys) == 0 {
		return
	}
	sum, big := 0.0, keys[0]
	for _, k := range keys {
		m[k] = float64(int64(m[k]*1000+0.5)) / 1000
		sum += m[k]
		if m[k] > m[big] {
			big = k
		}
	}
	m[big] = float64(int64((m[big]+1-sum)*1000+0.5)) / 1000
}

// attrName turns a member name into an attribute name (lower snake case,
// bind-name grammar), unique among taken.
func attrName(member string, taken map[string]bool) string {
	var b strings.Builder
	for i, c := range member {
		switch {
		case c >= 'A' && c <= 'Z':
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(c - 'A' + 'a')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
			b.WriteRune(c)
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "attr_" + name
	}
	if len(name) > 28 {
		name = name[:28]
	}
	base := name
	for n := 2; taken[name]; n++ {
		name = base + "_" + itoa(n)
	}
	taken[name] = true
	return name
}
