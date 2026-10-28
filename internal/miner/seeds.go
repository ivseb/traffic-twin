package miner

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Pre-existing entities per user (rules v1.6, C1, "seeds"). Most objects of
// a real application are not created while the traffic is captured: the
// contracts, consents, addresses and notifications of a user exist before,
// and the traffic only reads them. A token domain is a seed entity when:
//
//   - no write ever emits one of its tokens (a domain some write mints is a
//     created entity, or a rejected candidate: never a seed);
//   - successful reads return its tokens as the own id of records ("id",
//     else the only identifier of the record);
//   - those reads are scoped to the owner: in at least 99 % of the
//     observations the object belongs to the requesting subject (the
//     subject its token is seen with, findAliases), for at least KMin
//     subjects;
//   - it is not the identifier of the user itself: one token per subject
//     and per token one subject, carried by requests that list other
//     objects (/customers/{id}/orders).
//
// The entity has no created_by; its read_by, state field, relations and
// lifecycle are found like those of a created entity. Its seed tells how
// many objects each customer has: the distinct objects each subject read,
// in buckets, adjacent buckets merged until each holds at least KMin
// subjects; and the shares of the clear values of its state-like fields
// (each value seen for at least KMin owners).

// EntitySeed is the code of an accepted seed entity (EntityDiag.Code).
const EntitySeed = "seed"

type seedCand struct {
	dom, service, idField, readOp string
	first                         time.Time
	perSubject                    map[int32]map[int32]bool // subject → objects
	empty                         map[int32]bool           // subjects who read an empty list
	objs                          int
}

// seedBuckets are the count buckets before merging.
var seedBuckets = [][2]int{{0, 0}, {1, 1}, {2, 2}, {3, 5}, {6, 10}, {11, 20}, {21, -1}}

// selectSeeds finds the seed entities of the log (see above). It runs after
// selectEntities: the domains it accepts are never seeds.
func (m *miner) selectSeeds() {
	l := m.l
	m.seeds = map[string]*seedCand{}
	born := map[string]bool{}
	for t, b := range m.birth {
		if b.ev >= 0 {
			born[l.tokDom[t]] = true
		}
	}
	type obsKey struct{ dom, field string }
	type obsStat struct {
		toks     map[int32]bool
		ops      map[int32]int
		ok, all  int
		subjects map[int32]map[int32]bool
		first    time.Time
	}
	obs := map[obsKey]*obsStat{}
	listOf := map[string]map[int32]bool{}   // dom → list read ops that returned it
	listArr := map[string]map[string]bool{} // dom → op \x00 array path of those lists
	for ei := range l.evs {
		ev := &l.evs[ei]
		op := &l.ops[ev.op]
		if !op.read || !ev.ok() {
			continue
		}
		s := l.subjectOf(int32(ei))
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side != sideResp {
				continue
			}
			f, ok := seedOwnField(l, r)
			if !ok {
				continue
			}
			dom := l.tokDom[f.tok]
			if dom == "" || dom == "subject" || !reDomain.MatchString(dom) || born[dom] || m.isBest(dom) {
				continue
			}
			k := obsKey{dom, f.name}
			st := obs[k]
			if st == nil {
				st = &obsStat{toks: map[int32]bool{}, ops: map[int32]int{}, subjects: map[int32]map[int32]bool{}, first: ev.ts}
				obs[k] = st
			}
			st.toks[f.tok] = true
			st.ops[ev.op]++
			if strings.HasSuffix(r.path, "[*]") {
				if listOf[dom] == nil {
					listOf[dom] = map[int32]bool{}
				}
				listOf[dom][ev.op] = true
				if listArr[dom] == nil {
					listArr[dom] = map[string]bool{}
				}
				listArr[dom][itoa(int(ev.op))+"\x00"+strings.TrimSuffix(r.path, "[*]")] = true
			}
			if s < 0 {
				continue
			}
			st.all++
			if a, ok := m.alias[f.tok]; ok && a == s {
				st.ok++
			}
			if st.subjects[s] == nil {
				st.subjects[s] = map[int32]bool{}
			}
			st.subjects[s][f.tok] = true
		}
	}
	// One field per domain: the one with most objects ("id" on ties).
	best := map[string]obsKey{}
	for k, st := range obs {
		b, ok := best[k.dom]
		if !ok || len(st.toks) > len(obs[b].toks) || (len(st.toks) == len(obs[b].toks) && (k.field == "id" || (b.field != "id" && k.field < b.field))) {
			best[k.dom] = k
		}
	}
	for _, dom := range sortedKeys(best) {
		k := best[dom]
		st := obs[k]
		d := EntityDiag{Name: dom, Objects: len(st.toks), MinBirthShare: m.cfg.MinBirthShare, Code: EntitySeed}
		var topOp int32 = -1
		for op, n := range st.ops {
			if topOp < 0 || n > st.ops[topOp] || (n == st.ops[topOp] && op < topOp) {
				topOp = op
			}
		}
		o := l.ops[topOp]
		d.Op = o.service + " " + o.op
		switch {
		case len(st.subjects) < m.cfg.KMin:
			continue // too few users to say anything: not even a diagnostic
		case st.all == 0 || float64(st.ok) < 0.99*float64(st.all):
			continue // read by other users: not objects of their owner
		case !reFieldName.MatchString(k.field):
			continue
		case m.isUserReference(dom, st.subjects):
			continue
		}
		c := &seedCand{dom: dom, service: o.service, idField: k.field, readOp: o.op, first: st.first, perSubject: st.subjects,
			empty: map[int32]bool{}, objs: len(st.toks)}
		// Subjects who read an empty list of the domain hold no object.
		for ei := range l.evs {
			ev := &l.evs[ei]
			if !listOf[dom][ev.op] || !ev.ok() {
				continue
			}
			s := l.subjectOf(int32(ei))
			if s < 0 || len(st.subjects[s]) > 0 {
				continue
			}
			for _, a := range ev.arrays {
				if a.n == 0 && listArr[dom][itoa(int(ev.op))+"\x00"+a.path] {
					c.empty[s] = true
				}
			}
		}
		m.seeds[dom] = c
		d.Accepted = true
		d.PreExisting = len(st.toks)
		d.Reason = fmt.Sprintf("objects that exist before the traffic: no write creates them, %d users read their own (%d objects)", len(st.subjects), len(st.toks))
		m.ediag = append(m.ediag, d)
	}
}

// isBest reports whether dom has an accepted creator.
func (m *miner) isBest(dom string) bool {
	_, ok := m.best[dom]
	return ok
}

// seedOwnField is the identifier a record is about: its "id" member, else
// its only identifier.
func seedOwnField(l *Log, r *record) (recField, bool) {
	for _, f := range r.ids {
		if f.name == "id" {
			return f, true
		}
	}
	if len(r.ids) == 1 {
		return r.ids[0], true
	}
	return recField{}, false
}

// isUserReference reports whether dom identifies the users themselves: one
// token per subject and per token one subject, carried by the requests of
// reads that return other objects.
func (m *miner) isUserReference(dom string, subjects map[int32]map[int32]bool) bool {
	owners := map[int32]int32{}
	for s, objs := range subjects {
		if len(objs) != 1 {
			return false
		}
		for t := range objs {
			if o, dup := owners[t]; dup && o != s {
				return false
			}
			owners[t] = s
		}
	}
	l := m.l
	users := map[int32]bool{}
	for ei := range l.evs {
		ev := &l.evs[ei]
		if !ev.ok() {
			continue
		}
		var carried int32 = -1
		for _, t := range ev.toks {
			if l.locs[t.loc].side == sideReq && l.tokDom[t.tok] == dom {
				carried = t.tok
			}
		}
		if carried < 0 {
			continue
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side != sideResp {
				continue
			}
			if f, ok := seedOwnField(l, r); ok && l.tokDom[f.tok] != dom {
				users[owners[carried]] = true
				break
			}
		}
	}
	return len(users) >= m.cfg.KMin
}

// seedOf builds the seed of entity i from its candidate: buckets of the
// objects per subject and the shares of the clear values of its fields.
func (m *miner) seedOf(i int, c *seedCand) *Seed {
	counts := map[int32]int{}
	for s, objs := range c.perSubject {
		counts[s] = len(objs)
	}
	for s := range c.empty {
		counts[s] = 0
	}
	per := make([]int, len(seedBuckets))
	for _, n := range counts {
		for b, r := range seedBuckets {
			if n >= r[0] && (r[1] < 0 || n <= r[1]) {
				per[b]++
				break
			}
		}
	}
	type merged struct {
		lo, hi, n int
	}
	var out []merged
	cur := merged{lo: -1}
	for b, r := range seedBuckets {
		if per[b] == 0 && cur.lo < 0 {
			continue
		}
		if cur.lo < 0 {
			cur.lo = r[0]
		}
		cur.hi = r[1]
		cur.n += per[b]
		if cur.n >= m.cfg.KMin {
			out = append(out, cur)
			cur = merged{lo: -1}
		}
	}
	if cur.lo >= 0 && cur.n > 0 {
		if len(out) == 0 {
			return nil // fewer than KMin subjects in all
		}
		last := &out[len(out)-1]
		last.hi, last.n = cur.hi, last.n+cur.n
	}
	// The last bucket is open: more objects than seen are possible.
	total := 0
	for _, b := range out {
		total += b.n
	}
	seed := &Seed{Subjects: total}
	for _, b := range out {
		var n string
		switch {
		case b.hi < 0:
			n = itoa(b.lo) + "+"
		case b.hi == b.lo:
			n = itoa(b.lo)
		default:
			n = itoa(b.lo) + "-" + itoa(b.hi)
		}
		seed.PerCustomer = append(seed.PerCustomer, SeedBucket{N: n, Share: float64(b.n) / float64(total)})
	}
	roundShares(seed.PerCustomer)
	seed.Values = m.seedValues(i)
	return seed
}

// maxSeedFields bounds the fields whose values a seed describes.
const maxSeedFields = 4

// seedValues are the shares of the clear string values of the fields of a
// seed entity's records that take few values (an enum): the last value seen
// of each object, each value kept only when the objects of at least KMin
// owners had it. The state field comes first.
func (m *miner) seedValues(i int) map[string]map[string]float64 {
	l, e := m.l, m.ents[i]
	last := map[int32]map[string]string{}
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
			for _, a := range r.attrs {
				if a.val.Kind != 's' {
					continue
				}
				if last[own.tok] == nil {
					last[own.tok] = map[string]string{}
				}
				last[own.tok][a.name] = a.val.S
			}
		}
	}
	type fstat struct {
		objs   int
		owners map[string]map[int32]bool
		n      map[string]int
	}
	fs := map[string]*fstat{}
	for o, vals := range last {
		for f, v := range vals {
			st := fs[f]
			if st == nil {
				st = &fstat{owners: map[string]map[int32]bool{}, n: map[string]int{}}
				fs[f] = st
			}
			st.objs++
			st.n[v]++
			if st.owners[v] == nil {
				st.owners[v] = map[int32]bool{}
			}
			st.owners[v][m.owner[o]] = true
		}
	}
	names := sortedKeys(fs)
	if e.stateField != "" {
		sort.SliceStable(names, func(a, b int) bool { return names[a] == e.stateField && names[b] != e.stateField })
	}
	out := map[string]map[string]float64{}
	for _, f := range names {
		st := fs[f]
		if len(out) >= maxSeedFields || !reFieldPath.MatchString(f) || len(st.n) > 8 || len(st.n) < 2 ||
			float64(st.objs) < m.cfg.MinShare*float64(len(last)) {
			continue
		}
		kept, total := map[string]int{}, 0
		for v, n := range st.n {
			if len(st.owners[v]) >= m.cfg.KMin && len(v) <= 256 && !strings.HasPrefix(v, "${") {
				kept[v] = n
				total += n
			}
		}
		if len(kept) == 0 {
			continue
		}
		bs := make([]SeedBucket, 0, len(kept))
		for _, v := range sortedKeys(kept) {
			bs = append(bs, SeedBucket{N: v, Share: float64(kept[v]) / float64(total)})
		}
		roundShares(bs)
		out[f] = map[string]float64{}
		for _, b := range bs {
			out[f][b.N] = b.Share
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// roundShares rounds to 3 decimals keeping the sum at exactly 1.
func roundShares(bs []SeedBucket) {
	if len(bs) == 0 {
		return
	}
	sum, big := 0.0, 0
	for i := range bs {
		bs[i].Share = math.Round(bs[i].Share*1000) / 1000
		sum += bs[i].Share
		if bs[i].Share > bs[big].Share {
			big = i
		}
	}
	bs[big].Share = math.Round((bs[big].Share+1-sum)*1000) / 1000
}
