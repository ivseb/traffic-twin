package miner

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Objects that appear later, outside the trace (rules v1.8, C9). A ticket
// opened for a request, a contract issued for an application, the final
// order that replaces a provisional one: an object B no captured write
// mints (so a seed candidate, seeds.go) is first seen in a read, some time
// after another object A was created, and its record cites A's id. The
// creation of A is then the cause of B: its rule gets an effect
// `create B {<field>: "${a}"}` with a figurative delay, although B is
// minted outside the cause's trace (the nested creations of causal.go only
// see the calls made while serving the cause). B is accepted as such when:
//
//   - at least MinShare of B's objects cite an object of A in one field
//     (one of B's relations to an entity with a creator);
//   - the B objects that cite an A created in the window come from at least
//     KMin subjects, and appear after A's creation;
//   - at least MinBirthShare of the creations of A whose user could tell
//     (a list of B read by the same user late enough: at least the first
//     quartile of the times B took to appear) got their B.
//
// B then has no seed: its objects come from the creations of A, in the
// world as in the mock. The delay is figurative (decision D1): when, for at
// least KMin subjects and 1 − MinShare of the objects, a list of B read
// after the creation did not show B yet, from the order of magnitude of the
// median time to appear; otherwise 0s. Constant values of B at first sight
// (a status) go into the creation.
//
// "A hidden when B exists": when, once B appeared, A is gone for the user
// (the next list of A no longer returns it, or a read by id answers 404 or
// 410, as for a removal) for at least KMin subjects and MinShare of the
// pairs that could tell, and A was seen before B appeared for at least
// KMin subjects, the rule also removes A after B is created (a provisional
// id replaced by the final one). B citing only its user stays a seed.

// EntityLater is the code of an entity whose objects appear later, created
// by the rule of another one (EntityDiag.Code).
const EntityLater = "later"

// laterChild is an entity whose objects appear later for the creations of
// another one.
type laterChild struct {
	ent      int
	field    string
	fieldLoc int32
	byCause  map[int32]int32 // creation event of A → object of B
	after    Delay
	mag      string
	create   map[string]any
	replace  bool
	matches  int
}

// findLater finds the entities whose objects appear later (see above). It
// runs once the relations and the reads of every entity are known, before
// the seeds are summarized.
func (m *miner) findLater() {
	byName := map[string]int{}
	for i, e := range m.ents {
		byName[e.def.Name] = i
	}
	for bi, be := range m.ents {
		if be.seed == nil {
			continue
		}
		for _, rel := range be.def.Relations {
			ai, ok := byName[rel.Entity]
			if !ok || rel.Many || ai == bi || m.ents[ai].creatorOp < 0 {
				continue
			}
			lc := m.laterOf(bi, ai, rel.Field)
			if lc == nil {
				continue
			}
			if m.later == nil {
				m.later = map[int][]*laterChild{}
			}
			m.later[ai] = append(m.later[ai], lc)
			be.seed = nil
			for k := range m.ediag {
				if d := &m.ediag[k]; d.Accepted && d.Name == be.def.Name && d.Code == EntitySeed {
					d.Code = EntityLater
					d.Reason = fmt.Sprintf("objects that appear later, outside the trace: created by %s of %s (%d of them seen)",
						m.l.ops[m.ents[ai].creatorOp].op, m.ents[ai].def.Name, lc.matches)
				}
			}
			break
		}
	}
}

// bSight is the first sighting of an object of B.
type bSight struct {
	ev  int32
	at  time.Time
	a   int32 // the A object it cites, -1
	loc int32
	rec *record
}

// laterOf judges whether the objects of entity bi appear later for the
// creations of entity ai, through field (see the top of the file).
func (m *miner) laterOf(bi, ai int, field string) *laterChild {
	l, cfg := m.l, m.cfg
	ae := m.ents[ai]
	first := map[int32]*bSight{}
	var order []int32
	for ei := range l.evs {
		ev := &l.evs[ei]
		if !ev.ok() {
			continue
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			ent, own, ok := m.recEntity(r)
			if !ok || ent != bi {
				continue
			}
			s := first[own.tok]
			if s == nil {
				s = &bSight{ev: int32(ei), at: ev.at(r.side), a: -1, loc: -1, rec: r}
				first[own.tok] = s
				order = append(order, own.tok)
			}
			if s.a < 0 {
				if f, ok := r.id(field); ok && m.entityOf(f.tok) == ai {
					s.a, s.loc = f.tok, f.loc
				}
			}
		}
	}
	withRel := 0
	for _, b := range order {
		if first[b].a >= 0 {
			withRel++
		}
	}
	if len(order) == 0 || float64(withRel) < cfg.MinShare*float64(len(order)) {
		return nil
	}
	// The objects of B citing an A created in the window, after it.
	lc := &laterChild{ent: bi, field: field, byCause: map[int32]int32{}}
	subjects := map[int32]bool{}
	var linked []int32
	var delays []time.Duration
	locN := map[int32]int{}
	for _, b := range order {
		s := first[b]
		if s.a < 0 {
			continue
		}
		bt := m.birth[s.a]
		if bt.ev < 0 || bt.loc != ae.creatorLoc {
			continue
		}
		cev := &l.evs[bt.ev]
		if !s.at.After(cev.end) || l.evs[s.ev].root == cev.root {
			continue // seen with the creation itself: not later
		}
		if _, dup := lc.byCause[bt.ev]; dup {
			continue
		}
		lc.byCause[bt.ev] = b
		linked = append(linked, b)
		delays = append(delays, s.at.Sub(cev.ts))
		locN[s.loc]++
		if sub := l.subjectOf(bt.ev); sub >= 0 {
			subjects[sub] = true
		}
	}
	if len(subjects) < cfg.KMin {
		return nil
	}
	sort.Slice(delays, func(x, y int) bool { return delays[x] < delays[y] })
	early := delays[len(delays)/4] // a list read this late could show B
	lists, _ := m.readOps(bi)
	if len(lists) == 0 {
		return nil
	}
	// Coverage: the creations whose user read a list of B late enough.
	observable := 0
	for t, bt := range m.birth {
		if bt.ev < 0 || bt.loc != ae.creatorLoc || m.entityOf(int32(t)) != ai {
			continue
		}
		if _, ok := lc.byCause[bt.ev]; ok {
			observable++
			continue
		}
		s := l.subjectOf(bt.ev)
		if s < 0 {
			continue
		}
		from := l.evs[bt.ev].ts.Add(early)
		evs := m.subjectEvents(s)
		for _, j := range evs[sort.Search(len(evs), func(x int) bool { return evs[x] > bt.ev }):] {
			ev := &l.evs[j]
			if lists[ev.op] && ev.ok() && !ev.end.Before(from) && ev.root != l.evs[bt.ev].root {
				observable++
				break
			}
		}
	}
	if observable == 0 || float64(len(linked)) < cfg.MinBirthShare*float64(observable) {
		return nil
	}
	lc.matches = len(linked)
	lc.fieldLoc = -1
	for lcx, n := range locN {
		if lc.fieldLoc < 0 || n > locN[lc.fieldLoc] || (n == locN[lc.fieldLoc] && lcx < lc.fieldLoc) {
			lc.fieldLoc = lcx
		}
	}
	// Delay: a list of B read by the user after the creation and before B
	// showed up.
	var stale []time.Duration
	staleSubj := map[int32]bool{}
	for cause, b := range lc.byCause {
		s := first[b]
		sub := l.subjectOf(cause)
		if sub < 0 {
			continue
		}
		var lastNeg time.Time
		evs := m.subjectEvents(sub)
		for _, j := range evs[sort.Search(len(evs), func(x int) bool { return evs[x] > cause }):] {
			ev := &l.evs[j]
			if !ev.ts.Before(s.at) {
				break
			}
			if lists[ev.op] && ev.ok() && ev.root != l.evs[cause].root {
				lastNeg = ev.end
			}
		}
		if !lastNeg.IsZero() {
			stale = append(stale, mid(lastNeg, s.at).Sub(l.evs[cause].ts))
			staleSubj[sub] = true
		}
	}
	lc.after, lc.mag = Delay{Single: "0s"}, MagSeconds
	if len(staleSubj) >= cfg.KMin && float64(len(stale)) >= (1-cfg.MinShare)*float64(len(linked)) {
		sort.Slice(stale, func(x, y int) bool { return stale[x] < stale[y] })
		lc.mag = magnitude(stale[len(stale)/2])
		lc.after = delayFor(lc.mag)
	}
	// Constant values at first sight.
	present := map[string]int{}
	vals := map[string]map[string]int{}
	seen := map[string]Value{}
	for _, b := range linked {
		for _, a := range first[b].rec.attrs {
			present[a.name]++
			if vals[a.name] == nil {
				vals[a.name] = map[string]int{}
			}
			vals[a.name][valKey(a.val)]++
			seen[a.name+"\x00"+valKey(a.val)] = a.val
		}
	}
	lc.create = map[string]any{}
	for _, name := range sortedKeys(present) {
		if name == field || float64(present[name]) < cfg.MinShare*float64(len(linked)) || len(vals[name]) != 1 || !reFieldPath.MatchString(name) {
			continue
		}
		for k := range vals[name] {
			lc.create[name] = seen[name+"\x00"+k].Any()
		}
	}
	// A hidden when B exists.
	alists, abyID := m.readOps(ai)
	gone, present2 := 0, 0
	goneSubj, beforeSubj := map[int32]bool{}, map[int32]bool{}
	for cause, b := range lc.byCause {
		s := first[b]
		sub := l.subjectOf(cause)
		if sub < 0 {
			continue
		}
		if m.seenBefore(first[b].a, cause, s.at) {
			beforeSubj[sub] = true
		}
		switch v, _ := m.afterWrite(s.ev, sub, first[b].a, ai, alists, abyID); v {
		case 1:
			gone++
			goneSubj[sub] = true
		case -1:
			present2++
		}
	}
	lc.replace = len(goneSubj) >= cfg.KMin && len(beforeSubj) >= cfg.KMin && float64(gone) >= cfg.MinShare*float64(gone+present2)
	return lc
}

// readOps returns the list reads and the by-id reads of entity i.
func (m *miner) readOps(i int) (map[int32]bool, map[int32]*Ref) {
	l, e := m.l, m.ents[i]
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
	return lists, byID
}

// seenBefore reports whether object tok was returned by a read outside the
// trace of event cause, before instant t.
func (m *miner) seenBefore(tok, cause int32, t time.Time) bool {
	l := m.l
	for _, o := range l.occ[tok] {
		ev := &l.evs[o.ev]
		if !ev.ts.Before(t) {
			return false
		}
		if ev.root != l.evs[cause].root && ev.ok() && l.locs[o.loc].side == sideResp && l.ops[ev.op].read {
			return true
		}
	}
	return false
}
