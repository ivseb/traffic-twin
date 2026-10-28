package miner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Keyed state without an id (rules v1.6, C3). A profile, a cart, the
// consents of a user, the acknowledgement of a document: records that have
// no identifier of their own, read per user (GET /me/profile) or per a
// tuple of request selectors (GET /consents/{documentId}), and replaced by
// writes with the same key (PUT /me/profile, POST /consents). They become
// entities with a key instead of an id:
//
//   - a read candidate is a read whose answer has clear values in its state
//     node (stateNode) and is not the record of an entity with an id;
//   - a write candidate is a write that creates nothing and sends clear
//     values;
//   - a write W and a later read R by the same subject form a pair; with
//     the owner key every R pairs with the subject's last W, with a selector
//     key (a request token of R equal to a request token of W) only with
//     the last W that sent the same token;
//   - a pair is consistent when the members W sent and R returns under the
//     same names (at least one) are all equal;
//   - a key is accepted for (W, R) when its consistent pairs come from at
//     least KMin subjects, are at least MinShare of its pairs and show at
//     least two different values (a constant proves nothing). Selector keys
//     win over the owner key: their selectors are the key fields.
//
// The entity's read_by selects with key (field → request parameter), its
// upserted_by give the writes with their key and the request part copied
// into the state.

// EntityKeyed is the code of an accepted keyed entity (EntityDiag.Code).
const EntityKeyed = "keyed"

type keyedWrite struct {
	op       int32
	refs     map[string]Ref // key field → request ref of the write
	state    string         // tt-path of the request state node
	subjects int
}

type keyedCand struct {
	name, service string
	readOp        int32
	statePath     string
	fields        []string
	readRefs      map[string]Ref
	writes        []keyedWrite
	first         time.Time
}

type pairKey struct {
	w, r   int32 // operations
	wl, rl int32 // request locations of the selector, -1 for the owner key
}

type pairStat struct {
	pairs, consistent int
	subjects          map[int32]bool
	values            map[string]bool
	first             time.Time
}

// selectKeyed finds the keyed entities of the log (see above). It runs after
// selectEntities and selectSeeds.
func (m *miner) selectKeyed() {
	l := m.l
	entDom := func(d string) bool { return m.isBest(d) || m.seeds[d] != nil }
	// The id field of each entity with an id: a record that holds an
	// entity's id under that name is the entity's, whatever else it holds.
	idField := map[string]string{}
	creators := map[int32]bool{}
	for d, lc := range m.best {
		creators[l.locs[lc].op] = true
		if ps := splitTTPath(l.locs[lc].ref.Path); len(ps) > 0 {
			idField[d] = ps[len(ps)-1]
		}
	}
	for d, c := range m.seeds {
		idField[d] = c.idField
	}
	isR := func(i int) bool {
		ev := &l.evs[i]
		if !l.ops[ev.op].read || !ev.ok() || l.subjectOf(int32(i)) < 0 || len(ev.respState.attrs) == 0 {
			return false
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side == sideResp && strings.HasPrefix(r.path, ev.respState.path) {
				if f, ok := seedOwnField(l, r); ok && entDom(l.tokDom[f.tok]) {
					return false // the record of an entity with an id
				}
				for _, f := range r.ids {
					if d := l.tokDom[f.tok]; entDom(d) && idField[d] == f.name {
						return false
					}
				}
			}
		}
		return true
	}
	isW := func(i int) bool {
		ev := &l.evs[i]
		return l.ops[ev.op].write && ev.ok() && !creators[ev.op] && l.subjectOf(int32(i)) >= 0 && len(ev.reqState.attrs) > 0
	}
	type wAt struct {
		ev int32
		lc int32
	}
	lastW := map[int32]map[int32]int32{}            // subject → write op → event
	lastWTok := map[int32]map[int32]map[int32]wAt{} // subject → write op → token → event
	stats := map[pairKey]*pairStat{}
	record := func(k pairKey, w, r int32, s int32) {
		common, ok, sig := compareState(&l.evs[w].reqState, &l.evs[r].respState)
		if common == 0 {
			return
		}
		st := stats[k]
		if st == nil {
			st = &pairStat{subjects: map[int32]bool{}, values: map[string]bool{}, first: l.evs[r].ts}
			stats[k] = st
		}
		st.pairs++
		if ok {
			st.consistent++
			st.subjects[s] = true
			st.values[sig] = true
		}
	}
	for i := range l.evs {
		r, w := isR(i), isW(i)
		if !r && !w {
			continue
		}
		ev := &l.evs[i]
		s := l.subjectOf(int32(i))
		if r {
			for wop, we := range lastW[s] {
				if !l.evs[we].end.After(ev.ts) {
					record(pairKey{wop, ev.op, -1, -1}, we, int32(i), s)
				}
			}
			for _, t := range ev.toks {
				if lc := &l.locs[t.loc]; lc.side != sideReq || !lc.refOK || (lc.ref.Path != "" && !keyRefOK(lc.ref)) {
					continue
				}
				for wop, byTok := range lastWTok[s] {
					if wa, ok := byTok[t.tok]; ok && !l.evs[wa.ev].end.After(ev.ts) {
						record(pairKey{wop, ev.op, wa.lc, t.loc}, wa.ev, int32(i), s)
					}
				}
			}
		}
		if w {
			if lastW[s] == nil {
				lastW[s] = map[int32]int32{}
				lastWTok[s] = map[int32]map[int32]wAt{}
			}
			lastW[s][ev.op] = int32(i)
			if lastWTok[s][ev.op] == nil {
				lastWTok[s][ev.op] = map[int32]wAt{}
			}
			for _, t := range ev.toks {
				if lc := &l.locs[t.loc]; lc.side == sideReq && lc.refOK && (lc.ref.Path == "" || keyRefOK(lc.ref)) {
					lastWTok[s][ev.op][t.tok] = wAt{int32(i), t.loc}
				}
			}
		}
	}
	accepted := func(st *pairStat) bool {
		return len(st.subjects) >= m.cfg.KMin && float64(st.consistent) >= m.cfg.MinShare*float64(st.pairs) && len(st.values) >= 2
	}
	// Per read: the accepted writes and their keys.
	type wkey struct {
		pairs    []pairKey
		subjects int
		first    time.Time
	}
	byRead := map[int32]map[int32]*wkey{}
	keys := make([]pairKey, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		ka, kb := keys[a], keys[b]
		if ka.r != kb.r {
			return ka.r < kb.r
		}
		if ka.w != kb.w {
			return ka.w < kb.w
		}
		if ka.rl != kb.rl {
			return ka.rl < kb.rl
		}
		return ka.wl < kb.wl
	})
	for _, k := range keys {
		st := stats[k]
		if !accepted(st) {
			continue
		}
		if byRead[k.r] == nil {
			byRead[k.r] = map[int32]*wkey{}
		}
		wk := byRead[k.r][k.w]
		if wk == nil {
			wk = &wkey{first: st.first}
			byRead[k.r][k.w] = wk
		}
		if st.first.Before(wk.first) {
			wk.first = st.first
		}
		if k.rl < 0 {
			if len(wk.pairs) == 0 {
				wk.subjects = len(st.subjects)
			}
			continue
		}
		dup := false
		for _, p := range wk.pairs {
			if p.rl == k.rl || p.wl == k.wl {
				dup = true
			}
		}
		if !dup {
			if len(wk.pairs) == 0 || len(st.subjects) > wk.subjects {
				wk.subjects = len(st.subjects)
			}
			wk.pairs = append(wk.pairs, k)
		}
	}
	used := map[string]bool{}
	for d := range m.seeds {
		used[d] = true
	}
	for d := range m.best {
		used[d] = true
	}
	for _, d := range l.tokDom {
		used[d] = true
	}
	reads := make([]int32, 0, len(byRead))
	for r := range byRead {
		reads = append(reads, r)
	}
	sort.Slice(reads, func(a, b int) bool { return reads[a] < reads[b] })
	for _, r := range reads {
		ws := byRead[r]
		// The key of the read: the selectors of its best write.
		var best int32 = -1
		for w, wk := range ws {
			if best < 0 || wk.subjects > ws[best].subjects || (wk.subjects == ws[best].subjects && w < best) {
				best = w
			}
		}
		if best < 0 {
			continue
		}
		rlocs := map[int32]bool{}
		for _, p := range ws[best].pairs {
			rlocs[p.rl] = true
		}
		c := &keyedCand{readOp: r, service: l.ops[r].service, statePath: m.readStatePath(r), readRefs: map[string]Ref{}, first: ws[best].first}
		fieldOf := map[int32]string{}
		for _, p := range ws[best].pairs {
			f := selectorField(l.locs[p.rl].ref)
			if f == "" || !reFieldName.MatchString(f) || fieldOf[p.rl] != "" {
				continue
			}
			dup := false
			for _, g := range c.fields {
				dup = dup || g == f
			}
			if dup {
				continue
			}
			fieldOf[p.rl] = f
			c.fields = append(c.fields, f)
			c.readRefs[f] = l.locs[p.rl].ref
		}
		sort.Strings(c.fields)
		wops := make([]int32, 0, len(ws))
		for w := range ws {
			wops = append(wops, w)
		}
		sort.Slice(wops, func(a, b int) bool { return wops[a] < wops[b] })
		for _, w := range wops {
			wk := ws[w]
			kw := keyedWrite{op: w, refs: map[string]Ref{}, state: m.writeStatePath(w), subjects: wk.subjects}
			for _, p := range wk.pairs {
				if f := fieldOf[p.rl]; f != "" && rlocs[p.rl] {
					kw.refs[f] = l.locs[p.wl].ref
				}
			}
			if len(kw.refs) != len(c.fields) {
				continue // this write does not give the whole key
			}
			if c.first.After(wk.first) {
				c.first = wk.first
			}
			c.writes = append(c.writes, kw)
		}
		if len(c.writes) == 0 {
			continue
		}
		c.name = freeKeyedName(keyedBaseName(l.ops[r].op, c.statePath), used)
		used[c.name] = true
		m.keyed = append(m.keyed, c)
		subjects := 0
		for _, kw := range c.writes {
			subjects = max(subjects, kw.subjects)
		}
		op := l.ops[r]
		m.ediag = append(m.ediag, EntityDiag{Name: c.name, Op: op.service + " " + op.op, Accepted: true, Code: EntityKeyed,
			MinBirthShare: m.cfg.MinBirthShare,
			Reason: fmt.Sprintf("a state without an id of its own, keyed by %s: %d writes rewrite it and the read returns what they sent, for %d users",
				keyedKeyText(c.fields), len(c.writes), subjects)})
	}
}

func keyedKeyText(fields []string) string {
	if len(fields) == 0 {
		return "the user"
	}
	return "the user and " + strings.Join(fields, ", ")
}

// keyRefOK reports whether a request body ref may carry a key: a member
// outside arrays at most four levels down.
func keyRefOK(r Ref) bool {
	if strings.Contains(r.Path, "[*]") {
		return false
	}
	ps := splitTTPath(r.Path)
	return len(ps) >= 1 && len(ps) <= 4
}

// selectorField names the key field of a selector: the parameter name, or
// the last member of a body path.
func selectorField(r Ref) string {
	if r.Path == "" {
		return r.Name
	}
	ps := splitTTPath(r.Path)
	if len(ps) == 0 {
		return ""
	}
	return ps[len(ps)-1]
}

// compareState compares what a write sent with what a read returned: the
// members with the same name, whether they are all equal, and their values.
func compareState(w, r *stateObs) (common int, equal bool, sig string) {
	equal = true
	var b strings.Builder
	for _, a := range r.attrs {
		for _, x := range w.attrs {
			if x.name != a.name {
				continue
			}
			common++
			if x.val != a.val {
				equal = false
			}
			b.WriteString(a.name)
			b.WriteByte('=')
			b.WriteString(a.val.S)
			b.WriteByte(';')
		}
	}
	return common, equal, b.String()
}

// readStatePath is the most frequent state node path of a read's answers.
func (m *miner) readStatePath(op int32) string {
	cnt := map[string]int{}
	for i := range m.l.evs {
		if ev := &m.l.evs[i]; ev.op == op && ev.ok() && len(ev.respState.attrs) > 0 {
			cnt[ev.respState.path]++
		}
	}
	return argmax(cnt)
}

// writeStatePath is the most frequent state node path of a write's
// requests.
func (m *miner) writeStatePath(op int32) string {
	cnt := map[string]int{}
	for i := range m.l.evs {
		if ev := &m.l.evs[i]; ev.op == op && ev.ok() && len(ev.reqState.attrs) > 0 {
			cnt[ev.reqState.path]++
		}
	}
	return argmax(cnt)
}

// keyedBaseName names a keyed entity from its read: the object that holds
// the state ($.data.profile → profile), else the last literal segment of the
// path (GET /consents/{documentId} → consent), else "state".
func keyedBaseName(op, statePath string) string {
	ps := splitTTPath(statePath)
	for i := len(ps) - 1; i >= 0; i-- {
		if p := ps[i]; p != "[*]" && !graphqlStop[strings.ToLower(p)] {
			if n := cleanDomain(singular(strings.ToLower(p))); n != "" {
				return n
			}
		}
	}
	_, path, _ := strings.Cut(op, " ")
	path, _, _ = strings.Cut(path, "#")
	if segs, ok := event.OpSegments(path); ok {
		for i := len(segs) - 1; i >= 0; i-- {
			if segs[i].Literal {
				if n := cleanDomain(singular(strings.ToLower(segs[i].Inner))); n != "" && n != "me" && n != "v1" && n != "api" {
					return n
				}
			}
		}
	}
	if isGraphQLOp(op) {
		if d := graphqlDomain(op, Ref{Path: "$.x"}); d != "" {
			return d
		}
	}
	return "state"
}

// freeKeyedName returns a name for a keyed entity that no domain or entity
// of the log uses: base, else base-state, else base-state-2...
func freeKeyedName(base string, used map[string]bool) string {
	if len(base) > 24 {
		base = strings.TrimRight(base[:24], "-_")
	}
	if !used[base] && reIdent.MatchString(base) && reDomain.MatchString(base) {
		return base
	}
	for i := 1; ; i++ {
		n := base + "-state"
		if i > 1 {
			n += "-" + itoa(i)
		}
		if !used[n] && reDomain.MatchString(n) {
			return n
		}
	}
}
