package miner

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Entities: a domain whose tokens are minted by a write operation (they
// first appear in its response and never in its request) is an entity. The
// operation is its created_by; the records (JSON objects) that carry the id
// in the field named like the creator's id field are its projections; the
// other ids in those records are relations; the read operations that return
// such records are its read_by.

type birth struct {
	ev  int32 // creator event, -1 when the token existed before the window
	loc int32
}

type entity struct {
	def Entity
	dom string
	// sig stands for the entity in rule signatures: its domain, or its name
	// when another team's entity has the same service and domain.
	sig        string
	idField    string
	creatorOp  int32
	creatorLoc int32
	creatorRec string // tt-path of the creator record ("$")
	births     int
	stateField string
	// stateKind is the kind of the state values: 's' a code (also 0), 'b'
	// a boolean, 'q' a number bucket (rules v1.7).
	stateKind byte
	timeField string
	timeHour  bool
	// clearFields are the fields of the entity's records seen with values in
	// clear (keep, or code: the policy lets them out).
	clearFields []string
	// seed and keyed are set for the entities no write creates (rules
	// v1.6): pre-existing objects per user, records keyed without an id.
	seed  *seedCand
	keyed *keyedCand
}

// maxClearFields bounds the field names a diagnostic lists.
const maxClearFields = 12

type miner struct {
	cfg      *Config
	l        *Log
	birth    []birth
	owner    []int32 // per token: subject of the creator exchange, -1
	alias    map[int32]int32
	ents     []*entity
	entByDom map[string]int
	hist     map[int32]*history
	lifes    map[int]*lifecycle
	ediag    []EntityDiag
	rdiag    []RuleDiag
	// best is the accepted creator location of each domain, bornAt the
	// births per location (selectEntities).
	best   map[string]int32
	bornAt map[int32]int
	// seeds and keyed are the entities no write creates (seeds.go,
	// keyed.go), found after the creators.
	seeds map[string]*seedCand
	keyed []*keyedCand
	// bySubject indexes the events of each subject (subjectEvents).
	bySubject map[int32][]int32
	// caused are, per entity, the states a write sets (updates.go): their
	// transitions are not spontaneous outcomes of the creation.
	caused map[int]map[string]bool
	// later are, per entity with a creator, the entities whose objects
	// appear later for its creations (later.go, rules v1.8).
	later map[int][]*laterChild
	// rx is what the read-side analytics found (rules v1.9, reads19.go):
	// the customer attributes and each user's value.
	rx *readExtras
}

func newMiner(cfg *Config, l *Log) *miner {
	m := &miner{cfg: cfg, l: l, entByDom: map[string]int{}, hist: map[int32]*history{}, lifes: map[int]*lifecycle{}}
	m.findBirths()
	m.findAliases()
	return m
}

// findBirths finds, for every token, the exchange that minted it: within
// the trace of its first occurrence, the deepest exchange that has the token
// in its response but not in its request (a parent can relay what a child
// returned, a child cannot read its parent's response).
func (m *miner) findBirths() {
	l := m.l
	m.birth = make([]birth, len(l.toks))
	m.owner = make([]int32, len(l.toks))
	for t := range l.occ {
		m.birth[t] = birth{-1, -1}
		m.owner[t] = -1
		best := l.minter(int32(t))
		if best < 0 || !l.evs[best].ok() || !l.ops[l.evs[best].op].write {
			continue
		}
		bl := int32(-1)
		for _, tk := range l.evs[best].toks {
			if tk.tok == int32(t) && l.locs[tk.loc].side == sideResp && l.locs[tk.loc].ref.Path != "" {
				bl = tk.loc
				break
			}
		}
		if bl < 0 {
			continue
		}
		m.birth[t] = birth{best, bl}
		m.owner[t] = l.subjectOf(best)
	}
}

// minter returns the exchange that minted tok: within the trace of its
// first occurrence, the deepest exchange that has the token in its response
// but not in its request; -1.
func (l *Log) minter(tok int32) int32 {
	os := l.occ[tok]
	if len(os) == 0 {
		return -1
	}
	root := l.evs[os[0].ev].root
	rootEnd := l.evs[root].end
	best, bestDepth := int32(-1), -1
	for _, o := range os {
		if l.evs[o.ev].ts.After(rootEnd) {
			break // later traces
		}
		if l.evs[o.ev].root != root {
			continue
		}
		if o.ev == best {
			continue
		}
		inReq, inResp := l.tokIn(o.ev, tok)
		if inResp && !inReq && l.evs[o.ev].depth > bestDepth {
			best, bestDepth = o.ev, l.evs[o.ev].depth
		}
	}
	return best
}

// findAliases maps tokens to the subject they belong to, from successful
// exchanges made by that subject (a customer id in /customers/{id}/orders,
// in resp.customerId). A token seen with several subjects has no alias.
func (m *miner) findAliases() {
	l := m.l
	cnt := map[int32]map[int32]int{}
	for i := range l.evs {
		e := &l.evs[i]
		if e.subject < 0 || !e.ok() {
			continue
		}
		seen := map[int32]bool{}
		for _, t := range e.toks {
			if seen[t.tok] {
				continue
			}
			seen[t.tok] = true
			c := cnt[t.tok]
			if c == nil {
				c = map[int32]int{}
				cnt[t.tok] = c
			}
			c[e.subject]++
		}
	}
	m.alias = map[int32]int32{}
	for t, c := range cnt {
		total, best, bs := 0, int32(-1), 0
		for s, n := range c {
			total += n
			if n > bs || (n == bs && s < best) {
				best, bs = s, n
			}
		}
		if bs >= 2 && float64(bs) >= m.cfg.MinShare*float64(total) {
			m.alias[t] = best
		}
	}
}

// discoverEntities finds the entities and their creators. A candidate is a
// location where a write operation mints identifiers of a domain; it is
// accepted when enough objects were seen being created (see acceptBirths).
// Objects first seen without their creation are pre-existing, not evidence
// against the entity.
func (m *miner) discoverEntities() {
	m.selectEntities()
	m.selectSeeds()
	m.selectKeyed()
	m.buildEntities("", nil, nil)
}

// selectAll finds the creators, then the seed and keyed entities.
func (m *miner) selectAll() {
	m.selectEntities()
	m.selectSeeds()
	m.selectKeyed()
}

// selectEntities finds the accepted creator of each domain (see
// discoverEntities) and explains every candidate.
func (m *miner) selectEntities() {
	l := m.l
	births := map[int32]int{}
	// Births whose token comes back at the same location in later successful
	// exchanges of the creator (a member id in every POST /loans of that
	// member), and those of them that belong to the requesting user.
	repeated, self := map[int32]int{}, map[int32]int{}
	for t, b := range m.birth {
		if b.ev < 0 {
			continue
		}
		births[b.loc]++
		n := 0
		for _, o := range l.occ[t] {
			if o.loc == b.loc && o.ev != b.ev && l.evs[o.ev].ok() {
				n++
				break
			}
		}
		if n == 0 {
			continue
		}
		repeated[b.loc]++
		if a, ok := m.alias[int32(t)]; ok && a >= 0 && a == l.subjectOf(b.ev) {
			self[b.loc]++
		}
	}
	objects := map[string]int{}
	for t, os := range l.occ {
		if len(os) > 0 {
			objects[l.tokDom[t]]++
		}
	}
	st := l.locStats()
	best := map[string]int32{}
	diags := map[int32]EntityDiag{}
	worst := map[string]int32{} // per domain, the rejected candidate with most births
	for lc, n := range births {
		loc := &l.locs[lc]
		if loc.domain == "" || loc.domain == "subject" || !reIdent.MatchString(loc.domain) {
			continue
		}
		atCreator := st[lc].distinct
		if atCreator < n {
			atCreator = n
		}
		ok, low, code, why := m.acceptBirths(n, atCreator)
		reference := false
		if r := repeated[lc]; r > 0 && 2*r >= n {
			// A created object's id is returned once, by its creation; an id
			// returned again by later creations existed before them: the
			// user making the request (a member, a customer) or another
			// reference. Not an entity, and no warning: such references never
			// block the rules of the operation.
			ok, reference, code = false, true, EntityReference
			if 2*self[lc] >= n {
				why = fmt.Sprintf("the identifier of the user making the request (%d of %d objects returned again by later calls): it exists before the call, a reference, not a creation", r, n)
			} else {
				why = fmt.Sprintf("%d of %d objects are returned again by later calls of the same operation: they exist before it, a reference, not a creation", r, n)
			}
		}
		op := l.ops[loc.op]
		d := EntityDiag{Name: loc.domain, Op: op.service + " " + op.op, AtCreator: atCreator, Born: n,
			Objects: objects[loc.domain], MinBirthShare: m.cfg.MinBirthShare, Accepted: ok, Reason: why, Code: code, Reference: reference,
			BirthShare: round3(float64(n) / float64(atCreator)), BirthShareLow: round3(low)}
		if d.PreExisting = d.Objects - n; d.PreExisting < 0 {
			d.PreExisting = 0
		}
		diags[lc] = d
		if !ok {
			if w, seen := worst[loc.domain]; !seen || births[w] < n || (births[w] == n && w > lc) {
				worst[loc.domain] = lc
			}
			continue
		}
		if b, ok := best[loc.domain]; !ok || births[b] < n || (births[b] == n && b > lc) {
			best[loc.domain] = lc
		}
	}
	shown := map[string]int32{}
	for dom, lc := range worst {
		shown[dom] = lc
	}
	for dom, lc := range best {
		shown[dom] = lc // an accepted creator explains the entity
	}
	for _, dom := range sortedKeys(shown) {
		m.ediag = append(m.ediag, diags[shown[dom]])
	}
	m.best, m.bornAt = map[string]int32{}, births
	for _, dom := range sortedKeys(best) {
		lc := best[dom]
		ps := splitTTPath(l.locs[lc].ref.Path)
		if len(ps) == 0 || ps[len(ps)-1] == "[*]" || !reFieldName.MatchString(ps[len(ps)-1]) {
			continue
		}
		m.best[dom] = lc
	}
}

// candidates returns the accepted creators found by selectEntities, with
// the instant of their first creation (the earliest keeps the bare name).
func (m *miner) candidates(group string) []candidate {
	first := map[int32]time.Time{}
	for _, b := range m.birth {
		if b.ev < 0 {
			continue
		}
		if t, ok := first[b.loc]; !ok || m.l.evs[b.ev].ts.Before(t) {
			first[b.loc] = m.l.evs[b.ev].ts
		}
	}
	var out []candidate
	for _, dom := range sortedKeys(m.best) {
		lc := m.best[dom]
		out = append(out, candidate{group: group, domain: dom, service: m.l.ops[m.l.locs[lc].op].service, first: first[lc]})
	}
	for _, dom := range sortedKeys(m.seeds) {
		c := m.seeds[dom]
		out = append(out, candidate{group: group, domain: dom, service: c.service, first: c.first})
	}
	for _, c := range m.keyed {
		out = append(out, candidate{group: group, domain: c.name, service: c.service, first: c.first})
	}
	return out
}

// buildEntities makes the entities of the selected creators, named by
// names (nil: the domain), and finds their details, relations, lifecycles
// and reads.
func (m *miner) buildEntities(group string, names map[nameKey]*EntityName, book *nameBook) {
	l := m.l
	for _, dom := range sortedKeys(m.best) {
		lc := m.best[dom]
		loc := &l.locs[lc]
		ps := splitTTPath(loc.ref.Path)
		recPath := "$"
		if len(ps) > 1 {
			recPath = "$" + joinTTPath(ps[:len(ps)-1])
		}
		op := l.ops[loc.op]
		name, prefix, sig := dom, idPrefix(dom), dom
		if n := names[nameKey{group, dom, op.service}]; n != nil {
			name, prefix = n.Name, n.IDPrefix
			if book != nil {
				sig = book.sigKey(n)
			}
		}
		e := &entity{dom: dom, sig: sig, idField: ps[len(ps)-1], creatorOp: loc.op, creatorLoc: lc, creatorRec: recPath, births: m.bornAt[lc]}
		e.def = Entity{Name: name, Service: op.service, IDDomain: dom, IDField: e.idField, IDPrefix: prefix,
			CreatedBy: &CreatedBy{Op: op.op, ID: loc.ref}}
		m.entByDom[dom] = len(m.ents)
		m.ents = append(m.ents, e)
		if name != dom {
			for i := range m.ediag {
				if m.ediag[i].Accepted && m.ediag[i].Name == dom {
					m.ediag[i].Name = name
				}
			}
		}
	}
	for _, dom := range sortedKeys(m.seeds) {
		c := m.seeds[dom]
		name, prefix, sig := dom, idPrefix(dom), dom
		if n := names[nameKey{group, dom, c.service}]; n != nil {
			name, prefix = n.Name, n.IDPrefix
			if book != nil {
				sig = book.sigKey(n)
			}
		}
		e := &entity{dom: dom, sig: sig, idField: c.idField, creatorOp: -1, creatorLoc: -1, seed: c}
		e.def = Entity{Name: name, Service: c.service, IDDomain: dom, IDField: c.idField, IDPrefix: prefix}
		m.entByDom[dom] = len(m.ents)
		m.ents = append(m.ents, e)
		m.renameDiag(dom, name)
		// The owner of a pre-existing object is the user it is read by.
		for t := range l.toks {
			if l.tokDom[t] == dom && m.owner[t] < 0 {
				if a, ok := m.alias[int32(t)]; ok {
					m.owner[t] = a
				}
			}
		}
	}
	for _, c := range m.keyed {
		name, prefix := c.name, idPrefix(c.name)
		if n := names[nameKey{group, c.name, c.service}]; n != nil {
			name, prefix = n.Name, n.IDPrefix
		}
		e := &entity{dom: c.name, sig: name, idField: "id", creatorOp: -1, creatorLoc: -1, keyed: c}
		e.def = Entity{Name: name, Service: c.service, IDDomain: c.name, IDField: "id", IDPrefix: prefix,
			Key: &StateKey{Owner: true, Fields: c.fields}}
		for _, w := range c.writes {
			u := UpsertedBy{Op: l.ops[w.op].op}
			if svc := l.ops[w.op].service; svc != c.service {
				u.Service = svc
			}
			if len(w.refs) > 0 {
				u.Key = w.refs
			}
			if w.state != "" {
				u.State = &Ref{From: "req.body", Path: w.state}
			}
			e.def.UpsertedBy = append(e.def.UpsertedBy, u)
		}
		rb := ReadBy{Op: l.ops[c.readOp].op, At: Ref{From: "resp.body", Path: c.statePath}}
		if len(c.readRefs) > 0 {
			rb.Key = c.readRefs
		}
		e.def.ReadBy = []ReadBy{rb}
		m.renameDiag(c.name, name)
		m.ents = append(m.ents, e) // never in entByDom: no token is its id
	}
	for i := range m.ents {
		m.creatorDetails(i)
	}
	for i := range m.ents {
		m.relations(i)
	}
	for i := range m.ents {
		m.findLifecycle(i)
	}
	for i := range m.ents {
		if m.ents[i].keyed == nil {
			m.readBys(i)
		}
	}
	m.findLater()
	for i, e := range m.ents {
		if e.seed != nil {
			e.def.Seed = m.seedOf(i, e.seed)
		}
	}
}

// renameDiag gives the accepted diagnostic of a domain its entity name.
func (m *miner) renameDiag(dom, name string) {
	if name == dom {
		return
	}
	for i := range m.ediag {
		if m.ediag[i].Accepted && m.ediag[i].Name == dom {
			m.ediag[i].Name = name
		}
	}
}

func joinTTPath(ps []string) string {
	var b strings.Builder
	for _, p := range ps {
		if p == "[*]" {
			b.WriteString(p)
		} else {
			b.WriteString(".")
			b.WriteString(p)
		}
	}
	return b.String()
}

// idPrefix builds ^[A-Z]{2,5}-SYN-$ from a name: the first letter and the
// following consonants (order → ORD, shipment → SHP).
func idPrefix(name string) string {
	up := strings.ToUpper(name)
	var b []byte
	for i := 0; i < len(up) && len(b) < 3; i++ {
		c := up[i]
		if c < 'A' || c > 'Z' {
			continue
		}
		if len(b) > 0 && strings.IndexByte("AEIOU", c) >= 0 {
			continue
		}
		b = append(b, c)
	}
	if len(b) < 2 {
		b = b[:0]
		for i := 0; i < len(up) && len(b) < 3; i++ {
			if c := up[i]; c >= 'A' && c <= 'Z' {
				b = append(b, c)
			}
		}
	}
	for len(b) < 2 {
		b = append(b, 'X')
	}
	return string(b) + "-SYN-"
}

// entityOf returns the entity of a token (by its domain), -1.
func (m *miner) entityOf(tok int32) int {
	if i, ok := m.entByDom[m.l.tokDom[tok]]; ok {
		return i
	}
	return -1
}

// recEntity returns the entity a record is a projection of and its id: the
// record holds the entity id under the entity's id field. A member named
// "id" wins over foreign keys; two other candidates are ambiguous.
func (m *miner) recEntity(r *record) (int, recField, bool) {
	cand, idf := -1, recField{}
	for _, f := range r.ids {
		ei := m.entityOf(f.tok)
		if ei < 0 || m.ents[ei].idField != f.name {
			continue
		}
		if f.name == "id" {
			return ei, f, true
		}
		if cand >= 0 && cand != ei {
			cand = -2
			continue
		}
		if cand != -2 {
			cand, idf = ei, f
		}
	}
	if cand < 0 {
		return -1, recField{}, false
	}
	return cand, idf, true
}

// creatorDetails fills created_by.state and defaults.
func (m *miner) creatorDetails(i int) {
	l, e := m.l, m.ents[i]
	if e.creatorOp < 0 {
		return
	}
	var n, withBody int
	vals := map[string]map[string]int{}
	present := map[string]int{}
	reqKey := map[string]int{}
	seenVal := map[string]Value{}
	for ei := range l.evs {
		ev := &l.evs[ei]
		if ev.op != e.creatorOp || !ev.ok() {
			continue
		}
		var rec *record
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side == sideResp && r.path == e.creatorRec {
				if _, ok := r.id(e.idField); ok {
					rec = r
				}
			}
		}
		if rec == nil {
			continue
		}
		n++
		if len(ev.reqKeys) > 0 {
			withBody++
		}
		for _, k := range ev.reqKeys {
			reqKey[k]++
		}
		for _, a := range rec.attrs {
			present[a.name]++
			if vals[a.name] == nil {
				vals[a.name] = map[string]int{}
			}
			k := string(a.val.Kind) + a.val.S
			vals[a.name][k]++
			seenVal[a.name+"\x00"+k] = a.val
		}
	}
	if n == 0 {
		return
	}
	if float64(withBody) >= m.cfg.MinShare*float64(n) {
		e.def.CreatedBy.State = &Ref{From: "req.body", Path: "$"}
	}
	defaults := map[string]any{}
	for _, name := range sortedKeys(present) {
		if float64(present[name]) < m.cfg.MinShare*float64(n) || float64(reqKey[name]) >= 0.5*float64(n) {
			continue
		}
		if !reFieldPath.MatchString(name) {
			continue
		}
		k := argmax(vals[name])
		if float64(vals[name][k]) >= 0.99*float64(present[name]) && len(vals[name]) == 1 {
			defaults[name] = seenVal[name+"\x00"+k].Any()
		}
	}
	if len(defaults) > 0 {
		e.def.CreatedBy.Defaults = defaults
	}
}

// relations finds the foreign keys of an entity in its records.
func (m *miner) relations(i int) {
	l, e := m.l, m.ents[i]
	objs := map[string]map[int32]bool{}
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
			for _, f := range r.ids {
				if f.name == own.name {
					continue
				}
				fe := m.entityOf(f.tok)
				if fe < 0 {
					continue
				}
				k := f.name + "\x00" + m.ents[fe].def.Name
				if objs[k] == nil {
					objs[k] = map[int32]bool{}
				}
				objs[k][own.tok] = true
			}
		}
	}
	for _, k := range sortedKeys(objs) {
		if len(objs[k]) < m.cfg.KMin {
			continue
		}
		field, target, _ := strings.Cut(k, "\x00")
		if !reFieldPath.MatchString(field) {
			continue
		}
		e.def.Relations = append(e.def.Relations, Relation{Field: field, Entity: target})
	}
}

// relationField returns the field of entity i that refers to entity j.
func (m *miner) relationField(i, j int) string {
	for _, r := range m.ents[i].def.Relations {
		if r.Entity == m.ents[j].def.Name {
			return r.Field
		}
	}
	return ""
}

type readGroup struct {
	op   int32
	path string
}

type readStats struct {
	objs     map[int32]bool
	events   int // successful events with at least one record
	selector map[string]int
	states   map[string]int // state values exposed
	subjOK   int            // records owned by the requesting subject
	subjAll  int
	subjects map[int32]bool
}

// readBys finds the read operations of an entity.
func (m *miner) readBys(i int) {
	l, e := m.l, m.ents[i]
	groups := map[readGroup]*readStats{}
	var order []readGroup
	isList := func(p string) bool { return strings.HasSuffix(p, "[*]") }
	for ei := range l.evs {
		ev := &l.evs[ei]
		op := l.ops[ev.op]
		if !op.read || !ev.ok() {
			continue
		}
		perPath := map[string][]*record{}
		var owns map[string][]recField
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side != sideResp {
				continue
			}
			ent, own, ok := m.recEntity(r)
			if !ok || ent != i {
				continue
			}
			perPath[r.path] = append(perPath[r.path], r)
			if owns == nil {
				owns = map[string][]recField{}
			}
			owns[r.path] = append(owns[r.path], own)
		}
		for _, p := range sortedKeys(perPath) {
			g := readGroup{ev.op, p}
			s := groups[g]
			if s == nil {
				s = &readStats{objs: map[int32]bool{}, selector: map[string]int{}, states: map[string]int{}, subjects: map[int32]bool{}}
				groups[g] = s
				order = append(order, g)
			}
			s.events++
			recs := perPath[p]
			for k, r := range recs {
				own := owns[p][k]
				s.objs[own.tok] = true
				if e.stateField != "" {
					if v, ok := stateIn(r, e.stateField, e.stateKind); ok {
						s.states[v]++
					}
				}
				if ev.subject >= 0 && m.owner[own.tok] >= 0 {
					s.subjAll++
					s.subjects[ev.subject] = true
					if m.owner[own.tok] == ev.subject {
						s.subjOK++
					}
				}
			}
			// Selector candidates: request tokens of this exchange.
			for _, t := range ev.toks {
				lc := &l.locs[t.loc]
				if lc.side != sideReq || !lc.refOK || (lc.ref.Path != "" && !bodySelector(&op, lc.ref)) {
					continue
				}
				base := lc.ref.From + "\x00" + selectorName(lc.ref)
				allID, allOwner := true, true
				fields := map[string]bool{}
				for k, r := range recs {
					own := owns[p][k]
					if own.tok != t.tok {
						allID = false
					}
					if a, ok := m.alias[t.tok]; !ok || m.owner[own.tok] != a {
						allOwner = false
					}
					fs := map[string]bool{}
					for _, f := range r.ids {
						if f.tok == t.tok && f.name != own.name {
							fs[f.name] = true
						}
					}
					if k == 0 {
						fields = fs
					} else {
						for f := range fields {
							if !fs[f] {
								delete(fields, f)
							}
						}
					}
				}
				if allID {
					s.selector[base+"\x00id"]++
				}
				for f := range fields {
					s.selector[base+"\x00field\x00"+f]++
				}
				if allOwner {
					s.selector[base+"\x00owner"]++
				}
			}
		}
	}
	var kept []*readStats // stats of e.def.ReadBy, same order
	for _, g := range order {
		s := groups[g]
		if len(s.objs) < m.cfg.KMin {
			continue
		}
		op := l.ops[g.op]
		if cb := e.def.CreatedBy; cb != nil && op.op == cb.Op && op.service == e.def.Service {
			continue
		}
		rb := ReadBy{Op: op.op, At: Ref{From: "resp.body", Path: g.path}}
		if op.service != e.def.Service {
			rb.Service = op.service
		}
		bestSel, bestN := "", 0
		for _, k := range sortedKeys(s.selector) {
			n := s.selector[k]
			// Prefer id over field over owner on ties (sorted order: field, id, owner).
			if n > bestN || (n == bestN && strings.HasSuffix(k, "\x00id")) {
				bestSel, bestN = k, n
			}
		}
		if bestSel != "" && float64(bestN) >= m.cfg.MinShare*float64(s.events) {
			parts := strings.Split(bestSel, "\x00")
			ref := selectorRef(parts[0], parts[1])
			switch parts[2] {
			case "field":
				ref.Field = parts[3]
			case "owner":
				ref.Owner = true
			}
			// A request body member (a GraphQL variable too, rules v1.7)
			// selects by id, field or owner.
			if ref.Field == "" || reFieldName.MatchString(ref.Field) {
				rb.By = ref
			}
		}
		if rb.By == nil && !isList(g.path) {
			continue
		}
		if len(s.subjects) >= m.cfg.KMin && s.subjAll > 0 && float64(s.subjOK) >= 0.99*float64(s.subjAll) {
			rb.Scope = "owner"
			rb.Foreign = m.foreignAnswer(i, g, rb.By)
		}
		if isList(g.path) {
			if c := m.listCount(g); c != "" {
				rb.List = &ListShape{Count: c}
			}
		}
		if rb.By != nil && !rb.By.Owner {
			rb.HiddenWhen = m.hiddenWhen(i, g, rb.By, s)
		}
		e.def.ReadBy = append(e.def.ReadBy, rb)
		kept = append(kept, s)
	}
	m.shareHiddenWhen(e.def.ReadBy, kept)
	sort.SliceStable(e.def.ReadBy, func(a, b int) bool {
		ra, rb := e.def.ReadBy[a], e.def.ReadBy[b]
		if (ra.Service == "") != (rb.Service == "") {
			return ra.Service == ""
		}
		return ra.Op < rb.Op
	})
}

// shareHiddenWhen gives a read the hidden_when of a sibling read that
// locates the entity through the same field: visibility is a property of the
// entity's state and of how it is selected, so a front API that wraps the
// carrier's (shop GET /orders/{id}/shipment over carrier GET /v1/shipments)
// hides the same states even when its own 404s are too few to show it. The
// state must never have been exposed by the read itself.
func (m *miner) shareHiddenWhen(rbs []ReadBy, stats []*readStats) {
	for i := range rbs {
		if rbs[i].HiddenWhen != nil || rbs[i].By == nil || rbs[i].By.Owner || rbs[i].By.Field == "" {
			continue
		}
		for j := range rbs {
			if j == i || rbs[j].HiddenWhen == nil || rbs[j].By == nil || rbs[j].By.Field != rbs[i].By.Field {
				continue
			}
			hidden := true
			for _, st := range rbs[j].HiddenWhen {
				if v, ok := st.(string); ok && stats[i].states[v] > 0 {
					hidden = false
				}
			}
			if hidden {
				rbs[i].HiddenWhen = map[string]any{}
				for k, v := range rbs[j].HiddenWhen {
					rbs[i].HiddenWhen[k] = v
				}
				break
			}
		}
	}
}

// selected returns the token of the selector parameter of event ev.
func (m *miner) selected(ev *evt, by *Ref) (int32, bool) {
	for _, t := range ev.toks {
		lc := &m.l.locs[t.loc]
		if lc.side == sideReq && lc.ref.From == by.From && lc.ref.Name == by.Name && lc.ref.Path == by.Path {
			return t.tok, true
		}
	}
	return -1, false
}

// foreignAnswer looks at the requests of op that select another subject's
// entity (or owner): 403 → forbidden, otherwise not_found (the default,
// which does not reveal that the entity exists).
func (m *miner) foreignAnswer(i int, g readGroup, by *Ref) string {
	if by == nil {
		return "not_found"
	}
	l := m.l
	st := map[int]int{}
	for ei := range l.evs {
		ev := &l.evs[ei]
		if ev.op != g.op || ev.subject < 0 {
			continue
		}
		tok, ok := m.selected(ev, by)
		if !ok {
			continue
		}
		var own int32 = -1
		if by.Owner {
			if a, ok := m.alias[tok]; ok {
				own = a
			}
		} else {
			if m.birth[tok].ev < 0 {
				continue // unknown entity: a plain not-found, not a foreign one
			}
			own = m.owner[tok]
		}
		if own == ev.subject {
			continue
		}
		if ev.status == 403 || ev.status == 404 {
			st[ev.status]++
		}
	}
	if st[403] > st[404] && st[403] > 0 {
		return "forbidden"
	}
	return "not_found"
}

// listCount finds a number in the envelope equal to the number of items.
func (m *miner) listCount(g readGroup) string {
	l := m.l
	arr := strings.TrimSuffix(g.path, "[*]")
	ps := splitTTPath(arr)
	if len(ps) == 0 || strings.Contains(arr, "[*]") {
		return ""
	}
	// The envelope is the object holding the array: the root, or a nested
	// one ($.data.contracts.items[*] → $.data.contracts.count, rules v1.7).
	prefix := ""
	for _, p := range ps[:len(ps)-1] {
		prefix += p + "."
	}
	match := map[string]int{}
	n := 0
	for ei := range l.evs {
		ev := &l.evs[ei]
		if ev.op != g.op || !ev.ok() {
			continue
		}
		length := -1
		for _, a := range ev.arrays {
			if a.path == arr {
				length = a.n
			}
		}
		if length < 0 {
			continue
		}
		n++
		for _, a := range ev.nums {
			if a.val.S == itoa(length) {
				if k, ok := strings.CutPrefix(a.name, prefix); ok && reFieldName.MatchString(k) {
					match[a.name]++
				}
			}
		}
	}
	for _, k := range sortedKeys(match) {
		if n >= m.cfg.KMin && float64(match[k]) >= 0.99*float64(n) {
			return "$." + k
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// hiddenWhen finds a state in which an existing entity is not exposed by a
// read: the selection names an entity that exists, the answer is empty (or
// 404), the entity was in that state at the time, and the operation never
// exposes that state.
func (m *miner) hiddenWhen(i int, g readGroup, by *Ref, s *readStats) map[string]any {
	l, e := m.l, m.ents[i]
	if e.stateField == "" || !e.literalState() {
		return nil
	}
	lf := m.lifes[i]
	if lf == nil {
		return nil
	}
	// Index: selector value → entity objects (by id or by field).
	var byField map[int32][]int32
	if by.Field != "" {
		byField = lf.byField(m, by.Field)
	}
	arr := strings.TrimSuffix(g.path, "[*]")
	cnt := map[string]int{}
	total := 0
	for ei := range l.evs {
		ev := &l.evs[ei]
		if ev.op != g.op {
			continue
		}
		empty := ev.status == 404
		if ev.ok() {
			if !strings.HasSuffix(g.path, "[*]") {
				continue
			}
			for _, a := range ev.arrays {
				if a.path == arr && a.n == 0 {
					empty = true
				}
			}
		}
		if !empty {
			continue
		}
		tok, ok := m.selected(ev, by)
		if !ok {
			continue
		}
		var objs []int32
		if by.Field == "" {
			if m.entityOf(tok) == i {
				objs = []int32{tok}
			}
		} else {
			objs = byField[tok]
		}
		for _, o := range objs {
			h := m.hist[o]
			if h == nil {
				continue
			}
			if st, ok := h.stateAt(ev.ts); ok {
				cnt[st]++
				total++
			}
		}
	}
	st := argmax(cnt)
	if st == "" || cnt[st] < m.cfg.KMin || float64(cnt[st]) < m.cfg.MinShare*float64(total) || s.states[st] > 0 {
		return nil
	}
	v, _ := e.stateValue(st)
	return map[string]any{e.stateField: v}
}
