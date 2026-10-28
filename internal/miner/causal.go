package miner

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Mined is a rule found by one run, before persistence assigns its id.
type Mined struct {
	Rule Rule
	// Signature identifies the rule across runs (cause or batch shape).
	Signature string
	// Structure hashes what a reviewer approves (effects, outcomes names,
	// schedule); a change of structure means a new draft.
	Structure string
	// Confidence in [0, 1]: for causal rules the share of causes whose
	// effect was observed, for batch rules the share of days with a run.
	Confidence float64
}

type instance struct {
	ev    int32
	bound int32
	child map[int]int32 // entity → object created by a descendant exchange
}

func slug(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func bindName(s string) string {
	out := strings.ReplaceAll(s, "-", "_")
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// isDescendant reports whether event d is a (strict) descendant of a.
func (l *Log) isDescendant(d, a int32) bool {
	for i := 0; i < 16 && d >= 0; i++ {
		d = l.evs[d].pev
		if d == a {
			return true
		}
	}
	return false
}

// mineCausal mines the causal rule of the creator operation of entity e0 and
// records why when it proposes nothing.
func (m *miner) mineCausal(e0i int) *Mined {
	mm, why := m.mineCausalWhy(e0i)
	e0 := m.ents[e0i]
	op := m.l.ops[e0.creatorOp]
	d := RuleDiag{Signature: "causal|" + op.service + "|" + op.op + "|" + e0.sig, Kind: KindCausal,
		Service: op.service, Op: op.op, Entity: e0.def.Name}
	d.Values, d.ClearFields = valuesOf(e0)
	if mm != nil {
		d.Decision, d.Confidence, d.Reason, d.Code = DecisionProposed, mm.Confidence, "mined", WhyMined
	} else {
		d.Decision, d.Reason, d.Code = DecisionNotMined, why.text, why.code
		d.Causes, d.Decided, d.Subjects, d.HorizonSeconds = why.causes, why.decided, why.subjects, int64(why.horizon/time.Second)
		// A rejected entity created by another operation may be what the
		// rule is missing (a nested creation): say so.
		for _, ed := range m.ediag {
			if !ed.Accepted && ed.significant() && ed.Op != op.service+" "+op.op {
				d.Reason += "; entity " + ed.Name + " not accepted: " + ed.Reason
			}
		}
	}
	m.rdiag = append(m.rdiag, d)
	return mm
}

// valuesOf says whether the records of an entity carry values in clear.
func valuesOf(e *entity) (string, []string) {
	if len(e.clearFields) > 0 {
		return ValuesInClear, e.clearFields
	}
	return ValuesDropped, nil
}

// whyNot says why a candidate produced no rule: a code for the UI, the
// technical text, and the figures the UI shows.
type whyNot struct {
	code, text                string
	causes, decided, subjects int
	horizon                   time.Duration
}

func (m *miner) mineCausalWhy(e0i int) (*Mined, whyNot) {
	l, e0, cfg := m.l, m.ents[e0i], m.cfg
	var insts []instance
	statuses := map[int]int{}
	byEv := map[int32]int{}
	for t, b := range m.birth {
		if b.ev < 0 || b.loc != e0.creatorLoc {
			continue
		}
		if _, dup := byEv[b.ev]; dup {
			continue
		}
		byEv[b.ev] = len(insts)
		insts = append(insts, instance{ev: b.ev, bound: int32(t), child: map[int]int32{}})
		statuses[l.evs[b.ev].status]++
	}
	if len(insts) < cfg.KMin {
		return nil, whyNot{code: WhyFewCauses, causes: len(insts), text: fmt.Sprintf("only %d creations captured, at least %d needed", len(insts), cfg.KMin)}
	}
	sort.Slice(insts, func(a, b int) bool { return insts[a].ev < insts[b].ev })
	for k := range insts {
		byEv[insts[k].ev] = k
	}
	// Objects minted by exchanges nested in the cause.
	for t, b := range m.birth {
		if b.ev < 0 {
			continue
		}
		ei := m.entityOf(int32(t))
		if ei < 0 || ei == e0i {
			continue
		}
		for anc := l.evs[b.ev].pev; anc >= 0; anc = l.evs[anc].pev {
			if k, ok := byEv[anc]; ok {
				if _, has := insts[k].child[ei]; !has {
					insts[k].child[ei] = int32(t)
				}
				break
			}
		}
	}
	childN := map[int]int{}
	for _, in := range insts {
		for ei := range in.child {
			childN[ei]++
		}
	}
	var children []int
	for ei, n := range childN {
		// Not MinShare: a nested creation missing from some causes is a gap
		// of the capture (restart, sampling), like a missing creation.
		if float64(n) >= cfg.MinBirthShare*float64(len(insts)) {
			children = append(children, ei)
		}
	}
	// Objects that appear later, outside the trace (later.go, rules v1.8).
	laterOf := map[int]*laterChild{}
	for _, lc := range m.later[e0i] {
		for k := range insts {
			if b, ok := lc.byCause[insts[k].ev]; ok {
				insts[k].child[lc.ent] = b
			}
		}
		children = append(children, lc.ent)
		laterOf[lc.ent] = lc
	}
	sort.Ints(children)

	// The lifecycle followed by the outcomes: a child entity's, else the
	// created entity's own.
	lifeEnt := -1
	for _, ci := range children {
		if m.spontaneous(ci) && (lifeEnt < 0 || len(m.lifes[ci].objs) > len(m.lifes[lifeEnt].objs)) {
			lifeEnt = ci
		}
	}
	if lifeEnt < 0 && m.spontaneous(e0i) {
		lifeEnt = e0i
	}
	if len(children) == 0 && lifeEnt < 0 {
		return nil, whyNot{code: WhyNoEffect, causes: len(insts), text: noEffectText(e0)}
	}

	op := l.ops[e0.creatorOp]
	bind := bindName(e0.def.Name)
	bindRef := l.locs[e0.creatorLoc].ref
	rule := &CausalRule{Kind: KindCausal, Status: StatusDraft,
		Cause: Cause{Service: op.service, Op: op.op, Bind: map[string]Ref{bind: bindRef}}}
	for _, s := range sortedInts(statuses) {
		if statuses[s] >= cfg.KMin {
			rule.Cause.When.Status = append(rule.Cause.When.Status, s)
		}
	}
	if len(rule.Cause.When.Status) == 0 {
		return nil, whyNot{code: WhyFewCauses, causes: len(insts), text: "no response status with enough causes"}
	}
	mags := map[string]string{}
	var keys []KeyRef
	var immediate []string
	createOf := map[int]string{}

	for _, ci := range children {
		ce := m.ents[ci]
		if lc := laterOf[ci]; lc != nil {
			id := slug(ce.def.Name) + "-created"
			if !reIdent.MatchString(id) || !reFieldPath.MatchString(lc.field) {
				continue
			}
			create := map[string]any{lc.field: "${" + bind + "}"}
			for k, v := range lc.create {
				create[k] = v
			}
			rule.Effects = append(rule.Effects, Effect{ID: id, Entity: ce.def.Name, Create: create, After: lc.after})
			immediate = append(immediate, id)
			createOf[ci] = id
			mags[id] = lc.mag
			if lc.fieldLoc >= 0 {
				keys = append(keys, KeyRef{Domain: e0.dom, From: l.keyEnd(e0.creatorLoc), To: l.keyEnd(lc.fieldLoc), Matches: lc.matches})
			}
			if lc.replace {
				rid := slug(e0.def.Name) + "-replaced"
				if reIdent.MatchString(rid) {
					rule.Effects = append(rule.Effects, Effect{ID: rid, Entity: e0.def.Name, TargetID: "${" + bind + "}", Remove: true,
						AfterEffect: id, After: Delay{Single: "0s"}})
					immediate = append(immediate, rid)
					mags[rid] = MagSeconds
				}
			}
			continue
		}
		id := slug(ce.def.Name) + "-requested"
		create := map[string]any{}
		// Field of the child's creator record holding the bound token.
		fieldN, relLoc := map[string]int{}, map[string]int32{}
		for _, in := range insts {
			x, ok := in.child[ci]
			if !ok {
				continue
			}
			if r := m.creatorRecord(ci, x); r != nil {
				for _, f := range r.ids {
					if f.tok == in.bound {
						fieldN[f.name]++
						relLoc[f.name] = f.loc
						// The request of the creating exchange carries the
						// cause's id: that is the link key.
						for _, tk := range l.evs[m.birth[x].ev].toks {
							if tk.tok == in.bound && l.locs[tk.loc].side == sideReq && l.locs[tk.loc].refOK {
								relLoc[f.name] = tk.loc
								break
							}
						}
					}
				}
			}
		}
		for _, f := range sortedKeys(fieldN) {
			if float64(fieldN[f]) >= cfg.MinShare*float64(childN[ci]) && reFieldPath.MatchString(f) {
				create[f] = "${" + bind + "}"
				keys = append(keys, KeyRef{Domain: e0.dom, From: l.keyEnd(e0.creatorLoc), To: l.keyEnd(relLoc[f]), Matches: fieldN[f]})
			}
		}
		if cb := ce.def.CreatedBy; cb != nil {
			for k, v := range cb.Defaults {
				if _, ok := create[k]; !ok {
					create[k] = v
				}
			}
		}
		if len(create) == 0 {
			continue
		}
		rule.Effects = append(rule.Effects, Effect{ID: id, Entity: ce.def.Name, Create: create, After: Delay{Single: "0s"}})
		immediate = append(immediate, id)
		createOf[ci] = id
		mags[id] = MagSeconds

		// The created entity's record in the cause response refers to the child.
		linkN, linkLoc := map[string]int{}, map[string]int32{}
		for _, in := range insts {
			x, ok := in.child[ci]
			if !ok {
				continue
			}
			for ri := range l.evs[in.ev].recs {
				r := &l.evs[in.ev].recs[ri]
				if r.side != sideResp {
					continue
				}
				if ent, own, ok := m.recEntity(r); !ok || ent != e0i || own.tok != in.bound {
					continue
				}
				for _, f := range r.ids {
					if f.tok == x {
						linkN[f.name]++
						linkLoc[f.name] = f.loc
					}
				}
			}
		}
		for _, f := range sortedKeys(linkN) {
			if float64(linkN[f]) < cfg.MinShare*float64(childN[ci]) || !reFieldPath.MatchString(f) {
				continue
			}
			lid := slug(e0.def.Name) + "-linked"
			for _, e := range rule.Effects {
				if e.ID == lid {
					// Several nested creations linked from the record: one
					// effect each, named after the child.
					lid = slug(e0.def.Name) + "-" + slug(ce.def.Name) + "-linked"
					break
				}
			}
			if !reIdent.MatchString(lid) {
				continue
			}
			rule.Effects = append(rule.Effects, Effect{ID: lid, Entity: e0.def.Name, TargetID: "${" + bind + "}",
				Set: map[string]any{f: "${effect:" + id + "}"}, AfterEffect: id, After: Delay{Single: "0s"}})
			immediate = append(immediate, lid)
			mags[lid] = MagSeconds
			keys = append(keys, KeyRef{Domain: ce.dom, From: l.keyEnd(ce.creatorLoc), To: l.keyEnd(linkLoc[f]), Matches: linkN[f]})
			break
		}
	}

	// Lifecycle effects.
	edgeEffect := map[[2]string]string{}
	backEffect := map[[2]string]string{} // b → a returns (rules v1.8)
	var lf *lifecycle
	if lifeEnt >= 0 {
		lf = m.lifes[lifeEnt]
		le := m.ents[lifeEnt]
		usedIDs := map[string]bool{}
		for _, e := range rule.Effects {
			usedIDs[e.ID] = true
		}
		edges := lf.edges()
		caused := m.caused[lifeEnt]
		for _, ed := range edges {
			if caused[ed[1]] {
				continue // set by a write (updates.go), not spontaneous
			}
			id := slug(le.def.Name) + "-" + slug(ed[1])
			if usedIDs[id] {
				id = slug(le.def.Name) + "-" + slug(ed[1]) + "-from-" + slug(ed[0])
			}
			if usedIDs[id] || !reIdent.MatchString(id) {
				continue
			}
			usedIDs[id] = true
			edgeEffect[ed] = id
		}
		for _, ed := range edges {
			id, ok := edgeEffect[ed]
			if !ok {
				continue
			}
			sv, ok := le.stateValue(ed[1])
			if !ok {
				delete(edgeEffect, ed)
				continue
			}
			set := map[string]any{le.stateField: sv}
			for k, v := range lf.changeAttrs[ed] {
				set[k] = v
			}
			eff := Effect{ID: id, Entity: le.def.Name, Set: set}
			if len(caused) > 0 && le.literalState() {
				// A write can move the object elsewhere meanwhile: a step
				// applies only from the state it leaves (rules v1.7).
				eff.Where = map[string]any{le.stateField: le.literal(ed[0])}
			}
			ch := lf.chain(ed[1])
			var first string
			if len(ch) >= 2 {
				first = edgeEffect[[2]string{ch[0], ch[1]}]
			}
			if lifeEnt == e0i {
				if ed[0] == lf.initial {
					eff.TargetID = "${" + bind + "}"
				} else {
					eff.Target = first
				}
			} else {
				eff.Target = createOf[lifeEnt]
				if eff.Target == "" {
					continue
				}
			}
			if ed[0] != lf.initial {
				pc := lf.chain(ed[0])
				if len(pc) >= 2 {
					eff.AfterEffect = edgeEffect[[2]string{pc[len(pc)-2], pc[len(pc)-1]}]
				}
				if eff.AfterEffect == "" {
					continue
				}
			} else if lifeEnt != e0i {
				eff.AfterEffect = createOf[lifeEnt]
			}
			mag, _ := m.edgeMagnitude(lf, ed[0], ed[1])
			if mag != "" {
				mags[id] = mag
				eff.After = delayFor(mag)
			} else {
				eff.After = delayFor(MagHours)
			}
			rule.Effects = append(rule.Effects, eff)
		}
		// rules v1.8 (C10): a spontaneous return to an earlier state.
		used := map[string]bool{}
		for _, e := range rule.Effects {
			used[e.ID] = true
		}
		for _, key := range lf.backKeys() {
			eff, ok := m.backEffect(lf, lifeEnt, key, edgeEffect, used)
			if !ok {
				continue
			}
			if lifeEnt == e0i {
				eff.TargetID = "${" + bind + "}"
			} else if eff.Target = createOf[lifeEnt]; eff.Target == "" {
				continue
			}
			used[eff.ID] = true
			backEffect[key] = eff.ID
			mags[eff.ID] = backMag(lf.back[key])
			rule.Effects = append(rule.Effects, eff)
		}
	}
	if len(rule.Effects) == 0 {
		return nil, whyNot{code: WhyNoEffect, causes: len(insts), text: noEffectText(e0)}
	}

	// Outcomes.
	lifeObj := func(in instance) (int32, bool) {
		if lifeEnt < 0 {
			return -1, false
		}
		if lifeEnt == e0i {
			return in.bound, true
		}
		x, ok := in.child[lifeEnt]
		return x, ok
	}
	type group struct {
		final    string
		n        int
		subjects map[int32]bool
		back     *[2]string // the last transition was this return (rules v1.8)
	}
	horizon := cfg.MinCoverage()
	if lf != nil {
		var ds []time.Duration
		for _, in := range insts {
			x, ok := lifeObj(in)
			if !ok {
				continue
			}
			if h := m.hist[x]; h != nil {
				last := h.segs[len(h.segs)-1]
				if lf.terminal[last.state] && last.state != lf.initial {
					ds = append(ds, last.first.Sub(l.evs[in.ev].ts))
				}
			}
		}
		horizon = decisionHorizon(ds, cfg)
	}
	groups := map[string]*group{}
	var decided []decidedCause // rules v1.9: the causes and their group, for the conditions
	subjects := map[int32]bool{}
	matched, withX := 0, 0
	readLoc := map[int32]int{}
	for _, in := range insts {
		cev := &l.evs[in.ev]
		if s := l.subjectOf(in.ev); s >= 0 {
			subjects[s] = true
		}
		x, hasX := lifeObj(in)
		if !hasX && len(children) > 0 {
			x, hasX = in.child[children[0]]
		}
		if hasX {
			withX++
			found := false
			for _, o := range l.occ[x] {
				if l.evs[o.ev].root != cev.root && !l.evs[o.ev].ts.Before(cev.ts) {
					found = true
					readLoc[o.loc]++
				}
			}
			if found {
				matched++
			}
		}
		if lf == nil || cev.ts.Add(horizon).After(l.Last) {
			continue // undecided: not observed long enough
		}
		if !hasX {
			continue // the object of the outcome was not captured: unknown, not "never"
		}
		final := lf.initial
		gk := ""
		var back *[2]string
		if h := m.hist[x]; h != nil {
			final = h.segs[len(h.segs)-1].state
			if n := len(h.segs); n >= 2 {
				if key := [2]string{h.segs[n-2].state, final}; backEffect[key] != "" {
					back, gk = &key, "<-"+key[0]
				}
			}
		}
		gk = final + gk
		g := groups[gk]
		if g == nil {
			g = &group{final: final, subjects: map[int32]bool{}, back: back}
			groups[gk] = g
		}
		g.n++
		decided = append(decided, decidedCause{in.ev, gk})
		if s := l.subjectOf(in.ev); s >= 0 {
			g.subjects[s] = true
		}
	}
	if len(subjects) < cfg.KMin {
		return nil, whyNot{code: WhyFewSubjects, causes: len(insts), subjects: len(subjects), text: fmt.Sprintf("only %d distinct subjects, at least %d needed", len(subjects), cfg.KMin)}
	}
	rule.Evidence.Counts = CausalCounts{Causes: len(insts), DistinctSubjects: len(subjects), Outcomes: map[string]int{}}
	km := matched
	rule.Evidence.Counts.KeyMatches = &km
	if lf != nil && len(readLoc) > 0 {
		le := m.ents[lifeEnt]
		best, bn := int32(-1), 0
		for lc, n := range readLoc {
			if n > bn || (n == bn && lc < best) {
				best, bn = lc, n
			}
		}
		keys = append(keys, KeyRef{Domain: le.dom, From: l.keyEnd(le.creatorLoc), To: l.keyEnd(best), Matches: matched})
	}

	if lf == nil {
		rule.Outcomes = []Outcome{{Name: "always", P: 1, Effects: immediate}}
		rule.Evidence.Counts.Outcomes["always"] = len(insts)
	} else {
		var gs []*group
		// reached is the state the forward steps of a group reach (for a
		// return, the state it leaves).
		reached := func(g *group) string {
			if g.back != nil {
				return g.back[0]
			}
			return g.final
		}
		gkey := func(g *group) string {
			if g.back != nil {
				return g.final + "<-" + g.back[0]
			}
			return g.final
		}
		for _, g := range groups {
			if lf.chain(reached(g)) == nil || len(g.subjects) < cfg.KMin {
				continue
			}
			gs = append(gs, g)
		}
		sort.Slice(gs, func(a, b int) bool {
			if gs[a].n != gs[b].n {
				return gs[a].n > gs[b].n
			}
			return gkey(gs[a]) < gkey(gs[b])
		})
		total := 0
		for _, g := range gs {
			total += g.n
		}
		if total == 0 {
			var parts []string
			decided := 0
			for _, f := range sortedKeys(groups) {
				parts = append(parts, fmt.Sprintf("%s %d users", f, len(groups[f].subjects)))
				decided += groups[f].n
			}
			detail := "none decided yet"
			if len(parts) > 0 {
				detail = strings.Join(parts, ", ")
			}
			code := WhyOutcomeFewSubjects
			if decided == 0 {
				code = WhyUndecided
			}
			return nil, whyNot{code: code, causes: len(insts), decided: decided, subjects: len(subjects), horizon: horizon,
				text: fmt.Sprintf("no outcome with enough subjects (%s; k=%d; %d of %d causes decided, horizon %s)",
					detail, cfg.KMin, decided, len(insts), horizon.Round(time.Second))}
		}
		happyDone := false
		outName := map[string]string{}
		for _, g := range gs {
			effects := append([]string{}, immediate...)
			ch := lf.chain(reached(g))
			okChain := true
			for k := 1; k < len(ch); k++ {
				id, ok := edgeEffect[[2]string{ch[k-1], ch[k]}]
				if !ok {
					okChain = false
					break
				}
				effects = append(effects, id)
			}
			if !okChain {
				continue
			}
			var name string
			switch {
			case g.back != nil:
				effects = append(effects, backEffect[*g.back])
				name = slug(g.final) + "-again"
				if _, dup := rule.Evidence.Counts.Outcomes[name]; dup {
					name += "-from-" + slug(g.back[0])
				}
			case g.final == lf.initial:
				name = "never"
			case lf.terminal[g.final] && !happyDone:
				name, happyDone = "happy", true
			case lf.terminal[g.final]:
				name = slug(g.final)
			default:
				name = "stuck-" + slug(g.final)
			}
			if !reIdent.MatchString(name) {
				continue
			}
			rule.Outcomes = append(rule.Outcomes, Outcome{Name: name, P: float64(g.n) / float64(total), Effects: effects})
			rule.Evidence.Counts.Outcomes[name] = g.n
			outName[gkey(g)] = name
		}
		roundProbabilities(rule.Outcomes)
		m.conditionOutcomes(rule, decided, outName)
	}
	if len(rule.Outcomes) == 0 {
		return nil, whyNot{code: WhyNoOutcome, causes: len(insts), text: "no outcome observed"}
	}
	rule.Evidence.Keys = dedupeKeys(keys, cfg.KMin)
	if len(mags) > 0 {
		rule.Evidence.Hints = &CausalHints{Magnitude: mags}
	}
	rule.Title = causalTitle(rule, e0, lifeEnt, m)
	// Confidence: causes whose effect was observed, among the causes whose
	// effect object was captured at all (a gap in the capture is not a
	// failed rule).
	conf, denom := 0.0, withX
	if denom == 0 {
		denom = len(insts)
	}
	if denom > 0 {
		conf = float64(matched) / float64(denom)
	}
	return &Mined{Rule: Rule{Causal: rule}, Signature: "causal|" + op.service + "|" + op.op + "|" + e0.sig,
		Structure: causalStructure(rule), Confidence: conf}, whyNot{}
}

// creatorRecord returns the creator record of object x of entity i.
func (m *miner) creatorRecord(i int, x int32) *record {
	b := m.birth[x]
	if b.ev < 0 {
		return nil
	}
	e := m.ents[i]
	for ri := range m.l.evs[b.ev].recs {
		r := &m.l.evs[b.ev].recs[ri]
		if r.side == sideResp && r.path == e.creatorRec {
			if f, ok := r.id(e.idField); ok && f.tok == x {
				return r
			}
		}
	}
	return nil
}

func dedupeKeys(keys []KeyRef, kMin int) []KeyRef {
	seen := map[string]bool{}
	var out []KeyRef
	for _, k := range keys {
		if k.Matches < kMin {
			continue
		}
		s := k.Domain + "|" + k.From.Service + k.From.Op + k.From.At.String() + "|" + k.To.Service + k.To.Op + k.To.At.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, k)
	}
	return out
}

// roundProbabilities rounds to 3 decimals keeping the sum at exactly 1.
func roundProbabilities(os []Outcome) {
	if len(os) == 0 {
		return
	}
	sum := 0.0
	big := 0
	for i := range os {
		os[i].P = math.Round(os[i].P*1000) / 1000
		sum += os[i].P
		if os[i].P > os[big].P {
			big = i
		}
	}
	os[big].P = math.Round((os[big].P+1-sum)*1000) / 1000
}

func sortedInts(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func causalTitle(r *CausalRule, e0 *entity, lifeEnt int, m *miner) string {
	t := fmt.Sprintf("%s su %s crea %s", r.Cause.Op, r.Cause.Service, e0.def.Name)
	if lifeEnt >= 0 {
		le := m.ents[lifeEnt]
		var states []string
		lf := m.lifes[lifeEnt]
		for _, ed := range lf.edges() {
			if len(states) == 0 {
				states = append(states, ed[0])
			}
			states = append(states, ed[1])
		}
		if lifeEnt != m.entByDom[e0.dom] {
			t += fmt.Sprintf(" e %s", le.def.Name)
		}
		t += fmt.Sprintf("; ciclo di vita di %s: %s", le.def.Name, strings.Join(states, ", "))
	}
	if len([]rune(t)) > 200 {
		t = string([]rune(t)[:200])
	}
	return t
}

// spontaneous reports whether entity i has a lifecycle with a transition
// no write explains.
func (m *miner) spontaneous(i int) bool {
	lf := m.lifes[i]
	if lf == nil || len(lf.succ) == 0 {
		return false
	}
	for _, ed := range lf.edges() {
		if !m.caused[i][ed[1]] {
			return true
		}
	}
	return false
}

func causalStructure(r *CausalRule) string {
	var b strings.Builder
	for _, e := range r.Effects {
		fmt.Fprintf(&b, "%s/%s/%s/%s/%s;", e.ID, e.Entity, e.Target, e.TargetID, e.AfterEffect)
		if e.Remove {
			b.WriteString("remove;")
		}
		if e.TargetKey != nil {
			b.WriteString("key:")
			for _, k := range sortedKeys(*e.TargetKey) {
				fmt.Fprintf(&b, "%s=%s,", k, (*e.TargetKey)[k])
			}
			b.WriteString(";")
		}
		if rs := e.Respond; rs != nil {
			fmt.Fprintf(&b, "respond:%s %s %d;", rs.Service, rs.Op, rs.Status)
			if lm := rs.Limit; lm != nil {
				fmt.Fprintf(&b, "limit:%d/%s/%s;", lm.N, lm.Window, lm.Key)
			}
		}
		for _, k := range sortedKeys(e.Where) {
			fmt.Fprintf(&b, "where:%s=%v,", k, e.Where[k])
		}
		for _, k := range sortedKeys(e.Set) {
			fmt.Fprintf(&b, "%s=%v,", k, e.Set[k])
		}
		for _, k := range sortedKeys(e.Create) {
			fmt.Fprintf(&b, "%s=%v,", k, e.Create[k])
		}
	}
	for _, o := range r.Outcomes {
		fmt.Fprintf(&b, "|%s:%s", o.Name, strings.Join(o.Effects, ","))
		if len(o.When) > 0 {
			b.WriteString("?" + whenKey(o.When))
		}
	}
	return b.String()
}

// minDecisionHorizon is the floor of a horizon learned from the traffic.
const minDecisionHorizon = time.Minute

// decisionHorizon is how old a cause must be for its outcome to count as
// decided. Without enough observed completions it is the coverage floor
// (Config.MinHorizon, or the 99th percentile of the completions when longer).
// With at least KMin completions it is learned from them: twice their 99th
// percentile (at least a minute, at most the coverage floor unless the
// percentile itself is longer). A lifecycle that completes in seconds (a
// notification delivered or bounced) is decided after a minute instead of
// an hour: with the fixed floor the causes of the last hour were never
// decided, so a service whose identifiers became tokens less than an hour
// before the run could get no rule at all.
func decisionHorizon(ds []time.Duration, cfg *Config) time.Duration {
	floor := cfg.MinCoverage()
	if len(ds) == 0 {
		return floor
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	q := ds[int(math.Min(float64(len(ds)-1), math.Floor(0.99*float64(len(ds)))))]
	if len(ds) < cfg.KMin {
		return max(floor, q)
	}
	return max(q, min(floor, max(2*q, minDecisionHorizon)))
}

// noEffectText explains a candidate without effects. Values in clear (a
// status leaving as a code) mean the object simply has no lifecycle; only
// when nothing of it is in clear may the policy be what is missing.
func noEffectText(e *entity) string {
	if len(e.clearFields) > 0 {
		return "no object created by a nested call and no lifecycle observed: the object's values are in clear but they do not change over time"
	}
	return "no object created by a nested call and no lifecycle observed, and no field of the object is in clear"
}
