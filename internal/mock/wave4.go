package mock

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Rules v1.9 (docs/spec/rules.md 2.11-2.13, 3.12-3.15; docs/spec/mock.md
// 2.8).
//
//   - Conditions: cause.when.match must hold for a rule to fire;
//     outcomes[].when restricts the outcomes that can be drawn (the
//     eligible ones are those whose when holds, else those without when;
//     the draw is renormalized among them and always consumed; a forced
//     outcome wins).
//   - Customer attributes: one value per session, the customer's profile
//     value when the world has it, else drawn once from the attribute's
//     shares; written at the attribute's response members unless the
//     entity state gives that member.
//   - Aggregates: response numbers computed at read time from the
//     session's collections (count, sum) or moved by writes (delta).
//   - Lists no entity reads: their static answer is paged, so a full page
//     of an example never paginates forever.
//   - Preconditions (respond.until): from the start of the session a call
//     answers the effect's status until the effect applies.
//   - target_all: an effect on every entity of the cause's customer that
//     matches where.

// compiledMatch is one condition with its request ref compiled.
type compiledMatch struct {
	m   pack.Match
	ref compiledRef
}

type attrField struct {
	attr *pack.Attribute
	segs []pathSeg
}

type aggDef struct {
	g    *pack.Aggregate
	segs []pathSeg
	// deltas are the operations (service\x00op) that move a delta.
	deltas []string
	by     []int
}

type listOpDef struct {
	rd      *readDef // a read with the list shape only (parsePaging)
	arrSegs []pathSeg
}

type untilDef struct {
	cr  *causalRule
	eff *pack.Effect
	svc *service
}

func compileMatches(ms []pack.Match) ([]compiledMatch, error) {
	out := make([]compiledMatch, 0, len(ms))
	for _, m := range ms {
		cm := compiledMatch{m: m}
		if m.At != nil {
			cm.ref = compiledRef{ref: *m.At}
			if m.At.Path != "" {
				segs, err := parseTTPath(m.At.Path)
				if err != nil {
					return nil, err
				}
				cm.ref.segs = segs
			}
		}
		out = append(out, cm)
	}
	return out, nil
}

// compileWave4 compiles the v1.9 members of the pack's rules.
func (m *model) compileWave4() error {
	rules := m.pack.Rules
	opOK := func(svc, op string) bool {
		s := m.byName[svc]
		return s != nil && s.c.byKey[op] != nil
	}
	for _, cr := range m.causal {
		var err error
		if cr.match, err = compileMatches(cr.r.Cause.When.Match); err != nil {
			return fmt.Errorf("rule %s: %w", cr.r.ID, err)
		}
		for _, o := range cr.r.Outcomes {
			if len(o.When) == 0 {
				continue
			}
			cms, err := compileMatches(o.When)
			if err != nil {
				return fmt.Errorf("rule %s: %w", cr.r.ID, err)
			}
			if cr.outWhen == nil {
				cr.outWhen = map[string][]compiledMatch{}
			}
			cr.outWhen[o.Name] = cms
		}
		for i := range cr.r.Effects {
			e := &cr.r.Effects[i]
			if e.Respond != nil && e.Respond.Until {
				m.untils = append(m.untils, &untilDef{cr: cr, eff: e, svc: m.byName[e.Respond.Service]})
			}
		}
	}
	m.attrBy = map[string]*pack.Attribute{}
	m.attrFields = map[string][]attrField{}
	for i := range rules.Attributes {
		a := &rules.Attributes[i]
		m.attrBy[a.Name] = a
		for _, f := range a.Fields {
			if !opOK(f.Service, f.Op) {
				return fmt.Errorf("attribute %s: operation %q is not in the contract of %s", a.Name, f.Op, f.Service)
			}
			segs, err := parseTTPath(f.At.Path)
			if err != nil {
				return fmt.Errorf("attribute %s: %w", a.Name, err)
			}
			k := f.Service + "\x00" + f.Op
			m.attrFields[k] = append(m.attrFields[k], attrField{attr: a, segs: segs})
		}
	}
	m.aggs = map[string][]*aggDef{}
	m.deltaOps = map[string]bool{}
	for i := range rules.Aggregates {
		g := &rules.Aggregates[i]
		if !opOK(g.Service, g.Op) {
			return fmt.Errorf("aggregate: operation %q is not in the contract of %s", g.Op, g.Service)
		}
		segs, err := parseTTPath(g.At.Path)
		if err != nil {
			return fmt.Errorf("aggregate: %w", err)
		}
		ad := &aggDef{g: g, segs: segs}
		for _, d := range g.Delta {
			svc := d.Service
			if svc == "" {
				svc = g.Service
			}
			if !opOK(svc, d.Op) {
				return fmt.Errorf("aggregate: delta operation %q is not in the contract of %s", d.Op, svc)
			}
			k := svc + "\x00" + d.Op
			ad.deltas, ad.by = append(ad.deltas, k), append(ad.by, d.By)
			m.deltaOps[k] = true
		}
		k := g.Service + "\x00" + g.Op
		m.aggs[k] = append(m.aggs[k], ad)
	}
	m.listOps = map[string]*listOpDef{}
	for i := range rules.Lists {
		lo := &rules.Lists[i]
		if !opOK(lo.Service, lo.Op) {
			return fmt.Errorf("list: operation %q is not in the contract of %s", lo.Op, lo.Service)
		}
		segs, err := parseTTPath(lo.At.Path)
		if err != nil || len(segs) == 0 || segs[len(segs)-1].kind != segAnyIdx {
			return fmt.Errorf("list %s %s: bad items path", lo.Service, lo.Op)
		}
		l := lo.List
		rd := &readDef{rb: pack.ReadBy{Op: lo.Op, List: &l}, list: true}
		for _, pp := range []struct {
			src string
			dst *[]pathSeg
		}{{l.Count, &rd.countSegs}, {l.Total, &rd.totalSegs}, {l.NextCursor, &rd.nextSegs}} {
			if pp.src == "" {
				continue
			}
			if *pp.dst, err = parseTTPath(pp.src); err != nil {
				return fmt.Errorf("list %s %s: %w", lo.Service, lo.Op, err)
			}
		}
		m.listOps[lo.Service+"\x00"+lo.Op] = &listOpDef{rd: rd, arrSegs: segs[:len(segs)-1]}
	}
	return nil
}

// ---- conditions ----

// matchAll reports whether every condition holds for this exchange and
// the session's customer.
func (s *session) matchAll(ms []compiledMatch, ex *exchange) bool {
	for _, cm := range ms {
		var v any
		var ok bool
		if cm.m.Customer != "" {
			var sv string
			sv, ok = s.attrValue(cm.m.Customer)
			v = sv
		} else {
			v, ok = evalRef(cm.ref, ex)
		}
		if !pack.MatchValue(cm.m, v, ok) {
			return false
		}
	}
	return true
}

// conditionalOutcome draws among the eligible outcomes of a rule with
// conditional outcomes: those whose when holds, else those without when.
// u is the draw already taken; "" when no outcome is eligible.
func (s *session) conditionalOutcome(cr *causalRule, u float64, ex *exchange) string {
	var cond, plain []pack.Outcome
	for _, o := range cr.r.Outcomes {
		if ms, has := cr.outWhen[o.Name]; has {
			if s.matchAll(ms, ex) {
				cond = append(cond, o)
			}
			continue
		}
		plain = append(plain, o)
	}
	elig := cond
	if len(elig) == 0 {
		elig = plain
	}
	total := 0.0
	for _, o := range elig {
		total += o.P
	}
	if len(elig) == 0 || total <= 0 {
		return ""
	}
	cum := 0.0
	for _, o := range elig {
		cum += o.P
		if u*total < cum {
			return o.Name
		}
	}
	return elig[len(elig)-1].Name
}

// ---- customer attributes ----

// attrValue is the session's value of a customer attribute: the profile
// value of the session's customer when the world gives it, else a value
// drawn once for the session from the attribute's shares.
func (s *session) attrValue(name string) (string, bool) {
	mod := s.m.model
	a := mod.attrBy[name]
	if s.customer != nil {
		if c := mod.custByID[*s.customer]; c != nil {
			if v, ok := c.Profile[name]; ok && v != nil {
				if cv := pack.CanonScalar(v); cv != "" {
					return cv, true
				}
			}
		}
	}
	if a == nil {
		return "", false
	}
	if v, ok := s.attrCache[name]; ok {
		return v, true
	}
	vals := make([]string, 0, len(a.Values))
	for v := range a.Values {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	total := 0.0
	for _, v := range vals {
		total += a.Values[v]
	}
	if len(vals) == 0 || total <= 0 {
		return "", false
	}
	u := deriveRNG(s.seed, "attribute/"+s.id+"/"+name).Float64() * total
	pick, cum := vals[len(vals)-1], 0.0
	for _, v := range vals {
		cum += a.Values[v]
		if u < cum {
			pick = v
			break
		}
	}
	if s.attrCache == nil {
		s.attrCache = map[string]string{}
	}
	s.attrCache[name] = pick
	return pick, true
}

// ---- preconditions ----

func untilSlot(u *untilDef) string { return u.cr.r.ID + "\x00" + u.eff.ID }

// untilFor decides whether a precondition answers this call: the first
// (in rule order) of the operation not lifted yet in the session.
func (s *session) untilFor(svc *service, opKey string) (faultDecision, string, bool) {
	for _, u := range s.m.model.untils {
		if u.svc != svc || u.eff.Respond.Op != opKey || s.lifted[untilSlot(u)] {
			continue
		}
		return faultDecision{status: u.eff.Respond.Status, example: u.eff.Respond.Example}, u.cr.r.ID, true
	}
	return faultDecision{}, "", false
}

// liftUntil applies a precondition effect: the calls answer normally from
// now on.
func (s *session) liftUntil(q *queued) appliedEffect {
	if s.lifted == nil {
		s.lifted = map[string]bool{}
	}
	s.lifted[q.inst.rule.r.ID+"\x00"+q.eff.ID] = true
	return appliedEffect{At: fmtTime(s.now), Rule: q.inst.rule.r.ID, Outcome: q.inst.outcome, Effect: q.eff.ID,
		Respond: q.eff.Respond.Service + " " + q.eff.Respond.Op}
}

// ---- target_all ----

// applyAll applies an effect to every entity of its type owned by the
// customer of the cause that matches where.
func (s *session) applyAll(q *queued) []appliedEffect {
	e, inst := q.eff, q.inst
	var out []appliedEffect
	for _, rec := range s.sortedEnts(e.Entity) {
		if q.entityID != "" && rec.id != q.entityID {
			continue // a pending line of the world names one entity
		}
		if !sameOwner(rec.customerID, inst.customer) || (e.Where != nil && !s.matchWhere(rec, e.Where)) {
			continue
		}
		if a, ok := s.applyOn(q, rec); ok {
			out = append(out, a)
		}
	}
	return out
}

// ---- response finishing ----

// noteCall counts a successful call of an operation that moves a delta
// aggregate.
func (s *session) noteCall(svc *service, opKey string, status int) {
	k := svc.name + "\x00" + opKey
	if status < 200 || status > 299 || !s.m.model.deltaOps[k] {
		return
	}
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[k]++
}

// finishBody applies the v1.9 read-time members to a success body: the
// paging of a list no entity reads, the customer attributes and the
// aggregates. ov is the entity overlay the body was built from.
func (s *session) finishBody(svc *service, op *operation, status int, body any, ov optVal, params map[string]string, q url.Values, h http.Header) any {
	mod := s.m.model
	if status < 200 || status > 299 || body == nil {
		return body
	}
	k := svc.name + "\x00" + op.key
	if lo := mod.listOps[k]; lo != nil && len(mod.reads[k]) == 0 {
		body = s.pageStatic(svc, lo, op, status, body, params, q, h)
	}
	var schema any
	if r := op.responses[status]; r != nil {
		schema = r.schema
	}
	for _, af := range mod.attrFields[k] {
		if overlayHas(ov, af.segs) {
			continue // the entity state gives this member
		}
		val, ok := s.attrValue(af.attr.Name)
		if !ok {
			continue
		}
		cur, present := first(evalPath(body, af.segs))
		typ := ""
		if schema != nil {
			if ms := memberSchema(svc.c.sc, schema, af.segs); ms != nil {
				typ = primaryType(ms)
			}
		}
		if typ == "" && present {
			switch cur.(type) {
			case bool:
				typ = "boolean"
			case json.Number, float64:
				typ = "number"
			default:
				typ = "string"
			}
		}
		if typ == "" {
			continue
		}
		if v, ok := convertScalar(val, typ); ok {
			setAtPath(body, af.segs, v)
		}
	}
	for _, ad := range mod.aggs[k] {
		cur, _ := first(evalPath(body, ad.segs))
		if v, ok := s.aggregate(ad, cur); ok {
			setAtPath(body, ad.segs, v)
		}
	}
	return body
}

// aggregate computes the value of an aggregate; cur is the value the body
// already has (the base of a delta).
func (s *session) aggregate(ad *aggDef, cur any) (any, bool) {
	g := ad.g
	switch {
	case g.Count != nil || g.Sum != nil:
		entity, where := "", map[string]any(nil)
		if g.Count != nil {
			entity, where = g.Count.Entity, g.Count.Where
		} else {
			entity, where = g.Sum.Entity, g.Sum.Where
		}
		n, sum := 0, 0.0
		for _, rec := range s.sortedEnts(entity) {
			if s.customer != nil && !ownedBy(rec, *s.customer) {
				continue
			}
			if where != nil && !s.matchWhere(rec, where) {
				continue
			}
			n++
			if g.Sum != nil {
				if v, ok := getDotted(rec.state, g.Sum.Field); ok {
					if f, ok := numFloat(v); ok {
						sum += f
					}
				}
			}
		}
		if g.Count != nil {
			return intNumber(n), true
		}
		return numberOut(sum), true
	case len(ad.deltas) > 0:
		base, _ := numFloat(cur)
		for i, k := range ad.deltas {
			base += float64(ad.by[i] * s.calls[k])
		}
		return numberOut(base), true
	}
	return nil, false
}

func numberOut(f float64) any {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return json.Number(strconv.FormatInt(int64(f), 10))
	}
	return json.Number(strconv.FormatFloat(f, 'f', -1, 64))
}

// pageStatic pages the static answer of a list no entity reads: the items
// of the example are the whole list, a page beyond them is empty.
func (s *session) pageStatic(svc *service, lo *listOpDef, op *operation, status int, body any, params map[string]string, q url.Values, h http.Header) any {
	var arr []any
	if len(lo.arrSegs) == 0 {
		arr, _ = body.([]any)
	} else if v, ok := first(evalPath(body, lo.arrSegs)); ok {
		arr, _ = v.([]any)
	}
	if arr == nil {
		return body
	}
	total := len(arr)
	pg, viol := parsePaging(lo.rd, params, q, h)
	if viol != nil {
		l := lo.rd.rb.List
		if l.Cursor == nil || viol.ptr != paramPointer(l.Cursor.From, l.Cursor.Name) {
			return body
		}
		pg = paging{offset: total} // a cursor this mock did not mint: the end
	}
	end := total
	if pg.hasLimit {
		end = pg.offset + pg.limit
		if end > total || end < 0 {
			end = total
		}
	}
	start := pg.offset
	if start > total {
		start = total
	}
	if start > end {
		start = end
	}
	page := append([]any{}, arr[start:end]...)
	if len(lo.arrSegs) == 0 {
		return page
	}
	setAtPath(body, lo.arrSegs, page)
	if lo.rd.countSegs != nil {
		setAtPath(body, lo.rd.countSegs, intNumber(len(page)))
	}
	if lo.rd.totalSegs != nil {
		setAtPath(body, lo.rd.totalSegs, intNumber(total))
	}
	if lo.rd.nextSegs != nil {
		if pg.hasLimit && end < total {
			setAtPath(body, lo.rd.nextSegs, "c"+strconv.Itoa(end))
		} else {
			r := op.responses[status]
			if r != nil && r.schema != nil && nullableAt(svc.c.sc, r.schema, lo.rd.nextSegs) {
				setAtPath(body, lo.rd.nextSegs, nil)
			} else {
				deleteAtPath(body, lo.rd.nextSegs)
			}
		}
	}
	return body
}

// filterList keeps the items whose field equals the value of each filter
// parameter the request carries (rules v1.9).
func (s *session) filterList(rd *readDef, recs []*entityRec, params map[string]string, q url.Values, h http.Header) []*entityRec {
	l := rd.rb.List
	if l == nil || len(l.Filters) == 0 {
		return recs
	}
	for _, f := range l.Filters {
		val, ok := lookupParam(f.Param.From, f.Param.Name, params, q, h)
		if !ok {
			continue
		}
		want := pack.CanonScalar(val)
		kept := recs[:0:0]
		for _, r := range recs {
			if v, ok := getDotted(s.overlay(r), f.Field); ok && v != nil && pack.CanonScalar(v) == want {
				kept = append(kept, r)
			}
		}
		recs = kept
	}
	return recs
}

// overlayHas reports whether the entity overlay a body was built from
// gives the member at segs.
func overlayHas(ov optVal, segs []pathSeg) bool {
	if !ov.ok {
		return false
	}
	cur := ov.v
	for _, sg := range segs {
		if eo, ok := cur.(entOverlay); ok {
			cur = eo.vals
		}
		mm, ok := cur.(map[string]any)
		if !ok || sg.kind != segKey {
			return false
		}
		if cur, ok = mm[sg.key]; !ok {
			return false
		}
		if _, omit := cur.(omitValue); omit {
			return false
		}
	}
	return true
}

// memberSchema is the flat schema of the member at segs (keys only).
func memberSchema(sc *schemaCtx, schema any, segs []pathSeg) map[string]any {
	cur := schema
	for _, sg := range segs {
		if sg.kind != segKey {
			return nil
		}
		f := sc.flat(cur, 0)
		props, _ := f["properties"].(map[string]any)
		next, ok := props[sg.key]
		if !ok {
			return nil
		}
		cur = next
	}
	return sc.flat(cur, 0)
}

// convertScalar writes a clear value with the type of the schema.
func convertScalar(v, typ string) (any, bool) {
	switch typ {
	case "boolean":
		switch v {
		case "true":
			return true, true
		case "false":
			return false, true
		}
		return nil, false
	case "integer":
		if _, err := strconv.ParseInt(v, 10, 64); err == nil {
			return json.Number(v), true
		}
		return nil, false
	case "number":
		if f, err := strconv.ParseFloat(v, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return json.Number(strings.TrimSpace(v)), true
		}
		return nil, false
	case "string":
		return v, true
	}
	return nil, false
}

// deleteAtPath removes the member at ".a.b" style segs, if present.
func deleteAtPath(body any, segs []pathSeg) {
	cur, ok := body.(map[string]any)
	if !ok || len(segs) == 0 {
		return
	}
	for _, sg := range segs[:len(segs)-1] {
		if cur, ok = cur[sg.key].(map[string]any); !ok {
			return
		}
	}
	delete(cur, segs[len(segs)-1].key)
}
