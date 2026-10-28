package mock

import (
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Rules v1.8 (docs/spec/rules.md 3.8 and 3.9).
//
//   - target_key: an effect changes (or removes) the record of a keyed
//     entity, the one of the cause's customer (when the key has the owner)
//     whose key fields take the values of target_key. A set creates the
//     record when it is missing, like a write of upserted_by.
//   - respond.limit: a response effect becomes a counter per key. Every
//     application counts one call for its key (the value of limit.key in
//     the cause's request, else the cause's customer); before serving a
//     call of respond.service/op the mock counts the calls with the key of
//     that call within limit.window (the whole session when absent), and
//     when they are at least limit.n the call answers respond.status with
//     the contract example (a second creation with the same key, too many
//     attempts, a rate limit).

// countedCall is one call counted by a limit.
type countedCall struct {
	key string
	at  time.Time
}

// limitDef is a response effect with a limit, compiled.
type limitDef struct {
	cr     *causalRule
	eff    *pack.Effect
	svc    *service
	window time.Duration
	keyVar string
}

// compileLimits collects the response effects with a limit.
func (m *model) compileLimits() {
	for _, cr := range m.causal {
		for i := range cr.r.Effects {
			e := &cr.r.Effects[i]
			if e.Respond == nil || e.Respond.Limit == nil {
				continue
			}
			ld := &limitDef{cr: cr, eff: e, svc: m.byName[e.Respond.Service]}
			if w := e.Respond.Limit.Window; w != "" {
				ld.window, _ = pack.ParseDuration(w)
			}
			if k := e.Respond.Limit.Key; k != "" {
				if sm := wholeVarRE.FindStringSubmatch(k); sm != nil {
					ld.keyVar = sm[1]
				}
			}
			m.limits = append(m.limits, ld)
		}
	}
}

func limitSlot(cr *causalRule, e *pack.Effect) string { return cr.r.ID + "\x00" + e.ID }

// customerKey is the key of a limit without limit.key.
func customerKey(c *string) string {
	if c == nil {
		return "c:"
	}
	return "c:" + *c
}

// countCall applies a response effect with a limit: one more call for the
// key of the firing.
func (s *session) countCall(q *queued) appliedEffect {
	e, inst := q.eff, q.inst
	key := customerKey(inst.customer)
	if k := e.Respond.Limit.Key; k != "" {
		if sm := wholeVarRE.FindStringSubmatch(k); sm != nil {
			if v, ok := scalarString(inst.vars[sm[1]]); ok {
				key = "v:" + v
			}
		}
	}
	if s.counted == nil {
		s.counted = map[string][]countedCall{}
	}
	slot := limitSlot(inst.rule, e)
	s.counted[slot] = append(s.counted[slot], countedCall{key: key, at: s.now})
	return appliedEffect{At: fmtTime(s.now), Rule: inst.rule.r.ID, Outcome: inst.outcome, Effect: e.ID,
		Respond: e.Respond.Service + " " + e.Respond.Op}
}

// limitFor decides whether a limit answers this call: the first limit of
// the operation (in rule order) whose counted calls with the key of the
// call reach n within the window.
func (s *session) limitFor(svc *service, opKey string, ex *exchange) (faultDecision, string, bool) {
	for _, ld := range s.m.model.limits {
		rs := ld.eff.Respond
		if ld.svc != svc || rs.Op != opKey {
			continue
		}
		key := customerKey(s.customer)
		if ld.keyVar != "" {
			v, ok := evalRef(ld.cr.binds[ld.keyVar], ex)
			sv, isScalar := scalarString(v)
			if !ok || !isScalar {
				continue
			}
			key = "v:" + sv
		}
		n := 0
		for _, c := range s.counted[limitSlot(ld.cr, ld.eff)] {
			if c.key == key && (ld.window == 0 || s.now.Sub(c.at) < ld.window) {
				n++
			}
		}
		if n < rs.Limit.N {
			continue
		}
		if p := rs.Prob(); p < 1 && s.rngRespond.Float64() >= p {
			continue
		}
		return faultDecision{status: rs.Status, example: rs.Example}, ld.cr.r.ID, true
	}
	return faultDecision{}, "", false
}

// applyKeyed applies an effect with target_key: the record of the key,
// created by a set when missing.
func (s *session) applyKeyed(q *queued) (appliedEffect, bool) {
	e, inst := q.eff, q.inst
	ed := s.m.model.entities[e.Entity]
	if ed == nil || ed.def.Key == nil {
		return appliedEffect{}, false
	}
	vals := map[string]string{}
	for f, v := range *e.TargetKey {
		if sm := wholeVarRE.FindStringSubmatch(v); sm != nil {
			sv, ok := scalarString(inst.vars[sm[1]])
			if !ok {
				return appliedEffect{}, false
			}
			v = sv
		}
		vals[f] = v
	}
	owner := inst.customer
	if !ed.def.Key.Owner {
		owner = nil
	}
	var rec *entityRec
	if rs := s.keyedRecordsOf(ed, vals, owner, ed.def.Key.Owner); len(rs) > 0 {
		rec = rs[0]
	}
	if rec == nil {
		if e.Remove || e.Where != nil {
			return appliedEffect{}, false
		}
		state := map[string]any{}
		for f, v := range vals {
			setDotted(state, f, v)
		}
		rec = &entityRec{entity: e.Entity, id: s.nextID(e.Entity, state), customerID: copyStr(inst.customer), state: state, created: s.now, updated: s.now}
		s.putEnt(rec)
	}
	return s.applyOn(q, rec)
}
