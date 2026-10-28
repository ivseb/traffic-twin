package mock

import (
	"fmt"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Response effects (docs/spec/rules.md section 3.6, rules v1.4): a causal
// rule may change how later calls are answered instead of an entity ("after
// a cancelled order, the next GET of its invoice answers 410"; "after a
// payment, quotes fail 20% of the time"). When the effect applies, the
// session installs an override; each later call of the operation answers
// the override's status with probability p, for at most times calls.

// ruleResponse is an installed response effect.
type ruleResponse struct {
	rule, effect string
	svc          *service
	r            *pack.Respond
	used         int
}

// compileResponds checks the response effects of the causal rules against
// the services and contracts of the pack.
func (m *model) compileResponds() error {
	for _, cr := range m.causal {
		for i := range cr.r.Effects {
			e := &cr.r.Effects[i]
			if e.Respond == nil {
				continue
			}
			svc := m.byName[e.Respond.Service]
			if svc == nil {
				return fmt.Errorf("rule %s: effect %s answers for unknown service %q", cr.r.ID, e.ID, e.Respond.Service)
			}
			if svc.c.byKey[e.Respond.Op] == nil {
				return fmt.Errorf("rule %s: effect %s: op %q is not in the contract of %s", cr.r.ID, e.ID, e.Respond.Op, svc.name)
			}
		}
	}
	return nil
}

// installResponse applies a response effect.
func (s *session) installResponse(q *queued) appliedEffect {
	e := q.eff
	s.responses = append(s.responses, &ruleResponse{rule: q.inst.rule.r.ID, effect: e.ID, svc: s.m.model.byName[e.Respond.Service], r: e.Respond})
	return appliedEffect{At: fmtTime(s.now), Rule: q.inst.rule.r.ID, Outcome: q.inst.outcome, Effect: e.ID,
		Respond: e.Respond.Service + " " + e.Respond.Op}
}

// ruleResponseFor decides whether an installed response effect answers this
// call: the oldest matching one whose draw succeeds. Its draws come from a
// stream of their own, so they never shift faults or outcomes.
func (s *session) ruleResponseFor(svc *service, opKey string) (faultDecision, string, bool) {
	for _, rr := range s.responses {
		if rr.svc != svc || rr.r.Op != opKey {
			continue
		}
		if rr.r.Times > 0 && rr.used >= rr.r.Times {
			continue
		}
		if p := rr.r.Prob(); p < 1 && s.rngRespond.Float64() >= p {
			continue
		}
		rr.used++
		return faultDecision{status: rr.r.Status, example: rr.r.Example, body: rr.r.Body}, rr.rule, true
	}
	return faultDecision{}, "", false
}
