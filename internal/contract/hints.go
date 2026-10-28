package contract

import (
	"strings"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Location identifies a value in an operation.
type Location struct {
	Service string
	// Op is the event op ("GET /orders/{id}").
	Op string
	// Side is "req" or "resp".
	Side string
	// Part is "path", "query", "headers", "cookies" or "body".
	Part string
	// Name is the parameter name for path/query/headers/cookies and the
	// tt-path ("$.items[*].orderId") for body.
	Name string
}

// Hints supplies facts the events cannot carry: the HMAC domain of a token
// (it is part of the signed policy, not of the token), the full bounds of a
// numeric bucket, the entity an operation exposes. All methods may return
// "" or nil when unknown; a nil Hints is valid.
type Hints interface {
	// Domain returns the HMAC domain of the value at l ("order").
	Domain(l Location) string
	// Bounds returns the bucket(num) bounds (canonical lexemes) of l.
	Bounds(l Location) []string
	// Entity returns the entity exposed by the operation (x-tt-entity).
	Entity(service, op string) string
}

type noHints struct{}

func (noHints) Domain(Location) string       { return "" }
func (noHints) Bounds(Location) []string     { return nil }
func (noHints) Entity(string, string) string { return "" }

// NoHints is a Hints that knows nothing.
var NoHints Hints = noHints{}

// PolicyHints derives hints from compiled policies: HMAC domains and bucket
// bounds come from the effective rule of the value (operation, then service,
// then global). Policies are searched in order; the first that defines the
// service wins.
func PolicyHints(ps ...*policy.Policy) Hints { return policyHints{ps: ps} }

type policyHints struct{ ps []*policy.Policy }

func (policyHints) Entity(string, string) string { return "" }

func (h policyHints) Domain(l Location) string {
	if a, ok := h.action(l); ok && a.Kind == policy.ActHMAC {
		return a.Domain
	}
	return ""
}

func (h policyHints) Bounds(l Location) []string {
	a, ok := h.action(l)
	if !ok || a.Kind != policy.ActBucketNum {
		return nil
	}
	out := make([]string, len(a.Bounds))
	for i, b := range a.Bounds {
		out[i] = b.Lexeme
	}
	return out
}

func (h policyHints) action(l Location) (policy.Action, bool) {
	for _, p := range h.ps {
		for i := range p.Services {
			if p.Services[i].Name != l.Service {
				continue
			}
			return lookupInService(&p.Services[i], p, l)
		}
	}
	for _, p := range h.ps {
		if a, ok := lookupInScope(&p.Global, l); ok {
			return a, true
		}
	}
	return policy.Action{}, false
}

func lookupInService(s *policy.Service, p *policy.Policy, l Location) (policy.Action, bool) {
	for i := range s.Ops {
		if s.Ops[i].Op != l.Op {
			continue
		}
		part := &s.Ops[i].Request
		if l.Side == "resp" {
			part = &s.Ops[i].Response
		}
		if a, ok := lookupInPart(part, l, true); ok {
			return a, true
		}
		break
	}
	if a, ok := lookupInScope(&s.Scope, l); ok {
		return a, true
	}
	return lookupInScope(&p.Global, l)
}

func lookupInScope(sc *policy.Scope, l Location) (policy.Action, bool) {
	parts := []*policy.Part{&sc.Request}
	if l.Side == "resp" {
		// Errors rules refine the response rules for status >= 400; the
		// model does not know the status here, so both are consulted.
		parts = []*policy.Part{&sc.Response, &sc.Errors}
	}
	for _, p := range parts {
		if a, ok := lookupInPart(p, l, false); ok {
			return a, true
		}
	}
	return policy.Action{}, false
}

func lookupInPart(p *policy.Part, l Location, isOp bool) (policy.Action, bool) {
	switch l.Part {
	case "path":
		if isOp {
			a, ok := p.Path[l.Name]
			return a, ok
		}
	case "query":
		a, ok := p.Query[l.Name]
		return a, ok
	case "headers":
		a, ok := p.Headers[strings.ToLower(l.Name)]
		return a, ok
	case "cookies":
		a, ok := p.Cookies[l.Name]
		return a, ok
	case "body":
		return bestBodyRule(p.Body, l.Name)
	}
	return policy.Action{}, false
}

// bestBodyRule returns the rule whose tt-path matches the concrete path with
// the most literal steps.
func bestBodyRule(rules []policy.BodyRule, path string) (policy.Action, bool) {
	cs, ok := policy.ParseTTPath(path)
	if !ok {
		return policy.Action{}, false
	}
	best, bestScore := -1, -1
	for i := range rules {
		rs, ok := policy.ParseTTPath(rules[i].Path)
		if !ok || len(rs) != len(cs) {
			continue
		}
		score, match := 0, true
		for k := range rs {
			switch {
			case rs[k].Kind == cs[k].Kind && rs[k].Name == cs[k].Name:
				score += 2
			case rs[k].Kind == policy.StepAnyMember && (cs[k].Kind == policy.StepName || cs[k].Kind == policy.StepAnyMember):
				score++
			default:
				match = false
			}
			if !match {
				break
			}
		}
		if match && score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return policy.Action{}, false
	}
	return rules[best].Action, true
}
