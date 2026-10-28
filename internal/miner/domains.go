package miner

import (
	"strconv"
	"strings"
	"sync"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// DomainResolver tells the HMAC domain of the field where a token was seen.
// Tokens do not carry their domain: the compiled policy that produced the
// event does (docs/spec/sanitizer.md 5.4). Field uses the form of
// event.HMACToken.Where ("resp.body$.id", "req.path[1]", "req.query.orderId").
type DomainResolver interface {
	Domain(policyHash, service, op string, status int, field string) (string, bool)
}

// PolicyDomains resolves domains from compiled policies, by policy hash.
// It is safe for concurrent use.
type PolicyDomains struct {
	mu     sync.RWMutex
	byHash map[string]*policy.Policy
}

// NewPolicyDomains returns an empty resolver.
func NewPolicyDomains() *PolicyDomains { return &PolicyDomains{byHash: map[string]*policy.Policy{}} }

// Add registers a compiled policy under its body hash ("sha256:<hex>").
func (d *PolicyDomains) Add(hash string, p *policy.Policy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.byHash[hash] = p
}

// AddBody decodes a compiled policy body and registers it under its hash.
func (d *PolicyDomains) AddBody(body []byte) error {
	p, err := policy.DecodeBody(body)
	if err != nil {
		return err
	}
	d.Add(policy.Hash(body), p)
	return nil
}

// Domain implements DomainResolver.
func (d *PolicyDomains) Domain(policyHash, service, op string, status int, field string) (string, bool) {
	if field == "subject" {
		return "subject", true
	}
	d.mu.RLock()
	p := d.byHash[policyHash]
	d.mu.RUnlock()
	if p == nil {
		return "", false
	}
	var svc *policy.Service
	for i := range p.Services {
		if p.Services[i].Name == service {
			svc = &p.Services[i]
			break
		}
	}
	var parts []*policy.Part
	resp := strings.HasPrefix(field, "resp.")
	if svc != nil {
		for i := range svc.Ops {
			if svc.Ops[i].Op == op {
				if resp {
					parts = append(parts, &svc.Ops[i].Response)
				} else {
					parts = append(parts, &svc.Ops[i].Request)
				}
			}
		}
		if resp {
			if status >= 400 {
				parts = append(parts, &svc.Errors)
			}
			parts = append(parts, &svc.Response)
		} else {
			parts = append(parts, &svc.Request)
		}
	}
	if resp {
		if status >= 400 {
			parts = append(parts, &p.Global.Errors)
		}
		parts = append(parts, &p.Global.Response)
	} else {
		parts = append(parts, &p.Global.Request)
	}
	for _, part := range parts {
		if dom, ok := partDomain(part, op, field); ok {
			return dom, true
		}
	}
	return "", false
}

func hmacDomain(a policy.Action, ok bool) (string, bool) {
	if !ok || a.Kind != policy.ActHMAC {
		return "", false
	}
	if a.Domain == "" {
		return "id", true
	}
	return a.Domain, true
}

func partDomain(p *policy.Part, op, field string) (string, bool) {
	_, rest, _ := strings.Cut(field, ".") // drop req./resp.
	switch {
	case strings.HasPrefix(rest, "path["):
		name, ok := pathParamName(op, rest)
		if !ok {
			return "", false
		}
		a, ok := p.Path[name]
		return hmacDomain(a, ok)
	case strings.HasPrefix(rest, "query."):
		a, ok := p.Query[rest[len("query."):]]
		return hmacDomain(a, ok)
	case strings.HasPrefix(rest, "headers."):
		a, ok := p.Headers[rest[len("headers."):]]
		return hmacDomain(a, ok)
	case strings.HasPrefix(rest, "cookies."):
		a, ok := p.Cookies[rest[len("cookies."):]]
		return hmacDomain(a, ok)
	case strings.HasPrefix(rest, "body$"):
		path := rest[len("body"):]
		best, bestScore := policy.Action{}, -1
		for _, r := range p.Body {
			if s, ok := matchTTPath(r.Path, path); ok && s > bestScore {
				best, bestScore = r.Action, s
			}
		}
		return hmacDomain(best, bestScore >= 0)
	}
	return "", false
}

// pathParamName maps "path[<i>]" to the name of the i-th template segment of
// op ("GET /orders/{id}" → index 1 → "id").
func pathParamName(op, rest string) (string, bool) {
	i, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rest, "path["), "]"))
	if err != nil {
		return "", false
	}
	_, path, ok := strings.Cut(op, " ")
	if !ok {
		return "", false
	}
	segs, ok := event.OpSegments(path)
	if !ok || i < 0 || i >= len(segs) || segs[i].Literal {
		return "", false
	}
	return segs[i].Inner, true
}

// splitTTPath splits "$.a[*].b" into ["a", "[*]", "b"].
func splitTTPath(p string) []string {
	p = strings.TrimPrefix(p, "$")
	var out []string
	for len(p) > 0 {
		switch {
		case strings.HasPrefix(p, "[*]"):
			out = append(out, "[*]")
			p = p[3:]
		case p[0] == '.':
			p = p[1:]
			j := strings.IndexAny(p, ".[")
			if j < 0 {
				j = len(p)
			}
			out = append(out, p[:j])
			p = p[j:]
		default:
			return append(out, p)
		}
	}
	return out
}

// matchTTPath matches a policy rule path against an event leaf path; ".*"
// in the rule matches any member. The score prefers literal steps.
func matchTTPath(rule, path string) (int, bool) {
	rs, ps := splitTTPath(rule), splitTTPath(path)
	if len(rs) != len(ps) {
		return 0, false
	}
	score := 0
	for i := range rs {
		switch {
		case rs[i] == ps[i]:
			score++
		case rs[i] == "*" && ps[i] != "[*]":
		default:
			return 0, false
		}
	}
	return score, true
}
