package keyguard

import (
	"slices"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Classification of a policy change (policy.md 5).
const (
	ClassClosing = "closing"
	ClassOpening = "opening"
)

// classify compares a new body with an old one and reports whether the
// change is only closing (policy.md 5). Anything not in the closed list of
// closing operations opens; in doubt, the change opens. reason is a short
// machine code naming the first opening change found (never a value).
// version, issued_seq, created_at and not_after are metadata and ignored.
// withTargets includes targets.groups in the comparison (a group added
// opens); it is false when comparing with the current policy of a group,
// where only what the sources of that group receive matters.
func classify(old, cur *policy.Policy, withTargets bool) (closing bool, reason string) {
	c := &classifier{}
	if withTargets {
		c.list("targets.groups", old.Groups, cur.Groups)
	}
	// hmac
	if old.HMAC.Kid != cur.HMAC.Kid {
		c.open("hmac.kid")
	}
	if old.HMAC.Epoch != cur.HMAC.Epoch {
		c.open("hmac.epoch")
	}
	c.list("hmac.accept_kids", old.HMAC.AcceptKids, cur.HMAC.AcceptKids)
	// identity
	if !sameSubject(old.Subject, cur.Subject) {
		c.open("identity")
	}
	// sampling
	if cur.Sampling.RateBP > old.Sampling.RateBP {
		c.open("sampling.rate")
	}
	if cur.Sampling.TrustBaggage && !old.Sampling.TrustBaggage {
		c.open("sampling.trust_baggage")
	}
	c.list("sampling.propagate_to", old.Sampling.PropagateTo, cur.Sampling.PropagateTo)
	// segments
	switch {
	case cur.Segments.AutoWords && !old.Segments.AutoWords:
		c.open("segments.auto_words")
	case cur.Segments.AutoWords && cur.Segments.AutoWordsExpiresAt.After(old.Segments.AutoWordsExpiresAt):
		c.open("segments.auto_words_expires_at")
	}
	c.list("segments.allow", old.Segments.Allow, cur.Segments.Allow)
	c.list("segments.hosts_allow", old.Segments.HostsAllow, cur.Segments.HostsAllow)
	// hosts.discovery (spec v1.5): off -> auto lets host patterns leave.
	if cur.Hosts.Auto() && !old.Hosts.Auto() {
		c.open("hosts.discovery")
	}
	// discovery
	oldDisc, curDisc := old.Discovery != nil && old.Discovery.Enabled, cur.Discovery != nil && cur.Discovery.Enabled
	switch {
	case curDisc && !oldDisc:
		c.open("discovery.enabled")
	case curDisc && cur.Discovery.ExpiresAt.After(old.Discovery.ExpiresAt):
		c.open("discovery.expires_at")
	}
	// limits
	ol, nl := old.Limits, cur.Limits
	if nl.MaxBodyBytes > ol.MaxBodyBytes || nl.MaxDepth > ol.MaxDepth || nl.MaxArray > ol.MaxArray ||
		nl.MaxKeys > ol.MaxKeys || nl.KeepMaxBytes > ol.KeepMaxBytes {
		c.open("limits")
	}
	// services: added, removed or re-matched services open.
	oldSvc := map[string]*policy.Service{}
	for i := range old.Services {
		oldSvc[old.Services[i].Name] = &old.Services[i]
	}
	curSvc := map[string]bool{}
	for i := range cur.Services {
		s := &cur.Services[i]
		curSvc[s.Name] = true
		o, ok := oldSvc[s.Name]
		switch {
		case !ok:
			c.open("service.added")
		case o.Match != s.Match:
			c.open("service.match")
		}
		if ok {
			oldOps := map[string]bool{}
			for _, op := range o.Ops {
				oldOps[op.Op] = true
			}
			curOps := map[string]bool{}
			for _, op := range s.Ops {
				curOps[op.Op] = true
				if !oldOps[op.Op] {
					c.open("op.added")
				}
			}
			for op := range oldOps {
				if !curOps[op] {
					c.open("op.removed")
				}
			}
		}
	}
	for name := range oldSvc {
		if !curSvc[name] {
			c.open("service.removed")
		}
	}
	// rules
	or, nr := flattenRules(old), flattenRules(cur)
	for k, na := range nr {
		oa, ok := or[k]
		if !ok {
			c.open("rule.added")
			continue
		}
		if !closingAction(oa, na) {
			c.open("rule.changed")
		}
	}
	for k, oa := range or {
		if _, ok := nr[k]; !ok && oa.Kind != policy.ActKeep {
			// Removing a keep rule closes; removing any other rule may let a
			// broader rule apply.
			c.open("rule.removed")
		}
	}
	return c.reason == "", c.reason
}

type classifier struct{ reason string }

func (c *classifier) open(code string) {
	if c.reason == "" {
		c.reason = code
	}
}

// list: removing entries closes, adding entries opens.
func (c *classifier) list(code string, old, cur []string) {
	for _, v := range cur {
		if !slices.Contains(old, v) {
			c.open(code)
			return
		}
	}
}

func sameSubject(a, b *policy.Subject) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// closingAction reports whether replacing old by cur on the same rule is
// neutral or closing (policy.md 5).
func closingAction(old, cur policy.Action) bool {
	if sameAction(old, cur) || cur.Kind == policy.ActDrop {
		return true
	}
	switch {
	case old.Kind == policy.ActKeep && (cur.Kind == policy.ActHMAC || cur.Kind == policy.ActBucketNum || cur.Kind == policy.ActBucketTime || cur.Kind == policy.ActCode):
		return true
	case old.Kind == policy.ActCode && cur.Kind == policy.ActHMAC:
		// code lets out code-shaped strings; hmac only tokens.
		return true
	case old.Kind == policy.ActBucketNum && cur.Kind == policy.ActBucketNum:
		// Removing bounds only: the new bounds are a subset of the old ones.
		for _, b := range cur.Bounds {
			if !slices.ContainsFunc(old.Bounds, func(o policy.Bound) bool { return o.Lexeme == b.Lexeme }) {
				return false
			}
		}
		return true
	case old.Kind == policy.ActBucketTime && cur.Kind == policy.ActBucketTime:
		return timeUnitRank(cur.Unit) > timeUnitRank(old.Unit) && timeUnitRank(old.Unit) > 0
	}
	return false
}

func timeUnitRank(u string) int {
	switch u {
	case "hour":
		return 1
	case "day":
		return 2
	case "month":
		return 3
	case "year":
		return 4
	}
	return 0
}

func sameAction(a, b policy.Action) bool {
	if a.Kind != b.Kind || a.Domain != b.Domain || a.Unit != b.Unit || len(a.Bounds) != len(b.Bounds) {
		return false
	}
	for i := range a.Bounds {
		if a.Bounds[i].Lexeme != b.Bounds[i].Lexeme {
			return false
		}
	}
	return true
}

// flattenRules maps every rule of a policy to its action. Keys identify the
// scope (global, service, operation), the part, the kind and the name or
// tt-path; they use NUL separators so no name can forge another key.
func flattenRules(p *policy.Policy) map[string]policy.Action {
	out := map[string]policy.Action{}
	addPart := func(prefix string, part *policy.Part) {
		for kind, m := range map[string]map[string]policy.Action{"path": part.Path, "query": part.Query, "headers": part.Headers, "cookies": part.Cookies} {
			for name, a := range m {
				out[prefix+"\x00"+kind+"\x00"+name] = a
			}
		}
		for _, r := range part.Body {
			out[prefix+"\x00body\x00"+r.Path] = r.Action
		}
	}
	addScope := func(prefix string, s *policy.Scope) {
		addPart(prefix+"\x00request", &s.Request)
		addPart(prefix+"\x00response", &s.Response)
		addPart(prefix+"\x00errors", &s.Errors)
	}
	addScope("global", &p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		addScope("service\x00"+s.Name, &s.Scope)
		for j := range s.Ops {
			op := &s.Ops[j]
			prefix := "op\x00" + s.Name + "\x00" + op.Op
			addPart(prefix+"\x00request", &op.Request)
			addPart(prefix+"\x00response", &op.Response)
		}
	}
	return out
}

// hmacDomains returns every HMAC domain used by a rule of p, plus the
// subject domain (keyguard.md 3.1).
func hmacDomains(p *policy.Policy) []string {
	set := map[string]bool{"subject": true}
	for _, a := range flattenRules(p) {
		if a.Kind == policy.ActHMAC {
			set[a.Domain] = true
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}
