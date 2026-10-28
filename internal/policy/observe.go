package policy

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Observe-safe classification (policy.md 7, spec v1.6).
//
// A policy change is observe-safe when, compared with the previous signed
// body, it does not let any value leave the sources in clear beyond what the
// previous body already let out: only shapes (drop), HMAC tokens, the
// subject read from any request header that is not a credential
// (IdentityObserveSafe: it leaves only as a token) and the timed discovery/auto_words windows
// (at most 7 days, policy.md 1.4). Such a change applies without human
// approval. Every other change "opens values" and follows the approval flow
// of policy.md 5. In doubt, the change opens values.
//
// tt-core uses ClassifyValues to decide whether a draft applies at once;
// keyguard recomputes it on its own, from the bodies it signed, before it
// accepts to sign a body without approvals.

// Value reason codes: why a change opens values. They are machine codes the
// UI translates; Where names a location of the policy, never a value.
const (
	ReasonKeep             = "keep"              // a rule now keeps a value in clear
	ReasonBucket           = "bucket"            // a rule now buckets a value (or finer bounds/unit)
	ReasonCredentialHeader = "credential_header" // hmac on a credential header (refused by validation anyway)
	ReasonIdentity         = "identity"          // identity.subject from a cookie or a credential (IdentityObserveSafe)
	ReasonLiterals         = "literals"          // new segments.allow / segments.hosts_allow entries (literals in clear)
	ReasonHostsDiscovery   = "hosts_discovery"   // hosts.discovery off -> auto
	ReasonPropagate        = "propagate_to"      // new sampling.propagate_to hosts (changes the application's traffic)
	ReasonVolume           = "volume_with_values"
	ReasonRuleRemoved      = "rule_removed_with_values"
	ReasonMatchChanged     = "match_with_values"
	ReasonGroupAdded       = "group_with_values"
	// ReasonServiceChanged: a service declared or removed while the policy
	// keeps values: the services decide which rules apply to an exchange
	// (sanitizer.md 3.1), so traffic can move onto keep/bucket rules
	// already approved (red team round 4, RT4-OBS-1).
	ReasonServiceChanged = "service_with_values"
	// ReasonOperationChanged: an operation declared or removed while the
	// policy keeps values (the template decides the operation rules,
	// sanitizer.md 3.3; RT4-OBS-1).
	ReasonOperationChanged = "operation_with_values"
	// ReasonContainer: a change that can lift a container drop
	// (sanitizer.md 5.0) above a keep/bucket rule reaching one of its
	// descendants (red team round 4, RT4-OBS-2).
	ReasonContainer = "container_with_values"
	// ReasonCodeField: a code rule on a field whose name is not a status
	// or a code (policy.md 1.5; refused by validation anyway, spec v1.11).
	ReasonCodeField = "code_field"
)

// ValueReason is one reason why a change opens values beyond observe-safe.
type ValueReason struct {
	Code  string `json:"code"`
	Where string `json:"where"`
}

// ValueClass is the result of ClassifyValues.
type ValueClass struct {
	// OpensValues: the change needs approvals (policy.md 5).
	OpensValues bool
	// Reasons lists every opening change, sorted by location then code.
	Reasons []ValueReason
}

// ObserveSafe reports whether p, as a first policy, lets out only structure,
// HMAC tokens and the timed discovery windows (ClassifyValues against
// nothing).
func ObserveSafe(p *Policy) bool { return !ClassifyValues(nil, p).OpensValues }

// HasValues reports whether p has a rule that lets a value out in clear or
// as a band (keep, bucket).
func HasValues(p *Policy) bool {
	if p == nil {
		return false
	}
	for _, a := range RuleLocations(p) {
		if a.Kind == ActKeep || a.Kind == ActBucketNum || a.Kind == ActBucketTime {
			return true
		}
	}
	return false
}

// ClassifyValues compares next with prev (nil: nothing was captured, every
// field dropped) and lists what opens values (see the package comment).
// version, issued_seq, created_at, not_after, the HMAC key and epoch and
// the discovery and auto_words windows never open values; services and
// operations without rules open values only when next keeps values (they
// route traffic onto the rules). Targets count: a group added to a policy
// that keeps values opens them for that group.
func ClassifyValues(prev, next *Policy) ValueClass {
	if prev == nil {
		prev = &Policy{Limits: DefaultLimits(), Sampling: Sampling{}}
	}
	var out []ValueReason
	add := func(code, where string) { out = append(out, ValueReason{Code: code, Where: where}) }
	values := HasValues(next)

	// Rules.
	or, nr := RuleLocations(prev), RuleLocations(next)
	refusedCode := codeRefused(next)
	for k, na := range nr {
		oa, had := or[k]
		if !had {
			oa = Action{Kind: ActDrop}
		}
		switch na.Kind {
		case ActKeep:
			if oa.Kind != ActKeep {
				add(ReasonKeep, k)
			}
		case ActBucketNum:
			if !bucketNumNotFiner(oa, na) {
				add(ReasonBucket, k)
			}
		case ActBucketTime:
			if !bucketTimeNotFiner(oa, na) {
				add(ReasonBucket, k)
			}
		case ActHMAC:
			if credentialHeaderRule(k) {
				add(ReasonCredentialHeader, k)
			}
		case ActCode:
			// A code rule lets out only code-shaped strings (sanitizer.md
			// 5.6): observe-safe on a status or code field (policy.md 1.5).
			if credentialHeaderRule(k) {
				add(ReasonCredentialHeader, k)
			} else if refusedCode[k] {
				add(ReasonCodeField, k)
			}
		}
	}
	for k, oa := range or {
		if _, ok := nr[k]; ok {
			continue
		}
		// Removing a keep or bucket rule closes. Removing drop, hmac or code
		// may let a broader rule apply: it opens only if next keeps values.
		if (oa.Kind == ActDrop || oa.Kind == ActHMAC || oa.Kind == ActCode || oa.Kind == ActGraphQL) && values {
			add(ReasonRuleRemoved, k)
		}
	}

	// Identity: the subject leaves only as a token; any header that is not
	// a credential is observe-safe (IdentityObserveSafe, policy.md 7.1).
	if next.Subject != nil && !sameSubjectValue(prev.Subject, next.Subject) && !IdentityObserveSafe(next.Subject) {
		add(ReasonIdentity, "identity.subject")
	}

	// Volume: more of what is let out. Without values it is only more
	// shapes and tokens.
	if values {
		if next.Sampling.RateBP > prev.Sampling.RateBP {
			add(ReasonVolume, "sampling.rate")
		}
		if next.Sampling.TrustBaggage && !prev.Sampling.TrustBaggage {
			add(ReasonVolume, "sampling.trust_baggage")
		}
		ol, nl := prev.Limits, next.Limits
		for _, l := range []struct {
			where    string
			old, new int64
		}{
			{"limits.max_body_bytes", ol.MaxBodyBytes, nl.MaxBodyBytes},
			{"limits.max_depth", int64(ol.MaxDepth), int64(nl.MaxDepth)},
			{"limits.max_array", int64(ol.MaxArray), int64(nl.MaxArray)},
			{"limits.max_keys", int64(ol.MaxKeys), int64(nl.MaxKeys)},
			{"limits.keep_max_bytes", int64(ol.KeepMaxBytes), int64(nl.KeepMaxBytes)},
		} {
			if l.new > l.old {
				add(ReasonVolume, l.where)
			}
		}
		for _, g := range next.Groups {
			if len(prev.Groups) > 0 && !slices.Contains(prev.Groups, g) {
				add(ReasonGroupAdded, "targets.groups["+g+"]")
			}
		}
	}
	for _, h := range next.Sampling.PropagateTo {
		if !slices.Contains(prev.Sampling.PropagateTo, h) {
			add(ReasonPropagate, "sampling.propagate_to["+h+"]")
		}
	}
	for _, s := range next.Segments.Allow {
		if !slices.Contains(prev.Segments.Allow, s) {
			add(ReasonLiterals, "segments.allow["+s+"]")
		}
	}
	for _, h := range next.Segments.HostsAllow {
		if !slices.Contains(prev.Segments.HostsAllow, h) {
			add(ReasonLiterals, "segments.hosts_allow["+h+"]")
		}
	}
	// hosts.discovery: a person chose the strict mode; leaving it needs
	// approval. The first policy may use auto (the default).
	if next.Hosts.Auto() && !prev.Hosts.Auto() {
		add(ReasonHostsDiscovery, "hosts.discovery")
	}

	// Routing with values (RT4-OBS-1): which rules apply to an exchange
	// depends on the declared services (bases) and operation templates,
	// not only on the rules. When next keeps values, a service declared or
	// removed next to another service that can take the same traffic (same
	// origin, one base path a prefix of the other), any re-matched service,
	// and an operation declared or removed next to another operation of
	// the service with the same method and number of segments can move
	// traffic onto keep/bucket rules already approved (or away from
	// drop/hmac rules that overrode them). A service or an operation that
	// takes traffic from nothing only adds rules, which the checks above
	// and containerReasons judge. In doubt, it opens.
	if values {
		oldSvc, newSvc := map[string]*Service{}, map[string]*Service{}
		for i := range prev.Services {
			oldSvc[prev.Services[i].Name] = &prev.Services[i]
		}
		for i := range next.Services {
			newSvc[next.Services[i].Name] = &next.Services[i]
		}
		competitor := func(s *Service) bool {
			for _, list := range [][]Service{prev.Services, next.Services} {
				for i := range list {
					if list[i].Name != s.Name && servicesCompete(s, &list[i]) {
						return true
					}
				}
			}
			return false
		}
		for i := range next.Services {
			s := &next.Services[i]
			o, ok := oldSvc[s.Name]
			switch {
			case !ok:
				if competitor(s) {
					add(ReasonServiceChanged, "services."+s.Name)
				}
				continue
			case o.Match != s.Match:
				add(ReasonMatchChanged, "services."+s.Name+".match")
			}
			opReasons(o, s, add)
		}
		for i := range prev.Services {
			if r := &prev.Services[i]; newSvc[r.Name] == nil && competitor(r) {
				add(ReasonServiceChanged, "services."+r.Name)
			}
		}
		containerReasons(prev, next, add)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Where != out[j].Where {
			return out[i].Where < out[j].Where
		}
		return out[i].Code < out[j].Code
	})
	return ValueClass{OpensValues: len(out) > 0, Reasons: out}
}

func sameSubjectValue(a, b *Subject) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.From == b.From && strings.EqualFold(a.Name, b.Name) && a.JWTClaim == b.JWTClaim && a.JSONPath == b.JSONPath
}

// codeRefused lists the RuleLocations keys of p whose code rule stands on
// a name that does not allow it (CodeRuleSafe, policy.md 1.5).
func codeRefused(p *Policy) map[string]bool {
	out := map[string]bool{}
	if p == nil {
		return out
	}
	addPart := func(prefix string, part *Part) {
		for kind, m := range map[string]map[string]Action{CodePartPath: part.Path, CodePartQuery: part.Query, CodePartHeaders: part.Headers, CodePartCookies: part.Cookies} {
			for name, a := range m {
				if a.Kind == ActCode && !CodeRuleSafe(kind, name) {
					out[prefix+"."+kind+"."+name] = true
				}
			}
		}
		for _, r := range part.Body {
			if r.Action.Kind == ActCode && !CodeRuleSafe(CodePartBody, r.Path) {
				out[prefix+".body."+r.Path] = true
			}
		}
	}
	addScope := func(prefix string, s *Scope) {
		addPart(prefix+".request", &s.Request)
		addPart(prefix+".response", &s.Response)
		addPart(prefix+".errors", &s.Errors)
	}
	addScope("global", &p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		addScope("services."+s.Name, &s.Scope)
		for j := range s.Ops {
			op := &s.Ops[j]
			prefix := "services." + s.Name + ".ops." + op.Op
			addPart(prefix+".request", &op.Request)
			addPart(prefix+".response", &op.Response)
		}
	}
	return out
}

func credentialHeaderRule(where string) bool {
	i := strings.LastIndex(where, ".headers.")
	return i >= 0 && CredentialHeaders[where[i+len(".headers."):]]
}

// bucketNumNotFiner: cur is a numeric bucket that lets out no more than old
// (old keep, or old bucket with a superset of the bounds).
func bucketNumNotFiner(old, cur Action) bool {
	switch old.Kind {
	case ActKeep:
		return true
	case ActBucketNum:
		for _, b := range cur.Bounds {
			if !slices.ContainsFunc(old.Bounds, func(o Bound) bool { return o.Lexeme == b.Lexeme }) {
				return false
			}
		}
		return true
	}
	return false
}

var timeRank = map[string]int{"hour": 1, "day": 2, "month": 3, "year": 4}

// bucketTimeNotFiner: cur is a time bucket not finer than old (or old keep).
func bucketTimeNotFiner(old, cur Action) bool {
	switch old.Kind {
	case ActKeep:
		return true
	case ActBucketTime:
		return timeRank[cur.Unit] >= timeRank[old.Unit] && timeRank[old.Unit] > 0
	}
	return false
}

// servicesCompete reports whether two services can match the same
// outbound exchange (sanitizer.md 3.1): both have a base with the same
// origin and the path of one is a prefix of the other's (equal included).
// Inbound services are chosen by name, so they never compete. A base that
// does not parse competes (in doubt).
func servicesCompete(a, b *Service) bool {
	if a.Match.Base == "" || b.Match.Base == "" {
		return false
	}
	ba, ok1 := ParseBase(a.Match.Base)
	bb, ok2 := ParseBase(b.Match.Base)
	if !ok1 || !ok2 {
		return true
	}
	if ba.Origin() != bb.Origin() {
		return false
	}
	short, long := ba.Path, bb.Path
	if len(short) > len(long) {
		short, long = long, short
	}
	return slices.Equal(short, long[:len(short)])
}

// opReasons: an operation declared or removed in a service that has
// another operation with the same method and number of segments (the two
// templates may match the same request, sanitizer.md 3.3) moves requests
// between their rules.
func opReasons(prev, next *Service, add func(code, where string)) {
	shape := func(op string) string {
		method, tmpl, _ := strings.Cut(op, " ")
		return method + " " + strconv.Itoa(strings.Count(strings.Trim(tmpl, "/"), "/")+1)
	}
	shapes := map[string]int{}
	all := map[string]bool{}
	for _, list := range [][]Op{prev.Ops, next.Ops} {
		for _, op := range list {
			if !all[op.Op] {
				all[op.Op] = true
				shapes[shape(op.Op)]++
			}
		}
	}
	has := func(list []Op, name string) bool {
		return slices.ContainsFunc(list, func(o Op) bool { return o.Op == name })
	}
	for name := range all {
		if has(prev.Ops, name) != has(next.Ops, name) && shapes[shape(name)] > 1 {
			add(ReasonOperationChanged, "services."+next.Name+".ops."+name)
		}
	}
}

// containerReasons (RT4-OBS-2): an explicit drop on a container collapses
// it only while no rule of the same or a stronger group can reach one of
// its descendants (sanitizer.md 5.0); keep, hmac and bucket on a container
// are ignored. So, when next keeps values, two changes can expose a leaf
// to a keep/bucket rule of a weaker group that the collapse hid:
//   - a body rule that was drop becomes hmac (or anything but drop), and a
//     keep/bucket body rule of next may reach a descendant of a container
//     it matches;
//   - a body rule is added that may reach a descendant of a container
//     matched by a drop rule of next, and a keep/bucket rule of next may
//     reach a descendant of that container too.
//
// The check is static and ignores groups, parts and scopes: in doubt, it
// opens.
func containerReasons(prev, next *Policy, add func(code, where string)) {
	oldBody, newBody := bodyRuleLocations(prev), bodyRuleLocations(next)
	var values, drops []bodyLoc
	for _, r := range newBody {
		switch r.action.Kind {
		case ActKeep, ActBucketNum, ActBucketTime:
			values = append(values, r)
		case ActDrop:
			drops = append(drops, r)
		}
	}
	if len(values) == 0 {
		return
	}
	reachedByValue := func(container []string) bool {
		for _, v := range values {
			if reachesDescendant(v.steps, container) {
				return true
			}
		}
		return false
	}
	for loc, r := range newBody {
		o, had := oldBody[loc]
		switch {
		case had && o.action.Kind == ActDrop && r.action.Kind != ActDrop:
			if reachedByValue(r.steps) {
				add(ReasonContainer, loc)
			}
		case !had:
			for _, d := range drops {
				if d.loc != loc && reachesDescendant(r.steps, d.steps) && reachedByValue(d.steps) {
					add(ReasonContainer, loc)
					break
				}
			}
		}
	}
}

type bodyLoc struct {
	loc    string
	steps  []string
	action Action
}

// bodyRuleLocations maps the location (as RuleLocations) of every body
// rule of p to its tt-path steps and action.
func bodyRuleLocations(p *Policy) map[string]bodyLoc {
	out := map[string]bodyLoc{}
	if p == nil {
		return out
	}
	addPart := func(prefix string, part *Part) {
		for _, r := range part.Body {
			loc := prefix + ".body." + r.Path
			out[loc] = bodyLoc{loc: loc, steps: ttPathSteps(r.Path), action: r.Action}
		}
	}
	addScope := func(prefix string, s *Scope) {
		addPart(prefix+".request", &s.Request)
		addPart(prefix+".response", &s.Response)
		addPart(prefix+".errors", &s.Errors)
	}
	addScope("global", &p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		addScope("services."+s.Name, &s.Scope)
		for j := range s.Ops {
			op := &s.Ops[j]
			prefix := "services." + s.Name + ".ops." + op.Op
			addPart(prefix+".request", &op.Request)
			addPart(prefix+".response", &op.Response)
		}
	}
	return out
}

// ttPathSteps splits a tt-path ("$.items[*].sku") into its steps
// (".items", "[*]", ".sku"). The grammar (sanitizer.md 5.0) has no quoted
// names, so '.' and '[' always start a step.
func ttPathSteps(path string) []string {
	path = strings.TrimPrefix(path, "$")
	var out []string
	for path != "" {
		i := strings.IndexAny(path[1:], ".[")
		if i < 0 {
			out = append(out, path)
			break
		}
		out = append(out, path[:i+1])
		path = path[i+1:]
	}
	return out
}

// reachesDescendant reports whether a tt-path with steps p may reach a
// descendant of a container matched by the tt-path with steps c: p is
// longer and every step of c is compatible with the step of p in the same
// position (".name" equal names, ".*" any member, "[*]" any element).
func reachesDescendant(p, c []string) bool {
	if len(p) <= len(c) {
		return false
	}
	for i, cs := range c {
		ps := p[i]
		switch {
		case cs == "[*]" || ps == "[*]":
			if cs != ps {
				return false
			}
		case cs == ".*" || ps == ".*":
		case cs != ps:
			return false
		}
	}
	return true
}

// RuleLocations maps every rule of p to its action, keyed by a readable
// location: "global.request.headers.content-type",
// "services.shop-api.response.body.$.id",
// "services.shop-api.ops.GET /orders/{id}.request.path.id". Names follow the
// grammar of policy.md 1.2, so no name can forge another location.
func RuleLocations(p *Policy) map[string]Action {
	out := map[string]Action{}
	if p == nil {
		return out
	}
	addPart := func(prefix string, part *Part) {
		for kind, m := range map[string]map[string]Action{"path": part.Path, "query": part.Query, "headers": part.Headers, "cookies": part.Cookies} {
			for name, a := range m {
				out[prefix+"."+kind+"."+name] = a
			}
		}
		for _, r := range part.Body {
			out[prefix+".body."+r.Path] = r.Action
		}
	}
	addScope := func(prefix string, s *Scope) {
		addPart(prefix+".request", &s.Request)
		addPart(prefix+".response", &s.Response)
		addPart(prefix+".errors", &s.Errors)
	}
	addScope("global", &p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		addScope("services."+s.Name, &s.Scope)
		for j := range s.Ops {
			op := &s.Ops[j]
			prefix := "services." + s.Name + ".ops." + op.Op
			addPart(prefix+".request", &op.Request)
			addPart(prefix+".response", &op.Response)
		}
	}
	return out
}
