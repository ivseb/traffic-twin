package policy

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// Character-class helpers (ASCII only, no regexp needed).

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return isLower(c) || isUpper(c) }

// IsTokenChar reports whether c is an RFC 9110 tchar
// ([A-Za-z0-9!#$%&'*+.^_`|~-]).
func IsTokenChar(c byte) bool {
	if isAlpha(c) || isDigit(c) {
		return true
	}
	return strings.IndexByte("!#$%&'*+.^_`|~-", c) >= 0
}

func matchAll(s string, minLen, maxLen int, ok func(i int, c byte) bool) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ok(i, s[i]) {
			return false
		}
	}
	return true
}

// ValidPolicyID matches ^[a-z0-9][a-z0-9-]{0,62}$.
func ValidPolicyID(s string) bool {
	return matchAll(s, 1, 63, func(i int, c byte) bool {
		return isLower(c) || isDigit(c) || (i > 0 && c == '-')
	})
}

// ValidServiceName matches ^[a-z0-9][a-z0-9._-]{0,62}$.
func ValidServiceName(s string) bool {
	return matchAll(s, 1, 63, func(i int, c byte) bool {
		return isLower(c) || isDigit(c) || (i > 0 && (c == '.' || c == '_' || c == '-'))
	})
}

// ValidKid matches ^[a-z0-9]{1,8}$.
func ValidKid(s string) bool {
	return matchAll(s, 1, 8, func(_ int, c byte) bool { return isLower(c) || isDigit(c) })
}

// ValidEpoch matches ^[A-Za-z0-9._-]{1,32}$.
func ValidEpoch(s string) bool {
	return matchAll(s, 1, 32, func(_ int, c byte) bool {
		return isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '-'
	})
}

// ValidDomain matches ^[a-z][a-z0-9_-]{0,31}$ (reservation is checked apart).
func ValidDomain(s string) bool {
	return matchAll(s, 1, 32, func(i int, c byte) bool {
		return isLower(c) || (i > 0 && (isDigit(c) || c == '_' || c == '-'))
	})
}

// ValidSigningKid matches ^[A-Za-z0-9._-]{1,64}$.
func ValidSigningKid(s string) bool {
	return matchAll(s, 1, 64, func(_ int, c byte) bool {
		return isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '-'
	})
}

// ValidRuleName matches ^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$.
func ValidRuleName(s string) bool {
	return matchAll(s, 1, 64, func(_ int, c byte) bool { return IsTokenChar(c) })
}

// ValidParamName matches ^[A-Za-z_][A-Za-z0-9_]{0,63}$.
func ValidParamName(s string) bool {
	return matchAll(s, 1, 64, func(i int, c byte) bool {
		return isAlpha(c) || c == '_' || (i > 0 && isDigit(c))
	})
}

// ValidJWTClaim matches ^[A-Za-z_][A-Za-z0-9_.-]{0,63}$.
func ValidJWTClaim(s string) bool {
	return matchAll(s, 1, 64, func(i int, c byte) bool {
		return isAlpha(c) || c == '_' || (i > 0 && (isDigit(c) || c == '.' || c == '-'))
	})
}

func isSegChar(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '~' || c == '-'
}

// ValidAllowSegment matches ^[A-Za-z0-9._~-]{1,64}$ (also the path-keep
// grammar of sanitizer 4.2).
func ValidAllowSegment(s string) bool {
	return matchAll(s, 1, 64, func(_ int, c byte) bool { return isSegChar(c) })
}

// ValidKeyName matches ^[A-Za-z_][A-Za-z0-9_.-]{0,63}$ (query and cookie
// rule names, policy.md 1.2).
func ValidKeyName(s string) bool {
	return matchAll(s, 1, 64, func(i int, c byte) bool {
		return isAlpha(c) || c == '_' || (i > 0 && (isDigit(c) || c == '.' || c == '-'))
	})
}

// ValidHeaderName matches ^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$.
func ValidHeaderName(s string) bool {
	return matchAll(s, 1, 64, func(_ int, c byte) bool { return IsTokenChar(c) && !isUpper(c) })
}

// ValidGroup matches ^[a-z0-9][a-z0-9-]{0,62}$.
func ValidGroup(s string) bool { return ValidPolicyID(s) }

// ValidHostPort matches ^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$.
func ValidHostPort(s string) bool {
	host, port, hasPort := strings.Cut(s, ":")
	if !matchAll(host, 1, 253, func(_ int, c byte) bool { return isLower(c) || isDigit(c) || c == '.' || c == '-' }) {
		return false
	}
	return !hasPort || matchAll(port, 1, 5, func(_ int, c byte) bool { return isDigit(c) })
}

// HasWildcard reports whether a tt-path has a wildcard step, ".*" (any member)
// or "[*]" (any element). Names cannot contain "*", so a substring test is exact.
func HasWildcard(path string) bool {
	return strings.Contains(path, ".*") || strings.Contains(path, "[*]")
}

// Step kinds of a tt-path.
const (
	StepName      = iota // .name
	StepAnyMember        // .*
	StepAnyElem          // [*]
)

// Step is one tt-path step.
type Step struct {
	Kind int
	Name string
}

// MaxTTPathSteps is the maximum number of steps of a compiled tt-path.
const MaxTTPathSteps = 64

// ParseTTPath parses ^\$(\.[A-Za-z_][A-Za-z0-9_-]{0,63}|\.\*|\[\*\])*$.
func ParseTTPath(s string) ([]Step, bool) {
	if len(s) == 0 || s[0] != '$' {
		return nil, false
	}
	steps := []Step{}
	i := 1
	for i < len(s) {
		switch {
		case strings.HasPrefix(s[i:], "[*]"):
			steps = append(steps, Step{Kind: StepAnyElem})
			i += 3
		case strings.HasPrefix(s[i:], ".*"):
			steps = append(steps, Step{Kind: StepAnyMember})
			i += 2
		case strings.HasPrefix(s[i:], ".#text") && (i+6 == len(s) || s[i+6] == '.' || s[i+6] == '['):
			// Spec v1.19 (sanitizer.md 5.0, 22.2): mixed text of an XML element.
			steps = append(steps, Step{Kind: StepName, Name: "#text"})
			i += 6
		case s[i] == '.':
			j := i + 1
			at := j < len(s) && s[j] == '@' // spec v1.19: an XML attribute
			if at {
				j++
			}
			if j >= len(s) || !(isAlpha(s[j]) || s[j] == '_') {
				return nil, false
			}
			j++
			for j < len(s) && (isAlpha(s[j]) || isDigit(s[j]) || s[j] == '_' || s[j] == '-') {
				j++
			}
			n := j - (i + 1)
			if at {
				n--
			}
			if n > 64 {
				return nil, false
			}
			steps = append(steps, Step{Kind: StepName, Name: s[i+1 : j]})
			i = j
		default:
			return nil, false
		}
	}
	return steps, true
}

// TemplateSeg is one segment of an operation template.
type TemplateSeg struct {
	Literal string // set for literal segments
	Param   string // set for {name} segments
}

// MaxTemplateSegments is the maximum number of template segments.
const MaxTemplateSegments = 32

// ParseOpKey parses "METHOD /template" (opKey of the compiled schema:
// literals ^[A-Za-z0-9._~-]{1,64}$, parameters ^[A-Za-z_][A-Za-z0-9_]{0,63}$,
// at most 32 segments).
func ParseOpKey(op string) (method string, segs []TemplateSeg, ok bool) {
	sp := strings.IndexByte(op, ' ')
	if sp < 1 || sp > 16 {
		return "", nil, false
	}
	method = op[:sp]
	for i := 0; i < len(method); i++ {
		if !isUpper(method[i]) {
			return "", nil, false
		}
	}
	segs, ok = ParseTemplate(op[sp+1:])
	if !ok {
		return "", nil, false
	}
	return method, segs, true
}

// ParseTemplate parses "/seg/{param}/…" ("/" alone is the empty template).
func ParseTemplate(t string) ([]TemplateSeg, bool) {
	if len(t) == 0 || t[0] != '/' {
		return nil, false
	}
	segs := []TemplateSeg{}
	if t == "/" {
		return segs, true
	}
	for _, s := range strings.Split(t[1:], "/") {
		switch {
		case s == "":
			return nil, false
		case s[0] == '{':
			if len(s) < 3 || s[len(s)-1] != '}' || !ValidParamName(s[1:len(s)-1]) {
				return nil, false
			}
			segs = append(segs, TemplateSeg{Param: s[1 : len(s)-1]})
		default:
			if !ValidAllowSegment(s) {
				return nil, false
			}
			segs = append(segs, TemplateSeg{Literal: s})
		}
	}
	if len(segs) > MaxTemplateSegments {
		return nil, false
	}
	return segs, true
}

// BaseURL is a parsed match.base.
type BaseURL struct {
	Scheme string // lower case
	Host   string // lower case
	Port   string // empty when default for the scheme
	Path   []string
}

// Origin returns scheme://host[:port].
func (b BaseURL) Origin() string {
	o := b.Scheme + "://" + b.Host
	if b.Port != "" {
		o += ":" + b.Port
	}
	return o
}

// HostPort returns host[:port].
func (b BaseURL) HostPort() string {
	if b.Port != "" {
		return b.Host + ":" + b.Port
	}
	return b.Host
}

// String returns the normalized base.
func (b BaseURL) String() string {
	s := b.Origin()
	for _, p := range b.Path {
		s += "/" + p
	}
	return s
}

// ParseBase parses an author base ^https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~-]{1,64})*$
// and normalizes it as sanitizer 3.1 (lower case, default port removed).
func ParseBase(s string) (BaseURL, bool) {
	var b BaseURL
	rest := ""
	switch {
	case strings.HasPrefix(s, "https://"):
		b.Scheme, rest = "https", s[8:]
	case strings.HasPrefix(s, "http://"):
		b.Scheme, rest = "http", s[7:]
	default:
		return b, false
	}
	hostEnd := strings.IndexAny(rest, ":/")
	if hostEnd < 0 {
		hostEnd = len(rest)
	}
	host := rest[:hostEnd]
	if !matchAll(host, 1, 253, func(_ int, c byte) bool { return isAlpha(c) || isDigit(c) || c == '.' || c == '-' }) {
		return b, false
	}
	b.Host = strings.ToLower(host)
	rest = rest[hostEnd:]
	if strings.HasPrefix(rest, ":") {
		pe := strings.IndexByte(rest, '/')
		if pe < 0 {
			pe = len(rest)
		}
		port, ok := NormalizePort(b.Scheme, rest[1:pe])
		if !ok {
			return b, false
		}
		b.Port = port
		rest = rest[pe:]
	}
	if rest != "" {
		for _, seg := range strings.Split(rest[1:], "/") {
			if !ValidAllowSegment(seg) {
				return b, false
			}
			b.Path = append(b.Path, seg)
		}
	}
	return b, true
}

// NormalizePort validates 1-5 digits with value 1–65535 and returns "" for
// the scheme's default port, the decimal port without leading zeros
// otherwise.
func NormalizePort(scheme, p string) (string, bool) {
	if !matchAll(p, 1, 5, func(_ int, c byte) bool { return isDigit(c) }) {
		return "", false
	}
	n, _ := strconv.Atoi(p)
	if n < 1 || n > 65535 {
		return "", false
	}
	if (scheme == "http" && n == 80) || (scheme == "https" && n == 443) {
		return "", true
	}
	return strconv.Itoa(n), true
}

func sortedUnique(list []string, valid func(string) bool, maxItems int, where string) error {
	if len(list) > maxItems {
		return invalidf("%s: too many items", where)
	}
	seen := make(map[string]bool, len(list))
	for _, s := range list {
		if !valid(s) {
			return invalidf("%s: invalid item %q", where, s)
		}
		if seen[s] {
			return invalidf("%s: duplicate item %q", where, s)
		}
		seen[s] = true
	}
	return nil
}

// Validate applies the compiled schema, the reserved HMAC domains and the
// cross-field rules of policy.md 1.4 that tt-core enforces at compilation
// (time windows measured from created_at). Compile uses it.
// It includes the source-side safety subset (CheckUnsafe), so a policy that
// people can approve is never one that sources would refuse.
func Validate(p *Policy) error {
	if err := validate(p, true); err != nil {
		return err
	}
	return CheckUnsafe(p)
}

// ValidateSource applies what a source checks on every received body
// (policy.md 4 point 1, conformance/format.md): the compiled schema, no
// reserved HMAC domain, and from v1.3 the fixed safety subset H1 to H3 of
// hardening.md 2 (CheckUnsafe). The other compile-time rules are tt-core's
// and keyguard's. A body that is only unsafe fails with ErrUnsafe.
func ValidateSource(p *Policy) error {
	if err := validate(p, false); err != nil {
		return err
	}
	return CheckUnsafe(p)
}

// CheckUnsafe applies hardening.md 2.1, a fixed subset of policy.md 1.4 that
// depends neither on the clock nor on the group:
//
//	H1 keep, code (v1.11) or hmac on authorization, cookie, set-cookie,
//	   proxy-authorization (request, response and errors rules, global,
//	   services and operations);
//	H2 keep, code (v1.11) or hmac on a tt-path with any wildcard step (".*"
//	   or "[*]") in the global body rules (HasWildcard);
//	H3 discovery or auto_words expiring later than created_at + 7 days.
//
// It returns an error wrapping ErrUnsafe.
func CheckUnsafe(p *Policy) error {
	headers := func(part *Part, where string) error {
		for name, a := range part.Headers {
			if CredentialHeaders[name] && (a.Kind == ActKeep || a.Kind == ActHMAC || a.Kind == ActCode) {
				return unsafef("%s: keep, code and hmac are forbidden on header %q", where, name)
			}
		}
		return nil
	}
	scope := func(s *Scope, where string) error {
		for _, part := range []*Part{&s.Request, &s.Response, &s.Errors} {
			if err := headers(part, where); err != nil {
				return err
			}
		}
		return nil
	}
	if err := scope(&p.Global, "global"); err != nil {
		return err
	}
	for i := range p.Services {
		s := &p.Services[i]
		if err := scope(&s.Scope, s.Name); err != nil {
			return err
		}
		for j := range s.Ops {
			for _, part := range []*Part{&s.Ops[j].Request, &s.Ops[j].Response} {
				if err := headers(part, s.Name+" "+s.Ops[j].Op); err != nil {
					return err
				}
			}
		}
	}
	for _, part := range []*Part{&p.Global.Request, &p.Global.Response, &p.Global.Errors} {
		for _, r := range part.Body {
			if (r.Action.Kind == ActKeep || r.Action.Kind == ActHMAC || r.Action.Kind == ActCode) && HasWildcard(r.Path) {
				return unsafef("global: keep, code and hmac on %q are not allowed", r.Path)
			}
		}
	}
	limit := p.CreatedAt.Add(MaxOpenWindow)
	if p.Segments.AutoWords && p.Segments.AutoWordsExpiresAt.After(limit) {
		return unsafef("segments.auto_words_expires_at is beyond created_at + 7 days")
	}
	if d := p.Discovery; d != nil && d.Enabled && d.ExpiresAt.After(limit) {
		return unsafef("discovery.expires_at is beyond created_at + 7 days")
	}
	return nil
}

func validate(p *Policy, strict bool) error {
	if !ValidPolicyID(p.PolicyID) {
		return invalidf("policy_id")
	}
	if p.Version < 1 || p.IssuedSeq < 1 {
		return invalidf("version and issued_seq must be >= 1")
	}
	if p.CreatedAt.IsZero() || p.NotAfter.IsZero() || (strict && !p.NotAfter.After(p.CreatedAt)) {
		return invalidf("not_after must follow created_at")
	}
	if len(p.Groups) < 1 {
		return invalidf("targets.groups: at least one group")
	}
	if err := sortedUnique(p.Groups, ValidGroup, 256, "targets.groups"); err != nil {
		return err
	}
	if !ValidKid(p.HMAC.Kid) {
		return invalidf("hmac.kid")
	}
	if !ValidEpoch(p.HMAC.Epoch) {
		return invalidf("hmac.epoch")
	}
	if err := sortedUnique(p.HMAC.AcceptKids, ValidKid, 4, "hmac.accept_kids"); err != nil {
		return err
	}
	for _, k := range p.HMAC.AcceptKids {
		if strict && k == p.HMAC.Kid {
			return invalidf("hmac.accept_kids contains hmac.kid")
		}
	}
	if s := p.Subject; s != nil {
		if s.From != "header" && s.From != "cookie" {
			return invalidf("identity.subject.from")
		}
		if !ValidRuleName(s.Name) {
			return invalidf("identity.subject.name")
		}
		if s.JWTClaim != "" && !ValidJWTClaim(s.JWTClaim) {
			return invalidf("identity.subject.jwt_claim")
		}
		if s.JSONPath != "" && (s.From != "header" || s.JWTClaim != "" || !ValidJSONPath(s.JSONPath)) {
			return invalidf("identity.subject.json_path")
		}
	}
	if p.Sampling.RateBP < 0 || p.Sampling.RateBP > 10000 {
		return invalidf("sampling.rate_bp")
	}
	if err := sortedUnique(p.Sampling.PropagateTo, ValidHostPort, 256, "sampling.propagate_to"); err != nil {
		return err
	}
	if err := sortedUnique(p.Segments.Allow, ValidAllowSegment, 1024, "segments.allow"); err != nil {
		return err
	}
	if err := sortedUnique(p.Segments.HostsAllow, ValidHostPort, 1024, "segments.hosts_allow"); err != nil {
		return err
	}
	window := func(t time.Time, what string) error {
		if !t.After(p.CreatedAt) || t.After(p.CreatedAt.Add(MaxOpenWindow)) {
			return invalidf("%s must be after created_at and within 7 days", what)
		}
		return nil
	}
	if p.Segments.AutoWords {
		if p.Segments.AutoWordsExpiresAt.IsZero() {
			return invalidf("segments.auto_words_expires_at required")
		}
		if strict {
			if err := window(p.Segments.AutoWordsExpiresAt, "segments.auto_words_expires_at"); err != nil {
				return err
			}
		}
	}
	if d := p.Discovery; strict && d != nil && d.Enabled {
		if err := window(d.ExpiresAt, "discovery.expires_at"); err != nil {
			return err
		}
	}
	l := p.Limits
	if l.MaxBodyBytes < 0 || l.MaxBodyBytes > MaxMaxBodyBytes || l.MaxDepth < 1 || l.MaxDepth > MaxMaxDepth ||
		l.MaxArray < 0 || l.MaxArray > MaxMaxArray || l.MaxKeys < 1 || l.MaxKeys > MaxMaxKeys ||
		l.KeepMaxBytes < 0 || l.KeepMaxBytes > MaxKeepMaxBytes {
		return invalidf("limits out of range")
	}
	if err := validateScope(&p.Global, "global", true, strict); err != nil {
		return err
	}
	if len(p.Services) > 1024 {
		return invalidf("too many services")
	}
	names := map[string]bool{}
	bases := map[string]bool{}
	baseHosts := map[string]bool{}
	for i := range p.Services {
		s := &p.Services[i]
		if !ValidServiceName(s.Name) || (strict && names[s.Name]) {
			return invalidf("services[%d].name invalid or duplicate", i)
		}
		names[s.Name] = true
		if s.Match.Inbound == (s.Match.Base != "") || (s.Match.Internal && !s.Match.Inbound) {
			return invalidf("services[%d].match", i)
		}
		if !s.Match.Inbound {
			b, ok := ParseBase(s.Match.Base)
			if !ok || (strict && b.String() != s.Match.Base) {
				return invalidf("services[%d].match.base not valid or not normalized", i)
			}
			if strict && bases[s.Match.Base] {
				return invalidf("services[%d].match.base duplicates another service", i)
			}
			bases[s.Match.Base] = true
			baseHosts[b.Host] = true
			baseHosts[b.HostPort()] = true
		}
		if err := validateScope(&s.Scope, s.Name, false, strict); err != nil {
			return err
		}
		if len(s.Ops) > 4096 {
			return invalidf("%s: too many ops", s.Name)
		}
		keys := map[string]bool{}
		shapes := map[string]bool{}
		for j := range s.Ops {
			op := &s.Ops[j]
			method, segs, ok := ParseOpKey(op.Op)
			if !ok || (strict && keys[op.Op]) {
				return invalidf("%s.ops[%d].op %q invalid or duplicate", s.Name, j, op.Op)
			}
			keys[op.Op] = true
			shape := method
			params := map[string]bool{}
			for _, sg := range segs {
				if sg.Param != "" {
					if strict && params[sg.Param] {
						return invalidf("%s %q: repeated parameter", s.Name, op.Op)
					}
					params[sg.Param] = true
					shape += "/{}"
				} else {
					shape += "/=" + sg.Literal
				}
			}
			if strict && shapes[shape] {
				return invalidf("%s %q: equivalent to another operation", s.Name, op.Op)
			}
			shapes[shape] = true
			for _, part := range []*Part{&op.Request, &op.Response} {
				if err := validatePart(part, s.Name+" "+op.Op, true, false, strict); err != nil {
					return err
				}
				for name := range part.Path {
					if strict && !params[name] {
						return invalidf("%s %q: path parameter %q not in template", s.Name, op.Op, name)
					}
				}
			}
		}
	}
	for _, h := range p.Sampling.PropagateTo {
		if strict && baseHosts[h] {
			return invalidf("sampling.propagate_to %q is the host of a base", h)
		}
	}
	if strict {
		if err := checkGraphQLRules(p); err != nil {
			return err
		}
	}
	return nil
}

func validateScope(s *Scope, where string, global, strict bool) error {
	for _, part := range []*Part{&s.Request, &s.Response, &s.Errors} {
		if err := validatePart(part, where, false, global, strict); err != nil {
			return err
		}
	}
	return nil
}

func validatePart(p *Part, where string, isOp, global, strict bool) error {
	if len(p.Path) > 0 && !isOp {
		return invalidf("%s: path rules are only allowed in operations", where)
	}
	if len(p.Path) > 32 || len(p.Query) > 256 || len(p.Cookies) > 256 || len(p.Headers) > 256 || len(p.Body) > 1024 {
		return invalidf("%s: too many rules", where)
	}
	code := func(kind, name string, a Action) error {
		if strict && a.Kind == ActCode && !CodeRuleSafe(kind, name) {
			return invalidf("%s: %s %q: code is not allowed on cookies, credentials, secrets, postal or personal fields (policy.md 1.5)", where, kind, name)
		}
		return nil
	}
	for name, a := range p.Path {
		if !ValidParamName(name) {
			return invalidf("%s: path name %q", where, name)
		}
		if err := validateAction(strict, a, where); err != nil {
			return err
		}
		if err := code(CodePartPath, name, a); err != nil {
			return err
		}
	}
	for kind, m := range map[string]map[string]Action{CodePartQuery: p.Query, CodePartCookies: p.Cookies} {
		for name, a := range m {
			if !ValidKeyName(name) {
				return invalidf("%s: name %q", where, name)
			}
			if err := validateAction(strict, a, where); err != nil {
				return err
			}
			if err := code(kind, name, a); err != nil {
				return err
			}
		}
	}
	for name, a := range p.Headers {
		if !ValidHeaderName(name) {
			return invalidf("%s: header name %q", where, name)
		}
		if strict && a.Kind == ActKeep && ForbiddenKeepHeaders[name] {
			return invalidf("%s: keep is forbidden on header %q", where, name)
		}
		if strict && a.Kind == ActHMAC && CredentialHeaders[name] {
			return invalidf("%s: hmac is forbidden on header %q", where, name)
		}
		if err := validateAction(strict, a, where); err != nil {
			return err
		}
		if err := code(CodePartHeaders, name, a); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, r := range p.Body {
		steps, ok := ParseTTPath(r.Path)
		if !ok || len(steps) > MaxTTPathSteps {
			return invalidf("%s: body path %q", where, r.Path)
		}
		if strict && seen[r.Path] {
			return invalidf("%s: body rule %q given twice", where, r.Path)
		}
		seen[r.Path] = true
		if err := validateAction(strict, r.Action, where); err != nil {
			return err
		}
		if err := code(CodePartBody, r.Path, r.Action); err != nil {
			return err
		}
		if strict && global && r.Action.Kind != ActDrop && HasWildcard(r.Path) {
			return invalidf("%s: %q: keep, code, hmac and bucket on a wildcard step (.* or [*]) are not allowed in global rules", where, r.Path)
		}
	}
	return nil
}

func validateAction(strict bool, a Action, where string) error {
	switch a.Kind {
	case ActDrop, ActKeep, ActCode, ActGraphQL:
		return nil
	case ActHMAC:
		if !ValidDomain(a.Domain) {
			return invalidf("%s: hmac domain %q", where, a.Domain)
		}
		if ReservedDomains[a.Domain] {
			return invalidf("%s: hmac domain %q is reserved", where, a.Domain)
		}
		return nil
	case ActBucketNum:
		if len(a.Bounds) < 1 || len(a.Bounds) > 32 {
			return invalidf("%s: bucket needs 1 to 32 bounds", where)
		}
		for i, b := range a.Bounds {
			if !strict {
				break
			}
			if len(b.Lexeme) > MaxBoundLexeme || math.IsInf(b.F, 0) || math.IsNaN(b.F) {
				return invalidf("%s: bucket bound out of range", where)
			}
			if i > 0 && !(a.Bounds[i-1].F < b.F) {
				return invalidf("%s: bucket bounds must be strictly increasing as doubles", where)
			}
		}
		return nil
	case ActBucketTime:
		switch a.Unit {
		case "year", "month", "day", "hour":
			return nil
		}
		return invalidf("%s: bucket unit %q", where, a.Unit)
	}
	return invalidf("%s: unknown action", where)
}
