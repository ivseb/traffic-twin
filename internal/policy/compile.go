package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Author is an already parsed author policy (tt.policy/v1). YAML parsing is
// done by the caller (tt-core); AuthorFromGeneric converts the generic tree
// produced by any YAML or JSON decoder.
type Author struct {
	Format   string
	PolicyID string
	Default  string
	HMAC     HMACRef
	// Families (spec v1.18, C15) joins HMAC domains: every hmac(d) with d
	// in a family compiles to hmac(<family>). Author form only: the
	// compiled body does not change shape (no source change).
	Families  map[string][]string
	Subject   *Subject // identity.subject
	Sampling  *AuthorSampling
	Segments  AuthorSegments
	Limits    *AuthorLimits
	Discovery *AuthorDiscovery
	// Hosts is hosts.discovery (spec v1.5): "", "auto" or "off".
	Hosts string
	// Bodies (spec v1.19, sanitizer.md 22): nil takes CompileMeta.Bodies.
	Bodies   *AuthorBodies
	Global   AuthorScope
	Services map[string]AuthorService
}

// AuthorSampling is the author sampling block (required).
type AuthorSampling struct {
	Rate         string // decimal string, e.g. "0.05"
	TrustBaggage bool
	PropagateTo  []string
}

// AuthorSegments is the author segments block.
type AuthorSegments struct {
	AutoWords          bool
	AutoWordsExpiresAt string // RFC 3339; required when AutoWords
	Allow              []string
	HostsAllow         []string
}

// CompileMeta carries the fields assigned by tt-core at compilation.
type CompileMeta struct {
	Version   int64     // per policy_id, >= 1
	IssuedSeq int64     // global per tt-core instance, >= 1
	CreatedAt time.Time // compilation time
	NotAfter  time.Time // zero = CreatedAt + 30 days
	Groups    []string  // targets.groups, at least one
	// Bodies is tt-core's default bodies object (fleet.sanitizer.bodies,
	// spec v1.19) for authors without a bodies block; nil writes none, so
	// sources older than v1.19 keep accepting the body.
	Bodies *Bodies
}

// AuthorLimits holds optional limits; nil fields take the default.
type AuthorLimits struct {
	MaxBodyBytes, MaxDepth, MaxArray, MaxKeys, KeepMaxBytes *int64
}

// AuthorBodies is the author bodies block (sanitizer.md 22.1, spec v1.19);
// nil fields take tt-core's default (CompileMeta.Bodies, else DefaultBodies).
type AuthorBodies struct {
	XML, Multipart, Docs                            *bool
	MaxLargeBodyBytes, LargeArray, LargeNestedArray *int64
}

// AuthorDiscovery is the author discovery block.
type AuthorDiscovery struct {
	Enabled   bool
	ExpiresAt string // RFC 3339; required when Enabled
}

// AuthorPart holds author rules: name → action string, body tt-path →
// action string (the "$..." shorthand keys must already be merged into
// Body, AuthorFromGeneric does it).
type AuthorPart struct {
	Path, Query, Headers, Cookies, Body map[string]string
}

// AuthorScope groups request/response/errors.
type AuthorScope struct {
	Request, Response, Errors *AuthorPart
}

// AuthorService is one author service.
type AuthorService struct {
	Inbound  bool
	Internal bool
	Base     string
	AuthorScope
	Ops map[string]AuthorOp
}

// AuthorOp is one author operation.
type AuthorOp struct {
	Request, Response *AuthorPart
}

// ParseAction parses an author action string: drop | keep | code | hmac |
// hmac(<domain>) | bucket(num, [b0, ...]) | bucket(time, <unit>), with the
// exact optional-space grammar of schemas/policy.v1.schema.json.
func ParseAction(s string) (Action, error) {
	switch s {
	case "drop":
		return Action{Kind: ActDrop}, nil
	case "keep":
		return Action{Kind: ActKeep}, nil
	case "code":
		return Action{Kind: ActCode}, nil
	case "code(alnum)":
		return Action{Kind: ActCode, Shape: CodeShapeAlnum}, nil
	case "graphql":
		return Action{Kind: ActGraphQL}, nil
	case "hmac":
		return Action{Kind: ActHMAC, Domain: "id"}, nil
	}
	if strings.HasPrefix(s, "hmac(") && strings.HasSuffix(s, ")") {
		d := s[5 : len(s)-1]
		if !ValidDomain(d) {
			return Action{}, invalidf("action %q: bad domain", s)
		}
		if ReservedDomains[d] {
			return Action{}, invalidf("action %q: reserved domain", s)
		}
		return Action{Kind: ActHMAC, Domain: d}, nil
	}
	if rest, ok := strings.CutPrefix(s, "bucket(time,"); ok && strings.HasSuffix(rest, ")") {
		u := strings.TrimPrefix(rest[:len(rest)-1], " ")
		switch u {
		case "year", "month", "day", "hour":
			return Action{Kind: ActBucketTime, Unit: u}, nil
		}
		return Action{}, invalidf("action %q: bad unit", s)
	}
	if rest, ok := strings.CutPrefix(s, "bucket(num,"); ok && strings.HasSuffix(rest, "])") {
		rest = strings.TrimPrefix(rest, " ")
		if !strings.HasPrefix(rest, "[") {
			return Action{}, invalidf("action %q", s)
		}
		inner := rest[1 : len(rest)-2]
		inner = strings.TrimPrefix(inner, " ")
		inner = strings.TrimSuffix(inner, " ")
		a := Action{Kind: ActBucketNum}
		for _, item := range strings.Split(inner, ",") {
			// Allowed: optional single space on each side of the comma.
			if strings.HasPrefix(item, " ") {
				item = item[1:]
			}
			if strings.HasSuffix(item, " ") {
				item = item[:len(item)-1]
			}
			if !isAuthorBound(item) {
				return Action{}, invalidf("action %q: bad bound %q", s, item)
			}
			b, err := NewBound(item)
			if err != nil {
				return Action{}, invalidf("action %q: %v", s, err)
			}
			a.Bounds = append(a.Bounds, b)
		}
		if err := validateAction(true, a, "action"); err != nil {
			return Action{}, err
		}
		return a, nil
	}
	return Action{}, invalidf("unknown action %q", s)
}

// isAuthorBound matches -?(0|[1-9][0-9]*)(\.[0-9]+)?.
func isAuthorBound(s string) bool {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	if i >= len(s) {
		return false
	}
	if s[i] == '0' {
		i++
	} else if s[i] >= '1' && s[i] <= '9' {
		for i < len(s) && isDigit(s[i]) {
			i++
		}
	} else {
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		k := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i == k {
			return false
		}
	}
	return i == len(s)
}

// RateToBP converts a decimal sampling rate in [0, 1] to basis points; it
// fails when the rate has more precision than one basis point.
func RateToBP(rate string) (int, error) {
	r := strings.TrimSpace(rate)
	intPart, frac, _ := strings.Cut(r, ".")
	if intPart == "" || !matchAll(intPart, 1, 20, func(_ int, c byte) bool { return isDigit(c) }) ||
		!matchAll(frac, 0, 64, func(_ int, c byte) bool { return isDigit(c) }) || (strings.Contains(r, ".") && frac == "") {
		return 0, invalidf("sampling.rate %q", rate)
	}
	frac = strings.TrimRight(frac, "0")
	if len(frac) > 4 {
		return 0, invalidf("sampling.rate %q: more than 4 decimals", rate)
	}
	frac += strings.Repeat("0", 4-len(frac))
	ip, err := strconv.Atoi(intPart)
	if err != nil {
		return 0, invalidf("sampling.rate %q", rate)
	}
	fp, _ := strconv.Atoi(frac)
	bp := ip*10000 + fp
	if bp < 0 || bp > 10000 {
		return 0, invalidf("sampling.rate %q: not between 0 and 1", rate)
	}
	return bp, nil
}

func compilePart(ap *AuthorPart, where string, allowPath bool) (Part, error) {
	var p Part
	if ap == nil {
		return p, nil
	}
	conv := func(m map[string]string, kind string) (map[string]Action, error) {
		if len(m) == 0 {
			return nil, nil
		}
		out := make(map[string]Action, len(m))
		for k, s := range m {
			a, err := ParseAction(s)
			if err != nil {
				return nil, fmt.Errorf("%s.%s.%s: %w", where, kind, k, err)
			}
			out[k] = a
		}
		return out, nil
	}
	var err error
	if len(ap.Path) > 0 && !allowPath {
		return p, invalidf("%s: path rules are only allowed in operations", where)
	}
	if p.Path, err = conv(ap.Path, "path"); err != nil {
		return p, err
	}
	if p.Query, err = conv(ap.Query, "query"); err != nil {
		return p, err
	}
	if p.Headers, err = conv(ap.Headers, "headers"); err != nil {
		return p, err
	}
	if p.Cookies, err = conv(ap.Cookies, "cookies"); err != nil {
		return p, err
	}
	if len(ap.Body) > 0 {
		paths := make([]string, 0, len(ap.Body))
		for k := range ap.Body {
			paths = append(paths, k)
		}
		sort.Strings(paths)
		for _, k := range paths {
			a, err := ParseAction(ap.Body[k])
			if err != nil {
				return p, fmt.Errorf("%s.body.%s: %w", where, k, err)
			}
			p.Body = append(p.Body, BodyRule{Path: k, Action: a})
		}
	}
	return p, nil
}

// sortedSet returns a sorted copy of list, rejecting duplicates.
func sortedSet(list []string, where string) ([]string, error) {
	out := append([]string{}, list...)
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, invalidf("%s: duplicate %q", where, out[i])
		}
	}
	return out, nil
}

func utcSeconds(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

// Compile turns an author policy into canonical compiled body bytes
// (tt.policy.body/v1, policy.md section 2). The meta fields are assigned by
// tt-core; times are written in RFC 3339 UTC with second precision. The
// returned bytes always pass DecodeBody and are canonical; signing is done
// by tt keyguard over SignedMessage(body).
func Compile(a *Author, meta CompileMeta) ([]byte, *Policy, error) {
	if a.Format != FormatAuthor {
		return nil, nil, invalidf("format: expected %s", FormatAuthor)
	}
	if a.Default != "drop" {
		return nil, nil, invalidf("default: only drop is allowed")
	}
	if a.Sampling == nil {
		return nil, nil, invalidf("sampling is required")
	}
	created := utcSeconds(meta.CreatedAt)
	notAfter := utcSeconds(meta.NotAfter)
	if meta.NotAfter.IsZero() {
		notAfter = created.Add(DefaultValidity)
	}
	p := &Policy{
		PolicyID:  a.PolicyID,
		Version:   meta.Version,
		IssuedSeq: meta.IssuedSeq,
		CreatedAt: created,
		NotAfter:  notAfter,
		HMAC:      a.HMAC,
		Limits:    DefaultLimits(),
	}
	var err error
	if p.Groups, err = sortedSet(meta.Groups, "targets.groups"); err != nil {
		return nil, nil, err
	}
	if p.HMAC.AcceptKids, err = sortedSet(a.HMAC.AcceptKids, "hmac.accept_kids"); err != nil {
		return nil, nil, err
	}
	if a.Subject != nil {
		s := *a.Subject
		if s.From == "header" {
			s.Name = strings.ToLower(s.Name)
		}
		p.Subject = &s
	}
	alias, err := familyAliases(a.Families)
	if err != nil {
		return nil, nil, err
	}
	if p.Sampling.RateBP, err = RateToBP(a.Sampling.Rate); err != nil {
		return nil, nil, err
	}
	p.Sampling.TrustBaggage = a.Sampling.TrustBaggage
	if p.Sampling.PropagateTo, err = sortedSet(a.Sampling.PropagateTo, "sampling.propagate_to"); err != nil {
		return nil, nil, err
	}
	p.Segments.AutoWords = a.Segments.AutoWords
	if a.Segments.AutoWordsExpiresAt != "" {
		t, err := time.Parse(time.RFC3339Nano, a.Segments.AutoWordsExpiresAt)
		if err != nil {
			return nil, nil, invalidf("segments.auto_words_expires_at: not RFC 3339")
		}
		p.Segments.AutoWordsExpiresAt = t
		p.Segments.autoWordsRaw = a.Segments.AutoWordsExpiresAt
	}
	if p.Segments.Allow, err = sortedSet(a.Segments.Allow, "segments.allow"); err != nil {
		return nil, nil, err
	}
	if p.Segments.HostsAllow, err = sortedSet(a.Segments.HostsAllow, "segments.hosts_allow"); err != nil {
		return nil, nil, err
	}
	if l := a.Limits; l != nil {
		set := func(dst *int64, v *int64) {
			if v != nil {
				*dst = *v
			}
		}
		mb := p.Limits.MaxBodyBytes
		d, ar, k, kp := int64(p.Limits.MaxDepth), int64(p.Limits.MaxArray), int64(p.Limits.MaxKeys), int64(p.Limits.KeepMaxBytes)
		set(&mb, l.MaxBodyBytes)
		set(&d, l.MaxDepth)
		set(&ar, l.MaxArray)
		set(&k, l.MaxKeys)
		set(&kp, l.KeepMaxBytes)
		for _, v := range []int64{mb, d, ar, k, kp} {
			if v < 0 || v > math.MaxInt32 {
				return nil, nil, invalidf("limits out of range")
			}
		}
		p.Limits = Limits{mb, int(d), int(ar), int(k), int(kp)}
	}
	if a.Discovery != nil {
		if a.Discovery.ExpiresAt == "" {
			if a.Discovery.Enabled {
				return nil, nil, invalidf("discovery.expires_at is required when discovery is enabled")
			}
		} else {
			t, err := time.Parse(time.RFC3339Nano, a.Discovery.ExpiresAt)
			if err != nil {
				return nil, nil, invalidf("discovery.expires_at: not RFC 3339")
			}
			p.Discovery = &Discovery{Enabled: a.Discovery.Enabled, ExpiresAt: t, expiresRaw: a.Discovery.ExpiresAt}
		}
	}
	if p.Bodies, err = compileBodies(a.Bodies, meta.Bodies); err != nil {
		return nil, nil, err
	}
	// hosts.discovery: only the strict mode is written into the body; auto
	// is the default of an absent field (sanitizer.md 3.1, spec v1.5), so
	// sources that predate v1.5 keep accepting bodies in the default mode.
	switch a.Hosts {
	case "", HostsAuto:
	case HostsOff:
		p.Hosts.Discovery = HostsOff
	default:
		return nil, nil, invalidf("hosts.discovery: must be auto or off")
	}
	if p.Global, err = compileScope(&a.Global, "global"); err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(a.Services))
	for n := range a.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		as := a.Services[n]
		s := Service{Name: n, Match: Match{Inbound: as.Inbound, Internal: as.Internal}}
		if !as.Inbound {
			b, ok := ParseBase(as.Base)
			if !ok {
				return nil, nil, invalidf("services.%s.match.base %q", n, as.Base)
			}
			s.Match.Base = b.String()
		}
		if s.Scope, err = compileScope(&as.AuthorScope, n); err != nil {
			return nil, nil, err
		}
		keys := make([]string, 0, len(as.Ops))
		for k := range as.Ops {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		s.Ops = []Op{}
		for _, k := range keys {
			ao := as.Ops[k]
			op := Op{Op: k}
			if op.Request, err = compilePart(ao.Request, n+" "+k+".request", true); err != nil {
				return nil, nil, err
			}
			if op.Response, err = compilePart(ao.Response, n+" "+k+".response", true); err != nil {
				return nil, nil, err
			}
			s.Ops = append(s.Ops, op)
		}
		p.Services = append(p.Services, s)
	}
	if p.Services == nil {
		p.Services = []Service{}
	}
	applyFamilies(p, alias)
	if err := Validate(p); err != nil {
		return nil, nil, err
	}
	body, err := EncodeBody(p)
	if err != nil {
		return nil, nil, err
	}
	// Round trip: what we emit must be exactly what sources accept.
	p2, err := DecodeBody(body)
	if err != nil {
		return nil, nil, err
	}
	return body, p2, nil
}

func compileScope(s *AuthorScope, where string) (Scope, error) {
	var out Scope
	var err error
	if out.Request, err = compilePart(s.Request, where+".request", false); err != nil {
		return out, err
	}
	if out.Response, err = compilePart(s.Response, where+".response", false); err != nil {
		return out, err
	}
	if out.Errors, err = compilePart(s.Errors, where+".errors", false); err != nil {
		return out, err
	}
	return out, nil
}

// ---- Generic tree conversion (YAML/JSON decoded into any) ----

type gmap = map[string]any

func asMap(v any, where string) (gmap, error) {
	switch m := v.(type) {
	case map[string]any:
		return m, nil
	case map[any]any:
		out := make(gmap, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, invalidf("%s: non-string key", where)
			}
			out[ks] = val
		}
		return out, nil
	case nil:
		return gmap{}, nil
	}
	return nil, invalidf("%s: expected mapping", where)
}

func onlyKeys(m gmap, where string, allowed ...string) error {
	for k := range m {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
			}
		}
		if !ok {
			return invalidf("%s: unknown field %q", where, k)
		}
	}
	return nil
}

func asString(v any, where string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", invalidf("%s: expected string", where)
	}
	return s, nil
}

func asBool(v any, where string) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, invalidf("%s: expected boolean", where)
	}
	return b, nil
}

// asDecimal renders a decoded number as an exact decimal string.
func asDecimal(v any, where string) (string, error) {
	switch n := v.(type) {
	case int:
		return strconv.Itoa(n), nil
	case int64:
		return strconv.FormatInt(n, 10), nil
	case uint64:
		return strconv.FormatUint(n, 10), nil
	case float64:
		if math.IsInf(n, 0) || math.IsNaN(n) {
			return "", invalidf("%s: not a finite number", where)
		}
		return strconv.FormatFloat(n, 'f', -1, 64), nil
	case json.Number:
		return n.String(), nil
	}
	return "", invalidf("%s: expected number", where)
}

func asInt(v any, where string) (int64, error) {
	s, err := asDecimal(v, where)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, invalidf("%s: expected integer", where)
	}
	return n, nil
}

func asStringList(v any, where string) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, invalidf("%s: expected list", where)
	}
	out := []string{}
	for _, e := range list {
		s, err := asString(e, where+"[]")
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// asTime accepts an RFC 3339 string or a time.Time (some YAML decoders
// produce timestamps).
func asTime(v any, where string) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano), nil
	}
	return "", invalidf("%s: expected timestamp", where)
}

func asActionMap(v any, where string) (map[string]string, error) {
	m, err := asMap(v, where)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(m))
	for k, a := range m {
		s, err := asString(a, where+"."+k)
		if err != nil {
			return nil, err
		}
		out[k] = s
	}
	return out, nil
}

func genericPart(v any, where string, allowPath bool) (*AuthorPart, error) {
	m, err := asMap(v, where)
	if err != nil {
		return nil, err
	}
	p := &AuthorPart{Body: map[string]string{}}
	for k, val := range m {
		switch {
		case k == "path" && allowPath, k == "query", k == "headers", k == "cookies":
			am, err := asActionMap(val, where+"."+k)
			if err != nil {
				return nil, err
			}
			switch k {
			case "path":
				p.Path = am
			case "query":
				p.Query = am
			case "headers":
				p.Headers = am
			case "cookies":
				p.Cookies = am
			}
		case k == "body":
			am, err := asActionMap(val, where+".body")
			if err != nil {
				return nil, err
			}
			for bk, a := range am {
				if _, dup := p.Body[bk]; dup {
					return nil, invalidf("%s: body rule %q given twice", where, bk)
				}
				p.Body[bk] = a
			}
		case strings.HasPrefix(k, "$"):
			s, err := asString(val, where+"."+k)
			if err != nil {
				return nil, err
			}
			if _, dup := p.Body[k]; dup {
				return nil, invalidf("%s: body rule %q given twice", where, k)
			}
			p.Body[k] = s
		default:
			return nil, invalidf("%s: unknown field %q", where, k)
		}
	}
	return p, nil
}

func genericScope(m gmap, where string, out *AuthorScope) error {
	var err error
	if v, ok := m["request"]; ok {
		if out.Request, err = genericPart(v, where+".request", false); err != nil {
			return err
		}
	}
	if v, ok := m["response"]; ok {
		if out.Response, err = genericPart(v, where+".response", false); err != nil {
			return err
		}
	}
	if v, ok := m["errors"]; ok {
		if out.Errors, err = genericPart(v, where+".errors", false); err != nil {
			return err
		}
	}
	return nil
}

// AuthorFromGeneric converts an author policy decoded by a YAML or JSON
// library into map[string]any / map[any]any / []any / scalars. Unknown
// fields are rejected.
func AuthorFromGeneric(doc any) (*Author, error) {
	m, err := asMap(doc, "policy")
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(m, "policy", "format", "policy_id", "default", "hmac", "identity", "sampling",
		"segments", "limits", "discovery", "hosts", "bodies", "global", "services"); err != nil {
		return nil, err
	}
	a := &Author{Services: map[string]AuthorService{}}
	if a.Format, err = asString(m["format"], "format"); err != nil {
		return nil, err
	}
	if a.PolicyID, err = asString(m["policy_id"], "policy_id"); err != nil {
		return nil, err
	}
	if a.Default, err = asString(m["default"], "default"); err != nil {
		return nil, err
	}
	hm, err := asMap(m["hmac"], "hmac")
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(hm, "hmac", "kid", "epoch", "accept_kids", "families"); err != nil {
		return nil, err
	}
	if fv, ok := hm["families"]; ok {
		fm, err := asMap(fv, "hmac.families")
		if err != nil {
			return nil, err
		}
		a.Families = map[string][]string{}
		for name, lv := range fm {
			if a.Families[name], err = asStringList(lv, "hmac.families."+name); err != nil {
				return nil, err
			}
		}
	}
	if lv, ok := hm["accept_kids"]; ok {
		if a.HMAC.AcceptKids, err = asStringList(lv, "hmac.accept_kids"); err != nil {
			return nil, err
		}
	}
	if a.HMAC.Kid, err = asString(hm["kid"], "hmac.kid"); err != nil {
		return nil, err
	}
	if a.HMAC.Epoch, err = asString(hm["epoch"], "hmac.epoch"); err != nil {
		return nil, err
	}
	if v, ok := m["identity"]; ok {
		im, err := asMap(v, "identity")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(im, "identity", "subject"); err != nil {
			return nil, err
		}
		if sv, ok := im["subject"]; ok {
			sm, err := asMap(sv, "identity.subject")
			if err != nil {
				return nil, err
			}
			if err := onlyKeys(sm, "identity.subject", "from", "name", "jwt_claim", "json_path"); err != nil {
				return nil, err
			}
			s := &Subject{}
			if s.From, err = asString(sm["from"], "identity.subject.from"); err != nil {
				return nil, err
			}
			if s.Name, err = asString(sm["name"], "identity.subject.name"); err != nil {
				return nil, err
			}
			if jv, ok := sm["jwt_claim"]; ok {
				if s.JWTClaim, err = asString(jv, "identity.subject.jwt_claim"); err != nil {
					return nil, err
				}
			}
			if jv, ok := sm["json_path"]; ok {
				if s.JSONPath, err = asString(jv, "identity.subject.json_path"); err != nil {
					return nil, err
				}
				if !ValidJSONPath(s.JSONPath) {
					return nil, invalidf("identity.subject.json_path: a dotted path of 1 to 8 members")
				}
			}
			a.Subject = s
		}
	}
	if v, ok := m["sampling"]; ok {
		sm, err := asMap(v, "sampling")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(sm, "sampling", "rate", "trust_baggage", "propagate_to"); err != nil {
			return nil, err
		}
		r, err := asDecimal(sm["rate"], "sampling.rate")
		if err != nil {
			return nil, err
		}
		a.Sampling = &AuthorSampling{Rate: r}
		if bv, ok := sm["trust_baggage"]; ok {
			if a.Sampling.TrustBaggage, err = asBool(bv, "sampling.trust_baggage"); err != nil {
				return nil, err
			}
		}
		if lv, ok := sm["propagate_to"]; ok {
			if a.Sampling.PropagateTo, err = asStringList(lv, "sampling.propagate_to"); err != nil {
				return nil, err
			}
		}
	}
	if v, ok := m["segments"]; ok {
		sm, err := asMap(v, "segments")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(sm, "segments", "auto_words", "auto_words_expires_at", "allow", "hosts_allow"); err != nil {
			return nil, err
		}
		if ev, ok := sm["auto_words_expires_at"]; ok {
			if a.Segments.AutoWordsExpiresAt, err = asTime(ev, "segments.auto_words_expires_at"); err != nil {
				return nil, err
			}
		}
		if lv, ok := sm["hosts_allow"]; ok {
			if a.Segments.HostsAllow, err = asStringList(lv, "segments.hosts_allow"); err != nil {
				return nil, err
			}
		}
		if av, ok := sm["auto_words"]; ok {
			if a.Segments.AutoWords, err = asBool(av, "segments.auto_words"); err != nil {
				return nil, err
			}
		}
		if lv, ok := sm["allow"]; ok {
			list, ok := lv.([]any)
			if !ok {
				return nil, invalidf("segments.allow: expected list")
			}
			for _, e := range list {
				s, err := asString(e, "segments.allow[]")
				if err != nil {
					return nil, err
				}
				a.Segments.Allow = append(a.Segments.Allow, s)
			}
		}
	}
	if v, ok := m["limits"]; ok {
		lm, err := asMap(v, "limits")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(lm, "limits", "max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes"); err != nil {
			return nil, err
		}
		a.Limits = &AuthorLimits{}
		for k, dst := range map[string]**int64{
			"max_body_bytes": &a.Limits.MaxBodyBytes, "max_depth": &a.Limits.MaxDepth, "max_array": &a.Limits.MaxArray,
			"max_keys": &a.Limits.MaxKeys, "keep_max_bytes": &a.Limits.KeepMaxBytes,
		} {
			if lv, ok := lm[k]; ok {
				n, err := asInt(lv, "limits."+k)
				if err != nil {
					return nil, err
				}
				*dst = &n
			}
		}
	}
	if v, ok := m["discovery"]; ok {
		dm, err := asMap(v, "discovery")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(dm, "discovery", "enabled", "expires_at"); err != nil {
			return nil, err
		}
		a.Discovery = &AuthorDiscovery{}
		if a.Discovery.Enabled, err = asBool(dm["enabled"], "discovery.enabled"); err != nil {
			return nil, err
		}
		if ev, ok := dm["expires_at"]; ok {
			if a.Discovery.ExpiresAt, err = asTime(ev, "discovery.expires_at"); err != nil {
				return nil, err
			}
		}
	}
	if v, ok := m["hosts"]; ok {
		hm, err := asMap(v, "hosts")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(hm, "hosts", "discovery"); err != nil {
			return nil, err
		}
		if dv, ok := hm["discovery"]; ok {
			if a.Hosts, err = asString(dv, "hosts.discovery"); err != nil {
				return nil, err
			}
			if a.Hosts != HostsAuto && a.Hosts != HostsOff {
				return nil, invalidf("hosts.discovery: must be auto or off")
			}
		}
	}
	if v, ok := m["bodies"]; ok {
		bm, err := asMap(v, "bodies")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(bm, "bodies", "xml", "multipart", "docs", "max_large_body_bytes", "large_array", "large_nested_array"); err != nil {
			return nil, err
		}
		a.Bodies = &AuthorBodies{}
		for k, dst := range map[string]**bool{"xml": &a.Bodies.XML, "multipart": &a.Bodies.Multipart, "docs": &a.Bodies.Docs} {
			if bv, ok := bm[k]; ok {
				b, err := asBool(bv, "bodies."+k)
				if err != nil {
					return nil, err
				}
				*dst = &b
			}
		}
		for k, dst := range map[string]**int64{"max_large_body_bytes": &a.Bodies.MaxLargeBodyBytes,
			"large_array": &a.Bodies.LargeArray, "large_nested_array": &a.Bodies.LargeNestedArray} {
			if lv, ok := bm[k]; ok {
				n, err := asInt(lv, "bodies."+k)
				if err != nil {
					return nil, err
				}
				*dst = &n
			}
		}
	}
	if v, ok := m["global"]; ok {
		gm, err := asMap(v, "global")
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(gm, "global", "request", "response", "errors"); err != nil {
			return nil, err
		}
		if err := genericScope(gm, "global", &a.Global); err != nil {
			return nil, err
		}
	}
	if v, ok := m["services"]; ok {
		sm, err := asMap(v, "services")
		if err != nil {
			return nil, err
		}
		for name, sv := range sm {
			w := "services." + name
			svm, err := asMap(sv, w)
			if err != nil {
				return nil, err
			}
			if err := onlyKeys(svm, w, "match", "request", "response", "errors", "ops"); err != nil {
				return nil, err
			}
			var s AuthorService
			mm, err := asMap(svm["match"], w+".match")
			if err != nil {
				return nil, err
			}
			if err := onlyKeys(mm, w+".match", "inbound", "internal", "base"); err != nil {
				return nil, err
			}
			if iv, ok := mm["inbound"]; ok {
				if _, hasBase := mm["base"]; hasBase {
					return nil, invalidf("%s.match: inbound and base are exclusive", w)
				}
				if b, err := asBool(iv, w+".match.inbound"); err != nil || !b {
					return nil, invalidf("%s.match.inbound must be true", w)
				}
				s.Inbound = true
				if xv, ok := mm["internal"]; ok {
					if s.Internal, err = asBool(xv, w+".match.internal"); err != nil {
						return nil, err
					}
				}
			} else {
				if len(mm) != 1 {
					return nil, invalidf("%s.match: base excludes other fields", w)
				}
				if s.Base, err = asString(mm["base"], w+".match.base"); err != nil {
					return nil, err
				}
			}
			if err := genericScope(svm, w, &s.AuthorScope); err != nil {
				return nil, err
			}
			s.Ops = map[string]AuthorOp{}
			if ov, ok := svm["ops"]; ok {
				om, err := asMap(ov, w+".ops")
				if err != nil {
					return nil, err
				}
				for key, opv := range om {
					ow := w + ".ops." + key
					opm, err := asMap(opv, ow)
					if err != nil {
						return nil, err
					}
					if err := onlyKeys(opm, ow, "request", "response"); err != nil {
						return nil, err
					}
					var op AuthorOp
					if rv, ok := opm["request"]; ok {
						if op.Request, err = genericPart(rv, ow+".request", true); err != nil {
							return nil, err
						}
					}
					if rv, ok := opm["response"]; ok {
						if op.Response, err = genericPart(rv, ow+".response", true); err != nil {
							return nil, err
						}
					}
					s.Ops[key] = op
				}
			}
			a.Services[name] = s
		}
	}
	return a, nil
}

// compileBodies resolves the bodies object (sanitizer.md 22.1, spec v1.19):
// the author block over tt-core's default (def, else DefaultBodies). A
// result with every switch off is written as no object at all, so that
// sources older than v1.19 keep accepting the body.
func compileBodies(a *AuthorBodies, def *Bodies) (*Bodies, error) {
	if a == nil {
		if def == nil {
			return nil, nil
		}
		b := *def
		return validBodies(&b)
	}
	b := *DefaultBodies()
	if def != nil {
		b = *def
	}
	for _, f := range []struct {
		src *bool
		dst *bool
	}{{a.XML, &b.XML}, {a.Multipart, &b.Multipart}, {a.Docs, &b.Docs}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if a.MaxLargeBodyBytes != nil {
		b.MaxLargeBytes = *a.MaxLargeBodyBytes
	}
	for _, f := range []struct {
		src *int64
		dst *int
	}{{a.LargeArray, &b.LargeArray}, {a.LargeNestedArray, &b.LargeNestedArray}} {
		if f.src != nil {
			if *f.src < 0 || *f.src > MaxLargeArray {
				return nil, invalidf("bodies: large arrays out of range (0..%d)", MaxLargeArray)
			}
			*f.dst = int(*f.src)
		}
	}
	return validBodies(&b)
}

func validBodies(b *Bodies) (*Bodies, error) {
	if b.MaxLargeBytes < 0 || b.MaxLargeBytes > MaxLargeBodyBytes {
		return nil, invalidf("bodies.max_large_body_bytes out of range (0..%d)", MaxLargeBodyBytes)
	}
	if b.LargeArray < 0 || b.LargeArray > MaxLargeArray || b.LargeNestedArray < 0 || b.LargeNestedArray > MaxLargeArray {
		return nil, invalidf("bodies: large arrays out of range (0..%d)", MaxLargeArray)
	}
	if !b.XML && !b.Multipart && !b.Docs && b.MaxLargeBytes == 0 {
		return nil, nil
	}
	return b, nil
}
