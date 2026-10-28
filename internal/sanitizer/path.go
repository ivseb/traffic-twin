package sanitizer

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/hostpat"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// MaxSegments is the maximum number of path segments (section 4.1).
const MaxSegments = 32

type segment struct {
	dec   []byte
	valid bool // decoded bytes are UTF-8
}

// pctDecode decodes %XY (two hex digits); '+' is kept (section 4.1).
func pctDecode(b []byte) []byte {
	if bytes.IndexByte(b, '%') < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '%' && i+2 < len(b) && isHex(b[i+1]) && isHex(b[i+2]) {
			out = append(out, unhex(b[i+1])<<4|unhex(b[i+2]))
			i += 2
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// splitPath splits and decodes raw_path. truncated reports more than
// MaxSegments segments (the extra ones are not returned).
func splitPath(raw []byte) (segs []segment, truncated bool) {
	for _, s := range bytes.Split(raw, []byte{'/'}) {
		if len(s) == 0 {
			continue
		}
		if len(segs) == MaxSegments {
			return segs, true
		}
		d := pctDecode(s)
		segs = append(segs, segment{dec: d, valid: utf8.Valid(d)})
	}
	return segs, false
}

const methodOther = "OTHER"

// normalizeMethod upper-cases ASCII and returns OTHER unless ^[A-Z]{1,16}$.
func normalizeMethod(m string) string {
	if len(m) < 1 || len(m) > 16 {
		return methodOther
	}
	b := []byte(m)
	for i, c := range b {
		if isLower(c) {
			b[i] = c - ('a' - 'A')
		} else if !isUpper(c) {
			return methodOther
		}
	}
	return string(b)
}

// ---- framework_route normalization (section 3.4) ----

// identPrefix returns the length of a leading identifier
// [A-Za-z_][A-Za-z0-9_]* in s (0 if none).
func identPrefix(s string) int {
	if s == "" || !(isAlpha(s[0]) || s[0] == '_') {
		return 0
	}
	i := 1
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '_') {
		i++
	}
	return i
}

// Framework identifiers of section 3.4 (input "framework", A-FRAMEWORK-ID).
var knownFrameworks = map[string]bool{
	"express": true, "koa": true, "fastify": true, "flask": true, "fastapi": true, "django": true, "spring": true,
	"jaxrs": true, "aspnetcore": true, "gin": true, "chi": true, "nethttp": true, "laravel": true, "symfony": true,
}

// braceParam parses "{inner}" for the brace-style frameworks; it returns
// the name and the text after it (spaces ignored only for JAX-RS).
func braceParam(s string, spaces bool) (name, rest string, ok bool) {
	if len(s) < 3 || s[0] != '{' || s[len(s)-1] != '}' {
		return "", "", false
	}
	inner := s[1 : len(s)-1]
	if spaces {
		inner = strings.Trim(inner, " ")
	}
	n := identPrefix(inner)
	if n == 0 {
		return "", "", false
	}
	rest = inner[n:]
	if spaces {
		rest = strings.TrimLeft(rest, " ")
	}
	return inner[:n], rest, true
}

// frameworkParam returns the parameter name of segment s for framework fw,
// or ok=false when s is not one of that framework's parameter syntaxes.
// drop=true marks a segment that disappears (Go's final {$}).
func frameworkParam(fw, s string, last bool) (name string, drop, ok bool) {
	switch fw {
	case "express", "koa", "fastify", "gin":
		if s[0] != ':' {
			return "", false, false
		}
		n := identPrefix(s[1:])
		if n == 0 {
			return "", false, false
		}
		rest := s[1+n:]
		if rest == "" || (fw != "gin" && len(rest) >= 2 && rest[0] == '(' && rest[len(rest)-1] == ')') {
			return s[1 : 1+n], false, true
		}
	case "flask", "django":
		if len(s) < 3 || s[0] != '<' || s[len(s)-1] != '>' {
			return "", false, false
		}
		inner := s[1 : len(s)-1]
		if conv, nm, has := strings.Cut(inner, ":"); has {
			if conv == "path" || conv == "" || identPrefix(conv) != len(conv) {
				return "", false, false
			}
			inner = nm
		}
		return inner, false, true
	case "fastapi":
		nm, rest, ok := braceParam(s, false)
		if ok && (rest == "" || (rest[0] == ':' && len(rest) > 1 && rest[1:] != "path")) {
			return nm, false, true
		}
	case "spring", "chi":
		nm, rest, ok := braceParam(s, false)
		if ok && (rest == "" || (rest[0] == ':' && len(rest) > 1)) {
			return nm, false, true
		}
	case "jaxrs":
		nm, rest, ok := braceParam(s, true)
		if ok && (rest == "" || (rest[0] == ':' && strings.TrimSpace(rest[1:]) != "")) {
			return nm, false, true
		}
	case "aspnetcore":
		nm, rest, ok := braceParam(s, false)
		if ok && (rest == "" || (rest[0] == ':' && len(rest) > 1 && !strings.HasSuffix(rest, "?") && !strings.Contains(rest, "="))) {
			return nm, false, true
		}
	case "nethttp":
		if s == "{$}" {
			return "", true, last
		}
		nm, rest, ok := braceParam(s, false)
		if ok && rest == "" {
			return nm, false, true
		}
	case "laravel":
		nm, rest, ok := braceParam(s, false)
		if ok && rest == "" {
			return nm, false, true
		}
	case "symfony":
		nm, rest, ok := braceParam(s, false)
		if ok && (rest == "" || (len(rest) >= 2 && rest[0] == '<' && rest[len(rest)-1] == '>')) {
			return nm, false, true
		}
	}
	return "", false, false
}

// normalizeFrameworkRoute returns the template segments of a framework route
// (section 3.4) or ok=false when it cannot be normalized. A segment that is
// not a parameter syntax of the framework must be a literal of the
// operation-key grammar (A-FRAMEWORK-ID).
func normalizeFrameworkRoute(fw, route string) ([]policy.TemplateSeg, bool) {
	if !knownFrameworks[fw] {
		return nil, false
	}
	var raw []string
	for _, p := range strings.Split(route, "/") {
		if p != "" {
			raw = append(raw, p)
		}
	}
	segs := []policy.TemplateSeg{}
	for i, p := range raw {
		name, drop, ok := frameworkParam(fw, p, i == len(raw)-1)
		switch {
		case drop && ok:
			continue
		case drop:
			return nil, false
		case ok:
			if !policy.ValidParamName(name) {
				return nil, false
			}
			segs = append(segs, policy.TemplateSeg{Param: name})
		case policy.ValidAllowSegment(p):
			segs = append(segs, policy.TemplateSeg{Literal: p})
		default:
			return nil, false
		}
	}
	if len(segs) > policy.MaxTemplateSegments {
		return nil, false
	}
	return segs, true
}

// sameStructure reports equal literals at the same positions and parameters
// at the same positions (names ignored).
func sameStructure(a, b []policy.TemplateSeg) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i].Param == "") != (b[i].Param == "") || a[i].Literal != b[i].Literal {
			return false
		}
	}
	return true
}

// templateMatches implements step 2: literals equal to the decoded segment,
// parameters match any valid segment.
func templateMatches(o *opT, segs []segment) bool {
	if len(o.segs) != len(segs) {
		return false
	}
	for i, ts := range o.segs {
		if !segs[i].valid {
			return false
		}
		if ts.Param == "" && string(segs[i].dec) != ts.Literal {
			return false
		}
	}
	return true
}

// chooseOp implements section 3.3 on the operation path segments.
func chooseOp(s *svcT, method, framework, frameworkRoute string, segs []segment, truncated bool) (*opT, string) {
	if s == nil || truncated || method == methodOther {
		return nil, "raw"
	}
	if frameworkRoute != "" {
		if t, ok := normalizeFrameworkRoute(framework, frameworkRoute); ok && len(t) == len(segs) {
			for _, o := range s.ops {
				if o.method == method && sameStructure(o.segs, t) {
					return o, "framework"
				}
			}
		}
	}
	var best *opT
	for _, o := range s.ops {
		if o.method != method || !templateMatches(o, segs) {
			continue
		}
		if best == nil || o.literals > best.literals || (o.literals == best.literals && o.key < best.key) {
			best = o
		}
	}
	if best != nil {
		return best, "policy"
	}
	return nil, "raw"
}

// sanitizePath implements section 4.2. It returns the full sanitized path
// (req.path) and the sanitized operation path (after the base segments).
func (r *run) sanitizePath(op *opT, rs *ruleSet, segs []segment, baseLen int, truncated bool, autoWords bool) (full, opPath string) {
	var b strings.Builder
	opStart := 0
	for i, sg := range segs {
		if i == baseLen {
			opStart = b.Len()
		}
		b.WriteByte('/')
		disc := ""
		if r.discOn {
			disc = "req.path." + itoa(i)
		}
		switch {
		case !sg.valid:
			b.WriteString("{drop:bytes}")
		case i < baseLen:
			b.Write(sg.dec)
		case op != nil && op.segs[i-baseLen].Param == "":
			b.WriteString(op.segs[i-baseLen].Literal)
		case op != nil:
			l := leaf{kind: leafStr, s: sg.dec}
			a := rs.lookup(rs.path, op.segs[i-baseLen].Param)
			if a != nil && (a.Kind == policy.ActKeep || a.Kind == policy.ActBucketTime) && !policy.ValidAllowSegment(string(sg.dec)) {
				// keep (and the source of a time: token) only for path-safe values.
				b.WriteString("{" + r.dropForm(&l).Str + "}")
				continue
			}
			out, def := r.applyLeaf(&l, a)
			if def {
				r.addDisc(disc, &l)
			}
			b.WriteString("{" + out.Str + "}")
		case r.e.allow[string(sg.dec)] || (autoWords && isAutoWord(sg.dec)):
			b.Write(sg.dec)
		default:
			l := leaf{kind: leafStr, s: sg.dec}
			r.addDisc(disc, &l)
			b.WriteString("{" + r.dropForm(&l).Str + "}")
		}
	}
	if len(segs) <= baseLen {
		opStart = b.Len()
	}
	if truncated {
		b.WriteString("/{trunc}")
	}
	full = b.String()
	opPath = full[opStart:]
	if full == "" {
		full = "/"
	}
	if opPath == "" {
		opPath = "/"
	}
	return full, opPath
}

// ---- outbound service selection (section 3.1, 3.5) ----

type urlBase struct {
	scheme, host, port string
	// ip6 is set for a bracketed IPv6 literal (spec v1.5); host is then
	// "[<address as written, lower case>]" and never equals a base.
	ip6   [16]byte
	isIP6 bool
	ok    bool
}

func (u urlBase) origin() string {
	o := u.scheme + "://" + u.host
	if u.port != "" {
		o += ":" + u.port
	}
	return o
}

func (u urlBase) hostPort() string {
	if u.port != "" {
		return u.host + ":" + u.port
	}
	return u.host
}

// pattern returns the host pattern of sanitizer.md 3.5 ("" when the host
// has an empty label: host:invalid).
func (u urlBase) pattern() string {
	if u.isIP6 {
		return hostpat.FromIPv6(u.ip6, u.port)
	}
	p, ok := hostpat.FromHost(u.host, u.port)
	if !ok {
		return ""
	}
	return p
}

// parseURLBase normalizes scheme://host[:port] (section 3.1): credentials,
// path, query or fragment make the host invalid; scheme and host are
// lower-cased; the port must be 1–65535 and is dropped when default; the
// host must match ^[a-z0-9.-]{1,253}$ (no IDNA) or be a bracketed IPv6
// literal (spec v1.5).
func parseURLBase(s string) urlBase {
	i := strings.Index(s, "://")
	if i < 1 {
		return urlBase{}
	}
	scheme := asciiLower(s[:i])
	for k := 0; k < len(scheme); k++ {
		c := scheme[k]
		if !(isLower(c) || (k > 0 && (isDigit(c) || c == '+' || c == '.' || c == '-'))) {
			return urlBase{}
		}
	}
	rest := s[i+3:]
	if strings.ContainsAny(rest, "@/?#") {
		return urlBase{}
	}
	u := urlBase{scheme: scheme}
	var port string
	hasPort := false
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return urlBase{}
		}
		addr := asciiLower(rest[1:end])
		a, ok := hostpat.ParseIPv6(addr)
		if !ok {
			return urlBase{}
		}
		u.host, u.ip6, u.isIP6 = "["+addr+"]", a, true
		switch after := rest[end+1:]; {
		case after == "":
		case after[0] == ':':
			port, hasPort = after[1:], true
		default:
			return urlBase{}
		}
	} else {
		var host string
		host, port, hasPort = strings.Cut(rest, ":")
		host = asciiLower(host)
		if len(host) < 1 || len(host) > hostpat.MaxHostLen {
			return urlBase{}
		}
		for k := 0; k < len(host); k++ {
			c := host[k]
			if !(isLower(c) || isDigit(c) || c == '.' || c == '-') {
				return urlBase{}
			}
		}
		u.host = host
	}
	if hasPort {
		p, ok := policy.NormalizePort(scheme, port)
		if !ok {
			return urlBase{}
		}
		u.port = p
	}
	u.ok = true
	return u
}

// chooseOutbound returns the matching service (most base segments) and the
// number of base segments, or nil and the host-derived service name: the
// host as listed in segments.hosts_allow, the host pattern (hosts.discovery
// auto, or discovery mode), or host:unlisted (strict mode).
func (e *Engine) chooseOutbound(ub urlBase, segs []segment, discOn bool) (*svcT, int, string) {
	if !ub.ok {
		return nil, 0, "host:invalid"
	}
	origin := ub.origin()
	for _, s := range e.bases {
		if s.origin != origin || len(s.base.Path) > len(segs) {
			continue
		}
		match := true
		for i, p := range s.base.Path {
			if !segs[i].valid || string(segs[i].dec) != p {
				match = false
				break
			}
		}
		if match {
			return s, len(s.base.Path), s.name
		}
	}
	if hp := ub.hostPort(); e.hostsAllow[hp] {
		return nil, 0, "host:" + hp
	}
	if e.p.Hosts.Auto() || discOn {
		if p := ub.pattern(); p != "" {
			return nil, 0, "host:" + p
		}
		return nil, 0, "host:invalid"
	}
	return nil, 0, "host:unlisted"
}
