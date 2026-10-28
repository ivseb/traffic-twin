package intake

import (
	"strconv"
	"strings"
	"sync"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/hostpat"
)

// obsKind is the kind of a cardinality observation.
type obsKind uint8

const (
	obsKeep obsKind = iota + 1
	obsName
	obsSegment
	obsHost
	obsDisc
	// obsHostLabel: literal host labels per (registrable domain, position)
	// (event.md 5.2, spec v1.5). Added after obsDisc: kinds are stored as
	// integers in intake_sketch.
	obsHostLabel
)

type obsItem struct {
	kind obsKind
	off  int32
	n    int32
	val  uint64
}

// obsBuf collects the observations of one event: keys are written
// back-to-back in a byte buffer so that no per-observation string is
// allocated (lookups use m[string(key)], which does not allocate).
type obsBuf struct {
	keys  []byte
	items []obsItem
}

func (b *obsBuf) reset() {
	b.keys = b.keys[:0]
	b.items = b.items[:0]
}

func (b *obsBuf) emit(kind obsKind, start int, val uint64) {
	b.items = append(b.items, obsItem{kind: kind, off: int32(start), n: int32(len(b.keys) - start), val: val})
}

func (b *obsBuf) key(it obsItem) []byte { return b.keys[it.off : it.off+it.n] }

// checker verifies one event against its policy, the source identity and
// the rules of docs/spec/event.md 5.1. It is not safe for concurrent use;
// instances are pooled.
type checker struct {
	cfg *Config
	pol *Policy
	src *SourceInfo
	ev  *event.Event

	svc   *serviceRules
	op    *opRules
	opKey string

	obs   obsBuf
	steps []step
	stars int
	gs    groups
	// Current body (spec v1.19): XML tree (string leaves only, XML keys
	// allowed) and the longest array allowed.
	xml    bool
	maxArr int

	// prefix of the observation keys of the current part:
	// policy \0 service \0 op \0 part \0
	base   []byte
	prefix []byte

	rej Reject

	// GraphQL (sanitizer.md 5.7): resp is set while the response is
	// checked; gqlSeen and gqlNonIntro rebuild the introspection gate of the
	// source from the request values under a graphql rule.
	resp        bool
	gqlSeen     bool
	gqlNonIntro bool
}

var checkerPool = sync.Pool{New: func() any { return &checker{} }}

func (c *checker) fail(r Reason, detail string) bool {
	c.rej = Reject{Reason: r, Detail: detail}
	return false
}

// svcKey is the service component of observation keys: all host:<...>
// services share one key, so that rewriting a host pattern (a label to {*})
// never hides the keys of values observed under it.
func svcKey(service string) string {
	if strings.HasPrefix(service, "host:") {
		return "host:*"
	}
	return service
}

const rawOpKey = "(raw)"

// keySep separates the components of observation and quarantine keys. It
// cannot occur in any component (all are printable ASCII).
const keySep byte = 0x1f

// run performs every check. On success the observations are in c.obs.
func (c *checker) run() bool {
	ev, pol := c.ev, c.pol
	skew := c.cfg.ClockSkew
	c.obs.reset()
	c.rej = Reject{}

	if !pol.NotAfter.IsZero() && ev.Time.After(pol.NotAfter.Add(skew)) {
		return c.fail(ReasonPolicyTime, "event after policy not_after")
	}
	if !pol.CreatedAt.IsZero() && ev.Time.Before(pol.CreatedAt.Add(-skew)) {
		return c.fail(ReasonPolicyTime, "event before policy creation")
	}
	if !c.checkService() {
		return false
	}
	if ev.Subject != "" {
		if !pol.HasSubject {
			return c.fail(ReasonSubjectNotAllowed, "subject token but no identity.subject in policy")
		}
		kid, _, _ := event.SplitHMACToken(ev.Subject)
		if !pol.AcceptsKID(kid) {
			return c.fail(ReasonValueNotAllowed, "subject kid not accepted by policy")
		}
	}
	c.opKey = ev.Op
	if ev.RouteSource == event.RouteRaw {
		c.opKey = rawOpKey
	}
	if !c.checkRoute() {
		return false
	}
	// Prefix shared by all parts: policy \0 service \0 op \0
	c.base = c.base[:0]
	c.base = append(c.base, pol.ID...)
	c.base = append(c.base, keySep)
	c.base = append(c.base, svcKey(ev.Service)...)
	c.base = append(c.base, keySep)
	c.base = append(c.base, c.opKey...)
	c.base = append(c.base, keySep)

	// Request.
	c.resp, c.gqlSeen, c.gqlNonIntro = false, false, false
	r := &ev.Req
	c.gs = pol.groupsFor(c.svc, c.op, false, 0)
	if !c.checkNamed(partHeaders, "req.headers", r.Headers) ||
		!c.checkNamed(partCookies, "req.cookies", r.Cookies) ||
		!c.checkNamed(partQuery, "req.query", r.Query) ||
		!c.checkBodyPart("req", r.CT, r.Size, r.Fmt, r.XMLNS, r.Body) || !c.checkSoapAction(r) {
		return false
	}
	// Response.
	if ev.Resp != nil {
		c.resp = true
		c.gs = pol.groupsFor(c.svc, c.op, true, ev.Status)
		p := ev.Resp
		if !c.checkNamed(partHeaders, "resp.headers", p.Headers) ||
			!c.checkNamed(partCookies, "resp.cookies", p.Cookies) ||
			!c.checkBodyPart("resp", p.CT, p.Size, p.Fmt, p.XMLNS, p.Body) {
			return false
		}
	}
	if len(ev.Disc) > 0 {
		if !pol.DiscoveryActive(ev.Time, skew) {
			return c.fail(ReasonDiscNotAllowed, "disc present but discovery is not active")
		}
		// Discovery sketches are kept per operation as it left the source
		// (for a raw route: method + sanitized path, whose value segments
		// are already shapes) and per exact service: the policy assistant
		// groups them into operation templates (fleet.Assist). Their number
		// is bounded by MaxMonitors like every sketch.
		for _, d := range ev.Disc {
			start := len(c.obs.keys)
			c.obs.keys = append(c.obs.keys, pol.ID...)
			c.obs.keys = append(c.obs.keys, keySep)
			c.obs.keys = append(c.obs.keys, ev.Service...)
			c.obs.keys = append(c.obs.keys, keySep)
			c.obs.keys = append(c.obs.keys, ev.Op...)
			c.obs.keys = append(c.obs.keys, keySep)
			c.obs.keys = append(c.obs.keys, d.Path...)
			c.obs.emit(obsDisc, start, HashString(d.Token))
		}
	}
	return true
}

// checkService verifies identity-related fields: service allowed for the
// source group (inbound) or declared / listed (outbound).
func (c *checker) checkService() bool {
	ev, pol := c.ev, c.pol
	hostSvc := strings.HasPrefix(ev.Service, "host:")
	switch ev.Dir {
	case event.Inbound:
		if hostSvc {
			return c.fail(ReasonServiceNotAllowed, "inbound event with a host service")
		}
		if !c.src.AllowsService(ev.Service) {
			return c.fail(ReasonServiceNotAllowed, "service not allowed for the group of the source")
		}
		if c.src.ServiceName != "" && c.src.ServiceName != ev.Service {
			return c.fail(ReasonServiceNotAllowed, "service differs from the one assigned at enrollment")
		}
		if sv := pol.services[ev.Service]; sv != nil && sv.inbound {
			c.svc = sv
		}
	default:
		if hostSvc {
			if h, ok := event.IsHostService(ev.Service); ok {
				return c.checkHost(h)
			}
			return true
		}
		sv := pol.services[ev.Service]
		if sv == nil || sv.base == "" {
			return c.fail(ReasonServiceNotAllowed, "outbound service not declared by the policy")
		}
		c.svc = sv
	}
	return true
}

// checkHost accepts a host:<h> service (h neither unlisted nor invalid): a
// host listed in segments.hosts_allow, or a host pattern of
// docs/spec/sanitizer.md 3.5 while hosts.discovery is auto or discovery is
// active. The intake re-checks the safe-label rule of every literal label
// (a source that let a value through is rejected, not corrected) and
// observes the literal labels for the cardinality check of event.md 5.2:
// the distinct registrable domains per source (obsHost) and the distinct
// labels at each position left of the registrable domain (obsHostLabel).
func (c *checker) checkHost(h string) bool {
	pol := c.pol
	if _, listed := pol.HostsAllow[h]; listed {
		return true
	}
	if !pol.HostsAuto && !pol.DiscoveryActive(c.ev.Time, c.cfg.ClockSkew) {
		return c.fail(ReasonHostNotAllowed, "host not in segments.hosts_allow, hosts.discovery off and discovery not active")
	}
	if !hostpat.Valid(h) {
		return c.fail(ReasonHostNotAllowed, "host pattern with a label that is not safe (sanitizer.md 3.5)")
	}
	host, _ := hostpat.SplitPort(h)
	if hostpat.IsIP(host) {
		return true
	}
	labels, reg := hostpat.Registrable(host)
	domainStr := strings.Join(labels[reg:], ".")
	start := len(c.obs.keys)
	c.obs.keys = append(c.obs.keys, c.src.ID...)
	c.obs.emit(obsHost, start, HashString(domainStr))
	for p := 1; p <= reg; p++ {
		l := labels[reg-p]
		if l == hostpat.Star {
			continue
		}
		start := len(c.obs.keys)
		c.obs.keys = append(c.obs.keys, domainStr...)
		c.obs.keys = append(c.obs.keys, keySep)
		c.obs.keys = strconv.AppendInt(c.obs.keys, int64(p), 10)
		c.obs.emit(obsHostLabel, start, HashString(l))
	}
	return true
}

func autoWord(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	// ^([a-z]+([-_][a-z]+)*|v[0-9]{1,3})$
	if s[0] == 'v' && len(s) >= 2 && len(s) <= 4 {
		all := true
		for i := 1; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	prevSep := true // a word must start with a letter
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			prevSep = false
		case (ch == '-' || ch == '_') && !prevSep:
			prevSep = true
		default:
			return false
		}
	}
	return !prevSep
}

func (c *checker) segAllowed(seg string) bool {
	if _, ok := c.pol.SegmentsAllow[seg]; ok {
		return true
	}
	return c.pol.AutoWordsActive(c.ev.Time, c.cfg.ClockSkew) && autoWord(seg)
}

// checkRoute verifies op, route_source and req.path against the policy.
func (c *checker) checkRoute() bool {
	ev := c.ev
	method, opPath, _ := event.ParseOp(ev.Op)
	segs, _ := event.SplitPath(ev.Req.Path)
	var baseSegs []string
	if c.svc != nil && ev.Dir == event.Outbound {
		baseSegs = c.svc.baseSegs
	}
	n := len(baseSegs)
	if len(segs) < n {
		return c.fail(ReasonPathShape, "path shorter than the base of the service")
	}
	for i, b := range baseSegs {
		if !segs[i].Literal || segs[i].Raw != b {
			return c.fail(ReasonPathShape, "path does not start with the base of the service")
		}
	}
	rest := segs[n:]

	if ev.RouteSource != event.RouteRaw {
		if method == "OTHER" {
			return c.fail(ReasonOpUnknown, "OTHER method on a template route")
		}
		if c.svc == nil {
			return c.fail(ReasonOpUnknown, "template route for a service without rules")
		}
		op := c.svc.ops[ev.Op]
		if op == nil {
			return c.fail(ReasonOpUnknown, "operation not declared by the policy")
		}
		c.op = op
		if len(rest) != len(op.segs) {
			return c.fail(ReasonPathShape, "path length differs from the template")
		}
		for i, ts := range op.segs {
			s := rest[i]
			if ts.literal {
				if !s.Literal || s.Raw != ts.text {
					return c.fail(ReasonPathShape, "literal segment differs from the template")
				}
				continue
			}
			if s.Literal {
				return c.fail(ReasonPathShape, "parameter segment written as a literal")
			}
			if !c.checkPathParam(s.Inner, op.path[ts.text], n+i) {
				return false
			}
		}
		return true
	}

	// Raw route: op is METHOD + the sanitized path relative to the base.
	opSegs, ok := event.OpSegments(opPath)
	if !ok || len(opSegs) != len(rest) {
		return c.fail(ReasonPathShape, "raw op differs from the path")
	}
	for i, s := range rest {
		if opSegs[i].Raw != s.Raw {
			return c.fail(ReasonPathShape, "raw op differs from the path")
		}
		if s.Literal {
			if !c.segAllowed(s.Raw) {
				return c.fail(ReasonSegmentNotAllowed, "literal segment not allowed by the policy")
			}
			start := len(c.obs.keys)
			c.obs.keys = append(c.obs.keys, svcKey(ev.Service)...)
			c.obs.keys = append(c.obs.keys, keySep)
			c.obs.keys = append(c.obs.keys, method...)
			c.obs.keys = append(c.obs.keys, keySep)
			c.obs.keys = strconv.AppendInt(c.obs.keys, int64(i), 10)
			c.obs.emit(obsSegment, start, HashString(s.Raw))
			continue
		}
		if s.Inner != "trunc" && !strings.HasPrefix(s.Inner, "drop:") {
			return c.fail(ReasonValueNotAllowed, "value in a raw path segment")
		}
	}
	return true
}

// checkPathParam verifies a {token} at a template parameter position.
func (c *checker) checkPathParam(inner string, a *action, pos int) bool {
	switch {
	case strings.HasPrefix(inner, "drop:"):
		return true
	case strings.HasPrefix(inner, "keep:"):
		if d := c.keepDetail(inner, a); d != "" {
			return c.fail(ReasonValueNotAllowed, d)
		}
		start := len(c.obs.keys)
		c.obs.keys = append(c.obs.keys, c.pol.ID...)
		c.obs.keys = append(c.obs.keys, keySep)
		c.obs.keys = append(c.obs.keys, svcKey(c.ev.Service)...)
		c.obs.keys = append(c.obs.keys, keySep)
		c.obs.keys = append(c.obs.keys, c.opKey...)
		c.obs.keys = append(c.obs.keys, "\x1freq.path\x1fp"...)
		c.obs.keys = strconv.AppendInt(c.obs.keys, int64(pos), 10)
		c.obs.emit(obsKeep, start, HashString(inner[5:]))
		return true
	case strings.HasPrefix(inner, "tk1:"):
		if a == nil || a.kind != actHMAC {
			return c.fail(ReasonValueNotAllowed, "tk1 in a path parameter without hmac rule")
		}
		kid, _, _ := event.SplitHMACToken(inner)
		if !c.pol.AcceptsKID(kid) {
			return c.fail(ReasonValueNotAllowed, "tk1 kid not accepted by policy")
		}
		return true
	case strings.HasPrefix(inner, "time:"):
		if a == nil || a.kind != actBucketTime {
			return c.fail(ReasonValueNotAllowed, "time in a path parameter without bucket(time) rule")
		}
		if u, _ := event.TimeTokenUnit(inner); u != a.unit {
			return c.fail(ReasonValueNotAllowed, "time bucket of a different unit")
		}
		return true
	}
	return c.fail(ReasonValueNotAllowed, "token not allowed in a path parameter")
}

func (c *checker) setPrefix(part string) {
	c.prefix = append(c.prefix[:0], c.base...)
	c.prefix = append(c.prefix, part...)
	c.prefix = append(c.prefix, keySep)
}

// tokenDetail checks token tok against the action and returns "" if allowed,
// otherwise a static description of the violation. numOK is false for
// string-only parts (query, headers, cookies, forms), where bucket(num) never
// applies (sanitizer.md 8.3).
func (c *checker) tokenDetail(tok string, a *action, numOK bool) string {
	if len(tok) < 4 {
		return "malformed token"
	}
	switch tok[0] {
	case 'd':
		return "" // drop forms are always allowed
	case 'k':
		return c.keepDetail(tok, a)
	case 'g':
		return c.gqlDetail(tok, a)
	case 'n':
		if !numOK || a == nil || a.kind != actBucketNum {
			return "num without bucket(num) rule"
		}
		if _, ok := a.tokens[tok]; !ok {
			return "num bucket does not match the rule bounds"
		}
		return ""
	case 't':
		switch {
		case strings.HasPrefix(tok, "trunc:"):
			return ""
		case strings.HasPrefix(tok, "tk1:"):
			if a == nil || a.kind != actHMAC {
				return "tk1 without hmac rule"
			}
			kid, _, _ := event.SplitHMACToken(tok)
			if !c.pol.AcceptsKID(kid) {
				return "tk1 kid not accepted by policy"
			}
			return ""
		case strings.HasPrefix(tok, "time:"):
			if a == nil || a.kind != actBucketTime {
				return "time without bucket(time) rule"
			}
			if u, _ := event.TimeTokenUnit(tok); u != a.unit {
				return "time bucket of a different unit"
			}
			return ""
		}
	}
	return "token outside the grammar"
}

// checkNamed verifies a query, header or cookie map.
func (c *checker) checkNamed(part partID, partName string, m event.Multi) bool {
	if len(m) == 0 {
		return true
	}
	c.setPrefix(partName)
	maxVals := c.pol.Limits.MaxArray + 1
	for i := range m {
		en := &m[i]
		if en.Name == "{trunc}" {
			continue
		}
		if len(en.Values) > maxVals {
			return c.fail(ReasonLimits, "too many values for a name")
		}
		if part == partHeaders && en.Name != "{*}" && len(en.Values) != 1 {
			return c.fail(ReasonLimits, "a header has exactly one normalized value")
		}
		if en.Name == "{*}" {
			for _, tok := range en.Values {
				if tok[0] == 'd' || strings.HasPrefix(tok, "trunc:") {
					continue
				}
				if strings.HasPrefix(tok, "gql:") {
					return c.fail(ReasonValueNotAllowed, "gql under a collapsed name")
				}
				ok := c.gs.anyNamed(part, func(a *action) bool { return c.tokenDetail(tok, a, false) == "" })
				if !ok {
					return c.fail(ReasonValueNotAllowed, "value under {*} not allowed by any rule of the part")
				}
				if tok[0] == 'k' {
					c.observeKeepNamed("{*}", tok[5:])
				}
			}
			continue
		}
		// Literal name: cardinality of names per (service, op, part).
		start := len(c.obs.keys)
		c.obs.keys = append(c.obs.keys, c.prefix...)
		c.obs.emit(obsName, start, HashString(en.Name))

		act := c.gs.named(part, en.Name)
		for _, tok := range en.Values {
			if d := c.tokenDetail(tok, act, false); d != "" {
				return c.fail(ReasonValueNotAllowed, d)
			}
			c.gqlTrack(tok, act)
			if tok[0] == 'k' {
				c.observeKeepNamed(en.Name, tok[5:])
			}
		}
	}
	return true
}

func (c *checker) observeKeepNamed(name, value string) {
	start := len(c.obs.keys)
	c.obs.keys = append(c.obs.keys, c.prefix...)
	c.obs.keys = append(c.obs.keys, name...)
	c.obs.emit(obsKeep, start, HashString(value))
}

// checkBodyPart verifies the body of one side with its spec v1.19 fields:
// fmt only with a body, under the matching bodies switch and content type;
// xmlns only with an XML fmt. Events without fmt (sources before v1.19, or
// switches off) keep the v1.11 checks.
func (c *checker) checkBodyPart(side, ct, size, fmt string, xmlns []event.XMLNSEntry, b *event.Value) bool {
	c.xml = false
	c.maxArr = c.pol.maxArrayFor(size)
	switch {
	case fmt == "":
		if len(xmlns) > 0 {
			return c.fail(ReasonBodyShape, "xmlns without an XML body")
		}
	case b == nil:
		return c.fail(ReasonBodyShape, "fmt without a body")
	case event.IsXMLFmt(fmt):
		if !c.pol.Bodies.XML || !event.IsXMLContentType(ct) {
			return c.fail(ReasonBodyShape, "XML body without bodies.xml or an XML content type")
		}
		c.xml = true
	case fmt == event.FmtMultipart:
		if !c.pol.Bodies.Multipart || ct != event.CTMultipart || len(xmlns) > 0 {
			return c.fail(ReasonBodyShape, "multipart body without bodies.multipart or the multipart content type")
		}
	}
	if !c.checkBody(side+".body", ct, fmt, b) {
		return false
	}
	if len(xmlns) > 0 {
		if !c.xml {
			return c.fail(ReasonBodyShape, "xmlns without an XML body")
		}
		// Namespace patterns are structure: their cardinality is watched like names.
		c.setPrefix(side + ".xmlns")
		for _, e := range xmlns {
			if e.Path == "{trunc}" {
				continue
			}
			start := len(c.obs.keys)
			c.obs.keys = append(c.obs.keys, c.prefix...)
			c.obs.keys = append(c.obs.keys, e.Path...)
			c.obs.emit(obsName, start, HashString(e.Token))
		}
	}
	return true
}

// checkSoapAction verifies req.soap_action (sanitizer.md 22.2 point 11): only
// with bodies.xml and an XML request content type; a literal name is watched
// by the cardinality of names like a JSON key.
func (c *checker) checkSoapAction(r *event.Request) bool {
	if r.SoapAction == "" {
		return true
	}
	if !c.pol.Bodies.XML || !event.IsXMLContentType(r.CT) {
		return c.fail(ReasonBodyShape, "soap_action without bodies.xml or an XML content type")
	}
	if r.SoapAction != "{*}" {
		c.setPrefix("req.soap_action")
		start := len(c.obs.keys)
		c.obs.keys = append(c.obs.keys, c.prefix...)
		c.obs.emit(obsName, start, HashString(r.SoapAction))
	}
	return true
}

// checkBody verifies a body according to the content type and fmt.
func (c *checker) checkBody(part, ct, fmt string, b *event.Value) bool {
	if b == nil {
		return true
	}
	c.setPrefix(part)
	c.steps = c.steps[:0]
	c.stars = 0
	if b.Kind == event.String {
		k := event.ClassifyToken(b.S)
		switch b.S {
		case "trunc:invalid-xml":
			if !c.xml {
				return c.fail(ReasonBodyShape, "trunc:invalid-xml outside an XML body")
			}
		case "trunc:invalid-multipart":
			if fmt != event.FmtMultipart {
				return c.fail(ReasonBodyShape, "trunc:invalid-multipart outside a multipart body")
			}
		}
		if (event.IsJSONContentType(ct) || event.IsFormContentType(ct) || fmt != "") && (k == event.TokDrop || k == event.TokTrunc) {
			return true
		}
	}
	switch {
	case c.xml:
		return c.walkJSON(b, 1)
	case fmt == event.FmtMultipart:
		return c.walkForm(b)
	case event.IsJSONContentType(ct):
		return c.walkJSON(b, 1)
	case event.IsFormContentType(ct):
		if b.Kind == event.String {
			return c.markerOnly(b)
		}
		return c.walkForm(b)
	case ct == "application/graphql" && b.Kind == event.String && (strings.HasPrefix(b.S, "gql:") || c.rootGraphQL()):
		// sanitizer.md 9.1: one string leaf at $ under a graphql rule.
		return c.leaf(b)
	}
	return c.markerOnly(b)
}

// markerOnly accepts only drop and trunc tokens (bodies that the sanitizer
// does not parse: other content types, unsupported encodings).
func (c *checker) markerOnly(b *event.Value) bool {
	if b.Kind != event.String {
		return c.fail(ReasonBodyShape, "structured body for a content type that is not parsed")
	}
	if k := event.ClassifyToken(b.S); k != event.TokDrop && k != event.TokTrunc {
		return c.fail(ReasonBodyShape, "non-drop body token for a content type that is not parsed")
	}
	return true
}

func (c *checker) appendPath(dst []byte) []byte {
	dst = append(dst, '$')
	for _, s := range c.steps {
		switch s.kind {
		case stepName:
			dst = append(dst, '.')
			dst = append(dst, s.name...)
		case stepStar:
			dst = append(dst, '.', '*')
		default:
			dst = append(dst, '[', '*', ']')
		}
	}
	return dst
}

func (c *checker) walkJSON(v *event.Value, depth int) bool {
	lim := &c.pol.Limits
	switch v.Kind {
	case event.Array:
		if depth > lim.MaxDepth {
			return c.fail(ReasonLimits, "nesting deeper than max_depth")
		}
		if len(v.A) > max(c.maxArr, c.maxArray())+1 {
			return c.fail(ReasonLimits, "array longer than max_array")
		}
		c.steps = append(c.steps, step{kind: stepElem})
		for i := range v.A {
			if !c.walkJSON(&v.A[i], depth+1) {
				return false
			}
		}
		c.steps = c.steps[:len(c.steps)-1]
		return true
	case event.Object:
		if depth > lim.MaxDepth {
			return c.fail(ReasonLimits, "nesting deeper than max_depth")
		}
		if len(v.O) > lim.MaxKeys+2 {
			return c.fail(ReasonLimits, "object with more keys than max_keys")
		}
		for i := range v.O {
			m := &v.O[i]
			if !c.xml && event.IsXMLKey(m.K) {
				return c.fail(ReasonBodyShape, "XML key in a body that is not XML")
			}
			switch m.K {
			case "{trunc}":
				continue
			case "{*}":
				c.steps = append(c.steps, step{kind: stepStar})
				c.stars++
				for k := range m.V.A {
					if !c.walkJSON(&m.V.A[k], depth+1) {
						return false
					}
				}
				c.stars--
				c.steps = c.steps[:len(c.steps)-1]
				continue
			}
			// Literal name: cardinality of names per parent.
			start := len(c.obs.keys)
			c.obs.keys = append(c.obs.keys, c.prefix...)
			c.obs.keys = c.appendPath(c.obs.keys)
			c.obs.emit(obsName, start, HashString(m.K))

			c.steps = append(c.steps, step{kind: stepName, name: m.K})
			if !c.walkJSON(&m.V, depth+1) {
				return false
			}
			c.steps = c.steps[:len(c.steps)-1]
		}
		return true
	}
	return c.leaf(v)
}

func isKeepAction(a *action) bool { return a.kind == actKeep }

// codeShape is ^[A-Za-z_-]{2,32}$ (sanitizer.md 5.6). The intake keeps
// its own copy: it does not depend on the source-side policy package.
func codeShape(v string) bool {
	if len(v) < 2 || len(v) > 32 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// codeAlnumShape is ^[A-Za-z0-9_.-]{1,16}$ (sanitizer.md 5.6, spec v1.19).
func codeAlnumShape(v string) bool {
	if len(v) < 1 || len(v) > 16 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// keepDetail checks a keep: token against the action: a keep rule, or a
// code rule with a code-shaped value (sanitizer.md 5.6, spec v1.11); the
// value is never longer than keep_max_bytes. It returns "" if allowed.
func (c *checker) keepDetail(tok string, a *action) string {
	if !strings.HasPrefix(tok, "keep:") {
		return "malformed token"
	}
	switch {
	case a == nil:
		return "keep without keep rule"
	case a.kind == actKeep:
	case a.kind == actCode:
		if !codeShape(tok[5:]) {
			return "keep value under a code rule without the code shape"
		}
	case a.kind == actCodeAlnum:
		if !codeAlnumShape(tok[5:]) {
			return "keep value under a code(alnum) rule without the alnum code shape"
		}
	default:
		return "keep without keep rule"
	}
	if len(tok)-5 > c.pol.Limits.KeepMaxBytes {
		return "keep value longer than keep_max_bytes"
	}
	return ""
}

// leaf verifies a scalar body value.
func (c *checker) leaf(v *event.Value) bool {
	if c.stars == 0 && !c.resp {
		if a := c.gs.bodyAction(c.steps); a != nil && a.kind == actGraphQL {
			tok := ""
			if v.Kind == event.String {
				tok = v.S
			}
			c.gqlTrack(tok, a)
		}
	}
	if v.Kind == event.String && (v.S[0] == 'd' || strings.HasPrefix(v.S, "trunc:")) {
		return true
	}
	star := c.stars > 0
	var a *action
	if !star {
		a = c.gs.bodyAction(c.steps)
		if c.gs.containerDropped(c.steps) {
			return c.fail(ReasonValueNotAllowed, "value below a container collapsed by an explicit drop rule")
		}
	}
	var hv string
	switch v.Kind {
	case event.String:
		var ok bool
		if star && strings.HasPrefix(v.S, "gql:") {
			return c.fail(ReasonValueNotAllowed, "gql under a collapsed key")
		}
		if star {
			tok := v.S
			ok = c.gs.anyBodyAction(c.steps, func(a *action) bool { return c.tokenDetail(tok, a, !c.xml) == "" })
			if !ok {
				return c.fail(ReasonValueNotAllowed, "value under a collapsed key not allowed by any matching rule")
			}
		} else if d := c.tokenDetail(v.S, a, !c.xml); d != "" {
			return c.fail(ReasonValueNotAllowed, d)
		}
		if v.S[0] != 'k' {
			return true
		}
		hv = v.S[5:]
	default:
		ok := false
		if star {
			ok = c.gs.anyBodyAction(c.steps, isKeepAction)
		} else {
			ok = a != nil && a.kind == actKeep
		}
		if !ok {
			return c.fail(ReasonValueNotAllowed, "number, boolean or null without keep rule")
		}
		switch v.Kind {
		case event.Number:
			hv = v.S
		case event.Bool:
			hv = "true"
			if !v.B {
				hv = "false"
			}
		default:
			hv = "null"
		}
	}
	start := len(c.obs.keys)
	c.obs.keys = append(c.obs.keys, c.prefix...)
	c.obs.keys = c.appendPath(c.obs.keys)
	c.obs.emit(obsKeep, start, HashString(hv))
	return true
}

// walkForm verifies a form-encoded body: name -> [tokens]; only the rules
// $.name and $.* apply (sanitizer.md 9.1).
func (c *checker) walkForm(b *event.Value) bool {
	if b.Kind != event.Object {
		return c.fail(ReasonBodyShape, "form body is not a name map")
	}
	if len(b.O) > 66 {
		return c.fail(ReasonLimits, "too many form names")
	}
	for i := range b.O {
		m := &b.O[i]
		if m.K == "{trunc}" {
			continue
		}
		if m.V.Kind != event.Array {
			return c.fail(ReasonBodyShape, "form values are arrays of tokens")
		}
		if len(m.V.A) > c.maxArray()+1 {
			return c.fail(ReasonLimits, "too many values for a form name")
		}
		star := m.K == "{*}"
		if star {
			c.steps = append(c.steps[:0], step{kind: stepStar})
		} else {
			c.steps = append(c.steps[:0], step{kind: stepName, name: m.K})
			start := len(c.obs.keys)
			c.obs.keys = append(c.obs.keys, c.prefix...)
			c.obs.keys = append(c.obs.keys, '$')
			c.obs.emit(obsName, start, HashString(m.K))
		}
		var a *action
		if !star {
			a = c.gs.bodyAction(c.steps)
		}
		for k := range m.V.A {
			t := &m.V.A[k]
			if t.Kind != event.String {
				return c.fail(ReasonBodyShape, "form value is not a token")
			}
			if !star {
				c.gqlTrack(t.S, a)
			}
			if t.S[0] == 'd' || strings.HasPrefix(t.S, "trunc:") {
				continue
			}
			if star {
				if strings.HasPrefix(t.S, "gql:") {
					return c.fail(ReasonValueNotAllowed, "gql under a collapsed name")
				}
				tok := t.S
				if !c.gs.anyBodyAction(c.steps, func(a *action) bool { return c.tokenDetail(tok, a, false) == "" }) {
					return c.fail(ReasonValueNotAllowed, "form value under {*} not allowed by any rule")
				}
			} else if d := c.tokenDetail(t.S, a, false); d != "" {
				return c.fail(ReasonValueNotAllowed, d)
			}
			if t.S[0] == 'k' {
				start := len(c.obs.keys)
				c.obs.keys = append(c.obs.keys, c.prefix...)
				c.obs.keys = c.appendPath(c.obs.keys)
				c.obs.emit(obsKeep, start, HashString(t.S[5:]))
			}
		}
	}
	c.steps = c.steps[:0]
	return true
}
