package event

import (
	"strconv"
	"strings"
	"time"
)

// Schema is the value of the schema field.
const Schema = "tt.http.exchange/v1"

// Direction values.
const (
	Inbound  = "inbound"
	Outbound = "outbound"
)

// Route sources.
const (
	RouteFramework = "framework"
	RoutePolicy    = "policy"
	RouteRaw       = "raw"
)

// MaxEventBytes is the largest canonical event (docs/spec/sanitizer.md 10.3).
const MaxEventBytes = 512 * 1024

// MaxDiscPaths is the largest number of entries in disc.
const MaxDiscPaths = 4096

// PolicyRef identifies the compiled policy used by the source.
type PolicyRef struct {
	ID      string
	Version int64
	Hash    string
}

// SourceRef identifies the capture source.
type SourceRef struct {
	Kind    string
	Version string
	ID      string
}

// MultiEntry is one name of a query, header or cookie map.
type MultiEntry struct {
	Name   string
	Values []string // tokens
}

// Multi is a name to tokens map, sorted by name. A nil Multi means "absent";
// an empty non-nil Multi is not a valid event (empty maps are omitted).
type Multi []MultiEntry

// Get returns the tokens of name.
func (m Multi) Get(name string) ([]string, bool) {
	for i := range m {
		if m[i].Name == name {
			return m[i].Values, true
		}
	}
	return nil, false
}

// Body formats of the fmt field (docs/spec/sanitizer.md 22.1, spec v1.19).
const (
	FmtXML       = "xml"
	FmtSOAP11    = "soap11"
	FmtSOAP12    = "soap12"
	FmtMultipart = "multipart"
)

// XMLNSEntry is one entry of the xmlns field: tt-path of an element to the
// ns: pattern of its namespace, or {trunc} to a trunc:keys marker
// (docs/spec/sanitizer.md 22.2 point 9, spec v1.19).
type XMLNSEntry struct {
	Path  string
	Token string
}

// Request is the req part of an event.
type Request struct {
	Path    string
	Query   Multi
	Headers Multi
	Cookies Multi
	CT      string // "" when absent
	Size    string // "" when absent
	Body    *Value // nil when absent
	// Spec v1.19 (sanitizer.md 22): body format, XML namespaces and the
	// SOAP operation name; zero values when absent (older sources).
	Fmt        string
	XMLNS      []XMLNSEntry
	SoapAction string
}

// Response is the resp part of an event.
type Response struct {
	Headers Multi
	Cookies Multi
	CT      string
	Size    string
	Body    *Value
	Fmt     string       // spec v1.19
	XMLNS   []XMLNSEntry // spec v1.19
}

// IsXMLFmt reports whether f is one of the XML formats (xml, soap11, soap12).
func IsXMLFmt(f string) bool { return f == FmtXML || f == FmtSOAP11 || f == FmtSOAP12 }

// DiscEntry is one entry of the disc field (path to short token).
type DiscEntry struct {
	Path  string
	Token string
}

// Event is a decoded tt.http.exchange/v1 event. Fields that are optional in
// the schema use their zero value for "absent" (a valid value is never the
// zero value: status >= 100, tokens are non-empty).
type Event struct {
	Policy       PolicyRef
	Source       SourceRef
	TS           string
	Time         time.Time // TS parsed, UTC
	LatencyMS    int64
	Dir          string
	Service      string
	Op           string
	RouteSource  string
	Status       int
	NetError     string
	Subject      string
	SampledBy    string
	TraceID      string
	SpanID       string
	ParentSpanID string
	Req          Request
	Resp         *Response
	Disc         []DiscEntry
}

// Decode parses the exact canonical bytes of an event and validates them
// against the event schema and the token grammar. Any deviation is an error:
// see the package documentation.
func Decode(b []byte) (*Event, *DecodeError) {
	v, err := ParseCanonical(b)
	if err != nil {
		return nil, err
	}
	return FromValue(v)
}

// ---------------------------------------------------------------------------

const (
	fSchema = 1 << iota
	fPolicy
	fSource
	fTS
	fLatency
	fDir
	fService
	fOp
	fRoute
	fSampled
	fReq
	fStatus
	fNetError
	fSubject
	fTrace
	fSpan
	fParent
	fResp
	fDisc
)

const fRequired = fSchema | fPolicy | fSource | fTS | fLatency | fDir | fService | fOp | fRoute | fSampled | fReq

// FromValue maps a parsed (canonical) JSON document to an Event.
func FromValue(v Value) (*Event, *DecodeError) {
	if v.Kind != Object {
		return nil, schemaErr("event is not an object")
	}
	e := &Event{}
	var seen uint32
	for i := range v.O {
		m := &v.O[i]
		var err *DecodeError
		switch m.K {
		case "schema":
			seen |= fSchema
			if m.V.Kind != String || m.V.S != Schema {
				err = schemaErr("schema")
			}
		case "policy":
			seen |= fPolicy
			err = decodePolicy(&m.V, &e.Policy)
		case "source":
			seen |= fSource
			err = decodeSource(&m.V, &e.Source)
		case "ts":
			seen |= fTS
			var ok bool
			if e.Time, ok = parseTS(&m.V); !ok {
				err = schemaErr("ts")
			}
			e.TS = m.V.S
		case "latency_ms":
			seen |= fLatency
			n, ok := intOf(&m.V)
			if !ok || n < 0 {
				err = schemaErr("latency_ms")
			}
			e.LatencyMS = n
		case "dir":
			seen |= fDir
			if m.V.Kind != String || (m.V.S != Inbound && m.V.S != Outbound) {
				err = schemaErr("dir")
			}
			e.Dir = m.V.S
		case "service":
			seen |= fService
			if m.V.Kind != String || !ValidServiceRef(m.V.S) {
				err = schemaErr("service")
			}
			e.Service = m.V.S
		case "op":
			seen |= fOp
			if m.V.Kind != String || !ValidOp(m.V.S) {
				err = schemaErr("op")
			}
			e.Op = m.V.S
		case "route_source":
			seen |= fRoute
			if m.V.Kind != String || (m.V.S != RouteFramework && m.V.S != RoutePolicy && m.V.S != RouteRaw) {
				err = schemaErr("route_source")
			}
			e.RouteSource = m.V.S
		case "status":
			seen |= fStatus
			n, ok := intOf(&m.V)
			if !ok || n < 100 || n > 599 {
				err = schemaErr("status")
			}
			e.Status = int(n)
		case "net_error":
			seen |= fNetError
			switch m.V.S {
			case "timeout", "reset", "refused", "dns", "tls", "other":
			default:
				err = schemaErr("net_error")
			}
			if m.V.Kind != String {
				err = schemaErr("net_error")
			}
			e.NetError = m.V.S
		case "subject":
			seen |= fSubject
			if m.V.Kind != String || !ValidHMACToken(m.V.S) {
				err = schemaErr("subject")
			}
			e.Subject = m.V.S
		case "sampled_by":
			seen |= fSampled
			switch m.V.S {
			case "baggage", "subject", "trace", "random", "inherited":
			default:
				err = schemaErr("sampled_by")
			}
			if m.V.Kind != String {
				err = schemaErr("sampled_by")
			}
			e.SampledBy = m.V.S
		case "trace_id":
			seen |= fTrace
			if m.V.Kind != String || !lowerHex(m.V.S, 32) {
				err = schemaErr("trace_id")
			}
			e.TraceID = m.V.S
		case "span_id":
			seen |= fSpan
			if m.V.Kind != String || !lowerHex(m.V.S, 16) {
				err = schemaErr("span_id")
			}
			e.SpanID = m.V.S
		case "parent_span_id":
			seen |= fParent
			if m.V.Kind != String || !lowerHex(m.V.S, 16) {
				err = schemaErr("parent_span_id")
			}
			e.ParentSpanID = m.V.S
		case "req":
			seen |= fReq
			err = decodeReq(&m.V, &e.Req)
		case "resp":
			seen |= fResp
			e.Resp = &Response{}
			err = decodeResp(&m.V, e.Resp)
		case "disc":
			seen |= fDisc
			err = decodeDisc(&m.V, e)
		default:
			err = schemaErr("unknown field")
		}
		if err != nil {
			return nil, err
		}
	}
	if seen&fRequired != fRequired {
		return nil, schemaErr("missing required field")
	}
	if seen&fNetError != 0 {
		if seen&(fStatus|fResp) != 0 {
			return nil, schemaErr("net_error with status or resp")
		}
	} else if seen&fStatus == 0 {
		return nil, schemaErr("status missing")
	}
	return e, nil
}

func parseTS(v *Value) (time.Time, bool) {
	s := v.S
	if v.Kind != String || len(s) != 24 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != '.' || s[23] != 'Z' {
		return time.Time{}, false
	}
	if !digitsAt(s, 0, 4) || !digitsAt(s, 5, 2) || !digitsAt(s, 8, 2) || !digitsAt(s, 11, 2) || !digitsAt(s, 14, 2) || !digitsAt(s, 17, 2) || !digitsAt(s, 20, 3) {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func intOf(v *Value) (int64, bool) {
	if v.Kind != Number {
		return 0, false
	}
	n, err := strconv.ParseInt(v.S, 10, 64)
	return n, err == nil
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validPolicyID(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || (i > 0 && c == '-')
		if !ok {
			return false
		}
	}
	return true
}

func decodePolicy(v *Value, p *PolicyRef) *DecodeError {
	if v.Kind != Object || len(v.O) != 3 {
		return schemaErr("policy")
	}
	// Sorted keys: hash, id, version.
	h, i, ver := &v.O[0], &v.O[1], &v.O[2]
	if h.K != "hash" || i.K != "id" || ver.K != "version" {
		return schemaErr("policy fields")
	}
	if h.V.Kind != String || !ValidPolicyHash(h.V.S) {
		return schemaErr("policy.hash")
	}
	if i.V.Kind != String || !validPolicyID(i.V.S) {
		return schemaErr("policy.id")
	}
	n, ok := intOf(&ver.V)
	if !ok || n < 1 {
		return schemaErr("policy.version")
	}
	*p = PolicyRef{ID: i.V.S, Version: n, Hash: h.V.S}
	return nil
}

// ValidPolicyHash reports whether s is sha256:<64 lowercase hex>.
func ValidPolicyHash(s string) bool {
	r, ok := strings.CutPrefix(s, "sha256:")
	return ok && lowerHex(r, 64)
}

var sourceKinds = map[string]bool{
	"sdk-node": true, "sdk-python": true, "sdk-java": true, "sdk-dotnet": true, "sdk-go": true,
	"sdk-php": true, "egress": true, "obi": true, "import-har": true, "import-otlp": true,
}

func decodeSource(v *Value, s *SourceRef) *DecodeError {
	if v.Kind != Object || len(v.O) != 3 {
		return schemaErr("source")
	}
	// Sorted keys: id, kind, version.
	id, kind, ver := &v.O[0], &v.O[1], &v.O[2]
	if id.K != "id" || kind.K != "kind" || ver.K != "version" {
		return schemaErr("source fields")
	}
	if id.V.Kind != String || !ValidSourceID(id.V.S) {
		return schemaErr("source.id")
	}
	if kind.V.Kind != String || !sourceKinds[kind.V.S] {
		return schemaErr("source.kind")
	}
	if ver.V.Kind != String || !ValidSemver(ver.V.S) {
		return schemaErr("source.version")
	}
	*s = SourceRef{Kind: kind.V.S, Version: ver.V.S, ID: id.V.S}
	return nil
}

// ValidSourceID reports whether s matches ^src-[0-9A-Za-z]{1,32}$.
func ValidSourceID(s string) bool {
	r, ok := strings.CutPrefix(s, "src-")
	if !ok || len(r) < 1 || len(r) > 32 {
		return false
	}
	for i := 0; i < len(r); i++ {
		if !(isAlpha(r[i]) || isDigit(r[i])) {
			return false
		}
	}
	return true
}

// ValidSemver reports whether s matches the schema semver pattern.
func ValidSemver(s string) bool {
	if len(s) > 64 {
		return false
	}
	i := 0
	for part := 0; part < 3; part++ {
		st := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i == st {
			return false
		}
		if part < 2 {
			if i >= len(s) || s[i] != '.' {
				return false
			}
			i++
		}
	}
	if i == len(s) {
		return true
	}
	if s[i] != '-' && s[i] != '+' {
		return false
	}
	i++
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if !(isAlpha(c) || isDigit(c) || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// MaxServiceRef is maxLength of $defs/serviceRef: "host:" plus the
// longest host pattern (127 labels {*}) plus ":65535".
const MaxServiceRef = 518

// ValidServiceRef reports whether s matches $defs/serviceRef: a service
// name, host:invalid, host:unlisted, a listed host[:port] or a host pattern
// (docs/spec/sanitizer.md 3.5, spec v1.5). Whether a pattern's literal
// labels pass the safe-label rule is checked by the intake (package
// hostpat), not by the schema.
func ValidServiceRef(s string) bool {
	if len(s) > MaxServiceRef {
		return false
	}
	if h, ok := strings.CutPrefix(s, "host:"); ok {
		if h == "invalid" || h == "unlisted" {
			return true
		}
		return ValidHostPort(h) || ValidHostPattern(h)
	}
	return ValidServiceName(s)
}

// ValidHostPattern reports whether s (without "host:") matches the pattern
// alternatives of $defs/serviceRef:
// ({*}|[a-z0-9-]{1,63})(.({*}|[a-z0-9-]{1,63})){0,126}(:port)? or
// ip:(private|public)(:port)?, the port 1-65535.
func ValidHostPattern(s string) bool {
	host := s
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		port := s[i+1:]
		if len(port) >= 1 && len(port) <= 5 && digitsAt(port, 0, len(port)) {
			n, _ := strconv.Atoi(port)
			if n < 1 || n > 65535 {
				return false
			}
			host = s[:i]
		}
	}
	if host == "ip:private" || host == "ip:public" {
		return true
	}
	labels := 0
	for start := 0; start <= len(host); {
		end := strings.IndexByte(host[start:], '.')
		if end < 0 {
			end = len(host)
		} else {
			end += start
		}
		l := host[start:end]
		labels++
		if labels > 127 {
			return false
		}
		if l != "{*}" {
			if len(l) < 1 || len(l) > 63 {
				return false
			}
			for i := 0; i < len(l); i++ {
				c := l[i]
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
		start = end + 1
	}
	return true
}

// ValidServiceName reports whether s matches ^[a-z0-9][a-z0-9._-]{0,62}$.
func ValidServiceName(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if i > 0 {
			ok = ok || c == '.' || c == '_' || c == '-'
		}
		if !ok {
			return false
		}
	}
	return true
}

// ValidHostPort reports whether s matches ^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$
// (the port, when present, must also be 1-65535).
func ValidHostPort(s string) bool {
	host := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		host = s[:i]
		port := s[i+1:]
		if len(port) < 1 || len(port) > 5 || !digitsAt(port, 0, len(port)) {
			return false
		}
		n, _ := strconv.Atoi(port)
		if n < 1 || n > 65535 {
			return false
		}
	}
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// ValidOp reports whether s matches the op pattern of the schema:
// METHOD SP /printable-ASCII, METHOD = [A-Z]{1,16} or OTHER.
func ValidOp(s string) bool {
	if len(s) > 2100 {
		return false
	}
	sp := strings.IndexByte(s, ' ')
	if sp < 1 || sp > 16 || sp+1 >= len(s) || s[sp+1] != '/' {
		return false
	}
	for i := 0; i < sp; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	for i := sp + 1; i < len(s); i++ {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

func decodeReq(v *Value, r *Request) *DecodeError {
	if v.Kind != Object || len(v.O) == 0 {
		return schemaErr("req")
	}
	havePath := false
	for i := range v.O {
		m := &v.O[i]
		var err *DecodeError
		switch m.K {
		case "path":
			havePath = true
			if m.V.Kind != String || !ValidPath(m.V.S) {
				err = schemaErr("req.path")
			}
			r.Path = m.V.S
		case "query":
			r.Query, err = decodeMulti(&m.V, partQuery, "req.query")
		case "headers":
			r.Headers, err = decodeMulti(&m.V, partHeaders, "req.headers")
		case "cookies":
			r.Cookies, err = decodeMulti(&m.V, partCookies, "req.cookies")
		case "ct":
			r.CT, err = decodeCT(&m.V)
		case "size":
			r.Size, err = decodeSize(&m.V)
		case "body":
			r.Body, err = decodeBody(&m.V)
		case "fmt":
			r.Fmt, err = decodeFmt(&m.V)
		case "xmlns":
			r.XMLNS, err = decodeXMLNS(&m.V)
		case "soap_action":
			if m.V.Kind != String || !ValidSoapAction(m.V.S) {
				err = schemaErr("req.soap_action")
			}
			r.SoapAction = m.V.S
		default:
			err = schemaErr("req: unknown field")
		}
		if err != nil {
			return err
		}
	}
	if !havePath {
		return schemaErr("req.path missing")
	}
	return nil
}

func decodeResp(v *Value, r *Response) *DecodeError {
	if v.Kind != Object || len(v.O) == 0 {
		return schemaErr("resp")
	}
	for i := range v.O {
		m := &v.O[i]
		var err *DecodeError
		switch m.K {
		case "headers":
			r.Headers, err = decodeMulti(&m.V, partHeaders, "resp.headers")
		case "cookies":
			r.Cookies, err = decodeMulti(&m.V, partCookies, "resp.cookies")
		case "ct":
			r.CT, err = decodeCT(&m.V)
		case "size":
			r.Size, err = decodeSize(&m.V)
		case "body":
			r.Body, err = decodeBody(&m.V)
		case "fmt":
			r.Fmt, err = decodeFmt(&m.V)
		case "xmlns":
			r.XMLNS, err = decodeXMLNS(&m.V)
		default:
			err = schemaErr("resp: unknown field")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeFmt(v *Value) (string, *DecodeError) {
	if v.Kind != String {
		return "", schemaErr("fmt")
	}
	switch v.S {
	case FmtXML, FmtSOAP11, FmtSOAP12, FmtMultipart:
		return v.S, nil
	}
	return "", schemaErr("fmt")
}

// ValidSoapAction reports whether s is a soap_action value: {*} or a name
// that follows the name rule (sanitizer.md 9.3 point 3, 22.2 point 11).
func ValidSoapAction(s string) bool { return s == "{*}" || (validKeyName(s) && !DynamicName(s)) }

// MaxXMLNSEntries is the largest number of xmlns entries (64 and {trunc}).
const MaxXMLNSEntries = 65

func decodeXMLNS(v *Value) ([]XMLNSEntry, *DecodeError) {
	if v.Kind != Object || len(v.O) == 0 || len(v.O) > MaxXMLNSEntries {
		return nil, schemaErr("xmlns")
	}
	out := make([]XMLNSEntry, len(v.O))
	for i := range v.O {
		m := &v.O[i]
		if m.V.Kind != String {
			return nil, schemaErr("xmlns value")
		}
		if m.K == "{trunc}" {
			if !strings.HasPrefix(m.V.S, "trunc:keys:") || !ValidTrunc(m.V.S) {
				return nil, schemaErr("xmlns {trunc}")
			}
		} else if !ValidXMLNSPath(m.K) || !ValidNSToken(m.V.S) {
			return nil, schemaErr("xmlns entry")
		}
		out[i] = XMLNSEntry{Path: m.K, Token: m.V.S}
	}
	return out, nil
}

// ValidXMLNSPath reports whether k is the tt-path of an element in an XML
// body: $ then steps .name (a literal key) or .*, each optionally followed
// by [*] (sanitizer.md 22.2 point 9).
func ValidXMLNSPath(k string) bool {
	if len(k) < 2 || len(k) > 4300 || k[0] != '$' {
		return false
	}
	i := 1
	for i < len(k) {
		if k[i] != '.' {
			return false
		}
		j := i + 1
		if strings.HasPrefix(k[j:], "*") {
			j++
		} else {
			e := j
			for e < len(k) && k[e] != '.' && k[e] != '[' {
				e++
			}
			name := k[j:e]
			if !validKeyName(name) || DynamicName(name) {
				return false
			}
			j = e
		}
		if strings.HasPrefix(k[j:], "[*]") {
			j += 3
		}
		i = j
	}
	return true
}

// ValidNSToken reports whether s is an ns: pattern (sanitizer.md 22.2
// point 9): ns:{none}, ns:{*}, or ns: + at most 1600 printable ASCII bytes
// without @, { and } except the {*} placeholders, every [A-Za-z0-9_-] run of
// at most 64 bytes, without six consecutive digits or twelve consecutive hex
// characters. The run rule is checked again here, in zone B.
func ValidNSToken(s string) bool {
	rest, ok := strings.CutPrefix(s, "ns:")
	if !ok || rest == "" || len(rest) > 1600 {
		return false
	}
	if rest == "{none}" || rest == "{*}" {
		return true
	}
	run := 0
	digits, hexes := 0, 0
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c == '{' {
			if !strings.HasPrefix(rest[i:], "{*}") {
				return false
			}
			i += 2
			run, digits, hexes = 0, 0, 0
			continue
		}
		if c < 0x21 || c > 0x7e || c == '@' || c == '}' {
			return false
		}
		word := isAlpha(c) || isDigit(c) || c == '_' || c == '-'
		if !word {
			run, digits, hexes = 0, 0, 0
			continue
		}
		run++
		if isDigit(c) {
			digits++
		} else {
			digits = 0
		}
		if isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexes++
		} else {
			hexes = 0
		}
		if run > 64 || digits >= 6 || hexes >= 12 {
			return false
		}
	}
	return true
}

func decodeCT(v *Value) (string, *DecodeError) {
	if v.Kind != String || !ValidContentType(v.S) {
		return "", schemaErr("ct")
	}
	return v.S, nil
}

// ValidContentType reports whether s matches $defs/contentType.
func ValidContentType(s string) bool {
	if s == "invalid" {
		return true
	}
	i := strings.IndexByte(s, '/')
	if i < 1 || i > 64 || len(s)-i-1 < 1 || len(s)-i-1 > 64 {
		return false
	}
	for k := 0; k < len(s); k++ {
		if k == i {
			continue
		}
		c := s[k]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

func decodeSize(v *Value) (string, *DecodeError) {
	if v.Kind != String || !ValidLenClass(v.S) {
		return "", schemaErr("size")
	}
	return v.S, nil
}

func decodeBody(v *Value) (*Value, *DecodeError) {
	if err := validateBody(v); err != nil {
		return nil, err
	}
	b := *v
	return &b, nil
}

func validateBody(v *Value) *DecodeError {
	switch v.Kind {
	case String:
		if ClassifyToken(v.S) == TokInvalid {
			return schemaErr("body: string outside the token grammar")
		}
	case Number:
		if !NumberWithinLimits(v.S) {
			return schemaErr("body: number out of limits")
		}
	case Array:
		for i := range v.A {
			if err := validateBody(&v.A[i]); err != nil {
				return err
			}
		}
	case Object:
		for i := range v.O {
			m := &v.O[i]
			if !ValidBodyKey(m.K) {
				return schemaErr("body: key outside the name grammar")
			}
			switch m.K {
			case "{trunc}":
				if m.V.Kind != String || !strings.HasPrefix(m.V.S, "trunc:keys:") || !ValidTrunc(m.V.S) {
					return schemaErr("body: {trunc} value")
				}
				continue
			case "{*}":
				if m.V.Kind != Array || len(m.V.A) == 0 {
					return schemaErr("body: {*} value")
				}
			}
			if err := validateBody(&m.V); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidBodyKey reports whether k may appear as an object key of a body:
// {*}, {trunc}, or a literal key that respects the name rule of the sanitizer
// (character set of the schema and not a "dynamic" name, section 9.3).
func ValidBodyKey(k string) bool {
	if k == "{*}" || k == "{trunc}" || k == XMLTextKey {
		return true
	}
	if a, ok := strings.CutPrefix(k, "@"); ok {
		return validKeyName(a) && !DynamicName(a)
	}
	return validKeyName(k) && !DynamicName(k)
}

// XMLTextKey is the member of an XML element with attributes or children
// that holds its text (sanitizer.md 22.2 point 7, spec v1.19).
const XMLTextKey = "#text"

// IsXMLKey reports whether k can only come from an XML body: #text or an
// attribute key @name.
func IsXMLKey(k string) bool { return k == XMLTextKey || strings.HasPrefix(k, "@") }

// validKeyName reports whether k matches ^[A-Za-z_][A-Za-z0-9_.-]{0,63}$.
func validKeyName(k string) bool {
	if len(k) < 1 || len(k) > 64 {
		return false
	}
	c := k[0]
	if !(isAlpha(c) || c == '_') {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !(isAlpha(c) || isDigit(c) || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

type partKind uint8

const (
	partQuery partKind = iota
	partHeaders
	partCookies
)

func validHeaderName(k string) bool {
	if len(k) < 1 || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+.^_`|~-", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// ValidHeaderName reports whether k may appear literally as a header name of
// an event: lowercase token characters, not a dynamic name.
func ValidHeaderName(k string) bool { return validHeaderName(k) && !DynamicName(k) }

// ValidQueryName reports whether k may appear literally as a query or cookie
// name.
func ValidQueryName(k string) bool { return validKeyName(k) && !DynamicName(k) }

func decodeMulti(v *Value, part partKind, _ string) (Multi, *DecodeError) {
	if v.Kind != Object || len(v.O) == 0 || len(v.O) > 65 {
		return nil, schemaErr("name map")
	}
	out := make(Multi, len(v.O))
	for i := range v.O {
		m := &v.O[i]
		switch m.K {
		case "{*}", "{trunc}":
		default:
			ok := false
			if part == partHeaders {
				ok = ValidHeaderName(m.K)
			} else {
				ok = ValidQueryName(m.K)
			}
			if !ok {
				return nil, schemaErr("name map: name outside the name grammar")
			}
		}
		if m.V.Kind != Array || len(m.V.A) == 0 || len(m.V.A) > 1025 {
			return nil, schemaErr("name map: values")
		}
		toks := make([]string, len(m.V.A))
		for k := range m.V.A {
			t := &m.V.A[k]
			if t.Kind != String || ClassifyToken(t.S) == TokInvalid {
				return nil, schemaErr("name map: token")
			}
			toks[k] = t.S
		}
		if m.K == "{trunc}" && (len(toks) != 1 || !strings.HasPrefix(toks[0], "trunc:keys:") || ClassifyToken(toks[0]) != TokTrunc) {
			return nil, schemaErr("name map: {trunc} value")
		}
		out[i] = MultiEntry{Name: m.K, Values: toks}
	}
	return out, nil
}

func decodeDisc(v *Value, e *Event) *DecodeError {
	if v.Kind != Object || len(v.O) == 0 || len(v.O) > MaxDiscPaths {
		return schemaErr("disc")
	}
	e.Disc = make([]DiscEntry, len(v.O))
	for i := range v.O {
		m := &v.O[i]
		if !ValidDiscPath(m.K) || m.V.Kind != String || !ValidDiscToken(m.V.S) {
			return schemaErr("disc entry")
		}
		e.Disc[i] = DiscEntry{Path: m.K, Token: m.V.S}
	}
	return nil
}

// ValidDiscPath reports whether k matches the disc key pattern:
// ^(req|resp)\.(body|query|headers|cookies|path)([.\[][!-~]{0,250})?$ with
// at most 256 characters.
func ValidDiscPath(k string) bool {
	if len(k) > 256 {
		return false
	}
	rest, ok := strings.CutPrefix(k, "req.")
	if !ok {
		rest, ok = strings.CutPrefix(k, "resp.")
		if !ok {
			return false
		}
	}
	for _, p := range [...]string{"body", "query", "headers", "cookies", "path"} {
		if t, ok := strings.CutPrefix(rest, p); ok {
			if t == "" {
				return true
			}
			if t[0] != '.' && t[0] != '[' {
				return false
			}
			for i := 1; i < len(t); i++ {
				if t[i] < '!' || t[i] > '~' {
					return false
				}
			}
			return len(t)-1 <= 250
		}
	}
	return false
}
