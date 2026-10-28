package obi

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Span attribute names. The HTTP ones are the stable and the older
// OpenTelemetry semantic conventions; the header names follow the OBI header
// enrichment (http.request.header.<name>, http.response.header.<name>).
//
// The names of the body attributes are not documented by OBI at the time of
// writing: the adapter accepts the candidates below, in order, and the lab
// run must confirm which one the OBI release in use writes (README.md).
var (
	reqBodyAttrs  = []string{"http.request.body.content", "http.request.body"}
	respBodyAttrs = []string{"http.response.body.content", "http.response.body"}
	reqSizeAttrs  = []string{"http.request.body.size", "http.request_content_length"}
	respSizeAttrs = []string{"http.response.body.size", "http.response_content_length"}
)

const (
	reqHeaderPrefix  = "http.request.header."
	respHeaderPrefix = "http.response.header."
)

// MapOptions tunes Map.
type MapOptions struct {
	// ServiceName is the service name assigned at enrollment; inbound
	// exchanges are named after it (docs/spec/event.md section 1.2).
	ServiceName string
	// CaptureLimit is the OBI buffer size for HTTP payloads in bytes (0 =
	// unknown). A body that may have been cut at this size is reported to
	// the sanitizer as truncated.
	CaptureLimit int64
}

// Mapped is a span translated to the sanitizer input plus the event fields
// the sanitizer does not produce.
type Mapped struct {
	Exchange sanitizer.Exchange
	Start    time.Time
	Latency  time.Duration
	TraceID  string // 32 lower-case hex or ""
	SpanID   string // 16 lower-case hex or ""
	ParentID string
	// BodyBytes is the size of the captured bodies, for queue accounting.
	BodyBytes int64
}

type attrMap map[string]anyValue

func (a attrMap) str(names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := a[n]; ok {
			if s, ok := v.str(); ok {
				return s, true
			}
		}
	}
	return "", false
}

func (a attrMap) int(names ...string) (int64, bool) {
	for _, n := range names {
		if v, ok := a[n]; ok {
			if i, ok := v.int(); ok {
				return i, true
			}
		}
	}
	return 0, false
}

// IsHTTP reports whether the span is an HTTP server or client span.
func IsHTTP(sp *Span) bool {
	if sp.Kind != kindServer && sp.Kind != kindClient {
		return false
	}
	for i := range sp.Attributes {
		switch sp.Attributes[i].Key {
		case "http.request.method", "http.method":
			return true
		}
	}
	return false
}

// Map translates one HTTP span into the sanitizer input (docs/spec/sanitizer.md
// section 1). It returns false when the span does not describe an exchange
// (not HTTP, no method, neither a status nor an error). Map never fails
// open: whatever it cannot read is left out, and the sanitizer then falls
// back to the shape of the missing part.
func Map(sp *Span, o MapOptions) (*Mapped, bool) {
	if !IsHTTP(sp) {
		return nil, false
	}
	at := make(attrMap, len(sp.Attributes))
	for i := range sp.Attributes {
		at[sp.Attributes[i].Key] = sp.Attributes[i].Value
	}
	method, _ := at.str("http.request.method", "http.method")
	m := &Mapped{}
	ex := &m.Exchange
	ex.Method = method

	// Path and query.
	rawURL, _ := at.str("url.full", "http.url")
	var u *url.URL
	if rawURL != "" {
		if p, err := url.Parse(rawURL); err == nil {
			u = p
		}
	}
	path, hasPath := at.str("url.path")
	query, hasQuery := at.str("url.query")
	if !hasPath {
		if target, ok := at.str("http.target"); ok {
			p, q, hasQ := strings.Cut(target, "?")
			path, hasPath = p, true
			if hasQ && !hasQuery {
				query, hasQuery = q, true
			}
		}
	}
	if !hasPath && u != nil {
		path, hasPath = u.EscapedPath(), true
	}
	if !hasQuery && u != nil && (u.RawQuery != "" || u.ForceQuery) {
		query, hasQuery = u.RawQuery, true
	}
	if !hasPath || path == "" {
		path = "/"
	}
	ex.RawPath = []byte(path)
	if hasQuery && query != "" {
		ex.RawQuery = []byte(query)
	}

	if sp.Kind == kindServer {
		ex.Dir = sanitizer.Inbound
		ex.ServiceName = o.ServiceName
	} else {
		ex.Dir = sanitizer.Outbound
		ex.URLBase = urlBase(at, u)
	}

	// Status or transport error.
	if st, ok := at.int("http.response.status_code", "http.status_code"); ok && st >= 100 && st <= 599 {
		ex.Status = int(st)
	} else if sp.Status.Code == 2 || at["error.type"].StringValue != nil {
		ex.NetError = classifyError(at)
	} else {
		return nil, false // nothing to describe
	}

	// Headers.
	var reqCL, respCL int64 = -1, -1
	for i := range sp.Attributes {
		k := sp.Attributes[i].Key
		switch {
		case strings.HasPrefix(k, reqHeaderPrefix):
			name := strings.TrimPrefix(k, reqHeaderPrefix)
			for _, v := range sp.Attributes[i].Value.strs() {
				ex.ReqHeaders = append(ex.ReqHeaders, sanitizer.Header{Name: name, Value: []byte(v)})
				if name == "content-length" {
					reqCL = parseLen(v)
				}
			}
		case strings.HasPrefix(k, respHeaderPrefix):
			name := strings.TrimPrefix(k, respHeaderPrefix)
			for _, v := range sp.Attributes[i].Value.strs() {
				ex.RespHeaders = append(ex.RespHeaders, sanitizer.Header{Name: name, Value: []byte(v)})
				if name == "content-length" {
					respCL = parseLen(v)
				}
			}
		}
	}

	// Bodies.
	reqSize, ok := at.int(reqSizeAttrs...)
	if !ok {
		reqSize = reqCL
	}
	respSize, ok := at.int(respSizeAttrs...)
	if !ok {
		respSize = respCL
	}
	ex.ReqBody, ex.ReqBodyTotal, ex.ReqBodyDecoded = body(at, reqBodyAttrs, reqSize, ex.ReqHeaders, o.CaptureLimit)
	if ex.NetError == "" {
		ex.RespBody, ex.RespBodyTotal, ex.RespBodyDecoded = body(at, respBodyAttrs, respSize, ex.RespHeaders, o.CaptureLimit)
	}
	m.BodyBytes = int64(len(ex.ReqBody) + len(ex.RespBody))

	// Time, trace context.
	if sp.StartNano <= 0 {
		return nil, false
	}
	m.Start = time.Unix(0, int64(sp.StartNano)).UTC()
	if sp.EndNano > sp.StartNano {
		m.Latency = time.Duration(sp.EndNano - sp.StartNano)
	}
	m.TraceID = normID(sp.TraceID, 16)
	m.SpanID = normID(sp.SpanID, 8)
	m.ParentID = normID(sp.ParentSpanID, 8)
	if allZero(m.TraceID) {
		m.TraceID = ""
	}
	if allZero(m.SpanID) {
		m.SpanID = ""
	}
	if allZero(m.ParentID) {
		m.ParentID = ""
	}
	ex.TraceID = m.TraceID
	return m, true
}

// body picks the captured body of one side and works out the length the
// sanitizer must be told (section 9.0):
//
//   - the size is known and larger than the capture buffer: the body was
//     cut, the total is the real size (JSON then becomes trunc:size);
//   - the size is known and fits the buffer: the captured text is the whole
//     body even when OBI obfuscation made it shorter than the original;
//   - the size is unknown and the text fills the buffer: it may have been
//     cut, so the length is unknown (trunc:size);
//   - no body attribute but a known size: only the shape is available.
func body(at attrMap, names []string, size int64, hdrs []sanitizer.Header, limit int64) (b []byte, total int64, decoded bool) {
	s, has := at.str(names...)
	if has {
		b = []byte(s)
	}
	switch {
	case size > 0 && limit > 0 && size > limit:
		total = size
	case size > 0 && !has:
		total = size
	case size < 0 && has && limit > 0 && int64(len(b)) >= limit:
		total = sanitizer.UnknownLength
	}
	if has && len(b) > 0 {
		// The body travels as text in a span attribute: if the exchange
		// declares a content-encoding, OBI decoded it already unless the
		// bytes still look like a compressed stream.
		for _, h := range hdrs {
			if h.Name == "content-encoding" && !looksCompressed(b) {
				decoded = true
			}
		}
	}
	return b, total, decoded
}

func looksCompressed(b []byte) bool {
	return len(b) >= 2 && ((b[0] == 0x1f && b[1] == 0x8b) || (b[0] == 0x78 && (b[1] == 0x01 || b[1] == 0x5e || b[1] == 0x9c || b[1] == 0xda)))
}

func parseLen(v string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// urlBase builds scheme://host[:port] of a client span.
func urlBase(at attrMap, u *url.URL) string {
	scheme, host, port := "", "", ""
	if u != nil && u.Host != "" {
		scheme, host, port = u.Scheme, u.Hostname(), u.Port()
	}
	if v, ok := at.str("url.scheme"); ok && scheme == "" {
		scheme = v
	}
	if v, ok := at.str("server.address", "net.peer.name", "http.host"); ok && host == "" {
		host = v
		// http.host may carry the port.
		if h, p, ok := strings.Cut(v, ":"); ok && !strings.Contains(p, ":") {
			host, port = h, p
		}
	}
	if v, ok := at.int("server.port", "net.peer.port"); ok && port == "" && v > 0 && v < 65536 {
		port = strconv.FormatInt(v, 10)
	}
	if host == "" {
		return "" // the sanitizer reports host:invalid
	}
	if scheme == "" {
		// OBI hooks the TLS libraries before encryption and may not
		// know the scheme: the conventional port decides.
		scheme = "http"
		if port == "443" {
			scheme = "https"
		}
	}
	if port != "" {
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

// classifyError maps error.type to the net_error vocabulary.
func classifyError(at attrMap) string {
	e, _ := at.str("error.type")
	e = strings.ToLower(e)
	switch {
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline"):
		return "timeout"
	case strings.Contains(e, "refused"):
		return "refused"
	case strings.Contains(e, "reset"):
		return "reset"
	case strings.Contains(e, "dns") || strings.Contains(e, "no such host"):
		return "dns"
	case strings.Contains(e, "tls") || strings.Contains(e, "x509") || strings.Contains(e, "certificate"):
		return "tls"
	}
	return "other"
}

// normID returns n bytes of an id as lower-case hex: OTLP/JSON requires hex,
// some exporters write base64. Anything else gives "".
func normID(s string, n int) string {
	if s == "" {
		return ""
	}
	if len(s) == 2*n {
		if b, err := hex.DecodeString(s); err == nil && len(b) == n {
			return hex.EncodeToString(b)
		}
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == n {
		return hex.EncodeToString(b)
	}
	return ""
}

func allZero(h string) bool {
	if h == "" {
		return false
	}
	return strings.Trim(h, "0") == ""
}
