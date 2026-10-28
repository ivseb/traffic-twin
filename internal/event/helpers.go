package event

import (
	"strconv"
	"strings"
)

// WalkBody calls fn for every leaf (string token, number, boolean, null) of a
// body tree with its tt-path ("$.items[*].sku": members as .name, collapsed
// {*} members as .*, array elements as [*]; the values collected under {*}
// are visited at the path of the {*} member itself). The {trunc} marker and
// trunc: markers are leaves too: callers that only care about data filter
// them with [ClassifyToken]. The root scalar has path "$".
func WalkBody(v *Value, fn func(path string, leaf *Value)) {
	walkBody(v, "$", fn)
}

func walkBody(v *Value, path string, fn func(string, *Value)) {
	switch v.Kind {
	case Array:
		p := path + "[*]"
		for i := range v.A {
			walkBody(&v.A[i], p, fn)
		}
	case Object:
		for i := range v.O {
			m := &v.O[i]
			switch m.K {
			case "{*}":
				p := path + ".*"
				// Values collected under {*}: an array of values, each at p.
				if m.V.Kind == Array {
					for k := range m.V.A {
						walkBody(&m.V.A[k], p, fn)
					}
				} else {
					walkBody(&m.V, p, fn)
				}
			case "{trunc}":
				fn(path+".{trunc}", &m.V)
			default:
				walkBody(&m.V, path+"."+m.K, fn)
			}
		}
	default:
		fn(path, v)
	}
}

// Side names the side of an exchange.
type Side string

// Sides.
const (
	SideReq  Side = "req"
	SideResp Side = "resp"
)

// HMACToken is a tk1 token with the place where it appeared.
type HMACToken struct {
	// Where identifies the field: "subject", "req.path[2]" (segment index
	// in req.path), "req.query.<name>", "req.headers.<name>",
	// "req.cookies.<name>", "req.body$.items[*].id", and the same for resp.
	Where string
	Token string
}

// HMACTokens calls fn for every tk1 token of the event (subject, path
// parameters, query, headers, cookies and bodies), in a deterministic order.
func (e *Event) HMACTokens(fn func(HMACToken)) {
	if e.Subject != "" {
		fn(HMACToken{"subject", e.Subject})
	}
	if segs, ok := SplitPath(e.Req.Path); ok {
		for i, s := range segs {
			if !s.Literal && strings.HasPrefix(s.Inner, "tk1:") {
				fn(HMACToken{"req.path[" + strconv.Itoa(i) + "]", s.Inner})
			}
		}
	}
	multi := func(side Side, part string, m Multi) {
		for _, en := range m {
			for _, t := range en.Values {
				if strings.HasPrefix(t, "tk1:") {
					fn(HMACToken{string(side) + "." + part + "." + en.Name, t})
				}
			}
		}
	}
	body := func(side Side, b *Value) {
		if b == nil {
			return
		}
		WalkBody(b, func(p string, l *Value) {
			if l.Kind == String && strings.HasPrefix(l.S, "tk1:") {
				fn(HMACToken{string(side) + ".body" + p, l.S})
			}
		})
	}
	multi(SideReq, "query", e.Req.Query)
	multi(SideReq, "headers", e.Req.Headers)
	multi(SideReq, "cookies", e.Req.Cookies)
	body(SideReq, e.Req.Body)
	if e.Resp != nil {
		multi(SideResp, "headers", e.Resp.Headers)
		multi(SideResp, "cookies", e.Resp.Cookies)
		body(SideResp, e.Resp.Body)
	}
}

// IsError reports whether the exchange ended in a network error or a status
// of 400 or more.
func (e *Event) IsError() bool { return e.NetError != "" || e.Status >= 400 }

// StatusClass returns 2 for 2xx, 4 for 4xx and so on, 0 without status.
func (e *Event) StatusClass() int { return e.Status / 100 }

// OpMethod returns the method of e.Op.
func (e *Event) OpMethod() string {
	if i := strings.IndexByte(e.Op, ' '); i > 0 {
		return e.Op[:i]
	}
	return ""
}

// OpPath returns the path template (or sanitized path) of e.Op.
func (e *Event) OpPath() string {
	if i := strings.IndexByte(e.Op, ' '); i > 0 {
		return e.Op[i+1:]
	}
	return ""
}

// IsHostService reports whether service is host:<name> (not unlisted or
// invalid) and returns the host: a listed host[:port] or a host pattern
// (docs/spec/sanitizer.md 3.5).
func IsHostService(service string) (string, bool) {
	h, ok := strings.CutPrefix(service, "host:")
	if !ok || h == "unlisted" || h == "invalid" {
		return "", false
	}
	return h, true
}

// IsJSONContentType reports whether ct selects JSON body handling
// (docs/spec/sanitizer.md 9.1).
func IsJSONContentType(ct string) bool {
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// IsFormContentType reports whether ct is application/x-www-form-urlencoded.
func IsFormContentType(ct string) bool { return ct == "application/x-www-form-urlencoded" }

// CTMultipart is the multipart content type parsed with bodies.multipart
// (docs/spec/sanitizer.md 22.3, spec v1.19).
const CTMultipart = "multipart/form-data"

// IsXMLContentType reports the content types parsed as XML with bodies.xml
// (docs/spec/sanitizer.md 9.1, 22.2): application/xml, text/xml, *+xml.
func IsXMLContentType(ct string) bool {
	return ct == "application/xml" || ct == "text/xml" || strings.HasSuffix(ct, "+xml")
}
