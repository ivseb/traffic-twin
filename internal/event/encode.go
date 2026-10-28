package event

import "strconv"

// AppendCanonical appends the canonical (tt-cjson) encoding of e, including
// the disc field when present. For an event returned by [Decode] the result
// equals the decoded bytes.
func (e *Event) AppendCanonical(dst []byte) []byte { return e.appendCanonical(dst, true) }

// AppendCanonicalNoDisc is like AppendCanonical but omits disc, which the
// intake never stores (docs/spec/event.md 5.3).
func (e *Event) AppendCanonicalNoDisc(dst []byte) []byte { return e.appendCanonical(dst, false) }

// Canonical returns the canonical bytes of e.
func (e *Event) Canonical() []byte { return e.AppendCanonical(make([]byte, 0, 1024)) }

// key writes ,"name": (without the comma for the first member).
func key(dst []byte, first *bool, name string) []byte {
	if *first {
		*first = false
	} else {
		dst = append(dst, ',')
	}
	dst = append(dst, '"')
	dst = append(dst, name...)
	return append(dst, '"', ':')
}

func (e *Event) appendCanonical(dst []byte, withDisc bool) []byte {
	first := true
	dst = append(dst, '{')
	dst = key(dst, &first, "dir")
	dst = AppendString(dst, e.Dir)
	if withDisc && len(e.Disc) > 0 {
		dst = key(dst, &first, "disc")
		dst = append(dst, '{')
		for i, d := range e.Disc {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = AppendString(dst, d.Path)
			dst = append(dst, ':')
			dst = AppendString(dst, d.Token)
		}
		dst = append(dst, '}')
	}
	dst = key(dst, &first, "latency_ms")
	dst = strconv.AppendInt(dst, e.LatencyMS, 10)
	if e.NetError != "" {
		dst = key(dst, &first, "net_error")
		dst = AppendString(dst, e.NetError)
	}
	dst = key(dst, &first, "op")
	dst = AppendString(dst, e.Op)
	if e.ParentSpanID != "" {
		dst = key(dst, &first, "parent_span_id")
		dst = AppendString(dst, e.ParentSpanID)
	}
	dst = key(dst, &first, "policy")
	dst = append(dst, `{"hash":`...)
	dst = AppendString(dst, e.Policy.Hash)
	dst = append(dst, `,"id":`...)
	dst = AppendString(dst, e.Policy.ID)
	dst = append(dst, `,"version":`...)
	dst = strconv.AppendInt(dst, e.Policy.Version, 10)
	dst = append(dst, '}')
	dst = key(dst, &first, "req")
	dst = e.Req.appendCanonical(dst)
	if e.Resp != nil {
		dst = key(dst, &first, "resp")
		dst = e.Resp.appendCanonical(dst)
	}
	dst = key(dst, &first, "route_source")
	dst = AppendString(dst, e.RouteSource)
	dst = key(dst, &first, "sampled_by")
	dst = AppendString(dst, e.SampledBy)
	dst = key(dst, &first, "schema")
	dst = AppendString(dst, Schema)
	dst = key(dst, &first, "service")
	dst = AppendString(dst, e.Service)
	dst = key(dst, &first, "source")
	dst = append(dst, `{"id":`...)
	dst = AppendString(dst, e.Source.ID)
	dst = append(dst, `,"kind":`...)
	dst = AppendString(dst, e.Source.Kind)
	dst = append(dst, `,"version":`...)
	dst = AppendString(dst, e.Source.Version)
	dst = append(dst, '}')
	if e.SpanID != "" {
		dst = key(dst, &first, "span_id")
		dst = AppendString(dst, e.SpanID)
	}
	if e.Status != 0 {
		dst = key(dst, &first, "status")
		dst = strconv.AppendInt(dst, int64(e.Status), 10)
	}
	if e.Subject != "" {
		dst = key(dst, &first, "subject")
		dst = AppendString(dst, e.Subject)
	}
	if e.TraceID != "" {
		dst = key(dst, &first, "trace_id")
		dst = AppendString(dst, e.TraceID)
	}
	dst = key(dst, &first, "ts")
	dst = AppendString(dst, e.TS)
	return append(dst, '}')
}

func (m Multi) appendCanonical(dst []byte) []byte {
	dst = append(dst, '{')
	for i, en := range m {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = AppendString(dst, en.Name)
		dst = append(dst, ':', '[')
		for k, t := range en.Values {
			if k > 0 {
				dst = append(dst, ',')
			}
			dst = AppendString(dst, t)
		}
		dst = append(dst, ']')
	}
	return append(dst, '}')
}

func (r *Request) appendCanonical(dst []byte) []byte {
	first := true
	dst = append(dst, '{')
	if r.Body != nil {
		dst = key(dst, &first, "body")
		dst = r.Body.AppendCanonical(dst)
	}
	if len(r.Cookies) > 0 {
		dst = key(dst, &first, "cookies")
		dst = r.Cookies.appendCanonical(dst)
	}
	if r.CT != "" {
		dst = key(dst, &first, "ct")
		dst = AppendString(dst, r.CT)
	}
	if r.Fmt != "" {
		dst = key(dst, &first, "fmt")
		dst = AppendString(dst, r.Fmt)
	}
	if len(r.Headers) > 0 {
		dst = key(dst, &first, "headers")
		dst = r.Headers.appendCanonical(dst)
	}
	dst = key(dst, &first, "path")
	dst = AppendString(dst, r.Path)
	if len(r.Query) > 0 {
		dst = key(dst, &first, "query")
		dst = r.Query.appendCanonical(dst)
	}
	if r.Size != "" {
		dst = key(dst, &first, "size")
		dst = AppendString(dst, r.Size)
	}
	if r.SoapAction != "" {
		dst = key(dst, &first, "soap_action")
		dst = AppendString(dst, r.SoapAction)
	}
	if len(r.XMLNS) > 0 {
		dst = key(dst, &first, "xmlns")
		dst = appendXMLNS(dst, r.XMLNS)
	}
	return append(dst, '}')
}

func appendXMLNS(dst []byte, es []XMLNSEntry) []byte {
	dst = append(dst, '{')
	for i, e := range es {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = AppendString(dst, e.Path)
		dst = append(dst, ':')
		dst = AppendString(dst, e.Token)
	}
	return append(dst, '}')
}

func (r *Response) appendCanonical(dst []byte) []byte {
	first := true
	dst = append(dst, '{')
	if r.Body != nil {
		dst = key(dst, &first, "body")
		dst = r.Body.AppendCanonical(dst)
	}
	if len(r.Cookies) > 0 {
		dst = key(dst, &first, "cookies")
		dst = r.Cookies.appendCanonical(dst)
	}
	if r.CT != "" {
		dst = key(dst, &first, "ct")
		dst = AppendString(dst, r.CT)
	}
	if r.Fmt != "" {
		dst = key(dst, &first, "fmt")
		dst = AppendString(dst, r.Fmt)
	}
	if len(r.Headers) > 0 {
		dst = key(dst, &first, "headers")
		dst = r.Headers.appendCanonical(dst)
	}
	if r.Size != "" {
		dst = key(dst, &first, "size")
		dst = AppendString(dst, r.Size)
	}
	if len(r.XMLNS) > 0 {
		dst = key(dst, &first, "xmlns")
		dst = appendXMLNS(dst, r.XMLNS)
	}
	return append(dst, '}')
}
