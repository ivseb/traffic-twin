package sanitizer

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Input errors. Any error from Sanitize means: produce no event (the source
// counts it in sanitizer_errors).
var (
	ErrDirection   = errors.New("sanitizer: invalid direction")
	ErrServiceName = errors.New("sanitizer: invalid inbound service name")
	ErrNetError    = errors.New("sanitizer: invalid net_error")
	ErrSampledBy   = errors.New("sanitizer: invalid sampled_by")
)

var netErrors = map[string]bool{"timeout": true, "reset": true, "refused": true, "dns": true, "tls": true, "other": true}

// Capture runs the whole source pipeline after the policy and key checks:
// sampling (section 12), then sanitizing. When the exchange is not sampled
// it returns a nil Output and the decision. rnd returns a uniform integer in
// [0, 10000) for random sampling (nil uses math/rand/v2).
func (e *Engine) Capture(ex *Exchange, now time.Time, rnd func() int) (*Output, Decision, error) {
	d := e.Sample(ex, SampleOptions{RateBP: -1, Rand: rnd})
	if !d.Sampled {
		return nil, d, nil
	}
	out, err := e.Sanitize(ex, now, d.By)
	return out, d, err
}

// Sanitize applies the policy to one sampled exchange. It is pure and
// deterministic: the same exchange, policy, key, now and sampledBy always
// give the same output. now is the source clock, used only for the expiry
// of discovery and automatic path words (zero now ⇒ both off).
func (e *Engine) Sanitize(ex *Exchange, now time.Time, sampledBy SampledBy) (*Output, error) {
	if ex.Dir != Inbound && ex.Dir != Outbound {
		return nil, ErrDirection
	}
	if ex.NetError != "" && !netErrors[ex.NetError] {
		return nil, ErrNetError
	}
	switch sampledBy {
	case ByBaggage, BySubject, ByTrace, ByRandom, ByInherited:
	default:
		return nil, ErrSampledBy
	}
	r := &run{e: e, lim: e.p.Limits, discOn: e.p.DiscoveryActive(now)}
	if b := e.p.Bodies; b != nil {
		r.bodies, r.docs = *b, b.Docs
	}
	out := &Output{Dir: ex.Dir, SampledBy: sampledBy}

	method := normalizeMethod(ex.Method)
	segs, truncated := splitPath(ex.RawPath)
	reqH := normalizeHeaders(ex.ReqHeaders)

	var svc *svcT
	baseLen := 0
	switch ex.Dir {
	case Inbound:
		if !policy.ValidServiceName(ex.ServiceName) {
			return nil, ErrServiceName
		}
		out.Service = ex.ServiceName
		svc = e.byName[ex.ServiceName]
	case Outbound:
		svc, baseLen, out.Service = e.chooseOutbound(parseURLBase(ex.URLBase), segs, r.discOn)
	}
	route := ""
	if ex.Dir == Inbound {
		route = ex.FrameworkRoute
	}
	op, src := chooseOp(svc, method, ex.Framework, route, segs[baseLen:], truncated)
	out.RouteSource = src

	sd := e.global
	switch {
	case op != nil:
		sd = op.sides
	case svc != nil:
		sd = svc.sides
	}
	respRules := sd.resp
	if ex.NetError == "" && ex.Status >= 400 {
		respRules = sd.respErr
	}

	full, opPath := r.sanitizePath(op, sd.req, segs, baseLen, truncated, e.p.AutoWordsActive(now))
	if op != nil {
		out.Op = method + " " + op.template
	} else {
		out.Op = method + " " + opPath
	}

	// Request.
	req := ttjson.Obj(ttjson.Member{Key: "path", Value: ttjson.Str(full)})
	if ex.RawQuery != nil {
		if q, ok := r.urlencoded(ex.RawQuery, func(n string) *policy.Action { return sd.req.lookup(sd.req.query, n) }, "req.query", false); ok {
			req.Obj = append(req.Obj, ttjson.Member{Key: "query", Value: q})
		}
	}
	r.part(&req, "req", reqH, ex.ReqBody, ex.ReqBodyTotal, ex.ReqBodyNotConsumed, ex.ReqBodyDecoded, sd.req)
	out.Req = req

	// Response: ignored with net_error, even if the source passed parts.
	r.resp = true
	if ex.NetError == "" {
		resp := ttjson.Obj()
		r.part(&resp, "resp", normalizeHeaders(ex.RespHeaders), ex.RespBody, ex.RespBodyTotal, ex.RespBodyNotConsumed, ex.RespBodyDecoded, respRules)
		out.Resp = &resp
	}

	if subj, ok := extractSubject(e.p.Subject, reqH); ok {
		out.Subject = r.h().token(domainSubject, subj)
	}
	if r.discOn {
		out.Disc = r.finishDisc()
	}
	if err := limitOutput(out); err != nil {
		return nil, err
	}
	return out, nil
}

// limitOutput applies section 10.3 on the sanitizer output
// (A-EVENT-SIZE-BASE): over 512 KiB, req.body then resp.body become
// trunc:size, then disc is removed; still too large ⇒ ErrEventTooLarge.
func limitOutput(o *Output) error {
	fits := func() bool {
		b, err := o.Canonical()
		return err == nil && len(b) <= MaxEventBytes
	}
	if fits() {
		return nil
	}
	if replaceBodyIn(&o.Req) && fits() {
		return nil
	}
	if o.Resp != nil && replaceBodyIn(o.Resp) && fits() {
		return nil
	}
	if o.Disc != nil {
		o.Disc = nil
		if fits() {
			return nil
		}
	}
	return ErrEventTooLarge
}

func replaceBodyIn(part *ttjson.Value) bool {
	for j := range part.Obj {
		if part.Obj[j].Key == "body" {
			part.Obj[j].Value = tokTruncSize
			return true
		}
	}
	return false
}

// part fills headers, cookies, ct, size and body of one side, and, for
// XML and multipart bodies (spec v1.19), fmt and xmlns; for the request,
// soap_action (section 22.2 point 11).
func (r *run) part(o *ttjson.Value, side string, n *normHeaders, body []byte, total int64, notConsumed, decoded bool, rs *ruleSet) {
	if v, ok := r.headers(n, rs, side); ok {
		o.Obj = append(o.Obj, ttjson.Member{Key: "headers", Value: v})
	}
	if v, ok := r.cookies(n, rs, side); ok {
		o.Obj = append(o.Obj, ttjson.Member{Key: "cookies", Value: v})
	}
	ct, hasCT := contentType(n)
	if hasCT {
		o.Obj = append(o.Obj, ttjson.Member{Key: "ct", Value: ttjson.Str(ct)})
	}
	kind := r.treatment(ct, hasCT)
	if side == "req" && kind == treatXML {
		if sa, ok := soapAction(n); ok {
			o.Obj = append(o.Obj, ttjson.Member{Key: "soap_action", Value: ttjson.Str(sa)})
		}
	}
	ce, hasCE := contentField(n, "content-encoding")
	if hasCE && ce == "" {
		ce = "<empty>" // A-CE-EMPTY: an empty coding is unsupported
	}
	if r.resp && r.gqlGate() && r.lim.MaxArray < GraphQLIntrospectionMaxArray {
		// Section 5.7: an introspection result keeps its arrays.
		saved := r.lim.MaxArray
		r.lim.MaxArray = GraphQLIntrospectionMaxArray
		defer func() { r.lim.MaxArray = saved }()
	}
	res := r.body(body, total, notConsumed, decoded, ce, kind, n, rs, side)
	if res.size != "" {
		o.Obj = append(o.Obj, ttjson.Member{Key: "size", Value: ttjson.Str(res.size)})
	}
	if res.has {
		o.Obj = append(o.Obj, ttjson.Member{Key: "body", Value: res.body})
		// Section 22.1: fmt whenever a body leaves under the XML or
		// multipart treatment, also as a marker.
		switch {
		case res.fmt != "":
			o.Obj = append(o.Obj, ttjson.Member{Key: "fmt", Value: ttjson.Str(res.fmt)})
		case kind == treatXML:
			o.Obj = append(o.Obj, ttjson.Member{Key: "fmt", Value: ttjson.Str("xml")})
		case kind == treatMultipart:
			o.Obj = append(o.Obj, ttjson.Member{Key: "fmt", Value: ttjson.Str("multipart")})
		}
		if res.xmlns.Kind == ttjson.Object {
			o.Obj = append(o.Obj, ttjson.Member{Key: "xmlns", Value: res.xmlns})
		}
	}
}

// Body treatments (section 9.1).
const (
	treatNone = iota
	treatJSON
	treatForm
	treatXML
	treatMultipart
)

// treatment implements the table of section 9.1 (XML and multipart only
// with their bodies switch, spec v1.19).
func (r *run) treatment(ct string, hasCT bool) int {
	switch {
	case !hasCT:
		return treatNone
	case isJSONType(ct):
		return treatJSON
	case ct == "application/x-www-form-urlencoded":
		return treatForm
	case r.bodies.XML && (ct == "application/xml" || ct == "text/xml" || strings.HasSuffix(ct, "+xml")):
		return treatXML
	case r.bodies.Multipart && ct == "multipart/form-data":
		return treatMultipart
	}
	return treatNone
}

func isJSONType(ct string) bool {
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// errCapped reports a decompression that reached max_body_bytes + 1.
var errCapped = errors.New("decoded body over the limit")

// decode removes a single gzip or zlib (deflate) layer, stopping at
// limit+1 bytes of output (errCapped). A truncated stream or bytes after the
// end of the stream are errors (A-GZIP-STRICT).
func decode(b []byte, enc string, limit int64) ([]byte, error) {
	src := bytes.NewReader(b)
	var rd io.ReadCloser
	var err error
	switch enc {
	case "gzip", "x-gzip":
		var g *gzip.Reader
		if g, err = gzip.NewReader(src); err == nil {
			g.Multistream(false)
			rd = g
		}
	case "deflate":
		rd, err = zlib.NewReader(src)
	}
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	out, err := io.ReadAll(io.LimitReader(rd, limit+1))
	if int64(len(out)) > limit {
		return nil, errCapped
	}
	if err != nil {
		return nil, err
	}
	if src.Len() != 0 {
		return nil, errors.New("bytes after the compressed stream")
	}
	return out, nil
}

// bodyResult is the outcome of sections 9.0, 9.1 and 20 for one side.
type bodyResult struct {
	size  string // "" when size is absent
	body  ttjson.Value
	has   bool         // a body field is emitted
	fmt   string       // xml, soap11 or soap12 for a parsed XML body
	xmlns ttjson.Value // object, or the zero value when absent
}

// body implements sections 9.0, 9.1 and 20.
func (r *run) body(b []byte, total int64, notConsumed, decoded bool, ce string, kind int, n *normHeaders, rs *ruleSet, side string) bodyResult {
	// 1. Not consumed or unknown length.
	if notConsumed || total == UnknownLength {
		return bodyResult{size: LenClassUnknown, body: tokTruncSize, has: true}
	}
	if total == 0 || total < int64(len(b)) {
		total = int64(len(b))
	}
	// 2. Absent or empty.
	if total == 0 {
		return bodyResult{size: LenClass(0)}
	}
	// 3. Encoding. The decoding cap includes the large-body limit (22.5).
	limit := max(r.lim.MaxBodyBytes, r.bodies.MaxLargeBytes)
	switch ce {
	case "", "identity":
	case "gzip", "x-gzip", "deflate":
		if !decoded {
			out, err := decode(b, ce, limit)
			if errors.Is(err, errCapped) {
				return bodyResult{size: LenClassUnknown, body: tokTruncSize, has: true}
			}
			if err != nil {
				return bodyResult{body: tokDropBytes, has: true}
			}
			b, total = out, int64(len(out))
		}
	default:
		return bodyResult{body: tokDropBytes, has: true}
	}
	// 4. Size; a parsed body within bodies.max_large_body_bytes is analysed
	// in large-body mode (22.5).
	r.large = false
	if total > r.lim.MaxBodyBytes {
		if kind == treatNone || total > r.bodies.MaxLargeBytes {
			return bodyResult{size: LenClassUnknown, body: tokTruncSize, has: true}
		}
		r.large = true
	}
	size := LenClass(total)
	// 5. Treatment by content type.
	if ct, hasCT := contentType(n); hasCT && ct == "application/graphql" && int64(len(b)) == total {
		// Section 9.1 and 5.7 (v1.14): the whole body is one leaf under a graphql rule on $.
		if v, ok := r.graphqlBody(b, rs); ok {
			return bodyResult{size: size, body: v, has: true}
		}
	}
	if kind == treatNone {
		return bodyResult{size: size, body: ttjson.Str("drop:bytes:" + size), has: true}
	}
	if int64(len(b)) < total {
		// Only a prefix of a parsed body (a source should keep
		// CaptureLimit bytes): it cannot be analysed.
		return bodyResult{size: size, body: tokTruncSize, has: true}
	}
	prefix := side + ".body"
	res := bodyResult{size: size, has: true}
	switch kind {
	case treatForm:
		v, ok := r.urlencoded(b, func(n string) *policy.Action { return formRule(rs, n) }, prefix, true)
		if !ok {
			v = ttjson.Obj()
		}
		res.body = v
	case treatJSON:
		discMark := len(r.disc)
		v, err := r.jsonBody(b, rs, prefix)
		if err != nil {
			r.killDisc(discMark, len(r.disc))
			v = tokTruncJSON
		}
		res.body = v
	case treatXML:
		res.body, res.fmt, res.xmlns = r.xmlBody(b, rs, prefix)
	case treatMultipart:
		bnd, _ := n.get("content-type")
		res.body = r.multipartBody(b, bnd, rs, prefix)
	}
	return res
}

// formRule returns the winning body rule for a form field: only $.name and
// $.* can match (section 9.1).
func formRule(rs *ruleSet, name string) *policy.Action {
	for i := range rs.body {
		st := rs.body[i].steps
		if len(st) != 1 {
			continue
		}
		if st[0].Kind == policy.StepAnyMember || (st[0].Kind == policy.StepName && st[0].Name == name) {
			return rs.body[i].act
		}
	}
	return nil
}
