package sanitizer

import (
	"bytes"
	"sort"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Direction of an exchange relative to the capturing service.
type Direction string

// Directions.
const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
)

// UnknownLength marks a body whose total length is unknown at the end of
// the exchange (section 9.0: body trunc:size, size lmax).
const UnknownLength int64 = -1

// Header is one header field as the source sees it.
type Header struct {
	Name  string
	Value []byte
}

// Exchange is the sanitizer input (section 1). Byte fields are never
// retained after Sanitize returns.
type Exchange struct {
	Dir         Direction
	ServiceName string // inbound: service name assigned at enrollment
	URLBase     string // outbound: scheme://host[:port]
	Method      string
	RawPath     []byte // not decoded, without query
	RawQuery    []byte // not decoded, without '?'; nil when the URL has no '?'
	// FrameworkRoute is the inbound route template including mount
	// prefixes (e.g. "/api/orders/:id"); empty when unknown (section 3.4).
	FrameworkRoute string
	// Framework identifies the route syntax of FrameworkRoute (section 3.4):
	// express, koa, fastify, flask, fastapi, django, spring, jaxrs,
	// aspnetcore, gin, chi, nethttp, laravel, symfony. Without it the
	// route is not used.
	Framework string
	// TraceID is the W3C trace id (32 lower-case hex) if known (section 12).
	TraceID string
	// Inherited is the sampling decision of the inbound exchange being
	// served, for outbound calls; nil without such a context.
	Inherited *bool

	ReqHeaders []Header
	ReqBody    []byte // the body or the kept prefix
	// ReqBodyTotal is the total length after de-chunking: 0 means
	// len(ReqBody), UnknownLength means unknown.
	ReqBodyTotal int64
	// ReqBodyNotConsumed is true when the app did not read the body.
	ReqBodyNotConsumed bool
	// ReqBodyDecoded is true when the runtime already removed the
	// content-encoding.
	ReqBodyDecoded bool

	Status   int    // 0 when absent (only with NetError)
	NetError string // timeout | reset | refused | dns | tls | other

	RespHeaders         []Header
	RespBody            []byte
	RespBodyTotal       int64
	RespBodyNotConsumed bool
	RespBodyDecoded     bool
}

// Output is the sanitizer output of section 2.
type Output struct {
	Dir         Direction
	Service     string
	Op          string
	RouteSource string        // framework | policy | raw
	SampledBy   SampledBy     // reason of the sampling decision
	Req         ttjson.Value  // object: path, query, headers, cookies, ct, soap_action, size, body, fmt, xmlns
	Resp        *ttjson.Value // nil with net_error
	Subject     string        // tk1 token; "" when absent
	Disc        []ttjson.Member
}

// Value returns the sanitizer output object compared by the conformance
// vectors (section 2, 16): disc, op, req, resp, route_source, sampled_by,
// service, subject; absent fields omitted.
func (o *Output) Value() ttjson.Value {
	v := ttjson.Obj(
		ttjson.Member{Key: "op", Value: ttjson.Str(o.Op)},
		ttjson.Member{Key: "req", Value: o.Req},
		ttjson.Member{Key: "route_source", Value: ttjson.Str(o.RouteSource)},
		ttjson.Member{Key: "sampled_by", Value: ttjson.Str(string(o.SampledBy))},
		ttjson.Member{Key: "service", Value: ttjson.Str(o.Service)},
	)
	if o.Resp != nil {
		v.Obj = append(v.Obj, ttjson.Member{Key: "resp", Value: *o.Resp})
	}
	if o.Subject != "" {
		v.Obj = append(v.Obj, ttjson.Member{Key: "subject", Value: ttjson.Str(o.Subject)})
	}
	if len(o.Disc) > 0 {
		v.Obj = append(v.Obj, ttjson.Member{Key: "disc", Value: ttjson.Obj(o.Disc...)})
	}
	return v
}

// Canonical returns the canonical JSON bytes of Value().
func (o *Output) Canonical() ([]byte, error) { return ttjson.Encode(o.Value()) }

// ---- per-call state ----

type discEntry struct {
	path string
	val  []byte
	dead bool
}

type run struct {
	e      *Engine
	lim    policy.Limits
	hh     *hasher
	discOn bool
	disc   []discEntry
	arena  []int32
	keyBuf []byte
	// Spec v1.19 (section 20): bodies switches of the policy, and the
	// large-body mode of the body being sanitized.
	bodies policy.Bodies
	docs   bool
	large  bool
	// arrLevel is the number of arrays among the ancestors of the value
	// being sanitized (section 22.5).
	arrLevel int
	// GraphQL (section 5.7): resp is set while the response is sanitized;
	// gqlSeen and gqlNonIntro record the request leaves with a graphql rule.
	resp        bool
	gqlSeen     bool
	gqlNonIntro bool
}

func (r *run) h() *hasher {
	if r.hh == nil {
		r.hh = newHasher(r.e.key, r.e.epoch)
	}
	return r.hh
}

func (r *run) addDisc(path string, l *leaf) {
	if !r.discOn {
		return
	}
	v, ok := canonicalRepr(l)
	if !ok {
		return
	}
	r.disc = append(r.disc, discEntry{path: path, val: append([]byte(nil), v...)})
}

// Limits of the disc object (section 15, event schema).
const (
	maxDiscEntries = 4096
	maxDiscKeyLen  = 256
	maxDiscSuffix  = 251 // "[.[]" + [!-~]{0,250}
)

// discPrefixLen returns the length of "(req|resp).(body|query|headers|cookies|path)".
func discPrefixLen(p string) int {
	for _, pre := range [...]string{"req.", "resp."} {
		if len(p) >= len(pre) && p[:len(pre)] == pre {
			rest := p[len(pre):]
			for _, part := range [...]string{"body", "query", "headers", "cookies", "path"} {
				if len(rest) >= len(part) && rest[:len(part)] == part {
					return len(pre) + len(part)
				}
			}
		}
	}
	return -1
}

// finishDisc reduces the entries to one token per path (the smallest value
// bytes win), omits paths that would not fit the event schema and keeps the
// maxDiscEntries smallest paths.
func (r *run) finishDisc() []ttjson.Member {
	best := map[string][]byte{}
	for i := range r.disc {
		d := &r.disc[i]
		if d.dead {
			continue
		}
		pl := discPrefixLen(d.path)
		if pl < 0 || len(d.path) > maxDiscKeyLen || len(d.path)-pl > maxDiscSuffix ||
			(len(d.path) > pl && d.path[pl] != '.' && d.path[pl] != '[') {
			continue
		}
		ok := true
		for k := 0; k < len(d.path); k++ {
			if d.path[k] < '!' || d.path[k] > '~' {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if cur, seen := best[d.path]; !seen || bytes.Compare(d.val, cur) < 0 {
			best[d.path] = d.val
		}
	}
	if len(best) == 0 {
		return nil
	}
	paths := make([]string, 0, len(best))
	for p := range best {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) > maxDiscEntries {
		paths = paths[:maxDiscEntries]
	}
	out := make([]ttjson.Member, 0, len(paths))
	for _, p := range paths {
		out = append(out, ttjson.Member{Key: p, Value: ttjson.Str(r.h().discToken(p, best[p]))})
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }
