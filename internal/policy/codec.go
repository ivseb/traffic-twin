package policy

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// ErrInvalid wraps every validation failure of a policy document.
var ErrInvalid = errors.New("policy: invalid")

// ErrUnsafe marks a body that is valid but breaks the source-side safety
// subset (hardening.md 2.1, H1 to H3). It also wraps ErrInvalid. Sources
// report it as the heartbeat error code policy_unsafe.
var ErrUnsafe = errors.New("policy: unsafe")

// CodeUnsafe is the last_errors code of a policy refused for ErrUnsafe.
const CodeUnsafe = "policy_unsafe"

func unsafef(format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalid, ErrUnsafe, fmt.Sprintf(format, a...))
}

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// fields checks that v is an object whose keys are all in allowed and
// returns them as a map.
func fields(v ttjson.Value, where string, allowed ...string) (map[string]ttjson.Value, error) {
	if v.Kind != ttjson.Object {
		return nil, invalidf("%s: expected object", where)
	}
	m := make(map[string]ttjson.Value, len(v.Obj))
	for _, mem := range v.Obj {
		ok := false
		for _, a := range allowed {
			if a == mem.Key {
				ok = true
				break
			}
		}
		if !ok {
			return nil, invalidf("%s: unknown field %q", where, mem.Key)
		}
		m[mem.Key] = mem.Value
	}
	return m, nil
}

func require(m map[string]ttjson.Value, where string, keys ...string) error {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return invalidf("%s: missing %q", where, k)
		}
	}
	return nil
}

func str(v ttjson.Value, where string) (string, error) {
	if v.Kind != ttjson.String {
		return "", invalidf("%s: expected string", where)
	}
	return v.Str, nil
}

func boolean(v ttjson.Value, where string) (bool, error) {
	if v.Kind != ttjson.Bool {
		return false, invalidf("%s: expected boolean", where)
	}
	return v.Bool, nil
}

// integer accepts only integer lexemes that fit in int64.
func integer(v ttjson.Value, where string) (int64, error) {
	if v.Kind != ttjson.Number || !ttjson.IsIntLexeme([]byte(v.Str)) {
		return 0, invalidf("%s: expected integer", where)
	}
	n, err := strconv.ParseInt(v.Str, 10, 64)
	if err != nil {
		return 0, invalidf("%s: integer out of range", where)
	}
	return n, nil
}

func timeField(v ttjson.Value, where string) (time.Time, string, error) {
	s, err := str(v, where)
	if err != nil {
		return time.Time{}, "", err
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, "", invalidf("%s: not RFC 3339", where)
	}
	return t, s, nil
}

func strList(v ttjson.Value, where string) ([]string, error) {
	if v.Kind != ttjson.Array {
		return nil, invalidf("%s: expected array", where)
	}
	out := []string{}
	for _, e := range v.Arr {
		s, err := str(e, where+"[]")
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// MaxBodyBytes bounds the compiled body size a source accepts (schema:
// body_b64 at most 4 MiB of text).
const MaxBodyBytes = 3 << 20

// DecodeBody parses and validates compiled body bytes (schema plus
// Validate). It does not require canonical bytes or sorted arrays.
func DecodeBody(body []byte) (*Policy, error) {
	if len(body) > MaxBodyBytes {
		return nil, invalidf("body too large")
	}
	v, err := ttjson.Parse(body, ttjson.ParseOptions{MaxDepth: 16, RejectDuplicates: true})
	if err != nil {
		return nil, invalidf("body: %v", err)
	}
	return DecodeBodyValue(v)
}

// DecodeBodyValue is DecodeBody on an already parsed document.
func DecodeBodyValue(v ttjson.Value) (*Policy, error) {
	m, err := fields(v, "body", "format", "policy_id", "version", "issued_seq", "created_at", "not_after", "targets",
		"hmac", "identity", "sampling", "segments", "limits", "discovery", "hosts", "bodies", "global", "services")
	if err != nil {
		return nil, err
	}
	if err := require(m, "body", "format", "policy_id", "version", "issued_seq", "created_at", "not_after", "targets",
		"hmac", "sampling", "segments", "limits", "global", "services"); err != nil {
		return nil, err
	}
	p := &Policy{}
	if f, err := str(m["format"], "format"); err != nil || f != FormatBody {
		return nil, invalidf("format: expected %s", FormatBody)
	}
	if p.PolicyID, err = str(m["policy_id"], "policy_id"); err != nil {
		return nil, err
	}
	if p.Version, err = integer(m["version"], "version"); err != nil {
		return nil, err
	}
	if p.IssuedSeq, err = integer(m["issued_seq"], "issued_seq"); err != nil {
		return nil, err
	}
	if p.CreatedAt, p.createdRaw, err = timeField(m["created_at"], "created_at"); err != nil {
		return nil, err
	}
	if p.NotAfter, p.notAfterRaw, err = timeField(m["not_after"], "not_after"); err != nil {
		return nil, err
	}
	tm, err := fields(m["targets"], "targets", "groups")
	if err != nil {
		return nil, err
	}
	if err := require(tm, "targets", "groups"); err != nil {
		return nil, err
	}
	if p.Groups, err = strList(tm["groups"], "targets.groups"); err != nil {
		return nil, err
	}

	hm, err := fields(m["hmac"], "hmac", "kid", "accept_kids", "epoch")
	if err != nil {
		return nil, err
	}
	if err := require(hm, "hmac", "kid", "accept_kids", "epoch"); err != nil {
		return nil, err
	}
	if p.HMAC.Kid, err = str(hm["kid"], "hmac.kid"); err != nil {
		return nil, err
	}
	if p.HMAC.Epoch, err = str(hm["epoch"], "hmac.epoch"); err != nil {
		return nil, err
	}
	if p.HMAC.AcceptKids, err = strList(hm["accept_kids"], "hmac.accept_kids"); err != nil {
		return nil, err
	}
	if idv, ok := m["identity"]; ok {
		im, err := fields(idv, "identity", "subject")
		if err != nil {
			return nil, err
		}
		if sv, ok := im["subject"]; ok {
			sm, err := fields(sv, "identity.subject", "from", "name", "jwt_claim", "json_path")
			if err != nil {
				return nil, err
			}
			if err := require(sm, "identity.subject", "from", "name"); err != nil {
				return nil, err
			}
			s := &Subject{}
			if s.From, err = str(sm["from"], "identity.subject.from"); err != nil {
				return nil, err
			}
			if s.Name, err = str(sm["name"], "identity.subject.name"); err != nil {
				return nil, err
			}
			if jv, ok := sm["jwt_claim"]; ok {
				if s.JWTClaim, err = str(jv, "identity.subject.jwt_claim"); err != nil {
					return nil, err
				}
				if s.JWTClaim == "" {
					return nil, invalidf("identity.subject.jwt_claim: empty")
				}
			}
			if jv, ok := sm["json_path"]; ok {
				if s.JSONPath, err = str(jv, "identity.subject.json_path"); err != nil {
					return nil, err
				}
				if s.JSONPath == "" {
					return nil, invalidf("identity.subject.json_path: empty")
				}
			}
			p.Subject = s
		}
	}
	sm, err := fields(m["sampling"], "sampling", "rate_bp", "trust_baggage", "propagate_to")
	if err != nil {
		return nil, err
	}
	if err := require(sm, "sampling", "rate_bp", "trust_baggage", "propagate_to"); err != nil {
		return nil, err
	}
	bp, err := integer(sm["rate_bp"], "sampling.rate_bp")
	if err != nil {
		return nil, err
	}
	if bp < 0 || bp > 10000 {
		return nil, invalidf("sampling.rate_bp out of range")
	}
	p.Sampling.RateBP = int(bp)
	if p.Sampling.TrustBaggage, err = boolean(sm["trust_baggage"], "sampling.trust_baggage"); err != nil {
		return nil, err
	}
	if p.Sampling.PropagateTo, err = strList(sm["propagate_to"], "sampling.propagate_to"); err != nil {
		return nil, err
	}

	segm, err := fields(m["segments"], "segments", "auto_words", "auto_words_expires_at", "allow", "hosts_allow")
	if err != nil {
		return nil, err
	}
	if err := require(segm, "segments", "auto_words", "allow", "hosts_allow"); err != nil {
		return nil, err
	}
	if p.Segments.AutoWords, err = boolean(segm["auto_words"], "segments.auto_words"); err != nil {
		return nil, err
	}
	if ev, ok := segm["auto_words_expires_at"]; ok {
		if p.Segments.AutoWordsExpiresAt, p.Segments.autoWordsRaw, err = timeField(ev, "segments.auto_words_expires_at"); err != nil {
			return nil, err
		}
	}
	if p.Segments.Allow, err = strList(segm["allow"], "segments.allow"); err != nil {
		return nil, err
	}
	if p.Segments.HostsAllow, err = strList(segm["hosts_allow"], "segments.hosts_allow"); err != nil {
		return nil, err
	}

	lm, err := fields(m["limits"], "limits", "max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes")
	if err != nil {
		return nil, err
	}
	if err := require(lm, "limits", "max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes"); err != nil {
		return nil, err
	}
	var lv [5]int64
	for i, k := range []string{"max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes"} {
		if lv[i], err = integer(lm[k], "limits."+k); err != nil {
			return nil, err
		}
		if lv[i] < 0 || lv[i] > MaxMaxBodyBytes {
			return nil, invalidf("limits.%s out of range", k)
		}
	}
	p.Limits = Limits{lv[0], int(lv[1]), int(lv[2]), int(lv[3]), int(lv[4])}

	if dv, ok := m["discovery"]; ok {
		dm, err := fields(dv, "discovery", "enabled", "expires_at")
		if err != nil {
			return nil, err
		}
		if err := require(dm, "discovery", "enabled", "expires_at"); err != nil {
			return nil, err
		}
		d := &Discovery{}
		if d.Enabled, err = boolean(dm["enabled"], "discovery.enabled"); err != nil {
			return nil, err
		}
		if d.ExpiresAt, d.expiresRaw, err = timeField(dm["expires_at"], "discovery.expires_at"); err != nil {
			return nil, err
		}
		p.Discovery = d
	}
	if hv, ok := m["hosts"]; ok {
		hm, err := fields(hv, "hosts", "discovery")
		if err != nil {
			return nil, err
		}
		if err := require(hm, "hosts", "discovery"); err != nil {
			return nil, err
		}
		if p.Hosts.Discovery, err = str(hm["discovery"], "hosts.discovery"); err != nil {
			return nil, err
		}
		if p.Hosts.Discovery != HostsAuto && p.Hosts.Discovery != HostsOff {
			return nil, invalidf("hosts.discovery: must be auto or off")
		}
	}
	if bv, ok := m["bodies"]; ok {
		if p.Bodies, err = decodeBodies(bv); err != nil {
			return nil, err
		}
	}

	if p.Global, err = decodeScope(m["global"], "global", true); err != nil {
		return nil, err
	}
	sv := m["services"]
	if sv.Kind != ttjson.Array {
		return nil, invalidf("services: expected array")
	}
	p.Services = []Service{}
	for i, e := range sv.Arr {
		s, err := decodeService(e, fmt.Sprintf("services[%d]", i))
		if err != nil {
			return nil, err
		}
		p.Services = append(p.Services, s)
	}
	if err := ValidateSource(p); err != nil {
		return nil, err
	}
	return p, nil
}

// decodeBodies reads the bodies object (sanitizer.md 22.1, spec v1.19):
// every field required, nothing else.
func decodeBodies(v ttjson.Value) (*Bodies, error) {
	keys := []string{"xml", "multipart", "docs", "max_large_body_bytes", "large_array", "large_nested_array"}
	bm, err := fields(v, "bodies", keys...)
	if err != nil {
		return nil, err
	}
	if err := require(bm, "bodies", keys...); err != nil {
		return nil, err
	}
	b := &Bodies{}
	if b.XML, err = boolean(bm["xml"], "bodies.xml"); err != nil {
		return nil, err
	}
	if b.Multipart, err = boolean(bm["multipart"], "bodies.multipart"); err != nil {
		return nil, err
	}
	if b.Docs, err = boolean(bm["docs"], "bodies.docs"); err != nil {
		return nil, err
	}
	if b.MaxLargeBytes, err = integer(bm["max_large_body_bytes"], "bodies.max_large_body_bytes"); err != nil {
		return nil, err
	}
	if b.MaxLargeBytes < 0 || b.MaxLargeBytes > MaxLargeBodyBytes {
		return nil, invalidf("bodies.max_large_body_bytes out of range")
	}
	for _, f := range []struct {
		k   string
		dst *int
	}{{"large_array", &b.LargeArray}, {"large_nested_array", &b.LargeNestedArray}} {
		n, err := integer(bm[f.k], "bodies."+f.k)
		if err != nil {
			return nil, err
		}
		if n < 0 || n > MaxLargeArray {
			return nil, invalidf("bodies.%s out of range", f.k)
		}
		*f.dst = int(n)
	}
	return b, nil
}

func decodeScope(v ttjson.Value, where string, withErrors bool) (Scope, error) {
	var s Scope
	allowed := []string{"request", "response"}
	if withErrors {
		allowed = append(allowed, "errors")
	}
	m, err := fields(v, where, allowed...)
	if err != nil {
		return s, err
	}
	if pv, ok := m["request"]; ok {
		if s.Request, err = decodePart(pv, where+".request"); err != nil {
			return s, err
		}
	}
	if pv, ok := m["response"]; ok {
		if s.Response, err = decodePart(pv, where+".response"); err != nil {
			return s, err
		}
	}
	if pv, ok := m["errors"]; ok {
		if s.Errors, err = decodePart(pv, where+".errors"); err != nil {
			return s, err
		}
	}
	return s, nil
}

func decodeService(v ttjson.Value, where string) (Service, error) {
	var s Service
	m, err := fields(v, where, "name", "match", "request", "response", "errors", "ops")
	if err != nil {
		return s, err
	}
	if err := require(m, where, "name", "match", "ops"); err != nil {
		return s, err
	}
	if s.Name, err = str(m["name"], where+".name"); err != nil {
		return s, err
	}
	mm, err := fields(m["match"], where+".match", "inbound", "internal", "base")
	if err != nil {
		return s, err
	}
	if bv, ok := mm["base"]; ok {
		if len(mm) != 1 {
			return s, invalidf("%s.match: base excludes inbound and internal", where)
		}
		if s.Match.Base, err = str(bv, where+".match.base"); err != nil {
			return s, err
		}
	} else {
		if err := require(mm, where+".match", "inbound", "internal"); err != nil {
			return s, err
		}
		in, err := boolean(mm["inbound"], where+".match.inbound")
		if err != nil || !in {
			return s, invalidf("%s.match.inbound must be true", where)
		}
		s.Match.Inbound = true
		if s.Match.Internal, err = boolean(mm["internal"], where+".match.internal"); err != nil {
			return s, err
		}
	}
	scopeObj := ttjson.Obj()
	for _, k := range []string{"request", "response", "errors"} {
		if pv, ok := m[k]; ok {
			scopeObj.Obj = append(scopeObj.Obj, ttjson.Member{Key: k, Value: pv})
		}
	}
	if s.Scope, err = decodeScope(scopeObj, where, true); err != nil {
		return s, err
	}
	ov := m["ops"]
	if ov.Kind != ttjson.Array {
		return s, invalidf("%s.ops: expected array", where)
	}
	s.Ops = []Op{}
	for i, e := range ov.Arr {
		w := fmt.Sprintf("%s.ops[%d]", where, i)
		om, err := fields(e, w, "op", "request", "response")
		if err != nil {
			return s, err
		}
		if err := require(om, w, "op"); err != nil {
			return s, err
		}
		var op Op
		if op.Op, err = str(om["op"], w+".op"); err != nil {
			return s, err
		}
		if pv, ok := om["request"]; ok {
			if op.Request, err = decodePart(pv, w+".request"); err != nil {
				return s, err
			}
		}
		if pv, ok := om["response"]; ok {
			if op.Response, err = decodePart(pv, w+".response"); err != nil {
				return s, err
			}
		}
		s.Ops = append(s.Ops, op)
	}
	return s, nil
}

func decodePart(v ttjson.Value, where string) (Part, error) {
	var p Part
	m, err := fields(v, where, "path", "query", "headers", "cookies", "body")
	if err != nil {
		return p, err
	}
	dm := func(k string) (map[string]Action, error) {
		mv, ok := m[k]
		if !ok {
			return nil, nil
		}
		if mv.Kind != ttjson.Object {
			return nil, invalidf("%s.%s: expected object", where, k)
		}
		out := make(map[string]Action, len(mv.Obj))
		for _, mem := range mv.Obj {
			a, err := decodeAction(mem.Value, where+"."+k+"."+mem.Key)
			if err != nil {
				return nil, err
			}
			out[mem.Key] = a
		}
		return out, nil
	}
	if p.Path, err = dm("path"); err != nil {
		return p, err
	}
	if p.Query, err = dm("query"); err != nil {
		return p, err
	}
	if p.Headers, err = dm("headers"); err != nil {
		return p, err
	}
	if p.Cookies, err = dm("cookies"); err != nil {
		return p, err
	}
	if bv, ok := m["body"]; ok {
		if bv.Kind != ttjson.Array {
			return p, invalidf("%s.body: expected array", where)
		}
		p.Body = []BodyRule{}
		for i, e := range bv.Arr {
			w := fmt.Sprintf("%s.body[%d]", where, i)
			rm, err := fields(e, w, "path", "action")
			if err != nil {
				return p, err
			}
			if err := require(rm, w, "path", "action"); err != nil {
				return p, err
			}
			var r BodyRule
			if r.Path, err = str(rm["path"], w+".path"); err != nil {
				return p, err
			}
			if r.Action, err = decodeAction(rm["action"], w+".action"); err != nil {
				return p, err
			}
			p.Body = append(p.Body, r)
		}
	}
	return p, nil
}

func decodeAction(v ttjson.Value, where string) (Action, error) {
	var a Action
	m, err := fields(v, where, "action", "domain", "kind", "bounds", "unit", "shape")
	if err != nil {
		return a, err
	}
	if err := require(m, where, "action"); err != nil {
		return a, err
	}
	name, err := str(m["action"], where+".action")
	if err != nil {
		return a, err
	}
	only := func(keys ...string) error {
		if len(m) != len(keys)+1 {
			return invalidf("%s: unexpected fields for %s", where, name)
		}
		return require(m, where, keys...)
	}
	switch name {
	case "code":
		if _, ok := m["shape"]; ok {
			// Spec v1.19 (sanitizer.md 5.6): the only shape is alnum.
			if err := only("shape"); err != nil {
				return a, err
			}
			if a.Shape, err = str(m["shape"], where+".shape"); err != nil {
				return a, err
			}
			if a.Shape != CodeShapeAlnum {
				return a, invalidf("%s.shape: must be alnum", where)
			}
		} else if err := only(); err != nil {
			return a, err
		}
		a.Kind = ActCode
	case "drop", "keep", "graphql":
		if err := only(); err != nil {
			return a, err
		}
		if name == "keep" {
			a.Kind = ActKeep
		}
		if name == "graphql" {
			a.Kind = ActGraphQL
		}
	case "hmac":
		if err := only("domain"); err != nil {
			return a, err
		}
		a.Kind = ActHMAC
		if a.Domain, err = str(m["domain"], where+".domain"); err != nil {
			return a, err
		}
	case "bucket":
		kind, err := str(m["kind"], where+".kind")
		if err != nil {
			return a, err
		}
		switch kind {
		case "num":
			if err := only("kind", "bounds"); err != nil {
				return a, err
			}
			a.Kind = ActBucketNum
			bv := m["bounds"]
			if bv.Kind != ttjson.Array {
				return a, invalidf("%s.bounds: expected array", where)
			}
			for _, e := range bv.Arr {
				if e.Kind != ttjson.Number {
					return a, invalidf("%s.bounds: expected numbers", where)
				}
				b, err := NewBound(e.Str)
				if err != nil {
					return a, invalidf("%s.bounds: %v", where, err)
				}
				a.Bounds = append(a.Bounds, b)
			}
		case "time":
			if err := only("kind", "unit"); err != nil {
				return a, err
			}
			a.Kind = ActBucketTime
			if a.Unit, err = str(m["unit"], where+".unit"); err != nil {
				return a, err
			}
		default:
			return a, invalidf("%s.kind: unknown %q", where, kind)
		}
	default:
		return a, invalidf("%s.action: unknown %q", where, name)
	}
	return a, nil
}

// NewBound builds a bucket bound from a number lexeme. Non-finite doubles
// are rejected.
func NewBound(lex string) (Bound, error) {
	if len(lex) > MaxBoundLexeme {
		return Bound{}, errors.New("bound lexeme longer than 64 bytes")
	}
	c, err := ttjson.CanonicalNumber([]byte(lex))
	if err != nil {
		return Bound{}, errors.New("invalid number")
	}
	f := ttjson.ParseFloat([]byte(lex))
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return Bound{}, errors.New("bound out of double range")
	}
	return Bound{Lexeme: c, F: f}, nil
}

// EncodeBody writes p as canonical compiled body bytes. Empty maps, empty
// body rule lists and empty parts are omitted; global and services are
// always present.
func EncodeBody(p *Policy) ([]byte, error) {
	return ttjson.Encode(bodyValue(p))
}

func mem(k string, v ttjson.Value) ttjson.Member { return ttjson.Member{Key: k, Value: v} }

func strArr(list []string) ttjson.Value {
	a := ttjson.Value{Kind: ttjson.Array, Arr: []ttjson.Value{}}
	for _, s := range list {
		a.Arr = append(a.Arr, ttjson.Str(s))
	}
	return a
}

func timeStr(raw string, t time.Time) string {
	if raw != "" {
		return raw
	}
	return t.UTC().Format(time.RFC3339)
}

func bodyValue(p *Policy) ttjson.Value {
	seg := ttjson.Obj(
		mem("auto_words", ttjson.BoolV(p.Segments.AutoWords)),
		mem("allow", strArr(p.Segments.Allow)),
		mem("hosts_allow", strArr(p.Segments.HostsAllow)),
	)
	if !p.Segments.AutoWordsExpiresAt.IsZero() {
		seg.Obj = append(seg.Obj, mem("auto_words_expires_at", ttjson.Str(timeStr(p.Segments.autoWordsRaw, p.Segments.AutoWordsExpiresAt))))
	}
	o := ttjson.Obj(
		mem("format", ttjson.Str(FormatBody)),
		mem("policy_id", ttjson.Str(p.PolicyID)),
		mem("version", ttjson.Num(strconv.FormatInt(p.Version, 10))),
		mem("issued_seq", ttjson.Num(strconv.FormatInt(p.IssuedSeq, 10))),
		mem("created_at", ttjson.Str(timeStr(p.createdRaw, p.CreatedAt))),
		mem("not_after", ttjson.Str(timeStr(p.notAfterRaw, p.NotAfter))),
		mem("targets", ttjson.Obj(mem("groups", strArr(p.Groups)))),
		mem("hmac", ttjson.Obj(mem("kid", ttjson.Str(p.HMAC.Kid)), mem("accept_kids", strArr(p.HMAC.AcceptKids)), mem("epoch", ttjson.Str(p.HMAC.Epoch)))),
		mem("sampling", ttjson.Obj(
			mem("rate_bp", ttjson.Num(strconv.Itoa(p.Sampling.RateBP))),
			mem("trust_baggage", ttjson.BoolV(p.Sampling.TrustBaggage)),
			mem("propagate_to", strArr(p.Sampling.PropagateTo)),
		)),
		mem("segments", seg),
		mem("limits", ttjson.Obj(
			mem("max_body_bytes", ttjson.Num(strconv.FormatInt(p.Limits.MaxBodyBytes, 10))),
			mem("max_depth", ttjson.Num(strconv.Itoa(p.Limits.MaxDepth))),
			mem("max_array", ttjson.Num(strconv.Itoa(p.Limits.MaxArray))),
			mem("max_keys", ttjson.Num(strconv.Itoa(p.Limits.MaxKeys))),
			mem("keep_max_bytes", ttjson.Num(strconv.Itoa(p.Limits.KeepMaxBytes))),
		)),
		mem("global", scopeValue(&p.Global)),
	)
	if p.Subject != nil {
		s := ttjson.Obj(mem("from", ttjson.Str(p.Subject.From)), mem("name", ttjson.Str(p.Subject.Name)))
		if p.Subject.JSONPath != "" {
			s.Obj = append(s.Obj, mem("json_path", ttjson.Str(p.Subject.JSONPath)))
		}
		if p.Subject.JWTClaim != "" {
			s.Obj = append(s.Obj, mem("jwt_claim", ttjson.Str(p.Subject.JWTClaim)))
		}
		o.Obj = append(o.Obj, mem("identity", ttjson.Obj(mem("subject", s))))
	}
	if p.Discovery != nil {
		o.Obj = append(o.Obj, mem("discovery", ttjson.Obj(
			mem("enabled", ttjson.BoolV(p.Discovery.Enabled)),
			mem("expires_at", ttjson.Str(timeStr(p.Discovery.expiresRaw, p.Discovery.ExpiresAt))))))
	}
	if p.Hosts.Discovery != "" {
		o.Obj = append(o.Obj, mem("hosts", ttjson.Obj(mem("discovery", ttjson.Str(p.Hosts.Discovery)))))
	}
	if b := p.Bodies; b != nil {
		o.Obj = append(o.Obj, mem("bodies", ttjson.Obj(
			mem("xml", ttjson.BoolV(b.XML)),
			mem("multipart", ttjson.BoolV(b.Multipart)),
			mem("docs", ttjson.BoolV(b.Docs)),
			mem("max_large_body_bytes", ttjson.Num(strconv.FormatInt(b.MaxLargeBytes, 10))),
			mem("large_array", ttjson.Num(strconv.Itoa(b.LargeArray))),
			mem("large_nested_array", ttjson.Num(strconv.Itoa(b.LargeNestedArray))),
		)))
	}
	svcs := ttjson.Value{Kind: ttjson.Array, Arr: []ttjson.Value{}}
	for i := range p.Services {
		s := &p.Services[i]
		var match ttjson.Value
		if s.Match.Inbound {
			match = ttjson.Obj(mem("inbound", ttjson.BoolV(true)), mem("internal", ttjson.BoolV(s.Match.Internal)))
		} else {
			match = ttjson.Obj(mem("base", ttjson.Str(s.Match.Base)))
		}
		ops := ttjson.Value{Kind: ttjson.Array, Arr: []ttjson.Value{}}
		for j := range s.Ops {
			op := ttjson.Obj(mem("op", ttjson.Str(s.Ops[j].Op)))
			addPart(&op, "request", &s.Ops[j].Request)
			addPart(&op, "response", &s.Ops[j].Response)
			ops.Arr = append(ops.Arr, op)
		}
		sv := ttjson.Obj(mem("name", ttjson.Str(s.Name)), mem("match", match), mem("ops", ops))
		addPart(&sv, "request", &s.Request)
		addPart(&sv, "response", &s.Response)
		addPart(&sv, "errors", &s.Errors)
		svcs.Arr = append(svcs.Arr, sv)
	}
	o.Obj = append(o.Obj, mem("services", svcs))
	return o
}

func scopeValue(s *Scope) ttjson.Value {
	o := ttjson.Obj()
	o.Obj = []ttjson.Member{}
	addPart(&o, "request", &s.Request)
	addPart(&o, "response", &s.Response)
	addPart(&o, "errors", &s.Errors)
	return o
}

func addPart(o *ttjson.Value, key string, p *Part) {
	if p.IsEmpty() {
		return
	}
	pv := ttjson.Obj()
	for _, kv := range []struct {
		k string
		m map[string]Action
	}{{"path", p.Path}, {"query", p.Query}, {"headers", p.Headers}, {"cookies", p.Cookies}} {
		if len(kv.m) == 0 {
			continue
		}
		names := make([]string, 0, len(kv.m))
		for n := range kv.m {
			names = append(names, n)
		}
		sort.Strings(names)
		mv := ttjson.Obj()
		for _, n := range names {
			mv.Obj = append(mv.Obj, mem(n, actionValue(kv.m[n])))
		}
		pv.Obj = append(pv.Obj, mem(kv.k, mv))
	}
	if len(p.Body) > 0 {
		arr := ttjson.Arr()
		for _, r := range p.Body {
			arr.Arr = append(arr.Arr, ttjson.Obj(mem("path", ttjson.Str(r.Path)), mem("action", actionValue(r.Action))))
		}
		pv.Obj = append(pv.Obj, mem("body", arr))
	}
	o.Obj = append(o.Obj, mem(key, pv))
}

func actionValue(a Action) ttjson.Value {
	switch a.Kind {
	case ActKeep:
		return ttjson.Obj(mem("action", ttjson.Str("keep")))
	case ActCode:
		if a.Shape != "" {
			return ttjson.Obj(mem("action", ttjson.Str("code")), mem("shape", ttjson.Str(a.Shape)))
		}
		return ttjson.Obj(mem("action", ttjson.Str("code")))
	case ActGraphQL:
		return ttjson.Obj(mem("action", ttjson.Str("graphql")))
	case ActHMAC:
		return ttjson.Obj(mem("action", ttjson.Str("hmac")), mem("domain", ttjson.Str(a.Domain)))
	case ActBucketNum:
		b := ttjson.Arr()
		b.Arr = []ttjson.Value{}
		for _, x := range a.Bounds {
			b.Arr = append(b.Arr, ttjson.Num(x.Lexeme))
		}
		return ttjson.Obj(mem("action", ttjson.Str("bucket")), mem("kind", ttjson.Str("num")), mem("bounds", b))
	case ActBucketTime:
		return ttjson.Obj(mem("action", ttjson.Str("bucket")), mem("kind", ttjson.Str("time")), mem("unit", ttjson.Str(a.Unit)))
	}
	return ttjson.Obj(mem("action", ttjson.Str("drop")))
}
