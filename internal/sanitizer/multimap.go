package sanitizer

import (
	"bytes"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// MaxNames is the maximum number of distinct output names kept for
// headers, cookies, query and form bodies (section 8.1 point 4).
const MaxNames = 64

const (
	keyAny   = "{*}"
	keyTrunc = "{trunc}"
)

// ---- Header normalization (section 8.0) ----

// normHeader is one output header after normalization: one merged value
// per output name.
type normHeader struct {
	name  string   // output name: lower case, or {*}
	origs []string // distinct original lower-case names, arrival order
	value []byte   // values joined with ", "
}

// normHeaders is the normalized view of one direction's headers.
type normHeaders struct {
	headers    []normHeader      // excluding cookie and set-cookie, order of first appearance
	byOrig     map[string][]byte // merged value per original lower-case name
	setCookies [][]byte          // set-cookie values, never joined
}

func trimOWS(b []byte) []byte { return bytes.Trim(b, " \t") }

// asciiLower lower-cases ASCII letters only.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if isUpper(s[i]) {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if isUpper(b[j]) {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func joinValue(cur, v []byte, sep string, first bool) []byte {
	if first {
		return append([]byte(nil), v...)
	}
	cur = append(cur, sep...)
	return append(cur, v...)
}

// normalizeHeaders implements section 8.0: pseudo-headers removed, names
// lower-cased, OWS trimmed, values with the same name joined in arrival
// order (cookie with "; ", set-cookie kept apart, others with ", "), names
// in order of first appearance.
func normalizeHeaders(hs []Header) *normHeaders {
	n := &normHeaders{byOrig: map[string][]byte{}}
	idx := map[string]int{}
	for _, h := range hs {
		if len(h.Name) > 0 && h.Name[0] == ':' {
			continue
		}
		ln := asciiLower(h.Name)
		v := trimOWS(h.Value)
		switch ln {
		case "set-cookie":
			n.setCookies = append(n.setCookies, append([]byte(nil), v...))
			continue
		case "cookie":
			cur, seen := n.byOrig[ln]
			n.byOrig[ln] = joinValue(cur, v, "; ", !seen)
			continue
		}
		cur, seen := n.byOrig[ln]
		n.byOrig[ln] = joinValue(cur, v, ", ", !seen)
		out := keyAny
		if IsLiteralHeaderName([]byte(ln)) {
			out = ln
		}
		if i, ok := idx[out]; ok {
			nh := &n.headers[i]
			nh.value = joinValue(nh.value, v, ", ", false)
			known := false
			for _, o := range nh.origs {
				if o == ln {
					known = true
					break
				}
			}
			if !known {
				nh.origs = append(nh.origs, ln)
			}
			continue
		}
		idx[out] = len(n.headers)
		n.headers = append(n.headers, normHeader{name: out, origs: []string{ln}, value: append([]byte(nil), v...)})
	}
	return n
}

// get returns the normalized value of an original (lower-case) name.
func (n *normHeaders) get(name string) ([]byte, bool) {
	v, ok := n.byOrig[name]
	return v, ok
}

// ---- name → [token] maps (sections 8.1–8.3) ----

// multimap builds "name → [token]" objects: names in order of first
// appearance, at most MaxNames distinct output names (then {trunc} =
// ["trunc:keys:<class>"]), at most maxVals values per name (then
// "trunc:n:<class of the name's values>").
type multimap struct {
	order   []string
	vals    map[string][]ttjson.Value
	count   map[string]int
	rank    map[string]int
	maxVals int
}

func newMultimap(maxVals int) *multimap {
	return &multimap{vals: map[string][]ttjson.Value{}, count: map[string]int{}, rank: map[string]int{}, maxVals: maxVals}
}

// add records one value of name; mk is called only when the value is kept.
func (m *multimap) add(name string, mk func() ttjson.Value) {
	if _, ok := m.count[name]; !ok {
		m.rank[name] = len(m.order)
		m.order = append(m.order, name)
	}
	m.count[name]++
	if m.rank[name] >= MaxNames || m.count[name] > m.maxVals {
		return
	}
	m.vals[name] = append(m.vals[name], mk())
}

// value returns the object, or ok=false when there are no names.
func (m *multimap) value() (ttjson.Value, bool) {
	if len(m.order) == 0 {
		return ttjson.Value{}, false
	}
	kept := m.order
	if len(kept) > MaxNames {
		kept = kept[:MaxNames]
	}
	o := ttjson.Value{Kind: ttjson.Object, Obj: make([]ttjson.Member, 0, len(kept)+1)}
	for _, k := range kept {
		arr := append([]ttjson.Value{}, m.vals[k]...)
		if c := m.count[k]; c > m.maxVals {
			arr = append(arr, ttjson.Str("trunc:n:"+LenClass(int64(c))))
		}
		o.Obj = append(o.Obj, ttjson.Member{Key: k, Value: ttjson.Arr(arr...)})
	}
	if len(m.order) > MaxNames {
		o.Obj = append(o.Obj, ttjson.Member{Key: keyTrunc, Value: ttjson.Arr(ttjson.Str("trunc:keys:" + LenClass(int64(len(m.order)))))})
	}
	return o, true
}

// stringValue sanitizes a byte value that is a string in its context
// (header, cookie, query, form): non UTF-8 → drop:bytes. discPath "" means
// no discovery entry.
func (r *run) stringValue(v []byte, a *policy.Action, discPath string) ttjson.Value {
	if !utf8.Valid(v) {
		r.gqlUnusable(a)
		return tokDropBytes
	}
	l := leaf{kind: leafStr, s: v}
	out, def := r.applyLeaf(&l, a)
	if def && discPath != "" {
		r.addDisc(discPath, &l)
	}
	return out
}

func (r *run) discPath(side, part, name string) string {
	if !r.discOn {
		return ""
	}
	return side + "." + part + "." + name
}

// headers sanitizes the normalized headers of one side (section 8.1).
func (r *run) headers(n *normHeaders, rs *ruleSet, side string) (ttjson.Value, bool) {
	m := newMultimap(1)
	for i := range n.headers {
		h := &n.headers[i]
		m.add(h.name, func() ttjson.Value {
			// Rules match the original name, also when it collapses to
			// {*}; a {*} that merges several original names gets none.
			var a *policy.Action
			if len(h.origs) == 1 {
				a = rs.lookup(rs.headers, h.origs[0])
			}
			return r.stringValue(h.value, a, r.discPath(side, "headers", h.name))
		})
	}
	return m.value()
}

// contentField reads content-type or content-encoding from the normalized
// value: part before the first ';', OWS trimmed, lower case.
func contentField(n *normHeaders, name string) (string, bool) {
	v, ok := n.get(name)
	if !ok {
		return "", false
	}
	if i := bytes.IndexByte(v, ';'); i >= 0 && name == "content-type" {
		v = v[:i]
	}
	return asciiLower(string(trimOWS(v))), true
}

// contentType implements section 8.1 point 5.
func contentType(n *normHeaders) (string, bool) {
	ct, ok := contentField(n, "content-type")
	if !ok {
		return "", false
	}
	if validCT(ct) {
		return ct, true
	}
	return "invalid", true
}

// validCT matches ^[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}$.
func validCT(s string) bool {
	slash := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/':
			if slash >= 0 {
				return false
			}
			slash = i
		case isLower(c) || isDigit(c) || c == '.' || c == '+' || c == '-':
		default:
			return false
		}
	}
	return slash >= 1 && slash <= 64 && len(s)-slash-1 >= 1 && len(s)-slash-1 <= 64
}

// nameOut returns the output name of a cookie, query or form name.
func nameOut(raw []byte) string {
	if utf8.Valid(raw) && IsLiteralKey(raw) {
		return string(raw)
	}
	return keyAny
}

// requestCookies splits the normalized Cookie value (section 8.2) and calls
// fn for each name=value pair, in order.
func requestCookies(n *normHeaders, fn func(name, value []byte)) {
	v, ok := n.get("cookie")
	if !ok {
		return
	}
	for _, part := range bytes.Split(v, []byte{';'}) {
		part = trimOWS(part)
		eq := bytes.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		fn(part[:eq], part[eq+1:])
	}
}

// responseCookies handles Set-Cookie values: the part before the first ';',
// OWS trimmed, split on the first '='; without '=' the value is ignored.
func responseCookies(n *normHeaders, fn func(name, value []byte)) {
	for _, v := range n.setCookies {
		if i := bytes.IndexByte(v, ';'); i >= 0 {
			v = v[:i]
		}
		v = trimOWS(v)
		eq := bytes.IndexByte(v, '=')
		if eq < 0 {
			continue
		}
		fn(v[:eq], v[eq+1:])
	}
}

func (r *run) cookies(n *normHeaders, rs *ruleSet, side string) (ttjson.Value, bool) {
	m := newMultimap(r.lim.MaxArray)
	fn := func(rawName, val []byte) {
		name := nameOut(rawName)
		m.add(name, func() ttjson.Value {
			var a *policy.Action
			if utf8.Valid(rawName) {
				a = rs.lookup(rs.cookies, string(rawName))
			}
			return r.stringValue(val, a, r.discPath(side, "cookies", name))
		})
	}
	if side == "req" {
		requestCookies(n, fn)
	} else {
		responseCookies(n, fn)
	}
	return m.value()
}

// formDecode decodes a query/form component: '+' → space, then %XY.
func formDecode(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(b) && isHex(b[i+1]) && isHex(b[i+2]):
			out = append(out, unhex(b[i+1])<<4|unhex(b[i+2]))
			i += 2
		default:
			out = append(out, c)
		}
	}
	return out
}

func unhex(c byte) byte {
	switch {
	case isDigit(c):
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// urlencoded sanitizes a query string or an x-www-form-urlencoded body
// (section 8.3). lookup returns the action for a decoded UTF-8 name. A part
// without '=' has the name {*}, its whole decoded content as value and
// always drop. Discovery paths: "req.query.<name>" for the query,
// "<side>.body.<name>" or "<side>.body.*" for form bodies.
func (r *run) urlencoded(raw []byte, lookup func(name string) *policy.Action, discPrefix string, isBody bool) (ttjson.Value, bool) {
	m := newMultimap(r.lim.MaxArray)
	for _, part := range bytes.Split(raw, []byte{'&'}) {
		if len(part) == 0 {
			continue
		}
		var name string
		var dv []byte
		var a *policy.Action
		if eq := bytes.IndexByte(part, '='); eq >= 0 {
			dn := formDecode(part[:eq])
			dv = formDecode(part[eq+1:])
			name = nameOut(dn)
			if utf8.Valid(dn) {
				a = lookup(string(dn))
			}
		} else {
			name, dv = keyAny, formDecode(part)
		}
		dp := ""
		if r.discOn {
			switch {
			case !isBody:
				dp = discPrefix + "." + name
			case name == keyAny:
				dp = discPrefix + ".*"
			default:
				dp = discPrefix + "." + name
			}
		}
		m.add(name, func() ttjson.Value { return r.stringValue(dv, a, dp) })
	}
	return m.value()
}
