package mock

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/fielddeps"
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

// schemaCtx resolves and interprets the JSON Schema subset used by the
// contracts of a pack (OpenAPI 3.1 documents with local $ref only).
type schemaCtx struct {
	doc map[string]any
	// docs: some schema of the contract is a document in base64
	// (docSchema); examples are then checked for document fields.
	docs bool
}

const maxSchemaDepth = 24

// resolve follows local $ref chains and returns the schema object (nil when n
// is not an object, e.g. the boolean schemas).
func (c *schemaCtx) resolve(n any) map[string]any {
	for hops := 0; hops < 16; hops++ {
		m, ok := n.(map[string]any)
		if !ok {
			return nil
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		n = c.pointer(ref)
		if n == nil {
			return nil
		}
	}
	return nil
}

func (c *schemaCtx) pointer(ref string) any {
	if !strings.HasPrefix(ref, "#") {
		return nil
	}
	ref = strings.TrimPrefix(ref, "#")
	if ref == "" {
		return c.doc
	}
	if !strings.HasPrefix(ref, "/") {
		return nil
	}
	var cur any = c.doc
	for _, tok := range strings.Split(ref[1:], "/") {
		if u, err := url.PathUnescape(tok); err == nil {
			tok = u
		}
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch x := cur.(type) {
		case map[string]any:
			cur = x[tok]
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(x) {
				return nil
			}
			cur = x[i]
		default:
			return nil
		}
	}
	return cur
}

// flat resolves $ref and merges allOf (and the first non-null oneOf/anyOf
// alternative) into one schema object.
func (c *schemaCtx) flat(n any, depth int) map[string]any {
	s := c.resolve(n)
	if s == nil || depth > maxSchemaDepth {
		return map[string]any{}
	}
	_, hasAll := s["allOf"]
	_, hasOne := s["oneOf"]
	_, hasAny := s["anyOf"]
	if !hasAll && !hasOne && !hasAny {
		return s
	}
	out := map[string]any{}
	for k, v := range s {
		if k != "allOf" && k != "oneOf" && k != "anyOf" {
			out[k] = v
		}
	}
	var subs []any
	if a, ok := s["allOf"].([]any); ok {
		subs = append(subs, a...)
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		if a, ok := s[key].([]any); ok {
			for _, alt := range a {
				f := c.flat(alt, depth+1)
				if t, _ := f["type"].(string); t == "null" {
					continue
				}
				subs = append(subs, alt)
				break
			}
		}
	}
	for _, sub := range subs {
		mergeSchema(out, c.flat(sub, depth+1))
	}
	return out
}

func mergeSchema(dst, src map[string]any) {
	for k, v := range src {
		switch k {
		case "properties":
			dp, _ := dst[k].(map[string]any)
			sp, _ := v.(map[string]any)
			merged := map[string]any{}
			for pk, pv := range dp {
				merged[pk] = pv
			}
			for pk, pv := range sp {
				merged[pk] = pv
			}
			dst[k] = merged
		case "required":
			var list []any
			if d, ok := dst[k].([]any); ok {
				list = append(list, d...)
			}
			if s, ok := v.([]any); ok {
				list = append(list, s...)
			}
			dst[k] = list
		default:
			if _, ok := dst[k]; !ok {
				dst[k] = v
			}
		}
	}
}

// schemaTypes returns the declared types of a flat schema.
func schemaTypes(s map[string]any) []string {
	var out []string
	switch t := s["type"].(type) {
	case string:
		out = []string{t}
	case []any:
		for _, e := range t {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
	}
	if nb, _ := s["nullable"].(bool); nb {
		out = append(out, "null")
	}
	return out
}

// primaryType is the first non-null declared type, inferred from keywords
// when none is declared.
func primaryType(s map[string]any) string {
	for _, t := range schemaTypes(s) {
		if t != "null" {
			return t
		}
	}
	if _, ok := s["properties"]; ok {
		return "object"
	}
	if _, ok := s["items"]; ok {
		return "array"
	}
	return ""
}

func requiredSet(s map[string]any) map[string]bool {
	out := map[string]bool{}
	if r, ok := s["required"].([]any); ok {
		for _, e := range r {
			if str, ok := e.(string); ok {
				out[str] = true
			}
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- validation ----

type violation struct {
	ptr string
	msg string
}

func (v *violation) String() string { return v.ptr + ": " + v.msg }

var regexCache sync.Map

func cachedRegexp(p string) *regexp.Regexp {
	if re, ok := regexCache.Load(p); ok {
		r, _ := re.(*regexp.Regexp)
		return r
	}
	re, err := regexp.Compile(p)
	if err != nil {
		regexCache.Store(p, (*regexp.Regexp)(nil))
		return nil
	}
	regexCache.Store(p, re)
	return re
}

func typeMatches(t string, v any) bool {
	switch t {
	case "null":
		return v == nil
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && !math.IsInf(f, 0)
	case "integer":
		n, ok := v.(json.Number)
		return ok && isIntegral(n)
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	}
	return false
}

// validate checks v against the schema and returns the first violation in a
// deterministic order, or nil.
func (c *schemaCtx) validate(schema any, v any, ptr string, depth int) *violation {
	if depth > maxSchemaDepth {
		return nil
	}
	if b, ok := schema.(bool); ok {
		if !b {
			return &violation{ptr, "no value is allowed here"}
		}
		return nil
	}
	s := c.resolve(schema)
	if s == nil {
		return nil
	}
	if types := schemaTypes(s); len(types) > 0 {
		ok := false
		for _, t := range types {
			if typeMatches(t, v) {
				ok = true
				break
			}
		}
		if !ok {
			return &violation{ptr, "expected type " + strings.Join(types, " or ")}
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, cand := range e {
			if jsonEqual(cand, v) {
				found = true
				break
			}
		}
		if !found {
			return &violation{ptr, "value is not one of the allowed values"}
		}
	}
	if cv, ok := s["const"]; ok && !jsonEqual(cv, v) {
		return &violation{ptr, "value differs from the allowed constant"}
	}
	if sub, ok := s["allOf"].([]any); ok {
		for _, alt := range sub {
			if viol := c.validate(alt, v, ptr, depth+1); viol != nil {
				return viol
			}
		}
	}
	if sub, ok := s["anyOf"].([]any); ok && len(sub) > 0 {
		var first *violation
		matched := false
		for _, alt := range sub {
			viol := c.validate(alt, v, ptr, depth+1)
			if viol == nil {
				matched = true
				break
			}
			if first == nil {
				first = viol
			}
		}
		if !matched {
			return first
		}
	}
	if sub, ok := s["oneOf"].([]any); ok && len(sub) > 0 {
		count := 0
		var first *violation
		for _, alt := range sub {
			viol := c.validate(alt, v, ptr, depth+1)
			if viol == nil {
				count++
			} else if first == nil {
				first = viol
			}
		}
		if count == 0 {
			return first
		}
		if count > 1 {
			return &violation{ptr, "value matches more than one alternative"}
		}
	}
	switch x := v.(type) {
	case string:
		n := utf8.RuneCountInString(x)
		if m, ok := numFloat(s["minLength"]); ok && float64(n) < m {
			return &violation{ptr, "string is too short"}
		}
		if m, ok := numFloat(s["maxLength"]); ok && float64(n) > m {
			return &violation{ptr, "string is too long"}
		}
		if p, ok := s["pattern"].(string); ok {
			if re := cachedRegexp(p); re != nil && !re.MatchString(x) {
				return &violation{ptr, "string does not match the pattern"}
			}
		}
		if f, ok := s["format"].(string); ok && !formatOK(f, x) {
			return &violation{ptr, "string is not a valid " + f}
		}
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return &violation{ptr, "number out of range"}
		}
		if m, ok := numFloat(s["minimum"]); ok && f < m {
			return &violation{ptr, "number is below the minimum"}
		}
		if m, ok := numFloat(s["maximum"]); ok && f > m {
			return &violation{ptr, "number is above the maximum"}
		}
		if m, ok := numFloat(s["exclusiveMinimum"]); ok && f <= m {
			return &violation{ptr, "number is not above the exclusive minimum"}
		}
		if m, ok := numFloat(s["exclusiveMaximum"]); ok && f >= m {
			return &violation{ptr, "number is not below the exclusive maximum"}
		}
		if m, ok := numFloat(s["multipleOf"]); ok && m > 0 {
			if q := f / m; math.Abs(q-math.Round(q)) > 1e-9 {
				return &violation{ptr, "number is not a multiple"}
			}
		}
	case []any:
		if m, ok := numFloat(s["minItems"]); ok && float64(len(x)) < m {
			return &violation{ptr, "array has too few items"}
		}
		if m, ok := numFloat(s["maxItems"]); ok && float64(len(x)) > m {
			return &violation{ptr, "array has too many items"}
		}
		if items, ok := s["items"]; ok {
			for i, e := range x {
				if viol := c.validate(items, e, ptr+"/"+strconv.Itoa(i), depth+1); viol != nil {
					return viol
				}
			}
		}
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, present := x[name]; !present {
					return &violation{ptr + "/" + escapePointer(name), "required property is missing"}
				}
			}
		}
		for _, k := range sortedKeys(x) {
			if ps, ok := props[k]; ok {
				if viol := c.validate(ps, x[k], ptr+"/"+escapePointer(k), depth+1); viol != nil {
					return viol
				}
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					return &violation{ptr + "/" + escapePointer(k), "property is not allowed"}
				}
			case map[string]any:
				if viol := c.validate(ap, x[k], ptr+"/"+escapePointer(k), depth+1); viol != nil {
					return viol
				}
			}
		}
	}
	return nil
}

func formatOK(format, s string) bool {
	switch format {
	case "date-time":
		_, err := time.Parse(time.RFC3339, s)
		return err == nil
	case "date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	}
	return true
}

// coerceParam turns a raw parameter string into a JSON value for validation
// according to the schema type.
func (c *schemaCtx) coerceParam(schema any, raw string) any {
	s := c.flat(schema, 0)
	switch primaryType(s) {
	case "integer", "number":
		if _, err := strconv.ParseFloat(raw, 64); err == nil {
			return json.Number(raw)
		}
	case "boolean":
		if raw == "true" || raw == "false" {
			return raw == "true"
		}
	}
	return raw
}

// ---- value generation ----

// builder produces response values from schemas, entity overlays and
// examples. It never invents data beyond what the contract annotates.
type builder struct {
	sc       *schemaCtx
	now      time.Time
	seed     uint64
	key      string            // stable per request, feeds synthetic ids
	prefixes map[string]string // id domain -> id prefix
	fmts     map[string]*idfmt.Template
	// doc gives the synthetic text of the documents of the request (nil:
	// the date only).
	doc func() synthdoc.Text
}

func (b *builder) hashN(name string, mod uint64) uint64 {
	h := fnv.New64a()
	var tmp [8]byte
	for i := 0; i < 8; i++ {
		tmp[i] = byte(b.seed >> (8 * i))
	}
	_, _ = h.Write(tmp[:])
	_, _ = h.Write([]byte(b.key))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	return h.Sum64() % mod
}

type optVal struct {
	v  any
	ok bool
}

func some(v any) optVal { return optVal{v, true} }

// build produces a value for schema. ov is an entity overlay (values by
// property name, taking priority), ex is a fallback example for the same
// position.
func (b *builder) build(schema any, ov, ex optVal, name string, depth int) any {
	if depth > maxSchemaDepth {
		return nil
	}
	if !ov.ok {
		if kind, class, ok := docSchema(b.sc.flat(schema, 0)); ok {
			// a document is always generated, never the contract example
			return b.docBase64(kind, class)
		}
		if ex.ok {
			return b.withDocs(schema, cloneJSON(ex.v), depth)
		}
		return b.generate(schema, name, depth)
	}
	s := b.sc.flat(schema, 0)
	if ov.v == nil && !allowsNull(s) {
		// a null state value where the contract forbids null: fall back to a synthetic value
		return b.build(schema, optVal{}, ex, name, depth)
	}
	switch o := ov.v.(type) {
	case entOverlay:
		return b.buildObject(s, o.vals, o.rel, ex, depth)
	case map[string]any:
		return b.buildObject(s, o, nil, ex, depth)
	case []any:
		items, hasItems := s["items"]
		if !hasItems {
			return cloneJSON(o)
		}
		var exItem optVal
		if ea, ok := ex.v.([]any); ok && len(ea) > 0 {
			exItem = some(ea[0])
		}
		out := make([]any, 0, len(o))
		for _, e := range o {
			out = append(out, b.build(items, some(e), exItem, name, depth+1))
		}
		return out
	default:
		return cloneJSON(ov.v)
	}
}

// entOverlay is the overlay of an entity: its values by property name plus the
// names of its relation fields, which are never invented (a required one that
// is missing comes out null where the schema allows it, and is omitted
// otherwise).
type entOverlay struct {
	vals map[string]any
	rel  map[string]bool
}

func (b *builder) buildObject(s map[string]any, o map[string]any, rel map[string]bool, ex optVal, depth int) any {
	props, _ := s["properties"].(map[string]any)
	if len(props) == 0 {
		return cloneJSON(o)
	}
	exMap, _ := ex.v.(map[string]any)
	req := requiredSet(s)
	out := map[string]any{}
	for _, k := range sortedKeys(props) {
		var exv optVal
		if ex.ok {
			if e, ok := exMap[k]; ok {
				exv = some(e)
			}
		}
		if disc, vals, ok := whenOf(b.sc.flat(props[k], 0)); ok && !req[k] {
			// Conditional property (x-tt-when): present exactly while the
			// sibling holds one of the listed values, so a CANCELLED shipment
			// carries cancelReason and a shipment in any other state never does.
			dv, _ := o[disc].(string)
			if !containsString(vals, dv) {
				continue
			}
			if pv, ok := o[k]; ok {
				if _, omit := pv.(omitValue); !omit {
					out[k] = b.build(props[k], some(pv), exv, k, depth+1)
				}
			} else if exv.ok {
				out[k] = cloneJSON(exv.v)
			} else if v, ok := b.pickEnum(b.sc.flat(props[k], 0), k); ok {
				out[k] = v
			} else {
				out[k] = b.generate(props[k], k, depth+1)
			}
			continue
		}
		if pv, ok := o[k]; ok {
			if _, omit := pv.(omitValue); omit {
				continue
			}
			out[k] = b.build(props[k], some(pv), exv, k, depth+1)
		} else if req[k] {
			if rel[k] {
				if allowsNull(b.sc.flat(props[k], 0)) {
					out[k] = nil
				}
				continue
			}
			out[k] = b.build(props[k], optVal{}, exv, k, depth+1)
		}
	}
	b.dependencies(s, out, func(f string) bool {
		v, ok := o[f]
		if _, omit := v.(omitValue); omit {
			return false
		}
		return ok
	})
	return out
}

// dependencies keeps the dependent fields of a built object coherent
// (x-tt-dependencies): the values of the entity state (from the request or a
// rule) stay as they are; generated values are chosen among the observed
// combinations that agree with them, deterministically per request.
func (b *builder) dependencies(s map[string]any, out map[string]any, fixed func(string) bool) {
	deps := fielddeps.Parse(s)
	if len(deps) == 0 {
		return
	}
	props, _ := s["properties"].(map[string]any)
	req := requiredSet(s)
	fielddeps.Enforce(deps, out, fielddeps.Options{
		Fixed:    fixed,
		Required: func(f string) bool { return req[f] },
		Choose:   func(n int) int { return int(b.hashN("deps", uint64(n))) },
		Fresh:    true,
		Make: func(f string, v fielddeps.Value) any {
			if !v.Band {
				return cloneJSON(v.Lit)
			}
			integer := primaryType(b.sc.flat(props[f], 0)) == "integer"
			frac := float64(b.hashN("deps/"+f, 1000)) / 1000
			x := fielddeps.BandNumber(v, integer, frac)
			if integer {
				return json.Number(strconv.FormatInt(int64(x), 10))
			}
			return json.Number(strconv.FormatFloat(x, 'f', -1, 64))
		},
	})
}

// generate builds a value from the schema alone.
func (b *builder) generate(schema any, name string, depth int) any {
	if depth > maxSchemaDepth {
		return nil
	}
	s := b.sc.flat(schema, 0)
	if kind, class, ok := docSchema(s); ok {
		return b.docBase64(kind, class)
	}
	if ex, ok := s["example"]; ok {
		return cloneJSON(ex)
	}
	if exs, ok := s["examples"].([]any); ok && len(exs) > 0 {
		return cloneJSON(exs[0])
	}
	if xv, ok := s["x-tt-value"].(map[string]any); ok {
		if v, ok := b.fromXTT(xv, s, name); ok {
			return v
		}
	}
	if e, ok := s["enum"].([]any); ok && len(e) > 0 {
		return cloneJSON(e[0])
	}
	if cv, ok := s["const"]; ok {
		return cloneJSON(cv)
	}
	if d, ok := s["default"]; ok {
		return cloneJSON(d)
	}
	switch primaryType(s) {
	case "object":
		props, _ := s["properties"].(map[string]any)
		req := requiredSet(s)
		out := map[string]any{}
		for _, k := range sortedKeys(props) {
			ps := b.sc.flat(props[k], 0)
			include := req[k]
			if !include {
				if p, ok := numFloat(ps["x-tt-presence"]); ok && p >= 0.5 {
					include = true
				}
			}
			if include {
				out[k] = b.generate(props[k], k, depth+1)
			}
		}
		b.dependencies(s, out, nil)
		return out
	case "array":
		n := 1
		if m, ok := numFloat(s["minItems"]); ok && int(m) > n {
			n = int(m)
		}
		if n > 16 {
			n = 16
		}
		items, ok := s["items"]
		out := []any{}
		if !ok {
			return out
		}
		for i := 0; i < n; i++ {
			out = append(out, b.generate(items, name, depth+1))
		}
		return out
	case "string":
		return b.genString(s, name)
	case "integer", "number":
		if m, ok := numFloat(s["minimum"]); ok {
			if primaryType(s) == "integer" {
				return json.Number(strconv.FormatInt(int64(math.Ceil(m)), 10))
			}
			return json.Number(strconv.FormatFloat(m, 'f', -1, 64))
		}
		return json.Number("0")
	case "boolean":
		return false
	}
	if ts := schemaTypes(s); len(ts) > 0 && ts[0] == "null" {
		return nil
	}
	return nil
}

func (b *builder) genString(s map[string]any, name string) any {
	switch f, _ := s["format"].(string); f {
	case "date-time":
		return b.now.UTC().Format(time.RFC3339)
	case "date":
		return b.now.UTC().Format("2006-01-02")
	case "email":
		return "user@example.com"
	case "uuid":
		return b.uuid(name)
	case "uri", "url":
		return "https://example.com/"
	case "ipv4":
		return "192.0.2.1"
	}
	return "synthetic"
}

func (b *builder) uuid(name string) string {
	a, c := b.hashN(name+"/a", math.MaxUint64), b.hashN(name+"/b", math.MaxUint64)
	h := fmt.Sprintf("%016x%016x", a, c)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

// fromXTT applies the x-tt-value annotation (docs/spec/pack.md section 4.1).
func (b *builder) fromXTT(xv, s map[string]any, name string) (any, bool) {
	if lo, hi, ok := dateoff.FromXTT(xv); ok {
		// a relative date (pack.md 4.4): virtual clock + an offset of the
		// range, stable per request
		frac := float64(b.hashN("date/"+name, 1_000_000)) / 1_000_000
		return dateoff.Value(b.now, lo, hi, frac, dateFormat(s, xv)), true
	}
	kind, _ := xv["kind"].(string)
	switch kind {
	case "id":
		domain, _ := xv["domain"].(string)
		if t := b.fmts[domain]; t != nil {
			// The same window of ids the gate checks (pack.md 4.3).
			return t.ID(1+b.hashN("id/"+domain+"/"+name, 1000), domain, nil), true
		}
		prefix := b.prefixes[domain]
		if prefix == "" {
			prefix = "OBJ-SYN-"
		}
		return prefix + fmt.Sprintf("%04d", b.hashN("id/"+domain+"/"+name, 10000)), true
	case "enum":
		if e, ok := xv["enum"].([]any); ok && len(e) > 0 {
			return cloneJSON(e[0]), true
		}
	case "bucket":
		bounds, _ := xv["bounds"].([]any)
		probs, _ := xv["bucket_p"].([]any)
		if len(bounds) > 0 && len(probs) == len(bounds)+1 {
			best, bestP := 0, -1.0
			for i, p := range probs {
				if f, ok := numFloat(p); ok && f > bestP {
					best, bestP = i, f
				}
			}
			switch {
			case best == 0:
				if f, ok := numFloat(bounds[0]); ok {
					return json.Number(strconv.FormatFloat(f-1, 'f', -1, 64)), true
				}
			default:
				if f, ok := numFloat(bounds[best-1]); ok {
					return json.Number(strconv.FormatFloat(f, 'f', -1, 64)), true
				}
			}
		}
	case "shape":
		f, _ := xv["format"].(string)
		switch f {
		case "email":
			return "user@example.com", true
		case "phone":
			return "+39 555 0100", true
		case "uuid":
			return b.uuid(name), true
		case "url":
			return "https://example.com/", true
		case "ipv4":
			return "192.0.2.1", true
		case "datetime":
			return b.now.UTC().Format(time.RFC3339), true
		case "date":
			return b.now.UTC().Format("2006-01-02"), true
		case "digits":
			return "0000", true
		case "hex":
			return "00ff", true
		}
	}
	return nil, false
}

// dateFormat is "date" for a date field, "date-time" otherwise.
func dateFormat(s, xv map[string]any) string {
	if f, _ := s["format"].(string); f == "date" {
		return "date"
	}
	if f, _ := xv["format"].(string); f == "date" {
		return "date"
	}
	if u, _ := xv["unit"].(string); (u == "day" || u == "month" || u == "year") && s["format"] != "date-time" {
		return "date"
	}
	return "date-time"
}

func allowsNull(s map[string]any) bool {
	ts := schemaTypes(s)
	if len(ts) == 0 {
		return true
	}
	for _, t := range ts {
		if t == "null" {
			return true
		}
	}
	return false
}
