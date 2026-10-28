package contract

import (
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

// Examples are synthetic: they are generated from the annotations of the
// schema (types, formats, enums, domains, buckets) with invented
// placeholder values. They are never built from stored values, which only
// exist as shapes and tokens anyway. Reserved domains (example.com, +39 555)
// are used so that the pii-detectors check of the gate accepts them.

type exMode int

const (
	exMinimal exMode = iota // required properties only
	exTypical               // required and likely properties (presence >= 0.5)
	exFull                  // every property
)

// examplesFor returns the OpenAPI "examples" object for a body schema:
// "typical" (plus "full" and "minimal" when they differ) for a success or a
// request, one example per error code (published enum of a code-like field)
// for an error response.
func examplesFor(s *Schema, response bool, status int) map[string]any {
	if s == nil || (!s.HasType("object") && !s.HasType("array")) {
		return nil
	}
	out := map[string]any{}
	if response && status >= 400 {
		if path, vals := errorCodeField(s); path != nil {
			for _, v := range vals {
				name := kebab(v)
				if name == "" {
					continue
				}
				doc := gen(s, exTypical, "")
				setPath(doc, path, v)
				out[name] = map[string]any{"value": doc}
				if len(out) >= 8 {
					break
				}
			}
		}
		if len(out) == 0 {
			out[kebab(statusText(status))] = map[string]any{"value": gen(s, exTypical, "")}
		}
		return out
	}
	typ := gen(s, exTypical, "")
	out["typical"] = map[string]any{"value": typ}
	if full := gen(s, exFull, ""); !reflect.DeepEqual(full, typ) {
		out["full"] = map[string]any{"value": full}
	}
	if min := gen(s, exMinimal, ""); !reflect.DeepEqual(min, typ) {
		out["minimal"] = map[string]any{"value": min}
	}
	for name, ex := range stateExamples(s) {
		if _, taken := out[name]; !taken {
			out[name] = ex
		}
	}
	return out
}

var codeNames = map[string]bool{"code": true, "error_code": true, "errorCode": true, "error": true, "type": true, "reason": true, "title": true}

// errorCodeField finds, within three levels, a string property with a
// code-like name and a published enum, and returns its path and values.
func errorCodeField(s *Schema) ([]string, []string) {
	type item struct {
		s    *Schema
		path []string
	}
	queue := []item{{s, nil}}
	for depth := 0; depth < 4 && len(queue) > 0; depth++ {
		var next []item
		for _, it := range queue {
			for _, p := range it.s.Props {
				path := append(append([]string(nil), it.path...), p.Name)
				if codeNames[p.Name] && p.Schema.Kind == "enum" && p.Schema.HasType("string") {
					var vals []string
					for _, e := range p.Schema.PublishedEnum() {
						if e.Type == "string" {
							vals = append(vals, e.Value)
						}
					}
					if len(vals) > 0 {
						return path, vals
					}
				}
				if p.Schema.HasType("object") {
					next = append(next, item{p.Schema, path})
				}
			}
		}
		queue = next
	}
	return nil, nil
}

func setPath(doc any, path []string, v any) {
	m, ok := doc.(map[string]any)
	if !ok || len(path) == 0 {
		return
	}
	if len(path) == 1 {
		m[path[0]] = v
		return
	}
	setPath(m[path[0]], path[1:], v)
}

func kebab(s string) string {
	var sb strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			sb.WriteRune(r)
			dash = false
		} else if !dash && sb.Len() > 0 {
			sb.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(sb.String(), "-")
}

// gen builds a synthetic value for s.
func gen(s *Schema, mode exMode, name string) any { return genF(s, mode, name, nil) }

// genF is gen with forced values for enum properties by name (used to build
// one example per state); a conditional property (Prop.When) is present only
// when the sibling it depends on holds one of its values, so an example
// never mixes fields of different states.
func genF(s *Schema, mode exMode, name string, force map[string]string) any {
	if s == nil {
		return nil
	}
	switch s.primary() {
	case "object":
		m := map[string]any{}
		for _, p := range s.Props {
			if p.When != nil {
				continue
			}
			include := p.Required
			switch mode {
			case exTypical:
				include = include || p.Presence >= 0.5
			case exFull:
				include = true
			}
			if include {
				if fv, ok := force[p.Name]; ok && p.Schema != nil && p.Schema.Kind == "enum" {
					m[p.Name] = fv
				} else {
					m[p.Name] = genF(p.Schema, mode, p.Name, force)
				}
			}
		}
		exampleDeps(s, m, force)
		for _, p := range s.Props {
			if p.When == nil {
				continue
			}
			if dv, ok := m[p.When.Prop].(string); ok && containsStr(p.When.In, dv) {
				m[p.Name] = genF(p.Schema, mode, p.Name, force)
			}
		}
		if s.Additional != nil && (mode != exMinimal || len(s.Props) == 0) {
			m["key-1"] = genF(s.Additional, mode, "key-1", force)
		}
		return m
	case "array":
		if s.Items == nil {
			return []any{}
		}
		n := 1
		if s.MinItems != nil && *s.MinItems > 1 {
			n = *s.MinItems
		}
		if n > 3 {
			n = 3
		}
		out := make([]any, n)
		for i := range out {
			out[i] = genF(s.Items, mode, name, force)
		}
		return out
	case "string":
		return genString(s)
	case "integer":
		return intExample(s)
	case "number":
		return numExample(s)
	case "boolean":
		return true
	}
	return nil
}

// primary returns the first non-null type of the union by schema order.
func (s *Schema) primary() string {
	for _, t := range s.Types {
		if t != "null" {
			return t
		}
	}
	if len(s.Types) == 1 && s.Types[0] == "null" {
		return "null"
	}
	return ""
}

func intExample(s *Schema) any {
	if s.Kind == "enum" {
		if e := topEnum(s); e != nil {
			return num(e.Value)
		}
	}
	if s.Kind == "bucket" {
		if v, ok := bucketExample(s); ok {
			return num(strconv.FormatFloat(v, 'f', 0, 64))
		}
	}
	return int64(1)
}

func numExample(s *Schema) any {
	if s.Kind == "enum" {
		if e := topEnum(s); e != nil {
			return num(e.Value)
		}
	}
	if s.Kind == "bucket" {
		if v, ok := bucketExample(s); ok {
			return num(strconv.FormatFloat(v, 'f', -1, 64))
		}
	}
	return 1.5
}

// topEnum returns the most frequent published enum value.
func topEnum(s *Schema) *EnumValue {
	var best *EnumValue
	for i := range s.Enum {
		e := &s.Enum[i]
		if !e.Published {
			continue
		}
		if best == nil || e.Count > best.Count {
			best = e
		}
	}
	return best
}

// bucketExample picks a value inside the most probable band.
func bucketExample(s *Schema) (float64, bool) {
	if len(s.Bounds) == 0 || len(s.BucketP) != len(s.Bounds)+1 {
		return 0, false
	}
	best, bp := 0, -1.0
	for i, p := range s.BucketP {
		if p > bp {
			best, bp = i, p
		}
	}
	bv := func(i int) float64 { f, _ := strconv.ParseFloat(s.Bounds[i], 64); return f }
	switch {
	case best == 0:
		return bv(0) - 1, true
	case best == len(s.Bounds):
		return bv(len(s.Bounds) - 1), true
	default:
		return bv(best - 1), true
	}
}

func genString(s *Schema) any {
	switch s.Kind {
	case "id":
		return idExample(s.Domain)
	case "enum":
		if e := topEnum(s); e != nil {
			return e.Value
		}
	case "bucket":
		return timeExample(s.Unit)
	}
	switch s.Shape {
	case "doc":
		return docExample(s.DocType)
	case "email":
		return "user@example.com"
	case "phone":
		return "+39 555 0100"
	case "uuid":
		return "00000000-0000-4000-8000-000000000000"
	case "url":
		return "https://example.com/"
	case "ipv4":
		return "192.0.2.1"
	case "datetime":
		return "2026-10-19T10:00:00Z"
	case "date":
		return "2026-10-19"
	case "digits":
		return "0000"
	case "hex":
		return "00ff00ff00ff00ff"
	case "jwt":
		return "eyJzeW50aGV0aWMiOjF9.eyJzeW50aGV0aWMiOjF9.c3ludGhldGlj"
	}
	if s.Format == "date-time" {
		return "2026-10-19T10:00:00Z"
	}
	switch s.LenClass {
	case "l8":
		return "sample"
	case "l128":
		return fill(64)
	case "l1024":
		return fill(256)
	case "lmax":
		return fill(1100)
	}
	return "synthetic"
}

func fill(n int) string {
	const unit = "synthetic text "
	return strings.Repeat(unit, n/len(unit)+1)[:n-1] + "."
}

func timeExample(unit string) string {
	switch unit {
	case "year":
		return "2026-01-01T00:00:00Z"
	case "month":
		return "2026-10-01T00:00:00Z"
	case "hour":
		return "2026-10-19T10:00:00Z"
	}
	return "2026-10-19T00:00:00Z"
}

// idExample returns a synthetic identifier: the same domain always yields
// the same value, so that fields linked by a key agree inside an example.
// The id formats (internal/idfmt) replace exactly these values.
func idExample(domain string) string { return idfmt.ExampleID(domain) }

func containsStr(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// stateExamples builds one full example per value that switches a
// conditional property on (status CANCELLED -> cancelReason), named after
// the value.
func stateExamples(root *Schema) map[string]any {
	out := map[string]any{}
	obj := root
	if root != nil && root.primary() == "array" {
		obj = root.Items
	}
	if obj == nil {
		return out
	}
	for _, p := range obj.Props {
		if p.When == nil {
			continue
		}
		for _, v := range p.When.In {
			name := kebab(v)
			if name == "" || out[name] != nil || len(out) >= 4 {
				continue
			}
			out[name] = map[string]any{"value": genF(root, exFull, "", map[string]string{p.When.Prop: v})}
		}
	}
	return out
}

// docExample is a small valid synthetic document of the type, in base64
// (docs/spec/mock.md 2.9), or the base64 of "synthetic" for the file types
// the mock does not generate.
func docExample(typ string) string {
	if synthdoc.Known(typ) {
		if b, err := synthdoc.Generate(typ, "", synthdoc.Text{Refs: []string{"DOC-SYN-0001"}}); err == nil {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return "c3ludGhldGlj"
}
