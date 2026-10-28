package mock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// JSON values handled by the mock are the generic Go forms produced by a
// decoder with UseNumber: nil, bool, json.Number, string, []any, map[string]any.

func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func cloneJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneJSON(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneJSON(e)
		}
		return out
	default:
		return v
	}
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return cloneJSON(m).(map[string]any)
}

// numFloat converts any numeric JSON value to float64.
func numFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func isIntegral(n json.Number) bool {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		return true
	}
	r, ok := new(big.Rat).SetString(s)
	return ok && r.IsInt()
}

func jsonEqual(a, b any) bool {
	if fa, ok := numFloat(a); ok {
		fb, ok := numFloat(b)
		return ok && fa == fb
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, e := range x {
			f, ok := y[k]
			if !ok || !jsonEqual(e, f) {
				return false
			}
		}
		return true
	}
	return false
}

// scalarString renders a scalar the way a query/path parameter would carry it.
func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return string(x), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

// getDotted reads a dotted path ("delivery.eta") from a state object.
func getDotted(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// setDotted writes a dotted path, creating intermediate objects (and
// replacing non-object intermediates).
func setDotted(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
}

// ---- tt-path: $ (.name | .* | [*])* ----

type pathSeg struct {
	key  string
	kind int // segKey, segAnyKey, segAnyIdx
}

const (
	segKey = iota
	segAnyKey
	segAnyIdx
)

// .@name and .#text (spec v1.19) select the attributes and the mixed text of
// the XML trees (sanitizer.md 5.0, 22.2).
var ttPathSegRE = regexp.MustCompile(`\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\.#text|\.\*|\[\*\]`)

func parseTTPath(p string) ([]pathSeg, error) {
	if !strings.HasPrefix(p, "$") {
		return nil, fmt.Errorf("path %q does not start with $", p)
	}
	rest := p[1:]
	var segs []pathSeg
	for rest != "" {
		loc := ttPathSegRE.FindStringIndex(rest)
		if loc == nil || loc[0] != 0 {
			return nil, fmt.Errorf("bad path %q", p)
		}
		tok := rest[:loc[1]]
		rest = rest[loc[1]:]
		switch tok {
		case ".*":
			segs = append(segs, pathSeg{kind: segAnyKey})
		case "[*]":
			segs = append(segs, pathSeg{kind: segAnyIdx})
		default:
			segs = append(segs, pathSeg{key: tok[1:], kind: segKey})
		}
	}
	return segs, nil
}

// evalPath returns every value the path selects, in document order (object
// keys sorted for wildcards).
func evalPath(root any, segs []pathSeg) []any {
	cur := []any{root}
	for _, s := range segs {
		var next []any
		for _, c := range cur {
			switch s.kind {
			case segKey:
				if m, ok := c.(map[string]any); ok {
					if v, ok := m[s.key]; ok {
						next = append(next, v)
					}
				}
			case segAnyKey:
				if m, ok := c.(map[string]any); ok {
					keys := make([]string, 0, len(m))
					for k := range m {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						next = append(next, m[k])
					}
				}
			case segAnyIdx:
				if a, ok := c.([]any); ok {
					next = append(next, a...)
				}
			}
		}
		cur = next
	}
	return cur
}

// nest wraps leaf into the structure described by an "at" path made of
// ".name" segments, optionally ending in "[*]" (leaf must then be a []any).
func nest(segs []pathSeg, leaf any) (any, error) {
	for i := len(segs) - 1; i >= 0; i-- {
		switch segs[i].kind {
		case segKey:
			leaf = map[string]any{segs[i].key: leaf}
		case segAnyIdx:
			if i != len(segs)-1 {
				return nil, errors.New("[*] is only supported at the end of an at path")
			}
		default:
			return nil, errors.New("wildcard keys are not supported in an at path")
		}
	}
	return leaf, nil
}

// setAtPath sets ".a.b" style paths in a body (no wildcards).
func setAtPath(body any, segs []pathSeg, v any) bool {
	if len(segs) == 0 {
		return false
	}
	cur, ok := body.(map[string]any)
	if !ok {
		return false
	}
	for _, s := range segs[:len(segs)-1] {
		if s.kind != segKey {
			return false
		}
		cur, ok = cur[s.key].(map[string]any)
		if !ok {
			return false
		}
	}
	last := segs[len(segs)-1]
	if last.kind != segKey {
		return false
	}
	cur[last.key] = v
	return true
}

// escapePointer escapes a JSON pointer token.
func escapePointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

// compactJSON renders v deterministically (sorted keys, no HTML escaping).
func compactJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte("null")
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}
