package world

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// refVar reports whether s is exactly "${name}" (not ${effect:...}).
func refVar(s string) (string, bool) {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") || strings.HasPrefix(s, "${effect:") {
		return "", false
	}
	n := s[2 : len(s)-1]
	return n, n != ""
}

// refEffect reports whether s is exactly "${effect:id}".
func refEffect(s string) (string, bool) {
	if !strings.HasPrefix(s, "${effect:") || !strings.HasSuffix(s, "}") {
		return "", false
	}
	n := s[len("${effect:") : len(s)-1]
	return n, n != ""
}

// getPath reads "$", "$.a.b" (or "a.b") in a generic JSON object.
func getPath(v any, path string) any {
	path = strings.TrimPrefix(strings.TrimPrefix(path, "$"), ".")
	if path == "" {
		return v
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}

// setPath writes a dotted field path, creating intermediate objects.
func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = v
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

func jsonEqual(a, b any) bool {
	na, oka := numOf(a)
	nb, okb := numOf(b)
	if oka && okb {
		return na == nb
	}
	return reflect.DeepEqual(a, b)
}

// toValue converts generic JSON (numbers as json.Number, float64 or ints)
// to a ttjson tree.
func toValue(v any) (ttjson.Value, error) {
	switch x := v.(type) {
	case nil:
		return ttjson.Value{Kind: ttjson.Null}, nil
	case bool:
		return ttjson.BoolV(x), nil
	case string:
		return ttjson.Str(x), nil
	case json.Number:
		return ttjson.Num(x.String()), nil
	case float64:
		return ttjson.Num(strconv.FormatFloat(x, 'g', -1, 64)), nil
	case int:
		return ttjson.Num(strconv.Itoa(x)), nil
	case int64:
		return ttjson.Num(strconv.FormatInt(x, 10)), nil
	case uint64:
		return ttjson.Num(strconv.FormatUint(x, 10)), nil
	case []any:
		out := ttjson.Value{Kind: ttjson.Array, Arr: make([]ttjson.Value, 0, len(x))}
		for _, e := range x {
			ev, err := toValue(e)
			if err != nil {
				return ev, err
			}
			out.Arr = append(out.Arr, ev)
		}
		return out, nil
	case []string:
		out := ttjson.Value{Kind: ttjson.Array, Arr: []ttjson.Value{}}
		for _, e := range x {
			out.Arr = append(out.Arr, ttjson.Str(e))
		}
		return out, nil
	case map[string]any:
		out := ttjson.Value{Kind: ttjson.Object, Obj: make([]ttjson.Member, 0, len(x))}
		for _, k := range sortedKeys(x) {
			ev, err := toValue(x[k])
			if err != nil {
				return ev, err
			}
			out.Obj = append(out.Obj, ttjson.Member{Key: k, Value: ev})
		}
		return out, nil
	}
	return ttjson.Value{}, fmt.Errorf("world: unsupported JSON value %T", v)
}

// canonicalJSON encodes generic JSON in tt canonical form (no newline).
func canonicalJSON(v any) ([]byte, error) {
	tv, err := toValue(v)
	if err != nil {
		return nil, err
	}
	return ttjson.Encode(tv)
}

// CanonicalFile encodes v as a canonical JSON file (final newline).
func CanonicalFile(v any) ([]byte, error) {
	b, err := canonicalJSON(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Canonicalize re-encodes a JSON document in canonical form (final
// newline).
func Canonicalize(doc []byte) ([]byte, error) {
	v, err := ttjson.Parse(doc, ttjson.ParseOptions{MaxDepth: 128, RejectDuplicates: true})
	if err != nil {
		return nil, errors.New("world: not valid JSON")
	}
	b, err := ttjson.Encode(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeGeneric decodes JSON with numbers as json.Number.
func DecodeGeneric(b []byte, v any) error { return decodeUseNumber(b, v) }
