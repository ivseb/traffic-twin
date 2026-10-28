package world

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Small helpers over OpenAPI 3.1 documents decoded as generic JSON (numbers
// as json.Number).

type openapi struct {
	doc map[string]any
}

var methods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

// op returns the operation object of "METHOD /path".
func (o *openapi) op(op string) map[string]any {
	m, p, ok := strings.Cut(op, " ")
	if !ok || o == nil {
		return nil
	}
	paths, _ := o.doc["paths"].(map[string]any)
	item, _ := paths[p].(map[string]any)
	v, _ := item[strings.ToLower(m)].(map[string]any)
	return v
}

// ops lists every operation as "METHOD /path", sorted.
func (o *openapi) ops() []string {
	var out []string
	paths, _ := o.doc["paths"].(map[string]any)
	for p, it := range paths {
		item, _ := it.(map[string]any)
		for _, m := range methods {
			if _, ok := item[m]; ok {
				out = append(out, strings.ToUpper(m)+" "+p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// resolve follows local $ref chains.
func (o *openapi) resolve(s map[string]any) map[string]any {
	for i := 0; i < 16 && s != nil; i++ {
		ref, ok := s["$ref"].(string)
		if !ok {
			return s
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil
		}
		var cur any = o.doc
		for _, part := range strings.Split(ref[2:], "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			m, _ := cur.(map[string]any)
			cur = m[part]
		}
		s, _ = cur.(map[string]any)
	}
	return s
}

func jsonSchemaOf(content any) map[string]any {
	c, _ := content.(map[string]any)
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(k, "json") {
			mt, _ := c[k].(map[string]any)
			s, _ := mt["schema"].(map[string]any)
			return s
		}
	}
	return nil
}

// requestSchema returns the JSON request body schema of op.
func (o *openapi) requestSchema(op string) map[string]any {
	rb, _ := o.op(op)["requestBody"].(map[string]any)
	return o.resolve(jsonSchemaOf(rb["content"]))
}

// successStatus returns the 2xx response with the highest x-tt-frequency
// (ties: the lowest code), as the mock does (docs/spec/mock.md 2.5).
func (o *openapi) successStatus(op string) (int, map[string]any) {
	resps, _ := o.op(op)["responses"].(map[string]any)
	best, bestF := 0, -1.0
	var bestR map[string]any
	for code, r := range resps {
		n, err := strconv.Atoi(code)
		if err != nil || n < 200 || n > 299 {
			continue
		}
		rm, _ := r.(map[string]any)
		f := 0.0
		if v, ok := rm["x-tt-frequency"].(json.Number); ok {
			f, _ = v.Float64()
		}
		if f > bestF || (f == bestF && n < best) {
			best, bestF, bestR = n, f, rm
		}
	}
	return best, bestR
}

// responseSchema returns the JSON schema of the success response of op.
func (o *openapi) responseSchema(op string) map[string]any {
	_, r := o.successStatus(op)
	return o.resolve(jsonSchemaOf(r["content"]))
}

// schemaAt descends a schema along a simple path "$", "$.a.b" or
// "$.items[*]".
func (o *openapi) schemaAt(s map[string]any, path string) map[string]any {
	path = strings.TrimPrefix(path, "$")
	for path != "" && s != nil {
		s = o.resolve(s)
		switch {
		case strings.HasPrefix(path, "[*]"):
			it, _ := s["items"].(map[string]any)
			s, path = it, path[3:]
		case strings.HasPrefix(path, "."):
			path = path[1:]
			end := strings.IndexAny(path, ".[")
			name := path
			if end >= 0 {
				name, path = path[:end], path[end:]
			} else {
				path = ""
			}
			props, _ := s["properties"].(map[string]any)
			s, _ = props[name].(map[string]any)
		default:
			return nil
		}
	}
	return o.resolve(s)
}

// props returns the property names of an object schema.
func (o *openapi) props(s map[string]any) map[string]bool {
	out := map[string]bool{}
	s = o.resolve(s)
	p, _ := s["properties"].(map[string]any)
	for k := range p {
		out[k] = true
	}
	return out
}

func schemaTypes(s map[string]any) []string {
	switch t := s["type"].(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if v, ok := x.(string); ok {
				out = append(out, v)
			}
		}
		return out
	}
	if _, ok := s["properties"]; ok {
		return []string{"object"}
	}
	return nil
}

func mainType(s map[string]any) string {
	for _, t := range schemaTypes(s) {
		if t != "null" {
			return t
		}
	}
	return ""
}

func numOf(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
