package graphql

import (
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
)

// IntrospectionFromEvent rebuilds the introspection result of a captured
// introspection exchange (sanitizer.md 5.7.2) from the response body of the
// event: gql: names become strings, every other token (descriptions,
// default values, deprecation reasons: free text the source never lets
// out) becomes null, drop:bool becomes false, truncation markers are left
// out. It returns the value of data (an object with __schema and/or
// __type), or false when the body holds no usable schema (at least one
// named type is needed).
func IntrospectionFromEvent(ev *event.Event) (map[string]any, bool) {
	if ev.Resp == nil || ev.Resp.Body == nil || ev.Resp.Body.Kind != event.Object {
		return nil, false
	}
	data, ok := ev.Resp.Body.Get("data")
	if !ok || data.Kind != event.Object {
		return nil, false
	}
	out, _ := fromTokens(data).(map[string]any)
	if out == nil {
		return nil, false
	}
	sch, _ := out["__schema"].(map[string]any)
	if sch == nil {
		return nil, false
	}
	types, _ := sch["types"].([]any)
	named := 0
	for _, t := range types {
		if m, _ := t.(map[string]any); m != nil {
			if n, _ := m["name"].(string); n != "" {
				named++
			}
		}
	}
	if named == 0 {
		return nil, false
	}
	return out, true
}

func fromTokens(v *event.Value) any {
	switch v.Kind {
	case event.Object:
		m := map[string]any{}
		for i := range v.O {
			k := v.O[i].K
			if k == "{*}" || k == "{trunc}" {
				continue
			}
			m[k] = fromTokens(&v.O[i].V)
		}
		return m
	case event.Array:
		a := make([]any, 0, len(v.A))
		for i := range v.A {
			e := &v.A[i]
			if e.Kind == event.String && strings.HasPrefix(e.S, "trunc:") {
				continue
			}
			a = append(a, fromTokens(e))
		}
		return a
	case event.String:
		switch {
		case strings.HasPrefix(v.S, "gql:"):
			if n := v.S[4:]; IsName(n) {
				return n
			}
		case v.S == "drop:bool":
			return false
		}
		return nil
	case event.Bool:
		return v.B
	}
	return nil
}
