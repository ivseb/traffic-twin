package world

import (
	"sort"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Scope of the rules v1.9 members (customer attributes, aggregates, list
// operations): a pack of some services keeps only those whose operations
// are all of them, so that the mock never meets an operation it has no
// contract for.

// scopeAttributes keeps the attribute fields of the services in scope and
// the attributes with at least one field; attrDocs are their generic forms.
func scopeAttributes(r *Rules, in map[string]bool) ([]pack.Attribute, []any) {
	var out []pack.Attribute
	for _, a := range r.Attributes {
		var fs []pack.AttrField
		for _, f := range a.Fields {
			if in[f.Service] {
				fs = append(fs, f)
			}
		}
		if len(fs) > 0 {
			a.Fields = fs
			out = append(out, a)
		}
	}
	var docs []any
	list, _ := r.Doc["attributes"].([]any)
	keep := map[string]bool{}
	for _, a := range out {
		keep[a.Name] = true
	}
	for _, x := range list {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := m["name"].(string); !keep[n] {
			continue
		}
		cp := make(map[string]any, len(m))
		for k, v := range m {
			cp[k] = v
		}
		var fs []any
		if l, ok := m["fields"].([]any); ok {
			for _, f := range l {
				if fm, ok := f.(map[string]any); ok {
					if s, _ := fm["service"].(string); in[s] {
						fs = append(fs, f)
					}
				}
			}
		}
		cp["fields"] = fs
		docs = append(docs, cp)
	}
	return out, docs
}

// missingAttributes lists the customer attributes a rule names that the
// scope left out.
func missingAttributes(r *Rules, id string, kept []pack.Attribute) []string {
	have := map[string]bool{}
	for _, a := range kept {
		have[a.Name] = true
	}
	miss := map[string]bool{}
	for _, c := range r.Causal {
		if c.ID != id {
			continue
		}
		lists := [][]pack.Match{c.Cause.When.Match}
		for _, o := range c.Outcomes {
			lists = append(lists, o.When)
		}
		for _, ms := range lists {
			for _, m := range ms {
				if m.Customer != "" && !have[m.Customer] {
					miss["attribute:"+m.Customer] = true
				}
			}
		}
	}
	out := make([]string, 0, len(miss))
	for k := range miss {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scopeExtras filters the v1.9 members of a generic document.
func scopeExtras(doc map[string]any, in, keepEnt map[string]bool, attrs []any) {
	if _, ok := doc["attributes"]; ok {
		if len(attrs) == 0 {
			delete(doc, "attributes")
		} else {
			doc["attributes"] = attrs
		}
	}
	if list, ok := doc["aggregates"].([]any); ok {
		var kept []any
		for _, x := range list {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			svc, _ := m["service"].(string)
			good := in[svc]
			for _, k := range []string{"count", "sum"} {
				if c, ok := m[k].(map[string]any); ok {
					if e, _ := c["entity"].(string); !keepEnt[e] {
						good = false
					}
				}
			}
			if ds, ok := m["delta"].([]any); ok {
				for _, d := range ds {
					if dm, ok := d.(map[string]any); ok {
						if s, _ := dm["service"].(string); s != "" && !in[s] {
							good = false
						}
					}
				}
			}
			if good {
				kept = append(kept, x)
			}
		}
		if len(kept) == 0 {
			delete(doc, "aggregates")
		} else {
			doc["aggregates"] = kept
		}
	}
	if list, ok := doc["lists"].([]any); ok {
		var kept []any
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				if s, _ := m["service"].(string); in[s] {
					kept = append(kept, x)
				}
			}
		}
		if len(kept) == 0 {
			delete(doc, "lists")
		} else {
			doc["lists"] = kept
		}
	}
}
