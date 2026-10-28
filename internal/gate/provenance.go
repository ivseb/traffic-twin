package gate

import (
	"strings"

	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// packContext holds the names and literals declared by the pack's own
// declarative files (contracts and approved rules).
type packContext struct {
	contractKeys map[string]bool // every object key of every contract
	exampleNames map[string]bool // named examples
	ops          map[string]bool // "METHOD /path"
	services     map[string]bool
	ruleLiterals map[string]bool // literal values of approved rules
	ruleNames    map[string]bool // ids, entity, effect, outcome and field names of rules
	ruleTexts    map[string]bool // rule titles
	fieldNames   map[string]bool
	bindVars     map[string]bool
	archetypes   map[string]int
	enumOwners   map[string]bool // values listed in any contract enum
	// attrNames are the customer attributes of the rules (rules v1.9):
	// keys of the world's customer profiles.
	attrNames map[string]bool
}

// attrValueKeys reports whether keys are those of the values of a customer
// attribute (rules v1.9: attributes[].values, keys are the clear values).
func attrValueKeys(keys []string) bool {
	return len(keys) == 3 && keys[0] == "attributes" && keys[1] == "[]" && keys[2] == "values"
}

// conditionValue reports whether keys are those of the values of a
// condition (rules v1.9: cause.when.match[].in, outcomes[].when[].in).
func conditionValue(keys []string) bool {
	return len(keys) >= 3 && last(keys) == "[]" && keys[len(keys)-2] == "in" && has(keys, map[string]bool{"match": true, "when": true})
}

var fieldValueKeys = map[string]bool{"create": true, "set": true, "defaults": true, "where": true, "hidden_when": true, "target_key": true}

func newSet() map[string]bool { return map[string]bool{} }

func buildContext(files []*parsed, in *Input) *packContext {
	c := &packContext{contractKeys: newSet(), exampleNames: newSet(), ops: newSet(), services: newSet(), ruleLiterals: newSet(),
		ruleNames: newSet(), ruleTexts: newSet(), fieldNames: newSet(), bindVars: newSet(),
		archetypes: map[string]int{}, enumOwners: newSet(), attrNames: newSet()}
	for _, a := range in.Archetypes {
		c.archetypes[a.ID] = a.Size
	}
	for _, p := range files {
		if p.bad {
			continue
		}
		switch p.kind {
		case "contract":
			svc := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(p.path, "contracts/"), ".json"), ".openapi")
			if n, ok := in.ContractServices[p.path]; ok {
				svc = n
			}
			c.services[svc] = true
			if paths, ok := p.doc.Get("paths"); ok {
				for _, pm := range paths.Obj {
					for _, mm := range pm.Value.Obj {
						c.ops[strings.ToUpper(mm.Key)+" "+pm.Key] = true
					}
				}
			}
			walk(p.doc, "", nil, func(v ttjson.Value, _ string, keys []string, isKey bool) {
				if isKey {
					c.contractKeys[v.Str] = true
					if last(keys) == "examples" {
						c.exampleNames[v.Str] = true
					}
					return
				}
				if v.Kind == ttjson.String && last(keys) == "[]" && len(keys) > 1 && keys[len(keys)-2] == "enum" {
					c.enumOwners[v.Str] = true
				}
			})
		case "rules":
			walk(p.doc, "", nil, func(v ttjson.Value, _ string, keys []string, isKey bool) {
				inFV := has(keys, fieldValueKeys)
				if isKey && attrValueKeys(keys) {
					c.ruleLiterals[v.Str] = true // a clear value of a customer attribute
					return
				}
				if !isKey && v.Kind == ttjson.String && len(keys) == 3 && keys[0] == "attributes" && keys[2] == "name" {
					c.attrNames[v.Str] = true
				}
				if !isKey && v.Kind == ttjson.String && conditionValue(keys) {
					c.ruleLiterals[v.Str] = true
					return
				}
				if isKey {
					if inFV {
						for _, part := range strings.Split(v.Str, ".") {
							c.fieldNames[part] = true
						}
					}
					if last(keys) == "bind" {
						c.bindVars[v.Str] = true
					}
					return
				}
				if v.Kind != ttjson.String {
					return
				}
				switch {
				case inFV:
					if !strings.HasPrefix(v.Str, "${") {
						c.ruleLiterals[v.Str] = true
					}
				case last(keys) == "title":
					c.ruleTexts[v.Str] = true
				default:
					c.ruleNames[v.Str] = true
					switch last(keys) {
					case "id_field", "field", "order_by":
						c.fieldNames[v.Str] = true
					}
				}
			})
		}
	}
	return c
}

// Provenance: every string must be generated (synthetic), a declared keep
// value or literal of the contracts or approved rules, or structure.

var contractStructural = map[string]bool{
	"openapi": true, "type": true, "format": true, "$ref": true, "operationId": true, "description": true, "summary": true,
	"title": true, "version": true, "in": true, "name": true, "style": true, "x-tt-entity": true, "kind": true, "domain": true,
	"len_class": true, "unit": true, "first_seen": true, "last_seen": true, "contentMediaType": true, "contentEncoding": true,
	"required": true, "jsonSchemaDialect": true, "doc_type": true, "doc_class": true,
}

var exampleKeys = map[string]bool{"example": true, "examples": true, "default": true, "const": true}

func provenance(files []*parsed, c *packContext, in *Input) Check {
	var f findings
	syn := func(s string) bool { return in.Prov.Synthetic[s] }
	declared := func(s string) bool { _, ok := in.Prov.Declared[s]; return ok }
	for _, p := range files {
		if p.bad {
			f.add(p.path, "", "file is not valid JSON")
			continue
		}
		switch p.kind {
		case "contract":
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				if isKey || v.Kind != ttjson.String {
					return
				}
				s := v.Str
				if handled, ok := depsProvenance(s, keys, c, declared); handled {
					if !ok {
						f.add(p.path, ptr, "field dependency names a value or field without provenance")
					}
					return
				}
				switch {
				case last(keys) == idfmt.Key && len(keys) > 1 && keys[len(keys)-2] == "x-tt-value":
					// An id format chosen in the console (pack.md 4.3): a
					// template, structure only.
					if _, err := idfmt.Parse(s); err != nil {
						f.add(p.path, ptr, "id format is not a valid template")
					}
				case len(keys) > 2 && keys[len(keys)-2] == dateoff.Key && keys[len(keys)-3] == "x-tt-value":
					// a relative date (pack.md 4.4): structure only
					if _, err := dateoff.ParseOffset(s); err != nil {
						f.add(p.path, ptr, "relative date is not a valid offset")
					}
				case has(keys, graphqlKeys):
					// GraphQL structure (sanitizer.md 5.7): operation names,
					// document shapes, type references and the names of a
					// captured introspection result, never a value.
					if !graphqlStructural(s) {
						f.add(p.path, ptr, "GraphQL description that is not a name, a shape or an endpoint")
					}
				case has(keys, xmlKeys):
					// XML structure: fmt and namespace patterns, never a value.
					if !xmlStructural(s) {
						f.add(p.path, ptr, "XML description that is not a format or a namespace pattern")
					}
				case has(keys, map[string]bool{"servers": true}):
					if !syn(s) {
						f.add(p.path, ptr, "server address is not synthetic")
					}
				case has(keys, exampleKeys):
					if !syn(s) && !declared(s) && !c.ruleLiterals[s] && !(last(keys) == "summary" || last(keys) == "description") {
						f.add(p.path, ptr, "example value is neither synthetic nor declared")
					}
				case last(keys) == "[]" && len(keys) > 1 && keys[len(keys)-2] == "enum":
					if !declared(s) && !c.ruleLiterals[s] {
						f.add(p.path, ptr, "enum value is not a declared keep value")
					}
				case contractStructural[last(keys)] || (last(keys) == "[]" && len(keys) > 1 && contractStructural[keys[len(keys)-2]]):
				default:
					if !syn(s) && !declared(s) {
						f.add(p.path, ptr, "string without provenance")
					}
				}
			})
		case "rules":
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				if has(keys, map[string]bool{"review": true}) && !isKey && v.Kind == ttjson.String {
					f.add(p.path, ptr, "review identities and notes must not be published")
				}
			})
		case "world":
			worldProvenance(p, c, in, &f)
		case "faults":
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				if isKey || v.Kind != ttjson.String {
					return
				}
				ok := false
				switch last(keys) {
				case "format":
					ok = v.Str == "tt.faults/v1"
				case "service":
					ok = c.services[v.Str]
				case "op":
					ok = c.ops[v.Str]
				case "example":
					ok = c.exampleNames[v.Str]
				case "kind":
					ok = netErrors[v.Str]
				}
				if !ok {
					f.add(p.path, ptr, "string without provenance")
				}
			})
		case "scenarios":
			each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
				if isKey || v.Kind != ttjson.String {
					return
				}
				s := v.Str
				ok := false
				if has(keys, map[string]bool{"body": true}) {
					// an error body typed by a person (mock.md 4.1): the
					// personal data detectors check it (pii-detectors)
					return
				}
				switch last(keys) {
				case "format":
					ok = s == "tt.scenarios/v1"
				case "id", "name", "description":
					ok = syn(s) || in.Prov.Text[s]
				case "customer":
					ok = syn(s)
				case "archetype":
					_, ok = c.archetypes[s]
				case "rule", "outcome":
					ok = c.ruleNames[s]
				case "service":
					ok = c.services[s]
				case "op":
					ok = c.ops[s] || s == "*"
				case "example":
					ok = c.exampleNames[s]
				case "mode":
					ok = s == "observed" || s == "off" || s == "custom"
				case "net_error":
					ok = netErrors[s]
				}
				if !ok {
					f.add(p.path, ptr, "string without provenance")
				}
			})
		default:
			f.add(p.path, "", "file is not part of the pack format")
		}
	}
	return f.check(CheckProvenance, "tt-core")
}

var netErrors = map[string]bool{"timeout": true, "reset": true, "refused": true, "dns": true, "tls": true, "other": true}

var worldTop = map[string]bool{"type": true, "format": true, "seed": true, "t0": true, "id": true, "archetype": true, "profile": true,
	"entity": true, "customer_id": true, "state": true, "at": true, "seq": true, "rule_id": true, "outcome": true, "effect_id": true,
	"due_offset_s": true, "vars": true, "effect_ids": true}

var worldWords = map[string]bool{"meta": true, "customer": true, "entity": true, "history": true, "pending": true, "tt.world/v1": true}

func worldProvenance(p *parsed, c *packContext, in *Input, f *findings) {
	each(p, func(v ttjson.Value, ptr string, keys []string, isKey bool) {
		depth := len(keys)
		if isKey {
			k := v.Str
			switch {
			case depth == 0:
				if !worldTop[k] {
					f.add(p.path, ptr, "unknown key")
				}
			case keys[0] == "profile":
				if k != "email" && k != "name" && !c.attrNames[k] {
					f.add(p.path, ptr, "profile key without provenance")
				}
			case keys[0] == "vars":
				if !c.bindVars[k] {
					f.add(p.path, ptr, "key without provenance")
				}
			case keys[0] == "effect_ids":
				if !c.ruleNames[k] {
					f.add(p.path, ptr, "key without provenance")
				}
			case keys[0] == "state":
				if !c.contractKeys[k] && !c.fieldNames[k] {
					f.add(p.path, ptr, "state key is neither a contract nor a rule field")
				}
			}
			return
		}
		if v.Kind != ttjson.String {
			return
		}
		s := v.Str
		if worldWords[s] && depth == 1 {
			return
		}
		if in.Prov.Synthetic[s] || c.ruleLiterals[s] || c.ruleNames[s] || c.enumOwners[s] {
			return
		}
		if _, ok := in.Prov.Declared[s]; ok {
			return
		}
		if depth == 1 && keys[0] == "archetype" {
			if _, ok := c.archetypes[s]; ok {
				return
			}
		}
		f.add(p.path, ptr, "value is not tagged synthetic or declared")
	})
}
