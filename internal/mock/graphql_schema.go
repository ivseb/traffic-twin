package mock

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ivseb/traffic-twin/internal/graphql"
)

// Introspection answers (docs/spec/mock.md 7.2): the captured result of the
// endpoint (names only, sanitizer.md 5.7.2), or, when no introspection
// call was captured, a schema synthesized from the observed operations, so
// that a client that stitches or federates the service can start.

// schemaIndex is the type information of an endpoint.
type schemaIndex struct {
	schema       map[string]any // the __schema object
	query        string
	mutation     string
	subscription string
	types        map[string]map[string]any    // name -> __Type object
	fields       map[string]map[string]string // type -> field -> named type
}

var gqlIdx sync.Map // *gqlEndpoint -> *schemaIndex

func (s *session) schemaIndex(svc *service, ep *gqlEndpoint) *schemaIndex {
	if v, ok := gqlIdx.Load(ep); ok {
		return v.(*schemaIndex)
	}
	var sch map[string]any
	if ep.captured != nil {
		sch, _ = ep.captured["__schema"].(map[string]any)
	}
	if sch == nil {
		ep.once.Do(func() { ep.synth = synthSchema(svc.c, ep) })
		sch = ep.synth
	}
	idx := &schemaIndex{schema: sch, types: map[string]map[string]any{}, fields: map[string]map[string]string{}}
	idx.query = rootName(sch, "queryType", "Query")
	idx.mutation = rootName(sch, "mutationType", "Mutation")
	idx.subscription = rootName(sch, "subscriptionType", "Subscription")
	types, _ := sch["types"].([]any)
	for _, t := range types {
		tm, _ := t.(map[string]any)
		name, _ := tm["name"].(string)
		if name == "" {
			continue
		}
		idx.types[name] = tm
		fs, _ := tm["fields"].([]any)
		for _, f := range fs {
			fm, _ := f.(map[string]any)
			fname, _ := fm["name"].(string)
			if fname == "" {
				continue
			}
			if idx.fields[name] == nil {
				idx.fields[name] = map[string]string{}
			}
			idx.fields[name][fname] = namedType(fm["type"])
		}
	}
	gqlIdx.Store(ep, idx)
	return idx
}

func rootName(sch map[string]any, key, def string) string {
	if m, ok := sch[key].(map[string]any); ok {
		if n, _ := m["name"].(string); n != "" {
			return n
		}
	}
	return def
}

// namedType follows ofType down to the named type of a type reference.
func namedType(ref any) string {
	for i := 0; i < 16; i++ {
		m, ok := ref.(map[string]any)
		if !ok {
			return ""
		}
		if n, _ := m["name"].(string); n != "" {
			return n
		}
		ref = m["ofType"]
	}
	return ""
}

func (x *schemaIndex) rootType(opType string) string {
	switch opType {
	case graphql.Mutation:
		return x.mutation
	case graphql.Subscription:
		return x.subscription
	}
	return x.query
}

// fieldType is the named type of a field, or a name derived from the
// response key when the schema does not know it.
func (x *schemaIndex) fieldType(typ, field, key string) string {
	if t := x.fields[typ][field]; t != "" {
		return t
	}
	return pascal(singularWord(key))
}

// introspect executes an introspection operation against the schema.
func (s *session) introspect(svc *service, ep *gqlEndpoint, doc *graphql.Document, op *graphql.Operation, vars map[string]any) map[string]any {
	idx := s.schemaIndex(svc, ep)
	out := map[string]any{}
	var walk func(sel []*graphql.Selection, depth int)
	walk = func(sel []*graphql.Selection, depth int) {
		if depth > 32 {
			return
		}
		for _, f := range sel {
			switch f.Kind {
			case graphql.SelInline:
				walk(f.Selection, depth+1)
			case graphql.SelSpread:
				if fr := doc.Fragments[f.Name]; fr != nil {
					walk(fr.Selection, depth+1)
				}
			case graphql.SelField:
				switch f.Name {
				case "__typename":
					out[f.ResponseKey()] = idx.rootType(op.Type)
				case "__schema":
					out[f.ResponseKey()] = introObject(idx.schema, f.Selection, "__Schema", doc, idx, 0)
				case "__type":
					name := argString(f.Args, "name", vars)
					if t := idx.types[name]; t != nil {
						out[f.ResponseKey()] = introObject(t, f.Selection, "__Type", doc, idx, 0)
					} else {
						out[f.ResponseKey()] = nil
					}
				}
			}
		}
	}
	walk(op.Selection, 0)
	return out
}

// introChild is the introspection type of the value of a field.
var introChild = map[string]string{
	"types": "__Type", "queryType": "__Type", "mutationType": "__Type", "subscriptionType": "__Type", "type": "__Type",
	"ofType": "__Type", "interfaces": "__Type", "possibleTypes": "__Type", "fields": "__Field", "args": "__InputValue",
	"inputFields": "__InputValue", "enumValues": "__EnumValue", "directives": "__Directive",
}

func introObject(obj map[string]any, sel []*graphql.Selection, typename string, doc *graphql.Document, idx *schemaIndex, depth int) any {
	if obj == nil {
		return nil
	}
	out := map[string]any{}
	var walk func(sel []*graphql.Selection, d int)
	walk = func(sel []*graphql.Selection, d int) {
		if d > 64 {
			return
		}
		for _, f := range sel {
			switch f.Kind {
			case graphql.SelInline:
				walk(f.Selection, d+1)
			case graphql.SelSpread:
				if fr := doc.Fragments[f.Name]; fr != nil {
					walk(fr.Selection, d+1)
				}
			case graphql.SelField:
				key := f.ResponseKey()
				if f.Name == "__typename" {
					out[key] = typename
					continue
				}
				val, ok := obj[f.Name]
				if !ok {
					val = introDefault(f.Name, obj, typename, idx)
				}
				if len(f.Selection) > 0 && depth < 64 {
					child := introChild[f.Name]
					switch x := val.(type) {
					case map[string]any:
						val = introObject(x, f.Selection, child, doc, idx, depth+1)
					case []any:
						arr := make([]any, len(x))
						for i, e := range x {
							em, _ := e.(map[string]any)
							arr[i] = introObject(em, f.Selection, child, doc, idx, depth+1)
						}
						val = arr
					}
				}
				out[key] = val
			}
		}
	}
	walk(sel, 0)
	return out
}

// introDefault answers a field the captured result does not have: the
// lists a client needs are empty, the flags false, the texts null. A type
// reference that stops at a name is completed from the types of the schema.
func introDefault(field string, obj map[string]any, typename string, idx *schemaIndex) any {
	switch field {
	case "isDeprecated", "isRepeatable", "isOneOf":
		return false
	case "args", "locations":
		return []any{}
	case "interfaces":
		if k, _ := obj["kind"].(string); k == "OBJECT" || k == "INTERFACE" {
			if n, _ := obj["name"].(string); n != "" && idx.types[n] != nil {
				if v, ok := idx.types[n]["interfaces"]; ok {
					return v
				}
			}
			return []any{}
		}
	}
	if typename == "__Type" {
		// A reference ({kind, name}) asked for more: the full type.
		if n, _ := obj["name"].(string); n != "" && idx.types[n] != nil {
			if v, ok := idx.types[n][field]; ok {
				return v
			}
		}
	}
	return nil
}

// argString reads a string argument, literal or variable.
func argString(args []graphql.Arg, name string, vars map[string]any) string {
	for _, a := range args {
		if a.Name != name {
			continue
		}
		switch a.Value.Kind {
		case graphql.ValVar:
			s, _ := vars[a.Value.Name].(string)
			return s
		case graphql.ValString:
			var s string
			if err := json.Unmarshal([]byte(a.Value.Raw), &s); err == nil {
				return s
			}
			return strings.Trim(a.Value.Raw, `"`)
		}
	}
	return ""
}

// ---- schema synthesized from the contract ----

var builtinScalars = []string{"Boolean", "Float", "ID", "Int", "String"}

type synth struct {
	c     *contract
	types map[string]map[string]any
	order []string
}

func (y *synth) object(name, kind string) map[string]any {
	if t := y.types[name]; t != nil {
		return t
	}
	t := map[string]any{"kind": kind, "name": name, "description": nil, "interfaces": []any{}, "possibleTypes": nil, "enumValues": nil}
	switch kind {
	case "OBJECT":
		t["fields"] = []any{}
		t["inputFields"] = nil
	case "INPUT_OBJECT":
		t["fields"] = nil
		t["inputFields"] = []any{}
		t["interfaces"] = nil
	default:
		t["fields"] = nil
		t["inputFields"] = nil
		t["interfaces"] = nil
	}
	y.types[name] = t
	y.order = append(y.order, name)
	return t
}

func hasNamed(list []any, name string) bool {
	for _, e := range list {
		if m, _ := e.(map[string]any); m != nil && m["name"] == name {
			return true
		}
	}
	return false
}

func (y *synth) addField(t map[string]any, key string, f map[string]any) {
	list, _ := t[key].([]any)
	if hasNamed(list, f["name"].(string)) {
		return
	}
	t[key] = append(list, f)
}

func ref(kind, name string, of any) map[string]any {
	var n any
	if name != "" {
		n = name
	}
	return map[string]any{"kind": kind, "name": n, "ofType": of}
}

// typeRefOf parses a written type reference ("[ID!]!").
func (y *synth) typeRefOf(s string) map[string]any {
	if strings.HasSuffix(s, "!") {
		return ref("NON_NULL", "", y.typeRefOf(strings.TrimSuffix(s, "!")))
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return ref("LIST", "", y.typeRefOf(s[1:len(s)-1]))
	}
	if y.types[s] == nil {
		y.object(s, "SCALAR")
	}
	return ref(y.types[s]["kind"].(string), s, nil)
}

// outputType maps a JSON schema of the response to a GraphQL type.
func (y *synth) outputType(schema any, hint string, depth int) map[string]any {
	s := y.c.sc.flat(schema, 0)
	if depth > 12 {
		return y.typeRefOf("String")
	}
	switch primaryType(s) {
	case "array":
		return ref("LIST", "", y.outputType(s["items"], hint, depth+1))
	case "object":
		name := pascal(singularWord(hint))
		if name == "" {
			name = "Object"
		}
		t := y.object(name, "OBJECT")
		props, _ := s["properties"].(map[string]any)
		for _, k := range sortedKeys(props) {
			if !graphql.IsName(k) {
				continue
			}
			y.addField(t, "fields", map[string]any{"name": k, "description": nil, "args": []any{},
				"type": y.outputType(props[k], k, depth+1), "isDeprecated": false, "deprecationReason": nil})
		}
		if len(t["fields"].([]any)) == 0 {
			y.addField(t, "fields", map[string]any{"name": "_empty", "description": nil, "args": []any{},
				"type": y.typeRefOf("String"), "isDeprecated": false, "deprecationReason": nil})
		}
		return ref("OBJECT", name, nil)
	case "integer":
		return y.typeRefOf("Int")
	case "number":
		return y.typeRefOf("Float")
	case "boolean":
		return y.typeRefOf("Boolean")
	}
	if xv, _ := s["x-tt-value"].(map[string]any); xv != nil && xv["kind"] == "id" {
		return y.typeRefOf("ID")
	}
	return y.typeRefOf("String")
}

// inputObject describes an input type from the observed variables.
func (y *synth) inputObject(name string, schema any, depth int) {
	s := y.c.sc.flat(schema, 0)
	if primaryType(s) == "array" {
		s = y.c.sc.flat(s["items"], 0)
	}
	if primaryType(s) != "object" || depth > 8 {
		return
	}
	if t := y.types[name]; t != nil && t["kind"] != "SCALAR" {
		return
	}
	delete(y.types, name)
	for i, n := range y.order {
		if n == name {
			y.order = append(y.order[:i], y.order[i+1:]...)
			break
		}
	}
	t := y.object(name, "INPUT_OBJECT")
	props, _ := s["properties"].(map[string]any)
	for _, k := range sortedKeys(props) {
		if !graphql.IsName(k) {
			continue
		}
		var tr map[string]any
		ps := y.c.sc.flat(props[k], 0)
		switch primaryType(ps) {
		case "object":
			sub := name + pascal(k)
			y.inputObject(sub, props[k], depth+1)
			tr = ref("INPUT_OBJECT", sub, nil)
		case "array":
			tr = ref("LIST", "", y.scalarOf(ps["items"]))
		default:
			tr = y.scalarOf(props[k])
		}
		y.addField(t, "inputFields", map[string]any{"name": k, "description": nil, "type": tr, "defaultValue": nil})
	}
}

func (y *synth) scalarOf(schema any) map[string]any {
	switch primaryType(y.c.sc.flat(schema, 0)) {
	case "integer":
		return y.typeRefOf("Int")
	case "number":
		return y.typeRefOf("Float")
	case "boolean":
		return y.typeRefOf("Boolean")
	}
	return y.typeRefOf("String")
}

// synthSchema builds an introspection __schema from the logical operations
// of an endpoint: root fields with their arguments (types from the
// variable definitions of the observed documents) and result types from
// the observed response schemas.
func synthSchema(c *contract, ep *gqlEndpoint) map[string]any {
	y := &synth{c: c, types: map[string]map[string]any{}}
	for _, n := range builtinScalars {
		y.object(n, "SCALAR")
	}
	keys := make([]string, 0, len(ep.ops))
	for k := range ep.ops {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	roots := map[string]string{graphql.Query: "Query", graphql.Mutation: "Mutation", graphql.Subscription: "Subscription"}
	for _, k := range keys {
		op := ep.ops[k]
		x, _ := op.node["x-tt-graphql"].(map[string]any)
		docText, _ := x["document"].(string)
		name, _ := x["name"].(string)
		doc, err := graphql.ParseShape(docText)
		if err != nil || len(doc.Operations) == 0 {
			continue
		}
		gop := doc.Operations[0]
		for _, o := range doc.Operations {
			if graphql.OperationName(o, docText) == name {
				gop = o
				break
			}
		}
		if graphql.IsIntrospection(&graphql.Document{Operations: []*graphql.Operation{gop}}) {
			continue
		}
		varTypes := map[string]string{}
		var varsSchema map[string]any
		if op.bodySchema != nil {
			if bs := c.sc.flat(op.bodySchema, 0); bs != nil {
				if props, _ := bs["properties"].(map[string]any); props != nil {
					if vs := c.sc.flat(props["variables"], 0); vs != nil {
						varsSchema, _ = vs["properties"].(map[string]any)
					}
				}
			}
		}
		for _, v := range gop.Variables {
			varTypes[v.Name] = v.Type
			base := strings.Trim(v.Type, "[]!")
			if graphql.IsName(base) && y.types[base] == nil && varsSchema != nil {
				y.inputObject(base, varsSchema[v.Name], 0)
			}
		}
		var data map[string]any
		if r := op.responses[op.successCode]; r != nil && r.schema != nil {
			if rs := c.sc.flat(r.schema, 0); rs != nil {
				if props, _ := rs["properties"].(map[string]any); props != nil {
					if ds := c.sc.flat(props["data"], 0); ds != nil {
						data, _ = ds["properties"].(map[string]any)
					}
				}
			}
		}
		root := y.object(roots[gop.Type], "OBJECT")
		for _, f := range gop.Selection {
			if f.Kind != graphql.SelField || strings.HasPrefix(f.Name, "__") || f.Name == "*" {
				continue
			}
			var args []any
			for _, a := range f.Args {
				var tr map[string]any
				switch a.Value.Kind {
				case graphql.ValVar:
					if t := varTypes[a.Value.Name]; t != "" {
						tr = y.typeRefOf(t)
					}
				case graphql.ValInt:
					tr = y.typeRefOf("Int")
				case graphql.ValFloat:
					tr = y.typeRefOf("Float")
				case graphql.ValBool:
					tr = y.typeRefOf("Boolean")
				}
				if tr == nil {
					tr = y.typeRefOf("String")
				}
				args = append(args, map[string]any{"name": a.Name, "description": nil, "type": tr, "defaultValue": nil})
			}
			if args == nil {
				args = []any{}
			}
			var rt map[string]any
			if data != nil {
				if fs, ok := data[f.ResponseKey()]; ok {
					rt = y.outputType(fs, f.Name, 0)
				}
			}
			if rt == nil {
				rt = y.typeRefOf("String")
			}
			y.addField(root, "fields", map[string]any{"name": f.Name, "description": nil, "args": args, "type": rt,
				"isDeprecated": false, "deprecationReason": nil})
		}
	}
	if y.types["Query"] == nil {
		y.object("Query", "OBJECT")
		y.addField(y.types["Query"], "fields", map[string]any{"name": "_empty", "description": nil, "args": []any{},
			"type": y.typeRefOf("String"), "isDeprecated": false, "deprecationReason": nil})
	}
	sort.Strings(y.order)
	types := make([]any, 0, len(y.order))
	for _, n := range y.order {
		types = append(types, y.types[n])
	}
	boolArg := func(name string) []any {
		return []any{map[string]any{"name": name, "description": nil, "type": ref("NON_NULL", "", ref("SCALAR", "Boolean", nil)), "defaultValue": nil}}
	}
	sch := map[string]any{
		"description": nil, "queryType": map[string]any{"name": "Query"}, "mutationType": nil, "subscriptionType": nil,
		"types": types,
		"directives": []any{
			map[string]any{"name": "include", "description": nil, "isRepeatable": false, "locations": []any{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"}, "args": boolArg("if")},
			map[string]any{"name": "skip", "description": nil, "isRepeatable": false, "locations": []any{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"}, "args": boolArg("if")},
			map[string]any{"name": "deprecated", "description": nil, "isRepeatable": false, "locations": []any{"FIELD_DEFINITION", "ARGUMENT_DEFINITION", "INPUT_FIELD_DEFINITION", "ENUM_VALUE"},
				"args": []any{map[string]any{"name": "reason", "description": nil, "type": ref("SCALAR", "String", nil), "defaultValue": strconv.Quote("No longer supported")}}},
		},
	}
	if y.types["Mutation"] != nil {
		sch["mutationType"] = map[string]any{"name": "Mutation"}
	}
	if y.types["Subscription"] != nil {
		sch["subscriptionType"] = map[string]any{"name": "Subscription"}
	}
	return sch
}

func pascal(s string) string {
	var b strings.Builder
	up := true
	for _, r := range s {
		switch {
		case r == '_' || r == '-' || r == ' ':
			up = true
		case up && r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
			up = false
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9' && b.Len() > 0):
			b.WriteRune(r)
			up = false
		}
	}
	return b.String()
}
