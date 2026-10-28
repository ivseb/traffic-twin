package graphql

import (
	"github.com/ivseb/traffic-twin/internal/event"
)

// Logical is the GraphQL operation an exchange called (event.md 6).
type Logical struct {
	// Op is the logical op key: the HTTP operation, "#" and the operation
	// name (or "~" and the hash of the shape for an anonymous operation).
	Op string
	// Name is the part after "#".
	Name string
	// Type is query, mutation or subscription.
	Type string
	// Shape is the shape of the whole document (without "gql:").
	Shape string
	// Doc is the parsed shape; Operation the selected operation in it.
	Doc       *Document
	Operation *Operation
	// Introspection reports an introspection-only document.
	Introspection bool
}

// OperationName returns the name of op in a logical op key: its own name
// when it is a safe name, otherwise the hash of the whole shape.
func OperationName(op *Operation, shape string) string {
	if op.Name != "" && op.Name != "*" && NameSafe(op.Name) {
		return op.Name
	}
	return ShapeHash(shape)
}

// SplitEvent derives the logical GraphQL operation of a stored event from
// what the source sent (the gql: shape of the request document,
// sanitizer.md 5.7.5). ok is false when the event is not a GraphQL
// exchange, or already carries a logical op.
func SplitEvent(ev *event.Event) (Logical, bool) {
	if _, _, already := event.GraphQLOperation(ev.Op); already {
		return Logical{}, false
	}
	shape, ok := ev.GraphQLDocument()
	if !ok {
		return Logical{}, false
	}
	doc, err := ParseShape(shape)
	if err != nil || len(doc.Operations) == 0 {
		return Logical{}, false
	}
	op := pickOperation(doc, ev)
	name := OperationName(op, shape)
	return Logical{
		Op: ev.Op + "#" + name, Name: name, Type: op.Type, Shape: shape, Doc: doc, Operation: op,
		Introspection: IsIntrospection(doc),
	}, true
}

// pickOperation selects the executed operation of a document with several
// operations (the operationName of the request is a value and does not
// leave the source): the one whose root response keys cover the keys of
// the response data, else the first one.
func pickOperation(doc *Document, ev *event.Event) *Operation {
	if len(doc.Operations) == 1 || ev.Resp == nil || ev.Resp.Body == nil || ev.Resp.Body.Kind != event.Object {
		return doc.Operations[0]
	}
	data, ok := ev.Resp.Body.Get("data")
	if !ok || data.Kind != event.Object || len(data.O) == 0 {
		return doc.Operations[0]
	}
	for _, op := range doc.Operations {
		keys := map[string]bool{}
		for _, k := range RootKeys(doc, op.Selection) {
			keys[k] = true
		}
		all := true
		for _, m := range data.O {
			if m.K != "{*}" && !keys[m.K] {
				all = false
				break
			}
		}
		if all {
			return op
		}
	}
	return doc.Operations[0]
}

// RootKeys lists the response keys of a selection set, following fragment
// spreads and inline fragments of the document (each fragment once).
func RootKeys(doc *Document, sel []*Selection) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(sel []*Selection)
	walk = func(sel []*Selection) {
		for _, s := range sel {
			switch s.Kind {
			case SelField:
				out = append(out, s.ResponseKey())
			case SelInline:
				walk(s.Selection)
			case SelSpread:
				if f := doc.Fragments[s.Name]; f != nil && !seen[s.Name] {
					seen[s.Name] = true
					walk(f.Selection)
				}
			}
		}
	}
	walk(sel)
	return out
}

// Where the document of a GraphQL request is (Candidate).
const (
	InJSON  = "json"  // member "query" of a JSON body
	InQuery = "query" // query parameter "query" of a GET
	InBody  = "body"  // the whole application/graphql body
)

// Candidate recognizes a GraphQL exchange by its structure, before any
// graphql rule exists (sanitizer.md 5.7.5): a JSON request body with the
// member query and variables or operationName, a GET with the query
// parameter query, or an application/graphql body; and a JSON response
// body with data or errors (or no response). It returns where the document
// is, "" for any other exchange.
func Candidate(ev *event.Event) string {
	if ev.Resp != nil && ev.Resp.Body != nil {
		b := ev.Resp.Body
		if b.Kind != event.Object {
			return ""
		}
		_, d := b.Get("data")
		_, e := b.Get("errors")
		if !d && !e {
			return ""
		}
	}
	if ev.Req.CT == "application/graphql" && ev.Req.Body != nil {
		return InBody
	}
	if b := ev.Req.Body; b != nil && b.Kind == event.Object && event.IsJSONContentType(ev.Req.CT) {
		_, q := b.Get("query")
		_, v := b.Get("variables")
		_, n := b.Get("operationName")
		if q && (v || n || len(b.O) == 1) {
			return InJSON
		}
		return ""
	}
	if ev.OpMethod() == "GET" {
		if _, ok := ev.Req.Query.Get("query"); ok {
			return InQuery
		}
	}
	return ""
}
