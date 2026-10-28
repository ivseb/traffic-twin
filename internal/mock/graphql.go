package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/ivseb/traffic-twin/internal/graphql"
)

// GraphQL endpoints (docs/spec/mock.md 7). A GraphQL service has one HTTP
// endpoint and many logical operations, "POST /graphql#GetOrder" in the
// contract (event.md 6). The mock reads the GraphQL request, picks the
// logical operation by name (or by the hash of the shape of an anonymous
// document), and serves it through the same path as every operation:
// validation, faults, entities, rules, sessions, id formats. Then it fits
// the answer to GraphQL: data follows the selection of the request, faults
// become an errors array, introspection is answered from the captured
// schema (or from one synthesized from the contract).

// gqlEndpoint is one GraphQL endpoint of a service.
type gqlEndpoint struct {
	path string // "/graphql"
	ops  map[string]*operation
	// errors200: the endpoint was observed answering errors with HTTP 200.
	errors200 bool
	captured  map[string]any // data of the captured introspection result, nil if none

	once  sync.Once
	synth map[string]any
}

var gqlIndex sync.Map // *contract -> map[string]*gqlEndpoint (by path)

// gqlEndpoints indexes the GraphQL endpoints of a compiled contract.
func gqlEndpoints(c *contract) map[string]*gqlEndpoint {
	if v, ok := gqlIndex.Load(c); ok {
		return v.(map[string]*gqlEndpoint)
	}
	out := map[string]*gqlEndpoint{}
	for _, op := range c.ops {
		x, _ := op.node["x-tt-graphql"].(map[string]any)
		if x == nil {
			continue
		}
		path, _, _ := strings.Cut(op.tmpl, "#")
		ep := out[path]
		if ep == nil {
			ep = &gqlEndpoint{path: path, ops: map[string]*operation{}}
			out[path] = ep
		}
		ep.ops[op.key] = op
		if r := op.responses[http.StatusOK]; r != nil && r.schema != nil {
			if s := c.sc.flat(r.schema, 0); s != nil {
				if props, _ := s["properties"].(map[string]any); props != nil && props["errors"] != nil {
					ep.errors200 = true
				}
			}
		}
	}
	if list, ok := c.sc.doc["x-tt-graphql-schemas"].([]any); ok {
		for _, e := range list {
			m, _ := e.(map[string]any)
			endpoint, _ := m["endpoint"].(string)
			data, _ := m["data"].(map[string]any)
			_, path, _ := strings.Cut(endpoint, " ")
			if data == nil || path == "" {
				continue
			}
			ep := out[path]
			if ep == nil {
				ep = &gqlEndpoint{path: path, ops: map[string]*operation{}}
				out[path] = ep
			}
			ep.captured = data
		}
	}
	gqlIndex.Store(c, out)
	return out
}

// gqlCall is a GraphQL request routed to a logical operation.
type gqlCall struct {
	ep   *gqlEndpoint
	op   *operation
	doc  *graphql.Document
	sel  *graphql.Operation
	vars map[string]any
	// in replaces the inbound for the rest of the dispatch (an
	// application/graphql body is presented as JSON); reqBody is the
	// request as rules and reads see it: {query, variables, operationName}.
	in      *inbound
	reqBody map[string]any
	// path is the logical path the generator seeds on: the operation and
	// its variables (two orders read with two ids differ).
	path string
	// res is a complete answer (introspection, errors) that ends the dispatch.
	res *result
}

// gqlRequest is the GraphQL-over-HTTP request.
type gqlRequest struct {
	query, opName string
	vars          map[string]any
}

func gqlErrorBody(msg, code string) map[string]any {
	return map[string]any{"data": nil, "errors": []any{map[string]any{"message": msg, "extensions": map[string]any{"code": code}}}}
}

func gqlResult(status int, body any, unmatched string) *result {
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	if unmatched != "" {
		hdr.Set(hdrUnmatched, unmatched)
	}
	return &result{status: status, header: hdr, body: compactJSON(body)}
}

// graphqlRoute recognizes a request to a GraphQL endpoint of svc. It
// returns nil for any other request (the REST dispatch goes on).
func (s *session) graphqlRoute(svc *service, in *inbound, path string, e *journalEntry) *gqlCall {
	eps := gqlEndpoints(svc.c)
	if len(eps) == 0 {
		return nil
	}
	ep := eps[path]
	if ep == nil || (in.method != http.MethodPost && in.method != http.MethodGet) {
		return nil
	}
	call := &gqlCall{ep: ep, in: in}
	req, msg := parseGQLRequest(in)
	if msg != "" {
		e.Matched, e.Reason = false, "invalid-request"
		call.res = gqlResult(http.StatusBadRequest, gqlErrorBody(msg, "BAD_REQUEST"), "invalid-request")
		return call
	}
	doc, err := graphql.Parse(req.query)
	if err != nil {
		e.Matched, e.Reason = false, "invalid-request"
		call.res = gqlResult(http.StatusBadRequest, gqlErrorBody("Syntax Error: the document is not an executable GraphQL document", "GRAPHQL_PARSE_FAILED"), "invalid-request")
		return call
	}
	sel, msg := selectOperation(doc, req.opName)
	if msg != "" {
		e.Matched, e.Reason = false, "invalid-request"
		call.res = gqlResult(http.StatusBadRequest, gqlErrorBody(msg, "BAD_REQUEST"), "invalid-request")
		return call
	}
	call.doc, call.sel, call.vars = doc, sel, req.vars
	name := sel.Name
	if !graphql.NameSafe(name) {
		// An anonymous operation is known by the hash of the shape of its
		// document, exactly as the source computed it (sanitizer.md 5.7).
		r, ok := graphql.Shape(req.query)
		if !ok {
			name = ""
		} else {
			name = graphql.ShapeHash(r.Shape)
		}
	}
	key := in.method + " " + path + "#" + name
	op := ep.ops[key]
	if op == nil {
		// A query observed with POST may come with GET and the other way round.
		other := http.MethodGet
		if in.method == http.MethodGet {
			other = http.MethodPost
		}
		op = ep.ops[other+" "+path+"#"+name]
	}
	if isIntrospectionOp(sel) {
		e.Matched = true
		e.Op = strp(key)
		if op != nil {
			e.Op = strp(op.key)
		}
		data := s.introspect(svc, ep, doc, sel, req.vars)
		call.res = gqlResult(http.StatusOK, map[string]any{"data": data}, "")
		return call
	}
	if op == nil || name == "" {
		label := strings.ToUpper(sel.Type)
		if sel.Name != "" {
			label += " " + sel.Name
		}
		e.Matched, e.Reason = false, "no-operation"
		call.res = gqlResult(http.StatusOK, gqlErrorBody("operation not observed: "+label, "OPERATION_NOT_OBSERVED"), "no-operation")
		return call
	}
	call.op = op
	call.reqBody = map[string]any{"query": req.query}
	if req.vars != nil {
		call.reqBody["variables"] = req.vars
	}
	if sel.Name != "" {
		// The protocol fields are not the contract's business: a client may
		// omit operationName for a document with one operation.
		call.reqBody["operationName"] = sel.Name
	}
	if op.hasBody {
		// The request is validated in its JSON form, whatever the transport
		// (a GET, an application/graphql body).
		cp := *in
		cp.header = in.header.Clone()
		cp.header.Set("Content-Type", "application/json")
		cp.body = compactJSON(call.reqBody)
		call.in = &cp
	}
	h := sha256.Sum256(compactJSON(req.vars))
	call.path = op.tmpl + "?" + hex.EncodeToString(h[:6])
	return call
}

func isIntrospectionOp(op *graphql.Operation) bool {
	return graphql.IsIntrospection(&graphql.Document{Operations: []*graphql.Operation{op}})
}

// parseGQLRequest reads a GraphQL-over-HTTP request: a JSON body {query,
// variables, operationName}, an application/graphql body, or the query
// parameters query, variables and operationName of a GET.
func parseGQLRequest(in *inbound) (gqlRequest, string) {
	var r gqlRequest
	if in.method == http.MethodGet {
		q, _ := url.ParseQuery(in.rawQuery)
		r.query, r.opName = q.Get("query"), q.Get("operationName")
		if v := q.Get("variables"); v != "" {
			if err := json.Unmarshal([]byte(v), &r.vars); err != nil {
				return r, "variables must be a JSON object"
			}
		}
	} else {
		ct, _, _ := mime.ParseMediaType(in.header.Get("Content-Type"))
		if ct == "application/graphql" {
			r.query = string(in.body)
		} else {
			var body struct {
				Query         *string        `json:"query"`
				Variables     map[string]any `json:"variables"`
				OperationName *string        `json:"operationName"`
			}
			v, err := decodeJSON(in.body)
			if err != nil {
				return r, "the body is not valid JSON"
			}
			if _, ok := v.(map[string]any); !ok {
				return r, "the body must be a JSON object (batched requests are not supported)"
			}
			if err := json.Unmarshal(in.body, &body); err != nil {
				return r, "query must be a string, variables an object, operationName a string"
			}
			if body.Query != nil {
				r.query = *body.Query
			}
			if body.OperationName != nil {
				r.opName = *body.OperationName
			}
			m, _ := v.(map[string]any)
			r.vars, _ = m["variables"].(map[string]any)
		}
	}
	if strings.TrimSpace(r.query) == "" {
		return r, "the request has no query"
	}
	return r, ""
}

func selectOperation(doc *graphql.Document, name string) (*graphql.Operation, string) {
	if name != "" {
		for _, op := range doc.Operations {
			if op.Name == name {
				return op, ""
			}
		}
		return nil, "unknown operation named " + name
	}
	switch len(doc.Operations) {
	case 0:
		return nil, "the document has no operation"
	case 1:
		return doc.Operations[0], ""
	}
	return nil, "operationName is required when the document has several operations"
}

// graphqlFinish fits the answer of a logical GraphQL operation to GraphQL
// (mock.md 7.3): data follows the selection of the request (aliases,
// __typename, fields the contract does not know as null); a fault status
// the contract has no GraphQL answer for becomes an errors array, with HTTP
// 200 when the endpoint was observed answering errors that way.
func (s *session) graphqlFinish(svc *service, call *gqlCall, res *result, status int, body any) {
	if res.netErr != "" {
		return
	}
	if status >= 400 {
		if r := call.op.responses[status]; r != nil && r.schema != nil {
			if f := svc.c.sc.flat(r.schema, 0); f != nil {
				if props, _ := f["properties"].(map[string]any); props != nil && props["errors"] != nil {
					return // observed GraphQL errors for this status: served as observed
				}
			}
		}
		code := "HTTP_" + http.StatusText(status)
		code = strings.ToUpper(strings.ReplaceAll(code, " ", "_"))
		eb := gqlErrorBody(http.StatusText(status), code)
		if ext, ok := eb["errors"].([]any)[0].(map[string]any)["extensions"].(map[string]any); ok {
			ext["status"] = status
		}
		if call.ep.errors200 {
			res.status = http.StatusOK
		}
		res.header.Set("Content-Type", "application/json")
		res.body = compactJSON(eb)
		return
	}
	m, ok := body.(map[string]any)
	if !ok {
		return
	}
	data, has := m["data"]
	if !has {
		return
	}
	idx := s.schemaIndex(svc, call.ep)
	root := idx.rootType(call.sel.Type)
	if dm, ok := data.(map[string]any); ok || data == nil {
		if data == nil && m["errors"] != nil {
			return
		}
		m["data"] = shapeData(dm, call.sel.Selection, call.doc, root, idx)
		res.header.Set("Content-Type", "application/json")
		res.body = compactJSON(m)
	}
}

// shapeData keeps the response keys the selection asks for, in any
// fragment, and adds __typename.
func shapeData(v map[string]any, sel []*graphql.Selection, doc *graphql.Document, typ string, idx *schemaIndex) map[string]any {
	out := map[string]any{}
	var walk func(sel []*graphql.Selection, depth int)
	walk = func(sel []*graphql.Selection, depth int) {
		if depth > 32 {
			return
		}
		for _, s := range sel {
			switch s.Kind {
			case graphql.SelInline:
				walk(s.Selection, depth+1)
			case graphql.SelSpread:
				if f := doc.Fragments[s.Name]; f != nil {
					walk(f.Selection, depth+1)
				}
			case graphql.SelField:
				key := s.ResponseKey()
				if s.Name == "__typename" {
					out[key] = typ
					continue
				}
				val, ok := v[key]
				if !ok {
					val = v[s.Name]
				}
				if len(s.Selection) > 0 {
					val = shapeValue(val, s.Selection, doc, idx.fieldType(typ, s.Name, key), idx)
				}
				if prev, dup := out[key].(map[string]any); dup {
					if nv, ok := val.(map[string]any); ok {
						for k, x := range nv {
							prev[k] = x
						}
						continue
					}
				}
				out[key] = val
			}
		}
	}
	walk(sel, 0)
	return out
}

func shapeValue(v any, sel []*graphql.Selection, doc *graphql.Document, typ string, idx *schemaIndex) any {
	switch x := v.(type) {
	case map[string]any:
		return shapeData(x, sel, doc, typ, idx)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = shapeValue(e, sel, doc, typ, idx)
		}
		return out
	}
	return v
}

// refParam is the parameter a read selects by: the name of a request
// parameter, or the body path of a GraphQL variable (rules.md 2.3, v1.14),
// which graphqlParams puts into the parameters of the call.
func refParam(r compiledRef) string {
	if r.ref.From == "req.body" {
		return r.ref.Path
	}
	return r.ref.Name
}

// graphqlParams exposes the top-level variables of a GraphQL call to the
// reads as "$.variables.<name>" parameters.
func graphqlParams(vars map[string]any) map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if s, ok := scalarString(vars[k]); ok {
			out["$.variables."+k] = s
		}
	}
	return out
}
