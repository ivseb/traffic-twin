package contract

import (
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
)

// GraphQLOp describes a logical GraphQL operation (event.md 6): the
// operation a client called on a GraphQL endpoint, inferred from the shape
// of its document (sanitizer.md 5.7). Its request and response schemas are
// those of the Op (the JSON body: variables, data and errors).
type GraphQLOp struct {
	// Endpoint is the path of the HTTP operation ("/graphql"), Method its
	// method; In tells where the document is: json, query or body.
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	In       string `json:"in"`
	// Type is query, mutation or subscription; Name the operation name, or
	// "~" and a hash for an anonymous operation (Anonymous true).
	Type      string `json:"type"`
	Name      string `json:"name"`
	Anonymous bool   `json:"anonymous,omitempty"`
	// Document is the most frequent shape of the document (names, typed
	// placeholders, never a value); Documents the number of distinct shapes
	// seen (capped).
	Document  string `json:"document"`
	Documents int    `json:"documents,omitempty"`
	// Variables are the variable definitions of the operation, Fields the
	// response keys of its root selection (aliases included).
	Variables []GraphQLVar `json:"variables,omitempty"`
	Fields    []string     `json:"fields,omitempty"`
	// Introspection: the document selects only __schema, __type and
	// __typename.
	Introspection bool `json:"introspection,omitempty"`
}

// GraphQLVar is one variable definition.
type GraphQLVar struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	HasDefault bool   `json:"has_default,omitempty"`
}

// GraphQLSchema is the introspection result captured for one GraphQL
// endpoint (sanitizer.md 5.7.2): names only, descriptions and default
// values null. The mock answers introspection queries from it.
type GraphQLSchema struct {
	// Endpoint is the HTTP operation of the endpoint ("POST /graphql").
	Endpoint   string    `json:"endpoint"`
	CapturedAt time.Time `json:"captured_at"`
	// Data is the value of data of the introspection response.
	Data map[string]any `json:"data"`
}

const maxGQLShapes = 16

type gqlAcc struct {
	shapes  map[string]int64
	over    bool
	in      map[string]int64
	intro   map[string]bool // shape -> introspection-only
	capAt   int64
	capData map[string]any
}

// addGraphQL records the GraphQL side of an event of a logical GraphQL
// operation.
func (o *opAcc) addGraphQL(ev *event.Event) {
	if _, _, ok := event.GraphQLOperation(o.key); !ok {
		return
	}
	shape, ok := ev.GraphQLDocument()
	if !ok {
		return
	}
	g := o.gql
	if g == nil {
		g = &gqlAcc{shapes: map[string]int64{}, in: map[string]int64{}, intro: map[string]bool{}}
		o.gql = g
	}
	if _, seen := g.shapes[shape]; seen || len(g.shapes) < maxGQLShapes {
		g.shapes[shape]++
	} else {
		g.over = true
	}
	where := graphql.InQuery
	if b := ev.Req.Body; b != nil {
		if b.Kind == event.Object {
			where = graphql.InJSON
		} else if b.Kind == event.String {
			where = graphql.InBody
		}
	}
	g.in[where]++
	intro, known := g.intro[shape]
	if !known {
		d, err := graphql.ParseShape(shape)
		intro = err == nil && graphql.IsIntrospection(d)
		if len(g.intro) < 4*maxGQLShapes {
			g.intro[shape] = intro
		}
	}
	if !intro || ev.Status < 200 || ev.Status > 299 {
		return
	}
	if t := ev.Time.UnixMilli(); t >= g.capAt {
		if data, ok := graphql.IntrospectionFromEvent(ev); ok {
			g.capAt, g.capData = t, data
		}
	}
}

func (g *gqlAcc) finalize(key string) *GraphQLOp {
	if g == nil || len(g.shapes) == 0 {
		return nil
	}
	httpOp, name, _ := event.GraphQLOperation(key)
	method, endpoint, _ := strings.Cut(httpOp, " ")
	best, bestN := "", int64(-1)
	for s, n := range g.shapes {
		if n > bestN || (n == bestN && s < best) {
			best, bestN = s, n
		}
	}
	out := &GraphQLOp{Endpoint: endpoint, Method: method, In: modeKey(g.in), Name: name, Anonymous: strings.HasPrefix(name, "~"),
		Document: best, Documents: len(g.shapes)}
	doc, err := graphql.ParseShape(best)
	if err != nil {
		return out
	}
	op := doc.Operations[0]
	for _, o := range doc.Operations {
		if graphql.OperationName(o, best) == name {
			op = o
			break
		}
	}
	out.Type = op.Type
	for _, v := range op.Variables {
		out.Variables = append(out.Variables, GraphQLVar{Name: v.Name, Type: v.Type, HasDefault: v.Default != nil})
	}
	out.Fields = graphql.RootKeys(doc, op.Selection)
	out.Introspection = graphql.IsIntrospection(doc)
	return out
}

// graphqlSchemas returns the latest captured introspection result of each
// GraphQL endpoint of the service.
func graphqlSchemas(svc *svcAcc) []*GraphQLSchema {
	by := map[string]*GraphQLSchema{}
	for key, o := range svc.ops {
		if o.gql == nil || o.gql.capData == nil {
			continue
		}
		ep := event.HTTPOp(key)
		at := time.UnixMilli(o.gql.capAt).UTC()
		if cur := by[ep]; cur == nil || at.After(cur.CapturedAt) {
			by[ep] = &GraphQLSchema{Endpoint: ep, CapturedAt: at, Data: o.gql.capData}
		}
	}
	out := make([]*GraphQLSchema, 0, len(by))
	for _, s := range by {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

// GraphQLSchemaFor returns the captured schema of an endpoint ("POST
// /graphql"), or nil.
func (c *Contract) GraphQLSchemaFor(endpoint string) *GraphQLSchema {
	for _, s := range c.GraphQL {
		if s.Endpoint == endpoint {
			return s
		}
	}
	return nil
}

// renderGraphQLOp is the x-tt-graphql extension of an operation.
func renderGraphQLOp(g *GraphQLOp) map[string]any {
	m := map[string]any{
		"endpoint": g.Endpoint, "method": g.Method, "in": g.In, "type": g.Type, "name": g.Name, "document": g.Document,
	}
	if g.Anonymous {
		m["anonymous"] = true
	}
	if g.Introspection {
		m["introspection"] = true
	}
	if len(g.Variables) > 0 {
		vs := make([]any, len(g.Variables))
		for i, v := range g.Variables {
			vm := map[string]any{"name": v.Name, "type": v.Type}
			if v.HasDefault {
				vm["has_default"] = true
			}
			vs[i] = vm
		}
		m["variables"] = vs
	}
	if len(g.Fields) > 0 {
		fs := make([]any, len(g.Fields))
		for i, f := range g.Fields {
			fs[i] = f
		}
		m["fields"] = fs
	}
	return m
}

// GraphQLLabel is how a person reads a logical GraphQL operation: "QUERY
// GetOrder".
func (g *GraphQLOp) GraphQLLabel() string {
	t := g.Type
	if t == "" {
		t = graphql.Query
	}
	return strings.ToUpper(t) + " " + g.Name
}

// renderGraphQLSchemas is the document-level x-tt-graphql-schemas
// extension: the captured introspection result of each endpoint.
func renderGraphQLSchemas(ss []*GraphQLSchema) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, map[string]any{"endpoint": s.Endpoint, "captured_at": dateOf(s.CapturedAt), "data": s.Data})
	}
	return out
}
