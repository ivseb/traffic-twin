package contract

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/graphql/graphqltest"
)

func graphqlContract(t *testing.T) *Contract {
	t.Helper()
	evs, err := graphqltest.Events(graphqltest.Exchanges(25))
	if err != nil {
		t.Fatal(err)
	}
	in := NewInferrer(DefaultConfig(), nil)
	for _, ev := range evs {
		in.Add(ev, nil)
	}
	cs := in.Contracts(Window{})
	if len(cs) != 1 {
		t.Fatalf("%d contracts", len(cs))
	}
	return cs[0]
}

// Each GraphQL operation of one endpoint is an operation of the contract,
// with its variables, root fields and document shape (event.md 6).
func TestGraphQLContractOperations(t *testing.T) {
	c := graphqlContract(t)
	got := map[string]*Op{}
	for _, op := range c.Ops {
		got[op.Key] = op
	}
	anon := ""
	for k := range got {
		if strings.HasPrefix(k, "POST /graphql#~") {
			anon = k
		}
	}
	for _, k := range []string{"POST /graphql#GetOrder", "POST /graphql#CreateOrder", "POST /graphql#IntrospectionQuery", anon} {
		if got[k] == nil || got[k].GraphQL == nil {
			t.Fatalf("missing GraphQL operation %q in %v", k, gqlKeys(got))
		}
	}
	if len(got) != 4 {
		t.Fatalf("operations: %v", gqlKeys(got))
	}
	g := got["POST /graphql#GetOrder"].GraphQL
	if g.Type != "query" || g.Name != "GetOrder" || g.Endpoint != "/graphql" || g.Method != "POST" || g.In != "json" ||
		len(g.Variables) != 1 || g.Variables[0].Name != "id" || g.Variables[0].Type != "ID!" || strings.Join(g.Fields, ",") != "order" ||
		g.Document != "query GetOrder($id:ID!){order(id:$id){id status total}}" {
		t.Fatalf("GetOrder: %+v", g)
	}
	if m := got["POST /graphql#CreateOrder"].GraphQL; m.Type != "mutation" || m.GraphQLLabel() != "MUTATION CreateOrder" {
		t.Fatalf("CreateOrder: %+v", m)
	}
	if a := got[anon].GraphQL; !a.Anonymous || a.Document != "{orders(first:?i status:?e){id status}}" {
		t.Fatalf("anonymous: %+v", a)
	}
	if !got["POST /graphql#IntrospectionQuery"].GraphQL.Introspection {
		t.Fatal("introspection flag")
	}
	// The response schema of GetOrder follows the selection: data.order.{id,status,total}.
	r := got["POST /graphql#GetOrder"].Response(200)
	order := r.Body[0].Schema.Prop("data").Schema.Prop("order").Schema
	if order.Prop("id").Schema.Kind != "id" || order.Prop("total") == nil || order.Prop("status") == nil {
		t.Fatalf("order schema: %+v", order)
	}
	q := got["POST /graphql#GetOrder"].Body[0].Schema.Prop("query").Schema
	if q.Kind != "graphql" {
		t.Fatalf("query member kind %q", q.Kind)
	}
}

// The introspection call is captured as the schema of the endpoint: names
// in clear, descriptions dropped (sanitizer.md 5.7.2).
func TestGraphQLContractCapturesIntrospection(t *testing.T) {
	c := graphqlContract(t)
	s := c.GraphQLSchemaFor("POST /graphql")
	if s == nil {
		t.Fatal("no captured schema")
	}
	sch := s.Data["__schema"].(map[string]any)
	if sch["queryType"].(map[string]any)["name"] != "Query" || sch["mutationType"].(map[string]any)["name"] != "Mutation" {
		t.Fatalf("roots: %v", sch)
	}
	names := map[string]map[string]any{}
	for _, tp := range sch["types"].([]any) {
		m := tp.(map[string]any)
		if n, _ := m["name"].(string); n != "" {
			names[n] = m
		}
	}
	for _, n := range []string{"Query", "Mutation", "Order", "OrderStatus", "OrderInput", "ID", "String"} {
		if names[n] == nil {
			t.Fatalf("type %s missing: %v", n, keysOfAny(names))
		}
	}
	q := names["Query"]
	f := q["fields"].([]any)[0].(map[string]any)
	if f["name"] != "order" || f["description"] != nil || f["args"].([]any)[0].(map[string]any)["name"] != "id" {
		t.Fatalf("field: %v", f)
	}
	ty := f["args"].([]any)[0].(map[string]any)["type"].(map[string]any)
	if ty["kind"] != "NON_NULL" || ty["ofType"].(map[string]any)["name"] != "ID" {
		t.Fatalf("arg type: %v", ty)
	}
	doc, err := c.JSON(RenderOptions{IncludeRaw: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"Mario", "secret note", "Torino", "citofono", "ORD-2026", "user-0"} {
		if strings.Contains(string(doc), leak) {
			t.Fatalf("value %q in the contract", leak)
		}
	}
	for _, want := range []string{`"x-tt-graphql-schemas"`, `"x-tt-graphql"`, `"/graphql#GetOrder"`, `"summary":"QUERY GetOrder"`} {
		if !strings.Contains(string(doc), want) {
			t.Fatalf("%s missing from the OpenAPI document", want)
		}
	}
}

// The Postman collection sends a GraphQL operation to its endpoint, with a
// GraphQL body that a client can run.
func TestGraphQLPostman(t *testing.T) {
	c := graphqlContract(t)
	doc, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := PostmanCollection(doc, PostmanOptions{Name: "orders-graph"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"name": "QUERY GetOrder"`, `"raw": "{{baseUrl}}/graphql"`, `"mode": "graphql"`,
		`"query": "query GetOrder($id:ID!){order(id:$id){id status total}}"`, `{orders(first:0 status:null){id status}}`} {
		if !strings.Contains(s, want) {
			t.Fatalf("%s missing from the collection", want)
		}
	}
	if strings.Contains(s, "#GetOrder") {
		t.Fatal("the logical op reached a URL")
	}
}

func gqlKeys(m map[string]*Op) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfAny(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
