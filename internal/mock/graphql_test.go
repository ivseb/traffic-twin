package mock

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	ttcontract "github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/graphql/graphqltest"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// gqlEntity is an entity of the GraphQL service, as the miner derives it
// from the traffic (rules.md 2.3: a read selected by a GraphQL variable).
const gqlEntity = `{"name":"gorder","service":"orders-graph","id_domain":"order","id_field":"id","id_prefix":"GOR-SYN-",
  "created_by":{"op":"POST /graphql#CreateOrder","id":{"from":"resp.body","path":"$.data.createOrder.id"},
    "state":{"from":"req.body","path":"$.variables.input"},"defaults":{"status":"CREATED"}},
  "read_by":[{"op":"POST /graphql#GetOrder","by":{"from":"req.body","path":"$.variables.id"},"at":{"from":"resp.body","path":"$.data.order"}}]}`

// withGraphQL adds the orders-graph service: its contract is inferred from
// sanitized events of the fixture (graphqltest), as tt-core does.
func withGraphQL(introspection bool) func(*packtest.Spec) {
	return func(sp *packtest.Spec) {
		xs := graphqltest.Exchanges(25)
		if !introspection {
			xs = xs[1:]
		}
		evs, err := graphqltest.Events(xs)
		if err != nil {
			panic(err)
		}
		in := ttcontract.NewInferrer(ttcontract.DefaultConfig(), nil)
		for _, ev := range evs {
			in.Add(ev, nil)
		}
		doc, err := in.Contracts(ttcontract.Window{})[0].JSON(ttcontract.RenderOptions{})
		if err != nil {
			panic(err)
		}
		sp.Files["contracts/orders-graph.openapi.json"] = packtest.Canon(string(doc))
		svcs := sp.Manifest["services"].([]any)
		sp.Manifest["services"] = append(svcs, map[string]any{"name": "orders-graph", "contract": "contracts/orders-graph.openapi.json"})
		var rules map[string]any
		if err := json.Unmarshal(sp.Files["rules.json"], &rules); err != nil {
			panic(err)
		}
		rules["entities"] = append(rules["entities"].([]any), packtest.JSON(gqlEntity))
		b, _ := json.Marshal(rules)
		sp.Files["rules.json"] = packtest.Canon(string(b))
	}
}

func (e *env) gql(sid, query string, vars map[string]any, opName string) resp {
	e.t.Helper()
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	if opName != "" {
		body["operationName"] = opName
	}
	h := sess(sid)
	h["X-User-Id"] = "user-test"
	return e.req("POST", "/__svc/orders-graph/graphql", body, h)
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, _ := v.(map[string]any)
		v = m[p]
	}
	return v
}

// A stitching gateway: the introspection query first, answered with the
// captured schema; then named operations with variables, answered from
// the entities of the session (create, then read by the variable id).
func TestGraphQLStitchedFlow(t *testing.T) {
	e := newEnv(t, withSpec(withGraphQL(true)))
	sid := e.newSession(map[string]any{"seed": 7})

	r := e.gql(sid, graphqltest.IntrospectionQuery, nil, "IntrospectionQuery")
	if r.status != 200 {
		t.Fatalf("introspection: %d %s", r.status, r.body)
	}
	sch := dig(r.json(), "data", "__schema").(map[string]any)
	if dig(sch, "queryType", "name") != "Query" || dig(sch, "mutationType", "name") != "Mutation" {
		t.Fatalf("roots: %v", sch)
	}
	var order map[string]any
	for _, tp := range sch["types"].([]any) {
		if m := tp.(map[string]any); m["name"] == "Order" {
			order = m
		}
	}
	if order == nil || len(order["fields"].([]any)) != 3 || order["description"] != nil || order["interfaces"] == nil {
		t.Fatalf("Order: %v", order)
	}
	if strings.Contains(string(r.body), "Mario") || strings.Contains(string(r.body), "Torino") {
		t.Fatal("a description reached the mock")
	}

	// __type of one type, with a variable.
	r = e.gql(sid, `query T($n: String!) { __type(name: $n) { name kind fields { name type { kind ofType { name } } } } }`, map[string]any{"n": "Order"}, "")
	if dig(r.json(), "data", "__type", "name") != "Order" {
		t.Fatalf("__type: %s", r.body)
	}

	r = e.gql(sid, graphqltest.CreateOrder, map[string]any{"input": map[string]any{"note": "x", "customerId": "C-1"}}, "CreateOrder")
	if r.status != 200 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	id, _ := dig(r.json(), "data", "createOrder", "id").(string)
	if !strings.HasPrefix(id, "GOR-SYN-") || dig(r.json(), "data", "createOrder", "status") != "CREATED" {
		t.Fatalf("create answer: %s", r.body)
	}

	r = e.gql(sid, graphqltest.GetOrder, map[string]any{"id": id}, "GetOrder")
	if dig(r.json(), "data", "order", "id") != id || dig(r.json(), "data", "order", "status") != "CREATED" {
		t.Fatalf("read: %s", r.body)
	}
	if _, ok := dig(r.json(), "data", "order").(map[string]any)["total"]; !ok {
		t.Fatalf("total missing: %s", r.body)
	}

	// Same operation, another selection: an alias and __typename.
	r = e.gql(sid, `query GetOrder($id: ID!) { o: order(id: $id) { id __typename } }`, map[string]any{"id": id}, "")
	o, _ := dig(r.json(), "data", "o").(map[string]any)
	if o["id"] != id || o["__typename"] != "Order" || len(o) != 2 {
		t.Fatalf("alias: %s", r.body)
	}

	// The same document over GET.
	q := url.Values{"query": {graphqltest.GetOrder}, "variables": {`{"id":"` + id + `"}`}}
	h := sess(sid)
	h["X-User-Id"] = "user-test"
	r = e.req("GET", "/__svc/orders-graph/graphql?"+q.Encode(), nil, h)
	if dig(r.json(), "data", "order", "id") != id {
		t.Fatalf("GET: %d %s", r.status, r.body)
	}

	// An anonymous operation is found by the hash of its shape, with other
	// inline literals.
	r = e.gql(sid, `{ orders(first: 3, status: CREATED) { id status } }`, nil, "")
	if r.status != 200 || dig(r.json(), "data", "orders") == nil {
		t.Fatalf("anonymous: %d %s", r.status, r.body)
	}

	// An operation never observed.
	r = e.gql(sid, `query Other { customers { id } }`, nil, "")
	errs, _ := dig(r.json(), "errors").([]any)
	if r.status != 200 || len(errs) != 1 || !strings.Contains(dig(errs[0], "message").(string), "operation not observed: QUERY Other") ||
		r.header.Get("X-TT-Unmatched") != "no-operation" {
		t.Fatalf("unknown: %d %s", r.status, r.body)
	}

	// A syntax error.
	r = e.gql(sid, `{ order(id: ) }`, nil, "")
	if r.status != 400 || dig(r.json(), "errors") == nil {
		t.Fatalf("syntax: %d %s", r.status, r.body)
	}
}

// Faults of a GraphQL operation become a GraphQL errors array.
func TestGraphQLFaults(t *testing.T) {
	e := newEnv(t, withSpec(withGraphQL(true)))
	sid := e.newSession(map[string]any{"faults": map[string]any{"mode": "custom", "rules": []any{
		map[string]any{"service": "orders-graph", "op": "POST /graphql#GetOrder", "status": 503, "p": 1}}}})
	r := e.gql(sid, graphqltest.GetOrder, map[string]any{"id": "GOR-SYN-0001"}, "GetOrder")
	errs, _ := dig(r.json(), "errors").([]any)
	if r.status != 503 || len(errs) != 1 || dig(errs[0], "extensions", "code") != "HTTP_SERVICE_UNAVAILABLE" || dig(r.json(), "data") != nil {
		t.Fatalf("fault: %d %s", r.status, r.body)
	}
	// Other operations are not affected.
	r = e.gql(sid, graphqltest.CreateOrder, map[string]any{"input": map[string]any{"note": "n", "customerId": "C-1"}}, "")
	if r.status != 200 || dig(r.json(), "data", "createOrder", "id") == nil {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
}

// Without a captured introspection call the mock synthesizes a schema
// from the observed operations, enough for a gateway to stitch it.
func TestGraphQLSynthesizedIntrospection(t *testing.T) {
	e := newEnv(t, withSpec(withGraphQL(false)))
	sid := e.newSession(map[string]any{})
	r := e.gql(sid, graphqltest.IntrospectionQuery, nil, "")
	sch, _ := dig(r.json(), "data", "__schema").(map[string]any)
	if sch == nil {
		t.Fatalf("introspection: %d %s", r.status, r.body)
	}
	types := map[string]map[string]any{}
	for _, tp := range sch["types"].([]any) {
		m := tp.(map[string]any)
		types[m["name"].(string)] = m
	}
	q := types["Query"]
	if q == nil || types["Mutation"] == nil || types["OrderInput"] == nil || dig(sch, "mutationType", "name") != "Mutation" {
		t.Fatalf("types: %s", r.body)
	}
	var orderField map[string]any
	for _, f := range q["fields"].([]any) {
		if m := f.(map[string]any); m["name"] == "order" {
			orderField = m
		}
	}
	if orderField == nil {
		t.Fatalf("Query.order missing: %v", q)
	}
	a := orderField["args"].([]any)[0].(map[string]any)
	if a["name"] != "id" || dig(a, "type", "kind") != "NON_NULL" || dig(a, "type", "ofType", "name") != "ID" {
		t.Fatalf("argument: %v", a)
	}
	if dig(orderField, "type", "name") != "Order" || types["Order"] == nil {
		t.Fatalf("result type: %v", orderField)
	}
}
