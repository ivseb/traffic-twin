// Package graphqltest builds the events of an invented GraphQL service for
// tests (orders-graph: one /graphql endpoint, a few queries and a mutation,
// the standard introspection call). The exchanges go through the real
// sanitizer with graphql rules, then through the logical split of the
// intake, exactly as the core stores them. Test support only.
package graphqltest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Service is the name of the invented GraphQL service.
const Service = "orders-graph"

// Endpoint is its GraphQL endpoint.
const Endpoint = "/graphql"

// IntrospectionQuery is the standard introspection query of graphql-js
// (getIntrospectionQuery), as a stitching gateway sends it.
const IntrospectionQuery = `
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { ...FullType }
        directives { name description locations args { ...InputValue } }
      }
    }
    fragment FullType on __Type {
      kind name description
      fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }
    fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
    fragment TypeRef on __Type {
      kind name
      ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
    }`

// GetOrder, CreateOrder and ListOrders are the documents the client sends.
const (
	GetOrder    = "query GetOrder($id: ID!) { order(id: $id) { id status total } }"
	CreateOrder = "mutation CreateOrder($input: OrderInput!) { createOrder(input: $input) { id status } }"
	ListOrders  = `{ orders(first: 10, status: SHIPPED) { id status } }` // anonymous, inline literals
)

func nonNull(of any) map[string]any {
	return map[string]any{"kind": "NON_NULL", "name": nil, "ofType": of}
}
func list(of any) map[string]any { return map[string]any{"kind": "LIST", "name": nil, "ofType": of} }
func named(kind, name string) map[string]any {
	return map[string]any{"kind": kind, "name": name, "ofType": nil}
}

func field(name string, typ any, args ...any) map[string]any {
	if args == nil {
		args = []any{}
	}
	return map[string]any{"name": name, "description": "The " + name + " of Mario Rossi", "args": args, "type": typ,
		"isDeprecated": false, "deprecationReason": nil}
}

func arg(name string, typ any) map[string]any {
	return map[string]any{"name": name, "description": nil, "type": typ, "defaultValue": nil}
}

func object(name string, fields ...any) map[string]any {
	return map[string]any{"kind": "OBJECT", "name": name, "description": "secret note", "fields": fields, "inputFields": nil,
		"interfaces": []any{}, "enumValues": nil, "possibleTypes": nil}
}

// Schema is the introspection result of the service.
func Schema() map[string]any {
	str, id, flt := named("SCALAR", "String"), named("SCALAR", "ID"), named("SCALAR", "Float")
	types := []any{
		object("Query",
			field("order", named("OBJECT", "Order"), arg("id", nonNull(id))),
			field("orders", nonNull(list(nonNull(named("OBJECT", "Order")))), arg("first", named("SCALAR", "Int")), arg("status", named("ENUM", "OrderStatus")))),
		object("Mutation", field("createOrder", named("OBJECT", "Order"), arg("input", nonNull(named("INPUT_OBJECT", "OrderInput"))))),
		object("Order", field("id", nonNull(id)), field("status", named("ENUM", "OrderStatus")), field("total", flt)),
		map[string]any{"kind": "ENUM", "name": "OrderStatus", "description": nil, "fields": nil, "inputFields": nil, "interfaces": nil, "possibleTypes": nil,
			"enumValues": []any{
				map[string]any{"name": "CREATED", "description": nil, "isDeprecated": false, "deprecationReason": nil},
				map[string]any{"name": "SHIPPED", "description": "sent to Torino", "isDeprecated": false, "deprecationReason": nil}}},
		map[string]any{"kind": "INPUT_OBJECT", "name": "OrderInput", "description": nil, "fields": nil, "interfaces": nil, "enumValues": nil, "possibleTypes": nil,
			"inputFields": []any{arg("note", str), arg("customerId", nonNull(id))}},
		named("SCALAR", "String"), named("SCALAR", "ID"), named("SCALAR", "Float"), named("SCALAR", "Int"), named("SCALAR", "Boolean"),
	}
	for _, t := range types[len(types)-5:] {
		m := t.(map[string]any)
		delete(m, "ofType")
		m["description"], m["fields"], m["inputFields"], m["interfaces"], m["enumValues"], m["possibleTypes"] = nil, nil, nil, nil, nil, nil
	}
	return map[string]any{"__schema": map[string]any{
		"queryType": map[string]any{"name": "Query"}, "mutationType": map[string]any{"name": "Mutation"}, "subscriptionType": nil,
		"types": types,
		"directives": []any{map[string]any{"name": "include", "description": "Directs the executor", "locations": []any{"FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"},
			"args": []any{arg("if", nonNull(named("SCALAR", "Boolean")))}}},
	}}
}

// Policy compiles the policy of the source: graphql on the document and
// on the introspection names, hmac on the order ids, code on the status,
// the user from x-user-id.
func Policy() (*policy.Policy, error) {
	resp := map[string]any{
		"$.data.order.id": "hmac(order)", "$.data.createOrder.id": "hmac(order)", "$.data.orders[*].id": "hmac(order)",
		"$.data.order.status": "code", "$.data.createOrder.status": "code", "$.data.orders[*].status": "code",
	}
	for _, p := range policy.GraphQLIntrospectionPaths() {
		resp[p] = "graphql"
	}
	author := map[string]any{
		"format": "tt.policy/v1", "policy_id": "p-graph", "default": "drop",
		"hmac":     map[string]any{"kid": "k1", "epoch": "2026-10"},
		"identity": map[string]any{"subject": map[string]any{"from": "header", "name": "x-user-id"}},
		"sampling": map[string]any{"rate": 1},
		"services": map[string]any{Service: map[string]any{"match": map[string]any{"inbound": true}, "ops": map[string]any{
			"POST " + Endpoint: map[string]any{
				"request":  map[string]any{"$.query": "graphql", "$.variables.id": "hmac(order)", "$.variables.input.customerId": "hmac(customer)"},
				"response": resp,
			}}}},
	}
	b, _ := json.Marshal(author)
	var doc any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		return nil, err
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: T0.Add(-time.Hour), Groups: []string{"shop"}})
	return p, err
}

// T0 is the time of the first exchange.
var T0 = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

// Exchange is one invented call.
type Exchange struct {
	Query  string
	Vars   map[string]any
	OpName string
	Status int
	Resp   any
	User   string
}

// Exchanges is the invented traffic: the introspection call of the
// gateway, then n calls of each operation by n users.
func Exchanges(n int) []Exchange {
	out := []Exchange{{Query: IntrospectionQuery, OpName: "IntrospectionQuery", Status: 200, Resp: map[string]any{"data": Schema()}}}
	for i := 0; i < n; i++ {
		user := fmt.Sprintf("user-%03d", i)
		oid := fmt.Sprintf("ORD-2026-%06d", 100+i)
		out = append(out,
			Exchange{Query: CreateOrder, OpName: "CreateOrder", Status: 200, User: user,
				Vars: map[string]any{"input": map[string]any{"note": "citofono Rossi", "customerId": "C-" + user}},
				Resp: map[string]any{"data": map[string]any{"createOrder": map[string]any{"id": oid, "status": "CREATED"}}}},
			Exchange{Query: GetOrder, OpName: "GetOrder", Status: 200, User: user, Vars: map[string]any{"id": oid},
				Resp: map[string]any{"data": map[string]any{"order": map[string]any{"id": oid, "status": "CREATED", "total": 12.5 + float64(i)}}}},
			Exchange{Query: ListOrders, Status: 200, User: user,
				Resp: map[string]any{"data": map[string]any{"orders": []any{map[string]any{"id": oid, "status": "SHIPPED"}}}}},
		)
	}
	return out
}

// Events sanitizes the exchanges with the policy and returns the stored
// events (logical ops applied as the intake does).
func Events(xs []Exchange) ([]*event.Event, error) {
	p, err := Policy()
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := sanitizer.NewKey("k1", secret)
	if err != nil {
		return nil, err
	}
	eng, err := sanitizer.NewEngineWithKey(p, key)
	if err != nil {
		return nil, err
	}
	var out []*event.Event
	for i, x := range xs {
		body := map[string]any{"query": x.Query}
		if x.Vars != nil {
			body["variables"] = x.Vars
		}
		if x.OpName != "" {
			body["operationName"] = x.OpName
		}
		rb, _ := json.Marshal(body)
		sb, _ := json.Marshal(x.Resp)
		hdr := []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}}
		if x.User != "" {
			hdr = append(hdr, sanitizer.Header{Name: "X-User-Id", Value: []byte(x.User)})
		}
		ex := &sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: Service, Method: "POST", RawPath: []byte(Endpoint),
			ReqHeaders: hdr, ReqBody: rb, Status: x.Status,
			RespHeaders: []sanitizer.Header{{Name: "Content-Type", Value: []byte("application/json")}}, RespBody: sb}
		ts := T0.Add(time.Duration(i) * time.Second)
		o, err := eng.Sanitize(ex, ts, sanitizer.ByRandom)
		if err != nil {
			return nil, err
		}
		raw, err := sanitizer.BuildEvent(sanitizer.EventMeta{PolicyID: p.PolicyID, PolicyVersion: 1,
			PolicyHash: "sha256:" + strings.Repeat("ab", 32), SourceKind: "sdk-node", SourceVersion: "1.0.0", SourceID: "src-graph01",
			TS: ts, LatencyMS: 12, Status: x.Status}, o)
		if err != nil {
			return nil, err
		}
		ev, derr := event.Decode(raw)
		if derr != nil {
			return nil, derr
		}
		if lg, ok := graphql.SplitEvent(ev); ok {
			ev.Op = lg.Op
		}
		out = append(out, ev)
	}
	return out, nil
}
