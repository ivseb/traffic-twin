package mock

import (
	"encoding/json"
	"strconv"
	"testing"

	ttcontract "github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/graphql/graphqltest"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// Rules v1.7 (C16): a GraphQL read selects by field with a variable, in a
// nested list with its count.

const ordersByCustomer = "query OrdersByCustomer($customerId: ID!) { orders(customerId: $customerId) { items { id status } count } }"

// withGraphQLByField is the orders-graph service with a query that lists
// the orders of a customer (a variable compared with the field customerId).
func withGraphQLByField(sp *packtest.Spec) {
	var xs []graphqltest.Exchange
	for i := 0; i < 25; i++ {
		user := "user-" + strconv.Itoa(i)
		xs = append(xs,
			graphqltest.Exchange{Query: graphqltest.CreateOrder, OpName: "CreateOrder", Status: 200, User: user,
				Vars: map[string]any{"input": map[string]any{"note": "n", "customerId": "C-" + user}},
				Resp: map[string]any{"data": map[string]any{"createOrder": map[string]any{"id": "O-" + user, "status": "CREATED"}}}},
			graphqltest.Exchange{Query: ordersByCustomer, OpName: "OrdersByCustomer", Status: 200, User: user,
				Vars: map[string]any{"customerId": "C-" + user},
				Resp: map[string]any{"data": map[string]any{"orders": map[string]any{
					"items": []any{map[string]any{"id": "O-" + user, "status": "CREATED"}}, "count": 1}}}})
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
	rules["entities"] = append(rules["entities"].([]any), packtest.JSON(`{"name":"gorder","service":"orders-graph","id_domain":"order","id_field":"id","id_prefix":"GOR-SYN-",
  "created_by":{"op":"POST /graphql#CreateOrder","id":{"from":"resp.body","path":"$.data.createOrder.id"},
    "state":{"from":"req.body","path":"$.variables.input"},"defaults":{"status":"CREATED"}},
  "read_by":[{"op":"POST /graphql#OrdersByCustomer","by":{"from":"req.body","path":"$.variables.customerId","field":"customerId"},
    "at":{"from":"resp.body","path":"$.data.orders.items[*]"},"list":{"count":"$.data.orders.count"}}]}`))
	b, _ := json.Marshal(rules)
	sp.Files["rules.json"] = packtest.Canon(string(b))
}

func TestGraphQLReadByFieldInANestedList(t *testing.T) {
	e := newEnv(t, withSpec(withGraphQLByField))
	sid := e.newSession(map[string]any{"seed": 7})
	var ids []string
	for _, c := range []string{"C-1", "C-2", "C-1"} {
		r := e.gql(sid, graphqltest.CreateOrder, map[string]any{"input": map[string]any{"note": "n", "customerId": c}}, "CreateOrder")
		id, _ := dig(r.json(), "data", "createOrder", "id").(string)
		if r.status != 200 || id == "" {
			t.Fatalf("create: %d %s", r.status, r.body)
		}
		ids = append(ids, id)
	}
	r := e.gql(sid, ordersByCustomer, map[string]any{"customerId": "C-1"}, "OrdersByCustomer")
	items, _ := dig(r.json(), "data", "orders", "items").([]any)
	if r.status != 200 || len(items) != 2 || dig(items[0], "id") != ids[0] || dig(items[1], "id") != ids[2] {
		t.Fatalf("orders of C-1: %d %s", r.status, r.body)
	}
	if n, _ := dig(r.json(), "data", "orders", "count").(json.Number).Int64(); n != 2 {
		t.Fatalf("count: %s", r.body)
	}
	r = e.gql(sid, ordersByCustomer, map[string]any{"customerId": "C-9"}, "OrdersByCustomer")
	if items, _ := dig(r.json(), "data", "orders", "items").([]any); r.status != 200 || len(items) != 0 {
		t.Fatalf("orders of C-9: %d %s", r.status, r.body)
	}
}
