package graphql_test

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
	"github.com/ivseb/traffic-twin/internal/graphql/graphqltest"
)

// event.md 6: one endpoint, one logical operation per operation name; an
// anonymous operation by the hash of its shape; the same anonymous shape
// with other inline literals is the same operation.
func TestSplitEvents(t *testing.T) {
	xs := graphqltest.Exchanges(2)
	xs = append(xs, graphqltest.Exchange{Query: `{ orders(first: 99, status: CREATED) { id status } }`, Status: 200,
		Resp: map[string]any{"data": map[string]any{"orders": []any{}}}})
	evs, err := graphqltest.Events(xs)
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]int{}
	for _, ev := range evs {
		ops[ev.Op]++
		if _, _, ok := event.GraphQLOperation(ev.Op); !ok {
			t.Fatalf("not split: %s", ev.Op)
		}
		if event.HTTPOp(ev.Op) != "POST /graphql" {
			t.Fatalf("HTTP op of %s", ev.Op)
		}
		if graphql.Candidate(ev) != graphql.InJSON {
			t.Fatalf("candidate of %s: %q", ev.Op, graphql.Candidate(ev))
		}
	}
	var anon string
	for op := range ops {
		if strings.Contains(op, "#~") {
			anon = op
		}
	}
	if ops["POST /graphql#IntrospectionQuery"] != 1 || ops["POST /graphql#GetOrder"] != 2 || ops["POST /graphql#CreateOrder"] != 2 || ops[anon] != 3 || len(ops) != 4 {
		t.Fatalf("ops: %v", ops)
	}
	if lg, ok := graphql.SplitEvent(evs[0]); ok {
		t.Fatalf("a split event split again: %+v", lg)
	}
}

// A document with several operations: the one whose root keys cover the
// keys of data.
func TestSplitPicksTheExecutedOperation(t *testing.T) {
	doc := `query A { order(id: 1) { id } } query B { orders { id } }`
	evs, err := graphqltest.Events([]graphqltest.Exchange{{Query: doc, OpName: "B", Status: 200,
		Resp: map[string]any{"data": map[string]any{"orders": []any{}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if evs[0].Op != "POST /graphql#B" {
		t.Fatalf("op %s", evs[0].Op)
	}
}

// The introspection result rebuilt from an event: names, no description.
func TestIntrospectionFromEvent(t *testing.T) {
	evs, err := graphqltest.Events(graphqltest.Exchanges(0))
	if err != nil {
		t.Fatal(err)
	}
	data, ok := graphql.IntrospectionFromEvent(evs[0])
	if !ok {
		t.Fatal("no schema")
	}
	types := data["__schema"].(map[string]any)["types"].([]any)
	q := types[0].(map[string]any)
	if q["name"] != "Query" || q["description"] != nil || q["kind"] != "OBJECT" {
		t.Fatalf("Query: %v", q)
	}
	f := q["fields"].([]any)[0].(map[string]any)
	if f["isDeprecated"] != false || f["name"] != "order" {
		t.Fatalf("field: %v", f)
	}
}
