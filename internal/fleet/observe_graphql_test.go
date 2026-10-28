package fleet

import (
	"testing"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// The observe version puts graphql on the document of a GraphQL endpoint the
// assistant recognized, and on the introspection names; a field a person
// chose for is left alone (policy.md 7.4, v1.14).
func TestObserveGraphQLDecisions(t *testing.T) {
	res := &AssistResult{Services: []AssistService{
		{Service: "orders-graph", Name: "orders-graph", Kind: "inbound", Ops: []AssistOp{
			{Op: "POST /graphql", GraphQL: "json", Fields: []Suggestion{{Part: "request", Path: "$.variables.id", Suggestion: "hmac(order)", ReasonCode: "id"}}},
			{Op: "GET /graphql", GraphQL: "query"},
			{Op: "GET /health"},
		}},
		{Service: "host:api.example", Name: "api.example", Kind: "external", Ops: []AssistOp{{Op: "POST /graphql", GraphQL: "json"}}},
	}}
	a := &policy.Author{Services: map[string]policy.AuthorService{"orders-graph": {Ops: map[string]policy.AuthorOp{
		"GET /graphql": {Request: &policy.AuthorPart{Query: map[string]string{"query": "drop"}}}}}}}
	req := observeDecisions(res, a, nil, codeOptions{on: true, alnum: true})
	addGraphQLDecisions(&req, res, a, nil)
	if len(req.Services) != 1 || req.Services[0].Name != "orders-graph" {
		t.Fatalf("services: %+v", req.Services)
	}
	ops := map[string][]AssistDraftRule{}
	for _, o := range req.Services[0].Ops {
		ops[o.Op] = o.Rules
	}
	post := ops["POST /graphql"]
	n := len(policy.GraphQLIntrospectionPaths())
	if len(post) != 2+n || post[0].Path != "$.variables.id" || post[1].Path != "$.query" || post[1].Action != "graphql" || post[1].Part != "request" {
		t.Fatalf("POST rules: %d %+v", len(post), post[:2])
	}
	// GET: the person decided for the parameter query: only the response names.
	if get := ops["GET /graphql"]; len(get) != n || get[0].Part != "response" {
		t.Fatalf("GET rules: %+v", get)
	}
	if ops["GET /health"] != nil {
		t.Fatal("a non-GraphQL operation got graphql rules")
	}
}
