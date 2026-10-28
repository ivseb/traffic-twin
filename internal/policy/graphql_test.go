package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func compileGraphQL(t *testing.T, service string) (*Policy, error) {
	t.Helper()
	src := `{"format":"tt.policy/v1","policy_id":"p-g","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1},` + service + `}`
	dec := json.NewDecoder(strings.NewReader(src))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := AuthorFromGeneric(doc)
	if err != nil {
		return nil, err
	}
	_, p, err := Compile(a, CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC), Groups: []string{"g"}})
	return p, err
}

// policy.md 1.6: graphql only on the document of a request and on the
// names of an introspection result.
func TestGraphQLRulePlacement(t *testing.T) {
	op := func(req, resp string) string {
		return `"services":{"api":{"match":{"inbound":true},"ops":{"POST /graphql":{"request":` + req + `,"response":` + resp + `}}}}`
	}
	ok := []string{
		op(`{"$.query":"graphql"}`, `{"$.data.__schema.types[*].name":"graphql"}`),
		op(`{"$":"graphql"}`, `{"$.data.__type.fields[*].name":"graphql"}`),
		op(`{"query":{"query":"graphql"}}`, `{"$.data.__schema.queryType.name":"graphql"}`),
	}
	for _, s := range ok {
		if _, err := compileGraphQL(t, s); err != nil {
			t.Errorf("refused %s: %v", s, err)
		}
	}
	bad := []string{
		op(`{"$.variables.name":"graphql"}`, `{}`),
		op(`{"query":{"q":"graphql"}}`, `{}`),
		op(`{"headers":{"x-doc":"graphql"}}`, `{}`),
		op(`{}`, `{"$.data.user.name":"graphql"}`),
		op(`{}`, `{"$.data.__schema.*.name":"graphql"}`),
		op(`{}`, `{"$.data.__schemaX.name":"graphql"}`),
		`"global":{"request":{"body":{"$.query":"graphql"}}}`,
		`"services":{"api":{"match":{"inbound":true},"errors":{"body":{"$.data.__schema.types[*].name":"graphql"}}}}`,
	}
	for _, s := range bad {
		if _, err := compileGraphQL(t, s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

// A graphql rule never opens values: the observe version applies it without
// approvals (policy.md 7.1).
func TestGraphQLRulesAreObserveSafe(t *testing.T) {
	resp := map[string]string{}
	for _, p := range GraphQLIntrospectionPaths() {
		resp[p] = "graphql"
	}
	b, _ := json.Marshal(resp)
	p, err := compileGraphQL(t, `"services":{"api":{"match":{"inbound":true},"ops":{"POST /graphql":{"request":{"$.query":"graphql"},"response":`+string(b)+`}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if v := ClassifyValues(nil, p); v.OpensValues {
		t.Fatalf("graphql rules open values: %+v", v.Reasons)
	}
	if !HasGraphQLRules(p) {
		t.Fatal("HasGraphQLRules")
	}
	for _, path := range GraphQLIntrospectionPaths() {
		if !GraphQLResponsePath(path) {
			t.Fatalf("proposed path %s is not accepted", path)
		}
	}
}
