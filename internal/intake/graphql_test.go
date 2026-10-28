package intake

import (
	"context"
	"strings"
	"testing"
)

// gql: tokens (docs/spec/sanitizer.md 5.7, event.md 5.1 point 6): a shape
// only under a graphql rule of the request, a name only under a graphql
// rule of the response and behind the introspection gate rebuilt from the
// request. An accepted GraphQL exchange is stored under its logical op
// (event.md 6).
func TestGraphQLTokens(t *testing.T) {
	const body = `{
 "format":"tt.policy.body/v1","policy_id":"p-gql","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 "global":{},
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},
   "ops":[{"op":"POST /graphql",
     "request":{"body":[{"path":"$.query","action":{"action":"graphql"}}]},
     "response":{"body":[{"path":"$.data.__schema.types[*].name","action":{"action":"graphql"}}]}}]}]
}`
	pol, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.policies.Add(pol)
	mk := func(reqBody, respBody string) string {
		req := `"req":{"body":` + reqBody + `,"ct":"application/json","path":"/graphql","size":"l128"},"resp":{"body":` + respBody + `,"ct":"application/json","size":"l128"},`
		s := eventJSON(pol.Hash, "inbound", "shop-api", "POST /graphql", "policy", req)
		s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-gql","version":1`, 1)
		return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
	}
	types := func(names ...string) string {
		var parts []string
		for _, n := range names {
			parts = append(parts, `{"name":"`+n+`"}`)
		}
		return `{"data":{"__schema":{"types":[` + strings.Join(parts, ",") + `]}}}`
	}
	intro := `{"query":"gql:{__schema{types{name}}}"}`
	for _, c := range []struct {
		name, req, resp string
		want            Reason
	}{
		{"named query", `{"query":"gql:query GetOrder($id:ID!){order(id:$id){id}}"}`, `{"data":{"order":{"id":"drop:str:l8"}}}`, ReasonNone},
		{"introspection names", intro, types("gql:Query", "gql:Order"), ReasonNone},
		{"names with more than max_array types", intro, types(strings.Split(strings.Repeat("gql:T,", 40)+"gql:U", ",")...), ReasonNone},
		{"gql without rule", `{"other":"gql:{b}","query":"gql:{a}"}`, `{"data":{}}`, ReasonValueNotAllowed},
		{"not a shape", `{"query":"gql:{a"}`, `{"data":{}}`, ReasonValueNotAllowed},
		{"enum literal in a shape", `{"query":"gql:{a(x:Mario)}"}`, `{"data":{}}`, ReasonValueNotAllowed},
		{"number literal in a shape", `{"query":"gql:{a(x:42)}"}`, `{"data":{}}`, ReasonValueNotAllowed},
		{"unsafe name in a shape", `{"query":"gql:{p1234567}"}`, `{"data":{}}`, ReasonValueNotAllowed},
		{"name without the gate", `{"query":"gql:{order{id}}"}`, types("gql:Mario"), ReasonValueNotAllowed},
		{"alias trick", `{"query":"gql:{__schema:customers{types:list{name:fullName}}}"}`, types("gql:Mario"), ReasonValueNotAllowed},
		{"gate closed by a dropped document", `{"query":"drop:str:l32"}`, types("gql:Query"), ReasonValueNotAllowed},
		{"response value that is not a name", intro, types("gql:{a}"), ReasonValueNotAllowed},
		{"response name with six digits", intro, types("gql:T123456"), ReasonValueNotAllowed},
		{"token outside the alphabet", `{"query":"gql:{a}#"}`, `{"data":{}}`, ReasonSchema},
	} {
		t.Run(c.name, func(t *testing.T) {
			if rej := h.ingest(t, mk(c.req, c.resp)); rej.Reason != c.want {
				t.Fatalf("got %s (%s), want %s", rej.Reason, rej.Detail, c.want)
			}
		})
	}

	// Stored under the logical op.
	h.idle(t)
	ops := map[string]bool{}
	if err := h.in.Store().Scan(context.Background(), Query{Service: "shop-api"}, func(se *StoredEvent) error {
		ops[se.Event.Op] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"POST /graphql#GetOrder", "POST /graphql#~"} {
		found := false
		for op := range ops {
			if op == want || (strings.HasSuffix(want, "~") && strings.HasPrefix(op, want)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s not stored: %v", want, ops)
		}
	}
	// A source cannot send a logical op itself: only the intake derives it.
	if rej := h.ingest(t, strings.Replace(mk(`{"query":"gql:{a}"}`, `{"data":{}}`), `"op":"POST /graphql"`, `"op":"POST /graphql#GetOrder"`, 1)); rej.Reason == ReasonNone {
		t.Fatal("an op with # was accepted from a source")
	}
	if ops["POST /graphql"] {
		t.Fatalf("a GraphQL exchange kept its HTTP op: %v", ops)
	}
}
