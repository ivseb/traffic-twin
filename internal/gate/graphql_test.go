package gate

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/graphql/graphqltest"
)

// A contract with GraphQL operations and a captured schema passes the
// provenance check: its names and shapes come from gql: tokens. A value
// slipped into the GraphQL extensions does not.
func TestGateGraphQLContract(t *testing.T) {
	evs, err := graphqltest.Events(graphqltest.Exchanges(25))
	if err != nil {
		t.Fatal(err)
	}
	in := contract.NewInferrer(contract.DefaultConfig(), nil)
	for _, ev := range evs {
		in.Add(ev, nil)
	}
	doc, err := in.Contracts(contract.Window{})[0].JSON(contract.RenderOptions{PackSafe: true, NoExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	run := func(doc string) map[string]string {
		inp := input(okWorld, &fakeMatcher{})
		inp.Files["contracts/orders-graph.openapi.json"] = []byte(doc)
		for _, v := range []string{"CREATED", "SHIPPED"} {
			inp.Prov.Declared[v] = 50
		}
		res, err := Run(context.Background(), inp)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.Report.Checks {
			if c.Status == "fail" {
				t.Logf("%s: %+v", c.ID, c.Findings)
			}
		}
		return status(res)
	}
	if st := run(string(doc)); st[CheckProvenance] != "pass" {
		t.Fatalf("GraphQL contract refused: %v", st)
	}
	bad := strings.Replace(string(doc), `"name":"GetOrder"`, `"name":"mario.rossi@example.org"`, 1)
	if bad == string(doc) {
		t.Fatal("fixture changed")
	}
	if st := run(bad); st[CheckProvenance] != "fail" {
		t.Fatalf("a value in x-tt-graphql passed: %v", st)
	}
}
