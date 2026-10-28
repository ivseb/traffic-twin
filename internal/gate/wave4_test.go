package gate

import (
	"context"
	"strings"
	"testing"
)

// Rules v1.9: a customer attribute reaches the world's profiles; its
// values are clear values of the rules (provenance), and both its values
// and the subjects it counts respect k_min.
func TestGateCustomerAttributes(t *testing.T) {
	ctx := context.Background()
	attr := `"attributes":[{"name":"segment","values":{"GOLD":0.5,"STANDARD":0.5},"subjects":40,"fields":[{"service":"shop-api","op":"POST /orders","at":{"from":"resp.body","path":"$.segment"}}]}],`
	world := strings.Replace(okWorld, `"name":"Anna Rossi"`, `"name":"Anna Rossi","segment":"GOLD"`, 1)
	mk := func(rules string) *Input {
		in := input(world, &fakeMatcher{})
		in.Files["rules.json"] = []byte(strings.Replace(string(in.Files["rules.json"]), `"entities":`, rules+`"entities":`, 1))
		in.Prov.Declared["GOLD"], in.Prov.Declared["STANDARD"] = 30, 30
		return in
	}
	res, err := Run(ctx, mk(attr))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("an attribute of 40 subjects failed: %v %+v %+v", status(res), findingsOf(res, CheckProvenance), findingsOf(res, CheckK))
	}
	// Without the attribute, the profile key has no provenance.
	if res, _ := Run(ctx, mk("")); status(res)[CheckProvenance] != "fail" {
		t.Fatalf("a profile key that is no attribute passed: %v", status(res))
	}
	// Too few subjects behind the attribute.
	if res, _ := Run(ctx, mk(strings.Replace(attr, `"subjects":40`, `"subjects":7`, 1))); status(res)[CheckK] != "fail" {
		t.Fatalf("an attribute of 7 subjects passed k: %v", status(res))
	}
	// A value seen for fewer than k_min subjects.
	in := mk(attr)
	in.Prov.Declared["GOLD"] = 4
	if res, _ := Run(ctx, in); status(res)[CheckK] != "fail" {
		t.Fatalf("a rare attribute value passed k: %v", status(res))
	}
	// An aggregate counts its subjects too.
	agg := `"aggregates":[{"service":"shop-api","op":"POST /orders","at":{"from":"resp.body","path":"$.n"},"count":{"entity":"order"},"subjects":3}],`
	if res, _ := Run(ctx, mk(attr+agg)); status(res)[CheckK] != "fail" {
		t.Fatalf("an aggregate of 3 subjects passed k: %v", status(res))
	}
}
