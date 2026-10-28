package world

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"
)

type fixedRules struct{ doc []byte }

func (f fixedRules) ApprovedRules(context.Context) (*RuleSet, error) {
	return &RuleSet{Doc: f.doc}, nil
}

// groupContracts gives each group the contracts of its services.
type groupContracts map[string][]string

func (g groupContracts) Contracts(context.Context) ([]Contract, error) { return nil, nil }

func (g groupContracts) ContractsIn(_ context.Context, group string) ([]Contract, error) {
	var out []Contract
	for _, s := range g[group] {
		out = append(out, Contract{Service: s, Group: group, Doc: []byte(`{"openapi":"3.1.0","paths":{}}`)})
	}
	return out, nil
}

var teamContracts = groupContracts{"demo": {"shop-api", "shipping-ext"}, "billing": {"billing-api"}}

// docOf returns the document of twoTeams with change applied.
func docOf(t *testing.T, change func(doc map[string]any)) []byte {
	t.Helper()
	r := twoTeams(t)
	var doc map[string]any
	b, _ := json.Marshal(r.Doc)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(doc)
	}
	b, _ = json.Marshal(doc)
	return b
}

func inputsFor(t *testing.T, doc []byte, group string) (*Input, error) {
	t.Helper()
	s := &Service{o: Options{Rules: fixedRules{doc}, Contracts: teamContracts}}
	in, _, err := s.InputsIn(context.Background(), Params{Seed: 1, Customers: 5, T0: testT0}, nil, nil, nil, group)
	return in, err
}

// A lab bug: the demo group's order entity was renamed to
// another team's (orders-api), every demo rule needed orders-api and the
// demo world came out with no rule and no entity, silently. Now the
// generation refuses with no_usable_rules and names the group's own rules
// and the services they miss, never another team's rules.
func TestWorldWithEveryRuleOutOfScopeIsRefused(t *testing.T) {
	doc := docOf(t, func(doc map[string]any) {
		for _, e := range doc["entities"].([]any) {
			if m := e.(map[string]any); m["name"] == "order" {
				m["service"] = "orders-api"
			}
		}
	})
	_, err := inputsFor(t, doc, "demo")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "no_usable_rules" || ae.Status != http.StatusUnprocessableEntity {
		t.Fatalf("err = %v", err)
	}
	var ids []string
	for _, d := range ae.Details {
		id, _ := d["rule"].(string)
		ids = append(ids, id)
		if d["reason"] == "out_of_scope" && !slices.Contains(d["services"].([]string), "orders-api") {
			t.Errorf("detail %v does not name orders-api", d)
		}
	}
	if !slices.Contains(ids, "r-0007") {
		t.Errorf("details %v miss the demo rule r-0007", ae.Details)
	}
	if slices.Contains(ids, "r-0020") {
		t.Errorf("details name another team's rule: %v", ae.Details)
	}

	// The other team is not affected.
	in, err := inputsFor(t, doc, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(in.Rules.IDs, []string{"r-0020"}) || len(in.Report.Excluded) != 0 {
		t.Fatalf("billing world: ids %v, excluded %+v", in.Rules.IDs, in.Report.Excluded)
	}
}

// One of the group's rules needs another team's service: the world is made
// with the others and the answer names it (excluded_rules).
func TestWorldReportsTheGroupsExcludedRules(t *testing.T) {
	doc := docOf(t, func(doc map[string]any) {
		doc["rules"] = append(doc["rules"].([]any), map[string]any{
			"id": "r-0030", "kind": "causal", "status": "approved", "title": "order invoiced",
			"cause": map[string]any{"service": "shop-api", "op": "POST /orders", "when": map[string]any{"status": []any{201}},
				"bind": map[string]any{"invoice": map[string]any{"from": "resp.body", "path": "$.invoiceId"}}},
			"effects":  []any{map[string]any{"id": "e1", "entity": "invoice", "target_id": "${invoice}", "set": map[string]any{"status": "PAID"}, "after": "5m"}},
			"outcomes": []any{map[string]any{"name": "paid", "p": 1.0, "effects": []any{"e1"}}},
		})
	})
	in, err := inputsFor(t, doc, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Rules.IDs) == 0 || slices.Contains(in.Rules.IDs, "r-0030") {
		t.Fatalf("ids %v", in.Rules.IDs)
	}
	if len(in.Report.Excluded) != 1 || in.Report.Excluded[0].ID != "r-0030" || !slices.Equal(in.Report.Excluded[0].Services, []string{"billing-api"}) {
		t.Fatalf("excluded %+v", in.Report.Excluded)
	}
}

// Every approved rule unusable (no scope): refused with the reasons.
func TestWorldWithEveryRuleUnusableIsRefused(t *testing.T) {
	doc := []byte(`{"format":"tt.rules/v1","entities":[],"rules":[{"id":"r-0001","kind":"causal","status":"approved","title":"x",
		"cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201]},"bind":{}},
		"effects":[{"id":"e1","entity":"order","create":{},"after":"0s"}],"outcomes":[{"name":"ok","p":1,"effects":["e1"]}]}]}`)
	_, err := inputsFor(t, doc, "")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "no_usable_rules" || len(ae.Details) != 1 || ae.Details[0]["reason"] != "unusable" {
		t.Fatalf("err = %v (%+v)", err, ae)
	}
	// No approved rule at all: a world of the contracts only, as before.
	if _, err := inputsFor(t, []byte(`{"format":"tt.rules/v1","entities":[],"rules":[]}`), "demo"); err != nil {
		t.Fatal(err)
	}
}
