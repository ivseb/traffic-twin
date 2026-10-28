package world

import (
	"encoding/json"
	"slices"
	"testing"
)

// twoTeams is the demo rules of the shop team (shop-api, shipping-ext) plus a rule and an entity of
// another team (billing-api) on the same console.
func twoTeams(t *testing.T) *Rules {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(readTestdata(t, "rules.json"), &doc); err != nil {
		t.Fatal(err)
	}
	doc["entities"] = append(doc["entities"].([]any), map[string]any{
		"name": "invoice", "service": "billing-api", "id_domain": "invoice", "id_field": "invoiceId", "id_prefix": "INV-SYN-",
		"created_by": map[string]any{"op": "POST /invoices", "id": map[string]any{"from": "resp.body", "path": "$.invoiceId"},
			"state": map[string]any{"from": "req.body", "path": "$"}, "defaults": map[string]any{"status": "OPEN"}},
	})
	doc["rules"] = append(doc["rules"].([]any), map[string]any{
		"id": "r-0020", "kind": "causal", "status": "approved", "title": "invoice paid",
		"cause": map[string]any{"service": "billing-api", "op": "POST /invoices", "when": map[string]any{"status": []any{201}},
			"bind": map[string]any{"invoice": map[string]any{"from": "resp.body", "path": "$.invoiceId"}}},
		"effects":  []any{map[string]any{"id": "e1", "entity": "invoice", "target_id": "${invoice}", "set": map[string]any{"status": "PAID"}, "after": "5m"}},
		"outcomes": []any{map[string]any{"name": "paid", "p": 1.0, "effects": []any{"e1"}}},
	})
	b, _ := json.Marshal(doc)
	r, err := ParseRules(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRulesNeedsAndScope(t *testing.T) {
	r := twoTeams(t)
	needs := r.Needs()
	if !slices.Equal(needs["r-0020"], []string{"billing-api"}) {
		t.Fatalf("needs of the billing rule: %v", needs["r-0020"])
	}
	if !slices.Contains(needs["r-0007"], "shipping-ext") || !slices.Contains(needs["r-0007"], "shop-api") {
		t.Fatalf("needs of the shop rule (the order relates to the shipment): %v", needs["r-0007"])
	}

	// The shop team: the billing rule and entity are not theirs and stay out.
	shop, info := r.Scope([]string{"shop-api", "shipping-ext"})
	if !slices.Equal(shop.IDs, []string{"r-0007", "r-0008", "r-0012"}) || len(shop.Entities) != 2 {
		t.Fatalf("shop scope: ids %v, %d entities", shop.IDs, len(shop.Entities))
	}
	if !slices.Equal(info.Excluded["r-0020"], []string{"billing-api"}) || !slices.Equal(info.DroppedEntities, []string{"invoice"}) {
		t.Fatalf("shop scope info: %+v", info)
	}
	if got := shop.Doc["rules"].([]any); len(got) != 3 {
		t.Fatalf("the document keeps %d rules", len(got))
	}
	if got := shop.Doc["entities"].([]any); len(got) != 2 {
		t.Fatalf("the document keeps %d entities", len(got))
	}
	if shop.Entity("invoice") != nil || shop.Entity("order") == nil {
		t.Fatal("entity lookup of the scoped rules")
	}
	// A scoped world generates and holds together.
	in := demoInput(t, 7, 30)
	in.Rules = shop
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if probs := Verify(out.World, shop); len(probs) > 0 {
		t.Fatalf("scoped world: %v", probs)
	}

	// The other team gets its own rule and nothing of the shop.
	bill, info := r.Scope([]string{"billing-api"})
	if !slices.Equal(bill.IDs, []string{"r-0020"}) || len(bill.Entities) != 1 || bill.Entities[0].Name != "invoice" {
		t.Fatalf("billing scope: %v %+v", bill.IDs, bill.Entities)
	}
	if !slices.Contains(info.Excluded["r-0007"], "shop-api") {
		t.Fatalf("billing scope info: %+v", info)
	}

	// A team with a part of the services of a rule does not get half of it.
	part, info := r.Scope([]string{"shop-api"})
	if len(part.IDs) != 0 || len(part.Entities) != 0 || !slices.Equal(info.Excluded["r-0007"], []string{"shipping-ext"}) {
		t.Fatalf("partial scope: %v %v %+v", part.IDs, part.Entities, info)
	}

	// No services: nothing changes.
	if same, _ := r.Scope(nil); same != r {
		t.Fatal("an empty scope must return the rules as they are")
	}
}

// An approved rule of another team whose entity is no longer in the document
// (its traffic stopped: lab, usability test 3) is left out with its reason
// instead of stopping every world; asked for by id it is still an error.
func TestUnusableRuleIsSkipped(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(readTestdata(t, "rules.json"), &doc); err != nil {
		t.Fatal(err)
	}
	doc["rules"] = append(doc["rules"].([]any), map[string]any{
		"id": "r-0099", "kind": "causal", "status": "approved", "title": "loan message",
		"cause": map[string]any{"service": "library-loans-api", "op": "POST /loans", "when": map[string]any{"status": []any{201}},
			"bind": map[string]any{"message": map[string]any{"from": "resp.body", "path": "$.notificationId"}}},
		"effects":  []any{map[string]any{"id": "message-requested", "entity": "message", "target_id": "${message}", "set": map[string]any{"status": "queued"}}},
		"outcomes": []any{map[string]any{"name": "queued", "p": 1.0, "effects": []any{"message-requested"}}},
	})
	b, _ := json.Marshal(doc)
	r, err := ParseRules(b, nil)
	if err != nil {
		t.Fatalf("one unusable rule stopped the parse: %v", err)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].ID != "r-0099" || r.Skipped[0].Reason == "" || slices.Contains(r.IDs, "r-0099") {
		t.Fatalf("skipped %+v ids %v", r.Skipped, r.IDs)
	}
	for _, x := range r.Doc["rules"].([]any) {
		if x.(map[string]any)["id"] == "r-0099" {
			t.Fatal("the skipped rule is still in the document")
		}
	}
	if _, err := ParseRules(b, []string{"r-0099"}); err == nil {
		t.Fatal("an unusable rule asked for by id must be an error")
	}
}
