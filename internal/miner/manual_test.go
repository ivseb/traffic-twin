package miner

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// demoContracts serves the demo contracts (invented e-commerce + carrier).
type demoContracts struct{}

func (demoContracts) ContractDocs(context.Context, []string) ([]ContractDoc, error) {
	sp := packtest.DemoSpec()
	return []ContractDoc{
		{Service: "shop-api", Doc: sp.Files["contracts/shop-api.openapi.json"]},
		{Service: "shipping-ext", Doc: sp.Files["contracts/shipping-ext.openapi.json"]},
	}, nil
}

func newManualService(t *testing.T) (*Service, *audit.Log) {
	t.Helper()
	fix, _ := demoFixture(t)
	db := openDB(t)
	al := audit.New(db)
	now := fix.sim.end.Add(time.Hour)
	s, err := New(Deps{DB: db, Events: fix.store, Domains: fix.doms, Audit: al, Contracts: demoContracts{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, al
}

// A rule written by hand: when an order is created, after 1h it becomes
// ON_HOLD, and from then on the carrier's shipment list fails half the time.
const manualRule = `{
  "kind": "causal",
  "title": "Un ordine creato va in attesa e il corriere diventa instabile",
  "cause": {"service": "shop-api", "op": "POST /orders", "when": {"status": [201]},
            "bind": {"order": {"from": "resp.body", "path": "$.id"}}},
  "effects": [
    {"id": "order-on-hold", "entity": "order", "target_id": "${order}", "set": {"status": "ON_HOLD"}, "after": "1h"},
    {"id": "carrier-flaky", "respond": {"service": "shipping-ext", "op": "GET /v1/shipments", "status": 503, "p": 0.5}, "after_effect": "order-on-hold", "after": "0s"}
  ],
  "outcomes": [{"name": "always", "p": 1, "effects": ["order-on-hold", "carrier-flaky"]}]
}`

func problemCodes(t *testing.T, body []byte) []string {
	t.Helper()
	var e struct {
		Code    string           `json:"code"`
		Details []map[string]any `json:"details"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Code != "invalid_rule" {
		t.Fatalf("not an invalid_rule answer: %s", body)
	}
	var out []string
	for _, d := range e.Details {
		out = append(out, d["code"].(string)+"@"+d["path"].(string))
	}
	return out
}

func TestManualRuleCatalogAndValidation(t *testing.T) {
	s, _ := newManualService(t)
	h := s.Handler()
	reviewer := &auth.Principal{UserID: "usr_rev", DisplayName: "rev", Roles: []auth.Role{auth.RoleRuleReviewer}}
	auditor := &auth.Principal{UserID: "usr_aud", DisplayName: "aud", Roles: []auth.Role{auth.RoleAuditor}}

	code, body := call(t, h, auditor, "GET", "/api/v1/rules/catalog", "")
	var cat Catalog
	if code != http.StatusOK || json.Unmarshal(body, &cat) != nil {
		t.Fatalf("catalog: %d %s", code, body)
	}
	if op := cat.Service("shop-api").Op("POST /orders"); op == nil || len(op.Statuses) == 0 || len(op.Response) == 0 {
		t.Fatalf("catalog op: %+v", op)
	}
	ord := cat.Entity("order")
	if ord == nil {
		t.Fatalf("catalog entities: %+v", cat.Entities)
	}
	var states []string
	for _, f := range ord.Fields {
		if f.Name == "status" {
			states = f.Values
		}
	}
	if len(states) == 0 {
		t.Fatalf("no states for order.status: %+v", ord.Fields)
	}

	// Refused: an operation that does not exist, a field the entity does
	// not have, a response field the cause does not return.
	bad := map[string]string{
		"unknown_op@cause.op":                 strings.Replace(manualRule, `"op": "POST /orders"`, `"op": "POST /ordini"`, 1),
		"unknown_field@effects[0].set.colour": strings.Replace(manualRule, `"set": {"status": "ON_HOLD"}`, `"set": {"colour": "red"}`, 1),
		"unknown_field@cause.bind.order":      strings.Replace(manualRule, `"path": "$.id"`, `"path": "$.orderNumber"`, 1),
		"unknown_op@effects[1].respond.op":    strings.Replace(manualRule, `"op": "GET /v1/shipments"`, `"op": "GET /v1/quotes"`, 1),
		"unknown_service@cause.service":       strings.Replace(manualRule, `"service": "shop-api"`, `"service": "billing"`, 1),
	}
	for want, rule := range bad {
		code, body := call(t, h, reviewer, "POST", "/api/v1/rules", rule)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d %s", want, code, body)
		}
		if got := problemCodes(t, body); !strings.Contains(strings.Join(got, " "), want) {
			t.Errorf("%s: problems %v", want, got)
		}
	}
	// Structural problems (outcome probabilities) are refused too.
	code, body = call(t, h, reviewer, "POST", "/api/v1/rules", strings.Replace(manualRule, `"p": 1,`, `"p": 0.4,`, 1))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("p sum: %d %s", code, body)
	}
	// The dry run says the same without storing anything.
	code, body = call(t, h, auditor, "POST", "/api/v1/rules/check", bad["unknown_op@cause.op"])
	if code != http.StatusOK || !strings.Contains(string(body), `"valid":false`) || !strings.Contains(string(body), "unknown_op") {
		t.Fatalf("check: %d %s", code, body)
	}
	code, body = call(t, h, auditor, "POST", "/api/v1/rules/check", manualRule)
	if code != http.StatusOK || !strings.Contains(string(body), `"valid":true`) {
		t.Fatalf("check ok: %d %s", code, body)
	}
	// Only a rule reviewer writes rules.
	if code, _ := call(t, h, auditor, "POST", "/api/v1/rules", manualRule); code != http.StatusForbidden {
		t.Fatalf("auditor create: %d", code)
	}
}

func TestManualRuleLifecycle(t *testing.T) {
	s, al := newManualService(t)
	h := s.Handler()
	ctx := context.Background()
	admin := &auth.Principal{UserID: "usr_adm", DisplayName: "adm", Roles: []auth.Role{auth.RoleAdmin}}

	code, body := call(t, h, admin, "POST", "/api/v1/rules", manualRule)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created map[string]any
	_ = json.Unmarshal(body, &created)
	id, _ := created["id"].(string)
	if created["origin"] != "manual" || created["status"] != "draft" || id == "" {
		t.Fatalf("created: %s", body)
	}
	// The admin approves alone (audited as an override).
	if code, body := call(t, h, admin, "POST", "/api/v1/rules/"+id+"/approve", ""); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	found := false
	for _, e := range auditEntries(t, al) {
		if e.Action == "rule.create" && e.Outcome == audit.Success && e.Details["origin"] == "manual" && e.Details["admin_override"] == "true" {
			found = true
		}
	}
	if !found {
		t.Fatal("rule.create not audited")
	}
	// Mining again never touches a manual rule (no strike, no refresh).
	for i := 0; i < 4; i++ {
		if _, err := s.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r := mustGet(t, s.Repo(), id)
	if r.Rule.Status() != StatusApproved || r.Strikes != 0 || r.Rule.Origin() != OriginManual {
		t.Fatalf("after mining: %s strikes %d", r.Rule.Status(), r.Strikes)
	}
	// It is exported with the approved rules, origin and response effect included.
	doc, err := s.Repo().Document(ctx, StatusApproved, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	if !strings.Contains(string(b), `"origin":"manual"`) || !strings.Contains(string(b), `"respond":{"service":"shipping-ext","op":"GET /v1/shipments","status":503,"p":0.5}`) {
		t.Fatalf("document: %s", b)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("document invalid: %v", err)
	}
	// Changing an approved rule makes a new draft that supersedes it.
	code, body = call(t, h, admin, "PUT", "/api/v1/rules/"+id, strings.Replace(manualRule, `"p": 0.5`, `"p": 0.2`, 1))
	var nd map[string]any
	_ = json.Unmarshal(body, &nd)
	if code != http.StatusOK || nd["supersedes"] != id || nd["status"] != "draft" || nd["id"] == id || nd["origin"] != "manual" {
		t.Fatalf("replace approved: %d %s", code, body)
	}
}

func TestEditMinedDraftDefinition(t *testing.T) {
	s, _ := newManualService(t)
	h := s.Handler()
	ctx := context.Background()
	reviewer := &auth.Principal{UserID: "usr_rev", DisplayName: "rev", Roles: []auth.Role{auth.RoleRuleReviewer}}
	var id string
	var def *CausalRule
	drafts, _ := s.Repo().List(ctx, StatusDraft)
	for _, d := range drafts {
		if d.Rule.Causal != nil && d.Rule.Causal.Cause.Op == "POST /orders" {
			id, def = d.Rule.ID(), d.Rule.Causal
		}
	}
	if def == nil {
		t.Fatal("no mined causal draft")
	}
	// The reviewer adds a response effect to the mined rule.
	def.Effects = append(def.Effects, Effect{ID: "carrier-slow", Respond: &Respond{Service: "shipping-ext", Op: "GET /v1/shipments", Status: 503, Times: 1}, After: Delay{Single: "0s"}})
	for i := range def.Outcomes {
		def.Outcomes[i].Effects = append(def.Outcomes[i].Effects, "carrier-slow")
	}
	b, _ := json.Marshal(def)
	code, body := call(t, h, reviewer, "PUT", "/api/v1/rules/"+id, string(b))
	if code != http.StatusOK {
		t.Fatalf("replace draft: %d %s", code, body)
	}
	// A mining run refreshes the evidence but keeps the person's definition.
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r := mustGet(t, s.Repo(), id)
	if r.Rule.Status() != StatusDraft || r.Rule.Origin() != OriginMined {
		t.Fatalf("draft: %s %s", r.Rule.Status(), r.Rule.Origin())
	}
	has := false
	for _, e := range r.Rule.Causal.Effects {
		has = has || e.ID == "carrier-slow"
	}
	if !has || r.Rule.Causal.Evidence.Counts.Causes == 0 {
		t.Fatalf("the refresh lost the definition or the evidence: %+v", r.Rule.Causal)
	}
	// A rejected rule cannot change.
	if code, _ := call(t, h, reviewer, "POST", "/api/v1/rules/"+id+"/reject", ""); code != http.StatusOK {
		t.Fatal("reject")
	}
	if code, _ := call(t, h, reviewer, "PUT", "/api/v1/rules/"+id, string(b)); code != http.StatusConflict {
		t.Fatalf("replace rejected: %d", code)
	}
}
