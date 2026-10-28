package miner

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// Usability test 5: a rule replaced by a newer approved one (r-0018 by
// r-0019) stayed approved and in the packs, distorting the outcomes.
func TestApprovedReplacementSupersedesTheOldRule(t *testing.T) {
	_, res := demoFixture(t)
	ctx := context.Background()
	rp := NewRepo(openDB(t), DefaultConfig(), nil)
	now := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	if _, err := rp.Apply(ctx, copyResult(t, res), now, now); err != nil {
		t.Fatal(err)
	}
	orders := findStored(t, rp, "causal|shop-api|POST /orders")
	if _, err := rp.Approve(ctx, orders, "usr_a", now); err != nil {
		t.Fatal(err)
	}
	// The miner proposes the same family again with another structure.
	changed := copyResult(t, res)
	findSig(changed, "causal|shop-api|POST /orders").Structure += "|changed"
	rep, err := rp.Apply(ctx, changed, now, now.Add(time.Hour))
	if err != nil || len(rep.New) != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
	repl := rep.New[0]
	// Until the replacement is approved the old rule is still the active one.
	if mustGet(t, rp, orders).Rule.Status() != StatusApproved {
		t.Fatal("old rule left the active set before the replacement was approved")
	}
	ap, err := rp.Approve(ctx, repl, "usr_a", now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ap.Superseded) != 1 || ap.Superseded[0] != orders {
		t.Fatalf("superseded: %v", ap.Superseded)
	}
	old := mustGet(t, rp, orders)
	if old.Rule.Status() != StatusSuperseded || old.StaleReason != ReasonSupersededPrefix+repl {
		t.Fatalf("old rule: %s %q", old.Rule.Status(), old.StaleReason)
	}
	if old.Rule.Causal.Review == nil || old.Rule.Causal.Review.By[0] != "usr_a" {
		t.Errorf("history of the old rule lost: %+v", old.Rule.Causal.Review)
	}
	doc, err := rp.Document(ctx, StatusApproved, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Rules {
		if r.ID() == orders {
			t.Errorf("superseded rule %s is in the approved document (pack)", orders)
		}
	}
	// A superseded rule is not approved again.
	if _, err := rp.Approve(ctx, orders, "usr_a", now); err == nil {
		t.Error("a superseded rule was approved again")
	}
	// The next run keeps the replacement and proposes nothing new.
	rep, err = rp.Apply(ctx, copyResult(t, changed), now, now.Add(3*time.Hour))
	if err != nil || len(rep.New) != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	if mustGet(t, rp, orders).Rule.Status() != StatusSuperseded || mustGet(t, rp, repl).Rule.Status() != StatusApproved {
		t.Error("statuses changed by an unchanged run")
	}
}

func TestEditedApprovedRuleSupersededByItsApprovedEdit(t *testing.T) {
	_, res := demoFixture(t)
	ctx := context.Background()
	rp := NewRepo(openDB(t), DefaultConfig(), nil)
	now := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	if _, err := rp.Apply(ctx, copyResult(t, res), now, now); err != nil {
		t.Fatal(err)
	}
	batch := findStored(t, rp, "batch|")
	if _, err := rp.Approve(ctx, batch, "usr_a", now); err != nil {
		t.Fatal(err)
	}
	title := "Consolidamento notturno"
	ed, err := rp.Edit(ctx, batch, &title, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Approve(ctx, ed.Rule.ID(), "usr_a", now); err != nil {
		t.Fatal(err)
	}
	if mustGet(t, rp, batch).Rule.Status() != StatusSuperseded {
		t.Errorf("edited rule: %s", mustGet(t, rp, batch).Rule.Status())
	}
	if n := len(mustList(t, rp, StatusApproved)); n != 1 {
		t.Errorf("%d approved rules", n)
	}
}

// A console that approved a replacement before the rule existed has both
// rules approved: SupersedeApproved (run at start-up) settles it.
func TestSupersedeApprovedRepairsOldData(t *testing.T) {
	_, res := demoFixture(t)
	ctx := context.Background()
	db := openDB(t)
	rp := NewRepo(db, DefaultConfig(), nil)
	now := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	if _, err := rp.Apply(ctx, copyResult(t, res), now, now); err != nil {
		t.Fatal(err)
	}
	orders := findStored(t, rp, "causal|shop-api|POST /orders")
	if _, err := rp.Approve(ctx, orders, "usr_a", now); err != nil {
		t.Fatal(err)
	}
	changed := copyResult(t, res)
	findSig(changed, "causal|shop-api|POST /orders").Structure += "|changed"
	rep, err := rp.Apply(ctx, changed, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	repl := rep.New[0]
	if _, err := rp.review(ctx, repl, "usr_a", "", StatusApproved, now); err != nil {
		t.Fatal(err)
	}
	// Old behaviour: both stay approved.
	if _, err := db.ExecContext(ctx, `UPDATE miner_rules SET status = 'approved', stale_reason = NULL WHERE id = ?`, orders); err != nil {
		t.Fatal(err)
	}
	moved, err := rp.SupersedeApproved(ctx, now)
	if err != nil || len(moved) != 1 || moved[0] != orders {
		t.Fatalf("%v %v", err, moved)
	}
	if again, _ := rp.SupersedeApproved(ctx, now); len(again) != 0 {
		t.Errorf("not idempotent: %v", again)
	}
}

func TestRetireApprovedRuleAPI(t *testing.T) {
	s, al := newManualService(t)
	h := s.Handler()
	reviewer := &auth.Principal{UserID: "usr_rev", DisplayName: "rev", Roles: []auth.Role{auth.RoleRuleReviewer}}
	auditor := &auth.Principal{UserID: "usr_aud", DisplayName: "aud", Roles: []auth.Role{auth.RoleAuditor}}
	rp := s.Repo()
	id := findStored(t, rp, "causal|shop-api|POST /orders")

	// A draft is rejected, not retired.
	if code, _ := call(t, h, reviewer, "POST", "/api/v1/rules/"+id+"/retire", ""); code != 409 {
		t.Fatalf("retire a draft: %d", code)
	}
	if code, _ := call(t, h, reviewer, "POST", "/api/v1/rules/"+id+"/approve", ""); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if code, _ := call(t, h, auditor, "POST", "/api/v1/rules/"+id+"/retire", ""); code != 403 {
		t.Fatalf("retire without the role: %d", code)
	}
	code, body := call(t, h, reviewer, "POST", "/api/v1/rules/"+id+"/retire", `{"note":"non serve piu"}`)
	if code != 200 {
		t.Fatalf("retire: %d %s", code, body)
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v["status"] != StatusRejected || v["retired"] != true {
		t.Errorf("retired view: %v", v)
	}
	doc, err := rp.Document(context.Background(), StatusApproved, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Rules {
		if r.ID() == id {
			t.Error("retired rule still in the approved document")
		}
	}
	if code, _ := call(t, h, reviewer, "POST", "/api/v1/rules/"+id+"/retire", ""); code != 409 {
		t.Errorf("retire twice: %d", code)
	}
	found := false
	for _, e := range auditEntries(t, al) {
		if e.Action == "rule.retire" && e.Target.ID == id && e.Outcome == "success" {
			found = true
		}
	}
	if !found {
		t.Error("rule.retire not audited")
	}
}

func findStored(t *testing.T, rp *Repo, sigPrefix string) string {
	t.Helper()
	for _, r := range mustList(t, rp, "") {
		if len(r.Signature) >= len(sigPrefix) && r.Signature[:len(sigPrefix)] == sigPrefix {
			return r.Rule.ID()
		}
	}
	t.Fatalf("no rule with signature %q", sigPrefix)
	return ""
}
