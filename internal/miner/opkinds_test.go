package miner

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
)

// The console switch "this operation is a read": stored per group,
// audited, used by the next run over the traffic's classification.
func TestOpKindOverrideAPI(t *testing.T) {
	tr := lookupTraffic(30)
	db := openDB(t)
	al := audit.New(db)
	cfg := smallK()
	now := tr.now.Add(time.Hour)
	s, err := New(Deps{DB: db, Events: tr, Audit: al, Config: &cfg, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	reviewer := &auth.Principal{UserID: "usr_rev", DisplayName: "rev", Roles: []auth.Role{auth.RoleRuleReviewer}}
	auditor := &auth.Principal{UserID: "usr_aud", DisplayName: "aud", Roles: []auth.Role{auth.RoleAuditor}}
	body := `{"service":"app-api","op":"POST /orders/{id}/cancel","read":true}`
	if code, _ := call(t, h, auditor, "PUT", "/api/v1/rules/op-kinds", body); code != http.StatusForbidden {
		t.Fatalf("auditor may not decide: %d", code)
	}
	if code, b := call(t, h, reviewer, "PUT", "/api/v1/rules/op-kinds", `{"service":"app-api","op":"not an op","read":true}`); code != http.StatusBadRequest {
		t.Fatalf("bad op: %d %s", code, b)
	}
	if code, b := call(t, h, reviewer, "PUT", "/api/v1/rules/op-kinds", body); code != http.StatusOK {
		t.Fatalf("reviewer: %d %s", code, b)
	}
	rep, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var over, auto bool
	for _, d := range rep.Diagnostics.Reads {
		over = over || (d.Op == "POST /orders/{id}/cancel" && d.Read && d.Override)
		auto = auto || (d.Op == "POST /orders/lookup" && d.Read && d.Auto)
	}
	if !over || !auto {
		t.Fatalf("run reads: %+v", rep.Diagnostics.Reads)
	}
	code, b := call(t, h, auditor, "GET", "/api/v1/rules/op-kinds", "")
	var got struct {
		Decisions []OpKind       `json:"decisions"`
		Auto      []ReadDecision `json:"auto"`
	}
	if code != http.StatusOK || json.Unmarshal(b, &got) != nil || len(got.Decisions) != 1 || !got.Decisions[0].Read ||
		got.Decisions[0].SetBy != "usr_rev" || len(got.Auto) != 1 || got.Auto[0].Op != "POST /orders/lookup" {
		t.Fatalf("get: %d %s", code, b)
	}
	// Back to the traffic.
	if code, b := call(t, h, reviewer, "PUT", "/api/v1/rules/op-kinds", `{"service":"app-api","op":"POST /orders/{id}/cancel","read":null}`); code != http.StatusOK {
		t.Fatalf("clear: %d %s", code, b)
	}
	if ks, _ := s.repo.OpKinds(context.Background(), ""); len(ks) != 0 {
		t.Fatalf("decision not removed: %+v", ks)
	}
	var set, denied int
	for _, e := range auditEntries(t, al) {
		if e.Action != "rule.op_kind_set" {
			continue
		}
		switch e.Outcome {
		case audit.Success:
			set++
			if e.Target.Type != "operation" || e.Details["kind"] == "" {
				t.Fatalf("audit: %+v", e)
			}
		case audit.Denied:
			denied++
		}
	}
	if set != 2 || denied != 1 {
		t.Fatalf("audit: %d set, %d denied", set, denied)
	}
}
