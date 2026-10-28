package miner

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
)

func getStatus(t *testing.T, s *Service) Status {
	t.Helper()
	auditor := &auth.Principal{UserID: "usr_aud", DisplayName: "aud", Roles: []auth.Role{auth.RoleAuditor}}
	code, body := call(t, s.Handler(), auditor, "GET", "/api/v1/rules/status", "")
	var st Status
	if code != http.StatusOK || json.Unmarshal(body, &st) != nil {
		t.Fatalf("status: %d %s", code, body)
	}
	return st
}

func TestStatusNeverRunThenOK(t *testing.T) {
	s, _, _ := newTestService(t)
	if st := getStatus(t, s); st.State != StateNeverRun || st.MinHours != 1 {
		t.Fatalf("before the first run: %+v", st)
	}
	if code, _ := call(t, s.Handler(), nil, "GET", "/api/v1/rules/status", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous status: %d", code)
	}
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := getStatus(t, s)
	if st.State != StateOK || st.ObservedHours < 1 || st.Events == 0 || st.Rules["draft"] != 3 {
		t.Fatalf("after a run on the demo: %+v", st)
	}
	// The diagnostics explain every entity and rule of the run.
	if st.MinBirthShare != 0.6 || st.StaleRuns != 3 || len(st.Warnings) != 0 {
		t.Errorf("thresholds/warnings: %+v", st)
	}
	acc := map[string]bool{}
	for _, e := range st.Entities {
		acc[e.Name] = e.Accepted
		if e.Reason == "" || e.Op == "" {
			t.Errorf("entity diagnostic: %+v", e)
		}
	}
	if !acc["order"] || !acc["shipment"] || acc["customer"] {
		t.Errorf("entities: %v", acc)
	}
	proposed := 0
	for _, r := range st.RuleDiagnostics {
		if r.Decision == DecisionProposed && r.RuleID != "" {
			proposed++
		}
	}
	if proposed != 3 {
		t.Errorf("rule diagnostics: %+v", st.RuleDiagnostics)
	}
}

func TestStatusWarnsAboutWatchedRules(t *testing.T) {
	s, _, _ := newTestService(t)
	ctx := context.Background()
	rep, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := rep.New[0]
	if _, err := s.repo.Approve(ctx, id, "usr_alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	// The same traffic judged by a stricter miner: confidence below the floor.
	s.repo.cfg.MinConfidence = 1
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := getStatus(t, s)
	if len(st.Warnings) == 0 || !strings.Contains(strings.Join(st.Warnings, "\n"), "on watch (1 of 3 runs)") {
		t.Fatalf("warnings: %v", st.Warnings)
	}
	reviewer := &auth.Principal{UserID: "usr_rev", DisplayName: "rev", Roles: []auth.Role{auth.RoleRuleReviewer}}
	code, body := call(t, s.Handler(), reviewer, "GET", "/api/v1/rules/"+id, "")
	var one map[string]any
	if code != http.StatusOK || json.Unmarshal(body, &one) != nil || one["status"] != "approved" ||
		one["failed_runs"] != float64(1) || one["stale_reason"] == nil {
		t.Fatalf("rule view: %d %s", code, body)
	}
}

func TestStatusInsufficientData(t *testing.T) {
	s, _, _ := newTestService(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	res := &Result{Events: 500, Observed: 20 * time.Minute, Window: Window{From: "2026-01-01T11:00:00Z", To: "2026-01-01T12:00:00Z"}}
	rep, err := s.repo.Apply(context.Background(), res, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Insufficient || len(rep.New) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	st := getStatus(t, s)
	if st.State != StateInsufficientData || st.MinHours != 1 || st.ObservedHours < 0.33 || st.ObservedHours > 0.34 || st.Events != 500 {
		t.Fatalf("status: %+v", st)
	}

	empty := &Result{Window: res.Window}
	if _, err := s.repo.Apply(context.Background(), empty, now, now); err != nil {
		t.Fatal(err)
	}
	if st := getStatus(t, s); st.State != StateNoData {
		t.Fatalf("no events: %+v", st)
	}
}
