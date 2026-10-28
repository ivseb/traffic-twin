package miner

import (
	"context"
	"testing"

	"github.com/ivseb/traffic-twin/internal/audit"
)

// TestStaleAuditEventIsRecorded: the rule.stale event carries the reason
// sentence of the run; the audit refuses free text, so the details must be
// folded (on the lab every rule.stale event was lost: "miner audit failed").
func TestStaleAuditEventIsRecorded(t *testing.T) {
	al := audit.New(openDB(t))
	diags := []RuleDiag{{RuleID: "r-0013", Decision: DecisionStale, Code: "not_observed",
		Reason: "entity member: the identifier of the user making the request (36 of 36 objects returned again by later calls) for 3 runs"}}
	e := audit.Event{Actor: systemActor, Action: "rule.stale", Target: audit.Target{Type: "rule", ID: "r-0013"},
		Outcome: audit.Success, Details: staleAuditDetails("r-0013", diags)}
	if _, err := al.Record(context.Background(), e); err != nil {
		t.Fatalf("rule.stale not recorded: %v", err)
	}
	if e.Details["code"] != "not_observed" || e.Details["reason"] == "" {
		t.Errorf("details: %v", e.Details)
	}
}
