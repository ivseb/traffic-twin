package fleet

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// Usability test 5: a draft that needs two other approvers, proposed by a
// person who is not an approver, stayed pending for ever (and the observe
// automation does not work while a draft is pending).
func TestWithdrawPendingDraft(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("bob", auth.RolePolicyApprover)
	e.user("pat", auth.RoleOperator)
	e.user("quinn", auth.RoleOperator)

	v := e.propose("pat", policyV1)
	if v.Status != StatusDraft {
		t.Fatalf("draft: %+v", v)
	}
	path := fmt.Sprintf("/api/v1/fleet/policies/p-shop/versions/%d/withdraw", v.Version)

	// Somebody else (not an admin) cannot withdraw it; an unknown version is 404.
	if r := e.as("quinn", "POST", path, map[string]any{}); r.code != 403 || r.errCode() != "not_proposer" {
		t.Fatalf("other operator: %d %s", r.code, r.body)
	}
	if r := e.as("pat", "POST", "/api/v1/fleet/policies/p-shop/versions/99/withdraw", map[string]any{}); r.code != 404 {
		t.Fatalf("unknown version: %d", r.code)
	}

	var w PolicyVersion
	e.must(e.as("pat", "POST", path, map[string]any{"note": "bozza troppo larga"}), 200).json(t, &w)
	if w.Status != StatusRejected || !w.Withdrawn || !strings.HasPrefix(w.Note, WithdrawnNote) {
		t.Fatalf("withdrawn: %+v", w)
	}
	// It cannot be approved or withdrawn again; it stays in the history.
	if r := e.approve("bob", v, nil); r.code != 409 {
		t.Fatalf("approve withdrawn: %d %s", r.code, r.body)
	}
	if r := e.as("pat", "POST", path, map[string]any{}); r.code != 409 || r.errCode() != "not_draft" {
		t.Fatalf("withdraw twice: %d %s", r.code, r.body)
	}
	if !strings.Contains(e.auditDump(), `"action":"policy.withdraw"`) {
		t.Error("withdrawal not audited")
	}
}

func TestAdminWithdrawsSomeoneElsesDraftAudited(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("pat", auth.RoleOperator)
	e.user("root", auth.RoleAdmin)
	v := e.propose("pat", policyV1)
	path := fmt.Sprintf("/api/v1/fleet/policies/p-shop/versions/%d/withdraw", v.Version)
	var w PolicyVersion
	e.must(e.as("root", "POST", path, map[string]any{}), 200).json(t, &w)
	if !w.Withdrawn || w.Note != WithdrawnNote {
		t.Fatalf("admin withdraw: %+v", w)
	}
	if d := e.auditDump(); !strings.Contains(d, `"action":"policy.withdraw"`) || !strings.Contains(d, `"admin_override":"true"`) {
		t.Error("admin withdrawal not traced as an override")
	}
}
