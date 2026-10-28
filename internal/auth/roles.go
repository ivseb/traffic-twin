package auth

import (
	"fmt"
	"slices"
	"sort"
)

// Role is a coarse permission bundle. The roles other than admin are flat:
// none implies another. admin is the superuser of tt-core: it implies every
// other role ([Principal.HasAny], hence every route check of auth.Require
// and of the per-operation guards), so an admin sees and does everything.
// Separation of duties gives way to traceability for admins: whatever an
// admin does that would normally need another role is an admin override,
// recorded in the audit (authz.admin_override plus the action's own entry)
// and, for the actions that open or export data, alerted (threat model
// M17). keyguard keeps its own check: an admin's approval of a policy or of
// a pack is the admin override there too (reason, alert), and it can be
// switched off only by the installer (TT_KEYGUARD_ADMIN_OVERRIDE=false).
type Role string

// The roles known to tt-core.
const (
	RoleAdmin          Role = "admin"           // superuser: implies every role (overrides audited)
	RoleOperator       Role = "operator"        // fleet sources, enrollment, health
	RoleRuleReviewer   Role = "rule-reviewer"   // review/approve mined rules
	RolePolicyApprover Role = "policy-approver" // approve policy changes (second pair of eyes)
	RolePublisher      Role = "publisher"       // run the publication gate, sign packs
	RoleAuditor        Role = "auditor"         // read and export the audit log
	RoleEventExporter  Role = "event-exporter"  // event-level export inside zone B (M4)
)

var allRoles = []Role{
	RoleAdmin, RoleOperator, RoleRuleReviewer, RolePolicyApprover,
	RolePublisher, RoleAuditor, RoleEventExporter,
}

// AllRoles returns every known role in a stable order.
func AllRoles() []Role { return slices.Clone(allRoles) }

// ParseRole validates s as a known role.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if slices.Contains(allRoles, r) {
		return r, nil
	}
	return "", fmt.Errorf("unknown role %q", s)
}

// normalizeRoles validates, de-duplicates and sorts roles.
func normalizeRoles(in []Role) ([]Role, error) {
	out := make([]Role, 0, len(in))
	for _, r := range in {
		if _, err := ParseRole(string(r)); err != nil {
			return nil, err
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
