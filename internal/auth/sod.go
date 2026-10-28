package auth

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
)

// Separation-of-duties errors.
var (
	ErrNotAuthenticated  = errors.New("approval requires an authenticated user")
	ErrMissingRole       = errors.New("approver lacks the required role")
	ErrSelfApproval      = errors.New("the author of a change cannot approve it")
	ErrDuplicateApproval = errors.New("the same user cannot approve twice")
)

// SensitiveRoles are the roles whose grant is notified to the admins
// (user.sensitive_role alert) besides being audited. Any role set is
// accepted (admin implies every role, so admin together with
// policy-approver or event-exporter adds nothing and is no longer refused):
// the grants stay visible instead.
var SensitiveRoles = []Role{RoleAdmin, RolePolicyApprover, RoleEventExporter}

// Querier runs read queries (*sql.DB, *sql.Tx, *store.DB).
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// CurrentRoles reads the roles each of ids holds NOW. Disabled and unknown
// users are absent from the result. Quorums re-check stored approvals with
// it (stale approvals): an approver disabled, or stripped of the role, after
// approving no longer counts, and keyguard receives the current roles.
func CurrentRoles(ctx context.Context, q Querier, ids []string) (map[string][]Role, error) {
	out := map[string][]Role{}
	uniq := slices.Compact(slices.Sorted(slices.Values(ids)))
	if len(uniq) == 0 {
		return out, nil
	}
	args := make([]any, len(uniq))
	for i, id := range uniq {
		args[i] = id
	}
	rows, err := q.QueryContext(ctx, `SELECT u.id, COALESCE((SELECT group_concat(role, ',') FROM (SELECT role FROM auth_user_roles r WHERE r.user_id = u.id ORDER BY role)), '')
		FROM auth_users u WHERE u.disabled = 0 AND u.id IN (?`+strings.Repeat(", ?", len(uniq)-1)+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, roles string
		if err := rows.Scan(&id, &roles); err != nil {
			return nil, err
		}
		out[id] = splitRoles(roles)
	}
	return out, rows.Err()
}

// EntitledApprover reports whether a user holding roles may count as a
// (non-override) approver of required: it holds required and, unless
// required is admin itself, not admin. An admin is never counted in a quorum
// of policy-approvers: its approval is always the admin override, which is
// enough alone and is traced (reason, audit, alert).
func EntitledApprover(roles []Role, required Role) bool {
	return slices.Contains(roles, required) && (required == RoleAdmin || !slices.Contains(roles, RoleAdmin))
}

// CheckApproval enforces separation of duties for a change authored by
// authorID that already carries approvals from priorApproverIDs: approver
// must hold required (an admin always does, [Principal.HasAny]), must not be
// the author and must not have approved already. Callers handle an admin
// as an override (pass authorID "" for it: an admin may approve its own
// change, traced). Callers persist the approval only when it returns nil, in the
// same transaction that re-reads priorApproverIDs.
func CheckApproval(approver *Principal, required Role, authorID string, priorApproverIDs []string) error {
	if approver == nil || approver.UserID == "" {
		return ErrNotAuthenticated
	}
	if !approver.HasAny(required) {
		return ErrMissingRole
	}
	if approver.UserID == authorID {
		return ErrSelfApproval
	}
	if slices.Contains(priorApproverIDs, approver.UserID) {
		return ErrDuplicateApproval
	}
	return nil
}

// DistinctApprovals counts approvals from distinct users other than the
// author: use it to decide whether a change reached its quorum (two for
// policy changes that open data, threat model M7).
func DistinctApprovals(authorID string, approverIDs []string) int {
	seen := map[string]bool{}
	for _, id := range approverIDs {
		if id != "" && id != authorID {
			seen[id] = true
		}
	}
	return len(seen)
}
