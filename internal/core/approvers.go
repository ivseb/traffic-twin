package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/fleet"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Who can approve the policy drafts of a group (usability test #4, B1): a
// developer whose draft opens values (status in clear, amount buckets) waits
// for a second person, but without users.manage it could not even learn who
// that person is. The answer names the people only (username and display
// name, never an e-mail address) and only to the group's own members.
//
//	GET /api/v1/fleet/groups/{group}/approvers
//
// The route sits under the fleet prefix (internal/fleet) but is served here
// (server.MountRoute): the people are the auth package's, the group
// membership the one of the Group/Team filter (scope.go).
func (c *Core) mountApprovers() {
	rt := c.newRouter()
	pattern := "GET " + fleet.AdminPrefix + "/groups/{group}/approvers"
	roles := []auth.Role{auth.RoleOperator, auth.RoleAdmin}
	rt.handle(pattern, roles, c.apiGroupApprovers)
	c.srv.MountRoute(pattern, rt.mux, roles...)
}

// approverView is one person who can approve a policy draft of the group.
type approverView struct {
	// Name is the username of a local account ("" for an OIDC account).
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	// Roles that let the person approve: policy-approver and/or admin (an
	// administrator approves alone, with a reason).
	Roles []string `json:"roles"`
	// Self is the caller: listed, but a proposer never approves its own draft.
	Self bool `json:"self,omitempty"`
}

func (c *Core) apiGroupApprovers(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	group := r.PathValue("group")
	if group == "" || len(group) > 63 {
		return apiErr(http.StatusBadRequest, "invalid_group", "group must be a group name")
	}
	groups, err := c.fleet.ListGroups(r.Context())
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(groups, func(g *fleet.Group) bool { return g.Name == group }) {
		return apiErr(http.StatusNotFound, "not_found", "group not found")
	}
	if !p.IsAdmin() {
		ok, err := c.groupMember(r.Context(), p.UserID, group)
		if err != nil {
			return err
		}
		if !ok {
			return apiErr(http.StatusForbidden, "not_member",
				"only the members of the group (who created one of its enrollment tokens or proposed one of its policy versions) and administrators see who can approve its policies")
		}
	}
	users, err := c.auth.ListUsers(r.Context())
	if err != nil {
		return err
	}
	out := []approverView{}
	for _, u := range users {
		if u.Disabled {
			continue
		}
		var roles []string
		for _, role := range []auth.Role{auth.RolePolicyApprover, auth.RoleAdmin} {
			if slices.Contains(u.Roles, role) {
				roles = append(roles, string(role))
			}
		}
		if len(roles) == 0 {
			continue
		}
		out = append(out, approverView{Name: u.Username, DisplayName: noEmail(u.DisplayName, u.Username), Roles: roles, Self: u.ID == p.UserID})
	}
	// Approvers first, then the administrators; by name.
	slices.SortStableFunc(out, func(a, b approverView) int {
		ra, rb := slices.Contains(a.Roles, string(auth.RolePolicyApprover)), slices.Contains(b.Roles, string(auth.RolePolicyApprover))
		if ra != rb {
			if ra {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName))
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"group": group, "approvers": out})
	return nil
}

// noEmail keeps a display name that is not an e-mail address (an OIDC
// provider may use the address as the name): the local part instead, or
// the username.
func noEmail(display, username string) string {
	at := strings.IndexByte(display, '@')
	if at < 0 {
		return display
	}
	if at > 0 {
		return display[:at]
	}
	return username
}

// groupMember reports whether user works with group in the sense of the
// Group/Team filter ("I miei gruppi"): it created one of the group's
// enrollment tokens or proposed a version of the group's policy.
func (c *Core) groupMember(ctx context.Context, user, group string) (bool, error) {
	var one int
	err := c.db.QueryRowContext(ctx, `SELECT 1 FROM fleet_tokens WHERE created_by = ? AND grp = ?
		UNION SELECT 1 FROM fleet_groups g JOIN fleet_policy_versions v ON v.policy_id = g.policy_id WHERE v.proposed_by = ? AND g.name = ?
		LIMIT 1`, user, group, user, group).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
