package core_test

import (
	"strings"
	"testing"
)

// TestGroupApprovers: who can approve the policy drafts of a group, for the
// group's own members (usability test #4, B1). Names only, never e-mails;
// other operators, other teams and the other fleet routes keep their rules.
func TestGroupApprovers(t *testing.T) {
	if testing.Short() {
		t.Skip("starts keyguard and tt-core")
	}
	c, ada, olga := listCore(t, 10)
	_ = c

	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "piero", "display_name": "piero@example.test", "password": testPassword, "roles": []string{"policy-approver"}})
	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "rita", "password": testPassword, "roles": []string{"operator"}})
	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "vera", "password": testPassword, "roles": []string{"auditor"}})
	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "gone", "password": testPassword, "roles": []string{"policy-approver"}})
	var gone struct {
		ID string `json:"id"`
	}
	var list []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	ada.json(200, "GET", "/api/v1/users", nil, &list)
	for _, u := range list {
		if u.Username == "gone" {
			gone.ID = u.ID
		}
	}
	ada.must(200, "PATCH", "/api/v1/users/"+gone.ID, map[string]any{"disabled": true})

	ada.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "orders", "allowed_service_names": []string{"orders-api"}})
	ada.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "shop", "allowed_service_names": []string{"shop-api"}})
	// olga works with orders: she created one of its tokens.
	olga.must(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-node", "group": "orders", "token_type": "one_time"})

	type view struct {
		Group     string `json:"group"`
		Approvers []struct {
			Name        string   `json:"name"`
			DisplayName string   `json:"display_name"`
			Roles       []string `json:"roles"`
			Self        bool     `json:"self"`
		} `json:"approvers"`
	}
	var v view
	olga.json(200, "GET", "/api/v1/fleet/groups/orders/approvers", nil, &v)
	if v.Group != "orders" || len(v.Approvers) != 2 {
		t.Fatalf("approvers of orders: %+v", v)
	}
	// The approver first, then the administrator; the disabled one is left out.
	if v.Approvers[0].Name != "piero" || strings.Join(v.Approvers[0].Roles, ",") != "policy-approver" || v.Approvers[1].Name != "ada" || strings.Join(v.Approvers[1].Roles, ",") != "admin" {
		t.Fatalf("order or roles: %+v", v.Approvers)
	}
	if v.Approvers[0].DisplayName != "piero" {
		t.Fatalf("an e-mail address is never shown: %q", v.Approvers[0].DisplayName)
	}
	body := string(olga.must(200, "GET", "/api/v1/fleet/groups/orders/approvers", nil))
	if strings.Contains(body, "@") || strings.Contains(body, "gone") {
		t.Fatalf("answer leaks an address or a disabled user: %s", body)
	}

	// An operator of another team, an auditor and a non-member: refused.
	rita := signIn(t, ada.base, ada.hc, "/api/v1/auth/login", map[string]string{"username": "rita", "password": testPassword})
	rita.must(403, "GET", "/api/v1/fleet/groups/orders/approvers", nil)
	vera := signIn(t, ada.base, ada.hc, "/api/v1/auth/login", map[string]string{"username": "vera", "password": testPassword})
	vera.must(403, "GET", "/api/v1/fleet/groups/orders/approvers", nil)
	olga.must(403, "GET", "/api/v1/fleet/groups/shop/approvers", nil)
	olga.must(404, "GET", "/api/v1/fleet/groups/nope/approvers", nil)

	// An administrator sees every group, and itself flagged.
	ada.json(200, "GET", "/api/v1/fleet/groups/shop/approvers", nil, &v)
	if len(v.Approvers) != 2 || !v.Approvers[1].Self {
		t.Fatalf("admin view of shop: %+v", v)
	}

	// The rest of the fleet prefix is untouched (its own handler and roles).
	ada.must(200, "GET", "/api/v1/fleet/groups", nil)
	vera.must(200, "GET", "/api/v1/fleet/groups", nil)
}
