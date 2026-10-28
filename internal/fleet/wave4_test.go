package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// Spec v1.18: HMAC domain families and the identity from a JSON header
// apply at once (observe-safe), audited; a group marked as test gets a
// lower k only from an administrator, with a reason.
func TestFamiliesAndJSONIdentityFromConsole(t *testing.T) {
	e := newObserveEnv(t)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups/shop/starter-policy", map[string]any{}), 201)

	var v PolicyVersion
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/families", map[string]any{"family": "customer", "domains": []string{"client", "customer"}}), 200).json(t, &v)
	if v.Status != StatusActive || v.OpensValues || v.ApprovalsRequired != 0 {
		t.Fatalf("a family applies at once: %+v", v)
	}
	if a := activeOf(t, e, "p-shop"); !strings.Contains(a.AuthorYAML, "families") || !strings.Contains(a.AuthorYAML, "client") {
		t.Fatalf("family not in the policy: %s", a.AuthorYAML)
	}
	var st ObserveStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if got := st.Families["customer"]; len(got) != 2 || got[0] != "client" {
		t.Fatalf("observe families: %+v", st.Families)
	}
	if !strings.Contains(e.auditDump(), `"policy.families_set"`) {
		t.Fatal("the family is not audited")
	}
	// A domain in two families, a reserved domain, one member only.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/families", map[string]any{"family": "account", "domains": []string{"client", "account"}}), 409)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/families", map[string]any{"family": "account", "domains": []string{"subject", "account"}}), 422)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/families", map[string]any{"family": "account", "domains": []string{"account"}}), 422)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/families", map[string]any{"family": "Bad", "domains": []string{"a", "b"}}), 422)
	// Removing it is observe-safe too; a family the policy lacks is 404.
	e.must(e.as("olivia", "DELETE", "/api/v1/fleet/groups/shop/families/customer", nil), 200).json(t, &v)
	if v.Status != StatusActive || strings.Contains(activeOf(t, e, "p-shop").AuthorYAML, "families") {
		t.Fatalf("family not removed: %+v", v)
	}
	e.must(e.as("olivia", "DELETE", "/api/v1/fleet/groups/shop/families/customer", nil), 404)
	if !strings.Contains(e.auditDump(), `"policy.families_removed"`) {
		t.Fatal("the removal is not audited")
	}

	// The subject from a member of a JSON header: observe-safe, even when
	// the header name looks like a credential.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/identity", map[string]any{"from": "header", "name": "X-Auth-Context", "json_path": "user.id"}), 200).json(t, &v)
	if v.Status != StatusActive || v.OpensValues {
		t.Fatalf("a JSON header member applies at once: %+v", v)
	}
	if a := activeOf(t, e, "p-shop"); !strings.Contains(a.AuthorYAML, "json_path: user.id") {
		t.Fatalf("json_path not in the policy: %s", a.AuthorYAML)
	}
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop/observe", nil), 200).json(t, &st)
	if st.Identity == nil || st.Identity.JSONPath != "user.id" {
		t.Fatalf("observe identity: %+v", st.Identity)
	}
	for _, bad := range []map[string]any{
		{"from": "cookie", "name": "ctx", "json_path": "user.id"},
		{"from": "header", "name": "x-ctx", "json_path": "user.id", "jwt_claim": "sub"},
		{"from": "header", "name": "x-ctx", "json_path": "a..b"},
	} {
		e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/identity", bad), 422)
	}
}

func TestTestKOnlyByAdmin(t *testing.T) {
	e := newObserveEnv(t)
	e.user("ada", auth.RoleAdmin)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"k_min": 3, "reason": "five testers"}), 403)
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"k_min": 3}), 422)
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"k_min": 1, "reason": "x"}), 422)
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"k_min": DefaultKMin, "reason": "x"}), 422)
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"reason": "x"}), 422)
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/none/test-k", map[string]any{"k_min": 3, "reason": "x"}), 404)
	var st ObserveStatus
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"k_min": 3, "reason": "five testers in staging"}), 200).json(t, &st)
	if st.TestKMin != 3 || st.KMin != DefaultKMin {
		t.Fatalf("observe test k: %+v", st)
	}
	m, err := e.fleet.GroupTestK(context.Background())
	if err != nil || m["shop"] != 3 || len(m) != 1 {
		t.Fatalf("GroupTestK: %v %v", m, err)
	}
	var g Group
	e.must(e.as("ada", "GET", "/api/v1/fleet/groups/shop", nil), 200).json(t, &g)
	if g.TestKMin != 3 {
		t.Fatalf("group view: %+v", g)
	}
	if d := e.auditDump(); !strings.Contains(d, `"fleet.group_test_k"`) {
		t.Fatal("the test k is not audited")
	}
	e.must(e.as("ada", "PUT", "/api/v1/fleet/groups/shop/test-k", map[string]any{"k_min": 0}), 200).json(t, &st)
	if m, _ := e.fleet.GroupTestK(context.Background()); st.TestKMin != 0 || len(m) != 0 {
		t.Fatalf("test k not turned off: %+v %v", st, m)
	}
}
