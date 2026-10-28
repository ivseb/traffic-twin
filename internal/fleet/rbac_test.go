package fleet

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
)

func TestAdminRBACPerEndpoint(t *testing.T) {
	e := newEnv(t, nil)
	for _, r := range auth.AllRoles() {
		e.user("u-"+string(r), r)
	}
	O, A, P, AD := auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyApprover, auth.RoleAdmin
	cases := []struct {
		method, path string
		roles        []auth.Role
	}{
		{"GET", "/api/v1/fleet/groups", []auth.Role{O, A, P}},
		{"POST", "/api/v1/fleet/groups", []auth.Role{O}},
		{"GET", "/api/v1/fleet/groups/nope", []auth.Role{O, A, P}},
		{"PUT", "/api/v1/fleet/groups/nope", []auth.Role{O}},
		{"GET", "/api/v1/fleet/enrollment-tokens", []auth.Role{O, A}},
		{"POST", "/api/v1/fleet/enrollment-tokens", []auth.Role{O}},
		{"DELETE", "/api/v1/fleet/enrollment-tokens/tok-nope", []auth.Role{O}},
		{"GET", "/api/v1/fleet/onboarding/tok-nope/status", []auth.Role{O}},
		{"GET", "/api/v1/fleet/sources", []auth.Role{O, A}},
		{"GET", "/api/v1/fleet/sources/src-nope", []auth.Role{O, A}},
		{"POST", "/api/v1/fleet/sources/src-nope/revoke", []auth.Role{O}},
		{"PUT", "/api/v1/fleet/sources/src-nope/sampling", []auth.Role{O}},
		{"POST", "/api/v1/fleet/kill", []auth.Role{O}},
		{"GET", "/api/v1/fleet/policies", []auth.Role{O, P, A}},
		{"POST", "/api/v1/fleet/policies", []auth.Role{O, P}},
		{"GET", "/api/v1/fleet/policies/p-x/versions/1", []auth.Role{O, P, A}},
		{"POST", "/api/v1/fleet/policies/p-x/versions/1/approve", []auth.Role{P, AD}},
		{"POST", "/api/v1/fleet/policies/p-x/versions/1/reject", []auth.Role{P}},
		{"POST", "/api/v1/fleet/policies/p-x/versions/1/withdraw", []auth.Role{O, P}},
		{"POST", "/api/v1/fleet/policies/p-x/rollback", []auth.Role{O, P}},
		{"GET", "/api/v1/fleet/policies/p-x/assist", []auth.Role{O, P}},
		{"GET", "/api/v1/fleet/approval-settings", []auth.Role{O, P, A, AD}},
		{"POST", "/api/v1/fleet/groups/nope/starter-policy", []auth.Role{O, P}},
		{"GET", "/api/v1/fleet/signing-keys", []auth.Role{O, A, AD}},
		{"POST", "/api/v1/fleet/signing-keys/nope/revoke", []auth.Role{AD}},
	}
	for _, c := range cases {
		for _, r := range auth.AllRoles() {
			allowed := r == auth.RoleAdmin || containsStr(rolesStr(c.roles), string(r)) // admin implies every role
			res := e.as("u-"+string(r), c.method, c.path, "{}")
			if allowed && res.code == 403 {
				t.Errorf("%s %s as %s: 403 (%s)", c.method, c.path, r, res.body)
			}
			if !allowed && res.code != 403 {
				t.Errorf("%s %s as %s: %d, want 403", c.method, c.path, r, res.code)
			}
		}
		// Unauthenticated.
		if res := e.as("nobody", c.method, c.path, "{}"); res.code != 401 {
			t.Errorf("%s %s anonymous: %d", c.method, c.path, res.code)
		}
	}
	// Missing CSRF token on an unsafe call.
	s := e.sessions["u-operator"]
	e.sessions["nocsrf"] = session{cookie: s.cookie, csrf: "wrong"}
	if res := e.as("nocsrf", "POST", "/api/v1/fleet/kill", "{}"); res.code != 403 || res.errCode() != "csrf" {
		t.Errorf("csrf: %d %s", res.code, res.body)
	}
	if !strings.Contains(e.auditDump(), `"action":"authz.deny"`) {
		t.Error("denials not audited")
	}
	if !strings.Contains(e.auditDump(), `"action":"authz.admin_override"`) {
		t.Error("admin overrides not audited")
	}
}

func rolesStr(rs []auth.Role) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

func TestAuditHasNoValues(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenOneTime, "sdk-node")
	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	s.heartbeat("starting", 0)
	act := e.activateV1()
	e.user("ada", auth.RoleAdmin)
	const reason = "urgent fix approved by phone with the DPO"
	v := e.propose("olivia", policyClosing)
	e.must(e.approve("ada", v, map[string]any{"reason": reason, "note": "free text note"}), 200)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"all": true}}), 204)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/sources/"+s.id+"/revoke", nil), 204)

	dump := e.auditDump()
	secret := nt.Token[4:strings.IndexByte(nt.Token, '.')]
	keyLine := strings.Split(strings.TrimSpace(s.enr.ClientKey), "\n")[1]
	for name, v := range map[string]string{
		"token secret": secret, "client key": keyLine, "policy rule": "$.status", "reason": "DPO", "note": "free text",
		"certificate": strings.Split(s.enr.ClientCert, "\n")[1],
	} {
		if strings.Contains(dump, v) {
			t.Errorf("%s found in the audit log", name)
		}
	}
	for _, a := range []string{"fleet.group_create", "fleet.token_create", "fleet.enroll", "policy.propose", "policy.approve",
		"policy.activate", "policy.admin_approval", "fleet.kill", "fleet.source_revoke"} {
		if !strings.Contains(dump, `"action":"`+a+`"`) {
			t.Errorf("missing audit action %s", a)
		}
	}
	if !strings.Contains(dump, act.Hash) {
		t.Error("activation must record the policy hash")
	}
}
