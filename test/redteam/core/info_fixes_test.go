package core_rt

import (
	"fmt"
	"strings"
	"testing"
)

// FIXED (was info, red team round 2). The rules API validated rule_id
// before the role: a caller without rule-reviewer got 400 on a malformed
// id. Now the role is checked first (403), and the denial audits no
// client-chosen string.
func TestRT_Core_Fixed_RulesRoleBeforeID(t *testing.T) {
	e := getEnv(t)
	bad := "mario.rossi.rules@example.org"
	head := e.auditHead(t)
	for _, p := range []string{"/api/v1/rules/" + bad + "/approve", "/api/v1/rules/" + bad + "/reject"} {
		if code, b := e.u(t, "olga").do("POST", p, map[string]any{}); code != 403 {
			t.Errorf("operator POST %s = %d %s (want 403)", p, code, b)
		}
	}
	if code, b := e.u(t, "olga").do("PATCH", "/api/v1/rules/"+bad, map[string]any{"title": "x"}); code != 403 {
		t.Errorf("operator PATCH malformed rule id = %d %s (want 403)", code, b)
	}
	if code, _ := e.u(t, "rita").do("POST", "/api/v1/rules/"+bad+"/approve", map[string]any{}); code != 400 {
		t.Errorf("reviewer with a malformed id = %d (want 400)", code)
	}
	for _, a := range e.auditSince(t, head) {
		if strings.Contains(fmt.Sprint(a), "mario.rossi") {
			t.Errorf("audit entry carries the path value: %v", a)
		}
	}
}

// FIXED (was info, red team round 2). Failed logins are limited per
// account too, not only per client: after 10 wrong passwords the account
// answers 429 with Retry-After, also to the right password.
func TestRT_Limits_Fixed_LoginPerAccount(t *testing.T) {
	e := getEnv(t)
	e.newUser(t, "rt-acct")
	got := 0
	for i := 0; i < 12; i++ {
		_, code, _ := trySignIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "rt-acct", "password": fmt.Sprintf("wrong-password-%03d", i)}, nil)
		if code == 429 {
			got = i
			break
		}
		if code != 401 {
			t.Fatalf("wrong password = %d", code)
		}
	}
	if got == 0 {
		t.Fatal("no per-account 429 after repeated wrong passwords (the per-client limit of this env is not reached)")
	}
	if _, code, _ := trySignIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "rt-acct", "password": testPassword}, nil); code != 429 {
		t.Errorf("right password while the account is limited = %d (want 429)", code)
	}
	// Another account from the same client is not affected.
	if s, code, _ := trySignIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "nora", "password": testPassword}, nil); s == nil {
		t.Errorf("another account = %d", code)
	}
}

// FIXED (was info, red team round 2). Role denials of the pack API are
// audited (authz.deny, target = route pattern).
func TestRT_Core_Fixed_PackDenialAudited(t *testing.T) {
	e := getEnv(t)
	head := e.auditHead(t)
	if code, _ := e.u(t, "audrey").do("POST", "/api/v1/packs/"+e.packID+"/publish", nil); code != 403 {
		t.Fatalf("auditor publish = %d", code)
	}
	found := false
	for _, a := range e.auditSince(t, head) {
		if a["action"] == "authz.deny" && strings.Contains(fmt.Sprint(a["target"]), "_pack_id_") {
			found = true
		}
		if strings.Contains(fmt.Sprint(a["target"]), e.packID) {
			t.Errorf("denial target carries the raw path: %v", a["target"])
		}
	}
	if !found {
		t.Error("no authz.deny audit entry with the route pattern for the pack publish denial")
	}
}
