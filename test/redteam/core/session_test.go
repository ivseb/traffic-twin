package core_rt

import (
	"net/http"
	"strings"
	"testing"
)

// A disabled user, a user whose sessions were revoked, whose password was
// reset or who logged out cannot use the old cookie; re-enabling does not
// revive it.
func TestRT_Core_Holds_SessionRevocation(t *testing.T) {
	e := getEnv(t)
	ada := e.u(t, "ada")
	cases := []struct {
		name  string
		patch map[string]any
	}{
		{"rt-dis", map[string]any{"disabled": true}},
		{"rt-rev", map[string]any{"revoke_sessions": true}},
		{"rt-pwd", map[string]any{"password": "another-long-password-2"}},
	}
	for _, c := range cases {
		s := e.newUser(t, c.name, "operator")
		s.must(200, "GET", "/api/v1/fleet/sources", nil)
		ada.must(200, "PATCH", "/api/v1/users/"+e.ids[c.name], c.patch)
		if code, b := s.do("GET", "/api/v1/fleet/sources", nil); code != 401 {
			t.Errorf("%s: old session after %v = %d %s", c.name, c.patch, code, b)
		}
		if code, _ := s.do("POST", "/api/v1/fleet/groups", map[string]any{"name": "rt-x", "allowed_service_names": []string{"x"}}); code != 401 {
			t.Errorf("%s: unsafe call with old session = %d", c.name, code)
		}
	}
	ada.must(200, "PATCH", "/api/v1/users/"+e.ids["rt-dis"], map[string]any{"disabled": false})
	// Logout: the cookie is dead server-side, not only cleared.
	lo := e.newUser(t, "rt-logout", "auditor")
	lo.must(204, "POST", "/api/v1/auth/logout", nil)
	if code, _ := lo.do("GET", "/api/v1/auth/me", nil); code != 401 {
		t.Errorf("cookie after logout = %d", code)
	}
	// A disabled user cannot log in (same answer as a wrong password).
	ada.must(200, "PATCH", "/api/v1/users/"+e.ids["rt-dis"], map[string]any{"disabled": true})
	if _, code, b := trySignIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "rt-dis", "password": testPassword}, nil); code != 401 || errCode(b) != "invalid_credentials" {
		t.Errorf("disabled login = %d %s", code, b)
	}
}

// Login always issues a fresh random session id, never one chosen by the
// client, and kills the session the browser already carried; the cookie has
// the hardened attributes.
func TestRT_Core_Holds_SessionFixationAndCookie(t *testing.T) {
	e := getEnv(t)
	e.newUser(t, "rt-fix-a", "auditor")
	e.newUser(t, "rt-fix-v", "auditor")
	attacker := signIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "rt-fix-a", "password": testPassword}, "a")
	// The victim logs in with the attacker's cookie planted.
	victim, code, b := trySignIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "rt-fix-v", "password": testPassword},
		map[string]string{"Cookie": attacker.cookie})
	if victim == nil {
		t.Fatalf("victim login %d %s", code, b)
	}
	if victim.cookie == attacker.cookie || victim.csrf == attacker.csrf {
		t.Fatal("session id or CSRF token reused across logins")
	}
	if c, _ := attacker.do("GET", "/api/v1/auth/me", nil); c != 401 {
		t.Errorf("planted session still valid after a login over it: %d", c)
	}
	// A client-chosen id is never adopted.
	chosen := "__Host-tt_session=" + strings.Repeat("A", 43)
	v2, _, _ := trySignIn(t, e.base, e.hc, "/api/v1/auth/login", map[string]string{"username": "rt-fix-v", "password": testPassword},
		map[string]string{"Cookie": chosen})
	if v2 == nil || v2.cookie == chosen {
		t.Fatal("client-chosen session id adopted")
	}
	// Cookie attributes.
	req, _ := http.NewRequest("POST", e.base+"/api/v1/auth/login", strings.NewReader(`{"username":"rt-fix-v","password":"`+testPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"__Host-tt_session=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	if strings.Contains(strings.ToLower(sc), "domain=") || strings.Contains(strings.ToLower(sc), "max-age") {
		t.Errorf("Set-Cookie %q has Domain or Max-Age", sc)
	}
}
