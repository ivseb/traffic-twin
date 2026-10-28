package mock

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

var testIdentityKey = []byte("0123456789abcdef0123456789abcdef-test")

// The header name is only an example: any header (or JWT claim) can be
// configured.
func withIdentity(c IdentityConfig) envOpt {
	return func(_ *packtest.Spec, cfg *Config) {
		if c.Key == nil {
			c.Key = testIdentityKey
		}
		cfg.Identity = &c
	}
}

func userHdr(name, v string) map[string]string { return map[string]string{name: v} }

func (e *env) sessionOf(r resp) string {
	e.t.Helper()
	sid := r.header.Get("X-TT-Session")
	if !strings.HasPrefix(sid, "u-") || len(sid) != 18 {
		e.t.Fatalf("response session header %q, want u-<16 hex>", sid)
	}
	return sid
}

func (e *env) sessionCustomer(sid string) string {
	e.t.Helper()
	r := e.ctl("GET", "/sessions/"+sid, nil)
	if r.status != 200 {
		e.t.Fatalf("session %s: %d %s", sid, r.status, r.body)
	}
	c, _ := r.json()["customer"].(string)
	if r.json()["by_identity"] != true {
		e.t.Fatalf("session %s is not marked by_identity: %s", sid, r.body)
	}
	return c
}

func TestIdentitySessions(t *testing.T) {
	e := newEnv(t, withIdentity(IdentityConfig{Header: "x-test-user"}))
	ra := e.req("POST", "/__svc/shop-api/orders", orderBody, userHdr("X-Test-User", "alice@test"))
	if ra.status != 201 {
		t.Fatalf("order: %d %s", ra.status, ra.body)
	}
	sa := e.sessionOf(ra)
	if ra.json()["customerId"] != e.sessionCustomer(sa) || e.sessionCustomer(sa) == "" {
		t.Fatalf("the order belongs to %v, the session customer is %s", ra.json()["customerId"], e.sessionCustomer(sa))
	}
	// Same user: same session, the order is there.
	id := ra.json()["id"].(string)
	r := e.req("GET", "/__svc/shop-api/orders/"+id, nil, userHdr("X-Test-User", "alice@test"))
	if r.status != 200 || e.sessionOf(r) != sa {
		t.Fatalf("same user, another session or no order: %d %s", r.status, r.body)
	}
	// Another user: another session, which does not see it (own state).
	rb := e.req("GET", "/__svc/shop-api/orders/"+id, nil, userHdr("X-Test-User", "bob@test"))
	sb := e.sessionOf(rb)
	if sb == sa || rb.status == 200 {
		t.Fatalf("another user shares the session or sees the order: %s %d", sb, rb.status)
	}
	// Without the header: the default session, as before.
	if r := e.req("GET", "/__svc/shop-api/orders/"+id, nil, nil); r.header.Get("X-TT-Session") != "default" || r.status == 200 {
		t.Fatalf("no identity: want the default session, got %d %q", r.status, r.header.Get("X-TT-Session"))
	}
	// X-TT-Session wins over the identity.
	s := e.newSession(nil)
	r = e.req("GET", "/__svc/shop-api/orders/"+id, nil, map[string]string{"X-Test-User": "alice@test", "X-TT-Session": s})
	if r.status == 200 || r.header.Get("X-TT-Session") != s {
		t.Fatalf("X-TT-Session must win: %d", r.status)
	}
}

func TestIdentityDifferentUsersDifferentCustomers(t *testing.T) {
	e := newEnv(t, withIdentity(IdentityConfig{Header: "x-test-user"}))
	custs := map[string]string{}
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8"} {
		sid := e.sessionOf(e.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", u)))
		custs[e.sessionCustomer(sid)] = u
	}
	if len(custs) < 2 {
		t.Fatalf("eight users all got the same synthetic customer: %v", custs)
	}
}

func TestIdentityStableAcrossRestarts(t *testing.T) {
	e1 := newEnv(t, withIdentity(IdentityConfig{Header: "x-test-user"}))
	s1 := e1.sessionOf(e1.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", "carol")))
	c1 := e1.sessionCustomer(s1)
	// A new process with the same key and pack.
	cfg := e1.m.cfg
	m2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m2.Handler())
	defer srv.Close()
	e2 := &env{t: t, m: m2, srv: srv}
	s2 := e2.sessionOf(e2.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", "carol")))
	if s2 != s1 || e2.sessionCustomer(s2) != c1 {
		t.Fatalf("after a restart with the same key: session %s customer %s, before %s %s", s2, e2.sessionCustomer(s2), s1, c1)
	}
	// Another key: another mapping.
	cfg.Identity = &IdentityConfig{Header: "x-test-user", Key: []byte(strings.Repeat("k", 32))}
	m3, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st := m3.ident.Load(); IdentityHash(st.key, "carol")[:16] == strings.TrimPrefix(s1, "u-") {
		t.Fatal("a different key must give a different session")
	}
}

func TestIdentityExplicitMap(t *testing.T) {
	h := IdentityHash(testIdentityKey, "dave")
	e := newEnv(t, withIdentity(IdentityConfig{Header: "x-test-user", Map: map[string]string{
		"erin":   "CUS-SYN-0009",
		"h:" + h: "CUS-SYN-0001",
	}}))
	for u, want := range map[string]string{"erin": "CUS-SYN-0009", "dave": "CUS-SYN-0001"} {
		sid := e.sessionOf(e.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", u)))
		if got := e.sessionCustomer(sid); got != want {
			t.Fatalf("%s: customer %s, want %s", u, got, want)
		}
	}
	// A customer the pack does not have is ignored (hashed choice).
	e2 := newEnv(t, withIdentity(IdentityConfig{Header: "x-test-user", Map: map[string]string{"erin": "CUS-SYN-9999"}}))
	sid := e2.sessionOf(e2.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", "erin")))
	if c := e2.sessionCustomer(sid); c == "CUS-SYN-9999" || c == "" {
		t.Fatalf("unknown mapped customer: got %q", c)
	}
}

func TestIdentityJWTClaim(t *testing.T) {
	e := newEnv(t, withIdentity(IdentityConfig{Header: "authorization", Claim: "sub"}))
	jwt := func(claims map[string]any) string {
		b, _ := json.Marshal(claims)
		return "Bearer eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".c2ln"
	}
	r1 := e.req("GET", "/__svc/shop-api/ping", nil, userHdr("Authorization", jwt(map[string]any{"sub": "frank", "iat": 1})))
	r2 := e.req("GET", "/__svc/shop-api/ping", nil, userHdr("Authorization", jwt(map[string]any{"sub": "frank", "iat": 2})))
	r3 := e.req("GET", "/__svc/shop-api/ping", nil, userHdr("Authorization", jwt(map[string]any{"sub": "grace"})))
	if e.sessionOf(r1) != e.sessionOf(r2) || e.sessionOf(r1) == e.sessionOf(r3) {
		t.Fatal("the session must follow the claim, not the whole token")
	}
	// A token without the claim: the default session.
	if r := e.req("GET", "/__svc/shop-api/ping", nil, userHdr("Authorization", jwt(map[string]any{"x": 1}))); r.header.Get("X-TT-Session") != "default" {
		t.Fatal("no claim: default session")
	}
}

func TestIdentityNeverJournaled(t *testing.T) {
	// The identity header is one the journal records normally: it must be
	// left out, and nothing shows the value.
	const secret = "user-7f3c-secret"
	e := newEnv(t, withIdentity(IdentityConfig{Header: "X-Request-Id"}))
	r := e.req("POST", "/__svc/shop-api/orders", orderBody, userHdr("X-Request-Id", secret))
	sid := e.sessionOf(r)
	for _, path := range []string{"/sessions/" + sid + "/journal", "/sessions", "/sessions/" + sid} {
		if b := e.ctl("GET", path, nil).body; strings.Contains(string(b), secret) {
			t.Fatalf("%s shows the raw identity: %s", path, b)
		}
	}
	if !strings.Contains(string(e.ctl("GET", "/sessions/"+sid+"/journal", nil).body), "POST") {
		t.Fatal("the call must be journaled in the identity's session")
	}
}

func TestIdentityTooManySessions(t *testing.T) {
	e := newEnv(t, withIdentity(IdentityConfig{Header: "x-test-user"}), func(_ *packtest.Spec, c *Config) { c.MaxSessions = 2 })
	e.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", "one"))
	if r := e.req("GET", "/__svc/shop-api/ping", nil, userHdr("X-Test-User", "two")); r.status != 429 {
		t.Fatalf("over the session limit: %d, want 429", r.status)
	}
}

func TestIdentityConfigValidation(t *testing.T) {
	for _, c := range []IdentityConfig{
		{Header: "bad header"},
		{Header: "x", Claim: "bad claim"},
		{Header: "x", Key: []byte("short")},
		{Header: "x", Map: map[string]string{"u": "not-a-customer"}},
		{Header: "x", Map: map[string]string{"h:zz": "CUS-SYN-0001"}},
		{Claim: "sub"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v: want an error", c)
		}
	}
}
