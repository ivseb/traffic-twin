package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/store"
)

// fastParams keeps tests quick; production uses DefaultPasswordParams.
var fastParams = PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	svc   *Service
	audit *audit.Log
	db    *store.DB
	clock *clock
	mux   *http.ServeMux
}

func newEnv(t *testing.T, mutate func(*Options)) *env {
	t.Helper()
	// The default registry holds the real auth and audit migrations
	// (registered by their init functions).
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)}
	al := audit.New(db)
	opts := Options{
		IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 4 * time.Hour,
		LocalEnabled: true, PasswordParams: &fastParams, Now: clk.Now,
	}
	if mutate != nil {
		mutate(&opts)
	}
	svc, err := New(db, al, opts)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/auth/login", svc.LoginHandler())
	mux.Handle("/api/v1/setup", svc.SetupHandler())
	mux.Handle("/api/v1/auth/config", svc.ConfigHandler())
	mux.Handle("/api/v1/auth/logout", svc.Require()(svc.LogoutHandler()))
	mux.Handle("/api/v1/auth/me", svc.Require()(svc.MeHandler()))
	mux.Handle("/api/v1/auth/oidc/start", svc.OIDCStartHandler())
	mux.Handle("/api/v1/auth/oidc/callback", svc.OIDCCallbackHandler())
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		_, _ = w.Write([]byte("ok:" + p.UserID))
	})
	mux.Handle("/audit-only", svc.Require(RoleAuditor)(ok))
	mux.Handle("/approver-or-publisher", svc.Require(RolePolicyApprover, RolePublisher)(ok))
	mux.Handle("/publisher-download", svc.Require(RolePublisher)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="x.bin"`)
		_, _ = w.Write([]byte("file"))
	})))
	// A guard inside the handler (as fleet, gate, core... do): the innermost
	// check decides the roles recorded with an admin override.
	mux.Handle("/inner-guard", svc.Require()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		if !p.HasAny(RoleEventExporter) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok:" + p.UserID))
	})))
	return &env{svc: svc, audit: al, db: db, clock: clk, mux: mux}
}

type resp struct {
	code   int
	body   string
	header http.Header
}

func (e *env) do(t *testing.T, method, path, body string, hdr map[string]string, cookies ...*http.Cookie) resp {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return resp{rec.Code, rec.Body.String(), rec.Header()}
}

func sessionCookie(t *testing.T, r resp) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == cookiePlain || c.Name == cookieTLS {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Fatalf("weak session cookie attributes: %+v", c)
			}
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	t.Fatalf("no session cookie in %v", r.header)
	return nil
}

func decodeMe(t *testing.T, r resp) MeResponse {
	t.Helper()
	var m MeResponse
	if err := json.Unmarshal([]byte(r.body), &m); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
	return m
}

const goodPassword = "correct horse battery staple"

func (e *env) bootstrap(t *testing.T) (*http.Cookie, MeResponse) {
	t.Helper()
	tok, err := e.svc.EnsureSetupToken(context.Background())
	if err != nil || !strings.HasPrefix(tok, "tts_") {
		t.Fatalf("setup token %q %v", tok, err)
	}
	r := e.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok+`","username":"alice","password":"`+goodPassword+`"}`, nil)
	if r.code != http.StatusCreated {
		t.Fatalf("setup = %d %s", r.code, r.body)
	}
	return sessionCookie(t, r), decodeMe(t, r)
}

func TestPasswordHashing(t *testing.T) {
	h, err := newHasher(fastParams, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	enc, err := h.hash(ctx, goodPassword)
	if err != nil || !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("hash = %q %v", enc, err)
	}
	if ok, _ := h.verify(ctx, goodPassword, enc); !ok {
		t.Error("correct password rejected")
	}
	if ok, _ := h.verify(ctx, "wrong password!!", enc); ok {
		t.Error("wrong password accepted")
	}
	if ok, _ := h.verify(ctx, "dummy-password-for-timing", ""); ok {
		t.Error("empty hash accepted the dummy password")
	}
	for _, bad := range []string{"$argon2i$v=19$m=1,t=1,p=1$a$b", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA", "garbage"} {
		if _, err := h.verify(ctx, "x", bad); !errors.Is(err, errBadHash) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if checkPasswordPolicy("short") == nil || checkPasswordPolicy(strings.Repeat("a", 300)) == nil || checkPasswordPolicy(goodPassword) != nil {
		t.Error("password policy")
	}
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t, nil)
	r := e.do(t, "GET", "/api/v1/auth/config", "", nil)
	if !strings.Contains(r.body, `"setup_required":true`) {
		t.Fatalf("config = %s", r.body)
	}
	tok1, _ := e.svc.EnsureSetupToken(context.Background())
	tok2, _ := e.svc.EnsureSetupToken(context.Background())
	if tok1 == tok2 {
		t.Fatal("setup token not rotated")
	}
	// The superseded token no longer works.
	r = e.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok1+`","username":"alice","password":"`+goodPassword+`"}`, nil)
	if r.code != http.StatusUnauthorized {
		t.Fatalf("old token = %d", r.code)
	}
	r = e.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok2+`","username":"alice","password":"short"}`, nil)
	if r.code != http.StatusBadRequest {
		t.Fatalf("weak password = %d", r.code)
	}
	// Form-encoded bodies are refused (pre-auth CSRF defence).
	r = e.do(t, "POST", "/api/v1/setup", `{"setup_token":"x"}`, map[string]string{"Content-Type": "text/plain"})
	if r.code != http.StatusBadRequest {
		t.Fatalf("text/plain = %d", r.code)
	}
	r = e.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok2+`","username":"alice","password":"`+goodPassword+`"}`, nil)
	if r.code != http.StatusCreated {
		t.Fatalf("setup = %d %s", r.code, r.body)
	}
	me := decodeMe(t, r)
	if len(me.Roles) != 1 || me.Roles[0] != RoleAdmin || me.CSRFToken == "" {
		t.Fatalf("me = %+v", me)
	}
	r = e.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok2+`","username":"bob","password":"`+goodPassword+`"}`, nil)
	if r.code != http.StatusConflict {
		t.Fatalf("second setup = %d", r.code)
	}
	if tok, _ := e.svc.EnsureSetupToken(context.Background()); tok != "" {
		t.Fatal("setup token issued after setup")
	}
}

func TestSetupTokenExpires(t *testing.T) {
	e := newEnv(t, nil)
	tok, _ := e.svc.EnsureSetupToken(context.Background())
	e.clock.Add(SetupTokenTTL + time.Second)
	r := e.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok+`","username":"alice","password":"`+goodPassword+`"}`, nil)
	if r.code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d", r.code)
	}
}

func TestLoginMeLogoutCSRF(t *testing.T) {
	e := newEnv(t, nil)
	setupCookie, _ := e.bootstrap(t)

	for _, body := range []string{
		`{"username":"alice","password":"wrong password here"}`,
		`{"username":"nobody","password":"` + goodPassword + `"}`,
	} {
		if r := e.do(t, "POST", "/api/v1/auth/login", body, nil); r.code != http.StatusUnauthorized || !strings.Contains(r.body, "invalid_credentials") {
			t.Fatalf("bad login = %d %s", r.code, r.body)
		}
	}
	if r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"alice","password":"x","extra":1}`, nil); r.code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", r.code)
	}

	// Login while carrying the setup session: the old session is destroyed
	// (rotation, no fixation).
	r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"alice","password":"`+goodPassword+`"}`, nil, setupCookie)
	if r.code != http.StatusOK {
		t.Fatalf("login = %d %s", r.code, r.body)
	}
	c := sessionCookie(t, r)
	me := decodeMe(t, r)
	if c.Value == setupCookie.Value {
		t.Fatal("session id not rotated")
	}
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, setupCookie); r.code != http.StatusUnauthorized {
		t.Fatalf("old session still valid: %d", r.code)
	}

	r = e.do(t, "GET", "/api/v1/auth/me", "", nil, c)
	if r.code != http.StatusOK || decodeMe(t, r).CSRFToken != me.CSRFToken || decodeMe(t, r).User.Username != "alice" {
		t.Fatalf("me = %d %s", r.code, r.body)
	}
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("me without cookie = %d", r.code)
	}
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, &http.Cookie{Name: cookiePlain, Value: "forged"}); r.code != http.StatusUnauthorized {
		t.Fatalf("forged cookie = %d", r.code)
	}

	// CSRF: unsafe methods need the header.
	if r := e.do(t, "POST", "/api/v1/auth/logout", "", nil, c); r.code != http.StatusForbidden || !strings.Contains(r.body, "csrf") {
		t.Fatalf("logout without csrf = %d %s", r.code, r.body)
	}
	if r := e.do(t, "POST", "/api/v1/auth/logout", "", map[string]string{CSRFHeader: "nope"}, c); r.code != http.StatusForbidden {
		t.Fatalf("logout wrong csrf = %d", r.code)
	}
	if r := e.do(t, "POST", "/api/v1/auth/logout", "", map[string]string{CSRFHeader: me.CSRFToken}, c); r.code != http.StatusNoContent {
		t.Fatalf("logout = %d", r.code)
	}
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d", r.code)
	}
}

// A second login (another browser, curl) never ends the first session; at
// most MaxSessionsPerUser stay valid, the oldest ends first.
func TestConcurrentSessions(t *testing.T) {
	e := newEnv(t, nil)
	e.bootstrap(t)
	var cookies []*http.Cookie
	var csrfs []string
	for i := 0; i <= MaxSessionsPerUser; i++ {
		r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"alice","password":"`+goodPassword+`"}`, nil)
		if r.code != http.StatusOK {
			t.Fatalf("login %d = %d %s", i, r.code, r.body)
		}
		cookies = append(cookies, sessionCookie(t, r))
		csrfs = append(csrfs, decodeMe(t, r).CSRFToken)
		e.clock.Add(time.Second)
	}
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, cookies[0]); r.code != http.StatusUnauthorized {
		t.Fatalf("the oldest session beyond the bound is still valid: %d", r.code)
	}
	for i := 1; i < len(cookies); i++ {
		if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, cookies[i]); r.code != http.StatusOK || decodeMe(t, r).CSRFToken != csrfs[i] {
			t.Fatalf("session %d: %d", i, r.code)
		}
	}
	// Each session has its own CSRF token: another session's token is refused.
	if r := e.do(t, "POST", "/api/v1/auth/logout", "", map[string]string{CSRFHeader: csrfs[2]}, cookies[1]); r.code != http.StatusForbidden || !strings.Contains(r.body, `"csrf"`) {
		t.Fatalf("csrf of another session = %d %s", r.code, r.body)
	}
}

// overrides lists the authz.admin_override entries (route id -> roles).
func (e *env) overrides(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = e.audit.Iterate(context.Background(), 0, 0, func(en audit.Entry) error {
		if en.Action == "authz.admin_override" {
			out[en.Target.ID] = en.Details["roles_required"]
		}
		return nil
	})
	return out
}

func TestRBAC(t *testing.T) {
	e := newEnv(t, nil)
	c, me := e.bootstrap(t)
	// admin implies every role: it passes every check of Require and of
	// the guards inside the handlers.
	if r := e.do(t, "GET", "/audit-only", "", nil, c); r.code != http.StatusOK || r.body != "ok:"+me.User.UserID {
		t.Fatalf("admin on auditor route = %d %s (admin implies every role)", r.code, r.body)
	}
	if r := e.do(t, "GET", "/approver-or-publisher", "", nil, c); r.code != http.StatusOK {
		t.Fatalf("admin on any-of route = %d", r.code)
	}
	if r := e.do(t, "POST", "/inner-guard", "", map[string]string{CSRFHeader: me.CSRFToken}, c); r.code != http.StatusOK {
		t.Fatalf("admin through an inner guard = %d %s", r.code, r.body)
	}
	if r := e.do(t, "GET", "/publisher-download", "", nil, c); r.code != http.StatusOK {
		t.Fatalf("admin download = %d", r.code)
	}
	// ...never invisibly: a change or a download admitted only by admin is
	// an audited override (plain reads are not recorded).
	ov := e.overrides(t)
	if ov["POST:/inner-guard"] != "event-exporter" {
		t.Errorf("inner-guard override not audited with its roles: %v", ov)
	}
	if ov["GET:/publisher-download"] != "publisher" {
		t.Errorf("download override not audited: %v", ov)
	}
	if _, ok := ov["GET:/audit-only"]; ok {
		t.Errorf("plain read recorded as override: %v", ov)
	}
	if r := e.do(t, "GET", "/audit-only", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", r.code)
	}
	// Any role set is accepted (no separation-of-duties refusal for admin).
	if err := e.svc.SetRoles(context.Background(), me.User.UserID, []Role{RoleAdmin, RolePolicyApprover, RoleEventExporter}); err != nil {
		t.Fatalf("admin + policy-approver + event-exporter refused: %v", err)
	}
	// Roles are read live: changing them applies to the current session.
	if err := e.svc.SetRoles(context.Background(), me.User.UserID, []Role{RoleAuditor}); err != nil {
		t.Fatal(err)
	}
	if r := e.do(t, "GET", "/audit-only", "", nil, c); r.code != http.StatusOK || r.body != "ok:"+me.User.UserID {
		t.Fatalf("auditor = %d %s", r.code, r.body)
	}
	if r := e.do(t, "GET", "/approver-or-publisher", "", nil, c); r.code != http.StatusForbidden {
		t.Fatalf("any-of = %d", r.code)
	}
	if r := e.do(t, "POST", "/inner-guard", "", map[string]string{CSRFHeader: me.CSRFToken}, c); r.code != http.StatusForbidden {
		t.Fatalf("non-admin through an inner guard = %d", r.code)
	}
	_ = e.svc.SetRoles(context.Background(), me.User.UserID, []Role{RolePublisher})
	if r := e.do(t, "GET", "/publisher-download", "", nil, c); r.code != http.StatusOK {
		t.Fatalf("publisher download = %d", r.code)
	}
	if r := e.do(t, "GET", "/audit-only", "", nil, c); r.code != http.StatusForbidden {
		t.Fatalf("publisher on auditor route = %d", r.code)
	}
	if n := len(e.overrides(t)); n != 2 {
		t.Errorf("a non-admin request was recorded as an admin override (%d entries)", n)
	}
	if r := e.do(t, "GET", "/approver-or-publisher", "", nil, c); r.code != http.StatusOK {
		t.Fatalf("any-of with publisher = %d", r.code)
	}
	if err := e.svc.SetRoles(context.Background(), me.User.UserID, []Role{"root"}); err == nil {
		t.Fatal("unknown role accepted")
	}
	// Denials are audited.
	found := false
	_ = e.audit.Iterate(context.Background(), 0, 0, func(en audit.Entry) error {
		if en.Action == "authz.deny" && en.Outcome == audit.Denied && en.Target.ID == "GET:/audit-only" {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("authz denial not audited")
	}
	defer func() {
		if recover() == nil {
			t.Error("Require with unknown role did not panic")
		}
	}()
	e.svc.Require("root")
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.bootstrap(t)

	// Activity keeps the session alive past the idle timeout...
	for range 3 {
		e.clock.Add(20 * time.Minute)
		if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusOK {
			t.Fatalf("active session expired: %d", r.code)
		}
	}
	// ...but idleness ends it.
	e.clock.Add(31 * time.Minute)
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusUnauthorized {
		t.Fatalf("idle session alive: %d", r.code)
	}

	// Absolute timeout applies even with constant activity.
	r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"alice","password":"`+goodPassword+`"}`, nil)
	c = sessionCookie(t, r)
	for elapsed := time.Duration(0); elapsed < 4*time.Hour-10*time.Minute; elapsed += 10 * time.Minute {
		e.clock.Add(10 * time.Minute)
		if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusOK {
			t.Fatalf("session ended early at %v", elapsed)
		}
	}
	e.clock.Add(11 * time.Minute)
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusUnauthorized {
		t.Fatalf("absolute timeout not enforced: %d", r.code)
	}
	if err := e.svc.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledUser(t *testing.T) {
	e := newEnv(t, nil)
	c, me := e.bootstrap(t)
	if err := e.svc.SetDisabled(context.Background(), me.User.UserID, true); err != nil {
		t.Fatal(err)
	}
	if r := e.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusUnauthorized {
		t.Fatalf("disabled user session alive: %d", r.code)
	}
	if r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"alice","password":"`+goodPassword+`"}`, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("disabled login = %d", r.code)
	}
}

func TestUserManagement(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	u, err := e.svc.CreateLocalUser(ctx, "bob", goodPassword, []Role{RoleOperator, RoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Roles) != 1 {
		t.Errorf("roles not de-duplicated: %v", u.Roles)
	}
	if _, err := e.svc.CreateLocalUser(ctx, "bob", goodPassword, nil); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := e.svc.CreateLocalUser(ctx, "Bad Name", goodPassword, nil); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("bad username: %v", err)
	}
	got, err := e.svc.GetUser(ctx, u.ID)
	if err != nil || got.Username != "bob" || got.Method != "local" || got.Roles[0] != RoleOperator {
		t.Fatalf("get = %+v %v", got, err)
	}
	if err := e.svc.SetPassword(ctx, u.ID, "another long password"); err != nil {
		t.Fatal(err)
	}
	if r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"bob","password":"another long password"}`, nil); r.code != http.StatusOK {
		t.Fatalf("login with new password = %d", r.code)
	}
	if _, err := e.svc.GetUser(ctx, "usr_missing"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("missing user: %v", err)
	}
	users, _ := e.svc.ListUsers(ctx)
	if len(users) != 1 {
		t.Errorf("list = %v", users)
	}
}

func TestLoginAuditNeverRecordsUnknownUsername(t *testing.T) {
	e := newEnv(t, nil)
	e.bootstrap(t)
	secretish := "my-actual-password-typed-in-username"
	e.do(t, "POST", "/api/v1/auth/login", `{"username":"`+secretish+`","password":"whatever whatever"}`, nil)
	e.do(t, "POST", "/api/v1/auth/login", `{"username":"alice","password":"`+secretish+`"}`, nil)
	var all strings.Builder
	_ = e.audit.Iterate(context.Background(), 0, 0, func(en audit.Entry) error {
		b, _ := json.Marshal(en)
		all.Write(b)
		return nil
	})
	if strings.Contains(all.String(), secretish) {
		t.Fatal("audit log contains a submitted credential value")
	}
	if !strings.Contains(all.String(), `"reason":"invalid_credentials"`) {
		t.Fatal("failed logins not audited")
	}
	if _, err := e.audit.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLocalDisabled(t *testing.T) {
	e := newEnv(t, func(o *Options) {
		o.LocalEnabled = false
		o.OIDC = &OIDCOptions{IssuerURL: "http://127.0.0.1:1", ClientID: "c", RedirectURL: "http://127.0.0.1/api/v1/auth/oidc/callback"}
	})
	if r := e.do(t, "POST", "/api/v1/auth/login", `{"username":"a","password":"b"}`, nil); r.code != http.StatusNotFound {
		t.Fatalf("login = %d", r.code)
	}
	if tok, _ := e.svc.EnsureSetupToken(context.Background()); tok != "" {
		t.Fatal("setup token with local disabled")
	}
	// Discovery failure is reported, and retried only after a back-off.
	if r := e.do(t, "GET", "/api/v1/auth/oidc/start", "", nil); r.code != http.StatusServiceUnavailable {
		t.Fatalf("start with unreachable idp = %d", r.code)
	}
}

func TestSeparationOfDuties(t *testing.T) {
	author := &Principal{UserID: "usr_a", Roles: []Role{RolePolicyApprover}}
	b := &Principal{UserID: "usr_b", Roles: []Role{RolePolicyApprover}}
	c := &Principal{UserID: "usr_c", Roles: []Role{RoleOperator}}
	if err := CheckApproval(author, RolePolicyApprover, "usr_a", nil); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("self approval: %v", err)
	}
	if err := CheckApproval(b, RolePolicyApprover, "usr_a", nil); err != nil {
		t.Errorf("valid approval: %v", err)
	}
	if err := CheckApproval(b, RolePolicyApprover, "usr_a", []string{"usr_b"}); !errors.Is(err, ErrDuplicateApproval) {
		t.Errorf("double approval: %v", err)
	}
	if err := CheckApproval(c, RolePolicyApprover, "usr_a", nil); !errors.Is(err, ErrMissingRole) {
		t.Errorf("missing role: %v", err)
	}
	if err := CheckApproval(nil, RolePolicyApprover, "usr_a", nil); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("nil approver: %v", err)
	}
	if n := DistinctApprovals("usr_a", []string{"usr_a", "usr_b", "usr_b", "usr_c", ""}); n != 2 {
		t.Errorf("distinct = %d", n)
	}
}

func TestSafeReturnTo(t *testing.T) {
	cases := map[string]string{
		"":                     "/",
		"/rules?x=1":           "/rules?x=1",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"/ok\nbad":             "/",
		"rules":                "/",
	}
	for in, want := range cases {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}
