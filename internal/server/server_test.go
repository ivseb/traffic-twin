package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/store"
)

var fastParams = auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type harness struct {
	srv   *Server
	h     http.Handler
	svc   *auth.Service
	audit *audit.Log
	logs  *syncBuffer
	cfg   config.Config
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(t.TempDir(), "tt.db")
	cfg.Keyguard.URL = "unix:///run/tt/keyguard.sock" // required by config since the core integration; not dialled here
	cfg.Intake.Addr = ""                              // the intake is on by default since then; tests enable it
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger := NewLogger(logs, "debug", "json")
	db, err := store.Open(context.Background(), cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	al := audit.New(db)
	svc, err := auth.New(db, al, auth.Options{
		IdleTimeout: cfg.Auth.Session.IdleTimeout, AbsoluteTimeout: cfg.Auth.Session.AbsoluteTimeout,
		TLS: cfg.Admin.TLS.Enabled(), LocalEnabled: true, PasswordParams: &fastParams, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<!doctype html>ui")) })
	srv, err := New(cfg, Deps{Logger: logger, Auth: svc, Audit: al, DB: db, UI: ui})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{srv: srv, h: nil, svc: svc, audit: al, logs: logs, cfg: cfg}
}

func (hs *harness) handler() http.Handler {
	if hs.h == nil {
		hs.h = hs.srv.AdminHandler()
	}
	return hs.h
}

type result struct {
	code   int
	body   string
	header http.Header
}

func (hs *harness) do(t *testing.T, method, path, body string, hdr map[string]string, cookies ...*http.Cookie) result {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:5555"
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
	hs.handler().ServeHTTP(rec, req)
	return result{rec.Code, rec.Body.String(), rec.Header()}
}

func cookieFrom(t *testing.T, r result) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if strings.HasSuffix(c.Name, "tt_session") && c.Value != "" {
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	t.Fatalf("no session cookie: %v", r.header)
	return nil
}

const pw = "correct horse battery staple"

// login bootstraps alice (admin) and returns her cookie and CSRF token.
func (hs *harness) bootstrap(t *testing.T) (*http.Cookie, string, string) {
	t.Helper()
	tok, err := hs.svc.EnsureSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := hs.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+tok+`","username":"alice","password":"`+pw+`"}`, nil)
	if r.code != http.StatusCreated {
		t.Fatalf("setup = %d %s", r.code, r.body)
	}
	var me struct {
		User      struct{ ID string } `json:"user"`
		CSRFToken string              `json:"csrf_token"`
	}
	_ = json.Unmarshal([]byte(r.body), &me)
	return cookieFrom(t, r), me.CSRFToken, me.User.ID
}

func TestEndToEndAuthAndMount(t *testing.T) {
	hs := newHarness(t, nil)
	var seen string
	hs.srv.Mount("/fleet/v1/admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFrom(r.Context())
		seen = r.URL.Path
		_, _ = w.Write([]byte("fleet:" + p.DisplayName))
	}), auth.RoleOperator)

	c, csrf, uid := hs.bootstrap(t)

	if r := hs.do(t, "GET", "/fleet/v1/admin/sources", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", r.code)
	}
	if r := hs.do(t, "GET", "/fleet/v1/admin/sources", "", nil, c); r.code != http.StatusOK {
		t.Fatalf("admin without operator = %d (admin implies every role)", r.code)
	}
	if err := hs.svc.SetRoles(context.Background(), uid, []auth.Role{auth.RoleAuditor}); err != nil {
		t.Fatal(err)
	}
	if r := hs.do(t, "GET", "/fleet/v1/admin/sources", "", nil, c); r.code != http.StatusForbidden {
		t.Fatalf("auditor without operator = %d", r.code)
	}
	if err := hs.svc.SetRoles(context.Background(), uid, []auth.Role{auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor}); err != nil {
		t.Fatal(err)
	}
	r := hs.do(t, "GET", "/fleet/v1/admin/sources", "", nil, c)
	if r.code != http.StatusOK || r.body != "fleet:alice" || seen != "/fleet/v1/admin/sources" {
		t.Fatalf("operator = %d %q (path seen %q)", r.code, r.body, seen)
	}
	if r := hs.do(t, "POST", "/fleet/v1/admin/kill", "{}", nil, c); r.code != http.StatusForbidden {
		t.Fatalf("unsafe without CSRF = %d", r.code)
	}
	if r := hs.do(t, "POST", "/fleet/v1/admin/kill", "{}", map[string]string{"X-CSRF-Token": csrf}, c); r.code != http.StatusOK {
		t.Fatalf("unsafe with CSRF = %d", r.code)
	}

	// Auditor export and verify.
	r = hs.do(t, "GET", "/api/v1/audit/verify", "", nil, c)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"ok":true`) {
		t.Fatalf("verify = %d %s", r.code, r.body)
	}
	r = hs.do(t, "GET", "/api/v1/audit/export", "", nil, c)
	if r.code != http.StatusOK {
		t.Fatalf("export = %d", r.code)
	}
	var actions []string
	sc := bufio.NewScanner(strings.NewReader(r.body))
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, e.Action)
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"auth.setup_token_issued", "auth.setup", "authz.deny", "authz.csrf", "audit.verify", "audit.export"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit export lacks %s: %s", want, joined)
		}
	}

	// Logout.
	if r := hs.do(t, "POST", "/api/v1/auth/logout", "", map[string]string{"X-CSRF-Token": csrf}, c); r.code != http.StatusNoContent {
		t.Fatalf("logout = %d", r.code)
	}
	if r := hs.do(t, "GET", "/api/v1/auth/me", "", nil, c); r.code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d", r.code)
	}
}

func TestAuditRequiresAuditorRole(t *testing.T) {
	hs := newHarness(t, nil)
	c, _, uid := hs.bootstrap(t)
	// admin implies auditor.
	for _, p := range []string{"/api/v1/audit/export", "/api/v1/audit/verify"} {
		if r := hs.do(t, "GET", p, "", nil, c); r.code != http.StatusOK {
			t.Errorf("%s as admin = %d", p, r.code)
		}
	}
	if err := hs.svc.SetRoles(context.Background(), uid, []auth.Role{auth.RoleOperator}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/v1/audit/export", "/api/v1/audit/verify"} {
		if r := hs.do(t, "GET", p, "", nil, c); r.code != http.StatusForbidden {
			t.Errorf("%s as operator = %d", p, r.code)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	hs := newHarness(t, nil)
	for _, p := range []string{"/", "/api/v1/auth/config", "/api/nope", "/healthz"} {
		r := hs.do(t, "GET", p, "", nil)
		if r.header.Get("Content-Security-Policy") != ContentSecurityPolicy ||
			r.header.Get("X-Frame-Options") != "DENY" || r.header.Get("X-Content-Type-Options") != "nosniff" ||
			r.header.Get("Referrer-Policy") != "no-referrer" || r.header.Get("X-Request-Id") == "" {
			t.Errorf("%s: headers %v", p, r.header)
		}
		if strings.HasPrefix(p, "/api/") && r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: API response cacheable", p)
		}
	}
	if r := hs.do(t, "GET", "/api/nope", "", nil); r.code != http.StatusNotFound || !strings.Contains(r.body, "not_found") {
		t.Errorf("unknown API path = %d %s", r.code, r.body)
	}
	if r := hs.do(t, "GET", "/", "", nil); r.code != http.StatusOK || !strings.Contains(r.body, "ui") {
		t.Errorf("UI = %d", r.code)
	}
	if r := hs.do(t, "GET", "/", "", nil); r.header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS on plaintext listener")
	}
}

func TestCrossOriginRefused(t *testing.T) {
	hs := newHarness(t, nil)
	body := `{"username":"alice","password":"whatever whatever"}`
	if r := hs.do(t, "POST", "/api/v1/auth/login", body, map[string]string{"Origin": "https://evil.example"}); r.code != http.StatusForbidden {
		t.Errorf("foreign Origin = %d", r.code)
	}
	if r := hs.do(t, "POST", "/api/v1/auth/login", body, map[string]string{"Sec-Fetch-Site": "cross-site"}); r.code != http.StatusForbidden {
		t.Errorf("cross-site = %d", r.code)
	}
	if r := hs.do(t, "POST", "/api/v1/auth/login", body, map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"}); r.code != http.StatusUnauthorized {
		t.Errorf("same origin = %d (want 401 bad credentials)", r.code)
	}
}

func TestBodyLimit(t *testing.T) {
	hs := newHarness(t, func(c *config.Config) { c.Admin.HTTP.MaxBodyBytes = 2048 })
	big := `{"username":"` + strings.Repeat("a", 4096) + `","password":"x"}`
	if r := hs.do(t, "POST", "/api/v1/auth/login", big, nil); r.code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d", r.code)
	}
}

func TestRateLimitOnAuthEndpoints(t *testing.T) {
	hs := newHarness(t, func(c *config.Config) { c.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 1, Burst: 3} })
	body := `{"username":"alice","password":"whatever whatever"}`
	var last result
	for range 4 {
		last = hs.do(t, "POST", "/api/v1/auth/login", body, nil)
	}
	if last.code != http.StatusTooManyRequests || last.header.Get("Retry-After") == "" {
		t.Fatalf("4th login = %d", last.code)
	}
	// Other clients and non-auth routes are unaffected.
	if r := hs.do(t, "GET", "/healthz", "", nil); r.code != http.StatusOK {
		t.Errorf("healthz = %d", r.code)
	}
}

func TestRateLimiterRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := newRateLimiter(60, 2)
	l.now = func() time.Time { return now }
	if ok, _ := l.allow("192.0.2.1"); !ok {
		t.Fatal()
	}
	if ok, _ := l.allow("192.0.2.1"); !ok {
		t.Fatal()
	}
	if ok, wait := l.allow("192.0.2.1"); ok || wait <= 0 {
		t.Fatal("burst exceeded")
	}
	if ok, _ := l.allow("192.0.2.2"); !ok {
		t.Fatal("other IP throttled")
	}
	now = now.Add(time.Second)
	if ok, _ := l.allow("192.0.2.1"); !ok {
		t.Fatal("no refill")
	}
	// IPv6 addresses in the same /64 share a bucket.
	if clientKey("2001:db8::1") != clientKey("2001:db8::ffff") || clientKey("2001:db8::1") == clientKey("2001:db8:0:1::1") {
		t.Error("IPv6 /64 keying")
	}
	l.max = 2
	if ok, _ := l.allow("192.0.2.3"); ok {
		t.Error("table full should fail closed")
	}
	now = now.Add(time.Hour)
	if ok, _ := l.allow("192.0.2.3"); !ok {
		t.Error("stale entries not swept")
	}
}

func TestPanicRecovery(t *testing.T) {
	hs := newHarness(t, nil)
	hs.srv.MountPublic("/boom", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("internal detail /etc/secret")
	}))
	r := hs.do(t, "GET", "/boom", "", nil)
	if r.code != http.StatusInternalServerError || strings.Contains(r.body, "secret") || !strings.Contains(r.body, `"internal"`) {
		t.Fatalf("panic response = %d %s", r.code, r.body)
	}
	if !strings.Contains(hs.logs.String(), "panic recovered") {
		t.Error("panic not logged")
	}
}

func TestHealthAndReadiness(t *testing.T) {
	hs := newHarness(t, nil)
	if r := hs.do(t, "GET", "/healthz", "", nil); r.code != http.StatusOK || r.body != "ok\n" {
		t.Fatalf("healthz = %d %q", r.code, r.body)
	}
	if r := hs.do(t, "GET", "/readyz", "", nil); r.code != http.StatusOK {
		t.Fatalf("readyz = %d %s", r.code, r.body)
	}
	hs.srv.AddReadinessCheck("fleet", func(context.Context) error { return context.DeadlineExceeded })
	r := hs.do(t, "GET", "/readyz", "", nil)
	if r.code != http.StatusServiceUnavailable || !strings.Contains(r.body, `"fleet"`) || strings.Contains(r.body, "deadline") {
		t.Fatalf("readyz failing = %d %s", r.code, r.body)
	}
}

func TestMountValidation(t *testing.T) {
	hs := newHarness(t, nil)
	h := http.NotFoundHandler()
	hs.srv.Mount("/api/v1/rules", h, auth.RoleRuleReviewer)
	bad := map[string]func(){
		"no roles":        func() { hs.srv.Mount("/api/v1/x", h) },
		"overlap":         func() { hs.srv.Mount("/api/v1/rules/sub", h, auth.RoleAdmin) },
		"overlap parent":  func() { hs.srv.MountPublic("/api/v1", h) },
		"reserved":        func() { hs.srv.MountPublic("/api/v1/auth/extra", h) },
		"trailing slash":  func() { hs.srv.Mount("/api/v1/y/", h, auth.RoleAdmin) },
		"relative":        func() { hs.srv.Mount("api", h, auth.RoleAdmin) },
		"pattern":         func() { hs.srv.Mount("/api/{id}", h, auth.RoleAdmin) },
		"root":            func() { hs.srv.MountPublic("/", h) },
		"unknown role":    func() { hs.srv.Mount("/api/v1/z", h, auth.Role("root")) },
		"intake healthz":  func() { hs.srv.MountIntake("/healthz", h) },
		"intake overlap":  func() { hs.srv.MountIntake("/v1/logs", h); hs.srv.MountIntake("/v1/logs", h) },
		"intake relative": func() { hs.srv.MountIntake("v1", h) },
	}
	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		})
	}
	// Mounting a sibling with a shared string prefix (not a path prefix) is fine.
	hs.srv.Mount("/api/v1/rules-drafts", h, auth.RoleRuleReviewer)
}

// TestLogsNeverContainRequestValues is the M14 regression test: values
// sent in bodies, queries, headers, cookies, paths and panic messages must
// never reach the logs.
func TestLogsNeverContainRequestValues(t *testing.T) {
	hs := newHarness(t, func(c *config.Config) { c.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 1000, Burst: 1000} })
	const marker = "VALUE-MUST-NOT-BE-LOGGED-7f3a"
	hs.srv.MountPublic("/echo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "panic") {
			panic("boom " + marker)
		}
		var v map[string]any
		_ = json.NewDecoder(r.Body).Decode(&v)
		w.WriteHeader(http.StatusAccepted)
	}))
	hs.srv.MountIntake("/v1/logs", http.NotFoundHandler())

	hdr := map[string]string{
		"Authorization":   "Bearer " + marker,
		"X-Custom":        marker,
		"User-Agent":      marker,
		"Referer":         "https://x.example/" + marker,
		"X-Forwarded-For": marker,
	}
	ck := &http.Cookie{Name: "tt_session", Value: marker}
	body := `{"username":"` + marker + `","password":"` + marker + `"}`

	hs.do(t, "POST", "/api/v1/auth/login?q="+marker, body, hdr, ck)
	hs.do(t, "POST", "/api/v1/setup", `{"setup_token":"`+marker+`","username":"`+marker+`","password":"`+marker+`"}`, hdr, ck)
	hs.do(t, "POST", "/api/v1/setup", `{"unknown":"`+marker+`"}`, hdr)
	hs.do(t, "POST", "/echo/"+marker+"?x="+marker, `{"secret":"`+marker+`"}`, hdr, ck)
	hs.do(t, "GET", "/echo/panic/"+marker, "", hdr, ck)
	hs.do(t, "GET", "/api/"+marker, "", hdr, ck)
	hs.do(t, "GET", "/"+marker+"?"+marker+"="+marker, "", hdr, ck)
	hs.do(t, "GET", "/api/v1/auth/me", "", hdr, ck)
	hs.do(t, "GET", "/api/v1/auth/oidc/callback?code="+marker+"&state="+marker, "", hdr, ck)

	// Intake listener with a body (no TLS in this direct handler test).
	req := httptest.NewRequest("POST", "/v1/logs?"+marker, strings.NewReader(`{"resourceLogs":"`+marker+`"}`))
	req.Header.Set("Authorization", marker)
	hs.srv.IntakeHandler().ServeHTTP(httptest.NewRecorder(), req)

	// Direct logger use with sensitive keys is redacted too.
	hs.srv.log.Info("defence in depth", "password", marker, "csrf_token", marker, "request_body", marker)

	logs := hs.logs.String()
	if !strings.Contains(logs, `"msg":"http request"`) || !strings.Contains(logs, "panic recovered") {
		t.Fatalf("expected access and panic logs, got:\n%s", logs)
	}
	if strings.Contains(logs, marker) {
		t.Fatalf("request value leaked into logs:\n%s", logs)
	}
	// The audit log must not contain it either.
	var all strings.Builder
	_ = hs.audit.Iterate(context.Background(), 0, 0, func(e audit.Entry) error {
		b, _ := json.Marshal(e)
		all.Write(b)
		return nil
	})
	if strings.Contains(all.String(), marker) {
		t.Fatalf("request value leaked into the audit log:\n%s", all.String())
	}
}
