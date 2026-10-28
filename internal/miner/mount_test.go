package miner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Mount on the real tt-core server: sessions, CSRF and the route roles.
func TestMountOnServer(t *testing.T) {
	fix, _ := demoFixture(t)
	ctx := context.Background()
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(t.TempDir(), "core.db")
	db, err := store.Open(ctx, cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	al := audit.New(db)
	svc, err := auth.New(db, al, auth.Options{IdleTimeout: cfg.Auth.Session.IdleTimeout, AbsoluteTimeout: cfg.Auth.Session.AbsoluteTimeout,
		LocalEnabled: true, PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg, server.Deps{Auth: svc, Audit: al, DB: db})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := Mount(srv, Deps{DB: db, Events: fix.store, Domains: fix.doms, Audit: al, Now: func() time.Time { return fix.sim.end }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	h := srv.AdminHandler()
	const pw = "correct horse battery staple"
	for name, roles := range map[string][]auth.Role{"rev": {auth.RoleRuleReviewer}, "ops": {auth.RoleOperator}, "pub": {auth.RolePublisher}} {
		if _, err := svc.CreateLocalUser(ctx, name, pw, roles); err != nil {
			t.Fatal(err)
		}
	}
	login := func(user string) (*http.Cookie, string) {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+pw+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("login %s: %d %s", user, w.Code, w.Body)
		}
		var me struct {
			CSRF string `json:"csrf_token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &me)
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, "tt_session") {
				return &http.Cookie{Name: c.Name, Value: c.Value}, me.CSRF
			}
		}
		t.Fatal("no session cookie")
		return nil, ""
	}
	do := func(c *http.Cookie, csrf, method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:1"
		req.AddCookie(c)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	rules, err := ms.Repo().List(ctx, StatusDraft)
	if err != nil || len(rules) == 0 {
		t.Fatalf("no drafts: %v", err)
	}
	id := rules[0].Rule.ID()
	pubC, _ := login("pub")
	if code := do(pubC, "", "GET", "/api/v1/rules"); code != http.StatusForbidden {
		t.Errorf("publisher list: %d", code)
	}
	opsC, opsCSRF := login("ops")
	if code := do(opsC, "", "GET", "/api/v1/rules/"+id); code != http.StatusOK {
		t.Errorf("operator get: %d", code)
	}
	if code := do(opsC, opsCSRF, "POST", "/api/v1/rules/"+id+"/approve"); code != http.StatusForbidden {
		t.Errorf("operator approve: %d", code)
	}
	revC, revCSRF := login("rev")
	if code := do(revC, "", "POST", "/api/v1/rules/"+id+"/approve"); code != http.StatusForbidden {
		t.Errorf("approve without CSRF: %d", code)
	}
	if code := do(revC, revCSRF, "POST", "/api/v1/rules/"+id+"/approve"); code != http.StatusOK {
		t.Errorf("reviewer approve: %d", code)
	}
}
