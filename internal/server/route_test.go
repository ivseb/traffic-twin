package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// TestMountRoute: one route inside another package's prefix goes to its own
// handler with its own roles; every other path of the prefix is unchanged.
func TestMountRoute(t *testing.T) {
	hs := newHarness(t, nil)
	hs.srv.Mount("/fleet/v1/admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fleet"))
	}), auth.RoleAuditor)
	hs.srv.MountRoute("GET /fleet/v1/admin/groups/{group}/approvers", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("route:" + r.PathValue("group")))
	}), auth.RoleOperator)

	c, _, uid := hs.bootstrap(t)
	if r := hs.do(t, "GET", "/fleet/v1/admin/groups/orders/approvers", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", r.code)
	}
	if err := hs.svc.SetRoles(context.Background(), uid, []auth.Role{auth.RoleOperator}); err != nil {
		t.Fatal(err)
	}
	if r := hs.do(t, "GET", "/fleet/v1/admin/groups/orders/approvers", "", nil, c); r.code != http.StatusOK || r.body != "route:orders" {
		t.Fatalf("operator on the route = %d %q", r.code, r.body)
	}
	if r := hs.do(t, "GET", "/fleet/v1/admin/groups", "", nil, c); r.code != http.StatusForbidden {
		t.Fatalf("operator on the prefix (auditor only) = %d", r.code)
	}
	if err := hs.svc.SetRoles(context.Background(), uid, []auth.Role{auth.RoleAuditor}); err != nil {
		t.Fatal(err)
	}
	if r := hs.do(t, "GET", "/fleet/v1/admin/groups/orders/approvers", "", nil, c); r.code != http.StatusForbidden {
		t.Fatalf("auditor on the route (operator only) = %d", r.code)
	}
	if r := hs.do(t, "GET", "/fleet/v1/admin/groups", "", nil, c); r.code != http.StatusOK || r.body != "fleet" {
		t.Fatalf("auditor on the prefix = %d %q", r.code, r.body)
	}
	// Another method of the same path stays with the prefix.
	if r := hs.do(t, "DELETE", "/fleet/v1/admin/groups/orders/approvers", "", nil, c); r.code == http.StatusOK && r.body != "fleet" {
		t.Fatalf("DELETE reached the route: %q", r.body)
	}

	h := http.NotFoundHandler()
	bad := map[string]func(){
		"no roles":       func() { hs.srv.MountRoute("GET /x/y", h) },
		"no method":      func() { hs.srv.MountRoute("/x/y", h, auth.RoleAdmin) },
		"trailing slash": func() { hs.srv.MountRoute("GET /x/y/", h, auth.RoleAdmin) },
		"rest wildcard":  func() { hs.srv.MountRoute("GET /x/{rest...}", h, auth.RoleAdmin) },
		"reserved":       func() { hs.srv.MountRoute("GET /api/v1/auth/x", h, auth.RoleAdmin) },
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
}
