package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Denial targets come from the matched route pattern, never the raw path.
func TestRouteTargetUsesPattern(t *testing.T) {
	var got Target
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/fleet/groups/{name}", func(_ http.ResponseWriter, r *http.Request) { got = RouteTarget(r) })
	mux.HandleFunc("/api/v1/fleet/", func(_ http.ResponseWriter, r *http.Request) { got = RouteTarget(r) })
	for path, want := range map[string]string{
		"/api/v1/fleet/groups/mario.rossi@example.org": "PUT:/api/v1/fleet/groups/_name_",
		"/api/v1/fleet/kill/mario.rossi@example.org":   "PUT:/api/v1/fleet/",
	} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", path, nil))
		if got.ID != want || strings.Contains(got.ID, "mario") {
			t.Errorf("%s: target %q (want %q)", path, got.ID, want)
		}
	}
	r := httptest.NewRequest("BREW", "/x/mario.rossi", nil)
	if id := RouteTarget(r).ID; id != "OTHER:unmatched" {
		t.Errorf("unmatched: %q", id)
	}
}
