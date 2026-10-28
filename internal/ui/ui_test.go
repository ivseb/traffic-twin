package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHandlerServesBuiltUI(t *testing.T) {
	root := fstest.MapFS{
		"index.html":         {Data: []byte("<!doctype html><title>traffic-twin</title>")},
		"assets/app-abc.js":  {Data: []byte("console.log(1)")},
		".gitkeep":           {Data: nil},
		"assets/.hidden.txt": {Data: []byte("x")},
	}
	h := handler(root)

	rec := get(t, h, http.MethodGet, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "traffic-twin") {
		t.Fatalf("GET / = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Errorf("missing CSP, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}

	if rec := get(t, h, http.MethodGet, "/assets/app-abc.js"); rec.Code != http.StatusOK {
		t.Errorf("asset status = %d", rec.Code)
	}
	for _, p := range []string{"/assets/", "/.gitkeep", "/assets/.hidden.txt", "/missing.js"} {
		if rec := get(t, h, http.MethodGet, p); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := get(t, h, http.MethodPost, "/"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST / = %d, want 405", rec.Code)
	}
}

func TestHandlerWithoutBuild(t *testing.T) {
	h := handler(fstest.MapFS{".gitkeep": {}})
	rec := get(t, h, http.MethodGet, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "make build") {
		t.Fatalf("GET / = %d %q", rec.Code, rec.Body.String())
	}
}

func TestEmbeddedHandler(t *testing.T) {
	// Works whether or not the UI has been built.
	if rec := get(t, Handler(), http.MethodGet, "/"); rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
}

func TestViewerPageHasScopedCSP(t *testing.T) {
	h := handler(fstest.MapFS{
		"index.html":  {Data: []byte("<!doctype html>")},
		"viewer.html": {Data: []byte("<!doctype html>")},
	})
	for path, want := range map[string]string{
		"/viewer.html": ViewerContentSecurityPolicy,
		"/":            "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Content-Security-Policy"); got != want {
			t.Errorf("%s: CSP = %q, want %q", path, got, want)
		}
	}
}
