package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dist holds the Vite build output (ui/ is built into internal/ui/dist).
// The "all:" prefix keeps the tracked dist/.gitkeep embeddable, so the
// package compiles even before the UI has been built.
//
//go:embed all:dist
var dist embed.FS

const notBuilt = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>traffic-twin</title></head>
<body><h1>traffic-twin</h1><p>The UI has not been built into this binary. Run <code>make build</code>.</p></body></html>
`

// Handler returns an http.Handler serving the embedded UI. Responses carry a
// strict set of security headers.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // "dist" is a compile-time constant path; cannot fail.
	}
	return handler(sub)
}

func handler(root fs.FS) http.Handler {
	_, err := fs.Stat(root, "index.html")
	built := err == nil
	files := http.FileServerFS(root)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !built {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(notBuilt))
			return
		}
		// No directory listings and no dotfiles (e.g. dist/.gitkeep).
		p := r.URL.Path
		if (p != "/" && strings.HasSuffix(p, "/")) || strings.Contains(p, "/.") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(p, "/assets/") {
			// Vite emits content-hashed asset names: safe to cache forever.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			// HTML entry points must be revalidated so a new release is picked up.
			w.Header().Set("Cache-Control", "no-cache")
		}
		if p == "/viewer.html" {
			// Only the OpenAPI viewers page relaxes styles: Redoc and Scalar inject
			// <style> elements and all three viewers use data: URI icons.
			w.Header().Set("Content-Security-Policy", ViewerContentSecurityPolicy)
		}
		files.ServeHTTP(w, r)
	})
}

// ViewerContentSecurityPolicy is served for /viewer.html only; every other
// route keeps the strict default-src 'self' policy.
const ViewerContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}
