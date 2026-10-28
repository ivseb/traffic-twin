// Package ttchi is the chi adapter of the traffic-twin Go SDK. It lives in its
// own module so that applications that do not use chi never depend on it.
//
//	r := chi.NewRouter()
//	r.Use(ttchi.Middleware)
//
// The route template (framework_route) is chi's RoutePattern, which includes
// the prefixes of mounted sub-routers ("/api/orders/{id}"). A wildcard route
// ("/files/*") can not be turned into a template and the sanitizer uses the
// templates of the policy instead (docs/spec/sanitizer.md section 3.4).
package ttchi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	ttsdk "github.com/ivseb/traffic-twin/sdk/go"
)

// Middleware captures the requests of the router with the default agent
// (configured by the TT_* environment variables). With the SDK inert it
// returns next unchanged.
func Middleware(next http.Handler) http.Handler { return MiddlewareFor(nil)(next) }

// MiddlewareFor is Middleware with an explicit agent (nil: the default one).
func MiddlewareFor(a *ttsdk.Agent) func(http.Handler) http.Handler {
	if a == nil {
		a = ttsdk.Default()
	}
	return func(next http.Handler) http.Handler {
		return a.Handler(next, ttsdk.WithRoute(route))
	}
}

// route runs after the router handled the request, when chi knows the whole
// pattern, mount prefixes included.
func route(r *http.Request) (framework, route string) {
	rc := chi.RouteContext(r.Context())
	if rc == nil {
		return "", ""
	}
	return "chi", rc.RoutePattern()
}
