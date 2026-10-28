package audit

import (
	"net/http"
	"strings"
)

// RouteTarget identifies the route of r for denial entries (authz.deny,
// authz.csrf): the method and the matched route PATTERN (r.Pattern, e.g.
// "/api/v1/fleet/groups/{name}"), never the request path. The raw path is
// client-chosen: any authenticated user could otherwise write e-mail
// addresses or names into the append-only audit log (red team round 2).
// Without a matched pattern the target is "<method>:unmatched".
func RouteTarget(r *http.Request) Target {
	return Target{Type: "route", ID: SafeValue(RouteID(r))}
}

// RouteID is "<method>:<pattern path>" for r (see RouteTarget). The method is
// kept only when it is a standard one.
func RouteID(r *http.Request) string {
	p := r.Pattern
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = strings.TrimSpace(p[i+1:]) // "GET /x" -> "/x"
	}
	if i := strings.IndexByte(p, '/'); i > 0 {
		p = p[i:] // "host/x" -> "/x"
	}
	if p == "" {
		p = "unmatched"
	}
	m := r.Method
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
	default:
		m = "OTHER"
	}
	return m + ":" + p
}
