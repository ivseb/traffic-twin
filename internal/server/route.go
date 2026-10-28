package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// MountRoute serves h for one route of the admin listener ("GET
// /api/v1/fleet/groups/{group}/approvers") for authenticated users holding
// at least one of roles (CSRF enforced on unsafe methods).
//
// Unlike Mount it may sit inside a prefix another package mounted: the
// pattern names a method and a whole path, so it is more specific than the
// prefix and the mux sends that route here and every other path to the
// prefix's handler. It lets a package add one endpoint under another
// package's prefix without editing it. It panics on a pattern without a
// method, on a path ending in "/" or "{name...}" (a prefix: use Mount) and
// on the reserved prefixes (auth, setup, audit, health).
func (s *Server) MountRoute(pattern string, h http.Handler, roles ...auth.Role) {
	if len(roles) == 0 {
		panic("server: MountRoute needs at least one role")
	}
	method, path, ok := strings.Cut(pattern, " ")
	if !ok || method == "" || strings.ToUpper(method) != method || !strings.HasPrefix(path, "/") ||
		strings.HasSuffix(path, "/") || strings.Contains(path, "...}") || strings.Contains(path, "//") {
		panic(fmt.Sprintf("server: invalid route %q (METHOD /absolute/path, no trailing slash, no {name...})", pattern))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		panic("server: mount after Run: " + pattern)
	}
	for _, p := range reservedPrefixes {
		if overlaps(path, p) {
			panic(fmt.Sprintf("server: route %q overlaps %q", pattern, p))
		}
	}
	s.handleAdmin(pattern, s.deps.Auth.Require(roles...)(h))
}
