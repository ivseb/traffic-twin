package sanitizer

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// FuzzFrameworkRoute: route normalization never panics and only produces
// templates of the operation-key grammar.
func FuzzFrameworkRoute(f *testing.F) {
	for _, s := range []string{"/api/:id(\\d+)", "/a/<int:n>", "/{ id : x }", "/{$}", "/{id:int:min(1)}", "/{x<\\d+>?1}", "/*", ""} {
		f.Add(s, uint8(0))
	}
	fws := []string{"express", "koa", "fastify", "flask", "fastapi", "django", "spring", "jaxrs", "aspnetcore", "gin", "chi", "nethttp", "laravel", "symfony", "unknown"}
	f.Fuzz(func(t *testing.T, route string, k uint8) {
		segs, ok := normalizeFrameworkRoute(fws[int(k)%len(fws)], route)
		if !ok {
			return
		}
		var b strings.Builder
		b.WriteString("GET /")
		for i, s := range segs {
			if i > 0 {
				b.WriteByte('/')
			}
			if s.Param != "" {
				b.WriteString("{" + s.Param + "}")
			} else {
				b.WriteString(s.Literal)
			}
		}
		if _, _, ok := policy.ParseOpKey(b.String()); !ok {
			t.Fatalf("%q -> %q", route, b.String())
		}
	})
}
