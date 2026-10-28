package core_rt

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// route is one operation of api/admin-api.v1.openapi.yaml.
type route struct {
	method, path string
	roles        []string // x-tt-roles; ["any"] = every authenticated user
	public       bool     // security: []
	// mockToken: the agent API of tt mock --console (admin-api 1.12.0):
	// a mock token, never a console session.
	mockToken bool
	body      map[string]any
	query     []string
}

var (
	canaryID   = "rt.canary.7731@example.org" // identifier-shaped (survives audit.SafeValue)
	canaryText = "Rt Canary Giulia Neri 7731" // free text
)

func loadRoutes(t *testing.T) []route {
	t.Helper()
	b, err := os.ReadFile("../../../api/admin-api.v1.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	params, _ := comps["parameters"].(map[string]any)
	resolve := func(m map[string]any) map[string]any {
		for i := 0; i < 5 && m != nil; i++ {
			ref, ok := m["$ref"].(string)
			if !ok {
				return m
			}
			name := ref[strings.LastIndex(ref, "/")+1:]
			if strings.Contains(ref, "/parameters/") {
				m, _ = params[name].(map[string]any)
			} else {
				m, _ = schemas[name].(map[string]any)
			}
		}
		return m
	}
	var out []route
	for p, item := range doc["paths"].(map[string]any) {
		ops := item.(map[string]any)
		var common []any
		if ps, ok := ops["parameters"].([]any); ok {
			common = ps
		}
		for m, opv := range ops {
			op, ok := opv.(map[string]any)
			if !ok || m == "parameters" {
				continue
			}
			r := route{method: strings.ToUpper(m), path: p}
			if sec, ok := op["security"].([]any); ok && len(sec) == 0 {
				r.public = true
			} else if ok && len(sec) == 1 {
				if m, _ := sec[0].(map[string]any); m != nil {
					_, r.mockToken = m["mockToken"]
				}
			}
			if rs, ok := op["x-tt-roles"].([]any); ok {
				for _, x := range rs {
					r.roles = append(r.roles, fmt.Sprint(x))
				}
			}
			allParams := append(append([]any{}, common...), op["parameters"])
			for _, pv := range allParams {
				list, ok := pv.([]any)
				if !ok {
					if pm, ok := pv.(map[string]any); ok {
						list = []any{pm}
					}
				}
				for _, x := range list {
					pm := resolve(x.(map[string]any))
					if pm != nil && pm["in"] == "query" {
						r.query = append(r.query, fmt.Sprint(pm["name"]))
					}
				}
			}
			if rb, ok := op["requestBody"].(map[string]any); ok {
				ct, _ := rb["content"].(map[string]any)
				aj, _ := ct["application/json"].(map[string]any)
				sch := resolve(asMap(aj["schema"]))
				r.body = map[string]any{}
				if props, ok := sch["properties"].(map[string]any); ok {
					for k, v := range props {
						pm := resolve(asMap(v))
						if pm["type"] == "string" || (pm["type"] == nil && pm["enum"] == nil && pm["properties"] == nil) {
							r.body[k] = canaryText
						}
					}
				}
			}
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path+out[i].method < out[j].path+out[j].method })
	return out
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

var reParam = regexp.MustCompile(`\{[^}]+\}`)

func fill(path, with string) string {
	return reParam.ReplaceAllStringFunc(path, func(string) string { return url.PathEscape(with) })
}

func unsafeMethod(m string) bool { return m != "GET" && m != "HEAD" && m != "OPTIONS" }

// skipSweep are routes the sweep must not call with a valid session and
// CSRF token because they end the caller's session.
func skipSweep(r route) bool { return r.path == "/api/v1/auth/logout" }

// For every operation of the admin API and every role (plus a user with no
// role and no session): a role outside x-tt-roles gets 403 forbidden, no
// session gets 401, an allowed role is never refused for its role. admin
// implies every role: it is allowed everywhere.
func TestRT_Core_Holds_RBACMatrix(t *testing.T) {
	e := getEnv(t)
	routes := loadRoutes(t)
	if len(routes) < 90 {
		t.Fatalf("only %d operations parsed", len(routes))
	}
	roles := []string{"admin", "operator", "rule-reviewer", "policy-approver", "publisher", "auditor", "event-exporter", ""}
	checked := 0
	for _, r := range routes {
		if r.public || skipSweep(r) {
			continue
		}
		if r.mockToken {
			// A console session, of any role, never opens the agent API.
			var body any
			if r.method != "GET" {
				body = map[string]any{}
			}
			for _, role := range roles {
				if code, b := e.u(t, roleUser[role]).do(r.method, r.path, body); code != 401 {
					t.Errorf("%s %s with a %q session = %d %.120s (want 401: mock token only)", r.method, r.path, role, code, b)
				}
			}
			continue
		}
		if len(r.roles) == 0 {
			t.Errorf("%s %s: no x-tt-roles and not public", r.method, r.path)
			continue
		}
		// Well-formed identifiers, so that the role check is what answers
		// (the rules API validates rule_id before the role: info only).
		path := strings.ReplaceAll(fill(strings.ReplaceAll(r.path, "{rule_id}", "r-99999"), "rt-nope"), "%7B", "{")
		var body any
		if r.method != "GET" {
			body = map[string]any{}
		}
		// No session.
		if code, b := e.anon(t).do(r.method, path, body); code != 401 {
			t.Errorf("%s %s without session = %d %s (want 401)", r.method, r.path, code, b)
		}
		for _, role := range roles {
			s := e.u(t, roleUser[role])
			allowed := slices.Contains(r.roles, "any") || role == "admin" || (role != "" && slices.Contains(r.roles, role))
			code, b := s.do(r.method, path, body)
			checked++
			switch {
			case !allowed && !(code == 403 && errCode(b) == "forbidden"):
				t.Errorf("%s %s as %q (not in %v) = %d %.120s (want 403 forbidden)", r.method, r.path, role, r.roles, code, b)
			case allowed && (code == 401 || (code == 403 && errCode(b) == "forbidden")):
				t.Errorf("%s %s as %q (in %v) = %d %.120s (refused for its role)", r.method, r.path, role, r.roles, code, b)
			}
		}
	}
	t.Logf("%d operations x roles checked", checked)
}

// Every unsafe authenticated operation refuses a missing or wrong CSRF
// token, and every unsafe operation (also login and setup) refuses a
// cross-origin browser request.
func TestRT_Core_Holds_CSRFAndOrigin(t *testing.T) {
	e := getEnv(t)
	for _, r := range loadRoutes(t) {
		if !unsafeMethod(r.method) {
			continue
		}
		path := fill(r.path, "rt-nope")
		role := ""
		for _, x := range r.roles {
			if x != "any" {
				role = x
				break
			}
		}
		s := e.u(t, roleUser[role])
		if !r.public && !r.mockToken {
			for name, hdr := range map[string]map[string]string{
				"no token":           {"X-CSRF-Token": "-"},
				"wrong token":        {"X-CSRF-Token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
				"other user's token": {"X-CSRF-Token": e.users["olga"].csrf},
			} {
				if name == "other user's token" && roleUser[role] == "olga" {
					hdr["X-CSRF-Token"] = e.users["rita"].csrf
				}
				code, b, _ := s.req(r.method, path, map[string]any{}, hdr)
				if code != 403 || errCode(b) != "csrf" {
					t.Errorf("%s %s with %s = %d %.100s (want 403 csrf)", r.method, r.path, name, code, b)
				}
			}
		}
		for name, hdr := range map[string]map[string]string{
			"Origin evil":          {"Origin": "https://evil.example"},
			"Origin http scheme":   {"Origin": "http://" + strings.TrimPrefix(e.base, "https://")},
			"Sec-Fetch-Site cross": {"Sec-Fetch-Site": "cross-site"},
			"Origin null":          {"Origin": "null"},
		} {
			code, b, _ := s.req(r.method, path, map[string]any{}, hdr)
			if code != 403 || errCode(b) != "cross_origin" {
				t.Errorf("%s %s with %s = %d %.100s (want 403 cross_origin)", r.method, r.path, name, code, b)
			}
		}
	}
}

// Error answers never echo submitted values: every operation is called by
// an allowed role with path parameters, query parameters and every string
// field of its request body set to canaries.
func TestRT_Core_Holds_ErrorsDoNotEchoValues(t *testing.T) {
	e := getEnv(t)
	for _, r := range loadRoutes(t) {
		if skipSweep(r) || r.path == "/api/v1/setup" {
			continue
		}
		role := ""
		for _, x := range r.roles {
			if x != "any" {
				role = x
				break
			}
		}
		s := e.u(t, roleUser[role])
		if r.public {
			s = e.anon(t)
		}
		path := fill(r.path, canaryID)
		if len(r.query) > 0 {
			q := url.Values{}
			for _, k := range r.query {
				q.Set(k, canaryText)
			}
			path += "?" + q.Encode()
		}
		var body any
		if r.body != nil {
			body = r.body
		}
		code, b := s.do(r.method, path, body)
		if code < 400 {
			continue // created objects legitimately carry their own fields
		}
		low := strings.ToLower(string(b))
		if strings.Contains(low, "canary") || strings.Contains(low, "7731") {
			t.Errorf("%s %s = %d echoes a submitted value: %.200s", r.method, r.path, code, b)
		}
	}
}
