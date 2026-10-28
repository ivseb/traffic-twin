package core_rt

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// Every successful state change through the admin API leaves at least one
// audit entry (admin-api: "Every mutating call is written to the audit
// log").
func TestRT_Core_Holds_AuditForStateChanges(t *testing.T) {
	e := getEnv(t)
	olga, ada, paul := e.u(t, "olga"), e.u(t, "ada"), e.u(t, "paul")
	var tokID, hookID string
	steps := []struct {
		who    *session
		method string
		path   func() string
		body   any
		after  func([]byte)
	}{
		{olga, "POST", fix("/api/v1/fleet/groups"), map[string]any{"name": "rt-aud", "allowed_service_names": []string{"rt-aud-svc"}}, nil},
		{olga, "PUT", fix("/api/v1/fleet/groups/rt-aud"), map[string]any{"name": "rt-aud", "allowed_service_names": []string{"rt-aud-svc", "rt-aud-two"}}, nil},
		{olga, "POST", fix("/api/v1/fleet/enrollment-tokens"), map[string]any{"kind": "egress", "group": "rt-aud", "token_type": "group"},
			func(b []byte) { tokID = field(b, "token_id") }},
		{olga, "DELETE", func() string { return "/api/v1/fleet/enrollment-tokens/" + tokID }, nil, nil},
		{olga, "POST", fix("/api/v1/fleet/kill"), map[string]any{"active": true, "scope": map[string]any{"group": "rt-aud"}}, nil},
		{olga, "POST", fix("/api/v1/fleet/kill"), map[string]any{"active": false, "scope": map[string]any{"group": "rt-aud"}}, nil},
		{olga, "POST", fix("/api/v1/scenario-presets"), map[string]any{"preset_id": "rt-aud", "name": "Rt preset"}, nil},
		{olga, "PUT", fix("/api/v1/scenario-presets/rt-aud"), map[string]any{"preset_id": "rt-aud", "name": "Rt preset two"}, nil},
		{olga, "DELETE", fix("/api/v1/scenario-presets/rt-aud"), nil, nil},
		{olga, "POST", fix("/api/v1/contracts/shop-api/snapshots"), map[string]any{"from": e.start, "to": e.end}, nil},
		{olga, "POST", fix("/api/v1/worlds"), map[string]any{"seed": 7, "customers": 10}, nil},
		{ada, "POST", fix("/api/v1/webhooks"), map[string]any{"name": "rt-aud", "url": "http://" + e.hooks.addr + "/aud", "events": []string{"rule.stale"}},
			func(b []byte) { hookID = field(b, "webhook_id") }},
		{ada, "PUT", func() string { return "/api/v1/webhooks/" + hookID }, map[string]any{"name": "rt-aud2", "url": "http://" + e.hooks.addr + "/aud", "events": []string{"rule.stale"}}, nil},
		{ada, "POST", func() string { return "/api/v1/webhooks/" + hookID + "/test" }, nil, nil},
		{ada, "DELETE", func() string { return "/api/v1/webhooks/" + hookID }, nil, nil},
		{ada, "PUT", fix("/api/v1/store/retention"), map[string]any{"events_days": 300}, nil},
		{paul, "POST", fix("/api/v1/exports"), map[string]any{"pack_id": e.packID, "target": "prism"}, nil},
		{paul, "GET", fix("/api/v1/packs/" + e.packID + "/download"), nil, nil},
		{e.u(t, "eve"), "GET", fix("/api/v1/events/export/" + e.eveJob + "/download"), nil, nil},
	}
	for _, s := range steps {
		head := e.auditHead(t)
		p := s.path()
		code, b := s.who.do(s.method, p, s.body)
		if code >= 300 {
			t.Errorf("%s %s = %d %.200s (setup of the audit check)", s.method, p, code, b)
			continue
		}
		if s.after != nil {
			s.after(b)
		}
		var acts []string
		for _, a := range e.auditSince(t, head) {
			if a["action"] != "audit.export" {
				acts = append(acts, fmt.Sprint(a["action"]))
			}
		}
		if len(acts) == 0 {
			t.Errorf("%s %s (%d) left no audit entry", s.method, p, code)
		} else {
			t.Logf("%s %s -> %v", s.method, p, acts)
		}
	}
}

func fix(p string) func() string { return func() string { return p } }

func field(b []byte, k string) string {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return fmt.Sprint(m[k])
}

// No audit entry ever contains free text, real values, secrets or tokens:
// after the whole flow (approvals with reasons, quarantine values, canary
// requests) the export is scanned.
func TestRT_Core_Holds_AuditHasNoValuesOrSecrets(t *testing.T) {
	e := getEnv(t)
	// Canary requests: free text in bodies, values in queries.
	e.u(t, "olga").do("POST", "/api/v1/fleet/groups", map[string]any{"name": canaryText, "allowed_service_names": []string{canaryText}, "description": canaryText})
	e.u(t, "nora").do("GET", "/api/v1/rules?status="+url.QueryEscape(canaryText), nil)
	raw, _ := json.Marshal(e.auditEntries(t))
	all := string(raw)
	bad := map[string]string{
		"free text canary":     canaryText,
		"admin reason":         "single-maintainer trial",
		"quarantined value":    "RTQSTATE00",
		"password":             testPassword,
		"setup token":          e.core.SetupToken(),
		"a session CSRF token": e.users["olga"].csrf,
		"a session cookie":     strings.SplitN(e.users["olga"].cookie, "=", 2)[1],
		"the webhook secret":   e.hookSec,
		"a real order id":      e.orderIDs[0],
		"keyguard HMAC key":    keyB64(e.keyFiles["hmac.keys"]),
		"policy signing seed":  keyB64(e.keyFiles["policy.key"]),
		"pack signing seed":    keyB64(e.keyFiles["pack.key"]),
	}
	for what, v := range bad {
		if v != "" && strings.Contains(all, v) {
			t.Errorf("tt-core audit log contains %s", what)
		}
	}
}

// keyB64 returns the base64url part of the first "kid:base64url" line.
func keyB64(s string) string {
	line := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if i := strings.Index(line, ":"); i >= 0 {
		return line[i+1:]
	}
	return line
}

// FIXED (was low, red team round 2; now a regression test). Authorization and CSRF denials recorded by auth.Require use
// the raw request path as the audit target (auth/session.go routeTarget:
// r.Method + ":" + r.URL.Path, then SafeValue), unlike the core router that
// records the route pattern. Any authenticated user, even with no role, can
// therefore write chosen identifier-shaped strings (e-mail addresses, names
// joined with dots, up to 128 bytes) into the append-only, undeletable audit
// log: personal data that can never be erased, and log spam.
func TestRT_Core_Fixed_AuditTargetTakesRawPath(t *testing.T) {
	e := getEnv(t)
	victim := "mario.rossi.rt@example.org"
	e.u(t, "nora").do("PUT", "/api/v1/fleet/groups/"+victim, map[string]any{"name": "x", "allowed_service_names": []string{"x"}})
	e.u(t, "nora").req("POST", "/api/v1/fleet/kill/"+victim, map[string]any{}, map[string]string{"X-CSRF-Token": "-"})
	for _, a := range e.auditEntries(t) {
		if strings.Contains(fmt.Sprint(a["target"]), victim) {
			t.Fatalf("audit entry %v %v stores a client-chosen path value: %v", a["action"], a["reason"], a["target"])
		}
	}
}
