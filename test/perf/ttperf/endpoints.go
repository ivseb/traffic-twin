package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type endpoint struct {
	name  string // stable name used by the budgets
	path  string
	class string // list, detail, heavy
	note  string
}

// endpoints lists every GET operation of api/admin-api.v1.openapi.yaml with
// typical query parameters (the OIDC redirects excepted: they need an IdP).
func (h *harness) endpoints() []endpoint {
	svc := url.PathEscape(h.ids["service"])
	first := func(path, field string) string {
		var arr []map[string]any
		code, b, _, err := h.admin.do("GET", path, nil)
		if err != nil || code != 200 {
			return ""
		}
		if json.Unmarshal(b, &arr) != nil {
			var obj map[string]any
			if json.Unmarshal(b, &obj) == nil {
				for _, k := range []string{"items", "sources", "policies", "worlds", "packs", "tokens", "groups"} {
					if a, ok := obj[k].([]any); ok {
						for _, x := range a {
							if m, ok := x.(map[string]any); ok {
								arr = append(arr, m)
							}
						}
						break
					}
				}
			}
		}
		if len(arr) == 0 {
			return ""
		}
		return fmt.Sprint(arr[0][field])
	}
	srcID := h.sourceID
	tokID := h.ids["token_id"]
	if tokID == "" {
		tokID = first("/api/v1/fleet/enrollment-tokens", "token_id")
	}
	var pol struct {
		PolicyID string `json:"policy_id"`
		Version  any    `json:"version"`
	}
	{
		var arr []map[string]any
		if h.admin.json(200, "GET", "/api/v1/fleet/policies", nil, &arr) == nil && len(arr) > 0 {
			pol.PolicyID, pol.Version = fmt.Sprint(arr[0]["policy_id"]), arr[0]["version"]
		}
	}
	rule := first("/api/v1/rules", "id")
	world := h.ids["world"]
	cust := ""
	{
		var w map[string]any
		if world != "" && h.admin.json(200, "GET", "/api/v1/worlds/"+world, nil, &w) == nil {
			if cs, ok := w["customers"].([]any); ok && len(cs) > 0 {
				if c, ok := cs[0].(map[string]any); ok {
					cust = fmt.Sprint(c["id"])
				}
			}
			if cust == "" {
				if cs, ok := w["customer_ids"].([]any); ok && len(cs) > 0 {
					cust = fmt.Sprint(cs[0])
				}
			}
			if cust == "" {
				cust = "CUS-SYN-0001" // synthetic customer ids (world.md)
			}
		}
	}
	eps := []endpoint{
		{"healthz", "/healthz", "detail", ""},
		{"readyz", "/readyz", "detail", ""},
		{"auth.config", "/api/v1/auth/config", "detail", ""},
		{"auth.me", "/api/v1/auth/me", "detail", ""},
		{"version", "/api/v1/version", "detail", ""},
		{"settings", "/api/v1/settings", "detail", ""},
		{"users", "/api/v1/users", "list", ""},
		{"fleet.groups", "/api/v1/fleet/groups", "list", ""},
		{"fleet.group", "/api/v1/fleet/groups/demo", "detail", ""},
		{"fleet.tokens", "/api/v1/fleet/enrollment-tokens", "list", ""},
		{"fleet.onboarding", "/api/v1/fleet/onboarding/" + tokID + "/status", "detail", ""},
		{"fleet.sources", "/api/v1/fleet/sources", "list", ""},
		{"fleet.sources.group", "/api/v1/fleet/sources?group=demo", "list", ""},
		{"fleet.source", "/api/v1/fleet/sources/" + srcID, "detail", ""},
		{"fleet.policies", "/api/v1/fleet/policies", "list", ""},
		{"fleet.policy_version", fmt.Sprintf("/api/v1/fleet/policies/%s/versions/%v", pol.PolicyID, pol.Version), "detail", ""},
		{"fleet.policy_assist", "/api/v1/fleet/policies/p-demo/assist", "heavy", ""},
		{"fleet.signing_keys", "/api/v1/fleet/signing-keys", "list", ""},
		{"fleet.approval_settings", "/api/v1/fleet/approval-settings", "detail", ""},
		{"services", "/api/v1/services", "list", "aggregates: other work item"},
		{"services.ops", "/api/v1/services/" + svc + "/ops", "list", "same aggregate as /services"},
		{"hosts", "/api/v1/hosts", "list", "aggregates: other work item"},
		{"contracts", "/api/v1/contracts", "list", ""},
		{"contract", "/api/v1/contracts/" + svc, "detail", ""},
		{"contract.yaml", "/api/v1/contracts/" + svc + "?format=yaml", "detail", ""},
		{"contract.snapshots", "/api/v1/contracts/" + svc + "/snapshots", "list", ""},
		{"contract.snapshots.100", "/api/v1/contracts/" + svc + "/snapshots?limit=100", "list", ""},
		{"contract.snapshot", "/api/v1/contracts/" + svc + "/snapshots/" + h.ids["snapshot"], "detail", ""},
		{"contract.snapshot.diff", "/api/v1/contracts/" + svc + "/snapshots/" + h.ids["snapshot"] + "?diff_against=" + h.ids["snapshot_prev"], "detail", ""},
		{"drift", "/api/v1/drift", "list", ""},
		{"drift.open", "/api/v1/drift?state=open", "list", ""},
		{"drift.all.1000", "/api/v1/drift?kind=all&limit=1000", "list", ""},
		{"gaps", "/api/v1/gaps", "list", ""},
		{"rules", "/api/v1/rules", "list", ""},
		{"rules.draft", "/api/v1/rules?status=draft", "list", ""},
		{"rules.status", "/api/v1/rules/status", "detail", ""},
		{"rule", "/api/v1/rules/" + rule, "detail", ""},
		{"archetypes", "/api/v1/archetypes", "list", ""},
		{"worlds", "/api/v1/worlds", "list", ""},
		{"world", "/api/v1/worlds/" + world, "detail", ""},
		{"world.customer", "/api/v1/worlds/" + world + "/customers/" + url.PathEscape(cust), "detail", ""},
		{"packs", "/api/v1/packs", "list", ""},
		{"pack", "/api/v1/packs/" + h.ids["pack"], "detail", ""},
		{"pack.download", "/api/v1/packs/" + h.ids["pack"] + "/download", "heavy", ""},
		{"export", "/api/v1/exports/" + h.ids["export"], "detail", ""},
		{"export.download", "/api/v1/exports/" + h.ids["export"] + "/download", "heavy", ""},
		{"scenario_presets", "/api/v1/scenario-presets", "list", ""},
		{"quarantine", "/api/v1/quarantine", "list", ""},
		{"webhooks", "/api/v1/webhooks", "list", ""},
		{"webhook.deliveries", "/api/v1/webhooks/" + h.ids["webhook"] + "/deliveries", "list", ""},
		{"webhook.deliveries.50", "/api/v1/webhooks/" + h.ids["webhook"] + "/deliveries?limit=50", "list", ""},
		{"store.retention", "/api/v1/store/retention", "detail", ""},
		{"audit.export.last500", "/api/v1/audit/export?last=500", "list", ""},
		{"audit.export.page", "/api/v1/audit/export?after_seq=1000&limit=1000", "list", ""},
		{"audit.export.max", "/api/v1/audit/export?after_seq=0&limit=100000", "heavy", ""},
		{"audit.verify", "/api/v1/audit/verify", "heavy", ""},
		{"keyguard.status", "/api/v1/keyguard/status", "detail", ""},
		{"keyguard.audit", "/api/v1/keyguard/audit", "list", ""},
		{"jobs", "/api/v1/jobs", "list", ""},
	}
	if id := h.ids["event_export"]; id != "" {
		eps = append(eps, endpoint{"events.export.download", "/api/v1/events/export/" + id + "/download", "heavy", ""},
			endpoint{"job", "/api/v1/jobs/" + id, "detail", ""})
	}
	return eps
}

func (h *harness) benchEndpoints(ctx context.Context) {
	for _, e := range h.endpoints() {
		if h.skip[e.name] {
			h.rep.Endpoints = append(h.rep.Endpoints, &EndpointStats{Name: e.name, Path: e.path, Class: e.class, Note: "skipped (-skip)"})
			continue
		}
		if strings.Contains(e.path, "//") || strings.HasSuffix(e.path, "/") {
			h.rep.Endpoints = append(h.rep.Endpoints, &EndpointStats{Name: e.name, Path: e.path, Class: e.class, Note: "skipped: no id"})
			continue
		}
		n := h.sc.Iterations
		if e.class == "heavy" || e.note != "" {
			n = max(2, n/4)
		}
		st := &EndpointStats{Name: e.name, Path: e.path, Class: e.class, Note: e.note}
		var xs []float64
		// warm-up (page cache, prepared state), not counted
		_, _, _, _ = h.admin.do("GET", e.path, nil)
		for i := 0; i < n; i++ {
			code, b, d, err := h.admin.do("GET", e.path, nil)
			if err != nil {
				st.Note = strings.TrimSpace(st.Note + " error: " + err.Error())
				break
			}
			st.Status, st.Bytes = code, len(b)
			xs = append(xs, float64(d.Microseconds())/1000)
		}
		st.N = len(xs)
		st.P50, st.P95, st.Max = percentile(xs, 0.5), percentile(xs, 0.95), percentile(xs, 1)
		fmt.Printf("    %-28s %3d p50 %8.1f p95 %8.1f max %8.1f ms %9d B\n", e.name, st.Status, st.P50, st.P95, st.Max, st.Bytes)
		h.rep.Endpoints = append(h.rep.Endpoints, st)
	}
}
