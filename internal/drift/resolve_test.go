package drift_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
	"github.com/ivseb/traffic-twin/internal/drift"
)

func apiDo(h http.Handler, roles []auth.Role, method, url, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, url, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{UserID: "usr_test", Roles: roles}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAlertKindAndResolve(t *testing.T) {
	f := setup(t)
	f.snapshotDays(t, contracttest.Variant{EtaEpoch: true}, 600)
	h := drift.Handler(f.mgr)
	op, rr, aud := []auth.Role{auth.RoleOperator}, []auth.Role{auth.RoleRuleReviewer}, []auth.Role{auth.RoleAuditor}

	// Both kinds in one list, each with its kind.
	if err := f.mgr.RuleStale(f.ctx, drift.RuleStaleReport{RuleID: "r-1", Service: "shipping-ext", Op: "GET /v1/shipments", Confidence: 0.4, Previous: 0.9, Reason: "confidence-drop"}); err != nil {
		t.Fatal(err)
	}
	rec := apiDo(h, aud, "GET", "/api/v1/drift?kind=all", "")
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	kinds := map[string]int{}
	for _, a := range list {
		kinds[a["kind"].(string)]++
	}
	if kinds["contract.drift"] == 0 || kinds["rule.stale"] != 1 {
		t.Fatalf("kinds = %v", kinds)
	}
	var id string
	for _, a := range list {
		if a["kind"] == "contract.drift" {
			id = a["drift_id"].(string)
			break
		}
	}

	// Only operators resolve.
	body := `{"state":"resolved"}`
	if rec := apiDo(h, aud, "PATCH", "/api/v1/drift/"+id, body); rec.Code != 403 {
		t.Errorf("auditor resolves: %d", rec.Code)
	}
	if rec := apiDo(h, rr, "PATCH", "/api/v1/drift/"+id, body); rec.Code != 403 {
		t.Errorf("rule-reviewer resolves: %d", rec.Code)
	}
	for _, bad := range []string{`{"state":"open"}`, `{"state":"x"}`, `{}`, `{"state":"resolved","x":1}`} {
		if rec := apiDo(h, op, "PATCH", "/api/v1/drift/"+id, bad); rec.Code != 400 {
			t.Errorf("%s = %d", bad, rec.Code)
		}
	}
	if rec := apiDo(h, op, "PATCH", "/api/v1/drift/dr-77777777", body); rec.Code != 404 {
		t.Errorf("unknown: %d", rec.Code)
	}

	// open -> acknowledged -> resolved, repeatable; no way back.
	if rec := apiDo(h, op, "PATCH", "/api/v1/drift/"+id, `{"state":"acknowledged"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"acknowledged"`) {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body)
	}
	rec = apiDo(h, op, "PATCH", "/api/v1/drift/"+id, body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"resolved"`) || !strings.Contains(rec.Body.String(), `"resolved_by":"usr_test"`) {
		t.Fatalf("resolve: %d %s", rec.Code, rec.Body)
	}
	if rec := apiDo(h, op, "PATCH", "/api/v1/drift/"+id, body); rec.Code != 200 {
		t.Errorf("resolve twice: %d", rec.Code)
	}
	if rec := apiDo(h, op, "PATCH", "/api/v1/drift/"+id, `{"state":"acknowledged"}`); rec.Code != 409 {
		t.Errorf("resolved -> acknowledged: %d", rec.Code)
	}
	if rec := apiDo(h, op, "POST", "/api/v1/drift/"+id+"/ack", ""); rec.Code != 204 {
		t.Errorf("legacy ack of a resolved alert stays idempotent: %d", rec.Code)
	}

	// State filter.
	rec = apiDo(h, aud, "GET", "/api/v1/drift?state=resolved", "")
	var res []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != 200 || len(res) != 1 || res[0]["drift_id"] != id {
		t.Fatalf("resolved list: %d %s", rec.Code, rec.Body)
	}
	if rec := apiDo(h, aud, "GET", "/api/v1/drift?state=nope", ""); rec.Code != 400 {
		t.Errorf("bad state: %d", rec.Code)
	}

	var actions []string
	_ = audit.New(f.h.DB).Iterate(f.ctx, 0, 100, func(e audit.Entry) error { actions = append(actions, e.Action); return nil })
	if joined := strings.Join(actions, ","); !strings.Contains(joined, "drift.resolve") || !strings.Contains(joined, "drift.ack") {
		t.Errorf("audit = %s", joined)
	}
}

func TestWebhookEnableDisable(t *testing.T) {
	f := setup(t)
	h := drift.Handler(f.mgr)
	adm, op := []auth.Role{auth.RoleAdmin}, []auth.Role{auth.RoleOperator}

	rec := apiDo(h, adm, "GET", "/api/v1/webhooks", "")
	var hooks []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &hooks)
	if len(hooks) != 1 || hooks[0]["enabled"] != true {
		t.Fatalf("a new webhook is enabled: %s", rec.Body)
	}

	if rec := apiDo(h, op, "PATCH", "/api/v1/webhooks/"+f.hid, `{"enabled":false}`); rec.Code != 403 {
		t.Errorf("operator toggles: %d", rec.Code)
	}
	if rec := apiDo(h, adm, "PATCH", "/api/v1/webhooks/"+f.hid, `{}`); rec.Code != 400 {
		t.Errorf("missing enabled: %d", rec.Code)
	}
	if rec := apiDo(h, adm, "PATCH", "/api/v1/webhooks/wh-00000099", `{"enabled":false}`); rec.Code != 404 {
		t.Errorf("unknown: %d", rec.Code)
	}
	rec = apiDo(h, adm, "PATCH", "/api/v1/webhooks/"+f.hid, `{"enabled":false}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) || strings.Contains(rec.Body.String(), "secret\":") {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}

	// A disabled webhook gets nothing new; an update without "enabled" keeps it off.
	f.snapshotDays(t, contracttest.Variant{EtaEpoch: true}, 600)
	if n, err := f.mgr.DeliverDue(f.ctx); err != nil || n != 0 || len(f.rcv.all()) != 0 {
		t.Fatalf("disabled webhook delivered: n=%d err=%v got=%d", n, err, len(f.rcv.all()))
	}
	upd := `{"name":"ops chat","url":"` + f.rcv.srv.URL + `/hook","events":["contract.drift","rule.stale"]}`
	if rec := apiDo(h, adm, "PUT", "/api/v1/webhooks/"+f.hid, upd); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("update keeps the flag: %d %s", rec.Code, rec.Body)
	}

	// Enabled again: the next alert is delivered. A disabled webhook still answers a test.
	if rec := apiDo(h, adm, "PATCH", "/api/v1/webhooks/"+f.hid, `{"enabled":true}`); rec.Code != 200 {
		t.Fatalf("enable: %d", rec.Code)
	}
	if err := f.mgr.RuleStale(f.ctx, drift.RuleStaleReport{RuleID: "r-9", Service: "s", Op: "GET /x", Confidence: 0.1, Previous: 0.9, Reason: "confidence-drop"}); err != nil {
		t.Fatal(err)
	}
	if n, err := f.mgr.DeliverDue(f.ctx); err != nil || n != 1 {
		t.Fatalf("enabled webhook: n=%d err=%v", n, err)
	}

	var actions []string
	_ = audit.New(f.h.DB).Iterate(f.ctx, 0, 100, func(e audit.Entry) error { actions = append(actions, e.Action); return nil })
	if joined := strings.Join(actions, ","); !strings.Contains(joined, "webhook.disable") || !strings.Contains(joined, "webhook.enable") {
		t.Errorf("audit = %s", joined)
	}
}
