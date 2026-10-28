package mockreg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/mock"
)

func TestPagesSetting(t *testing.T) {
	e := newEnv(t, nil)
	page := map[string]any{"id": "pay", "title": "Pagamento", "buttons": []any{map[string]any{"action": "approve", "label": "Approva"}},
		"return_url": "https://app.test/back?r={ref}",
		"callback":   map[string]any{"method": "POST", "url": "https://app.test/cb", "body": `{"r":"{ref}"}`, "hmac": map[string]any{"header": "X-Sig", "key": "secret-of-test"}}}
	code, body := e.adminDo(olga, "GET", "/api/v1/mocks/pages?group=shop", nil)
	if code != 200 || !strings.Contains(string(body), `"pages":[]`) {
		t.Fatalf("default: %d %s", code, body)
	}
	if code, _ := e.adminDo(&auth.Principal{UserID: "u-a", Roles: []auth.Role{auth.RoleAuditor}}, "PUT", "/api/v1/mocks/pages", map[string]any{"group": "shop", "pages": []any{page}}); code != 403 {
		t.Fatalf("auditor changed the pages: %d", code)
	}
	bad := map[string]any{"id": "pay", "title": "x", "buttons": []any{map[string]any{"action": "ok", "label": "ok"}}, "callback": map[string]any{"method": "POST", "url": "{query.cb}"}}
	if code, body := e.adminDo(olga, "PUT", "/api/v1/mocks/pages", map[string]any{"group": "shop", "pages": []any{bad}}); code != 422 || !strings.Contains(string(body), "invalid_pages") {
		t.Fatalf("invalid: %d %s", code, body)
	}
	code, body = e.adminDo(olga, "PUT", "/api/v1/mocks/pages", map[string]any{"group": "shop", "pages": []any{page}})
	if code != 200 || strings.Contains(string(body), "secret-of-test") || !strings.Contains(string(body), `"updated_by"`) {
		t.Fatalf("set: %d %s", code, body)
	}
	// saving again with the masked (empty) key keeps the key
	page["title"] = "Pagamento simulato"
	page["callback"].(map[string]any)["hmac"].(map[string]any)["key"] = ""
	if code, body := e.adminDo(olga, "PUT", "/api/v1/mocks/pages", map[string]any{"group": "shop", "pages": []any{page}}); code != 200 {
		t.Fatalf("set again: %d %s", code, body)
	}
	// the configuration, with the key, goes to the group's mocks
	tok := e.token("shop")
	rec, b := e.agentDo("POST", "/api/v1/mock-agent/report", tok, mock.Report{Instance: "ci-1", Group: "shop", Status: "serving", PackID: "pk-20261025-0001"})
	if rec.Code != 200 {
		t.Fatalf("report: %d %s", rec.Code, b)
	}
	var ans mock.ReportAnswer
	if err := json.Unmarshal(b, &ans); err != nil || ans.Pages == nil || len(ans.Pages.Pages) != 1 || ans.Pages.Pages[0].Callback.HMAC.Key != "secret-of-test" || ans.Pages.Pages[0].Title != "Pagamento simulato" {
		t.Fatalf("answer: %s", b)
	}
}
