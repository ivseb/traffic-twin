package mockreg

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/mock"
)

func TestIdentitySetting(t *testing.T) {
	e := newEnv(t, nil)
	const user = "tester.seven@corp.test"
	// Off by default.
	code, body := e.adminDo(olga, "GET", "/api/v1/mocks/identity?group=shop", nil)
	if code != 200 || !strings.Contains(string(body), `"enabled":false`) {
		t.Fatalf("default: %d %s", code, body)
	}
	// Any header name is accepted; a malformed one is not.
	if code, body := e.adminDo(olga, "PUT", "/api/v1/mocks/identity", map[string]any{"group": "shop", "header": "bad header"}); code != 422 || !strings.Contains(string(body), "invalid_header") {
		t.Fatalf("bad header: %d %s", code, body)
	}
	if code, _ := e.adminDo(&auth.Principal{UserID: "u-a", Roles: []auth.Role{auth.RoleAuditor}}, "PUT", "/api/v1/mocks/identity", map[string]any{"group": "shop", "header": "x-user"}); code != 403 {
		t.Fatalf("auditor changed the setting: %d", code)
	}
	code, body = e.adminDo(olga, "PUT", "/api/v1/mocks/identity", map[string]any{"group": "shop", "header": "X-Caller", "claim": ""})
	if code != 200 || !strings.Contains(string(body), `"enabled":true`) {
		t.Fatalf("set: %d %s", code, body)
	}
	code, body = e.adminDo(olga, "POST", "/api/v1/mocks/identity/map", map[string]any{"group": "shop", "user": user, "customer": "CUS-SYN-0007"})
	if code != 200 {
		t.Fatalf("map: %d %s", code, body)
	}
	if code, body := e.adminDo(olga, "POST", "/api/v1/mocks/identity/map", map[string]any{"group": "shop", "user": "x", "customer": "nobody"}); code != 422 || !strings.Contains(string(body), "invalid_customer") {
		t.Fatalf("bad customer: %d %s", code, body)
	}
	var v IdentityView
	_ = json.Unmarshal(body, &v)
	// The user is never stored, shown or audited in clear.
	if strings.Contains(string(body), user) {
		t.Fatalf("view shows the user: %s", body)
	}
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM mockreg_identity_map WHERE user_hash LIKE '%' || ? || '%' OR customer = ?`, "tester", user).Scan(&n)
	if n != 0 {
		t.Fatal("the user is stored in clear")
	}
	_ = e.audit.Iterate(t.Context(), 0, 10000, func(x audit.Entry) error {
		if b, _ := json.Marshal(x); strings.Contains(string(b), user) {
			t.Fatalf("audit shows the user: %s", b)
		}
		return nil
	})

	// The setting goes to the group's mocks with the key and hashed users.
	tok := e.token("shop")
	rec, b := e.agentDo("POST", "/api/v1/mock-agent/report", tok, mock.Report{Instance: "ci-1", Group: "shop", Status: "serving", PackID: "pk-20261025-0001"})
	if rec.Code != 200 {
		t.Fatalf("report: %d %s", rec.Code, b)
	}
	var ans mock.ReportAnswer
	_ = json.Unmarshal(b, &ans)
	if ans.Identity == nil || ans.Identity.Header != "X-Caller" || ans.Identity.Key == "" {
		t.Fatalf("answer identity: %s", b)
	}
	key, _ := base64.RawURLEncoding.DecodeString(ans.Identity.Key)
	h := mock.IdentityHash(key, user)
	if ans.Identity.Map["h:"+h] != "CUS-SYN-0007" || strings.Contains(string(b), user) {
		t.Fatalf("answer map: %s", b)
	}
	cfg, err := ans.Identity.Config()
	if err != nil || cfg.Header != "X-Caller" || len(cfg.Key) != 32 {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	// The key stays: the same user keeps the same hash after a change.
	e.adminDo(olga, "PUT", "/api/v1/mocks/identity", map[string]any{"group": "shop", "header": "authorization", "claim": "sub"})
	_, b = e.agentDo("POST", "/api/v1/mock-agent/report", tok, mock.Report{Instance: "ci-1", Group: "shop", Status: "serving", PackID: "pk-20261025-0001"})
	var ans2 mock.ReportAnswer
	_ = json.Unmarshal(b, &ans2)
	if ans2.Identity == nil || ans2.Identity.Key != ans.Identity.Key || ans2.Identity.Claim != "sub" {
		t.Fatalf("after a change: %s", b)
	}
	// Removing the user, then turning the setting off.
	if code, body := e.adminDo(olga, "DELETE", "/api/v1/mocks/identity/map/"+h+"?group=shop", nil); code != 200 || strings.Contains(string(body), h) {
		t.Fatalf("remove: %d %s", code, body)
	}
	e.adminDo(olga, "PUT", "/api/v1/mocks/identity", map[string]any{"group": "shop", "header": ""})
	_, b = e.agentDo("POST", "/api/v1/mock-agent/report", tok, mock.Report{Instance: "ci-1", Group: "shop", Status: "serving", PackID: "pk-20261025-0001"})
	var ans3 mock.ReportAnswer
	_ = json.Unmarshal(b, &ans3)
	if ans3.Identity == nil || ans3.Identity.Header != "" {
		t.Fatalf("off: %s", b)
	}
	if c, _ := ans3.Identity.Config(); c != nil {
		t.Fatal("an off setting must turn the identity sessions off")
	}
	acts := strings.Join(e.actions(), ",")
	for _, a := range []string{"mock.identity_set", "mock.identity_map_set", "mock.identity_map_delete"} {
		if !strings.Contains(acts, a) {
			t.Errorf("audit lacks %s: %s", a, acts)
		}
	}
	// Another group's mock gets nothing.
	other := e.token("other")
	_, b = e.agentDo("POST", "/api/v1/mock-agent/report", other, mock.Report{Instance: "ci-2", Group: "other", Status: "serving", PackID: "pk-20261025-0009"})
	if strings.Contains(string(b), `"identity"`) {
		t.Fatalf("another group got the setting: %s", b)
	}
}

func (e *env) token(group string) string {
	e.t.Helper()
	code, body := e.adminDo(olga, "POST", "/api/v1/mocks/tokens", map[string]any{"group": group})
	if code != 201 {
		e.t.Fatalf("token: %d %s", code, body)
	}
	var nt NewToken
	_ = json.Unmarshal(body, &nt)
	return nt.Token
}
