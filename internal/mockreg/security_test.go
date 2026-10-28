package mockreg

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/mock"
)

// Security review of the mock registry and the agent API (mock.md 6).

func (e *env) newToken(group string) NewToken {
	e.t.Helper()
	code, body := e.adminDo(olga, "POST", "/api/v1/mocks/tokens", map[string]any{"group": group})
	if code != 201 {
		e.t.Fatalf("create token: %d %s", code, body)
	}
	var nt NewToken
	_ = json.Unmarshal(body, &nt)
	return nt
}

// A revocation that lands while a report is held (long poll) answers 401 at
// once, and a report that authenticated just before the revocation does not
// bring the instance back.
func TestRevocationEndsLongPollAndStays(t *testing.T) {
	e := newEnv(t, nil)
	e.reg.o.ReportInterval = 5 * time.Second
	nt := e.newToken("shop")
	rep := mock.Report{Instance: "ci-1", Group: "shop", Status: "serving", PackID: "pk-20261025-0001"}
	// First report: up to date, held until the interval or an event.
	done := make(chan int, 1)
	go func() {
		rec, _ := e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep)
		done <- rec.Code
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if code, _ := e.adminDo(olga, "DELETE", "/api/v1/mocks/tokens/"+nt.TokenID, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	select {
	case code := <-done:
		if code != 401 {
			t.Fatalf("held report after revocation: %d", code)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("the revocation did not wake the held report")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("held report not ended by the revocation")
	}
	// A request that authenticated before the revocation reaches report():
	// refused, and the instance stays revoked (no commands for it).
	tok := &TokenInfo{TokenID: nt.TokenID, Group: "shop"}
	if _, err := e.reg.report(tok, &rep, e.reg.o.Wall()); err == nil {
		t.Fatal("report of a revoked instance accepted")
	}
	_, body := e.adminDo(olga, "GET", "/api/v1/mocks", nil)
	if !strings.Contains(string(body), `"status":"revoked"`) {
		t.Fatalf("revoked mock shown as %s", body)
	}
	if code, _ := e.adminDo(olga, "POST", "/api/v1/mocks/"+nt.TokenID+".ci-1/commands", map[string]any{"method": "GET", "path": "/__tt/pack"}); code != 409 {
		t.Fatalf("command queued for a revoked mock: %d", code)
	}
}

// One token cannot fill the registry and lock out the mocks of the other
// groups.
func TestInstancesPerTokenBounded(t *testing.T) {
	e := newEnv(t, nil)
	nt := e.newToken("shop")
	for i := range maxInstancesPerToken {
		rep := mock.Report{Instance: fmt.Sprintf("ci-%d", i), Group: "shop", Status: "waiting"}
		if rec, b := e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep); rec.Code != 200 {
			t.Fatalf("report %d: %d %s", i, rec.Code, b)
		}
	}
	rep := mock.Report{Instance: "one-too-many", Group: "shop", Status: "waiting"}
	if rec, _ := e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep); rec.Code != 429 {
		t.Fatalf("instance over the per-token cap: %d", rec.Code)
	}
	other := e.newToken("other")
	rep = mock.Report{Instance: "ci-0", Group: "other", Status: "waiting", PackID: "x"}
	if rec, _ := e.agentDo("POST", "/api/v1/mock-agent/report", other.Token, rep); rec.Code != 200 {
		t.Fatalf("another group's mock locked out: %d", rec.Code)
	}
}

// What a mock reports is bounded and cleaned before the console shows it:
// URLs only http(s) without credentials, no control or bidi characters, no
// query string in a call path, no oversized command result.
func TestReportedFieldsAreCleaned(t *testing.T) {
	e := newEnv(t, nil)
	nt := e.newToken("shop")
	rep := mock.Report{Instance: "ci-1", Group: "shop", Status: "serving\x1b[31m", PackID: "pk-20261025-0001", PublicURL: "javascript:alert(document.cookie)",
		Version: "1.0‮gnp.exe",
		Services: []mock.ServiceURL{
			{Name: "carrier", BaseURL: "https://user:pw@mock.example/__svc/carrier"},
			{Name: "host:evil.example/<script>", BaseURL: "http://mock:8480/__svc/x"},
			{Name: strings.Repeat("n", 5000), BaseURL: "data:text/html,<script>alert(1)</script>"},
		},
		Sessions: []mock.SessionSummary{{ID: "t1\n", Clock: strings.Repeat("9", 500), Calls: -4}},
		Calls:    []mock.Call{{Method: "GET", Path: "/__svc/carrier/x?card=4111", Session: "t1", Op: strings.Repeat("o", 2000), LatencyMS: -1}},
	}
	if rec, b := e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep); rec.Code != 200 {
		t.Fatalf("report: %d %s", rec.Code, b)
	}
	_, body := e.adminDo(olga, "GET", "/api/v1/mocks", nil)
	var lv ListView
	if err := json.Unmarshal(body, &lv); err != nil || len(lv.Mocks) != 1 {
		t.Fatalf("list: %s", body)
	}
	m := lv.Mocks[0]
	if m.PublicURL != "" || m.Status != "serving[31m" || strings.ContainsRune(m.Version, '‮') {
		t.Fatalf("fields: %+v", m)
	}
	if m.Services[0].MockURL != "" || m.Services[2].MockURL != "" || len(m.Services[2].Name) > 128 {
		t.Fatalf("service URLs: %+v", m.Services)
	}
	if m.Services[1].RealBase != "" {
		t.Fatalf("a malformed host became a real base: %+v", m.Services[1])
	}
	if s := m.Sessions[0]; s.ID != "t1" || len(s.Clock) > 40 || s.Calls != 0 {
		t.Fatalf("session: %+v", s)
	}
	_, body = e.adminDo(olga, "GET", "/api/v1/mocks/"+m.MockID+"/calls", nil)
	if strings.Contains(string(body), "4111") || strings.Contains(string(body), "?") || strings.Contains(string(body), strings.Repeat("o", 301)) {
		t.Fatalf("calls: %s", body)
	}

	// Command result larger than the mock may send: not kept as is.
	code, body := e.adminDo(olga, "POST", "/api/v1/mocks/"+m.MockID+"/commands", map[string]any{"method": "GET", "path": "/__tt/pack"})
	if code != 202 {
		t.Fatalf("command: %d %s", code, body)
	}
	var cq struct {
		CommandID string `json:"command_id"`
	}
	_ = json.Unmarshal(body, &cq)
	big := `{"x":"` + strings.Repeat("a", 70<<10) + `"}`
	rep2 := mock.Report{Instance: "ci-1", Group: "shop", Status: "serving", PackID: "pk-20261025-0001",
		Results: []mock.CommandResult{{ID: cq.CommandID, Status: 200, Body: json.RawMessage(big)}}}
	e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep2)
	_, body = e.adminDo(olga, "GET", "/api/v1/mocks/"+m.MockID+"/commands/"+cq.CommandID, nil)
	if len(body) > 64<<10 || !strings.Contains(string(body), "too_large") {
		t.Fatalf("oversized result kept: %d bytes", len(body))
	}
}

// Refused tokens are rate limited per client and token id; a valid token
// of another id from the same client keeps working.
func TestRefusedTokensRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	nt := e.newToken("shop")
	id, _, _ := strings.Cut(strings.TrimPrefix(nt.Token, "ttm_"), ".")
	guess := "ttm_" + id + "." + strings.Repeat("A", 43)
	for i := range failBurst {
		if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", guess, nil); rec.Code != 401 {
			t.Fatalf("guess %d: %d", i, rec.Code)
		}
	}
	rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", guess, nil)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("guess over the budget: %d", rec.Code)
	}
	// the right secret is not even checked while the budget is spent
	if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", nt.Token, nil); rec.Code != 429 {
		t.Fatalf("lookup while limited: %d", rec.Code)
	}
	// another token from the same client is not locked out
	other := e.newToken("shop")
	if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", other.Token, nil); rec.Code != 200 {
		t.Fatalf("another token locked out: %d", rec.Code)
	}
}
