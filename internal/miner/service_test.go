package miner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
)

func newTestService(t *testing.T) (*Service, *audit.Log, *memSink) {
	t.Helper()
	fix, _ := demoFixture(t)
	db := openDB(t)
	al := audit.New(db)
	sink := &memSink{}
	now := fix.sim.end.Add(time.Hour)
	s, err := New(Deps{DB: db, Events: fix.store, Domains: fix.doms, Audit: al, Staleness: sink, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return s, al, sink
}

func call(t *testing.T, h http.Handler, p *auth.Principal, method, path, body string) (int, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if p != nil {
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func auditEntries(t *testing.T, al *audit.Log) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	if err := al.Iterate(context.Background(), 0, 10000, func(e audit.Entry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestServiceRunAndAPI(t *testing.T) {
	s, al, _ := newTestService(t)
	ctx := context.Background()
	rep, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.New) != 3 {
		t.Fatalf("run: %+v", rep)
	}
	h := s.Handler()
	reviewer := &auth.Principal{UserID: "usr_rev", DisplayName: "rev", Roles: []auth.Role{auth.RoleRuleReviewer}}
	auditor := &auth.Principal{UserID: "usr_aud", DisplayName: "aud", Roles: []auth.Role{auth.RoleAuditor}}
	admin := &auth.Principal{UserID: "usr_adm", DisplayName: "adm", Roles: []auth.Role{auth.RoleAdmin}}

	if code, _ := call(t, h, nil, "GET", "/api/v1/rules", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous list: %d", code)
	}
	if code, _ := call(t, h, admin, "GET", "/api/v1/rules", ""); code != http.StatusOK {
		t.Errorf("admin list: %d (admin implies every role)", code)
	}
	code, body := call(t, h, auditor, "GET", "/api/v1/rules?status=draft", "")
	var list []json.RawMessage
	if code != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list) != 3 {
		t.Fatalf("auditor list: %d %s", code, body)
	}
	if code, _ := call(t, h, auditor, "GET", "/api/v1/rules?status=bogus", ""); code != http.StatusBadRequest {
		t.Errorf("bad status filter: %d", code)
	}
	id := rep.New[0]
	code, body = call(t, h, auditor, "GET", "/api/v1/rules/"+id, "")
	var one map[string]any
	if code != http.StatusOK || json.Unmarshal(body, &one) != nil || one["id"] != id || one["evidence"] == nil {
		t.Fatalf("get: %d %s", code, body)
	}
	if at, _ := one["proposed_at"].(string); at == "" {
		t.Fatalf("proposed_at missing: %s", body)
	} else if _, err := time.Parse(time.RFC3339, at); err != nil {
		t.Fatalf("proposed_at: %v", err)
	}
	if list[0] == nil || !strings.Contains(string(list[0]), `"proposed_at"`) {
		t.Fatalf("proposed_at missing from the list: %s", list[0])
	}
	if code, _ := call(t, h, auditor, "GET", "/api/v1/rules/r-9999", ""); code != http.StatusNotFound {
		t.Errorf("unknown rule: %d", code)
	}
	if code, _ := call(t, h, auditor, "GET", "/api/v1/rules/../x", ""); code == http.StatusOK {
		t.Errorf("bad id accepted")
	}

	// Only rule-reviewer changes rules; a denial is audited.
	if code, _ := call(t, h, auditor, "POST", "/api/v1/rules/"+id+"/approve", ""); code != http.StatusForbidden {
		t.Errorf("auditor approve: %d", code)
	}
	var causalID string
	for _, x := range rep.New {
		r := mustGet(t, s.Repo(), x)
		if r.Rule.Causal != nil && r.Rule.Causal.Cause.Op == "POST /orders" {
			causalID = x
		}
	}
	if code, b := call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, `{"after":{"shipment-created":"5m"},"title":"Ordine e spedizione"}`); code != http.StatusOK {
		t.Errorf("edit: %d %s", code, b)
	}
	if code, _ := call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, `{"after":{"shipment-created":"5 min"}}`); code != http.StatusBadRequest {
		t.Errorf("bad duration: %d", code)
	}
	// A range is accepted (rules spec 3.3) and shown back as a {min, max} object.
	code, body = call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, `{"after":{"shipment-created":{"min":"2m","max":"10m"}}}`)
	if code != http.StatusOK || !strings.Contains(string(body), `"after":{"min":"2m","max":"10m"}`) {
		t.Errorf("range edit: %d %s", code, body)
	}
	for _, bad := range []string{
		`{"after":{"shipment-created":{"min":"10m","max":"2m"}}}`, // min > max
		`{"after":{"shipment-created":{"min":"2m"}}}`,             // max missing
		`{"after":{"shipment-created":{"min":"2m","max":"1 h"}}}`, // bad duration
		`{"after":{"shipment-created":{"min":"2m","max":"5m","x":1}}}`,
		`{"after":{"shipment-created":null}}`,
		`{"after":{"shipment-created":5}}`,
	} {
		if code, _ := call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, code)
		}
	}
	if code, b := call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, `{"after":{"shipment-created":"5m"}}`); code != http.StatusOK || !strings.Contains(string(b), `"after":"5m"`) {
		t.Errorf("single again: %d %s", code, b)
	}
	if code, _ := call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, `{"status":"approved"}`); code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", code)
	}
	code, body = call(t, h, reviewer, "POST", "/api/v1/rules/"+causalID+"/approve", "")
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"approved"`) || !strings.Contains(string(body), `"by":["usr_rev"]`) {
		t.Fatalf("approve: %d %s", code, body)
	}
	if code, _ := call(t, h, reviewer, "POST", "/api/v1/rules/"+causalID+"/approve", ""); code != http.StatusConflict {
		t.Errorf("approve twice: %d", code)
	}
	// Edit of an approved rule: a new draft that supersedes it.
	code, body = call(t, h, reviewer, "PATCH", "/api/v1/rules/"+causalID, `{"title":"Nuova bozza"}`)
	if code != http.StatusOK || !strings.Contains(string(body), `"supersedes":"`+causalID+`"`) {
		t.Errorf("edit approved: %d %s", code, body)
	}
	const secretNote = "Nota privata del revisore"
	other := rep.New[1]
	if other == causalID {
		other = rep.New[0]
	}
	if code, b := call(t, h, reviewer, "POST", "/api/v1/rules/"+other+"/reject", `{"note":"`+secretNote+`"}`); code != http.StatusOK {
		t.Errorf("reject: %d %s", code, b)
	}

	// The audit log has every change, never the note.
	actions := map[string]int{}
	for _, e := range auditEntries(t, al) {
		actions[e.Action+":"+string(e.Outcome)]++
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "privata") {
			t.Errorf("free text in the audit log: %s", raw)
		}
	}
	for _, a := range []string{"rule.mine:success", "rule.approve:denied", "rule.edit:success", "rule.edit:failure",
		"rule.approve:success", "rule.approve:failure", "rule.reject:success"} {
		if actions[a] == 0 {
			t.Errorf("audit lacks %s (have %v)", a, actions)
		}
	}

	// A second run keeps ids and approvals.
	rep2, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.New) != 0 || mustGet(t, s.Repo(), causalID).Rule.Status() != StatusApproved {
		t.Errorf("second run: %+v", rep2)
	}
	doc, err := s.Repo().Document(ctx, StatusApproved, time.Now())
	if err != nil || len(doc.Rules) != 1 || doc.Validate() != nil {
		t.Errorf("approved document: %v", err)
	}
}

func TestOCELExport(t *testing.T) {
	fix, _ := demoFixture(t)
	var buf bytes.Buffer
	err := ExportOCEL(context.Background(), fix.store, ExportQuery{From: simStart, To: simStart.Add(24 * time.Hour)}, fix.doms, DefaultConfig(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ObjectTypes []struct{ Name string } `json:"objectTypes"`
		EventTypes  []struct{ Name string } `json:"eventTypes"`
		Objects     []struct {
			ID, Type      string
			Relationships []struct{ ObjectID, Qualifier string }
		} `json:"objects"`
		Events []struct {
			ID, Type, Time string
			Relationships  []struct{ ObjectID, Qualifier string }
		} `json:"events"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("OCEL JSON: %v", err)
	}
	types := map[string]bool{}
	for _, ot := range doc.ObjectTypes {
		types[ot.Name] = true
	}
	for _, want := range []string{"order", "shipment", "customer", "subject"} {
		if !types[want] {
			t.Errorf("object type %s missing (%v)", want, types)
		}
	}
	ids := map[string]bool{}
	o2o := 0
	for _, o := range doc.Objects {
		ids[o.ID] = true
		if o.Type == "shipment" {
			for _, r := range o.Relationships {
				if r.Qualifier == "orderId" {
					o2o++
				}
			}
		}
		if !strings.HasPrefix(o.ID, "tk1:") {
			t.Fatalf("object id is not a token")
		}
	}
	if o2o == 0 {
		t.Errorf("no shipment → order relationships")
	}
	for _, e := range doc.Events {
		for _, r := range e.Relationships {
			if !ids[r.ObjectID] {
				t.Fatalf("event %s refers to an unknown object", e.ID)
			}
		}
	}
	if len(doc.Events) == 0 || len(doc.EventTypes) < 6 {
		t.Errorf("events %d, event types %d", len(doc.Events), len(doc.EventTypes))
	}
}
