package contract_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
)

func asRoles(h http.Handler, roles ...auth.Role) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), &auth.Principal{UserID: "usr_test", Roles: roles})))
	})
}

func get(t *testing.T, h http.Handler, method, url string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, url, nil))
	return rec
}

func TestEngineSnapshotsAPIAndDiff(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 700, contracttest.Variant{})
	day2 := day1.Add(24 * time.Hour)
	h.DemoDay(day2, 700, contracttest.Variant{EtaEpoch: true})
	h.Wait()

	now := day2.Add(48 * time.Hour)
	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var hooked int
	eng.OnSnapshot(func(_ context.Context, prev, cur *contract.Snapshot) error {
		if prev != nil {
			hooked++
		}
		return nil
	})
	ctx := context.Background()
	for _, d := range []time.Time{day1, day2} {
		if _, err := eng.SnapshotWindow(ctx, contract.Window{From: d, To: d.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if hooked != 2 { // one previous snapshot per service for day 2
		t.Errorf("hook calls with a previous snapshot: %d", hooked)
	}
	// Idempotent: same window again keeps ids.
	again, err := eng.SnapshotWindow(ctx, contract.Window{From: day1, To: day1.Add(24 * time.Hour)})
	if err != nil || len(again) == 0 {
		t.Fatal(err)
	}
	list, _ := eng.Snapshots().List(ctx, "shipping-ext", 10)
	if len(list) != 2 {
		t.Fatalf("snapshots: %+v", list)
	}

	api := contract.Handler(contract.APIDeps{Engine: eng})
	op := asRoles(api, auth.RoleOperator)

	// Role check.
	if rec := get(t, asRoles(api, auth.RoleAdmin), "GET", "/api/v1/contracts"); rec.Code != 200 {
		t.Errorf("admin implies every role: %d", rec.Code)
	}
	if rec := get(t, asRoles(api, auth.RoleEventExporter), "GET", "/api/v1/contracts"); rec.Code != 403 {
		t.Errorf("event-exporter alone must be refused: %d", rec.Code)
	}
	if rec := get(t, asRoles(api, auth.RolePublisher), "GET", "/api/v1/contracts/shipping-ext/snapshots"); rec.Code != 403 {
		t.Errorf("publisher cannot list snapshots: %d", rec.Code)
	}
	if rec := get(t, asRoles(api, auth.RolePublisher), "GET", "/api/v1/contracts/shipping-ext"); rec.Code != 200 {
		t.Errorf("publisher reads contracts: %d", rec.Code)
	}

	rec := get(t, op, "GET", "/api/v1/contracts")
	var infos []contract.SnapshotInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &infos); err != nil || len(infos) != 2 {
		t.Fatalf("contracts: %v %s", err, rec.Body)
	}
	if infos[0].Window.To != day2.Add(24*time.Hour) {
		t.Errorf("latest snapshot window: %+v", infos[0].Window)
	}

	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext")
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), `{"info"`) || rec.Header().Get("X-TT-Snapshot") == "" {
		t.Fatalf("contract: %d %.100s", rec.Code, rec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || doc["openapi"] != "3.1.0" {
		t.Fatalf("not an OpenAPI document: %v", err)
	}
	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext?format=yaml")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/yaml") || !strings.Contains(rec.Body.String(), "openapi: 3.1.0") {
		t.Fatalf("yaml: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec = get(t, op, "GET", "/api/v1/contracts/nope"); rec.Code != 404 {
		t.Errorf("unknown service: %d", rec.Code)
	}

	// Snapshots and diff between any two.
	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots")
	var snaps []contract.SnapshotInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &snaps)
	if len(snaps) != 2 || snaps[0].SnapshotID <= snaps[1].SnapshotID {
		t.Fatalf("snapshots newest first: %+v", snaps)
	}
	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots/"+snaps[1].SnapshotID)
	if rec.Code != 200 {
		t.Fatalf("snapshot: %d", rec.Code)
	}
	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots/"+snaps[0].SnapshotID+"?diff_against="+snaps[1].SnapshotID)
	var diff contract.DiffResult
	if err := json.Unmarshal(rec.Body.Bytes(), &diff); err != nil || rec.Code != 200 {
		t.Fatalf("diff: %v %d", err, rec.Code)
	}
	if diff.From.SnapshotID != snaps[1].SnapshotID || diff.To.SnapshotID != snaps[0].SnapshotID {
		t.Errorf("baseline must be the older snapshot: %+v %+v", diff.From, diff.To)
	}
	var typeChange *contract.Change
	for i, c := range diff.Changes {
		if c.Kind == "type-changed" && strings.Contains(c.Text, "'eta'") {
			typeChange = &diff.Changes[i]
		}
	}
	if typeChange == nil || typeChange.Severity != contract.Breaking || typeChange.Op != "GET /v1/shipments" {
		t.Fatalf("eta type change not reported as breaking: %+v", diff.Changes)
	}
	if !strings.Contains(typeChange.Text, "string(date-time)") || !strings.Contains(typeChange.Text, "integer") {
		t.Errorf("text: %s", typeChange.Text)
	}
	if diff.Breaking == 0 {
		t.Error("breaking counter")
	}
	// The same diff with swapped arguments has the same baseline.
	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots/"+snaps[1].SnapshotID+"?diff_against="+snaps[0].SnapshotID)
	var diff2 contract.DiffResult
	_ = json.Unmarshal(rec.Body.Bytes(), &diff2)
	if len(diff2.Changes) != len(diff.Changes) {
		t.Error("diff must not depend on argument order")
	}
	if rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots/sn-99999999"); rec.Code != 404 {
		t.Errorf("unknown snapshot: %d", rec.Code)
	}

	// Services, ops, gaps.
	rec = get(t, op, "GET", "/api/v1/services")
	var svcs []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &svcs)
	if len(svcs) != 2 || svcs[0]["service"] != "shipping-ext" || svcs[0]["kind"] != "outbound-policy" || svcs[1]["kind"] != "inbound" {
		t.Errorf("services: %s", rec.Body)
	}
	rec = get(t, op, "GET", "/api/v1/services/shop-api/ops")
	var ops []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ops)
	if len(ops) < 3 || ops[0]["route_source"] == nil {
		t.Errorf("ops: %s", rec.Body)
	}
	if rec = get(t, op, "GET", "/api/v1/services/none/ops"); rec.Code != 404 {
		t.Errorf("unknown service ops: %d", rec.Code)
	}
	rec = get(t, op, "GET", "/api/v1/gaps")
	var gaps []contract.Gap
	if err := json.Unmarshal(rec.Body.Bytes(), &gaps); err != nil || rec.Code != 200 {
		t.Fatal(err, rec.Code)
	}
	kinds := map[string]bool{}
	for _, g := range gaps {
		kinds[g.Kind] = true
		if strings.Contains(g.Detail, "tk1:") {
			t.Errorf("gap detail with a token: %s", g.Detail)
		}
	}
	if !kinds["status-unseen"] {
		t.Errorf("expected status-unseen gaps: %+v", gaps)
	}

	// Forced snapshot (operator only).
	if rec := get(t, asRoles(api, auth.RoleAuditor), "POST", "/api/v1/contracts/shop-api/snapshots"); rec.Code != 403 {
		t.Errorf("auditor cannot snapshot: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	body := strings.NewReader(`{"from":"` + day1.Format(time.RFC3339) + `","to":"` + day2.Format(time.RFC3339) + `"}`)
	req := httptest.NewRequest("POST", "/api/v1/contracts/shop-api/snapshots", body)
	req.Header.Set("Content-Type", "application/json")
	op.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("forced snapshot: %d %s", rec.Code, rec.Body)
	}
}

func TestLiveContractWithoutSnapshot(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 200, contracttest.Variant{})
	h.Wait()
	eng, _ := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy)})
	api := asRoles(contract.Handler(contract.APIDeps{Engine: eng}), auth.RoleOperator)
	rec := get(t, api, "GET", "/api/v1/contracts/shop-api")
	if rec.Code != 200 || rec.Header().Get("X-TT-Snapshot") != "" {
		t.Fatalf("live contract: %d", rec.Code)
	}
}

func TestLastCompletedWindow(t *testing.T) {
	h := contracttest.New(t)
	eng, _ := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store})
	w := eng.LastCompletedWindow(time.Date(2026, 10, 20, 0, 3, 0, 0, time.UTC))
	if !w.From.Equal(time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)) || !w.To.Equal(time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("within grace, previous day still current: %+v", w)
	}
	w = eng.LastCompletedWindow(time.Date(2026, 10, 20, 0, 6, 0, 0, time.UTC))
	if !w.To.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("after grace: %+v", w)
	}
}
