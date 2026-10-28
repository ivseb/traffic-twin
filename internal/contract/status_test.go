package contract_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
)

// Before its first snapshot a service says how far it is from a contract,
// and "update now" takes one over the last window up to now.
func TestContractStatusAndUpdateNow(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 200, contracttest.Variant{})
	h.Wait()
	now := day1.Add(20 * time.Hour)
	eng, _ := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy), Now: func() time.Time { return now }})
	op := asRoles(contract.Handler(contract.APIDeps{Engine: eng}), auth.RoleOperator)

	status := func() map[string]any {
		t.Helper()
		rec := get(t, op, "GET", "/api/v1/contracts/shop-api/status")
		var st map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil {
			t.Fatalf("status: %d %s", rec.Code, rec.Body)
		}
		return st
	}
	st := status()
	if st["calls"].(float64) <= 0 || st["operations"].(float64) <= 0 || st["min_calls"].(float64) != 20 || st["snapshot"] != nil {
		t.Fatalf("status before the snapshot: %v", st)
	}
	if next, _ := time.Parse(time.RFC3339, st["next_snapshot_at"].(string)); !next.After(now) {
		t.Fatalf("next snapshot %v is not after now", st["next_snapshot_at"])
	}
	if rec := get(t, op, "GET", "/api/v1/contracts/nobody/status"); rec.Code != 404 {
		t.Fatalf("unknown service: %d", rec.Code)
	}

	// The last completed window (the day before) has no events: "recent" does.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/contracts/shop-api/snapshots", strings.NewReader(`{"recent":true}`))
	req.Header.Set("Content-Type", "application/json")
	op.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("update now: %d %s", rec.Code, rec.Body)
	}
	if st := status(); st["snapshot"] == nil {
		t.Fatalf("status after the snapshot: %v", st)
	}
}
