package contract_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
	"github.com/ivseb/traffic-twin/internal/groupscope"
)

// twoTeams stores the demo traffic of team "shop" (source src-demo1) and a
// copy of its outbound calls made by team "pizza" (source src-team-b) to
// the same external service name, on another operation (/v1/charges): two
// teams calling the same host:port.
func twoTeams(t *testing.T) (*contracttest.Harness, string) {
	t.Helper()
	h := contracttest.New(t)
	h.DemoDay(day1, 300, contracttest.Variant{})
	h.Wait()
	ctx := context.Background()
	var ext string
	if err := h.DB.QueryRowContext(ctx, `SELECT service FROM intake_events WHERE dir = 1 LIMIT 1`).Scan(&ext); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.ExecContext(ctx, `INSERT INTO intake_events (received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op,
		route_source, status, net_error, latency_ms, subject, trace_id, span_id, parent_span_id, body)
		SELECT received_ms, ts_ms, 'src-team-b', policy_id, policy_version, dir, service, replace(op, '/v1/shipments', '/v1/charges'),
		route_source, status, net_error, latency_ms, subject, NULL, span_id, parent_span_id,
		CAST(replace(CAST(body AS TEXT), '/v1/shipments', '/v1/charges') AS BLOB)
		FROM intake_events WHERE dir = 1 AND service = ?`, ext); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.ExecContext(ctx, `INSERT INTO intake_agg (service, op, status, source_id, policy_id, dir, n, first_ms, last_ms)
		SELECT service, op, coalesce(status, 0), source_id, policy_id, dir, count(*), min(ts_ms), max(ts_ms)
		FROM intake_events WHERE source_id = 'src-team-b' GROUP BY service, op, coalesce(status, 0), source_id, policy_id, dir`); err != nil {
		t.Fatal(err)
	}
	return h, ext
}

var teams = groupscope.Func(func(context.Context) (map[string]string, error) {
	return map[string]string{"src-demo1": "shop", "src-team-b": "pizza"}, nil
})

func TestTwoGroupsSameHostStaySeparate(t *testing.T) {
	h, ext := twoTeams(t)
	now := day1.Add(72 * time.Hour)
	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy),
		Groups: teams, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	snaps, err := eng.SnapshotWindow(ctx, contract.Window{From: day1, To: day1.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string][]string{}
	for _, s := range snaps {
		if s.Service != ext {
			continue
		}
		for _, o := range s.Contract.Ops {
			ops[s.Group] = append(ops[s.Group], o.Key)
		}
	}
	has := func(group, path string) bool {
		for _, k := range ops[group] {
			if strings.Contains(k, path) {
				return true
			}
		}
		return false
	}
	if !has("shop", "/v1/shipments") || has("shop", "/v1/charges") {
		t.Errorf("shop contract of %s mixes the other team's calls: %v", ext, ops["shop"])
	}
	if !has("pizza", "/v1/charges") || has("pizza", "/v1/shipments") {
		t.Errorf("pizza contract of %s mixes the other team's calls: %v", ext, ops["pizza"])
	}

	api := asRoles(contract.Handler(contract.APIDeps{Engine: eng}), auth.RoleOperator)
	type svc struct{ Service, Group string }
	var all, pizza []svc
	if rec := get(t, api, "GET", "/api/v1/services"); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &all) != nil {
		t.Fatalf("services: %d %s", rec.Code, rec.Body)
	}
	rows := 0
	for _, s := range all {
		if s.Service == ext {
			rows++
		}
	}
	if rows != 2 {
		t.Errorf("every group: %s should be one row per group, got %d (%v)", ext, rows, all)
	}
	if rec := get(t, api, "GET", "/api/v1/services?group=pizza"); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &pizza) != nil {
		t.Fatalf("services pizza: %d", rec.Code)
	}
	if len(pizza) != 1 || pizza[0].Service != ext || pizza[0].Group != "pizza" {
		t.Errorf("pizza services: %v (shop-api and the shop calls must not show)", pizza)
	}
	rec := get(t, api, "GET", "/api/v1/contracts/"+ext+"?group=shop")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "/v1/charges") || !strings.Contains(rec.Body.String(), "/v1/shipments") {
		t.Errorf("shop contract: %d, has charges=%v", rec.Code, strings.Contains(rec.Body.String(), "/v1/charges"))
	}
	rec = get(t, api, "GET", "/api/v1/contracts/"+ext+"?group=pizza")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/v1/charges") || strings.Contains(rec.Body.String(), "/v1/shipments") {
		t.Errorf("pizza contract: %d", rec.Code)
	}
	var infos []contract.SnapshotInfo
	if rec := get(t, api, "GET", "/api/v1/contracts?group=pizza"); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &infos) != nil {
		t.Fatalf("contracts pizza: %d", rec.Code)
	}
	for _, i := range infos {
		if i.Group != "pizza" {
			t.Errorf("contracts?group=pizza lists %s of %q", i.Service, i.Group)
		}
	}
	if rec := get(t, api, "GET", "/api/v1/contracts/"+ext+"/status?group=pizza"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"group":"pizza"`) {
		t.Errorf("status pizza: %d %s", rec.Code, rec.Body)
	}
	var gaps []contract.Gap
	if rec := get(t, api, "GET", "/api/v1/gaps?group=pizza"); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &gaps) != nil {
		t.Fatalf("gaps: %d", rec.Code)
	}
	for _, g := range gaps {
		if g.Group != "pizza" {
			t.Errorf("gaps?group=pizza has a gap of %s/%q", g.Service, g.Group)
		}
	}
	// Live (worlds, packs): one group's traffic only.
	cs, err := eng.LiveIn(ctx, contract.Window{From: day1, To: day1.Add(24 * time.Hour)}, "pizza")
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Service != ext || cs[0].Group != "pizza" {
		t.Errorf("live contracts of pizza: %d", len(cs))
	}
}
