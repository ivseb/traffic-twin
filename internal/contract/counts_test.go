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
)

func TestSnapshotChangeCountsAndGapFields(t *testing.T) {
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
	ctx := context.Background()
	for _, d := range []time.Time{day1, day2} {
		if _, err := eng.SnapshotWindow(ctx, contract.Window{From: d, To: d.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	op := asRoles(contract.Handler(contract.APIDeps{Engine: eng}), auth.RoleOperator)

	list := func() []contract.SnapshotInfo {
		rec := get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots")
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 2 {
			t.Fatalf("snapshots: %v %s", err, rec.Body)
		}
		if _, ok := out[0]["breaking"]; !ok {
			t.Fatalf("breaking missing: %s", rec.Body)
		}
		if _, ok := out[0]["non_breaking"]; !ok {
			t.Fatalf("non_breaking missing: %s", rec.Body)
		}
		var infos []contract.SnapshotInfo
		_ = json.Unmarshal(rec.Body.Bytes(), &infos)
		return infos
	}
	check := func(infos []contract.SnapshotInfo) {
		t.Helper()
		if infos[1].Breaking != 0 || infos[1].NonBreaking != 0 {
			t.Errorf("the first snapshot has nothing to compare to: %+v", infos[1])
		}
		d := get(t, op, "GET", "/api/v1/contracts/shipping-ext/snapshots/"+infos[0].SnapshotID+"?diff_against="+infos[1].SnapshotID)
		var diff contract.DiffResult
		_ = json.Unmarshal(d.Body.Bytes(), &diff)
		if diff.Breaking == 0 || infos[0].Breaking != diff.Breaking || infos[0].NonBreaking != diff.NonBreaking {
			t.Errorf("counts %d/%d, diff %d/%d", infos[0].Breaking, infos[0].NonBreaking, diff.Breaking, diff.NonBreaking)
		}
	}
	check(list())

	// Snapshots stored before the counts existed are filled on first read.
	if _, err := h.DB.ExecContext(ctx, `UPDATE contract_snapshots SET breaking = -1, non_breaking = -1`); err != nil {
		t.Fatal(err)
	}
	check(list())
	var br int
	if err := h.DB.QueryRowContext(ctx, `SELECT breaking FROM contract_snapshots WHERE service = 'shipping-ext' ORDER BY id DESC LIMIT 1`).Scan(&br); err != nil || br < 0 {
		t.Errorf("counts not stored: %d %v", br, err)
	}

	// Gaps: stable id, scope and threshold.
	gaps := func() []contract.Gap {
		rec := get(t, op, "GET", "/api/v1/gaps")
		var g []contract.Gap
		if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	g1, g2 := gaps(), gaps()
	if len(g1) == 0 || len(g1) != len(g2) {
		t.Fatalf("gaps: %d %d", len(g1), len(g2))
	}
	ids := map[string]bool{}
	for i, g := range g1 {
		if !strings.HasPrefix(g.ID, "gp-") || ids[g.ID] || g.ID != g2[i].ID {
			t.Errorf("id not stable and unique: %+v", g)
		}
		ids[g.ID] = true
		if g.Scope != contract.ScopeOp && g.Scope != contract.ScopeField {
			t.Errorf("scope: %+v", g)
		}
		if g.Kind == "few-samples" && g.Threshold != int64(contract.DefaultConfig().MinSamples) {
			t.Errorf("few-samples threshold: %+v", g)
		}
		if g.Kind == "status-unseen" && g.Scope != contract.ScopeOp {
			t.Errorf("status-unseen is about the operation: %+v", g)
		}
	}
}
