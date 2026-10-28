package drift_test

import (
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
	"github.com/ivseb/traffic-twin/internal/drift"
)

func win(from time.Time, hours int) contract.Window {
	return contract.Window{From: from, To: from.Add(time.Duration(hours) * time.Hour)}
}

// Usability test 5: eleven "compatible" alerts after a few manual "update
// the contract now": the contract only completed with more samples.
func TestQuietDropsResamplingNoise(t *testing.T) {
	day := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	nb := func(kind string, shift float64) contract.Change {
		return contract.Change{Kind: kind, Severity: contract.NonBreaking, Shift: shift}
	}
	br := func(kind string, shift float64) contract.Change {
		return contract.Change{Kind: kind, Severity: contract.Breaking, Shift: shift}
	}
	all := []contract.Change{nb("enum-added", 0), nb("required-changed", 0.02), nb("op-added", 0), br("type-changed", 0), br("required-changed", 0.02), nb("required-changed", 0.6)}
	kinds := func(cs []contract.Change) (out []string) {
		for _, c := range cs {
			s := c.Kind + "/" + c.Severity
			out = append(out, s)
		}
		return
	}

	// The same window twice, and a manual refresh that covers almost all of
	// the previous window: no non-breaking alert at all.
	for name, w := range map[string][2]contract.Window{
		"same window": {win(day, 24), win(day, 24)},
		"refresh":     {win(day, 24), win(day.Add(5*time.Minute), 24)},
		"half":        {win(day, 24), win(day.Add(12*time.Hour), 24)},
	} {
		got := kinds(drift.Quiet(w[0], w[1], all))
		if len(got) != 1 || got[0] != "type-changed/breaking" {
			t.Errorf("%s: %v", name, got)
		}
	}
	// Different windows: real changes stay, the tiny required flips go.
	got := kinds(drift.Quiet(win(day, 24), win(day.Add(24*time.Hour), 24), all))
	want := []string{"enum-added/non-breaking", "op-added/non-breaking", "type-changed/breaking", "required-changed/non-breaking"}
	if len(got) != len(want) {
		t.Fatalf("disjoint windows: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("disjoint windows: %v, want %v", got, want)
			break
		}
	}
}

// The overlapping refresh of a snapshot that shows changes raises only the
// breaking ones; the alerts carry the names and figures of their sentence
// (change_kind + params) so the console does not show English free text.
func TestOverlappingSnapshotRaisesNoCompatibleAlertsAndAlertsCarryParams(t *testing.T) {
	f := setup(t)
	day2 := day1.Add(24 * time.Hour)
	f.h.DemoDay(day1, 900, contracttest.Variant{})
	f.h.DemoDay(day2, 900, contracttest.Variant{EtaEpoch: true, CarrierBadGateway: 0.08})
	f.h.Wait()
	if _, err := f.eng.SnapshotWindow(f.ctx, contract.Window{From: day1, To: day1.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Half of the old window plus half of the new one: overlapping traffic.
	if _, err := f.eng.SnapshotWindow(f.ctx, contract.Window{From: day1.Add(12 * time.Hour), To: day2.Add(12 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	alerts, err := f.mgr.List(f.ctx, drift.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) == 0 {
		t.Fatal("the overlapping snapshot should still raise the breaking changes")
	}
	for _, a := range alerts {
		if a.Severity != contract.Breaking {
			t.Errorf("a non-breaking alert after an overlapping snapshot: %s %s %q", a.Service, a.ChangeKind, a.Change)
		}
		if a.ChangeKind == "" || len(a.Params) == 0 && a.ChangeKind != "op-removed" {
			t.Errorf("alert without structured text: %+v", a)
		}
	}
	// The disjoint pair of days (the existing scenario) has typed params.
	f2 := setup(t)
	f2.snapshotDays(t, contracttest.Variant{EtaEpoch: true, CarrierBadGateway: 0.08}, 900)
	al2, err := f2.mgr.List(f2.ctx, drift.ListFilter{Severity: "breaking"})
	if err != nil {
		t.Fatal(err)
	}
	var sawType, sawStatus bool
	for _, a := range al2 {
		switch a.ChangeKind {
		case "type-changed":
			sawType = a.Params["name"] == "eta" && a.Params["from"] != "" && a.Params["to"] == "integer"
		case "status-added":
			sawStatus = a.Params["status"] == "502" && a.Params["pct"] != ""
		}
	}
	if !sawType || !sawStatus {
		t.Errorf("params missing: type=%v status=%v in %+v", sawType, sawStatus, al2)
	}
}
