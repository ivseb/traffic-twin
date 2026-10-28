package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBudgetsCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, []byte(`{"_doc": "x",
		"default": {"class_p95_ms": {"list": 200}, "exempt": {"slow": "other work"}, "job_seconds": {"j": 1},
			"job_detail_max": {"j.stall": 10, "a.b.lag": 1}, "job_detail_min": {"j.rate": 100}},
		"full": {"class_p95_ms": {"list": 300}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := loadBudgets(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &Report{
		Endpoints: []*EndpointStats{
			{Name: "ok", Class: "list", Status: 200, P95: 150},
			{Name: "over", Class: "list", Status: 200, P95: 250},
			{Name: "slow", Class: "list", Status: 200, P95: 9000},
			{Name: "broken", Class: "list", Status: 500, P95: 1},
		},
		Jobs: []*JobStats{{Name: "j", OK: true, Seconds: 2, Detail: map[string]any{"stall": int64(20), "rate": 50.0}},
			{Name: "a.b", OK: true, Detail: map[string]any{"lag": 3.0}}},
	}
	v := strings.Join(b.check(r), "\n")
	for _, want := range []string{"endpoint over p95 250.0 ms > 200 ms", "endpoint broken answered 500", "job j took 2.00 s > 1.0 s",
		"job j stall = 20.0 > 10.0", "job j rate = 50.0 < 100.0", "job a.b lag = 3.0 > 1.0"} {
		if !strings.Contains(v, want) {
			t.Errorf("missing %q in:\n%s", want, v)
		}
	}
	if strings.Contains(v, "slow") || strings.Contains(v, "endpoint ok") {
		t.Errorf("exempt or good endpoint reported:\n%s", v)
	}
	t.Setenv("TTPERF_BUDGET_PROFILE", "full")
	b, _ = loadBudgets(p)
	if v := strings.Join(b.check(r), "\n"); strings.Contains(v, "endpoint over") {
		t.Errorf("profile full allows 300 ms:\n%s", v)
	}
}

func TestPlanFlagsAndNormalize(t *testing.T) {
	f := planFlags([]string{"SCAN intake_events", "SEARCH t USING INDEX i (a=?)", "USE TEMP B-TREE FOR ORDER BY", "SCAN x USING COVERING INDEX y"})
	if len(f) != 2 || !strings.HasPrefix(f[0], "full-scan") || !strings.HasPrefix(f[1], "temp-sort") {
		t.Fatalf("flags %v", f)
	}
	if got := normalize("INSERT INTO t (a) VALUES (?,?,?,?,?),(?,?,?,?,?)"); got != "INSERT INTO t (a) VALUES (?,?,?,?,?),..." {
		t.Fatalf("normalize: %q", got)
	}
	if got := normalize("SELECT  a\n\t FROM t"); got != "SELECT a FROM t" {
		t.Fatalf("normalize: %q", got)
	}
}
