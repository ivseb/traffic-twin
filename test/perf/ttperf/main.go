// Command ttperf is the large-dataset performance harness of tt-core.
//
// It builds a synthetic but realistic tt-core database (real demo traffic
// sanitized by a real source under a policy signed by a real keyguard, then
// replicated in bulk across services, host patterns, sources and time), boots
// tt-core on it and measures every GET endpoint of the admin API and every
// background job, with the SQL statements traced and explained. The report
// (JSON and Markdown) lists p50/p95/max per endpoint, the duration and memory
// peak of each job, the database growth and the query plans; with -budgets
// the run fails when a budget is exceeded.
//
//	go run ./test/perf/ttperf -scale ci -budgets test/perf/budgets.json
//	go run ./test/perf/ttperf -scale full -dir /big/disk/ttperf -keep
//
// It is a test tool, not part of the product: every value is invented
// (demo e-commerce and carrier, *.example hosts).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

// Scale is the size of the synthetic dataset and of the load.
type Scale struct {
	Name         string `json:"name"`
	Events       int    `json:"events"`
	Days         int    `json:"days"` // span of the events, ending now
	Services     int    `json:"services"`
	HostPatterns int    `json:"host_patterns"`
	Sources      int    `json:"sources"`
	Rules        int    `json:"rules"`
	SnapshotDays int    `json:"snapshot_days"`
	Audit        int    `json:"audit_entries"`
	Alerts       int    `json:"alerts"`
	Deliveries   int    `json:"deliveries"`
	Worlds       int    `json:"worlds"`
	Packs        int    `json:"packs"`
	Iterations   int    `json:"iterations"` // requests per endpoint
	MockSessions int    `json:"mock_sessions"`
	KGTokens     int    `json:"keyguard_tokens"`
	Customers    int    `json:"sim_customers"`
}

var scales = map[string]Scale{
	// full: the dataset of the audit (about 10 GB on disk).
	"full": {Name: "full", Events: 10_000_000, Days: 30, Services: 50, HostPatterns: 2000, Sources: 200, Rules: 100,
		SnapshotDays: 365, Audit: 1_000_000, Alerts: 5000, Deliveries: 100_000, Worlds: 200, Packs: 50, Iterations: 15,
		MockSessions: 1000, KGTokens: 5_000_000, Customers: 2000},
	// ci: the reduced dataset of the weekly job (a few minutes on a CI runner).
	"ci": {Name: "ci", Events: 300_000, Days: 30, Services: 50, HostPatterns: 2000, Sources: 200, Rules: 100,
		SnapshotDays: 365, Audit: 100_000, Alerts: 2000, Deliveries: 20_000, Worlds: 40, Packs: 20, Iterations: 10,
		MockSessions: 200, KGTokens: 500_000, Customers: 800},
	// lab: the volume of a 4 GiB test core at the time of its OOM
	// (docs/PERFORMANCE.md 3.5): about 2 M events in a 48 h retention, mined as a whole.
	"lab": {Name: "lab", Events: 2_000_000, Days: 2, Services: 50, HostPatterns: 2000, Sources: 200, Rules: 100,
		SnapshotDays: 30, Audit: 100_000, Alerts: 2000, Deliveries: 20_000, Worlds: 10, Packs: 5, Iterations: 5,
		MockSessions: 50, KGTokens: 500_000, Customers: 800},
	// smoke: seconds, to check the harness itself.
	"smoke": {Name: "smoke", Events: 30_000, Days: 30, Services: 10, HostPatterns: 100, Sources: 20, Rules: 30,
		SnapshotDays: 30, Audit: 5000, Alerts: 200, Deliveries: 1000, Worlds: 5, Packs: 3, Iterations: 3,
		MockSessions: 20, KGTokens: 50_000, Customers: 300},
}

func main() {
	scaleName := flag.String("scale", "ci", "dataset size: smoke, ci, lab or full")
	dir := flag.String("dir", "", "working directory (default: a temporary one, removed unless -keep)")
	keep := flag.Bool("keep", false, "keep the working directory (database included)")
	out := flag.String("out", "", "report path without extension (default <dir>/report): writes .json and .md")
	budgets := flag.String("budgets", "", "budget file (JSON): exit 1 when a budget is exceeded")
	events := flag.Int("events", 0, "override the number of events")
	label := flag.String("label", "", "free label stored in the report (e.g. before/after)")
	skip := flag.String("skip", "", "comma-separated endpoint names not to measure (e.g. services,services.ops,hosts on the full dataset: minutes per call)")
	only := flag.String("only", "", "comma-separated phases to run after the dataset: http,jobs,memory,purge,keyguard,mock (default all)")
	check := flag.String("check", "", "only check the budgets against an existing report (JSON) and exit")
	memLimit := flag.String("memlimit", "", "memory of the emulated host (e.g. 4GiB, the lab core): the core sizes its jobs and the Go soft limit from it")
	minerMax := flag.Int("miner-max-events", 0, "miner.max_events of the core (0: automatic; the lab sets 5000000)")
	memScen := flag.String("mem", "", "comma-separated scenarios of the memory phase: one,two,mixed (default all)")
	flag.Parse()
	if *check != "" {
		os.Exit(checkOnly(*check, *budgets))
	}

	sc, ok := scales[*scaleName]
	if !ok {
		fatal(fmt.Errorf("unknown scale %q", *scaleName))
	}
	if *events > 0 {
		sc.Events = *events
	}
	wd := *dir
	if wd == "" {
		var err error
		if wd, err = os.MkdirTemp("", "ttperf"); err != nil {
			fatal(err)
		}
		if !*keep {
			defer os.RemoveAll(wd)
		}
	}
	if err := os.MkdirAll(wd, 0o700); err != nil {
		fatal(err)
	}
	if err := registerTracedDriver(); err != nil {
		fatal(err)
	}
	store.DriverName = tracedDriver

	rep := &Report{Label: *label, Scale: sc, Started: time.Now().UTC(), GoVersion: runtime.Version(),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU()}
	h := &harness{sc: sc, dir: wd, rep: rep, phases: parsePhases(*only), skip: map[string]bool{}, minerMaxEvents: *minerMax}
	if *memScen != "" {
		h.memScenarios = map[string]bool{}
		for _, n := range splitComma(*memScen) {
			h.memScenarios[n] = true
		}
	}
	if *memLimit != "" {
		n, err := parseBytes(*memLimit)
		if err != nil {
			fatal(err)
		}
		h.memLimit = n
		rep.MemLimitMB = float64(n) / (1 << 20)
	}
	for _, n := range splitComma(*skip) {
		h.skip[n] = true
	}
	ctx := context.Background()
	err := h.run(ctx)
	rep.Finished = time.Now().UTC()
	rep.Queries = trace.snapshot()
	if err != nil {
		rep.Error = err.Error()
	}
	base := *out
	if base == "" {
		base = filepath.Join(wd, "report")
	}
	if werr := writeReport(rep, base); werr != nil {
		fmt.Fprintln(os.Stderr, "ttperf: report:", werr)
	}
	fmt.Printf("report: %s.md, %s.json\n", base, base)
	if err != nil {
		fatal(err)
	}
	if *budgets != "" {
		b, err := loadBudgets(*budgets)
		if err != nil {
			fatal(err)
		}
		violations := b.check(rep)
		vb, _ := json.MarshalIndent(violations, "", "  ")
		_ = os.WriteFile(base+".violations.json", vb, 0o600)
		if len(violations) > 0 {
			fmt.Fprintf(os.Stderr, "ttperf: %d budget(s) exceeded:\n", len(violations))
			for _, v := range violations {
				fmt.Fprintln(os.Stderr, "  -", v)
			}
			os.Exit(1)
		}
		fmt.Println("all budgets met")
	}
}

// checkOnly evaluates the budgets on a saved report: 0 met, 1 exceeded.
func checkOnly(report, budgets string) int {
	if budgets == "" {
		fatal(fmt.Errorf("-check needs -budgets"))
	}
	b, err := os.ReadFile(report)
	if err != nil {
		fatal(err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		fatal(err)
	}
	bs, err := loadBudgets(budgets)
	if err != nil {
		fatal(err)
	}
	v := bs.check(&r)
	for _, x := range v {
		fmt.Println("  -", x)
	}
	if len(v) > 0 {
		fmt.Printf("%d budget(s) exceeded\n", len(v))
		return 1
	}
	fmt.Println("all budgets met")
	return 0
}

func parsePhases(s string) map[string]bool {
	m := map[string]bool{}
	if s == "" {
		for _, p := range []string{"http", "jobs", "memory", "purge", "keyguard", "mock"} {
			m[p] = true
		}
		return m
	}
	for _, p := range splitComma(s) {
		m[p] = true
	}
	return m
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ttperf:", err)
	os.Exit(2)
}

// parseBytes reads a size: a byte count or a number with KiB, MiB, GiB.
func parseBytes(s string) (uint64, error) {
	mult := uint64(1)
	for _, u := range []struct {
		suf string
		m   uint64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSuffix(s, u.suf), u.m
			break
		}
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: want a byte count or KiB/MiB/GiB", s)
	}
	return n * mult, nil
}
