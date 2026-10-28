package core_test

import (
	"os"
	"testing"
	"time"
)

// checkBudget fails the test when took exceeds the latency budget. On shared CI
// runners (CI is set by GitHub Actions and most CI systems) timings vary by 2-3x
// between runs of the same commit, so an overrun is only logged there; the
// budgets are enforced on local runs, and `make perf` has its own.
func checkBudget(t *testing.T, what string, took, budget time.Duration, events int) {
	t.Helper()
	if took <= budget {
		return
	}
	if os.Getenv("CI") != "" {
		t.Logf("WARNING: %s took %s on %d events (budget %s, not enforced on CI)", what, took, events, budget)
		return
	}
	t.Errorf("%s took %s on %d events (budget %s)", what, took, events, budget)
}
