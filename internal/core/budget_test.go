package core_test

import (
	"os"
	"time"
)

// budget scales a latency budget for shared CI runners (CI is set by GitHub
// Actions and most CI systems), which are 1.5-2x slower than the reference
// hardware the budgets were measured on. `make perf` has its own budgets.
func budget(d time.Duration) time.Duration {
	if os.Getenv("CI") != "" {
		return 2 * d
	}
	return d
}
