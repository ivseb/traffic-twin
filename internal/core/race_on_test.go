//go:build race

package core_test

// raceEnabled reports whether the tests run under the race detector, which slows
// SQLite and the HTTP stack by 5-10x: latency budgets are not meaningful there.
const raceEnabled = true
