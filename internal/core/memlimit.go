package core

import (
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// Memory guard rails.
//
// tt-core usually runs in a container, an LXC or a systemd unit with a hard
// memory limit (e.g. a 4 GiB LXC container). The Go runtime does not read that
// limit: by default the heap may grow to twice the live data before a
// collection, and a mining run that holds millions of events in memory got
// the whole process (intake included) killed by the kernel instead of
// slowing down (a 4 GiB test core: 1.95 M events, 4 GB of RSS for one run).
// At startup the limit becomes the soft limit of the Go runtime (85 %,
// unless GOMEMLIMIT is set), sizes the miner window (miner.max_events is
// lowered to what fits) and the number of heavy jobs that may run at once
// (heavy.go).
//
// Where the limit is found, smallest first:
//   - the cgroup of the process and every parent up to the root of its
//     cgroup namespace, memory.max and memory.high (cgroup v2), or
//     memory.limit_in_bytes (v1): a systemd MemoryMax=/MemoryHigh=, a
//     Docker or Kubernetes limit;
//   - /proc/meminfo MemTotal: inside an LXC the limit is set above the
//     namespace (every cgroup file says "max") and lxcfs reports it there.
//     A unit with ProcSubset=pid does not see /proc/meminfo at all: hence
//     MemoryMax= in the unit (deploy/, test/lab/units);
//   - GOMEMLIMIT, when set, read back as 85 % of the limit.

// memLimitFrac is the share of the memory limit given to the Go heap (the
// rest: SQLite caches, allocated outside the Go heap, stacks, the binary).
const memLimitFrac = 0.85

// memoryLimit returns the memory available to the process in bytes and
// where it was found ("" and 0 when nowhere).
func memoryLimit() (uint64, string) { return memoryLimitAt("/") }

// memoryLimitAt is memoryLimit with the file system rooted at root (tests).
func memoryLimitAt(root string) (uint64, string) {
	var best uint64
	src := ""
	take := func(n uint64, from string) {
		if n > 0 && (best == 0 || n < best) {
			best, src = n, from
		}
	}
	cg, _ := os.ReadFile(filepath.Join(root, "proc/self/cgroup"))
	v2, v1 := cgroupPaths(string(cg))
	if v2 != "" || len(cg) == 0 {
		// cgroup v2: the own cgroup, then each parent up to the root.
		for _, d := range cgroupDirs(filepath.Join(root, "sys/fs/cgroup"), v2) {
			for _, f := range []string{"memory.max", "memory.high"} {
				if b, err := os.ReadFile(filepath.Join(d, f)); err == nil {
					take(parseMemoryLimit(string(b)), "cgroup")
				}
			}
		}
	}
	for _, d := range cgroupDirs(filepath.Join(root, "sys/fs/cgroup/memory"), v1) {
		if b, err := os.ReadFile(filepath.Join(d, "memory.limit_in_bytes")); err == nil {
			take(parseMemoryLimit(string(b)), "cgroup")
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "proc/meminfo")); err == nil {
		take(parseMemTotal(string(b)), "meminfo")
	}
	return best, src
}

// cgroupPaths reads /proc/self/cgroup: the path of the v2 hierarchy
// ("0::/system.slice/tt-core.service") and of the v1 memory controller.
func cgroupPaths(s string) (v2, v1 string) {
	for _, l := range strings.Split(s, "\n") {
		parts := strings.SplitN(strings.TrimSpace(l), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2 = parts[2]
		case strings.Contains(","+parts[1]+",", ",memory,"):
			v1 = parts[2]
		}
	}
	return v2, v1
}

// cgroupDirs lists base+path and each parent directory up to base. A path
// outside the namespace ("/../..") stops at base.
func cgroupDirs(base, path string) []string {
	p := filepath.Clean("/" + path)
	var out []string
	for {
		out = append(out, filepath.Join(base, p))
		if p == "/" {
			return out
		}
		p = filepath.Dir(p)
	}
}

// parseMemoryLimit reads a cgroup memory limit file ("max" or a byte count;
// cgroup v1 reports "no limit" as a huge number).
func parseMemoryLimit(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n >= 1<<62 {
		return 0
	}
	return n
}

// parseMemTotal reads the MemTotal line of /proc/meminfo (in kB).
func parseMemTotal(s string) uint64 {
	for _, l := range strings.Split(s, "\n") {
		rest, ok := strings.CutPrefix(l, "MemTotal:")
		if !ok {
			continue
		}
		if f := strings.Fields(rest); len(f) >= 1 {
			if n, err := strconv.ParseUint(f[0], 10, 64); err == nil {
				return n << 10
			}
		}
	}
	return 0
}

// applyMemoryLimit sets the soft memory limit of the runtime from the memory
// limit (override, else memoryLimit), unless GOMEMLIMIT is set. It returns
// the limit the core sizes its work with (0: unknown).
func applyMemoryLimit(log *slog.Logger, override uint64) uint64 {
	limit, src := override, "option"
	if limit == 0 {
		limit, src = memoryLimit()
	}
	if os.Getenv("GOMEMLIMIT") != "" {
		soft := debug.SetMemoryLimit(-1)
		if limit == 0 && soft > 0 && soft < math.MaxInt64 {
			limit, src = uint64(float64(soft)/memLimitFrac), "GOMEMLIMIT"
		}
		if limit > 0 {
			log.Info("memory limit", "limit_mb", limit>>20, "source", src, "go_soft_limit_mb", soft>>20)
		}
	} else if limit > 0 {
		soft := uint64(float64(limit) * memLimitFrac)
		debug.SetMemoryLimit(int64(soft))
		log.Info("memory limit", "limit_mb", limit>>20, "source", src, "go_soft_limit_mb", soft>>20)
	}
	if limit == 0 {
		log.Warn("memory limit unknown: heavy jobs are sized for the defaults; set MemoryMax= in the systemd unit, a container limit or GOMEMLIMIT (docs/OPERATIONS.md 2)")
	}
	return limit
}
