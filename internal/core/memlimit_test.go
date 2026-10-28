package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseMemoryLimit(t *testing.T) {
	for in, want := range map[string]uint64{
		"max\n":                 0,
		"4294967296\n":          4 << 30,
		"9223372036854771712\n": 0, // cgroup v1 "no limit"
		"":                      0,
		"garbage":               0,
	} {
		if got := parseMemoryLimit(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}

func TestParseMemTotal(t *testing.T) {
	if got := parseMemTotal("MemTotal:        4194304 kB\nMemFree: 1 kB\n"); got != 4<<30 {
		t.Fatalf("MemTotal: %d", got)
	}
	if got := parseMemTotal("nothing"); got != 0 {
		t.Fatalf("no MemTotal: %d", got)
	}
}

// writeFS writes files (relative path -> content) under a temporary root.
func writeFS(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, s := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Where the limit is found. OOM on a 4 GiB test core: tt-core in a systemd
// unit with ProcSubset=pid inside a 4 GiB LXC saw "max" in every cgroup
// file and no /proc/meminfo, so no limit at all (no GOMEMLIMIT, the miner
// window not narrowed).
func TestMemoryLimitAt(t *testing.T) {
	const svc = "sys/fs/cgroup/system.slice/tt-core.service/"
	for name, tc := range map[string]struct {
		files map[string]string
		want  uint64
		src   string
	}{
		"lxc unit without MemoryMax, ProcSubset=pid": {map[string]string{
			"proc/self/cgroup":                      "0::/system.slice/tt-core.service\n",
			"sys/fs/cgroup/memory.max":              "max\n",
			"sys/fs/cgroup/system.slice/memory.max": "max\n",
			svc + "memory.max":                      "max\n",
		}, 0, ""},
		"lxc unit without MemoryMax, meminfo from lxcfs": {map[string]string{
			"proc/self/cgroup":         "0::/system.slice/tt-core.service\n",
			"sys/fs/cgroup/memory.max": "max\n",
			"proc/meminfo":             "MemTotal:        4194304 kB\n",
		}, 4 << 30, "meminfo"},
		"lxc unit with MemoryMax and MemoryHigh": {map[string]string{
			"proc/self/cgroup":         "0::/system.slice/tt-core.service\n",
			"sys/fs/cgroup/memory.max": "max\n",
			svc + "memory.max":         "3758096384\n",
			svc + "memory.high":        "3221225472\n",
			"proc/meminfo":             "MemTotal:        4194304 kB\n",
		}, 3 << 30, "cgroup"},
		"limit on a parent slice": {map[string]string{
			"proc/self/cgroup":                                  "0::/tt.slice/tt-core.service\n",
			"sys/fs/cgroup/tt.slice/memory.max":                 "2147483648\n",
			"sys/fs/cgroup/tt.slice/tt-core.service/memory.max": "max\n",
		}, 2 << 30, "cgroup"},
		"docker: the namespace root": {map[string]string{
			"proc/self/cgroup":         "0::/\n",
			"sys/fs/cgroup/memory.max": "1073741824\n",
		}, 1 << 30, "cgroup"},
		"cgroup v1": {map[string]string{
			"proc/self/cgroup": "12:memory:/docker/abc\n11:cpu,cpuacct:/docker/abc\n",
			"sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes": "536870912\n",
			"sys/fs/cgroup/memory/memory.limit_in_bytes":            "9223372036854771712\n",
		}, 512 << 20, "cgroup"},
		"path outside the namespace": {map[string]string{
			"proc/self/cgroup":         "0::/../../lxc/9102\n",
			"sys/fs/cgroup/memory.max": "805306368\n",
		}, 768 << 20, "cgroup"},
	} {
		got, src := memoryLimitAt(writeFS(t, tc.files))
		if got != tc.want || src != tc.src {
			t.Errorf("%s: %d MB from %q, want %d MB from %q", name, got>>20, src, tc.want>>20, tc.src)
		}
	}
}

// The mining window follows the memory limit: half of it for the one heavy
// job of a 4 GiB host, at about 1.5 KB per event (test/perf memory phase).
func TestAutoMinerEvents(t *testing.T) {
	for _, tc := range []struct {
		limit uint64
		slots int
		want  int
	}{
		{0, 1, 1_000_000},
		{4 << 30, 1, 1_431_655},
		{3 << 30, 1, 1_073_741},
		{8 << 30, 1, 2_863_311},
		{16 << 30, 2, 2_863_311},
		{512 << 20, 1, 178_956},
		{128 << 20, 1, 100_000},
		{1 << 40, 4, 5_000_000},
	} {
		if got := autoMinerEvents(tc.limit, tc.slots); got != tc.want {
			t.Errorf("limit %d MB, %d slots: %d, want %d", tc.limit>>20, tc.slots, got, tc.want)
		}
	}
}

// An explicit miner.max_events larger than what fits is lowered (the lab
// set 5 M on 4 GiB); without a known limit it is kept.
func TestSizeMinerWindow(t *testing.T) {
	c := longJobCore(t, time.Second)
	c.cfg.Miner.MaxEvents = 5_000_000
	c.memLimit = 4 << 30
	if got := c.sizeMinerWindow(); got != 1_431_655 {
		t.Fatalf("5M on 4 GiB: %d", got)
	}
	c.cfg.Miner.MaxEvents = 500_000
	if got := c.sizeMinerWindow(); got != 500_000 {
		t.Fatalf("500k on 4 GiB: %d", got)
	}
	c.cfg.Miner.MaxEvents, c.memLimit = 5_000_000, 0
	if got := c.sizeMinerWindow(); got != 5_000_000 {
		t.Fatalf("5M, unknown limit: %d", got)
	}
	c.cfg.Miner.MaxEvents = 0
	if got := c.sizeMinerWindow(); got != 1_000_000 {
		t.Fatalf("auto, unknown limit: %d", got)
	}
}
