package config

import (
	"strings"
	"testing"
	"time"
)

func TestByteSize(t *testing.T) {
	for in, want := range map[string]ByteSize{"0": 0, "1048576": 1 << 20, "20GiB": 20 << 30, "500MB": 500e6, "1.5 GiB": 3 << 29} {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "x", "-1GB", "1PB"} {
		if _, err := ParseByteSize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestLifecycleConfig(t *testing.T) {
	cfg := Default()
	cfg.Keyguard.URL = "unix:///tmp/kg.sock"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if cfg.Retention.Events != 7*24*time.Hour || cfg.Miner.Window != cfg.Retention.Events || cfg.Retention.Audit.ArchiveAfter == 0 {
		t.Fatalf("defaults: %+v", cfg.Retention)
	}
	y := `
storage:
  path: data/x.db
  max_bytes: 20GiB
  quotas: {events: 12GiB, nonsense: 1GiB}
retention:
  rollups: {hourly: 48h, daily: 24h}
  audit: {archive_after: 24h}
`
	c := Default()
	c.Keyguard.URL = "unix:///tmp/kg.sock"
	if err := Parse([]byte(y), &c); err != nil {
		t.Fatal(err)
	}
	if c.Storage.MaxBytes != 20<<30 || c.Storage.Quotas["events"] != 12<<30 {
		t.Fatalf("parsed %+v", c.Storage)
	}
	err := c.Validate()
	for _, want := range []string{"storage.quotas.nonsense", "retention.rollups.daily", "retention.audit.archive_after"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
	env := Default()
	env.Keyguard.URL = "unix:///tmp/kg.sock"
	if err := applyEnv(&env, []string{"TT_CORE_STORAGE_MAX_BYTES=2GiB", "TT_CORE_RETENTION_ROLLUPS_HOURLY=240h"}); err != nil {
		t.Fatal(err)
	}
	if env.Storage.MaxBytes != 2<<30 || env.Retention.Rollups.Hourly != 240*time.Hour {
		t.Fatalf("env: %+v", env.Storage)
	}
}
