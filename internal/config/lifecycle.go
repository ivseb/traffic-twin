package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Data lifecycle configuration (docs/DATA_LIFECYCLE.md): the tiers of every
// dataset that grows, the size budget of the database and its guard rails.

// ByteSize is a size in bytes. In YAML and in the environment it is an
// integer or a number with a unit: KB, MB, GB, TB (powers of 1000) or KiB,
// MiB, GiB, TiB (powers of 1024), e.g. "20GiB".
type ByteSize int64

// ParseByteSize parses "123", "500MB", "20GiB".
func ParseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}, {"B", 1}}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f*float64(mult) > 1<<62 {
		return 0, errors.New("invalid size (use bytes or a unit: MB, GB, MiB, GiB, ...)")
	}
	return ByteSize(f * float64(mult)), nil
}

// UnmarshalYAML accepts an integer or a string with a unit.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %v", n.Line, err)
	}
	*b = v
	return nil
}

// String formats with a binary unit.
func (b ByteSize) String() string {
	for _, u := range []struct {
		s string
		m int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if int64(b) >= u.m && int64(b)%(u.m/1024) == 0 {
			return strconv.FormatFloat(float64(b)/float64(u.m), 'f', -1, 64) + u.s
		}
	}
	return strconv.FormatInt(int64(b), 10)
}

// Datasets are the names accepted by storage.quotas (and reported by
// GET /api/v1/store/usage).
var Datasets = []string{"events", "tokens", "rollups", "aggregates", "sketches", "snapshots", "drift", "deliveries",
	"miner", "worlds", "packs", "audit", "fleet", "auth", "other"}

// Rollups: the time-bucketed aggregates that outlive the raw events.
type Rollups struct {
	// Hourly keeps hourly buckets this long, then merges them into days.
	Hourly time.Duration `yaml:"hourly"`
	// Daily keeps daily buckets this long, then merges them into months
	// (kept forever).
	Daily time.Duration `yaml:"daily"`
}

// SnapshotRetention compacts the contract history.
type SnapshotRetention struct {
	// KeepAll keeps every snapshot of this recent past.
	KeepAll time.Duration `yaml:"keep_all"`
	// Weekly keeps one snapshot per week up to this age; older: one per
	// month. Snapshots referenced by drift alerts or published packs are
	// always kept; contract.keep_snapshots stays the hard cap.
	Weekly time.Duration `yaml:"weekly"`
}

// AuditRetention archives old segments of the audit log.
type AuditRetention struct {
	// ArchiveAfter: entries older than this leave the database as signed
	// archive segments (never silently). 0 disables archiving: the log
	// then stays whole in the database.
	ArchiveAfter time.Duration `yaml:"archive_after"`
	// ArchiveDir receives the segments (default "audit-archive" next to
	// the database). Put it on WORM storage or copy it off the host.
	ArchiveDir string `yaml:"archive_dir"`
	// SegmentEntries bounds one segment (segments are also cut at month
	// boundaries).
	SegmentEntries int `yaml:"segment_entries"`
}

// PackRetention: published packs are always kept.
type PackRetention struct {
	// KeepBuilt unpublished packs keep their archive; older or expired
	// ones lose it (rebuild to publish).
	KeepBuilt int `yaml:"keep_built"`
	// Unpublished rows (signed or gate-failed) are deleted after this.
	Unpublished time.Duration `yaml:"unpublished"`
}

// WorldRetention: worlds referenced by packs are always kept.
type WorldRetention struct {
	Keep int           `yaml:"keep"`
	TTL  time.Duration `yaml:"ttl"`
}

// FleetRetention cleans enrollment leftovers.
type FleetRetention struct {
	// RevokedSources: a revoked source not seen for this long is archived
	// (audit entry fleet.source.archive, then deleted).
	RevokedSources time.Duration `yaml:"revoked_sources"`
	ExpiredTokens  time.Duration `yaml:"expired_tokens"`
	ExpiredCerts   time.Duration `yaml:"expired_certs"`
}

func defaultLifecycle(c *Config) {
	c.Storage.HighWatermarkPct, c.Storage.CriticalWatermarkPct = 80, 90
	c.Storage.MinEventsRetention = 24 * time.Hour
	r := &c.Retention
	r.Rollups = Rollups{Hourly: 30 * 24 * time.Hour, Daily: 365 * 24 * time.Hour}
	r.Snapshots = SnapshotRetention{KeepAll: 30 * 24 * time.Hour, Weekly: 180 * 24 * time.Hour}
	r.Audit = AuditRetention{ArchiveAfter: 180 * 24 * time.Hour, SegmentEntries: 50_000}
	r.Deliveries = 30 * 24 * time.Hour
	r.ResolvedAlerts = 365 * 24 * time.Hour
	r.MinerRuns = 90 * 24 * time.Hour
	r.KeepMinerRuns = 50
	r.Packs = PackRetention{KeepBuilt: 20, Unpublished: 180 * 24 * time.Hour}
	r.Worlds = WorldRetention{Keep: 20, TTL: 30 * 24 * time.Hour}
	r.Fleet = FleetRetention{RevokedSources: 90 * 24 * time.Hour, ExpiredTokens: 30 * 24 * time.Hour, ExpiredCerts: 30 * 24 * time.Hour}
	r.ReleasedQuarantines = 365 * 24 * time.Hour
}

func validateLifecycle(c *Config, add func(string, string, ...any)) {
	const day = 24 * time.Hour
	durIn := func(key string, d, lo, hi time.Duration) {
		if d < lo || d > hi {
			add(key, "must be between %s and %s", lo, hi)
		}
	}
	optIn := func(key string, d, lo, hi time.Duration) {
		if d != 0 {
			durIn(key, d, lo, hi)
		}
	}
	s := c.Storage
	if s.MaxBytes != 0 && s.MaxBytes < 64<<20 {
		add("storage.max_bytes", "must be 0 (no budget) or at least 64MiB")
	}
	if s.HighWatermarkPct < 50 || s.CriticalWatermarkPct <= s.HighWatermarkPct || s.CriticalWatermarkPct > 99 {
		add("storage.high_watermark_pct", "need 50 <= high_watermark_pct < critical_watermark_pct <= 99")
	}
	for k, v := range s.Quotas {
		if !contains(Datasets, k) {
			add("storage.quotas."+k, "unknown dataset (one of %s)", strings.Join(Datasets, ", "))
		}
		if v < 1<<20 {
			add("storage.quotas."+k, "must be at least 1MiB")
		}
	}
	durIn("storage.min_events_retention", s.MinEventsRetention, time.Hour, 365*day)
	if s.MinEventsRetention > c.Retention.Events {
		add("storage.min_events_retention", "must not exceed retention.events")
	}
	r := c.Retention
	durIn("retention.rollups.hourly", r.Rollups.Hourly, day, 365*day)
	durIn("retention.rollups.daily", r.Rollups.Daily, r.Rollups.Hourly, 10*365*day)
	durIn("retention.snapshots.keep_all", r.Snapshots.KeepAll, day, 365*day)
	durIn("retention.snapshots.weekly", r.Snapshots.Weekly, r.Snapshots.KeepAll, 10*365*day)
	optIn("retention.audit.archive_after", r.Audit.ArchiveAfter, 30*day, 100*365*day)
	if r.Audit.SegmentEntries < 1000 || r.Audit.SegmentEntries > 1_000_000 {
		add("retention.audit.segment_entries", "must be between 1000 and 1000000")
	}
	optIn("retention.deliveries", r.Deliveries, day, 10*365*day)
	optIn("retention.resolved_alerts", r.ResolvedAlerts, 7*day, 100*365*day)
	optIn("retention.miner_runs", r.MinerRuns, day, 10*365*day)
	if r.KeepMinerRuns < 1 || r.KeepMinerRuns > 100_000 {
		add("retention.keep_miner_runs", "must be between 1 and 100000")
	}
	if r.Packs.KeepBuilt < 1 || r.Packs.KeepBuilt > 10_000 {
		add("retention.packs.keep_built", "must be between 1 and 10000")
	}
	// Pack and world ids count the rows of their day: never delete rows of
	// the current day.
	optIn("retention.packs.unpublished", r.Packs.Unpublished, 7*day, 100*365*day)
	if r.Worlds.Keep < 1 || r.Worlds.Keep > 10_000 {
		add("retention.worlds.keep", "must be between 1 and 10000")
	}
	durIn("retention.worlds.ttl", r.Worlds.TTL, 7*day, 100*365*day)
	optIn("retention.fleet.revoked_sources", r.Fleet.RevokedSources, c.Fleet.ClientCertTTL, 100*365*day)
	optIn("retention.fleet.expired_tokens", r.Fleet.ExpiredTokens, day, 100*365*day)
	optIn("retention.fleet.expired_certs", r.Fleet.ExpiredCerts, day, 100*365*day)
	optIn("retention.released_quarantines", r.ReleasedQuarantines, 7*day, 100*365*day)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
