package core

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/fleet"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/lifecycle"
	"github.com/ivseb/traffic-twin/internal/packwriter"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/world"
)

// The data lifecycle of tt-core (docs/DATA_LIFECYCLE.md): one dataset per
// growing family of tables, each with its policy, run in this order by the
// maintenance job (internal/lifecycle) every retention.purge_interval.

const jobMaintenance = "store.maintenance"

const day = 24 * time.Hour

func days(d time.Duration) int64 { return int64(d / day) }

// auditArchiveDir is retention.audit.archive_dir or "audit-archive" next
// to the database.
func (c *Core) auditArchiveDir() string {
	if d := c.cfg.Retention.Audit.ArchiveDir; d != "" {
		return d
	}
	return filepath.Join(c.dataDir, "audit-archive")
}

var archiveKeyMu sync.Mutex

func (c *Core) archiveKey() (*audit.ArchiveKey, error) {
	archiveKeyMu.Lock()
	defer archiveKeyMu.Unlock()
	return audit.LoadOrCreateArchiveKey(filepath.Join(c.dataDir, "audit-archive.key"))
}

func dirBytes(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// protectedSnapshots: snapshots referenced by drift alerts, and the
// contract baseline of every published pack (the newest snapshot of each of
// its services at the time it was built).
func (c *Core) protectedSnapshots(ctx context.Context) (map[int64]bool, error) {
	out := map[int64]bool{}
	ids, err := c.drift.ReferencedSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if seq, ok := contract.ParseSnapshotID(id); ok {
			out[seq] = true
		}
	}
	pubs, _, err := c.packs.PackRefs(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pubs {
		for _, svc := range p.Services {
			seqs, err := c.eng.Snapshots().NewestAtEachGroup(ctx, svc, p.CreatedAt)
			if err != nil {
				return nil, err
			}
			for _, seq := range seqs {
				out[seq] = true
			}
		}
	}
	return out, nil
}

func (c *Core) datasets() []lifecycle.Dataset {
	r := c.cfg.Retention
	pol := func(code string, kv ...any) lifecycle.Policy {
		p := lifecycle.Policy{Code: code, Params: map[string]int64{}}
		for i := 0; i+1 < len(kv); i += 2 {
			switch v := kv[i+1].(type) {
			case int64:
				p.Params[kv[i].(string)] = v
			case int:
				p.Params[kv[i].(string)] = int64(v)
			}
		}
		return p
	}
	auditPolicy := pol("audit_forever")
	if r.Audit.ArchiveAfter > 0 {
		auditPolicy = pol("audit_archive", "days", days(r.Audit.ArchiveAfter), "segment_entries", r.Audit.SegmentEntries)
	}
	return []lifecycle.Dataset{
		{Name: "events", Tables: []string{"intake_events", "intake_fields"}, Value: 1,
			Policy: pol("raw_events", "days", days(c.intake.Retention()), "miner_window_days", days(c.cfg.Miner.Window), "floor_hours", int64(c.cfg.Storage.MinEventsRetention/time.Hour)),
			Run: func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
				res, err := c.intake.Purge(ctx)
				return lifecycle.Outcome{Deleted: res.Events + res.Tokens, Note: res.ReclaimNote,
					Details: map[string]int64{"events": res.Events, "tokens": res.Tokens, "rolled_up": res.RolledUp}}, err
			}},
		{Name: "rollups", Tables: []string{"intake_rollup*"}, Value: 8,
			Policy: pol("rollup_tiers", "hourly_days", days(r.Rollups.Hourly), "daily_days", days(r.Rollups.Daily)),
			Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
				ru, err := c.intake.Store().RollupPending(ctx)
				if err != nil {
					return lifecycle.Outcome{}, err
				}
				cr, err := c.intake.Store().CompactRollups(ctx, now, r.Rollups.Hourly, r.Rollups.Daily)
				return lifecycle.Outcome{Deleted: cr.Rows, Details: map[string]int64{"rolled_up": ru.Events, "days": int64(cr.Days), "months": int64(cr.Months)}}, err
			}},
		{Name: "tokens", Tables: []string{"intake_tokens", "intake_outbox"}, Value: 1, Policy: pol("with_events")},
		{Name: "aggregates", Tables: []string{"intake_agg*", "intake_source_counts"}, Value: 7, Policy: pol("stored_events")},
		{Name: "sketches", Tables: []string{"intake_sketch", "intake_quarantine"}, Value: 6,
			Policy: pol("sketches", "released_days", days(r.ReleasedQuarantines)),
			Run: func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
				n, err := c.intake.PruneQuarantines(ctx, r.ReleasedQuarantines)
				return lifecycle.Outcome{Deleted: n, Details: map[string]int64{"released_quarantines": n}}, err
			}},
		{Name: "deliveries", Tables: []string{"drift_deliveries"}, Value: 2, Policy: pol("ttl", "days", days(r.Deliveries)),
			Run: func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
				res, err := c.drift.Prune(ctx, r.Deliveries, 0)
				return lifecycle.Outcome{Deleted: res.Deliveries}, err
			}},
		{Name: "drift", Tables: []string{"drift_alerts", "drift_webhooks"}, Value: 9, Policy: pol("resolved_alerts", "days", days(r.ResolvedAlerts)),
			Run: func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
				res, err := c.drift.Prune(ctx, 0, r.ResolvedAlerts)
				return lifecycle.Outcome{Deleted: res.Alerts}, err
			}},
		{Name: "snapshots", Tables: []string{"contract_snapshots"}, Value: 9,
			Policy: pol("snapshot_compaction", "keep_all_days", days(r.Snapshots.KeepAll), "weekly_days", days(r.Snapshots.Weekly), "max", c.cfg.Contract.KeepSnapshots),
			Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
				res, err := c.eng.Snapshots().Compact(ctx, now, contract.SnapshotPolicy{KeepAll: r.Snapshots.KeepAll, Weekly: r.Snapshots.Weekly})
				return lifecycle.Outcome{Deleted: res.Deleted, Details: map[string]int64{"kept": res.Kept}}, err
			}},
		{Name: "miner", Tables: []string{"miner_*"}, Value: 8, Policy: pol("miner_runs", "days", days(r.MinerRuns), "keep", r.KeepMinerRuns),
			Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
				n, err := c.miner.Repo().PruneRuns(ctx, now, r.MinerRuns, r.KeepMinerRuns)
				return lifecycle.Outcome{Deleted: n}, err
			}},
		{Name: "packs", Tables: []string{"packwriter_*"}, Value: 9, Policy: pol("packs", "keep", r.Packs.KeepBuilt, "days", days(r.Packs.Unpublished)),
			Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
				res, err := c.packs.Prune(ctx, now, packwriter.RetentionPolicy{KeepBuilt: r.Packs.KeepBuilt, RowTTL: r.Packs.Unpublished})
				return lifecycle.Outcome{Deleted: res.Archives + res.Rows, Details: map[string]int64{"archives": res.Archives, "rows": res.Rows, "bytes": res.Bytes}}, err
			}},
		{Name: "worlds", Tables: []string{"world_*"}, Value: 7, Policy: pol("worlds", "keep", r.Worlds.Keep, "days", days(r.Worlds.TTL)),
			Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
				_, refs, err := c.packs.PackRefs(ctx)
				if err != nil {
					return lifecycle.Outcome{}, err
				}
				res, err := c.world.Prune(ctx, now, world.RetentionPolicy{Keep: r.Worlds.Keep, TTL: r.Worlds.TTL, KeepBuilds: 10}, refs)
				return lifecycle.Outcome{Deleted: res.Worlds + res.Builds, Details: map[string]int64{"worlds": res.Worlds, "archetype_builds": res.Builds}}, err
			}},
		{Name: "fleet", Tables: []string{"fleet_*"}, Value: 9,
			Policy: pol("fleet", "revoked_days", days(r.Fleet.RevokedSources), "tokens_days", days(r.Fleet.ExpiredTokens), "certs_days", days(r.Fleet.ExpiredCerts)),
			Run: func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
				res, err := c.fleet.Prune(ctx, fleet.RetentionPolicy{RevokedSources: r.Fleet.RevokedSources, ExpiredTokens: r.Fleet.ExpiredTokens, ExpiredCerts: r.Fleet.ExpiredCerts})
				return lifecycle.Outcome{Deleted: res.Sources + res.Tokens + res.Certs, Details: map[string]int64{"sources": res.Sources, "tokens": res.Tokens, "certs": res.Certs}}, err
			}},
		{Name: "auth", Tables: []string{"auth_*"}, Value: 9, Policy: pol("expired"),
			Run: func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
				return lifecycle.Outcome{}, c.auth.Cleanup(ctx)
			}},
		{Name: "audit", Tables: []string{"audit_*"}, Value: 10, Policy: auditPolicy,
			Files: func() int64 { return dirBytes(c.auditArchiveDir()) },
			Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
				if r.Audit.ArchiveAfter <= 0 {
					return lifecycle.Outcome{}, nil
				}
				key, err := c.archiveKey()
				if err != nil {
					return lifecycle.Outcome{}, err
				}
				res, err := c.audit.Archive(ctx, audit.ArchiveOptions{Dir: c.auditArchiveDir(), Key: key, Before: now.Add(-r.Audit.ArchiveAfter),
					SegmentEntries: r.Audit.SegmentEntries, LogName: "tt-core", Actor: systemActor})
				return lifecycle.Outcome{Deleted: res.Entries, Details: map[string]int64{"segments": int64(len(res.Segments))}}, err
			}},
		{Name: "exports", Value: 0, Policy: pol("ttl_hours", "hours", int64(r.Exports/time.Hour)),
			Files: func() int64 { return dirBytes(filepath.Join(c.dataDir, "exports")) }},
		{Name: "other", Tables: []string{"core_*", "store_*", "lifecycle_*", "sqlite_*"}, Value: 10, Policy: pol("bounded")},
	}
}

// shedLadder: what to give up first when the database exceeds the critical
// watermark (or the events/rollups quota): raw events beyond the miner
// window, then raw events halving down to the floor, then hourly rollup
// detail. Contracts, rules, alerts, packs and the audit log are never shed.
func (c *Core) shedLadder() []lifecycle.ShedStep {
	floor := c.cfg.Storage.MinEventsRetention
	keep := min(c.cfg.Miner.Window, c.intake.Retention())
	purge := func(k time.Duration) func(context.Context, time.Time) (lifecycle.Outcome, error) {
		return func(ctx context.Context, _ time.Time) (lifecycle.Outcome, error) {
			if k >= c.intake.Retention() {
				return lifecycle.Outcome{Note: "nothing beyond the retention"}, nil
			}
			res, err := c.intake.PurgeKeeping(ctx, k)
			return lifecycle.Outcome{Deleted: res.Events + res.Tokens, Details: map[string]int64{"events": res.Events, "tokens": res.Tokens, "keep_hours": int64(k / time.Hour)}}, err
		}
	}
	steps := []lifecycle.ShedStep{{Name: "events_beyond_miner_window", Datasets: []string{"events", "tokens"}, Run: purge(keep)}}
	for k := keep / 2; k > floor; k /= 2 {
		steps = append(steps, lifecycle.ShedStep{Name: "events_keep_" + durName(k), Datasets: []string{"events", "tokens"}, Run: purge(k)})
	}
	steps = append(steps, lifecycle.ShedStep{Name: "events_keep_" + durName(floor), Datasets: []string{"events", "tokens"}, Run: purge(floor)})
	hourly := min(7*day, c.cfg.Retention.Rollups.Hourly)
	steps = append(steps, lifecycle.ShedStep{Name: "rollups_hourly_" + durName(hourly), Datasets: []string{"rollups"},
		Run: func(ctx context.Context, now time.Time) (lifecycle.Outcome, error) {
			cr, err := c.intake.Store().CompactRollups(ctx, now, hourly, c.cfg.Retention.Rollups.Daily)
			return lifecycle.Outcome{Deleted: cr.Rows}, err
		}})
	return steps
}

func durName(d time.Duration) string {
	if d%day == 0 {
		return strconv.FormatInt(int64(d/day), 10) + "d"
	}
	return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
}

func (c *Core) newLifecycle(ctx context.Context) (*lifecycle.Manager, error) {
	s := c.cfg.Storage
	quotas := map[string]int64{}
	for k, v := range s.Quotas {
		quotas[k] = int64(v)
	}
	c.eng.Snapshots().SetProtector(c.protectedSnapshots)
	if c.cfg.Miner.Window > c.cfg.Retention.Events {
		c.log.Warn("miner.window is longer than retention.events: the miner sees only the retained events",
			"miner_window", c.cfg.Miner.Window.String(), "retention_events", c.cfg.Retention.Events.String())
	}
	return lifecycle.New(ctx, c.db, lifecycle.Config{
		Interval: c.cfg.Retention.PurgeInterval, MaxBytes: int64(s.MaxBytes), HighPct: s.HighWatermarkPct, CriticalPct: s.CriticalWatermarkPct,
		Quotas: quotas, Now: c.now, Logger: c.log, Audit: c.audit,
		OnWatermark: func(ctx context.Context, w lifecycle.Watermark) {
			p := map[string]any{"level": string(w.Level), "previous": string(w.Previous), "peak": string(w.Peak), "used_bytes": w.UsedBytes, "max_bytes": w.MaxBytes,
				"used_pct": w.UsedPct, "ingestion_active": w.IngestionActive}
			if len(w.OverQuota) > 0 {
				p["datasets_over_quota"] = w.OverQuota
			}
			if len(w.Shed) > 0 {
				p["shed"] = w.Shed
			}
			c.alerts.emit(ctx, "storage.high_watermark", p)
		},
	}, c.datasets(), c.shedLadder())
}

// maintenance runs one lifecycle pass as a job (store.maintenance): progress
// and result readable at /api/v1/jobs/{job_id}.
func (c *Core) maintenance(ctx context.Context, trigger, owner string) (*Job, <-chan struct{}, error) {
	if j := c.jobs.running(jobMaintenance); j != nil || c.lifecycle.Running() {
		return j, nil, lifecycle.ErrRunning
	}
	j := c.jobs.start(jobMaintenance, owner)
	c.jobs.setMeta(j, "trigger", trigger)
	done := make(chan struct{})
	go func() {
		defer close(done)
		rep, err := c.lifecycle.RunOnce(ctx, trigger, func(p lifecycle.Progress) { c.jobs.setProgress(j, p) })
		switch {
		case err != nil:
			c.log.Error("maintenance failed", "job_id", j.ID, "err", err)
			c.jobs.fail(j, "maintenance_failed")
		default:
			c.jobs.done(j, rep)
		}
	}()
	return j, done, nil
}

func (c *Core) runLifecycle(ctx context.Context) {
	c.lifecycle.Run(ctx, func(ctx context.Context) {
		_, done, err := c.maintenance(ctx, "schedule", "system")
		if err == nil {
			<-done
		}
	})
}

// Admin API -----------------------------------------------------------------

func (c *Core) apiStoreUsage(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	u, err := c.lifecycle.Usage(r.Context())
	if err != nil {
		return err
	}
	out := struct {
		*lifecycle.Usage
		JobID        string                   `json:"job_id,omitempty"`
		EventsDays   int64                    `json:"events_retention_days"`
		Rollups      []intake.RollupTierStats `json:"rollups"`
		AuditArchive *auditArchiveInfo        `json:"audit_archive,omitempty"`
	}{Usage: u, EventsDays: days(c.intake.Retention())}
	if j := c.jobs.running(jobMaintenance); j != nil {
		out.JobID = j.ID
	}
	if out.Rollups, err = c.intake.Store().RollupStats(r.Context()); err != nil {
		return err
	}
	if segs, err := c.audit.Segments(r.Context()); err == nil {
		a := &auditArchiveInfo{Enabled: c.cfg.Retention.Audit.ArchiveAfter > 0, Segments: len(segs), Dir: filepath.Base(c.auditArchiveDir())}
		for _, s := range segs {
			a.Entries += s.Entries
			if a.LastSeq < s.LastSeq {
				a.LastSeq, a.HeadHash = s.LastSeq, s.HeadHash
			}
		}
		out.AuditArchive = a
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

type auditArchiveInfo struct {
	Enabled  bool   `json:"enabled"`
	Dir      string `json:"dir"`
	Segments int    `json:"segments"`
	Entries  int64  `json:"entries"`
	LastSeq  int64  `json:"last_seq,omitempty"`
	HeadHash string `json:"head_hash,omitempty"`
}

func (c *Core) apiStoreMaintenance(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	j, _, err := c.maintenance(c.jobs.context(), "api", p.UserID)
	if errors.Is(err, lifecycle.ErrRunning) {
		msg := "a maintenance run is in progress"
		if j != nil {
			msg += ": follow it at /api/v1/jobs/" + j.ID
		}
		return apiErr(http.StatusConflict, "maintenance_running", msg)
	}
	if err != nil {
		return err
	}
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "store.maintenance.start", Target: audit.Target{Type: "store"}, Outcome: audit.Success,
		RequestID: httpx.RequestID(r.Context()), Details: map[string]string{"job_id": j.ID}})
	httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	return nil
}

// apiStoreTraffic serves the rolled-up traffic: GET /api/v1/store/traffic
// ?service=&op=&dir=&from=&to=&step=hour|day|month.
func (c *Core) apiStoreTraffic(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	q := r.URL.Query()
	tq := intake.TrafficQuery{Service: q.Get("service"), Op: q.Get("op"), Dir: q.Get("dir")}
	switch q.Get("step") {
	case "", "hour":
		tq.Step = intake.TierHour
	case "day":
		tq.Step = intake.TierDay
	case "month":
		tq.Step = intake.TierMonth
	default:
		return apiErr(http.StatusBadRequest, "invalid_query", "step must be hour, day or month")
	}
	if tq.Dir != "" && tq.Dir != "inbound" && tq.Dir != "outbound" {
		return apiErr(http.StatusBadRequest, "invalid_query", "dir must be inbound or outbound")
	}
	var err error
	if tq.From, tq.To, err = period(q.Get("from"), q.Get("to")); err != nil {
		return err
	}
	if tq.From.IsZero() {
		tq.From = c.now().Add(-7 * day)
	}
	pts, err := c.intake.Store().Traffic(r.Context(), tq)
	if err != nil {
		return err
	}
	if pts == nil {
		pts = []intake.TrafficPoint{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"step": intake.TierName(tq.Step), "from": tq.From.UTC(), "points": pts})
	return nil
}

// period parses optional RFC 3339 from/to query values.
func period(from, to string) (time.Time, time.Time, error) {
	var f, t time.Time
	var err error
	if from != "" {
		if f, err = time.Parse(time.RFC3339, from); err != nil {
			return f, t, apiErr(http.StatusBadRequest, "invalid_query", "from must be an RFC 3339 date-time")
		}
	}
	if to != "" {
		if t, err = time.Parse(time.RFC3339, to); err != nil {
			return f, t, apiErr(http.StatusBadRequest, "invalid_query", "to must be an RFC 3339 date-time")
		}
	}
	if !f.IsZero() && !t.IsZero() && !t.After(f) {
		return f, t, apiErr(http.StatusBadRequest, "invalid_query", "to must be after from")
	}
	return f, t, nil
}
