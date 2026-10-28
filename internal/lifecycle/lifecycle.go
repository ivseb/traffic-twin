// Package lifecycle runs the data lifecycle of tt-core: the background
// maintenance that applies the retention of every growing dataset, gives the
// freed pages back to the file system, measures the database per dataset and
// keeps it within its size budget (docs/DATA_LIFECYCLE.md).
//
// The package knows no table of its own beyond its run log: core describes
// each dataset (its tables, its policy and the function that applies it) and
// the shedding ladder (what to give up first when the budget is exceeded).
// Every step deletes in small transactions (the owning packages do), so the
// intake keeps writing while the maintenance runs. A run is idempotent: a
// restart in the middle only means the next run finishes the work.
package lifecycle

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "lifecycle", Migrations: []store.Migration{
		{Version: 1, Name: "runs_state", SQL: `
CREATE TABLE lifecycle_runs (
	id          INTEGER PRIMARY KEY,
	started_ms  INTEGER NOT NULL,
	finished_ms INTEGER NOT NULL,
	trigger     TEXT    NOT NULL,
	report      BLOB    NOT NULL
) STRICT;
CREATE TABLE lifecycle_state (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
) STRICT;
`},
	}})
}

// Outcome is what one step did.
type Outcome struct {
	// Deleted counts the rows (or items) removed or compacted.
	Deleted int64 `json:"deleted"`
	// Details break Deleted down (for example events, tokens, rolled_up).
	Details map[string]int64 `json:"details,omitempty"`
	// Note explains a step that could not do everything ("legacy database").
	Note string `json:"note,omitempty"`
}

// Policy describes a dataset's retention for the UI: a stable code and its
// parameters (days, counts).
type Policy struct {
	Code   string           `json:"code"`
	Params map[string]int64 `json:"params,omitempty"`
}

// Dataset is one growing dataset.
type Dataset struct {
	// Name is one of config.Datasets.
	Name string
	// Tables are the tables whose pages count for the dataset (with their
	// indexes); a trailing "*" makes a prefix.
	Tables []string
	// Files reports the bytes kept outside the database (optional).
	Files func() int64
	// Policy is shown in the UI.
	Policy Policy
	// Run applies the retention (optional: some datasets only shrink with
	// another one, or are bounded by construction).
	Run func(ctx context.Context, now time.Time) (Outcome, error)
	// Value orders the shedding report (lower = less valuable); informative.
	Value int
}

// ShedStep is one rung of the shedding ladder, tried in order while the
// database (or a dataset quota) stays over budget.
type ShedStep struct {
	Name string
	// Datasets lists the datasets the step frees (to test quotas).
	Datasets []string
	Run      func(ctx context.Context, now time.Time) (Outcome, error)
}

// Level of the budget.
type Level string

// Levels.
const (
	LevelOK       Level = "ok"
	LevelHigh     Level = "high"     // >= high watermark
	LevelCritical Level = "critical" // >= critical watermark: shedding
	LevelOver     Level = "over"     // over the budget after shedding
)

func levelRank(l Level) int {
	switch l {
	case LevelHigh:
		return 1
	case LevelCritical:
		return 2
	case LevelOver:
		return 3
	}
	return 0
}

// Watermark is sent when the level changes.
type Watermark struct {
	Level    Level `json:"level"`
	Previous Level `json:"previous"`
	// Peak is the highest level of the run (before shedding).
	Peak            Level    `json:"peak"`
	UsedBytes       int64    `json:"used_bytes"`
	MaxBytes        int64    `json:"max_bytes"`
	UsedPct         float64  `json:"used_pct"`
	OverQuota       []string `json:"datasets_over_quota,omitempty"`
	Shed            []string `json:"shed,omitempty"`
	IngestionActive bool     `json:"ingestion_active"`
}

// Config configures a Manager.
type Config struct {
	// Interval between runs (the first runs one interval after Run starts,
	// or at once when the last run is older than an interval).
	Interval time.Duration
	// MaxBytes is the budget (0: none); HighPct and CriticalPct its watermarks.
	MaxBytes    int64
	HighPct     int
	CriticalPct int
	// Quotas by dataset name (bytes).
	Quotas map[string]int64
	// Reclaim gives the freed pages back after the steps (default on).
	NoReclaim bool
	// Now is the clock of the policies (tests inject a virtual clock).
	Now    func() time.Time
	Logger *slog.Logger
	Audit  *audit.Log
	// OnWatermark is told about level changes (storage.high_watermark).
	OnWatermark func(ctx context.Context, w Watermark)
}

// Manager runs the maintenance.
type Manager struct {
	db       *store.DB
	cfg      Config
	datasets []Dataset
	shed     []ShedStep
	log      *slog.Logger

	running atomic.Bool
	mu      sync.Mutex
	last    *Report
	sizes   map[string]int64
	measAt  time.Time
	level   Level
	lastAt  time.Time
}

// ErrRunning is returned by RunOnce while another run is in progress.
var ErrRunning = errors.New("lifecycle: a maintenance run is already in progress")

// New returns a manager. It loads the last report and level from the
// database.
func New(ctx context.Context, db *store.DB, cfg Config, datasets []Dataset, shed []ShedStep) (*Manager, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HighPct == 0 {
		cfg.HighPct, cfg.CriticalPct = 80, 90
	}
	m := &Manager{db: db, cfg: cfg, datasets: datasets, shed: shed, log: cfg.Logger, level: LevelOK, sizes: map[string]int64{}}
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT report FROM lifecycle_runs ORDER BY id DESC LIMIT 1`).Scan(&raw)
	if err == nil {
		var r Report
		if json.Unmarshal(raw, &r) == nil {
			m.last = &r
			m.lastAt = r.StartedAt
			m.sizes = r.Sizes
			m.measAt = r.FinishedAt
			if m.sizes == nil {
				m.sizes = map[string]int64{}
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var lv string
	if err := db.QueryRowContext(ctx, `SELECT v FROM lifecycle_state WHERE k = 'level'`).Scan(&lv); err == nil {
		m.level = Level(lv)
	}
	return m, nil
}

// StepReport is the result of one dataset policy or shedding step.
type StepReport struct {
	Name       string  `json:"name"`
	Outcome    Outcome `json:"outcome"`
	Error      string  `json:"error,omitempty"`
	DurationMS int64   `json:"duration_ms"`
}

// Report is the result of a run.
type Report struct {
	Trigger     string           `json:"trigger"`
	StartedAt   time.Time        `json:"started_at"`
	FinishedAt  time.Time        `json:"finished_at"`
	Steps       []StepReport     `json:"steps"`
	Shed        []StepReport     `json:"shed,omitempty"`
	Deleted     int64            `json:"deleted"`
	Reclaimed   int64            `json:"reclaimed_bytes"`
	ReclaimNote string           `json:"reclaim_note,omitempty"`
	Sizes       map[string]int64 `json:"sizes"`
	UsedBytes   int64            `json:"used_bytes"`
	Level       Level            `json:"level"`
	Peak        Level            `json:"peak_level"`
	OverQuota   []string         `json:"datasets_over_quota,omitempty"`
	Errors      int              `json:"errors"`
}

// Progress is reported during a run.
type Progress struct {
	Phase string `json:"phase"` // dataset name, "reclaim", "measure", "shed:<step>"
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// Run runs the maintenance every interval until ctx ends. tick, when not
// nil, is called instead of RunOnce (core wraps the run in a job).
func (m *Manager) Run(ctx context.Context, tick func(ctx context.Context)) {
	first := m.cfg.Interval
	m.mu.Lock()
	if m.lastAt.IsZero() || m.cfg.Now().Sub(m.lastAt) >= m.cfg.Interval {
		first = time.Minute
	}
	m.mu.Unlock()
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if tick != nil {
			tick(ctx)
		} else if _, err := m.RunOnce(ctx, "schedule", nil); err != nil && ctx.Err() == nil && !errors.Is(err, ErrRunning) {
			m.log.Error("lifecycle: maintenance run failed", "err", err)
		}
		t.Reset(m.cfg.Interval)
	}
}

// NextRun is when the scheduled run is due.
func (m *Manager) NextRun() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastAt.IsZero() {
		return time.Time{}
	}
	return m.lastAt.Add(m.cfg.Interval)
}

// Running reports whether a run is in progress.
func (m *Manager) Running() bool { return m.running.Load() }

// RunOnce applies every dataset policy, reclaims the space, measures the
// datasets and enforces the budget. trigger is "schedule", "api" or "test".
func (m *Manager) RunOnce(ctx context.Context, trigger string, progress func(Progress)) (*Report, error) {
	if !m.running.CompareAndSwap(false, true) {
		return nil, ErrRunning
	}
	defer m.running.Store(false)
	if progress == nil {
		progress = func(Progress) {}
	}
	now := m.cfg.Now()
	rep := &Report{Trigger: trigger, StartedAt: now.UTC()}
	m.mu.Lock()
	m.lastAt = now
	m.mu.Unlock()
	total := len(m.datasets) + 2
	for i, d := range m.datasets {
		if d.Run == nil {
			continue
		}
		progress(Progress{Phase: d.Name, Done: i, Total: total})
		sr := m.step(ctx, d.Name, now, d.Run)
		rep.Steps = append(rep.Steps, sr)
		rep.Deleted += sr.Outcome.Deleted
		if sr.Error != "" {
			rep.Errors++
		}
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
	}
	progress(Progress{Phase: "reclaim", Done: len(m.datasets), Total: total})
	m.reclaim(ctx, rep)
	progress(Progress{Phase: "measure", Done: len(m.datasets) + 1, Total: total})
	sizes, err := m.measure(ctx)
	if err != nil {
		return rep, err
	}
	rep.Sizes = sizes
	used, err := m.usedBytes(ctx)
	if err != nil {
		return rep, err
	}
	rep.UsedBytes = used
	rep.OverQuota = m.overQuota(sizes)
	level := m.levelOf(used)
	rep.Peak = level

	// Shed the least valuable data while over the critical watermark or a
	// quota of a sheddable dataset.
	if m.mustShed(level, rep.OverQuota) {
		for _, s := range m.shed {
			if !m.mustShed(level, rep.OverQuota) {
				break
			}
			if levelRank(level) < levelRank(LevelCritical) && !intersects(rep.OverQuota, s.Datasets) {
				continue
			}
			progress(Progress{Phase: "shed:" + s.Name, Done: len(m.datasets) + 1, Total: total})
			sr := m.step(ctx, s.Name, now, s.Run)
			rep.Shed = append(rep.Shed, sr)
			rep.Deleted += sr.Outcome.Deleted
			if sr.Error != "" {
				rep.Errors++
			}
			m.reclaim(ctx, rep)
			if sizes, err = m.measure(ctx); err != nil {
				return rep, err
			}
			rep.Sizes = sizes
			if used, err = m.usedBytes(ctx); err != nil {
				return rep, err
			}
			rep.UsedBytes, rep.OverQuota = used, m.overQuota(sizes)
			level = m.levelOf(used)
			if ctx.Err() != nil {
				return rep, ctx.Err()
			}
		}
		if m.cfg.MaxBytes > 0 && used > m.cfg.MaxBytes {
			level = LevelOver
		}
	}
	rep.Level = level
	rep.FinishedAt = m.cfg.Now().UTC()
	m.finish(ctx, rep)
	return rep, nil
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func (m *Manager) mustShed(level Level, over []string) bool {
	if levelRank(level) >= levelRank(LevelCritical) {
		return true
	}
	for _, s := range m.shed {
		if intersects(over, s.Datasets) {
			return true
		}
	}
	return false
}

func (m *Manager) step(ctx context.Context, name string, now time.Time, run func(context.Context, time.Time) (Outcome, error)) StepReport {
	began := time.Now()
	out, err := run(ctx, now)
	sr := StepReport{Name: name, Outcome: out, DurationMS: time.Since(began).Milliseconds()}
	if err != nil {
		sr.Error = err.Error()
		if ctx.Err() == nil {
			m.log.Error("lifecycle: step failed", "step", name, "err", err)
		}
	}
	return sr
}

func (m *Manager) reclaim(ctx context.Context, rep *Report) {
	if m.cfg.NoReclaim {
		return
	}
	freed, err := m.db.Reclaim(ctx)
	rep.Reclaimed += freed
	switch {
	case errors.Is(err, store.ErrNoIncrementalVacuum):
		rep.ReclaimNote = "legacy database (auto_vacuum off): freed pages are reused but the file keeps its size; stop the core and run \"tt compact\" once"
	case err != nil && ctx.Err() == nil:
		rep.ReclaimNote = "reclaim failed: " + err.Error()
	}
}

// usedBytes is the space really taken: file + WAL - free pages (on a legacy
// database the free pages are reused by new rows, so they count as room).
func (m *Manager) usedBytes(ctx context.Context) (int64, error) {
	sp, err := m.db.Space(ctx)
	if err != nil {
		return 0, err
	}
	return sp.FileBytes + sp.WALBytes - sp.FreeBytes, nil
}

func (m *Manager) levelOf(used int64) Level {
	if m.cfg.MaxBytes <= 0 {
		return LevelOK
	}
	pct := float64(used) * 100 / float64(m.cfg.MaxBytes)
	switch {
	case pct >= float64(m.cfg.CriticalPct):
		return LevelCritical
	case pct >= float64(m.cfg.HighPct):
		return LevelHigh
	}
	return LevelOK
}

func (m *Manager) overQuota(sizes map[string]int64) []string {
	var out []string
	for name, q := range m.cfg.Quotas {
		if q > 0 && sizes[name] > q {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// measure attributes every table and index of the database to a dataset
// (dbstat). It reads every page: it runs in the background job only.
func (m *Manager) measure(ctx context.Context) (map[string]int64, error) {
	owner := map[string]string{}
	rows, err := m.db.QueryContext(ctx, `SELECT name, tbl_name FROM sqlite_schema WHERE type IN ('table', 'index')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, tbl string
		if err := rows.Scan(&name, &tbl); err != nil {
			rows.Close()
			return nil, err
		}
		owner[name] = tbl
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = m.db.QueryContext(ctx, `SELECT name, pgsize FROM dbstat WHERE aggregate = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: dbstat: %w", err)
	}
	sizes := map[string]int64{}
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			rows.Close()
			return nil, err
		}
		tbl := owner[name]
		if tbl == "" {
			tbl = name
		}
		sizes[m.datasetOf(tbl)] += size
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, d := range m.datasets {
		if d.Files != nil {
			sizes[d.Name+".files"] = d.Files()
		}
	}
	m.mu.Lock()
	m.sizes, m.measAt = sizes, m.cfg.Now().UTC()
	m.mu.Unlock()
	return sizes, nil
}

func (m *Manager) datasetOf(table string) string {
	for _, d := range m.datasets {
		for _, t := range d.Tables {
			if p, ok := strings.CutSuffix(t, "*"); ok && strings.HasPrefix(table, p) || t == table {
				return d.Name
			}
		}
	}
	return "other"
}

func (m *Manager) finish(ctx context.Context, rep *Report) {
	m.mu.Lock()
	prev := m.level
	m.level = rep.Level
	m.last = rep
	m.mu.Unlock()
	raw, _ := json.Marshal(rep)
	if _, err := m.db.ExecContext(ctx, `INSERT INTO lifecycle_runs (started_ms, finished_ms, trigger, report) VALUES (?, ?, ?, ?)`,
		rep.StartedAt.UnixMilli(), rep.FinishedAt.UnixMilli(), rep.Trigger, raw); err != nil {
		m.log.Error("lifecycle: run log not saved", "err", err)
	}
	// The run log bounds itself.
	_, _ = m.db.ExecContext(ctx, `DELETE FROM lifecycle_runs WHERE id NOT IN (SELECT id FROM lifecycle_runs ORDER BY id DESC LIMIT 200)`)
	_, _ = m.db.ExecContext(ctx, `INSERT INTO lifecycle_state (k, v) VALUES ('level', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, string(rep.Level))
	if m.cfg.Audit != nil {
		d := map[string]string{"trigger": audit.SafeValue(rep.Trigger), "deleted": strconv.FormatInt(rep.Deleted, 10),
			"reclaimed_bytes": strconv.FormatInt(rep.Reclaimed, 10), "used_bytes": strconv.FormatInt(rep.UsedBytes, 10),
			"level": string(rep.Level), "errors": strconv.Itoa(rep.Errors)}
		if len(rep.Shed) > 0 {
			names := make([]string, len(rep.Shed))
			for i, s := range rep.Shed {
				names[i] = s.Name
			}
			d["shed"] = audit.SafeValue(strings.Join(names, ","))
		}
		outcome := audit.Success
		if rep.Errors > 0 {
			outcome = audit.Failure
		}
		if _, err := m.cfg.Audit.Record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSystem, ID: "tt-core", Name: "maintenance"},
			Action: "store.maintenance", Target: audit.Target{Type: "store"}, Outcome: outcome, Details: d}); err != nil {
			m.log.Error("lifecycle: audit failed", "err", err)
		}
	}
	if rep.Level != prev || len(rep.Shed) > 0 {
		w := Watermark{Level: rep.Level, Previous: prev, Peak: rep.Peak, UsedBytes: rep.UsedBytes, MaxBytes: m.cfg.MaxBytes, OverQuota: rep.OverQuota, IngestionActive: true}
		if m.cfg.MaxBytes > 0 {
			w.UsedPct = float64(rep.UsedBytes) * 100 / float64(m.cfg.MaxBytes)
		}
		for _, s := range rep.Shed {
			w.Shed = append(w.Shed, s.Name)
		}
		lvl := slog.LevelInfo
		if rep.Level != LevelOK {
			lvl = slog.LevelWarn
		}
		if rep.Level == LevelOver {
			lvl = slog.LevelError
		}
		m.log.Log(ctx, lvl, "lifecycle: storage level changed (ingestion continues)", "level", rep.Level, "previous", prev,
			"used_bytes", rep.UsedBytes, "max_bytes", m.cfg.MaxBytes, "shed", w.Shed)
		if m.cfg.OnWatermark != nil {
			m.cfg.OnWatermark(ctx, w)
		}
	}
}

// DatasetUsage is one row of /store/usage.
type DatasetUsage struct {
	Name       string      `json:"name"`
	Bytes      int64       `json:"bytes"`
	FileBytes  int64       `json:"file_bytes,omitempty"`
	QuotaBytes int64       `json:"quota_bytes,omitempty"`
	OverQuota  bool        `json:"over_quota"`
	Policy     Policy      `json:"policy"`
	LastRun    *StepReport `json:"last_run,omitempty"`
}

// Usage is GET /api/v1/store/usage.
type Usage struct {
	DB         DBUsage        `json:"db"`
	Datasets   []DatasetUsage `json:"datasets"`
	MeasuredAt *time.Time     `json:"measured_at,omitempty"`
	LastRun    *RunSummary    `json:"last_run,omitempty"`
	NextRun    *time.Time     `json:"next_run,omitempty"`
	Running    bool           `json:"running"`
	Interval   int64          `json:"interval_seconds"`
}

// DBUsage describes the database file and its budget.
type DBUsage struct {
	File        string  `json:"file"`
	FileBytes   int64   `json:"file_bytes"`
	WALBytes    int64   `json:"wal_bytes"`
	FreeBytes   int64   `json:"free_bytes"`
	UsedBytes   int64   `json:"used_bytes"`
	MaxBytes    int64   `json:"max_bytes"`
	UsedPct     float64 `json:"used_pct"`
	HighPct     int     `json:"high_watermark_pct"`
	CriticalPct int     `json:"critical_watermark_pct"`
	Level       Level   `json:"level"`
	AutoVacuum  string  `json:"auto_vacuum"`
}

// RunSummary is the last run without the per-step detail.
type RunSummary struct {
	Trigger     string       `json:"trigger"`
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at"`
	Deleted     int64        `json:"deleted"`
	Reclaimed   int64        `json:"reclaimed_bytes"`
	ReclaimNote string       `json:"reclaim_note,omitempty"`
	Errors      int          `json:"errors"`
	Shed        []StepReport `json:"shed,omitempty"`
}

// Usage reports the live file sizes and the last measured dataset sizes.
func (m *Manager) Usage(ctx context.Context) (*Usage, error) {
	sp, err := m.db.Space(ctx)
	if err != nil {
		return nil, err
	}
	used := sp.FileBytes + sp.WALBytes - sp.FreeBytes
	u := &Usage{Running: m.running.Load(), Interval: int64(m.cfg.Interval / time.Second)}
	u.DB = DBUsage{File: filepath.Base(m.db.Path()), FileBytes: sp.FileBytes, WALBytes: sp.WALBytes, FreeBytes: sp.FreeBytes, UsedBytes: used,
		MaxBytes: m.cfg.MaxBytes, HighPct: m.cfg.HighPct, CriticalPct: m.cfg.CriticalPct, AutoVacuum: "none"}
	if sp.AutoVacuum == store.AutoVacuumIncremental {
		u.DB.AutoVacuum = "incremental"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u.DB.Level = m.levelOf(used)
	if levelRank(m.level) > levelRank(u.DB.Level) && m.level == LevelOver {
		u.DB.Level = LevelOver
	}
	if m.cfg.MaxBytes > 0 {
		u.DB.UsedPct = float64(used) * 100 / float64(m.cfg.MaxBytes)
	}
	if !m.measAt.IsZero() {
		t := m.measAt
		u.MeasuredAt = &t
	}
	steps := map[string]StepReport{}
	if m.last != nil {
		for _, s := range m.last.Steps {
			steps[s.Name] = s
		}
		u.LastRun = &RunSummary{Trigger: m.last.Trigger, StartedAt: m.last.StartedAt, FinishedAt: m.last.FinishedAt, Deleted: m.last.Deleted,
			Reclaimed: m.last.Reclaimed, ReclaimNote: m.last.ReclaimNote, Errors: m.last.Errors, Shed: m.last.Shed}
		next := m.lastAt.Add(m.cfg.Interval)
		u.NextRun = &next
	}
	seen := map[string]bool{}
	for _, d := range m.datasets {
		seen[d.Name] = true
		du := DatasetUsage{Name: d.Name, Bytes: m.sizes[d.Name], FileBytes: m.sizes[d.Name+".files"], QuotaBytes: m.cfg.Quotas[d.Name], Policy: d.Policy}
		du.OverQuota = du.QuotaBytes > 0 && du.Bytes > du.QuotaBytes
		if s, ok := steps[d.Name]; ok {
			du.LastRun = &s
		}
		u.Datasets = append(u.Datasets, du)
	}
	if !seen["other"] {
		u.Datasets = append(u.Datasets, DatasetUsage{Name: "other", Bytes: m.sizes["other"], Policy: Policy{Code: "bounded"}})
	}
	return u, nil
}

// Level returns the last computed level.
func (m *Manager) Level() Level {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.level
}
