package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "core", Migrations: []store.Migration{
		{Version: 1, Name: "settings", SQL: `CREATE TABLE core_settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		) STRICT;`},
		{Version: 2, Name: "quarantine_approvals", SQL: `CREATE TABLE core_quarantine_approvals (
			item_id    INTEGER NOT NULL,
			resolution TEXT NOT NULL CHECK (resolution IN ('close', 'dismiss')),
			user_id    TEXT NOT NULL,
			at_ms      INTEGER NOT NULL,
			PRIMARY KEY (item_id, resolution, user_id)
		) STRICT;`},
		{Version: 3, Name: "scenario_presets", SQL: `CREATE TABLE core_scenario_presets (
			id         TEXT PRIMARY KEY,
			doc        TEXT NOT NULL,
			updated_ms INTEGER NOT NULL
		) STRICT;`},
		{Version: 4, Name: "twin_selection", SQL: `CREATE TABLE core_twin (
			service TEXT PRIMARY KEY,
			twin    INTEGER NOT NULL CHECK (twin IN (0, 1))
		) STRICT;`},
	}})
}

const settingRetention = "retention.events_days"

func (c *Core) saveSetting(ctx context.Context, key, value string) error {
	_, err := c.db.ExecContext(ctx, `INSERT INTO core_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// loadSettings applies the settings changed from the admin API, which
// override the configuration file until changed again.
func (c *Core) loadSettings(ctx context.Context) error {
	var v string
	err := c.db.QueryRowContext(ctx, `SELECT value FROM core_settings WHERE key = ?`, settingRetention).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if d, err := strconv.Atoi(v); err == nil && d >= 1 && d <= 365 {
		c.intake.SetRetention(time.Duration(d) * 24 * time.Hour)
	}
	return nil
}

// Job is the admin API Job object. A long operation answers it with the
// final status when it ends within syncWait, else "queued" (waiting for a
// heavy slot) or "running" (longjobs.go); jobs stay readable at GET
// /api/v1/jobs/{job_id} for retention.exports.
type Job struct {
	ID     string `json:"job_id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	// Details are the details of the error answer of a failed long request
	// (which rules, which services), as in the Error object.
	Details json.RawMessage `json:"details,omitempty"`
	// Progress is set while a background job runs (for example the rows a
	// purge has deleted so far).
	Progress any `json:"progress,omitempty"`

	owner   string
	created time.Time
	file    string // downloadable artifact, removed with the job
	meta    map[string]string
	// viewers are the users who joined the job (a second mining request):
	// they may read it like its owner.
	viewers []string
	// claimed is set when the handler of a long request writes the job
	// itself (startJob): its answer is the job.
	claimed bool
}

// visibleTo reports whether user may read the job as its owner.
func (j *Job) visibleTo(user string) bool {
	if j.owner == user {
		return true
	}
	for _, v := range j.viewers {
		if v == user {
			return true
		}
	}
	return false
}

type jobs struct {
	dir string
	ttl time.Duration
	log *slog.Logger

	mu   sync.Mutex
	byID map[string]*Job
	bg   context.Context // set by Run: the lifetime of background jobs
}

func newJobs(dir string, ttl time.Duration, log *slog.Logger) *jobs {
	return &jobs{dir: dir, ttl: ttl, log: log, byID: map[string]*Job{}}
}

func (js *jobs) start(kind, owner string) *Job {
	j := &Job{ID: httpx.NewID("job_"), Kind: kind, Status: "running", owner: owner, created: time.Now(), meta: map[string]string{}}
	js.mu.Lock()
	js.byID[j.ID] = j
	js.mu.Unlock()
	return j
}

// startOrJoin starts a long job of kind in status "queued" or, when join
// is set and a job of kind is queued or running, returns that one (joined)
// with owner among its viewers. The check and the start are atomic: two
// requests at once never both start.
func (js *jobs) startOrJoin(kind, owner string, join bool) (*Job, bool) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if join {
		for _, j := range js.byID {
			if j.Kind == kind && (j.Status == "queued" || j.Status == "running") {
				if !j.visibleTo(owner) {
					j.viewers = append(j.viewers, owner)
				}
				return j, true
			}
		}
	}
	j := &Job{ID: httpx.NewID("job_"), Kind: kind, Status: "queued", owner: owner, created: time.Now(), meta: map[string]string{}}
	js.byID[j.ID] = j
	return j, false
}

// claim marks j as written by its handler, with the handler's kind.
func (js *jobs) claim(j *Job, kind string) {
	js.mu.Lock()
	j.claimed, j.Kind = true, kind
	js.mu.Unlock()
}

func (js *jobs) claimed(j *Job) bool {
	js.mu.Lock()
	defer js.mu.Unlock()
	return j.claimed
}

// setStatus moves a job that has not ended between queued and running.
func (js *jobs) setStatus(j *Job, status string) {
	js.mu.Lock()
	if j.Status == "queued" || j.Status == "running" {
		j.Status = status
	}
	js.mu.Unlock()
}

func (js *jobs) status(j *Job) string {
	js.mu.Lock()
	defer js.mu.Unlock()
	return j.Status
}

// remove forgets a job (and its file).
func (js *jobs) remove(id string) {
	js.mu.Lock()
	j := js.byID[id]
	delete(js.byID, id)
	js.mu.Unlock()
	if j != nil && j.file != "" {
		_ = os.Remove(j.file)
	}
}

// list returns copies of the jobs see accepts, newest first, without
// their results and progress (GET /api/v1/jobs).
func (js *jobs) list(see func(*Job) bool) []*Job {
	js.mu.Lock()
	out := make([]*Job, 0, len(js.byID))
	for _, j := range js.byID {
		if see(j) {
			cp := *j
			cp.Result, cp.Progress = nil, nil
			out = append(out, &cp)
		}
	}
	js.mu.Unlock()
	slices.SortFunc(out, func(a, b *Job) int {
		if c := b.created.Compare(a.created); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	return out
}

func (js *jobs) done(j *Job, result any) {
	js.mu.Lock()
	j.Status, j.Result = "done", result
	js.mu.Unlock()
}

// setProgress records the progress of a running job.
func (js *jobs) setProgress(j *Job, progress any) {
	js.mu.Lock()
	j.Progress = progress
	js.mu.Unlock()
}

// context is the context of background jobs: it ends when the core stops,
// not when the request that started the job ends.
func (js *jobs) context() context.Context {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.bg == nil {
		return context.Background()
	}
	return js.bg
}

// running returns a running job of kind, if any.
func (js *jobs) running(kind string) *Job {
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, j := range js.byID {
		if j.Kind == kind && j.Status == "running" {
			cp := *j
			return &cp
		}
	}
	return nil
}

func (js *jobs) fail(j *Job, code string) {
	js.failWith(j, code, nil)
}

// failWith is fail with the details of the error answer.
func (js *jobs) failWith(j *Job, code string, details json.RawMessage) {
	js.mu.Lock()
	j.Status, j.Error, j.Details = "failed", code, details
	js.mu.Unlock()
	if j.file != "" {
		_ = os.Remove(j.file)
	}
}

// get returns a copy of the job (nil when unknown or expired).
func (js *jobs) get(id string) *Job {
	js.mu.Lock()
	defer js.mu.Unlock()
	j := js.byID[id]
	if j == nil {
		return nil
	}
	cp := *j
	return &cp
}

// find returns the first job of kind whose meta key has value.
func (js *jobs) find(kind, key, value string) *Job {
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, j := range js.byID {
		if j.Kind == kind && j.meta[key] == value {
			cp := *j
			return &cp
		}
	}
	return nil
}

// artifactPath returns a fresh path for a job's file (0700 directory).
func (js *jobs) artifactPath(j *Job, ext string) (string, error) {
	if err := os.MkdirAll(js.dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(js.dir, j.ID+ext)
	js.mu.Lock()
	j.file = p
	js.mu.Unlock()
	return p, nil
}

func (js *jobs) setMeta(j *Job, key, value string) {
	js.mu.Lock()
	j.meta[key] = value
	js.mu.Unlock()
}

// Run expires jobs and their files; at start it removes files left by a
// previous process (the registry is in memory).
func (js *jobs) Run(ctx context.Context) {
	js.mu.Lock()
	js.bg = ctx
	js.mu.Unlock()
	if ents, err := os.ReadDir(js.dir); err == nil {
		for _, e := range ents {
			_ = os.Remove(filepath.Join(js.dir, e.Name()))
		}
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cut := time.Now().Add(-js.ttl)
		js.mu.Lock()
		for id, j := range js.byID {
			if j.created.Before(cut) {
				if j.file != "" {
					_ = os.Remove(j.file)
				}
				delete(js.byID, id)
			}
		}
		js.mu.Unlock()
	}
}
