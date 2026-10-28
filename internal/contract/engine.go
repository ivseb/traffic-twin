package contract

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Deps are the collaborators of an [Engine].
type Deps struct {
	// DB is the database opened with store.Open.
	DB *store.DB
	// Events is the event store (*intake.Store).
	Events EventSource
	// Hints supplies HMAC domains and bucket bounds; may be nil.
	Hints Hints
	// Groups attributes the sources of the events to groups (fleet); may be
	// nil: then every event is of group "" (one contract per service).
	// With it a contract describes one group's traffic to a service.
	Groups groupscope.Resolver
	// Logger defaults to a discarding logger.
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// SnapshotHook is called after a snapshot is stored, with the previous
// snapshot of the same service (nil for the first one). Hooks run in order
// on the snapshotting goroutine; an error is logged and does not stop the
// others.
type SnapshotHook func(ctx context.Context, prev, cur *Snapshot) error

// Engine produces and serves contract snapshots.
type Engine struct {
	cfg    Config
	db     *store.DB
	src    EventSource
	groups groupscope.Resolver
	snaps  *SnapshotStore
	log    *slog.Logger
	now    func() time.Time

	mu    sync.RWMutex
	hints Hints
	hooks []SnapshotHook
	// gate admits the scheduled snapshot runs (SetGate): they read the
	// events of a whole window, like the other heavy jobs of the core.
	gate func(context.Context) (func(), error)

	// preview caches the live contract of the services without a snapshot
	// (GET /api/v1/contracts/{service}): inferring it reads the events.
	previewMu sync.Mutex
	preview   map[string]previewEntry
}

type previewEntry struct {
	c  *Contract
	at time.Time
}

// previewTTL is how long a live preview is reused; previewSampleCap bounds
// the events decoded per (op, status) group for it (exact counts still come
// from the summaries).
const (
	previewTTL       = 30 * time.Second
	previewSampleCap = 2000
)

// Preview is the live contract of one service over all stored events, as
// shown before its first snapshot: inferred with a smaller sample and kept
// for previewTTL. It returns nil when the service has no events.
func (e *Engine) Preview(ctx context.Context, service string) (*Contract, error) {
	return e.PreviewIn(ctx, nil, service)
}

// PreviewIn is Preview over the traffic of the selected groups only (nil:
// every group).
func (e *Engine) PreviewIn(ctx context.Context, groups groupscope.Set, service string) (*Contract, error) {
	key := strings.Join(groups, ",") + "\x1f" + service
	now := time.Now()
	e.previewMu.Lock()
	if p, ok := e.preview[key]; ok && now.Sub(p.at) < previewTTL {
		e.previewMu.Unlock()
		return p.c, nil
	}
	e.previewMu.Unlock()
	srcs, err := e.SourcesOf(ctx, groups)
	if err != nil {
		return nil, err
	}
	cfg := e.cfg
	cfg.SampleCap = min(cfg.SampleCap, previewSampleCap)
	cs, err := InferFromStore(ctx, e.src, InferOptions{Services: []string{service}, Sources: srcs, Config: cfg, Hints: e.Hints()})
	if err != nil {
		return nil, err
	}
	var c *Contract
	if len(cs) > 0 {
		c = cs[0]
		if len(groups) == 1 {
			c.Group = groups[0]
		}
	}
	e.previewMu.Lock()
	if e.preview == nil {
		e.preview = map[string]previewEntry{}
	}
	e.preview[key] = previewEntry{c: c, at: now}
	e.previewMu.Unlock()
	return c, nil
}

// dropPreview forgets the cached previews of a service (after a snapshot).
func (e *Engine) dropPreview(service string) {
	e.previewMu.Lock()
	for k := range e.preview {
		if strings.HasSuffix(k, "\x1f"+service) {
			delete(e.preview, k)
		}
	}
	e.previewMu.Unlock()
}

// sourceLister is implemented by event sources that know the sources of
// their events (*intake.Store).
type sourceLister interface {
	ServiceSources(ctx context.Context) (map[string][]string, error)
}

// GroupSources maps each group to the sources of the stored events (the
// sources no group claims are of group ""). Without a resolver it is
// {"": nil}: one group, every source.
func (e *Engine) GroupSources(ctx context.Context) (map[string][]string, error) {
	if e.groups == nil {
		return map[string][]string{"": nil}, nil
	}
	m, err := e.groups.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	if sl, ok := e.src.(sourceLister); ok {
		bySvc, err := sl.ServiceSources(ctx)
		if err != nil {
			return nil, err
		}
		for _, l := range bySvc {
			for _, id := range l {
				ids[id] = true
			}
		}
	} else {
		for id := range m {
			ids[id] = true
		}
	}
	out := map[string][]string{}
	for id := range ids {
		out[m[id]] = append(out[m[id]], id)
	}
	for _, l := range out {
		sort.Strings(l)
	}
	return out, nil
}

// ServiceGroups maps each stored service to the groups whose sources
// produced it (nil without a resolver).
func (e *Engine) ServiceGroups(ctx context.Context) (map[string][]string, error) {
	sl, ok := e.src.(sourceLister)
	if e.groups == nil || !ok {
		return nil, nil
	}
	m, err := e.groups.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	bySvc, err := sl.ServiceSources(ctx)
	if err != nil {
		return nil, err
	}
	return groupscope.ServiceGroups(bySvc, m), nil
}

// SourcesOf returns the sources of the selected groups (nil: every group, or
// no resolver; a non-nil empty slice when the groups have no source).
func (e *Engine) SourcesOf(ctx context.Context, groups groupscope.Set) ([]string, error) {
	if groups.All() || e.groups == nil {
		return nil, nil
	}
	m, err := e.groups.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	return groups.Sources(m), nil
}

// New creates an engine. The "contract" migrations are registered at init
// time, so db must be opened after this package is imported.
func New(cfg Config, d Deps) (*Engine, error) {
	cfg.setDefaults()
	if d.DB == nil || d.Events == nil {
		return nil, errors.New("contract: DB and Events are required")
	}
	e := &Engine{cfg: cfg, db: d.DB, src: d.Events, groups: d.Groups, snaps: NewSnapshotStore(d.DB), log: d.Logger, now: d.Now, hints: d.Hints}
	e.snaps.diff = cfg.Diff
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.hints == nil {
		e.hints = NoHints
	}
	return e, nil
}

// Config returns the effective configuration.
func (e *Engine) Config() Config { return e.cfg }

// Snapshots returns the snapshot store.
func (e *Engine) Snapshots() *SnapshotStore { return e.snaps }

// Events returns the event source.
func (e *Engine) Events() EventSource { return e.src }

// Hints returns the current hints.
func (e *Engine) Hints() Hints {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.hints
}

// SetHints replaces the hints (for example after a new policy is signed).
func (e *Engine) SetHints(h Hints) {
	if h == nil {
		h = NoHints
	}
	e.mu.Lock()
	e.hints = h
	e.mu.Unlock()
}

// OnSnapshot registers a hook called after each stored snapshot.
func (e *Engine) OnSnapshot(h SnapshotHook) {
	e.mu.Lock()
	e.hooks = append(e.hooks, h)
	e.mu.Unlock()
}

// RenderOptions returns the default render options for this engine.
func (e *Engine) RenderOptions() RenderOptions {
	return RenderOptions{IncludeRaw: e.cfg.IncludeRaw, Hints: e.Hints()}
}

// Live infers the contracts of the window without storing them. Zero window
// ends are open. services restricts the result (empty: all).
func (e *Engine) Live(ctx context.Context, w Window, services ...string) ([]*Contract, error) {
	return InferFromStore(ctx, e.src, InferOptions{From: w.From, To: w.To, Services: services, Config: e.cfg, Hints: e.Hints()})
}

// LiveIn infers the contracts of one group's traffic (Group set on each):
// what that group's sources sent and received, never another group's
// calls to the same service or host pattern.
func (e *Engine) LiveIn(ctx context.Context, w Window, group string, services ...string) ([]*Contract, error) {
	gs, err := e.GroupSources(ctx)
	if err != nil {
		return nil, err
	}
	srcs, ok := gs[group]
	if !ok {
		return nil, nil
	}
	cs, err := InferFromStore(ctx, e.src, InferOptions{From: w.From, To: w.To, Services: services, Sources: srcs, Config: e.cfg, Hints: e.Hints()})
	for _, c := range cs {
		c.Group = group
	}
	return cs, err
}

// SnapshotWindow infers and stores one snapshot per (group, service) seen in
// the window, then runs the hooks. Services without events are skipped.
func (e *Engine) SnapshotWindow(ctx context.Context, w Window, services ...string) ([]*Snapshot, error) {
	gs, err := e.GroupSources(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(gs))
	for g := range gs {
		names = append(names, g)
	}
	sort.Strings(names)
	var out []*Snapshot
	for _, g := range names {
		snaps, err := e.SnapshotWindowIn(ctx, w, g, services...)
		out = append(out, snaps...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// SnapshotWindowIn is SnapshotWindow for the traffic of one group.
func (e *Engine) SnapshotWindowIn(ctx context.Context, w Window, group string, services ...string) ([]*Snapshot, error) {
	cs, err := e.LiveIn(ctx, w, group, services...)
	if err != nil {
		return nil, err
	}
	e.mu.RLock()
	hooks := append([]SnapshotHook(nil), e.hooks...)
	e.mu.RUnlock()
	var out []*Snapshot
	for _, c := range cs {
		if len(c.Ops) == 0 {
			continue
		}
		snap, err := e.snaps.Save(ctx, c, e.now().UTC())
		if err != nil {
			return out, err
		}
		e.dropPreview(c.Service)
		prev, err := e.snaps.PreviousIn(ctx, c.Group, c.Service, snap.Seq())
		if err != nil && !errors.Is(err, ErrNotFound) {
			return out, err
		}
		br, nb := 0, 0
		if prev != nil {
			d := DiffOf(prev, snap, e.cfg.Diff)
			br, nb = d.Breaking, d.NonBreaking
		}
		if err := e.snaps.SetCounts(ctx, &snap.SnapshotInfo, br, nb); err != nil {
			return out, err
		}
		if err := e.snaps.PruneIn(ctx, c.Group, c.Service, e.cfg.KeepSnapshots); err != nil {
			e.log.WarnContext(ctx, "contract: prune snapshots", "service", c.Service, "err", err)
		}
		for _, h := range hooks {
			if err := h(ctx, prev, snap); err != nil {
				e.log.WarnContext(ctx, "contract: snapshot hook failed", "service", c.Service, "err", err)
			}
		}
		out = append(out, snap)
	}
	return out, nil
}

// LastCompletedWindow returns the newest window that ended at least Grace
// before now, aligned to multiples of the window length since the Unix epoch.
func (e *Engine) LastCompletedWindow(now time.Time) Window {
	ws := int64(e.cfg.Window / time.Second)
	if ws <= 0 {
		ws = 1
	}
	end := ((now.Add(-e.cfg.Grace).Unix()) / ws) * ws
	return Window{From: time.Unix(end-ws, 0).UTC(), To: time.Unix(end, 0).UTC()}
}

// SetGate makes every scheduled run (Run) wait for gate first; gate
// returns the function that ends the run's turn. Call it before Run.
func (e *Engine) SetGate(gate func(context.Context) (func(), error)) {
	e.mu.Lock()
	e.gate = gate
	e.mu.Unlock()
}

// runGated is RunOnce through the gate, if any.
func (e *Engine) runGated(ctx context.Context) error {
	e.mu.RLock()
	gate := e.gate
	e.mu.RUnlock()
	if gate != nil {
		release, err := gate(ctx)
		if err != nil {
			return err
		}
		defer release()
	}
	_, err := e.RunOnce(ctx)
	return err
}

// RunOnce snapshots the last completed window unless it already exists.
func (e *Engine) RunOnce(ctx context.Context) ([]*Snapshot, error) {
	w := e.LastCompletedWindow(e.now())
	if w.From.Unix() < 0 {
		return nil, nil
	}
	if ok, err := e.snaps.HasWindow(ctx, w); err != nil || ok {
		return nil, err
	}
	return e.SnapshotWindow(ctx, w)
}

// Run snapshots every completed window until ctx is done: once at start
// (catching up the last window) and then after each window boundary plus
// Grace.
func (e *Engine) Run(ctx context.Context) error {
	for {
		if err := e.runGated(ctx); err != nil && ctx.Err() == nil {
			e.log.ErrorContext(ctx, "contract: snapshot run failed", "err", err)
		}
		ws := e.cfg.Window
		now := e.now()
		next := time.Unix((now.Add(-e.cfg.Grace).Unix()/int64(ws/time.Second)+1)*int64(ws/time.Second), 0).Add(e.cfg.Grace)
		wait := next.Sub(now)
		if wait < time.Second {
			wait = time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// DiffSnapshots diffs two snapshots of a service: the older (by sequence) is
// the baseline.
func (e *Engine) DiffSnapshots(ctx context.Context, service, idA, idB string) (*DiffResult, error) {
	return e.DiffSnapshotsIn(ctx, "", service, idA, idB)
}

// DiffSnapshotsIn is DiffSnapshots for (group, service).
func (e *Engine) DiffSnapshotsIn(ctx context.Context, group, service, idA, idB string) (*DiffResult, error) {
	a, err := e.snaps.GetIn(ctx, group, service, idA)
	if err != nil {
		return nil, err
	}
	b, err := e.snaps.GetIn(ctx, group, service, idB)
	if err != nil {
		return nil, err
	}
	if a.Seq() > b.Seq() {
		a, b = b, a
	}
	return DiffOf(a, b, e.cfg.Diff), nil
}

// DiffOf builds the structured diff of two snapshots (older first).
func DiffOf(older, newer *Snapshot, cfg DiffConfig) *DiffResult {
	from, to := older.SnapshotInfo, newer.SnapshotInfo
	d := &DiffResult{Service: newer.Service, From: &from, To: &to, Changes: Diff(older.Contract, newer.Contract, cfg)}
	if d.Changes == nil {
		d.Changes = []Change{}
	}
	d.Count()
	return d
}
