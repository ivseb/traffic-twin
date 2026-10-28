package intake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Deps are the collaborators of an [Intake].
type Deps struct {
	// DB is the database opened with store.Open (so that this package's
	// migrations, registered in init, have been applied).
	DB *store.DB
	// Sources resolves the identity and group of enrolled sources (fleet).
	Sources SourceRegistry
	// Policies resolves signed policies by hash (fleet / policy).
	Policies PolicyRegistry
	// Tokens receives the real HMAC tokens for keyguard's Bloom filter.
	// Optional; without it tokens are only indexed locally.
	Tokens TokenSink
	// Alarms is told about new quarantines. Optional.
	Alarms AlarmSink
	// Audit records quarantine alarms in the audit log. Optional.
	Audit *audit.Log
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now defaults to time.Now (tests inject a clock).
	Now func() time.Time
}

// Intake receives sanitized events over OTLP/HTTP JSON, rejects everything
// the specification says to reject, watches the cardinality of what leaves
// in clear, and stores what is accepted.
type Intake struct {
	cfg      Config
	db       *store.DB
	sources  SourceRegistry
	policies PolicyRegistry
	sink     TokenSink
	alarms   AlarmSink
	audit    *audit.Log
	log      *slog.Logger
	now      func() time.Time

	store    *Store
	monitors *monitorSet
	quar     *quarantineManager
	stats    *statsRegistry
	dup      *doubleCapture
	writer   *writer
	feeder   *outboxFeeder

	queued      atomic.Int64
	queuedBytes atomic.Int64
	retention   atomic.Int64

	rewriteCh chan int64
	bgCtx     context.Context
	bgCancel  context.CancelFunc
	wg        sync.WaitGroup
	closed    atomic.Bool
	closeOnce sync.Once
}

// New creates the intake, loads its persisted state (quarantines,
// sketches, counters) and starts its background goroutines. Call Close to
// stop it.
func New(ctx context.Context, cfg Config, d Deps) (*Intake, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if d.DB == nil || d.Sources == nil || d.Policies == nil {
		return nil, errors.New("intake: DB, Sources and Policies are required")
	}
	in := &Intake{
		cfg: cfg, db: d.DB, sources: d.Sources, policies: d.Policies, sink: d.Tokens, alarms: d.Alarms, audit: d.Audit,
		log: d.Logger, now: d.Now,
		rewriteCh: make(chan int64, 1024),
	}
	if in.log == nil {
		in.log = slog.Default()
	}
	if in.now == nil {
		in.now = time.Now
	}
	in.retention.Store(int64(cfg.Retention))
	in.store = NewStore(d.DB)
	in.monitors = newMonitorSet(&in.cfg)
	in.quar = newQuarantineManager(d.DB)
	in.stats = newStats()
	in.dup = newDoubleCapture()
	in.writer = newWriter(in)
	in.feeder = &outboxFeeder{in: in, quit: make(chan struct{}), done: make(chan struct{})}
	in.bgCtx, in.bgCancel = context.WithCancel(context.Background())

	if err := in.quar.load(ctx); err != nil {
		return nil, fmt.Errorf("intake: load quarantines: %w", err)
	}
	if err := in.loadSketches(ctx); err != nil {
		return nil, fmt.Errorf("intake: load sketches: %w", err)
	}
	for _, q := range in.quar.list(false) {
		in.monitors.mark(q.Kind.obs(), q.Key)
	}
	if err := in.stats.load(ctx, d.DB); err != nil {
		return nil, fmt.Errorf("intake: load counters: %w", err)
	}
	if err := in.writer.loadFields(ctx); err != nil {
		return nil, fmt.Errorf("intake: load field dictionary: %w", err)
	}

	go in.writer.run()
	in.wg.Add(4)
	go func() { defer in.wg.Done(); in.backfillAggregates() }()
	go func() { defer in.wg.Done(); in.feeder.run(in.writer.outboxCh) }()
	go func() { defer in.wg.Done(); in.rewriteLoop() }()
	go func() { defer in.wg.Done(); in.housekeeping() }()

	// Finish rewrites interrupted by a restart.
	rows, err := in.db.QueryContext(ctx, `SELECT id FROM intake_quarantine WHERE rewrite_done = 0 AND state <> 'released'`)
	if err == nil {
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				in.scheduleRewrite(id)
			}
		}
		rows.Close()
	}
	return in, nil
}

// Store returns the read side of the event storage.
func (in *Intake) Store() *Store { return in.store }

// Config returns the effective configuration.
func (in *Intake) Config() Config { return in.cfg }

// SetRetention changes the retention at run time (admin API).
func (in *Intake) SetRetention(d time.Duration) {
	if d > 0 {
		in.retention.Store(int64(d))
		in.monitors.retention.Store(int64(d))
	}
}

// Retention returns the current retention.
func (in *Intake) Retention() time.Duration { return time.Duration(in.retention.Load()) }

// Close stops accepting events, writes what is queued, delivers pending
// tokens when possible, persists the state and stops the goroutines.
func (in *Intake) Close(ctx context.Context) error {
	var err error
	in.closeOnce.Do(func() {
		in.closed.Store(true)
		in.writer.stop()
		in.feeder.stop()
		in.bgCancel()
		in.wg.Wait()
		err = in.Flush(ctx)
	})
	return err
}

// WaitIdle blocks until every queued event is committed (or ctx ends).
func (in *Intake) WaitIdle(ctx context.Context) error {
	return in.writer.barrier(ctx)
}

// ---------------------------------------------------------------------------
// Ingestion

// unsafeBytes views a string as bytes without copying. The event decoder and
// the writer never modify them, and the string stays alive while referenced.
func unsafeBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func rejectOf(e *event.DecodeError) Reject {
	switch e.Code {
	case event.CodeJSON:
		return Reject{ReasonJSON, e.Detail}
	case event.CodeNonCanonical:
		return Reject{ReasonNonCanonical, e.Detail}
	}
	return Reject{ReasonSchema, e.Detail}
}

// ingest runs the checks of docs/spec/event.md 5.1 on one event body and, if
// they all pass, applies the active quarantines and queues the event for
// storage. The caller must have reserved queue capacity. cross (optional)
// lets the transport layer compare envelope fields with the decoded event.
func (in *Intake) ingest(ctx context.Context, src *SourceInfo, raw string, cross func(*event.Event) Reject) Reject {
	if len(raw) > in.cfg.MaxEventBytes {
		return Reject{ReasonTooLarge, "event larger than 512 KiB"}
	}
	b := unsafeBytes(raw)
	ev, derr := event.Decode(b)
	if derr != nil {
		return rejectOf(derr)
	}
	if cross != nil {
		if r := cross(ev); r.Reason != ReasonNone {
			return r
		}
	}
	if ev.Source.ID != src.ID {
		return Reject{ReasonSourceMismatch, "source.id differs from the certificate identity"}
	}
	pol, ok := in.policies.LookupPolicy(ev.Policy.Hash)
	if !ok {
		return Reject{ReasonPolicyUnknown, "policy hash is not a known signed policy"}
	}
	if pol.ID != ev.Policy.ID || pol.Version != ev.Policy.Version {
		return Reject{ReasonPolicyMismatch, "policy id or version differ from the policy with that hash"}
	}
	if !pol.TargetsGroup(src.Group) {
		return Reject{ReasonPolicyGroup, "policy not assigned to the group of the source"}
	}

	c := checkerPool.Get().(*checker)
	defer func() {
		// Keep the buffers, drop references to the event and the policy.
		*c = checker{obs: c.obs, base: c.base[:0], prefix: c.prefix[:0], steps: c.steps[:0]}
		checkerPool.Put(c)
	}()
	c.cfg, c.pol, c.src, c.ev = &in.cfg, pol, src, ev
	if !c.run() {
		return c.rej
	}
	raised, overflow := in.monitors.observe(&c.obs, in.now())
	for _, n := range raised {
		in.raiseQuarantine(ctx, n)
	}
	if overflow {
		return Reject{ReasonMonitorOverflow, "too many distinct fields to watch"}
	}

	snap := in.quar.snapshot()
	changed := applyQuarantine(ev, snap)
	if lg, ok := graphql.SplitEvent(ev); ok {
		// event.md 6: a GraphQL exchange is stored under its logical op.
		ev.Op = lg.Op
		changed = true
	} else if name, ok := ev.SOAPOperation(); ok && event.HTTPOp(ev.Op) == ev.Op {
		// event.md 6 (spec v1.19): so is a SOAP exchange, by operation name.
		ev.Op += "#" + name
		changed = true
	}
	blob := b
	if changed || len(ev.Disc) > 0 {
		blob = ev.AppendCanonicalNoDisc(make([]byte, 0, len(b)))
	}
	in.dup.observe(ev, in.now())
	it := newItem(ev, blob, snap.version, in.cfg.IndexTokens || in.sink != nil)
	it.epoch = pol.Epoch
	it.size = int64(len(raw)) // what the caller reserved for this event
	in.writer.ch <- it        // capacity was reserved: never blocks
	return Reject{}
}

// IngestEvent is the transport-independent entry point: it checks one event
// body received from the source with the given enrollment id (the identity
// of the client certificate) and queues it. It reserves queue capacity
// itself and returns [ErrOverloaded] when the queue is full. A zero Reject
// means the event was accepted.
func (in *Intake) IngestEvent(ctx context.Context, sourceID string, body []byte) (Reject, error) {
	src, ok := in.sources.LookupSource(sourceID)
	if !ok || src.Revoked {
		return Reject{}, ErrUnknownSource
	}
	if !in.reserve(1, int64(len(body))) {
		return Reject{}, ErrOverloaded
	}
	c := in.stats.source(src.ID)
	rej := in.ingest(ctx, &src, string(body), nil)
	if rej.Reason != ReasonNone {
		in.release(1, int64(len(body)))
		in.countReject(c, rej.Reason)
		return rej, nil
	}
	// Accepted: the writer releases the reservation once committed.
	c.accepted.Add(1)
	c.dirty.Store(true)
	return Reject{}, nil
}

// Errors of the ingestion API.
var (
	ErrOverloaded    = errors.New("intake: ingestion queue full")
	ErrUnknownSource = errors.New("intake: unknown or revoked source")
)

// rejectLogEvery is the least time between two log lines for the same
// source and rejection reason.
const rejectLogEvery = time.Minute

func (in *Intake) countReject(c *srcCounters, r Reason) {
	n := c.rejected[r].Add(1)
	c.dirty.Store(true)
	c.recent.add(r, in.now())
	now := time.Now().UnixMilli()
	if last := c.warnedAt[r].Load(); now-last >= rejectLogEvery.Milliseconds() && c.warnedAt[r].CompareAndSwap(last, now) {
		// Reason code and count only: never the value that was rejected.
		in.log.Warn("intake: events rejected", "source", c.id, "reason", r.String(), "total", n)
	}
}

// reserve takes queue capacity for n events and bytes bytes.
func (in *Intake) reserve(n int, bytes int64) bool {
	for {
		q := in.queued.Load()
		if q+int64(n) > int64(in.cfg.QueueEvents) || in.queuedBytes.Load()+bytes > in.cfg.QueueBytes {
			return false
		}
		if in.queued.CompareAndSwap(q, q+int64(n)) {
			in.queuedBytes.Add(bytes)
			return true
		}
	}
}

// release gives back unused capacity.
func (in *Intake) release(n int, bytes int64) {
	if n != 0 {
		in.queued.Add(-int64(n))
	}
	if bytes != 0 {
		in.queuedBytes.Add(-bytes)
	}
}

// full is the cheap pre-check done before reading a request.
func (in *Intake) full() bool {
	return in.queued.Load() >= int64(in.cfg.QueueEvents) || in.queuedBytes.Load() >= in.cfg.QueueBytes
}

// retryAfter estimates, in seconds, how long until the queue has room.
func (in *Intake) retryAfter() int {
	rate := float64frombits(in.writer.rate.Load())
	if rate < 1 {
		rate = 100
	}
	s := int(math.Ceil(float64(in.queued.Load()) / rate))
	if s < 1 {
		s = 1
	}
	if s > 30 {
		s = 30
	}
	return s
}

// ---------------------------------------------------------------------------
// Quarantine

func (in *Intake) raiseQuarantine(ctx context.Context, n newQuarantine) {
	q, err := in.quar.raise(ctx, n, in.now())
	if err != nil {
		in.log.Error("intake: cannot record quarantine", "error", err)
		return
	}
	in.log.Warn("intake: element quarantined", "id", q.ID, "kind", q.Kind, "estimate", q.Estimate, "threshold", q.Threshold)
	if in.audit != nil {
		_, err := in.audit.Record(ctx, audit.Event{
			Actor:   audit.Actor{Kind: audit.ActorSystem, ID: "intake", Name: "intake"},
			Action:  "intake.quarantine",
			Target:  audit.Target{Type: "quarantine", ID: strconv.FormatInt(q.ID, 10)},
			Outcome: audit.Success,
			Reason:  "threshold_exceeded",
			Details: map[string]string{
				"kind":      string(q.Kind),
				"estimate":  strconv.Itoa(q.Estimate),
				"threshold": strconv.Itoa(q.Threshold),
			},
		})
		if err != nil {
			in.log.Error("intake: cannot audit quarantine", "error", err)
		}
	}
	if in.alarms != nil {
		in.alarms.QuarantineRaised(ctx, q)
	}
	in.scheduleRewrite(q.ID)
}

func (in *Intake) scheduleRewrite(id int64) {
	select {
	case in.rewriteCh <- id:
	default:
		go func() {
			select {
			case in.rewriteCh <- id:
			case <-in.bgCtx.Done():
			}
		}()
	}
}

// Quarantines lists the quarantined elements (released ones only when
// includeReleased).
func (in *Intake) Quarantines(includeReleased bool) []Quarantine {
	return in.quar.list(includeReleased)
}

// CloseQuarantine marks a quarantine as closed by a policy change that
// closes the field (1 approval, policy.md section 5). The rewrite of stored
// and future values stays in force; only [Intake.ReleaseQuarantine] lifts it.
func (in *Intake) CloseQuarantine(ctx context.Context, id int64) (Quarantine, error) {
	return in.quar.setState(ctx, id, []QuarantineState{StateOpen}, StateClosed, in.now())
}

// ReleaseQuarantine dissolves a quarantine (counts as opening data: 2
// approvals, enforced by the caller). Counting restarts from zero; values
// already rewritten stay rewritten.
func (in *Intake) ReleaseQuarantine(ctx context.Context, id int64) (Quarantine, error) {
	q, err := in.quar.setState(ctx, id, []QuarantineState{StateOpen, StateClosed}, StateReleased, in.now())
	if err != nil {
		return q, err
	}
	in.monitors.forget(q.Kind.obs(), q.Key)
	_, err = in.db.ExecContext(ctx, `DELETE FROM intake_sketch WHERE kind = ? AND skey = ?`, int(q.Kind.obs()), q.Key)
	return q, err
}

// Discovery returns the estimated distinct counts per field gathered in
// discovery mode for a policy id ("" for all policies).
func (in *Intake) Discovery(policyID string) []DiscField { return in.monitors.discFields(policyID) }

// DiscoveryUnion returns the discovery sketches of a policy merged by the
// operation key opOf gives to each (service, op) of the sketches: the
// distinct estimates of the union (the policy assistant merges raw paths
// into operation templates). Sketches whose op is rejected are skipped.
func (in *Intake) DiscoveryUnion(policyID string, opOf func(service, op string) (string, bool)) []DiscField {
	return in.monitors.discUnion(policyID, opOf)
}

// ---------------------------------------------------------------------------
// Rewrite of stored events

func (in *Intake) rewriteLoop() {
	for {
		select {
		case id := <-in.rewriteCh:
			if err := in.runRewrite(in.bgCtx, id); err != nil && in.bgCtx.Err() == nil {
				in.log.Error("intake: rewriting stored events failed", "quarantine", id, "error", err)
			}
		case <-in.bgCtx.Done():
			return
		}
	}
}

func (in *Intake) runRewrite(ctx context.Context, id int64) error {
	q, ok := in.quar.get(id)
	if !ok || q.State == StateReleased {
		return nil
	}
	var startMax sql.NullInt64
	if err := in.db.QueryRowContext(ctx, `SELECT max(id) FROM intake_events`).Scan(&startMax); err != nil {
		return err
	}
	if _, err := in.rewritePass(ctx, q, 0, startMax.Int64); err != nil {
		return err
	}
	// Events whose item was queued before the quarantine existed are
	// re-checked by the writer; the barrier waits for them to be committed
	// and the second pass covers everything committed meanwhile.
	if err := in.writer.barrier(ctx); err != nil {
		return err
	}
	if _, err := in.rewritePass(ctx, q, startMax.Int64, math.MaxInt64); err != nil {
		return err
	}
	in.scrub(ctx)
	_, err := in.db.ExecContext(ctx, `UPDATE intake_quarantine SET rewrite_done = 1 WHERE id = ?`, id)
	return err
}

// scrub empties the write-ahead log, so that the page images that still hold
// rewritten or deleted values do not outlive the change (the database
// overwrites freed pages, secure_delete, but the log keeps old images until
// it is checkpointed).
func (in *Intake) scrub(ctx context.Context) {
	if _, err := in.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil && ctx.Err() == nil {
		in.log.Warn("intake: cannot truncate the write-ahead log", "error", err)
	}
}

// candidateIDs selects the stored events a quarantine can affect.
func (in *Intake) candidateIDs(ctx context.Context, q Quarantine, after, upTo int64) ([]int64, error) {
	where := "id > ? AND id <= ?"
	args := []any{after, upTo}
	svcCond := func(service string) {
		if service == "host:*" {
			where += " AND service >= 'host:' AND service < 'host;'"
		} else {
			where += " AND service = ?"
			args = append(args, service)
		}
	}
	switch q.Kind {
	case QuarantineKeep, QuarantineName:
		where += " AND policy_id = ?"
		args = append(args, q.PolicyID)
		svcCond(q.Service)
		if q.Op == rawOpKey {
			where += " AND route_source = 2"
		} else {
			where += " AND op = ?"
			args = append(args, q.Op)
		}
	case QuarantineSegment:
		svcCond(q.Service)
		where += " AND route_source = 2 AND op >= ? AND op < ?"
		args = append(args, q.Method+" /", q.Method+" 0")
	case QuarantineHost:
		where += " AND service >= 'host:' AND service < 'host;' AND source_id = ?"
		args = append(args, q.SourceID)
	case QuarantineHostLabel:
		where += " AND service >= 'host:' AND service < 'host;'"
	}
	rows, err := in.db.QueryContext(ctx, "SELECT id FROM intake_events WHERE "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (in *Intake) rewritePass(ctx context.Context, q Quarantine, after, upTo int64) (int64, error) {
	ids, err := in.candidateIDs(ctx, q, after, upTo)
	if err != nil {
		return 0, err
	}
	var changed int64
	for len(ids) > 0 {
		n := in.cfg.RewriteChunk
		if n > len(ids) {
			n = len(ids)
		}
		chunk := ids[:n]
		ids = ids[n:]
		snap := in.quar.snapshot()
		err := in.db.InTx(ctx, func(tx *sql.Tx) error {
			cur, err := readAggCursor(ctx, tx)
			if err != nil {
				return err
			}
			rolled, err := readRollupCursor(ctx, tx)
			if err != nil {
				return err
			}
			agg := newAggDelta()
			for _, id := range chunk {
				var body []byte
				var old aggKey
				var ts int64
				if err := tx.QueryRowContext(ctx, `SELECT body, service, op, coalesce(status, 0), source_id, policy_id, dir, ts_ms FROM intake_events WHERE id = ?`, id).
					Scan(&body, &old.service, &old.op, &old.status, &old.source, &old.policyID, &old.dir, &ts); err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						continue // purged meanwhile
					}
					return err
				}
				ev, derr := event.Decode(body)
				if derr != nil {
					continue
				}
				if !applyQuarantine(ev, snap) {
					continue
				}
				if _, err := tx.ExecContext(ctx, `UPDATE intake_events SET body = ?, service = ?, op = ? WHERE id = ?`,
					ev.AppendCanonicalNoDisc(nil), ev.Service, ev.Op, id); err != nil {
					return err
				}
				if cur.covers(id) && (ev.Service != old.service || ev.Op != old.op) {
					nk := old
					nk.service, nk.op = ev.Service, ev.Op
					agg.add(old, -1, ts, ts)
					agg.add(nk, 1, ts, ts)
					if old.dir == 1 && ev.Service != old.service {
						agg.addLat(old.service, ev.LatencyMS, -1)
						agg.addLat(ev.Service, ev.LatencyMS, 1)
					}
				}
				// Already in the rollups: move it there too (rollup.go).
				if id < rolled && (ev.Service != old.service || ev.Op != old.op) {
					if err := rollupMove(ctx, tx, old, ev.Service, ev.Op, ts, ev.LatencyMS); err != nil {
						return err
					}
				}
				changed++
			}
			return agg.apply(ctx, tx)
		})
		if err != nil {
			return changed, err
		}
		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
	}
	return changed, nil
}

// ---------------------------------------------------------------------------
// Persistence and retention

func (in *Intake) loadSketches(ctx context.Context) error {
	rows, err := in.db.QueryContext(ctx, `SELECT kind, skey, day, data FROM intake_sketch`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind int
		var key string
		var day int64
		var data []byte
		if err := rows.Scan(&kind, &key, &day, &data); err != nil {
			return err
		}
		h, err := UnmarshalHLL(data)
		if err != nil || kind < int(obsKeep) || kind >= numObsKinds {
			continue
		}
		in.monitors.restore(obsKind(kind), key, day, h)
	}
	return rows.Err()
}

// Flush persists sketches and per-source counters now.
func (in *Intake) Flush(ctx context.Context) error {
	rows := in.monitors.takeDirty()
	return in.db.InTx(ctx, func(tx *sql.Tx) error {
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO intake_sketch (kind, skey, day, data) VALUES (?, ?, ?, ?)
				ON CONFLICT (kind, skey, day) DO UPDATE SET data = excluded.data`, int(r.kind), r.key, r.day, r.data); err != nil {
				return err
			}
		}
		return in.stats.flush(ctx, tx)
	})
}

// Purge applies the retention now: events received before now-retention and
// the matching token index partitions and old sketches are deleted.
func (in *Intake) Purge(ctx context.Context) (PurgeResult, error) {
	cutoff := in.now().Add(-in.Retention())
	in.monitors.purgeOld(in.now())
	res, err := in.store.PurgeBefore(ctx, cutoff)
	if err == nil && (res.Events > 0 || res.Tokens > 0) {
		in.scrub(ctx)
	}
	return res, err
}

func (in *Intake) housekeeping() {
	flush := time.NewTicker(in.cfg.FlushInterval)
	purge := time.NewTicker(in.cfg.PurgeInterval)
	defer flush.Stop()
	defer purge.Stop()
	for {
		select {
		case <-flush.C:
			if err := in.Flush(in.bgCtx); err != nil && in.bgCtx.Err() == nil {
				in.log.Error("intake: persisting state failed", "error", err)
			}
		case <-purge.C:
			res, err := in.Purge(in.bgCtx)
			if err != nil && in.bgCtx.Err() == nil {
				in.log.Error("intake: retention purge failed", "error", err)
			} else if err == nil && (res.Events > 0 || res.Tokens > 0) {
				in.log.Info("intake: retention purge", "events", res.Events, "tokens", res.Tokens, "reclaimed_bytes", res.Reclaimed)
				if res.ReclaimNote != "" {
					in.log.Warn("intake: space not reclaimed", "note", res.ReclaimNote)
				}
			}
		case <-in.bgCtx.Done():
			return
		}
	}
}
