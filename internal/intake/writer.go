package intake

import (
	"context"
	"database/sql"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/store"
)

// item is an accepted event on its way to the database. It holds the
// canonical bytes and the scalar columns, not the decoded tree, to keep the
// queue small.
type item struct {
	blob   []byte
	size   int64 // bytes reserved in the queue budget
	qver   uint64
	marker chan struct{} // barrier: closed when everything before it is committed

	tsMS          int64
	source        string
	policyID      string
	policyVersion int64
	epoch         string
	dir           int
	service       string
	op            string
	route         int
	status        int
	netError      string
	latencyMS     int64
	subject       string
	traceID       string
	spanID        string
	parentSpanID  string
	tokens        []event.HMACToken
}

func routeCode(rs string) int {
	switch rs {
	case event.RouteFramework:
		return 0
	case event.RoutePolicy:
		return 1
	}
	return 2
}

func newItem(ev *event.Event, blob []byte, qver uint64, withTokens bool) *item {
	it := &item{blob: blob, size: int64(len(blob)), qver: qver}
	it.fill(ev)
	if withTokens {
		ev.HMACTokens(func(t event.HMACToken) { it.tokens = append(it.tokens, t) })
	}
	return it
}

// fill sets the scalar columns from the event (also used after a rewrite).
func (it *item) fill(ev *event.Event) {
	it.tsMS = ev.Time.UnixMilli()
	it.source = ev.Source.ID
	it.policyID, it.policyVersion = ev.Policy.ID, ev.Policy.Version
	if ev.Dir == event.Outbound {
		it.dir = 1
	}
	it.service, it.op = ev.Service, ev.Op
	it.route = routeCode(ev.RouteSource)
	it.status, it.netError = ev.Status, ev.NetError
	it.latencyMS = ev.LatencyMS
	it.subject, it.traceID, it.spanID, it.parentSpanID = ev.Subject, ev.TraceID, ev.SpanID, ev.ParentSpanID
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// writer is the single goroutine that inserts events: one transaction per
// batch, prepared statements, token index and outbox in the same transaction.
type writer struct {
	in  *Intake
	db  *store.DB
	log *slog.Logger

	conn     *sql.Conn
	ch       chan *item
	quit     chan struct{}
	done     chan struct{}
	failing  atomic.Bool
	lastRcv  int64
	fields   map[string]int64
	rate     atomic.Uint64 // events per second, float bits
	outboxCh chan struct{}
}

const maxFieldDict = 50_000

func newWriter(in *Intake) *writer {
	return &writer{
		in: in, db: in.db, log: in.log,
		ch:       make(chan *item, in.cfg.QueueEvents+16),
		quit:     make(chan struct{}),
		done:     make(chan struct{}),
		fields:   map[string]int64{},
		outboxCh: make(chan struct{}, 1),
	}
}

func (w *writer) loadFields(ctx context.Context) error {
	rows, err := w.db.QueryContext(ctx, `SELECT id, field FROM intake_fields`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var f string
		if err := rows.Scan(&id, &f); err != nil {
			return err
		}
		w.fields[f] = id
	}
	return rows.Err()
}

func (w *writer) run() {
	defer close(w.done)
	// The writer owns one connection: a bigger page cache and a longer WAL
	// between checkpoints (per-connection settings) make batch commits much
	// cheaper than with the pool defaults.
	if conn, err := w.db.Conn(context.Background()); err == nil {
		defer conn.Close()
		for _, p := range []string{"PRAGMA cache_size = -65536", "PRAGMA wal_autocheckpoint = 8000"} {
			if _, err := conn.ExecContext(context.Background(), p); err != nil {
				w.log.Warn("intake: cannot tune the writer connection", "pragma", p, "error", err)
			}
		}
		w.conn = conn
	}
	batch := make([]*item, 0, w.in.cfg.BatchSize)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		var first *item
		select {
		case first = <-w.ch:
		case <-w.quit:
			// Drain what is left, then stop.
			for {
				select {
				case it := <-w.ch:
					batch = append(batch, it)
					if len(batch) >= w.in.cfg.BatchSize {
						w.commit(batch)
						batch = batch[:0]
					}
				default:
					w.commit(batch)
					return
				}
			}
		}
		batch = append(batch[:0], first)
		// Fill the batch: take what is there, wait briefly for more.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(w.in.cfg.BatchWait)
	fill:
		for len(batch) < w.in.cfg.BatchSize {
			select {
			case it := <-w.ch:
				batch = append(batch, it)
				if it.marker != nil {
					break fill
				}
			case <-timer.C:
				break fill
			case <-w.quit:
				break fill
			}
		}
		w.commit(batch)
		batch = batch[:0]
	}
}

// commit writes a batch, retrying transient failures, and releases the
// queue budget whatever the outcome.
func (w *writer) commit(batch []*item) {
	if len(batch) == 0 {
		return
	}
	start := time.Now()
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = w.write(batch)
		if err == nil {
			break
		}
		w.log.Error("intake: write batch failed", "attempt", attempt+1, "events", len(batch), "error", err)
		select {
		case <-time.After(time.Duration(attempt+1) * 200 * time.Millisecond):
		case <-w.quit:
			attempt = 3
		}
	}
	var evs, bytes int64
	for _, it := range batch {
		if it.marker != nil {
			close(it.marker)
			continue
		}
		evs++
		bytes += it.size
	}
	w.in.queued.Add(-evs)
	w.in.queuedBytes.Add(-bytes)
	if err != nil {
		w.failing.Store(true)
		w.in.stats.global.storageErrors.Add(uint64(evs))
		return
	}
	w.failing.Store(false)
	w.in.stats.global.stored.Add(uint64(evs))
	if d := time.Since(start).Seconds(); d > 0 && evs > 0 {
		cur := float64(evs) / d
		old := float64frombits(w.rate.Load())
		if old == 0 {
			old = cur
		}
		w.rate.Store(float64bits(0.7*old + 0.3*cur))
	}
	select {
	case w.outboxCh <- struct{}{}:
	default:
	}
}

const maxOutboxTokens = 50_000

var tokenInserts sync.Map // number of rows -> statement text

func tokenInsertSQL(n int) string {
	if v, ok := tokenInserts.Load(n); ok {
		return v.(string)
	}
	var sb strings.Builder
	sb.WriteString("INSERT OR IGNORE INTO intake_tokens (hour, token, event_id, field, ts_ms) VALUES ")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("(?,?,?,?,?)")
	}
	tokenInserts.Store(n, sb.String())
	return sb.String()
}

type tokRow struct {
	token string
	id    int64
	field int64
	ts    int64
}

func (w *writer) write(batch []*item) error {
	ctx := context.Background()
	newFields := map[string]int64{}
	err := w.inTx(ctx, func(tx *sql.Tx) error {
		for k := range newFields {
			delete(newFields, k)
		}
		stEv, err := tx.PrepareContext(ctx, `INSERT INTO intake_events
			(received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op, route_source,
			 status, net_error, latency_ms, subject, trace_id, span_id, parent_span_id, body)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stEv.Close()
		rcv := w.in.now().UnixMilli()
		if rcv < w.lastRcv {
			rcv = w.lastRcv
		}
		hour := rcv / 3_600_000
		perEpoch := map[string]map[string]struct{}{}
		var tokRows []tokRow
		agg := newAggDelta()
		snap := w.in.quar.snapshot()
		for _, it := range batch {
			if it.marker != nil {
				continue
			}
			if it.qver != snap.version {
				w.reapply(it, snap)
			}
			res, err := stEv.ExecContext(ctx, rcv, it.tsMS, it.source, it.policyID, it.policyVersion, it.dir, it.service, it.op, it.route,
				statusArg(it.status), nullStr(it.netError), it.latencyMS, nullStr(it.subject), nullStr(it.traceID), nullStr(it.spanID), nullStr(it.parentSpanID), it.blob)
			if err != nil {
				return err
			}
			// New rows always have ids above the backfill range: aggregate them now.
			agg.add(aggKey{service: it.service, op: it.op, status: it.status, source: it.source, policyID: it.policyID, dir: it.dir}, 1, it.tsMS, it.tsMS)
			if it.dir == 1 {
				agg.addLat(it.service, it.latencyMS, 1)
			}
			if len(it.tokens) == 0 {
				continue
			}
			id, err := res.LastInsertId()
			if err != nil {
				return err
			}
			for _, t := range it.tokens {
				if w.in.cfg.IndexTokens {
					fid, known := w.fields[t.Where]
					if !known {
						fid, known = newFields[t.Where]
					}
					if !known {
						if len(w.fields)+len(newFields) >= maxFieldDict {
							fid = 0
						} else {
							r, err := tx.ExecContext(ctx, `INSERT INTO intake_fields (field) VALUES (?)`, t.Where)
							if err != nil {
								return err
							}
							fid, _ = r.LastInsertId()
							newFields[t.Where] = fid
						}
					}
					tokRows = append(tokRows, tokRow{token: t.Token, id: id, field: fid, ts: it.tsMS})
				}
				if w.in.sink != nil {
					m := perEpoch[it.epoch]
					if m == nil {
						m = map[string]struct{}{}
						perEpoch[it.epoch] = m
					}
					m[t.Token] = struct{}{}
				}
			}
		}
		// Within a batch the hour is the same: inserting in key order touches
		// the pages of the index sequentially instead of randomly.
		sort.Slice(tokRows, func(i, j int) bool {
			a, b := &tokRows[i], &tokRows[j]
			if a.token != b.token {
				return a.token < b.token
			}
			if a.id != b.id {
				return a.id < b.id
			}
			return a.field < b.field
		})
		// Multi-row inserts: most of the cost of a small insert is the call.
		const perStmt = 100
		args := make([]any, 0, perStmt*5)
		for len(tokRows) > 0 {
			n := len(tokRows)
			if n > perStmt {
				n = perStmt
			}
			args = args[:0]
			for _, r := range tokRows[:n] {
				args = append(args, hour, r.token, r.id, r.field, r.ts)
			}
			if _, err := tx.ExecContext(ctx, tokenInsertSQL(n), args...); err != nil {
				return err
			}
			tokRows = tokRows[n:]
		}
		for epoch, set := range perEpoch {
			toks := make([]string, 0, len(set))
			for t := range set {
				toks = append(toks, t)
			}
			for len(toks) > 0 {
				n := len(toks)
				if n > maxOutboxTokens {
					n = maxOutboxTokens
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO intake_outbox (epoch, tokens) VALUES (?, ?)`, epoch, strings.Join(toks[:n], "\n")); err != nil {
					return err
				}
				toks = toks[n:]
			}
		}
		if err := agg.apply(ctx, tx); err != nil {
			return err
		}
		w.lastRcv = rcv
		return nil
	})
	if err == nil {
		for k, v := range newFields {
			w.fields[k] = v
		}
	}
	return err
}

// inTx runs fn in a write transaction on the writer's own connection.
func (w *writer) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if w.conn == nil {
		return w.db.InTx(ctx, fn)
	}
	tx, err := w.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func statusArg(s int) any {
	if s == 0 {
		return nil
	}
	return s
}

// reapply re-checks an item queued before the active quarantines changed.
func (w *writer) reapply(it *item, snap *qSnapshot) {
	it.qver = snap.version
	ev, derr := event.Decode(it.blob)
	if derr != nil {
		return // cannot happen: the blob was produced by the encoder
	}
	if applyQuarantine(ev, snap) {
		it.blob = ev.AppendCanonicalNoDisc(nil)
		it.fill(ev)
	}
}

func (w *writer) stop() {
	select {
	case <-w.quit:
	default:
		close(w.quit)
	}
	<-w.done
}

// barrier returns once every item enqueued before the call is committed.
func (w *writer) barrier(ctx context.Context) error {
	m := &item{marker: make(chan struct{})}
	select {
	case w.ch <- m:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-m.marker:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return nil
	}
}

// ---------------------------------------------------------------------------
// Outbox feeder: at-least-once delivery of tokens to keyguard.

type outboxFeeder struct {
	in   *Intake
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

func (f *outboxFeeder) run(wakeFrom <-chan struct{}) {
	defer close(f.done)
	t := time.NewTicker(f.in.cfg.OutboxInterval)
	defer t.Stop()
	backoff := time.Duration(0)
	for {
		select {
		case <-f.quit:
			f.drain(context.Background())
			return
		case <-wakeFrom:
		case <-t.C:
		}
		if backoff > 0 {
			select {
			case <-time.After(backoff):
			case <-f.quit:
				return
			}
		}
		if err := f.drain(context.Background()); err != nil {
			f.in.log.Warn("intake: token delivery to keyguard failed", "error", err)
			if backoff == 0 {
				backoff = f.in.cfg.OutboxInterval
			} else if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = 0
		}
	}
}

// drain delivers pending outbox rows in order, stopping at the first failure.
func (f *outboxFeeder) drain(ctx context.Context) error {
	if f.in.sink == nil {
		return nil
	}
	for {
		rows, err := f.in.db.QueryContext(ctx, `SELECT id, epoch, tokens FROM intake_outbox ORDER BY id LIMIT 20`)
		if err != nil {
			return err
		}
		type row struct {
			id     int64
			epoch  string
			tokens string
		}
		var batch []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.epoch, &r.tokens); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if len(batch) == 0 {
			return nil
		}
		for _, r := range batch {
			if err := f.in.sink.AddTokens(ctx, r.epoch, strings.Split(r.tokens, "\n")); err != nil {
				return err
			}
			if _, err := f.in.db.ExecContext(ctx, `DELETE FROM intake_outbox WHERE id = ?`, r.id); err != nil {
				return err
			}
		}
	}
}

func (f *outboxFeeder) stop() {
	f.once.Do(func() { close(f.quit) })
	<-f.done
}
