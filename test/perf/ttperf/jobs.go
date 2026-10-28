package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/store"
)

type jobResp struct {
	JobID  string         `json:"job_id"`
	Status string         `json:"status"`
	Result map[string]any `json:"result"`
	Error  any            `json:"error"`
}

// waitJob polls a job until it is no longer running.
func (h *harness) waitJob(j *jobResp, limit time.Duration) error {
	for deadline := time.Now().Add(limit); j.Status == "running"; {
		if time.Now().After(deadline) {
			return errors.New("job still running")
		}
		time.Sleep(50 * time.Millisecond)
		if err := h.admin.json(200, "GET", "/api/v1/jobs/"+j.JobID, nil, j); err != nil {
			return err
		}
	}
	if j.Status != "done" {
		return fmt.Errorf("job %s: %v", j.Status, j.Error)
	}
	return nil
}

func (h *harness) postJob(path string, body any) (*jobResp, error) {
	var j jobResp
	code, b, _, err := h.admin.do("POST", path, body)
	if err != nil {
		return nil, err
	}
	if code != 202 && code != 200 && code != 201 {
		return nil, fmt.Errorf("POST %s = %d: %.300s", path, code, b)
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, h.waitJob(&j, 30*time.Minute)
}

func (h *harness) services() []string {
	in, out, hosts := h.serviceNames()
	all := append(append(in, out...), hosts...)
	return all
}

// firstJobs runs the analysis that a live installation would have run: a
// contract snapshot per service, mining, approval of the rules, archetypes,
// worlds, a pack.
func (h *harness) firstJobs(ctx context.Context) error {
	in, out, _ := h.serviceNames()
	h.job("contract.snapshot.all_services", func() (map[string]any, error) {
		var worst float64
		var worstSvc string
		n := 0
		for _, s := range append(append([]string{}, in...), out...) {
			code, b, d, err := h.admin.do("POST", "/api/v1/contracts/"+url.PathEscape(s)+"/snapshots", nil)
			if err != nil {
				return nil, err
			}
			if code != 201 && code != 404 {
				return nil, fmt.Errorf("snapshot %s = %d: %.200s", s, code, b)
			}
			n++
			if ms := d.Seconds() * 1000; ms > worst {
				worst, worstSvc = ms, s
			}
		}
		return map[string]any{"services": n, "max_ms": worst, "max_service": worstSvc}, nil
	})
	h.job("rules.mine.first", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/rules/mine", nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"events": j.Result["events"], "new": count(j.Result["new"])}, nil
	})
	var drafts []map[string]any
	if err := h.admin.json(200, "GET", "/api/v1/rules?status=draft", nil, &drafts); err != nil {
		return err
	}
	for _, r := range drafts {
		_ = h.admin.json(200, "POST", "/api/v1/rules/"+fmt.Sprint(r["id"])+"/approve", nil, nil)
	}
	h.job("archetypes.build", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/archetypes/build", map[string]any{"k_min": 20})
		if err != nil {
			return nil, err
		}
		return map[string]any{"archetypes": count(j.Result["archetypes"])}, nil
	})
	h.job("worlds.generate", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/worlds", map[string]any{"seed": 42, "customers": 200})
		if err != nil {
			return nil, err
		}
		h.ids["world"] = fmt.Sprint(j.Result["world_id"])
		return map[string]any{"world_id": h.ids["world"]}, nil
	})
	h.job("pack.build", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/packs", map[string]any{"world_id": h.ids["world"]})
		if err != nil {
			return nil, err
		}
		h.ids["pack"] = fmt.Sprint(j.Result["pack_id"])
		return map[string]any{"pack_id": h.ids["pack"], "status": j.Result["status"]}, nil
	})
	if h.ids["pack"] != "" {
		if err := h.admin.json(200, "POST", "/api/v1/packs/"+h.ids["pack"]+"/publish", map[string]any{"reason": "perf harness"}, nil); err != nil {
			return err
		}
	}
	h.job("export.wiremock", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/exports", map[string]any{"pack_id": h.ids["pack"], "target": "wiremock"})
		if err != nil {
			return nil, err
		}
		h.ids["export"] = fmt.Sprint(j.Result["export_id"])
		return nil, nil
	})
	var wh struct {
		ID string `json:"webhook_id"`
	}
	if err := h.admin.json(201, "POST", "/api/v1/webhooks", map[string]any{"name": "perf", "url": h.hook.URL + "/fast",
		"events": []string{"contract.drift"}}, &wh); err != nil {
		return err
	}
	h.ids["webhook"] = wh.ID
	// One source of each kind for the detail endpoints.
	h.ids["service"] = in[0]
	return nil
}

func count(x any) int {
	switch v := x.(type) {
	case []any:
		return len(v)
	case float64:
		return int(v)
	case map[string]any:
		return len(v)
	}
	return 0
}

// history adds, with plain SQL on a second connection, what a year of use
// leaves behind: daily contract snapshots, many rules, resolved alerts,
// webhook deliveries, worlds and packs (copies of the real rows).
func (h *harness) history(ctx context.Context) error {
	db, err := store.OpenWith(ctx, h.dbPath(), store.NewRegistry())
	if err != nil {
		return err
	}
	defer db.Close()
	day := int64(24 * time.Hour / time.Millisecond)
	// Snapshots: for each service, SnapshotDays-1 older windows, then the
	// real latest is re-inserted so that it keeps the highest id.
	rows, err := db.QueryContext(ctx, `SELECT id, service FROM contract_snapshots WHERE id IN (SELECT max(id) FROM contract_snapshots GROUP BY service)`)
	if err != nil {
		return err
	}
	type latest struct {
		id  int64
		svc string
	}
	var ls []latest
	for rows.Next() {
		var l latest
		_ = rows.Scan(&l.id, &l.svc)
		ls = append(ls, l)
	}
	rows.Close()
	cols := `service, window_from_ms, window_to_ms, created_ms, ops, calls, hash, model, breaking, non_breaking`
	for _, l := range ls {
		err := db.InTx(ctx, func(tx *sql.Tx) error {
			for _, q := range []string{
				`CREATE TEMP TABLE IF NOT EXISTS perf_snap AS SELECT * FROM contract_snapshots WHERE 0`,
				`DELETE FROM temp.perf_snap`,
			} {
				if _, err := tx.ExecContext(ctx, q); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO temp.perf_snap SELECT * FROM contract_snapshots WHERE id = ?`, l.id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM contract_snapshots WHERE id = ?`, l.id); err != nil {
				return err
			}
			for d := int64(h.sc.SnapshotDays - 1); d >= 1; d-- {
				if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO contract_snapshots (`+cols+`)
					SELECT service, window_from_ms - ?, window_to_ms - ?, created_ms - ?, ops, calls, hash || ?, model, 0, 0
					FROM temp.perf_snap`, d*day, d*day, d*day, fmt.Sprint(d)); err != nil {
					return err
				}
			}
			// The real latest last: it keeps the highest id.
			_, err := tx.ExecContext(ctx, `INSERT INTO contract_snapshots (`+cols+`) SELECT `+cols+` FROM temp.perf_snap`)
			return err
		})
		if err != nil {
			return fmt.Errorf("snapshots of %s: %w", l.svc, err)
		}
	}
	h.ids["snapshot_service"] = h.ids["service"]
	// Rules: copies of the mined rules up to Rules.
	var have int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM miner_rules`).Scan(&have)
	if have > 0 {
		err := db.InTx(ctx, func(tx *sql.Tx) error {
			for i := have; i < h.sc.Rules; i++ {
				// Copies are drafts or rejected: an approved copy would put two
				// identical rules in the packs.
				status := "draft"
				if i%3 == 0 {
					status = "rejected"
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO miner_rules (id, seq, signature, kind, status, structure, confidence, approved_confidence,
					body, latest, edits, created_at, updated_at, last_run, strikes, stale_reason)
					SELECT printf('r-%04d', (SELECT max(seq) FROM miner_rules) + 1), (SELECT max(seq) FROM miner_rules) + 1, signature || ?, kind, ?,
					structure, confidence, approved_confidence,
					replace(body, '"' || id || '"', '"' || printf('r-%04d', (SELECT max(seq) FROM miner_rules) + 1) || '"'),
					latest, edits, created_at, updated_at, last_run, 0, NULL
					FROM miner_rules ORDER BY seq LIMIT 1 OFFSET ?`, fmt.Sprintf("/perf%d", i), status, i%have); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("rules: %w", err)
		}
	}
	// Alerts: mostly resolved, some open.
	now := time.Now().UnixMilli()
	err = db.InTx(ctx, func(tx *sql.Tx) error {
		for i := 0; i < h.sc.Alerts; i++ {
			state := "resolved"
			if i%20 == 0 {
				state = "open"
			}
			svc := h.services()[i%len(h.services())]
			if _, err := tx.ExecContext(ctx, `INSERT INTO drift_alerts (kind, dedupe_key, service, op, where_text, change_kind, severity, change,
				first_seen_ms, last_seen_ms, calls_after, state) VALUES ('contract.drift', ?, ?, 'GET /orders/{id}', '$.status', 'enum_added',
				?, 'new value in an enum', ?, ?, 10, ?)`, fmt.Sprintf("perf-%d", i), svc, map[bool]string{true: "breaking", false: "non-breaking"}[i%3 == 0],
				now-int64(i)*60000, now-int64(i)*60000, state); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("alerts: %w", err)
	}
	// Deliveries of the webhook (delivered or failed: history only).
	var whID int64
	if _, err := fmt.Sscanf(h.ids["webhook"], "wh-%d", &whID); err == nil {
		err = db.InTx(ctx, func(tx *sql.Tx) error {
			for i := 0; i < h.sc.Deliveries; i++ {
				state := "delivered"
				if i%10 == 0 {
					state = "failed"
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO drift_deliveries (webhook_id, event_type, alert_id, payload, state, attempts,
					next_attempt_ms, last_status, created_ms, delivered_ms) VALUES (?, 'contract.drift', ?, ?, ?, 1, ?, 204, ?, ?)`,
					whID, i+1, []byte(`{"event":"contract.drift","perf":true}`), state, now-int64(i)*1000, now-int64(i)*1000, now-int64(i)*1000); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("deliveries: %w", err)
		}
	}
	// Worlds and packs: copies of the real ones (with their blobs), through a
	// temporary table so that columns added by later migrations follow.
	cloneRows := func(table, id, format string, n int, extra string) error {
		return db.InTx(ctx, func(tx *sql.Tx) error {
			for i := 1; i < n; i++ {
				for _, q := range []string{`DROP TABLE IF EXISTS temp.perf_clone`, `CREATE TEMP TABLE perf_clone AS SELECT * FROM ` + table + ` WHERE id = ?`} {
					args := []any{}
					if strings.Contains(q, "?") {
						args = append(args, id)
					}
					if _, err := tx.ExecContext(ctx, q, args...); err != nil {
						return err
					}
				}
				if _, err := tx.ExecContext(ctx, `UPDATE temp.perf_clone SET id = printf(?, ?), created_at = created_at - ? * 3600`+extra, format, i, i); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO `+table+` SELECT * FROM temp.perf_clone`); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if w := h.ids["world"]; w != "" {
		if err := cloneRows("world_worlds", w, "w-20250101-%04d", h.sc.Worlds, ", seed = seed + 1"); err != nil {
			return fmt.Errorf("worlds: %w", err)
		}
	}
	if p := h.ids["pack"]; p != "" {
		if err := cloneRows("packwriter_packs", p, "pk-20250101-%04d", h.sc.Packs, ""); err != nil {
			return fmt.Errorf("packs: %w", err)
		}
	}
	var snap int64
	_ = db.QueryRowContext(ctx, `SELECT max(id) FROM contract_snapshots WHERE service = ?`, h.ids["service"]).Scan(&snap)
	h.ids["snapshot"] = fmt.Sprintf("sn-%08d", snap)
	var prev int64
	_ = db.QueryRowContext(ctx, `SELECT max(id) FROM contract_snapshots WHERE service = ? AND id < ?`, h.ids["service"], snap).Scan(&prev)
	h.ids["snapshot_prev"] = fmt.Sprintf("sn-%08d", prev)
	return nil
}

// ---- jobs on the full history ----

func (h *harness) benchJobs(ctx context.Context) {
	svc := h.ids["service"]
	h.job("contract.snapshot.one_service", func() (map[string]any, error) {
		code, b, _, err := h.admin.do("POST", "/api/v1/contracts/"+url.PathEscape(svc)+"/snapshots", nil)
		if err != nil {
			return nil, err
		}
		if code != 201 {
			return nil, fmt.Errorf("snapshot = %d: %.200s", code, b)
		}
		return nil, nil
	})
	h.job("rules.mine", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/rules/mine", nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"events": j.Result["events"]}, nil
	})
	h.job("worlds.generate.second", func() (map[string]any, error) {
		_, err := h.postJob("/api/v1/worlds", map[string]any{"seed": 43, "customers": 200})
		return nil, err
	})
	h.job("pack.build.second", func() (map[string]any, error) {
		j, err := h.postJob("/api/v1/packs", map[string]any{"world_id": h.ids["world"]})
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": j.Result["status"]}, nil
	})
	h.job("events.export.ocel", func() (map[string]any, error) {
		to := time.Now().UTC()
		from := to.Add(-24 * time.Hour)
		j, err := h.postJob("/api/v1/events/export", map[string]any{"from": from, "to": to, "format": "ocel2-json", "service": svc})
		if err != nil {
			return nil, err
		}
		h.ids["event_export"] = j.JobID
		return nil, nil
	})
	h.job("audit.verify", func() (map[string]any, error) {
		code, b, _, err := h.admin.do("GET", "/api/v1/audit/verify", nil)
		if err != nil {
			return nil, err
		}
		if code != 200 {
			return nil, fmt.Errorf("verify = %d", code)
		}
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		return map[string]any{"entries": v["entries"], "ok": v["ok"]}, nil
	})
	h.benchWebhooks(ctx)
}

// benchWebhooks queues deliveries to a fast and to a slow receiver and
// measures how long the fast ones wait (head-of-line blocking).
func (h *harness) benchWebhooks(ctx context.Context) {
	// A reused dataset points the webhook at the receiver of an earlier run.
	if err := h.admin.json(200, "PUT", "/api/v1/webhooks/"+h.ids["webhook"], map[string]any{"name": "perf", "url": h.hook.URL + "/fast",
		"events": []string{"contract.drift"}}, nil); err != nil {
		h.rep.Jobs = append(h.rep.Jobs, &JobStats{Name: "webhook.delivery", Error: err.Error()})
		return
	}
	var slow struct {
		ID string `json:"webhook_id"`
	}
	if err := h.admin.json(201, "POST", "/api/v1/webhooks", map[string]any{"name": "perf-slow", "url": h.hook.URL + "/slow",
		"events": []string{"contract.drift"}}, &slow); err != nil {
		h.rep.Jobs = append(h.rep.Jobs, &JobStats{Name: "webhook.delivery", Error: err.Error()})
		return
	}
	h.hook.delay.Store(int64(2 * time.Second))
	defer h.hook.delay.Store(0)
	db, err := store.OpenWith(ctx, h.dbPath(), store.NewRegistry())
	if err != nil {
		return
	}
	defer db.Close()
	var fastID, slowID int64
	fmt.Sscanf(h.ids["webhook"], "wh-%d", &fastID)
	fmt.Sscanf(slow.ID, "wh-%d", &slowID)
	const nSlow, nFast = 5, 200
	h.job("webhook.delivery", func() (map[string]any, error) {
		before := h.hook.n.Load()
		now := time.Now().UnixMilli()
		err := db.InTx(ctx, func(tx *sql.Tx) error {
			for i := 0; i < nSlow+nFast; i++ {
				wh := fastID
				if i < nSlow {
					wh = slowID
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO drift_deliveries (webhook_id, event_type, payload, state, next_attempt_ms, created_ms)
					VALUES (?, 'contract.drift', ?, 'pending', ?, ?)`, wh, []byte(`{"perf":true}`), now, now); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		t0 := time.Now()
		var fastDone time.Duration
		for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			var pending int
			_ = db.QueryRowContext(ctx, `SELECT count(*) FROM drift_deliveries WHERE webhook_id = ? AND state = 'pending'`, fastID).Scan(&pending)
			if pending == 0 {
				fastDone = time.Since(t0)
				break
			}
		}
		_ = before
		return map[string]any{"fast_deliveries": nFast, "slow_deliveries": nSlow, "slow_delay_s": 2,
			"fast_drained_s": fastDone.Seconds()}, nil
	})
	_, _, _, _ = h.admin.do("DELETE", "/api/v1/webhooks/"+slow.ID, nil)
}

// benchPurge lowers the retention so that a fifth of the events go, runs
// the purge job and, meanwhile, ingests events at a steady rate through
// the intake: the backpressure answers and the queue tell whether the purge
// starves the writer.
func (h *harness) benchPurge(ctx context.Context) {
	if len(h.wire) == 0 || h.sourceID == "" {
		return
	}
	keepDays := max(1, h.sc.Days*4/5)
	in := h.c.Intake()
	// Writer throughput on the big database: a burst as fast as the queue
	// takes it (the random-key indexes slow the inserts as they grow).
	h.job("intake.burst", func() (map[string]any, error) {
		const n = 40000
		start := in.Totals().Stored
		t0 := time.Now()
		for i := 0; i < n; i++ {
			w := retime(h.wire[i%len(h.wire)], time.Now().UTC(), i+1<<30)
			for {
				_, err := in.IngestEvent(ctx, h.sourceID, w)
				if errors.Is(err, intake.ErrOverloaded) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err != nil {
					return nil, err
				}
				break
			}
		}
		if err := in.WaitIdle(ctx); err != nil {
			return nil, err
		}
		stored := in.Totals().Stored - start
		return map[string]any{"events": n, "stored": stored, "events_per_s": float64(stored) / time.Since(t0).Seconds()}, nil
	})
	var sent, overloaded, rejected atomic.Int64
	var maxQueue, maxStallMS atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // writer progress: the longest time without a commit while events wait
		defer wg.Done()
		last, lastT := in.Totals().Stored, time.Now()
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			tt := in.Totals()
			if tt.QueuedEvents > maxQueue.Load() {
				maxQueue.Store(tt.QueuedEvents)
			}
			if tt.Stored != last || tt.QueuedEvents == 0 {
				last, lastT = tt.Stored, time.Now()
				continue
			}
			if s := time.Since(lastT).Milliseconds(); s > maxStallMS.Load() {
				maxStallMS.Store(s)
			}
		}
	}()
	const rate = 2000 // events/s
	wg.Add(1)
	go func() {
		defer wg.Done()
		t0 := time.Now()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if due := t0.Add(time.Duration(i) * time.Second / rate); time.Until(due) > 0 {
				time.Sleep(time.Until(due))
			}
			w := retime(h.wire[i%len(h.wire)], time.Now().UTC(), i)
			rej, err := in.IngestEvent(ctx, h.sourceID, w)
			switch {
			case errors.Is(err, intake.ErrOverloaded):
				overloaded.Add(1)
			case err != nil || rej.Reason != intake.ReasonNone:
				rejected.Add(1)
			default:
				sent.Add(1)
			}
		}
	}()
	time.Sleep(2 * time.Second) // steady state first
	h.job("store.purge", func() (map[string]any, error) {
		if err := h.admin.json(200, "PUT", "/api/v1/store/retention", map[string]any{"events_days": keepDays}, nil); err != nil {
			return nil, err
		}
		j, err := h.postJob("/api/v1/store/purge", map[string]any{"before": time.Now().UTC().Add(-time.Duration(keepDays) * 24 * time.Hour)})
		close(stop)
		wg.Wait()
		det := map[string]any{"ingest_rate": rate, "ingested": sent.Load(), "overloaded": overloaded.Load(), "rejected": rejected.Load(),
			"max_queue": maxQueue.Load(), "max_writer_stall_ms": maxStallMS.Load()}
		if j != nil {
			for k, v := range j.Result {
				det["result_"+k] = v
			}
		}
		return det, err
	})
}

// retime replaces the ts of a wire event and makes its span id unique
// (same lengths: the event stays canonical).
func retime(w []byte, t time.Time, n int) []byte {
	s := string(w)
	if i := strings.Index(s, `"ts":"`); i >= 0 {
		s = s[:i+6] + t.Format("2006-01-02T15:04:05.000Z") + s[i+6+24:]
	}
	if i := strings.Index(s, `"span_id":"`); i >= 0 && len(s) > i+11+16 {
		s = s[:i+11] + fmt.Sprintf("%016x", uint64(n)+uint64(t.UnixNano())) + s[i+11+16:]
	}
	return []byte(s)
}
