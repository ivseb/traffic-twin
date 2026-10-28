package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/store"
)

// The dataset: the templates (real sanitized demo events) are replayed in
// time order over the event span; copy k of a template gets another service
// (inbound services for the shop's inbound calls, declared outbound
// services or host patterns for its outbound calls), another source and
// unique trace/span ids. Rows are written with the statements of the intake
// writer, in received order (the retention job relies on it).

func (h *harness) serviceNames() (in, out, hosts []string) {
	nIn := max(1, h.sc.Services/2)
	nOut := max(1, h.sc.Services-nIn)
	for i := 0; i < nIn; i++ {
		if i == 0 {
			in = append(in, "shop-api")
		} else {
			in = append(in, fmt.Sprintf("shop-api-%02d", i))
		}
	}
	for i := 0; i < nOut; i++ {
		if i == 0 {
			out = append(out, "shipping-ext")
		} else {
			out = append(out, fmt.Sprintf("partner-%02d-ext", i))
		}
	}
	for i := 0; i < h.sc.HostPatterns; i++ {
		switch i % 4 {
		case 0:
			hosts = append(hosts, fmt.Sprintf("host:{*}.tenant%04d.example", i))
		case 1:
			hosts = append(hosts, fmt.Sprintf("host:api.vendor%04d.example", i))
		case 2:
			hosts = append(hosts, fmt.Sprintf("host:cdn%04d.assets.example", i))
		default:
			hosts = append(hosts, fmt.Sprintf("host:{*}.region%02d.cloud%04d.example", i%17, i))
		}
	}
	return
}

func (h *harness) sourceIDs() []string {
	ids := []string{h.sourceID}
	for i := 1; i < h.sc.Sources; i++ {
		ids = append(ids, fmt.Sprintf("src-perf%04d", i))
	}
	return ids
}

func hash32(s string, k int) uint32 {
	f := fnv.New32a()
	fmt.Fprintf(f, "%s/%d", s, k)
	return f.Sum32()
}

func (h *harness) generate(ctx context.Context) error {
	db, err := store.Open(ctx, h.dbPath())
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, p := range []string{"PRAGMA cache_size = -262144", "PRAGMA synchronous = OFF", "PRAGMA wal_autocheckpoint = 100000"} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	// The secondary indexes of the event table are built after the bulk
	// load (a sort instead of millions of random inserts: the trace and
	// subject indexes have random keys). Their DDL is replayed verbatim.
	var indexDDL []string
	{
		rows, err := conn.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'intake_events' AND sql IS NOT NULL`)
		if err != nil {
			return err
		}
		var names []string
		for rows.Next() {
			var n, q string
			if err := rows.Scan(&n, &q); err != nil {
				rows.Close()
				return err
			}
			names, indexDDL = append(names, n), append(indexDDL, q)
		}
		rows.Close()
		for _, n := range names {
			if _, err := conn.ExecContext(ctx, `DROP INDEX "`+n+`"`); err != nil {
				return err
			}
		}
	}
	in, out, hosts := h.serviceNames()
	srcs := h.sourceIDs()
	end := time.Now().UTC().Add(-10 * time.Minute)
	start := end.Add(-time.Duration(h.sc.Days) * 24 * time.Hour)
	span := end.Sub(start)
	n := h.sc.Events
	copies := max(1, (n+len(h.tpl)-1)/len(h.tpl))
	fields := map[string]int64{}
	var nextField int64 = 1
	const perTx = 20000
	t0 := time.Now()
	buf := make([]byte, 0, 4096)
	for done := 0; done < n; {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		stEv, err := tx.PrepareContext(ctx, `INSERT INTO intake_events
			(received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op, route_source,
			 status, net_error, latency_ms, subject, trace_id, span_id, parent_span_id, body)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		type tok struct {
			hour  int64
			token string
			id    int64
			field int64
			ts    int64
		}
		var toks []tok
		lim := min(n, done+perTx)
		for i := done; i < lim; i++ {
			// Copy k of template t: the copies of a template are adjacent in
			// time (the simulated week is stretched over the span), each copy
			// is its own universe (identifiers rewritten, trace ids mixed)
			// and lives in one pair of services (shop-api-NN calls
			// partner-NN-ext), so that the flows stay whole and the miner
			// finds the demo's rules in every pair.
			t, k := i/copies, i%copies
			if t >= len(h.tpl) {
				t = len(h.tpl) - 1
			}
			tp := h.tpl[t]
			ev := *tp
			ts := start.Add(time.Duration(float64(span) * float64(i) / float64(n))).Truncate(time.Millisecond)
			ev.Time = ts
			ev.TS = ts.Format("2006-01-02T15:04:05.000Z")
			pair := k % len(in)
			if ev.Dir == event.Inbound {
				ev.Service = in[pair]
			} else if hs := hash32(tp.TraceID, k); int(hs%100) < 10 && len(hosts) > 0 {
				ev.Service = hosts[int(hs/100)%len(hosts)]
			} else {
				ev.Service = out[pair%len(out)]
			}
			ev.Source.ID = srcs[int(hash32(ev.Service, k%3))%len(srcs)]
			if k > 0 {
				ev.TraceID = mix(tp.TraceID, k)
				ev.SpanID = mix(tp.SpanID, k)
				if tp.ParentSpanID != "" {
					ev.ParentSpanID = mix(tp.ParentSpanID, k)
				}
			}
			// The subject column follows the body (rewritten below).
			subject := ev.Subject
			if k > 0 {
				subject = retoken(subject, k)
			}
			buf = ev.AppendCanonicalNoDisc(buf[:0])
			if k > 0 {
				retokenBody(buf, k)
			}
			if i%100_003 == 1 { // spot check: the rewritten event stays valid
				chk, derr := event.Decode(buf)
				if derr != nil || chk.Subject != subject {
					return fmt.Errorf("generated event %d is not valid: %v", i, derr)
				}
			}
			rcv := ts.UnixMilli() + ev.LatencyMS + 40
			dir := 0
			if ev.Dir == event.Outbound {
				dir = 1
			}
			res, err := stEv.ExecContext(ctx, rcv, ts.UnixMilli(), ev.Source.ID, ev.Policy.ID, ev.Policy.Version, dir, ev.Service, ev.Op,
				routeCode(ev.RouteSource), statusArg(ev.Status), nullStr(ev.NetError), ev.LatencyMS, nullStr(subject),
				nullStr(ev.TraceID), nullStr(ev.SpanID), nullStr(ev.ParentSpanID), buf)
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			hour := rcv / 3_600_000
			ev.HMACTokens(func(t event.HMACToken) {
				fid, ok := fields[t.Where]
				if !ok {
					fid = nextField
					nextField++
					fields[t.Where] = fid
				}
				tk := t.Token
				if k > 0 {
					tk = retoken(tk, k)
				}
				toks = append(toks, tok{hour, tk, id, fid, ts.UnixMilli()})
			})
		}
		stEv.Close()
		sort.Slice(toks, func(a, b int) bool {
			if toks[a].hour != toks[b].hour {
				return toks[a].hour < toks[b].hour
			}
			if toks[a].token != toks[b].token {
				return toks[a].token < toks[b].token
			}
			return toks[a].id < toks[b].id
		})
		const per = 100
		args := make([]any, 0, per*5)
		for len(toks) > 0 {
			m := min(per, len(toks))
			args = args[:0]
			for _, t := range toks[:m] {
				args = append(args, t.hour, t.token, t.id, t.field, t.ts)
			}
			if _, err := tx.ExecContext(ctx, tokenInsert(m), args...); err != nil {
				return err
			}
			toks = toks[m:]
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		done = lim
		if done%(perTx*25) == 0 || done == n {
			el := time.Since(t0).Seconds()
			fmt.Printf("    %d/%d events (%.0f ev/s)\n", done, n, float64(done)/el)
		}
	}
	t1 := time.Now()
	for _, q := range indexDDL {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("rebuild index: %w", err)
		}
	}
	fmt.Printf("    event indexes rebuilt in %.0f s\n", time.Since(t1).Seconds())
	for f, id := range fields {
		if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO intake_fields (id, field) VALUES (?, ?)`, id, f); err != nil {
			return err
		}
	}
	// The rows bypassed the writer: hand them to the aggregate backfill
	// (as for a database of an older version) and count them into the
	// rollups now, as the ingest and the maintenance of a live
	// installation would have done along the way.
	if _, err := conn.ExecContext(ctx, `UPDATE intake_agg_state SET v = (SELECT coalesce(min(id), 1) FROM intake_events) WHERE k = 'next'`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `UPDATE intake_agg_state SET v = (SELECT coalesce(max(id), 0) FROM intake_events) WHERE k = 'hi'`); err != nil {
		return err
	}
	t2 := time.Now()
	st := intake.NewStore(db)
	if err := st.BackfillAggregates(ctx, 0); err != nil {
		return fmt.Errorf("aggregates: %w", err)
	}
	if _, err := st.RollupPending(ctx); err != nil {
		return fmt.Errorf("rollups: %w", err)
	}
	fmt.Printf("    aggregates and rollups in %.0f s\n", time.Since(t2).Seconds())
	if err := h.genSources(ctx, conn, in, out); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return err
	}
	conn.Close()
	return h.genAudit(ctx, db)
}

// retoken maps an HMAC token to the one of copy k: same kid, same length,
// another MAC (a different identifier in every copy).
func retoken(tok string, k int) string {
	kid, mac, ok := event.SplitHMACToken(tok)
	if !ok {
		return tok
	}
	return "tk1:" + kid + ":" + macOf(mac, k)
}

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func macOf(mac string, k int) string {
	f := fnv.New64a()
	fmt.Fprintf(f, "%s/%d", mac, k)
	h1 := f.Sum64()
	fmt.Fprintf(f, "#")
	h2 := f.Sum64()
	var b [22]byte
	for i := range b {
		var x uint64
		if i < 11 {
			x = h1 >> (6 * uint(i))
		} else {
			x = h2 >> (6 * uint(i-11))
		}
		b[i] = b64url[x&63]
	}
	return string(b[:])
}

// retokenBody rewrites, in place, every HMAC token of a canonical event:
// the lengths do not change, so the event stays canonical.
func retokenBody(b []byte, k int) {
	for i := 0; ; {
		j := bytes.Index(b[i:], []byte("tk1:"))
		if j < 0 {
			return
		}
		j += i
		end := j + 4
		for end < len(b) && b[end] != ':' && end-j < 4+9 {
			end++
		}
		if end+1+22 <= len(b) && b[end] == ':' {
			tok := string(b[j : end+1+22])
			if nt := retoken(tok, k); nt != tok {
				copy(b[j:], nt)
			}
			i = end + 1 + 22
		} else {
			i = j + 4
		}
	}
}

// mix replaces the last 8 hex digits of a trace or span id with the copy
// number (ids stay valid lowercase hex of the same length).
func mix(id string, k int) string {
	if len(id) < 8 {
		return id
	}
	return id[:len(id)-8] + fmt.Sprintf("%08x", uint32(k)^hash32(id, 0))
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

func statusArg(s int) any {
	if s == 0 {
		return nil
	}
	return s
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func tokenInsert(n int) string {
	var sb strings.Builder
	sb.WriteString("INSERT OR IGNORE INTO intake_tokens (hour, token, event_id, field, ts_ms) VALUES ")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("(?,?,?,?,?)")
	}
	return sb.String()
}

// genSources clones the real source row (enrolled through Fleet) into the
// synthetic sources of the events.
func (h *harness) genSources(ctx context.Context, conn *sql.Conn, in, out []string) error {
	ids := h.sourceIDs()
	all := append(append([]string{}, in...), out...)
	for i, id := range ids[1:] {
		svc := all[i%len(all)]
		_, err := conn.ExecContext(ctx, `INSERT INTO fleet_sources (id, token_id, grp, kind, version, service_name, instance, runtime, hmac_kids,
			enrolled_at, cert_not_after, revoked, killed, last_seen, state, policy_id, policy_version, policy_seq, policy_hash, counters,
			events_per_min, drop_ratio, last_errors, signing_kids)
			SELECT ?, token_id, grp, kind, version, ?, ?, runtime, hmac_kids, enrolled_at, cert_not_after, 0, 0, ?, state, policy_id,
			policy_version, policy_seq, policy_hash, counters, 12.5, 0, last_errors, signing_kids FROM fleet_sources WHERE id = ?`,
			id, svc, fmt.Sprintf("perf-%d", i), time.Now().Add(-time.Duration(i)*time.Second).Unix(), h.sourceID)
		if err != nil {
			return fmt.Errorf("sources: %w", err)
		}
	}
	return nil
}

// genAudit appends the audit entries through the audit log itself (hash
// chain included), with a mix of actions like a busy installation.
func (h *harness) genAudit(ctx context.Context, db *store.DB) error {
	l := audit.New(db)
	actions := []string{"auth.login", "rule.approve", "policy.propose", "contract.snapshot", "pack.build", "authz.deny", "fleet.enroll", "service.twin"}
	t0 := time.Now()
	for i := 0; i < h.sc.Audit; i++ {
		a := actions[i%len(actions)]
		if _, err := l.Record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorUser, ID: fmt.Sprintf("u-%03d", i%40), Name: "perf user"},
			Action: a, Target: audit.Target{Type: "perf", ID: fmt.Sprintf("t-%d", i%997)}, Outcome: audit.Success,
			RequestID: fmt.Sprintf("req-%d", i), Details: map[string]string{"n": fmt.Sprint(i)}}); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		if (i+1)%100000 == 0 {
			fmt.Printf("    %d audit entries (%.0f/s)\n", i+1, float64(i+1)/time.Since(t0).Seconds())
		}
	}
	return nil
}
