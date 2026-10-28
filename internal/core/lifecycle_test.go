package core_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
)

// TestDataLifecycleOverMonths simulates four months of traffic on a real
// tt-core with a virtual clock: every simulated day the events of that day
// are written (straight into SQLite, as the intake would) together with the
// day's contract snapshots, then the maintenance runs through the admin API.
// It checks that the database stays within its budget, that the rollups
// give the numbers the raw events gave (before and after their deletion),
// that the contract, drift and hosts pages answer for old periods, that a
// traffic spike is shed (raw events beyond the miner window first) without
// stopping anything, and that the audit chain verifies across the archived
// segments.
func TestDataLifecycleOverMonths(t *testing.T) {
	if testing.Short() {
		t.Skip("months of simulated traffic")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kgDir, err := os.MkdirTemp("", "ttlife")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(kgDir) })
	kg, err := core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: kgDir, Logger: keyguard.NewLogger(io.Discard, "error", "text")})
	if err != nil {
		t.Fatal(err)
	}
	defer kg.Close()
	dir := t.TempDir()
	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(dir, kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	const budget = 64 << 20
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Retention.Events = 7 * 24 * time.Hour
	cfg.Retention.PurgeInterval = 24 * time.Hour // the test runs the maintenance itself
	cfg.Retention.Audit.ArchiveAfter = 30 * 24 * time.Hour
	cfg.Retention.Audit.SegmentEntries = 1000
	cfg.Miner.Window = 3 * 24 * time.Hour
	cfg.Miner.Schedule = 0
	cfg.Storage.MaxBytes = budget
	cfg.Storage.HighWatermarkPct, cfg.Storage.CriticalWatermarkPct = 60, 70
	cfg.Log.Level = "error"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	day0 := time.Now().UTC().Truncate(24 * time.Hour)
	clock := &vclock{t: day0}
	c, err := core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-life", AdminListener: adminLn, IntakeListener: intakeLn, Now: clock.Now,
		Logger:         server.NewLogger(io.Discard, "error", "text"),
		PasswordParams: &auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Run(ctx) }()
	pem, _ := os.ReadFile(cfg.Admin.TLS.CertFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	base := "https://" + adminLn.Addr().String()
	eventually(t, 10*time.Second, "readyz", func() bool {
		resp, err := hc.Get(base + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	ada := signIn(t, base, hc, "/api/v1/setup", map[string]string{"setup_token": c.SetupToken(), "username": "ada", "password": testPassword})
	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "olga", "password": testPassword, "roles": []string{"operator"}})
	ada.must(201, "POST", "/api/v1/users", map[string]any{"username": "aldo", "password": testPassword, "roles": []string{"auditor"}})
	var olga, aldo *session
	// The sessions follow the virtual clock: sign in again after each jump.
	relogin := func() {
		ada = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "ada", "password": testPassword})
		olga = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "olga", "password": testPassword})
		aldo = signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "aldo", "password": testPassword})
	}
	relogin()

	db, err := store.Open(ctx, cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snaps := c.Contracts().Snapshots()

	// What was sent, per day and service (the truth the rollups must keep).
	type key struct {
		day int
		svc string
	}
	sent := map[key]int64{}
	inbound := []string{"svc-a", "svc-b", "svc-c"}
	hosts := []string{"host:api.pay.example", "host:api.ship.example"}
	write := func(d, n int) {
		t.Helper()
		start := day0.Add(time.Duration(d) * 24 * time.Hour)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		st, err := tx.PrepareContext(ctx, `INSERT INTO intake_events (received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op,
			route_source, status, net_error, latency_ms, body) VALUES (?, ?, ?, 'p-1', 1, ?, ?, ?, 1, ?, NULL, ?, randomblob(600))`)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			ts := start.Add(time.Duration(i) * 24 * time.Hour / time.Duration(n)).UnixMilli()
			dir, svc, op := 0, inbound[i%3], fmt.Sprintf("GET /r%d", i%2)
			if i%4 == 3 {
				dir, svc, op = 1, hosts[i%2], "POST /v1/x"
			}
			status := []int{200, 200, 404, 500}[i%4]
			if _, err := st.ExecContext(ctx, ts, ts, fmt.Sprintf("src-%d", i%3), dir, svc, op, status, 20+i%300); err != nil {
				t.Fatal(err)
			}
			sent[key{d, svc}]++
		}
		st.Close()
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		// The contract snapshots of the day.
		w := contract.Window{From: start, To: start.Add(24 * time.Hour)}
		for _, svc := range inbound {
			if _, err := snaps.Save(ctx, &contract.Contract{Service: svc, Window: w}, w.To); err != nil {
				t.Fatal(err)
			}
		}
	}
	type usage struct {
		DB struct {
			UsedBytes int64  `json:"used_bytes"`
			MaxBytes  int64  `json:"max_bytes"`
			Level     string `json:"level"`
		} `json:"db"`
		Datasets []struct {
			Name  string `json:"name"`
			Bytes int64  `json:"bytes"`
		} `json:"datasets"`
		LastRun *struct {
			Shed []struct {
				Name string `json:"name"`
			} `json:"shed"`
		} `json:"last_run"`
	}
	type report struct {
		UsedBytes int64 `json:"used_bytes"`
		Level     string
		Errors    int
		Steps     []struct {
			Name  string `json:"name"`
			Error string `json:"error"`
		} `json:"steps"`
		Shed []struct {
			Name string `json:"name"`
		} `json:"shed"`
	}
	maintain := func() report {
		t.Helper()
		var j struct {
			ID     string          `json:"job_id"`
			Status string          `json:"status"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		for {
			code, b := ada.do("POST", "/api/v1/store/maintenance", nil)
			if code == 202 {
				_ = json.Unmarshal(b, &j)
				break
			}
			if code != 409 {
				t.Fatalf("maintenance: %d %s", code, b)
			}
			time.Sleep(50 * time.Millisecond) // the scheduled run is in progress
		}
		eventually(t, 2*time.Minute, "maintenance job", func() bool {
			ada.json(200, "GET", "/api/v1/jobs/"+j.ID, nil, &j)
			return j.Status != "running"
		})
		if j.Status != "done" {
			t.Fatalf("maintenance job: %+v", j)
		}
		var r report
		if err := json.Unmarshal(j.Result, &r); err != nil {
			t.Fatal(err)
		}
		for _, s := range r.Steps {
			if s.Error != "" {
				t.Fatalf("step %s: %s", s.Name, s.Error)
			}
		}
		return r
	}
	rawCount := func(d int) int64 {
		var n int64
		start := day0.Add(time.Duration(d) * 24 * time.Hour)
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM intake_events WHERE ts_ms >= ? AND ts_ms < ?`,
			start.UnixMilli(), start.Add(24*time.Hour).UnixMilli()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	traffic := func(from, to time.Time, step string) (calls int64, tiers map[string]bool) {
		t.Helper()
		var out struct {
			Points []struct {
				Calls int64  `json:"calls"`
				Tier  string `json:"tier"`
			} `json:"points"`
		}
		q := url.Values{"from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}, "step": {step}}
		olga.json(200, "GET", "/api/v1/store/traffic?"+q.Encode(), nil, &out)
		tiers = map[string]bool{}
		for _, p := range out.Points {
			calls += p.Calls
			tiers[p.Tier] = true
		}
		return calls, tiers
	}
	dayStart := func(d int) time.Time { return day0.Add(time.Duration(d) * 24 * time.Hour) }
	sumDay := func(d int) (n int64) {
		for k, v := range sent {
			if k.day == d {
				n += v
			}
		}
		return n
	}

	const days, perDay = 120, 2500
	var protected string
	maxUsed := int64(0)
	for d := 0; d < days; d++ {
		write(d, perDay)
		if d == 3 {
			// A drift alert compares the snapshots of days 2 and 3 of svc-a.
			list, err := snaps.List(ctx, "svc-a", 10)
			if err != nil || len(list) < 2 {
				t.Fatalf("snapshots: %v %v", list, err)
			}
			protected = list[0].SnapshotID
			if _, err := db.ExecContext(ctx, `INSERT INTO drift_alerts (kind, dedupe_key, service, op, where_text, change_kind, severity, change,
				first_seen_ms, last_seen_ms, calls_after, state, snapshot_from, snapshot_to)
				VALUES ('contract.drift', 'k1', 'svc-a', 'GET /r0', 'resp.body', 'type_changed', 'breaking', '{}', ?, ?, 10, 'open', ?, ?)`,
				clock.Now().UnixMilli(), clock.Now().UnixMilli(), list[1].SnapshotID, list[0].SnapshotID); err != nil {
				t.Fatal(err)
			}
		}
		clock.Set(dayStart(d).Add(23 * time.Hour))
		relogin()
		if d == 9 {
			// Day 2 is about to be purged: the rollups match its raw events.
			if raw := rawCount(2); raw != sumDay(2) {
				t.Fatalf("raw day 2: %d of %d", raw, sumDay(2))
			}
			if _, err := c.Intake().Store().RollupPending(ctx); err != nil {
				t.Fatal(err)
			}
			if n, _ := traffic(dayStart(2), dayStart(3), "hour"); n != sumDay(2) {
				t.Fatalf("rollup of day 2 before the purge: %d, raw %d", n, sumDay(2))
			}
		}
		r := maintain()
		maxUsed = max(maxUsed, r.UsedBytes)
		if r.UsedBytes > budget {
			t.Fatalf("day %d: %d bytes used, budget %d", d, r.UsedBytes, budget)
		}
		if d == 9 && rawCount(2) >= sumDay(2) {
			t.Fatal("day 2 not purged at day 9")
		}
	}
	t.Logf("%d days x %d events: at most %d MiB used (budget %d MiB)", days, perDay, maxUsed>>20, budget>>20)

	// Every day ever sent is in the rollups, raw events or not.
	for _, d := range []int{0, 1, 5, 40, 80, days - 1} {
		n, tiers := traffic(dayStart(d), dayStart(d+1), "day")
		if n != sumDay(d) {
			t.Fatalf("day %d: %d calls in the rollups, %d sent (tiers %v)", d, n, sumDay(d), tiers)
		}
	}
	if _, tiers := traffic(dayStart(0), dayStart(1), "hour"); !tiers["day"] {
		t.Fatalf("day 0 should be compacted to the daily tier: %v", tiers)
	}

	// The hosts registry of an old period (raw events long gone).
	var hv struct {
		Domains []struct {
			Calls int64 `json:"calls"`
		} `json:"domains"`
	}
	q := url.Values{"from": {dayStart(5).Format(time.RFC3339)}, "to": {dayStart(6).Format(time.RFC3339)}}
	olga.json(200, "GET", "/api/v1/hosts?"+q.Encode(), nil, &hv)
	var hostCalls int64
	for _, dmn := range hv.Domains {
		hostCalls += dmn.Calls
	}
	if want := sent[key{5, hosts[0]}] + sent[key{5, hosts[1]}]; hostCalls != want || rawCount(5) != 0 {
		t.Fatalf("hosts of day 5: %d calls, want %d", hostCalls, want)
	}

	// Contracts: compacted history, the alert's snapshot kept and readable.
	var list []map[string]any
	olga.json(200, "GET", "/api/v1/contracts/svc-a/snapshots?limit=1000", nil, &list)
	if len(list) >= days || len(list) < 31 {
		t.Fatalf("svc-a keeps %d snapshots of %d", len(list), days)
	}
	found := false
	for _, s := range list {
		found = found || s["snapshot_id"] == protected
	}
	if !found {
		t.Fatalf("snapshot %s referenced by a drift alert was compacted away", protected)
	}
	olga.must(200, "GET", "/api/v1/contracts/svc-a/snapshots/"+protected, nil)
	var alerts []map[string]any
	olga.json(200, "GET", "/api/v1/drift", nil, &alerts)
	if len(alerts) != 1 {
		t.Fatalf("drift alerts: %v", alerts)
	}

	// A spike of traffic: over the critical watermark the raw events beyond
	// the miner window are shed first, and the database is back in budget.
	var u usage
	ada.json(200, "GET", "/api/v1/store/usage", nil, &u)
	var evBytes int64
	for _, ds := range u.Datasets {
		if ds.Name == "events" {
			evBytes = ds.Bytes
		}
	}
	var stored int64
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM intake_events`).Scan(&stored)
	perEvent := max(1, evBytes/max(1, stored))
	spike := int((int64(budget)*78/100 - u.DB.UsedBytes) / perEvent)
	if spike > 0 {
		write(days, spike)
	}
	clock.Set(dayStart(days).Add(23 * time.Hour))
	relogin()
	r := maintain()
	if len(r.Shed) == 0 || r.Shed[0].Name != "events_beyond_miner_window" {
		t.Fatalf("spike of %d events not shed: %+v (used %d)", spike, r.Shed, r.UsedBytes)
	}
	if r.UsedBytes > budget {
		t.Fatalf("over budget after shedding: %d", r.UsedBytes)
	}
	var oldest int64
	_ = db.QueryRowContext(ctx, `SELECT min(received_ms) FROM intake_events`).Scan(&oldest)
	if clock.Now().Sub(time.UnixMilli(oldest)) > cfg.Miner.Window {
		t.Fatalf("events older than the miner window survived the shedding")
	}
	// Shed raw events are still in the rollups.
	if n, _ := traffic(dayStart(days-5), dayStart(days-4), "day"); n != sumDay(days-5) {
		t.Fatalf("shed day lost from the rollups: %d of %d", n, sumDay(days-5))
	}
	ada.json(200, "GET", "/api/v1/store/usage", nil, &u)
	if u.DB.Level == "over" {
		t.Fatalf("usage level %s", u.DB.Level)
	}

	// The audit log: old segments archived, the chain verifies across them.
	var v struct {
		OK       bool  `json:"ok"`
		Archived int64 `json:"archived"`
		Segments int   `json:"segments"`
	}
	aldo.json(200, "GET", "/api/v1/audit/verify", nil, &v)
	if !v.OK || v.Archived == 0 || v.Segments == 0 {
		t.Fatalf("audit verify: %+v", v)
	}
	rep, err := audit.VerifyArchive(filepath.Join(filepath.Dir(cfg.Storage.Path), "audit-archive"))
	if err != nil || rep.Entries != v.Archived {
		t.Fatalf("archive: %+v %v (verify says %d archived)", rep, err, v.Archived)
	}
}
