package core_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
)

// largeStoreEvents is the size of the synthetic store of
// TestListEndpointsLatencyOnLargeStore. TT_LIST_EVENTS overrides it.
const largeStoreEvents = 1_000_000

// listLatencyBudget is what the services and hosts lists may take on that
// store (the lab measured 9-13 s before the ingest aggregates).
const listLatencyBudget = 200 * time.Millisecond

// TestListEndpointsLatencyOnLargeStore fills the event store of a real
// tt-core with a million synthetic events (written straight into SQLite, as an
// older version would have left them), lets the aggregate backfill run, and
// checks that GET /api/v1/services and GET /api/v1/hosts answer within the
// budget and with the same numbers as the event scan.
func TestListEndpointsLatencyOnLargeStore(t *testing.T) {
	if testing.Short() {
		t.Skip("large store")
	}
	if raceEnabled {
		t.Skip("latency budget: not meaningful under the race detector")
	}
	n := largeStoreEvents
	if v := os.Getenv("TT_LIST_EVENTS"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	c, _, olga := listCore(t, n)
	ctx := context.Background()
	var began time.Time
	// Before the backfill completes the lists still answer (event scan).
	st := c.Intake().Store()
	var scanServices, scanHosts []byte
	if !st.AggregatesReady(ctx) {
		began = time.Now()
		scanServices = olga.must(200, "GET", "/api/v1/services", nil)
		scanHosts = olga.must(200, "GET", "/api/v1/hosts", nil)
		t.Logf("lists by event scan: %s", time.Since(began).Round(time.Millisecond))
	}
	began = time.Now()
	eventually(t, 5*time.Minute, "aggregate backfill", func() bool { return st.AggregatesReady(ctx) })
	t.Logf("backfill done in %s", time.Since(began).Round(time.Millisecond))

	for _, path := range []string{"/api/v1/services", "/api/v1/hosts"} {
		olga.must(200, "GET", path, nil) // warm the connection
		var worst time.Duration
		var body []byte
		for i := 0; i < 5; i++ {
			began := time.Now()
			body = olga.must(200, "GET", path, nil)
			worst = max(worst, time.Since(began))
		}
		t.Logf("%s: worst of 5 = %s", path, worst.Round(time.Microsecond))
		if worst > budget(listLatencyBudget) {
			t.Errorf("%s took %s on %d events (budget %s)", path, worst, n, budget(listLatencyBudget))
		}
		// The aggregates give the same answer as the scan.
		want := map[string][]byte{"/api/v1/services": scanServices, "/api/v1/hosts": scanHosts}[path]
		// (The hosts list's median latency is a histogram bucket from the aggregates.)
		if want != nil && p50.ReplaceAllString(string(want), "") != p50.ReplaceAllString(string(body), "") {
			t.Errorf("%s differs between scan and aggregates:\nscan %.400s\nagg  %.400s", path, want, body)
		}
	}
}

var p50 = regexp.MustCompile(`"latency_p50_ms":[0-9]+,?`)

// listCore starts keyguard and tt-core on a store pre-filled with n
// synthetic events and returns the core and an operator session.
func listCore(t *testing.T, n int) (*core.Core, *session, *session) {
	t.Helper()
	return listCoreWith(t, func(db *store.DB) {
		began := time.Now()
		fillEvents(t, db, n)
		t.Logf("%d events written in %s", n, time.Since(began).Round(time.Millisecond))
	})
}

// listCoreWith is listCore with the store filled by fill.
func listCoreWith(t *testing.T, fill func(db *store.DB)) (*core.Core, *session, *session) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kgDir, err := os.MkdirTemp("", "ttlist")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(kgDir) })
	kg, err := core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: kgDir, Logger: keyguard.NewLogger(io.Discard, "error", "text")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kg.Close() })
	dir := t.TempDir()
	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg, err := core.DevConfig(dir, kg.URL, adminLn.Addr().String(), intakeLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	cfg.Retention.Events = 365 * 24 * time.Hour
	cfg.Miner.Schedule = 0
	cfg.Log.Level = "error"

	// The events first, in a database of their own handle, before tt-core
	// starts: like an existing installation upgraded to this version.
	db, err := store.Open(ctx, cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	fill(db)
	db.Close()

	c, err := core.New(ctx, core.Options{Config: cfg, Version: "0.0.0-list", AdminListener: adminLn, IntakeListener: intakeLn,
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
	olga := signIn(t, base, hc, "/api/v1/auth/login", map[string]string{"username": "olga", "password": testPassword})

	return c, ada, olga
}

// fillEvents writes n synthetic rows: 60% inbound to 6 services, 40%
// outbound to 30 host patterns, from 20 sources under 3 policies, over 48 h.
func fillEvents(t *testing.T, db *store.DB, n int) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().Add(-48 * time.Hour).UnixMilli()
	statuses := []any{200, 200, 200, 201, 404, 500, nil}
	const chunk = 50_000
	for done := 0; done < n; {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		st, err := tx.PrepareContext(ctx, `INSERT INTO intake_events (received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op,
			route_source, status, net_error, latency_ms, body) VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, ?, ?, ?, x'7b7d')`)
		if err != nil {
			t.Fatal(err)
		}
		for i := done; i < min(n, done+chunk); i++ {
			ts := base + int64(i)*(48*3600*1000)/int64(n)
			src := fmt.Sprintf("src-%02d", i%20)
			pol := fmt.Sprintf("p-%d", i%3)
			status := statuses[i%len(statuses)]
			var netErr any
			if status == nil {
				netErr = "timeout"
			}
			dir, svc, op := 0, fmt.Sprintf("svc-%d", i%6), fmt.Sprintf("GET /r%d/{id}", i%8)
			if i%5 >= 3 {
				dir, svc, op = 1, fmt.Sprintf("host:api%d.ext%d.example", i%30, i%7), fmt.Sprintf("POST /v1/x%d", i%4)
			}
			if _, err := st.ExecContext(ctx, ts, ts, src, pol, dir, svc, op, status, netErr, int64(i%900)); err != nil {
				t.Fatal(err)
			}
		}
		st.Close()
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		done = min(n, done+chunk)
	}
	// The rows predate the aggregates: hand them to the backfill.
	if _, err := db.ExecContext(ctx, `UPDATE intake_agg_state SET v = CASE k WHEN 'hi' THEN (SELECT max(id) FROM intake_events)
		ELSE (SELECT min(id) FROM intake_events) END`); err != nil {
		t.Fatal(err)
	}
}
