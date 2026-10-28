package core_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

type catalogAnswer struct {
	Services []struct {
		Name string `json:"name"`
		Ops  []struct {
			Op string `json:"op"`
		} `json:"ops"`
	} `json:"services"`
	Entities []struct {
		Name string `json:"name"`
	} `json:"entities"`
}

func (c catalogAnswer) opsOf(service string) map[string]bool {
	out := map[string]bool{}
	for _, s := range c.Services {
		if s.Name == service {
			for _, o := range s.Ops {
				out[o.Op] = true
			}
		}
	}
	return out
}

// fillTwoTeamsValid is fillTwoTeams with canonical event bodies, so that the
// contracts can be inferred from them.
func fillTwoTeamsValid(t *testing.T, db *store.DB) {
	t.Helper()
	fillTwoTeams(t, db)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DELETE FROM intake_events`); err != nil {
		t.Fatal(err)
	}
	type row struct {
		src, pol string
		dir      int
		svc, op  string
		path     string
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	rows := []row{
		{"src-lib", "p-library", 0, "library-loans-api", "POST /loans", "/loans"},
		{"src-lib", "p-library", 1, "host:ip:private:9301", "GET /v1/books/{id}", "/v1/books/{drop:str:digits}"},
		{"src-piz", "p-pizzeria", 0, "pizzeria-orders", "POST /orders", "/orders"},
		{"src-piz", "p-pizzeria", 1, "host:ip:private:9301", "POST /v1/charges", "/v1/charges"},
	}
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 200; i++ {
		r := rows[i%len(rows)]
		at := base.Add(time.Duration(i) * time.Second)
		dir := "inbound"
		if r.dir == 1 {
			dir = "outbound"
		}
		// Canonical form: keys in alphabetical order.
		body := fmt.Sprintf(`{"dir":%q,"latency_ms":12,"op":%q,"policy":{"hash":%q,"id":%q,"version":1},`+
			`"req":{"path":%q},"resp":{"body":{"id":"drop:str:l8"},"ct":"application/json"},"route_source":"framework","sampled_by":"random",`+
			`"schema":"tt.http.exchange/v1","service":%q,"source":{"id":%q,"kind":"sdk-node","version":"1.0.0"},"status":200,"ts":%q}`,
			dir, r.op, hash, r.pol, r.path, r.svc, r.src, at.UTC().Format("2006-01-02T15:04:05.000Z"))
		if _, err := db.ExecContext(ctx, `INSERT INTO intake_events (received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op,
			route_source, status, latency_ms, body) VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, 200, 12, ?)`,
			at.UnixMilli(), at.UnixMilli(), r.src, r.pol, r.dir, r.svc, r.op, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE intake_agg_state SET v = CASE k WHEN 'hi' THEN (SELECT max(id) FROM intake_events)
		ELSE (SELECT min(id) FROM intake_events) END`); err != nil {
		t.Fatal(err)
	}
}

// Usability test 5: choosing payments-ext in the rule editor showed the
// operations of other teams. Two groups whose traffic reaches a service of
// the same name each get only their own operations.
func TestRuleCatalogIsScopedToTheGroupOnASharedServiceName(t *testing.T) {
	_, ada, _ := listCoreWith(t, func(db *store.DB) { fillTwoTeamsValid(t, db) })
	eventually(t, 20*time.Second, "aggregates", func() bool {
		var all []svcRow
		ada.json(200, "GET", "/api/v1/services", nil, &all)
		return len(all) == 4
	})
	const shared = "host:ip:private:9301"
	var lib, piz, both catalogAnswer
	ada.json(200, "GET", "/api/v1/rules/catalog?group=library", nil, &lib)
	ada.json(200, "GET", "/api/v1/rules/catalog?group=pizzeria", nil, &piz)
	ada.json(200, "GET", "/api/v1/rules/catalog", nil, &both)

	if ops := lib.opsOf(shared); !ops["GET /v1/books/{id}"] || ops["POST /v1/charges"] {
		t.Errorf("library sees %v on %s", ops, shared)
	}
	if ops := piz.opsOf(shared); !ops["POST /v1/charges"] || ops["GET /v1/books/{id}"] {
		t.Errorf("pizzeria sees %v on %s", ops, shared)
	}
	for _, s := range lib.Services {
		if s.Name == "pizzeria-orders" {
			t.Errorf("library sees the service of pizzeria")
		}
	}
	for _, s := range piz.Services {
		if s.Name == "library-loans-api" {
			t.Errorf("pizzeria sees the service of library")
		}
	}
	// Without a selection a person with access to every group sees both.
	if ops := both.opsOf(shared); !ops["GET /v1/books/{id}"] || !ops["POST /v1/charges"] {
		t.Errorf("all groups: %v", ops)
	}
	// After a snapshot per group the catalog follows the stored snapshots
	// (no inference) and stays scoped.
	for _, g := range []string{"library", "pizzeria"} {
		if code, b := ada.do("POST", "/api/v1/contracts/"+shared+"/snapshots?group="+g, map[string]any{"recent": true}); code != 201 {
			t.Fatalf("snapshot of %s for %s = %d: %s", shared, g, code, b)
		}
	}
	lib, piz = catalogAnswer{}, catalogAnswer{}
	ada.json(200, "GET", "/api/v1/rules/catalog?group=library", nil, &lib)
	ada.json(200, "GET", "/api/v1/rules/catalog?group=pizzeria", nil, &piz)
	if ops := lib.opsOf(shared); !ops["GET /v1/books/{id}"] || ops["POST /v1/charges"] {
		t.Errorf("from the snapshot, library sees %v on %s", ops, shared)
	}
	if ops := piz.opsOf(shared); !ops["POST /v1/charges"] || ops["GET /v1/books/{id}"] {
		t.Errorf("from the snapshot, pizzeria sees %v on %s", ops, shared)
	}
	var none catalogAnswer
	ada.json(200, "GET", "/api/v1/rules/catalog?group=nobody", nil, &none)
	if len(none.Services) != 0 {
		t.Errorf("a group without traffic sees %d services", len(none.Services))
	}
}

// catalogBudget is what the rule editor's catalog may take on the lab-sized
// store (it took about 100 s with 1.25 M events: every contract of the
// console was inferred from the raw events at each opening).
const catalogBudget = 2 * time.Second

// TestRuleCatalogIsFastOnALargeStore: a group with little traffic opens the
// editor at once on a store of a million events that belong to other groups,
// the first time and then from the cache. TT_CATALOG_EVENTS overrides the size.
func TestRuleCatalogIsFastOnALargeStore(t *testing.T) {
	if testing.Short() {
		t.Skip("large store")
	}
	if raceEnabled {
		t.Skip("latency budget: not meaningful under the race detector")
	}
	n := largeStoreEvents
	if v := os.Getenv("TT_CATALOG_EVENTS"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	_, ada, _ := listCoreWith(t, func(db *store.DB) {
		fillEvents(t, db, n)
		canonicalizeSource(t, db, "src-00")
		// src-00 is the small team's source (1/20 of the events), the other
		// 19 sources belong to the big one.
		ctx := context.Background()
		q := `INSERT INTO fleet_groups (name, description, policy_id, allowed_service_names, created_at, updated_at) VALUES
			('small', '', 'p-0', '[]', 0, 0), ('big', '', 'p-1', '[]', 0, 0)`
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO fleet_source_groups (source_id, grp, service_name) VALUES ('src-00', 'small', 'svc')`); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < 20; i++ {
			if _, err := db.ExecContext(ctx, `INSERT INTO fleet_source_groups (source_id, grp, service_name) VALUES (?, 'big', 'svc')`, "src-"+pad2(i)); err != nil {
				t.Fatal(err)
			}
		}
	})
	eventually(t, 5*time.Minute, "aggregates", func() bool {
		var all []svcRow
		ada.json(200, "GET", "/api/v1/services", nil, &all)
		return len(all) > 0
	})
	var services []struct {
		Name string `json:"name"`
		Ops  []struct {
			Op string `json:"op"`
		} `json:"ops"`
	}
	for round, name := range []string{"first call", "cached call"} {
		began := time.Now()
		var cat catalogAnswer
		ada.json(200, "GET", "/api/v1/rules/catalog?group=small", nil, &cat)
		took := time.Since(began)
		t.Logf("%s: %s, %d services (%d events in the store)", name, took.Round(time.Millisecond), len(cat.Services), n)
		if took > budget(catalogBudget) {
			t.Errorf("%s of the catalog took %s on %d events (budget %s)", name, took, n, budget(catalogBudget))
		}
		if round == 0 && len(cat.Services) == 0 {
			t.Error("the small group has traffic but the catalog is empty")
		}
		services = cat.Services
	}
	// Once the group's services are snapshotted (the contract engine does it
	// at every window), the catalog reads the stored snapshots only: no
	// event is read, whatever the size of the store.
	for _, s := range services {
		if code, b := ada.do("POST", "/api/v1/contracts/"+s.Name+"/snapshots?group=small", map[string]any{"recent": true}); code != 201 {
			t.Fatalf("snapshot of %s = %d: %s", s.Name, code, b)
		}
	}
	began := time.Now()
	var cat catalogAnswer
	ada.json(200, "GET", "/api/v1/rules/catalog?group=small", nil, &cat)
	took := time.Since(began)
	t.Logf("from the snapshots: %s, %d services", took.Round(time.Millisecond), len(cat.Services))
	if took > catalogBudget/4 || len(cat.Services) != len(services) {
		t.Errorf("catalog from the snapshots: %s (budget %s), %d services of %d", took, catalogBudget/4, len(cat.Services), len(services))
	}
}

func pad2(i int) string {
	if i < 10 {
		return "0" + strconv.Itoa(i)
	}
	return strconv.Itoa(i)
}

// canonicalizeSource gives the events of one source canonical bodies, so
// that the contracts of its traffic can be inferred (fillEvents writes {}).
func canonicalizeSource(t *testing.T, db *store.DB, src string) {
	t.Helper()
	ctx := context.Background()
	type row struct {
		id, ts       int64
		pol, svc, op string
		dir          int
		status       *int
	}
	rows, err := db.QueryContext(ctx, `SELECT id, ts_ms, policy_id, dir, service, op, status FROM intake_events WHERE source_id = ?`, src)
	if err != nil {
		t.Fatal(err)
	}
	var all []row
	for rows.Next() {
		var r row
		var st *int
		if err := rows.Scan(&r.id, &r.ts, &r.pol, &r.dir, &r.svc, &r.op, &st); err != nil {
			t.Fatal(err)
		}
		r.status = st
		all = append(all, r)
	}
	rows.Close()
	hash := "sha256:" + strings.Repeat("a", 64)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	up, err := tx.PrepareContext(ctx, `UPDATE intake_events SET body = ? WHERE id = ?`)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		dir := "inbound"
		if r.dir == 1 {
			dir = "outbound"
		}
		path := "/" + strings.ReplaceAll(strings.SplitN(r.op, " ", 2)[1][1:], "{id}", "{drop:str:digits}")
		out := `"resp":{"body":{"id":"drop:str:l8"},"ct":"application/json"},`
		tail := `"status":200,`
		if r.status == nil {
			out, tail = "", `"net_error":"timeout",`
		} else {
			tail = fmt.Sprintf(`"status":%d,`, *r.status)
		}
		// Canonical form: keys in alphabetical order (net_error sorts before op, status after source).
		var body string
		ts := time.UnixMilli(r.ts).UTC().Format("2006-01-02T15:04:05.000Z")
		if r.status == nil {
			body = fmt.Sprintf(`{"dir":%q,"latency_ms":12,"net_error":"timeout","op":%q,"policy":{"hash":%q,"id":%q,"version":1},"req":{"path":%q},`+
				`"route_source":"framework","sampled_by":"random","schema":"tt.http.exchange/v1","service":%q,"source":{"id":%q,"kind":"sdk-node","version":"1.0.0"},"ts":%q}`,
				dir, r.op, hash, r.pol, path, r.svc, src, ts)
		} else {
			body = fmt.Sprintf(`{"dir":%q,"latency_ms":12,"op":%q,"policy":{"hash":%q,"id":%q,"version":1},"req":{"path":%q},%s"route_source":"framework","sampled_by":"random",`+
				`"schema":"tt.http.exchange/v1","service":%q,"source":{"id":%q,"kind":"sdk-node","version":"1.0.0"},%s"ts":%q}`,
				dir, r.op, hash, r.pol, path, out, r.svc, src, tail, ts)
		}
		if _, err := up.ExecContext(ctx, []byte(body), r.id); err != nil {
			t.Fatal(err)
		}
	}
	up.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
