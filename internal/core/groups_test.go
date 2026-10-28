package core_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

// fillTwoTeams stores the traffic of two teams whose fake external APIs
// listen on the same 127.0.0.1:9301 (usability test 3): team library
// (source src-lib, policy p-library) and team pizzeria (src-piz,
// p-pizzeria), each with its inbound service and its calls to
// host:ip:private:9301 on its own operation. The sources are attributed to
// their groups as the fleet migration does (fleet_source_groups).
func fillTwoTeams(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO fleet_groups (name, description, policy_id, allowed_service_names, created_at, updated_at) VALUES
			('library', '', 'p-library', '[]', 0, 0), ('pizzeria', '', 'p-pizzeria', '[]', 0, 0)`,
		`INSERT INTO fleet_source_groups (source_id, grp, service_name) VALUES
			('src-lib', 'library', 'library-loans-api'), ('src-piz', 'pizzeria', 'pizzeria-orders')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-2 * time.Hour).UnixMilli()
	type row struct {
		src, pol string
		dir      int
		svc, op  string
	}
	rows := []row{
		{"src-lib", "p-library", 0, "library-loans-api", "POST /loans"},
		{"src-lib", "p-library", 1, "host:ip:private:9301", "GET /v1/books/{id}"},
		{"src-piz", "p-pizzeria", 0, "pizzeria-orders", "POST /orders"},
		{"src-piz", "p-pizzeria", 1, "host:ip:private:9301", "POST /v1/charges"},
	}
	for i := 0; i < 200; i++ {
		r := rows[i%len(rows)]
		ts := base + int64(i)*1000
		if _, err := db.ExecContext(ctx, `INSERT INTO intake_events (received_ms, ts_ms, source_id, policy_id, policy_version, dir, service, op,
			route_source, status, latency_ms, body) VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, 200, 12, x'7b7d')`, ts, ts, r.src, r.pol, r.dir, r.svc, r.op); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE intake_agg_state SET v = CASE k WHEN 'hi' THEN (SELECT max(id) FROM intake_events)
		ELSE (SELECT min(id) FROM intake_events) END`); err != nil {
		t.Fatal(err)
	}
}

type svcRow struct {
	Service string `json:"service"`
	Group   string `json:"group"`
	Calls   int64  `json:"calls"`
}

type hostsAnswer struct {
	Domains []struct {
		Patterns []struct {
			Pattern string `json:"pattern"`
			Group   string `json:"group"`
			Calls   int64  `json:"calls"`
		} `json:"patterns"`
	} `json:"domains"`
}

// TestTwoGroupsSameHostPort: two teams calling the same host:port are two
// services and two hosts, each with its own calls; every list keeps only
// the selected group's rows.
func TestTwoGroupsSameHostPort(t *testing.T) {
	_, ada, _ := listCoreWith(t, func(db *store.DB) { fillTwoTeams(t, db) })
	var all []svcRow
	eventually(t, 20*time.Second, "aggregates", func() bool {
		all = nil
		ada.json(200, "GET", "/api/v1/services", nil, &all)
		return len(all) == 4
	})
	shared := map[string]int64{}
	for _, s := range all {
		if s.Service == "host:ip:private:9301" {
			shared[s.Group] = s.Calls
		}
	}
	if len(shared) != 2 || shared["library"] != 50 || shared["pizzeria"] != 50 {
		t.Errorf("host:ip:private:9301 must be one row per group with its own calls: %v", shared)
	}
	var lib []svcRow
	ada.json(200, "GET", "/api/v1/services?group=library", nil, &lib)
	for _, s := range lib {
		if s.Group != "library" || s.Service == "pizzeria-orders" {
			t.Errorf("services?group=library: %v", s)
		}
	}
	if len(lib) != 2 {
		t.Errorf("services?group=library: %d rows, want 2", len(lib))
	}

	var h hostsAnswer
	ada.json(200, "GET", "/api/v1/hosts", nil, &h)
	entries := map[string]int64{}
	for _, d := range h.Domains {
		for _, p := range d.Patterns {
			if p.Pattern == "ip:private:9301" {
				entries[p.Group] = p.Calls
			}
		}
	}
	if len(entries) != 2 || entries["library"] != 50 {
		t.Errorf("hosts: the shared pattern must be one entry per group: %v", entries)
	}
	h = hostsAnswer{}
	ada.json(200, "GET", "/api/v1/hosts?group=pizzeria", nil, &h)
	for _, d := range h.Domains {
		for _, p := range d.Patterns {
			if p.Group != "pizzeria" {
				t.Errorf("hosts?group=pizzeria lists %s of %q", p.Pattern, p.Group)
			}
		}
	}

	// The contract of one group's calls only (live, before a snapshot).
	code, body := ada.do("GET", "/api/v1/contracts/host:ip:private:9301?group=library", nil)
	if code == 200 && strings.Contains(string(body), "charges") {
		t.Errorf("library's contract of the shared host shows pizzeria's operation")
	}

	// The scope still maps the shared name to both groups (the header filter).
	var scope struct {
		Services map[string][]string `json:"services"`
	}
	ada.json(200, "GET", "/api/v1/scope", nil, &scope)
	if len(scope.Services["host:ip:private:9301"]) != 2 {
		t.Errorf("scope: %v", scope.Services)
	}
}

// TestGroupFilterCoverage: every list of the console takes ?group= and a
// group without data gets nothing of the others.
func TestGroupFilterCoverage(t *testing.T) {
	_, ada, _ := listCoreWith(t, func(db *store.DB) { fillTwoTeams(t, db) })
	eventually(t, 20*time.Second, "aggregates", func() bool {
		var all []svcRow
		ada.json(200, "GET", "/api/v1/services", nil, &all)
		return len(all) == 4
	})
	empty := func(path string) {
		t.Helper()
		code, b := ada.do("GET", path, nil)
		if code != 200 {
			t.Errorf("%s = %d: %s", path, code, b)
			return
		}
		var list []json.RawMessage
		if err := json.Unmarshal(b, &list); err != nil {
			t.Errorf("%s: not a list: %s", path, b)
			return
		}
		if len(list) != 0 {
			t.Errorf("%s: %d rows of other groups: %s", path, len(list), b)
		}
	}
	for _, p := range []string{
		"/api/v1/services?group=nobody",
		"/api/v1/contracts?group=nobody",
		"/api/v1/gaps?group=nobody",
		"/api/v1/drift?group=nobody",
		"/api/v1/quarantine?group=nobody",
		"/api/v1/rules?group=nobody",
		"/api/v1/worlds?group=nobody",
		"/api/v1/packs?group=nobody",
		"/api/v1/fleet/policies?group=nobody",
	} {
		empty(p)
	}
	var h hostsAnswer
	ada.json(200, "GET", "/api/v1/hosts?group=nobody", nil, &h)
	if len(h.Domains) != 0 {
		t.Errorf("hosts?group=nobody: %d domains", len(h.Domains))
	}
	var arch struct {
		Built bool   `json:"built"`
		Group string `json:"group"`
	}
	ada.json(200, "GET", "/api/v1/archetypes?group=library", nil, &arch)
	if arch.Built || arch.Group != "library" {
		t.Errorf("archetypes?group=library: %+v", arch)
	}
	// Comma-separated groups select both.
	var both []svcRow
	ada.json(200, "GET", "/api/v1/services?group=library,pizzeria", nil, &both)
	if len(both) != 4 {
		t.Errorf("services?group=library,pizzeria: %d rows", len(both))
	}
	// The status of the miner answers with a filter too.
	if code, b := ada.do("GET", "/api/v1/rules/status?group=library", nil); code != 200 {
		t.Errorf("rules/status?group=library = %d: %s", code, b)
	}
}
