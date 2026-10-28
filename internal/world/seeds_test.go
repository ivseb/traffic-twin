package world

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// An invented service whose customers own addresses and contracts that no
// write creates (rules v1.6 seeds); contracts cite an address.
const seedContract = `{
 "openapi": "3.1.0", "info": {"title": "app-api", "version": "1"},
 "paths": {
  "/addresses": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {
    "type": "object", "required": ["items"], "properties": {"items": {"type": "array", "items": {"$ref": "#/components/schemas/Address"}}}}}}}}}},
  "/contracts": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {
    "type": "object", "required": ["items"], "properties": {"items": {"type": "array", "items": {"$ref": "#/components/schemas/Contract"}}}}}}}}}},
  "/contracts/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
    "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Contract"}}}}}}}
 },
 "components": {"schemas": {
  "Address": {"type": "object", "required": ["id", "city"], "properties": {
    "id": {"type": "string", "x-tt-value": {"kind": "id", "domain": "address"}},
    "city": {"type": "string", "x-tt-value": {"kind": "enum", "enum": ["Nord", "Sud"]}}}},
  "Contract": {"type": "object", "required": ["id", "status", "addressId"], "properties": {
    "id": {"type": "string", "x-tt-value": {"kind": "id", "domain": "contract"}},
    "status": {"type": "string", "x-tt-value": {"kind": "enum", "enum": ["ACTIVE", "SUSPENDED"]}},
    "addressId": {"type": "string", "x-tt-value": {"kind": "id", "domain": "address"}}}}
 }}
}`

const seedRules = `{
 "format": "tt.rules/v1",
 "entities": [
  {"name": "contract", "service": "app-api", "id_domain": "contract", "id_field": "id", "id_prefix": "CNT-SYN-",
   "seed": {"per_customer": [{"n": "1-2", "share": 0.5}, {"n": "3", "share": 0.5}], "values": {"status": {"ACTIVE": 1}}, "subjects": 40},
   "relations": [{"field": "addressId", "entity": "address"}],
   "read_by": [
    {"op": "GET /contracts", "at": {"from": "resp.body", "path": "$.items[*]"}, "scope": "owner"},
    {"op": "GET /contracts/{id}", "by": {"from": "req.path", "name": "id"}, "at": {"from": "resp.body", "path": "$"}, "scope": "owner"}]},
  {"name": "address", "service": "app-api", "id_domain": "address", "id_field": "id", "id_prefix": "ADR-SYN-",
   "seed": {"per_customer": [{"n": "1", "share": 1}], "subjects": 40},
   "read_by": [{"op": "GET /addresses", "at": {"from": "resp.body", "path": "$.items[*]"}, "scope": "owner"}]}
 ],
 "rules": []
}`

func seedInput(t *testing.T, seed uint64, n int) *Input {
	t.Helper()
	r, err := ParseRules([]byte(seedRules), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Input{Params: Params{Seed: seed, Customers: n, T0: testT0, Locale: "it"}, Rules: r,
		Contracts: []Contract{{Service: "app-api", Doc: []byte(seedContract)}}}
}

type worldRow struct {
	Type       string         `json:"type"`
	Entity     string         `json:"entity"`
	ID         string         `json:"id"`
	CustomerID *string        `json:"customer_id"`
	State      map[string]any `json:"state"`
}

func worldRows(t *testing.T, w []byte) []worldRow {
	var out []worldRow
	sc := bufio.NewScanner(bytes.NewReader(w))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var r worldRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestSeedsPerCustomer(t *testing.T) {
	in := seedInput(t, 7, 20)
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if probs := Verify(out.World, in.Rules); len(probs) > 0 {
		t.Fatalf("world: %v", probs)
	}
	addr := map[string]string{} // address id → owner
	contracts := map[string]int{}
	for _, r := range worldRows(t, out.World) {
		if r.Type != "entity" {
			continue
		}
		if r.CustomerID == nil {
			t.Fatalf("a seed without owner: %+v", r)
		}
		switch r.Entity {
		case "address":
			if !strings.HasPrefix(r.ID, "ADR-SYN-") || r.State["id"] != r.ID {
				t.Fatalf("address: %+v", r)
			}
			addr[r.ID] = *r.CustomerID
		}
	}
	for _, r := range worldRows(t, out.World) {
		if r.Type != "entity" || r.Entity != "contract" {
			continue
		}
		contracts[*r.CustomerID]++
		if r.State["status"] != "ACTIVE" {
			t.Fatalf("seed values not applied: %+v", r.State)
		}
		if a, _ := r.State["addressId"].(string); addr[a] != *r.CustomerID {
			t.Fatalf("contract %s cites address %q of another customer (or none)", r.ID, a)
		}
	}
	if len(addr) != 20 || len(contracts) != 20 {
		t.Fatalf("addresses %d, customers with contracts %d", len(addr), len(contracts))
	}
	for c, n := range contracts {
		if n < 1 || n > 3 {
			t.Fatalf("customer %s has %d contracts", c, n)
		}
	}
	// Deterministic.
	again, err := Generate(seedInput(t, 7, 20))
	if err != nil || !bytes.Equal(again.World, out.World) {
		t.Fatalf("not deterministic: %v", err)
	}
}

// A relative date of a seed entity (pack.md 4.4) counts from t0, not from
// the start of the window: the renewal is still ahead when the mock starts.
func TestSeedRelativeDates(t *testing.T) {
	in := seedInput(t, 3, 10)
	doc := strings.Replace(seedContract, `"required": ["id", "status", "addressId"], "properties": {`,
		`"required": ["id", "status", "addressId", "renewal"], "properties": {
    "renewal": {"type": "string", "format": "date", "x-tt-value": {"kind": "bucket", "unit": "day", "date_offset": {"min": "+30d", "max": "+60d"}}},`, 1)
	if doc == seedContract {
		t.Fatal("fixture changed")
	}
	in.Contracts = []Contract{{Service: "app-api", Doc: []byte(doc)}}
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range worldRows(t, out.World) {
		if r.Type != "entity" || r.Entity != "contract" {
			continue
		}
		d, err := time.Parse("2006-01-02", fmt.Sprint(r.State["renewal"]))
		if err != nil {
			t.Fatalf("renewal %v: %v", r.State["renewal"], err)
		}
		if off := d.Sub(testT0.Truncate(24 * time.Hour)); off < 29*24*time.Hour || off > 61*24*time.Hour {
			t.Fatalf("renewal %s is %s from t0 %s", d, off, testT0)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no contract with a renewal")
	}
}
