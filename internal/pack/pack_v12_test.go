package pack_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// load builds the demo pack with a mutation and loads it.
func load(t *testing.T, mutate func(sp *packtest.Spec), opt pack.Options) (*pack.Pack, error) {
	t.Helper()
	spec := packtest.DemoSpec()
	if mutate != nil {
		mutate(&spec)
	}
	b, err := packtest.Build(filepath.Join(t.TempDir(), "p"), spec)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := pack.ParseKeySet(b.Keys)
	if err != nil {
		t.Fatal(err)
	}
	opt.Keys = ks
	if opt.MaxAge == 0 {
		opt.MaxAge = -1 // the fixture is dated 2026-10-19: no age check
	}
	return pack.Load(b.Dir, opt)
}

func replaceIn(file, old, new string) func(sp *packtest.Spec) {
	return func(sp *packtest.Spec) {
		s := string(sp.Files[file])
		if !strings.Contains(s, old) {
			panic("missing " + old)
		}
		sp.Files[file] = []byte(strings.Replace(s, old, new, 1))
	}
}

func TestNotAfter(t *testing.T) {
	set := func(v string) func(sp *packtest.Spec) {
		return func(sp *packtest.Spec) { sp.Manifest["not_after"] = v }
	}
	now := func(s string) pack.Options {
		v, _ := time.Parse(time.RFC3339, s)
		return pack.Options{Now: func() time.Time { return v }}
	}
	p, err := load(t, set("2026-12-01T00:00:00Z"), now("2026-11-30T23:59:59Z"))
	if err != nil || p.NotAfter.Format(time.RFC3339) != "2026-12-01T00:00:00Z" {
		t.Fatalf("valid pack: %v", err)
	}
	// at or after not_after: pack_expired
	for _, at := range []string{"2026-12-01T00:00:00Z", "2027-06-01T00:00:00Z"} {
		if _, err := load(t, set("2026-12-01T00:00:00Z"), now(at)); !errors.Is(err, pack.ErrExpired) || !strings.Contains(err.Error(), "pack_expired") {
			t.Fatalf("at %s: %v", at, err)
		}
	}
	// the local limit applies too, whichever is stricter
	opt := now("2026-11-30T00:00:00Z")
	opt.MaxAge = time.Hour
	if _, err := load(t, set("2026-12-01T00:00:00Z"), opt); !errors.Is(err, pack.ErrExpired) {
		t.Fatalf("max age: %v", err)
	}
	// not_after must be later than created_at, and a date-time
	for _, bad := range []string{"2026-10-19T03:20:00Z", "2026-01-01T00:00:00Z", "soon"} {
		if _, err := load(t, set(bad), pack.Options{}); !errors.Is(err, pack.ErrManifest) {
			t.Fatalf("not_after %q: %v", bad, err)
		}
	}
}

func expectContentError(t *testing.T, cases map[string]func(sp *packtest.Spec)) {
	t.Helper()
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, mut, pack.Options{}); !errors.Is(err, pack.ErrContent) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
}

func TestRulesV12Strictness(t *testing.T) {
	expectContentError(t, map[string]func(sp *packtest.Spec){
		"unknown field in read_by":      replaceIn("rules.json", `"scope":"owner"`, `"scope":"owner","bogus":1`),
		"bad scope":                     replaceIn("rules.json", `"scope":"owner"`, `"scope":"team"`),
		"bad foreign":                   replaceIn("rules.json", `"foreign":"forbidden"`, `"foreign":"maybe"`),
		"read_by of an unknown service": replaceIn("rules.json", `"scope":"owner","service":"shop-api"`, `"scope":"owner","service":"nope"`),
		"by.owner on a single read": replaceIn("rules.json",
			`"by":{"from":"req.path","name":"id"},"foreign":"not_found"`,
			`"by":{"from":"req.path","name":"id","owner":true},"foreign":"not_found"`),
		"offset and cursor together": replaceIn("rules.json", `"offset":{"from":"req.query","name":"offset"}`,
			`"offset":{"from":"req.query","name":"offset"},"cursor":{"from":"req.query","name":"c"}`),
		"next_cursor without cursor":       replaceIn("rules.json", `"count":"$.count"`, `"count":"$.count","next_cursor":"$.next"`),
		"relation to an unknown entity":    replaceIn("rules.json", `{"entity":"shipment","field":"shipmentId"}`, `{"entity":"parcel","field":"shipmentId"}`),
		"range with min > max":             replaceIn("rules.json", `{"max":"10m","min":"2m"}`, `{"max":"2m","min":"10m"}`),
		"range without max":                replaceIn("rules.json", `{"max":"10m","min":"2m"}`, `{"min":"2m"}`),
		"embedded reference":               replaceIn("rules.json", `"orderId":"${order}"`, `"orderId":"id-${order}"`),
		"unbound target_id":                replaceIn("rules.json", `"target_id":"${order}"`, `"target_id":"${nobody}"`),
		"effect ref to a non-ancestor":     replaceIn("rules.json", `"shipmentId":"${effect:shipment-requested}"`, `"shipmentId":"${effect:shipment-cancelled}"`),
		"effect ref to an unknown effect":  replaceIn("rules.json", `"shipmentId":"${effect:shipment-requested}"`, `"shipmentId":"${effect:ghost}"`),
		"effect with create and target_id": replaceIn("rules.json", `"target_id":"${order}"`, `"target_id":"${order}","create":{"a":"b"}`),
		// rules v1.7: where is a literal guard of a set; ${not:} negates a
		// field of the target, so never in a creation.
		"where with a reference": replaceIn("rules.json", `"target_id":"${order}"`, `"target_id":"${order}","where":{"status":"${order}"}`),
		"where on a creation":    replaceIn("rules.json", `"create":{"orderId":"${order}"`, `"where":{"status":"PENDING"},"create":{"orderId":"${order}"`),
		"${not:} in a creation":  replaceIn("rules.json", `"orderId":"${order}"`, `"orderId":"${not:status}"`),
		"${not:} of a bad field": replaceIn("rules.json", `"shipmentId":"${effect:shipment-requested}"`, `"shipmentId":"${not:a..b}"`),
		// rules v1.8: target_key needs a keyed entity and excludes the
		// other targets; a limit excludes times and counts from the request.
		"target_key on an entity with an id": replaceIn("rules.json", `"target_id":"${order}"`, `"target_key":{}`),
		"target_key with target_id":          replaceIn("rules.json", `"target_id":"${order}"`, `"target_id":"${order}","target_key":{}`),
		"outcome missing the referenced effect": replaceIn("rules.json",
			`"effects":["shipment-requested","order-linked"],"name":"never-shipped"`,
			`"effects":["order-linked"],"name":"never-shipped"`),
	})
}

func TestWorldV12Checks(t *testing.T) {
	expectContentError(t, map[string]func(sp *packtest.Spec){
		"dangling relation": replaceIn("world.jsonl", `"shipmentId":"SHP-SYN-0091","status":"CONFIRMED"`, `"shipmentId":"SHP-SYN-0777","status":"CONFIRMED"`),
		"unknown owner":     replaceIn("world.jsonl", `"customer_id":"CUS-SYN-0009","due_offset_s"`, `"customer_id":"CUS-SYN-0777","due_offset_s"`),
		"pending of an unknown rule": replaceIn("world.jsonl",
			`"rule_id":"r-0007","seq":1,"type":"pending"`, `"rule_id":"r-0099","seq":1,"type":"pending"`),
		"pending of an unknown outcome": replaceIn("world.jsonl",
			`"outcome":"happy","rule_id":"r-0007","seq":1,"type":"pending"`, `"outcome":"nope","rule_id":"r-0007","seq":1,"type":"pending"`),
		"pending changes another entity": replaceIn("world.jsonl",
			`"entity":"shipment","id":"SHP-SYN-0092","outcome":"happy","rule_id":"r-0007","seq":2`,
			`"entity":"order","id":"ORD-SYN-0060","outcome":"happy","rule_id":"r-0007","seq":2`),
		"pending of a missing entity": replaceIn("world.jsonl",
			`"id":"SHP-SYN-0092","outcome":"happy","rule_id":"r-0007","seq":2`, `"id":"SHP-SYN-0888","outcome":"happy","rule_id":"r-0007","seq":2`),
		"pending out of order": replaceIn("world.jsonl", `"due_offset_s":3600`, `"due_offset_s":100`),
		"pending offset zero":  replaceIn("world.jsonl", `"due_offset_s":300`, `"due_offset_s":0`),
		"history after t0":     replaceIn("world.jsonl", `"at":"2026-10-18T23:55:00Z"`, `"at":"2026-10-19T00:00:00Z"`),
		"rows out of order": func(sp *packtest.Spec) {
			lines := strings.Split(strings.TrimSuffix(string(sp.Files["world.jsonl"]), "\n"), "\n")
			lines[1], lines[4] = lines[4], lines[1] // an entity row before the customers
			sp.Files["world.jsonl"] = []byte(strings.Join(lines, "\n") + "\n")
		},
		"unknown row type": replaceIn("world.jsonl", `"type":"meta"`, "\"type\":\"meta\"}\n{\"type\":\"mystery\""),
	})
}

func TestScenariosChecks(t *testing.T) {
	expectContentError(t, map[string]func(sp *packtest.Spec){
		"unknown customer":       replaceIn("scenarios.json", `"customer":"CUS-SYN-0007"`, `"customer":"CUS-SYN-0555"`),
		"unknown archetype":      replaceIn("scenarios.json", `"archetype":"arch-03"`, `"archetype":"arch-99"`),
		"customer and archetype": replaceIn("scenarios.json", `"customer":"CUS-SYN-0007"`, `"customer":"CUS-SYN-0007","archetype":"arch-03"`),
		"unknown rule":           replaceIn("scenarios.json", `"rule":"r-0007"`, `"rule":"r-0099"`),
		"batch rule":             replaceIn("scenarios.json", `"rule":"r-0007"`, `"rule":"r-0012"`),
		"unknown outcome":        replaceIn("scenarios.json", `"outcome":"cancelled"`, `"outcome":"vanished"`),
		"unsorted ids":           replaceIn("scenarios.json", `"id":"tracking-down"`, `"id":"aaa-first"`),
		"unknown service":        replaceIn("scenarios.json", `"service":"shipping-ext"`, `"service":"nope"`),
		"unknown field":          replaceIn("scenarios.json", `"seed":7`, `"seed":7,"colour":"red"`),
		"wrong format":           replaceIn("scenarios.json", `tt.scenarios/v1`, `tt.scenarios/v9`),
	})
}

// The raw verified bytes stay available for the exporter.
func TestFilesAreKept(t *testing.T) {
	p, err := load(t, nil, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "rules.json", "world.jsonl", "scenarios.json", "contracts/shop-api.openapi.json"} {
		if len(p.Files[name]) == 0 {
			t.Errorf("%s missing from Files", name)
		}
	}
}
