package mock

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCronNext(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		expr, after, want string
	}{
		{"0 2 * * *", "2026-10-19T00:00:00Z", "2026-10-19T02:00:00Z"},
		{"0 2 * * *", "2026-10-19T02:00:00Z", "2026-10-20T02:00:00Z"}, // strictly after
		{"0 2 * * *", "2026-10-19T01:59:59Z", "2026-10-19T02:00:00Z"},
		{"*/15 * * * *", "2026-10-19T10:07:00Z", "2026-10-19T10:15:00Z"},
		{"30 8 1 * *", "2026-10-19T00:00:00Z", "2026-11-01T08:30:00Z"},
		{"0 0 * * 1", "2026-10-19T00:00:00Z", "2026-10-26T00:00:00Z"}, // Monday after Monday 19th
		{"0 0 * * 7", "2026-10-19T00:00:00Z", "2026-10-25T00:00:00Z"}, // 7 = Sunday
		{"0,30 9-10 * * *", "2026-10-19T09:30:00Z", "2026-10-19T10:00:00Z"},
		{"0 0 29 2 *", "2026-10-19T00:00:00Z", "2028-02-29T00:00:00Z"},
		{"0 0 1 1 1", "2026-10-19T00:00:00Z", "2027-01-01T00:00:00Z"}, // day-of-month OR day-of-week
	}
	for _, tc := range cases {
		c, err := parseCron(tc.expr)
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		got, ok := c.next(at(tc.after))
		if !ok || !got.Equal(at(tc.want)) {
			t.Errorf("%s after %s = %v, want %s", tc.expr, tc.after, got, tc.want)
		}
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "*/0 * * * *", "5-1 * * * *", "a * * * *"} {
		if _, err := parseCron(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	never, _ := parseCron("0 0 31 2 *")
	if _, ok := never.next(at("2026-01-01T00:00:00Z")); ok {
		t.Error("31 February must never fire")
	}
}

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	v, err := decodeJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSchemaValidation(t *testing.T) {
	doc := mustJSON(t, `{"components":{"schemas":{
		"Item":{"type":"object","required":["sku"],"properties":{"sku":{"type":"string","pattern":"^SKU-[0-9]+$"},"qty":{"type":"integer","minimum":1,"maximum":3}},"additionalProperties":false},
		"List":{"type":"array","minItems":1,"items":{"$ref":"#/components/schemas/Item"}},
		"Either":{"oneOf":[{"type":"string","enum":["a","b"]},{"type":"integer"}]},
		"Nullable":{"type":["string","null"],"format":"date-time"}}}}`).(map[string]any)
	sc := &schemaCtx{doc: doc}
	ref := func(n string) any { return map[string]any{"$ref": "#/components/schemas/" + n} }
	cases := []struct {
		schema, value, ptr string
		ok                 bool
	}{
		{"List", `[{"sku":"SKU-1","qty":2}]`, "", true},
		{"List", `[]`, "", false},
		{"List", `[{"sku":"SKU-1"},{"sku":"bad"}]`, "/1/sku", false},
		{"List", `[{"sku":"SKU-1","qty":4}]`, "/0/qty", false},
		{"List", `[{"sku":"SKU-1","qty":1.5}]`, "/0/qty", false},
		{"List", `[{"sku":"SKU-1","qty":2.0}]`, "", true}, // 2.0 is an integer
		{"List", `[{"sku":"SKU-1","extra":1}]`, "/0/extra", false},
		{"List", `[{"qty":1}]`, "/0/sku", false},
		{"List", `{}`, "", false},
		{"Either", `"a"`, "", true},
		{"Either", `"c"`, "", false},
		{"Either", `7`, "", true},
		{"Nullable", `null`, "", true},
		{"Nullable", `"2026-10-19T00:00:00Z"`, "", true},
		{"Nullable", `"yesterday"`, "", false},
	}
	for _, tc := range cases {
		v := sc.validate(ref(tc.schema), mustJSON(t, tc.value), "", 0)
		if (v == nil) != tc.ok {
			t.Errorf("%s %s: violation = %v", tc.schema, tc.value, v)
			continue
		}
		if v != nil && v.ptr != tc.ptr {
			t.Errorf("%s %s: pointer = %q, want %q", tc.schema, tc.value, v.ptr, tc.ptr)
		}
	}
	// pointer tokens are escaped
	obj := mustJSON(t, `{"type":"object","required":["a/b"]}`)
	if v := sc.validate(obj, mustJSON(t, `{}`), "", 0); v == nil || v.ptr != "/a~1b" {
		t.Errorf("escaped pointer = %v", v)
	}
	// reference cycles do not hang
	cyc := &schemaCtx{doc: mustJSON(t, `{"a":{"$ref":"#/b"},"b":{"$ref":"#/a"}}`).(map[string]any)}
	if got := cyc.validate(map[string]any{"$ref": "#/a"}, "x", "", 0); got != nil {
		t.Errorf("cycle: %v", got)
	}
}

func TestBuilderUsesOverlayThenExamplesThenAnnotations(t *testing.T) {
	doc := mustJSON(t, `{"components":{"schemas":{"S":{"type":"object","required":["id","status","n","at","tag"],"properties":{
		"id":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}},
		"status":{"type":"string","enum":["A","B"]},
		"n":{"type":"integer","x-tt-value":{"kind":"bucket","bounds":[10,20],"bucket_p":[0.1,0.7,0.2]}},
		"at":{"type":"string","format":"date-time"},
		"tag":{"type":"string","x-tt-value":{"kind":"enum","enum":["x","y"]}},
		"opt":{"type":"string"},
		"hidden":{"type":"string"}}}}}}`).(map[string]any)
	b := &builder{sc: &schemaCtx{doc: doc}, now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), seed: 1, key: "GET /x?", prefixes: map[string]string{"shipment": "SHP-SYN-"}}
	schema := map[string]any{"$ref": "#/components/schemas/S"}

	gen := b.generate(schema, "", 0).(map[string]any)
	if !strings.HasPrefix(gen["id"].(string), "SHP-SYN-") || gen["status"] != "A" || gen["at"] != "2026-10-19T12:00:00Z" || gen["tag"] != "x" {
		t.Fatalf("generated = %v", gen)
	}
	if gen["n"].(json.Number).String() != "10" { // the most frequent bucket is [10,20)
		t.Fatalf("bucket value = %v", gen["n"])
	}
	if _, has := gen["opt"]; has {
		t.Fatal("optional property generated")
	}
	if again := b.generate(schema, "", 0).(map[string]any); again["id"] != gen["id"] {
		t.Fatal("synthetic ids must be stable for the same request")
	}

	ov := map[string]any{"status": "B", "hidden": "state-only", "opt": "set", "extra": "never shown"}
	ex := mustJSON(t, `{"tag":"from-example","n":15}`)
	out := b.build(schema, some(ov), some(ex), "", 0).(map[string]any)
	if out["status"] != "B" || out["opt"] != "set" || out["tag"] != "from-example" || out["n"].(json.Number).String() != "15" {
		t.Fatalf("built = %v", out)
	}
	if _, has := out["extra"]; has {
		t.Fatal("state field outside the contract leaked into the response")
	}
}

func TestParseFlags(t *testing.T) {
	var sink bytes.Buffer
	c, err := ParseFlags([]string{"--pack", "p", "--seed", "9", "--faults", "off", "--latency", "record", "--addr", "127.0.0.1:0", "--max-pack-age", "24h"}, &sink)
	if err != nil {
		t.Fatal(err)
	}
	if c.Pack != "p" || c.Seed == nil || *c.Seed != 9 || c.Faults != "off" || c.Latency != LatencyRecord || c.MaxPackAge != 24*time.Hour {
		t.Fatalf("config = %+v", c.Config)
	}
	if c, err := ParseFlags([]string{"some/dir"}, &sink); err != nil || c.Pack != "some/dir" {
		t.Fatalf("positional: %v", err)
	}
	for _, bad := range [][]string{{}, {"--pack", "p", "--faults", "chaos"}, {"--pack", "p", "--latency", "x"}, {"--pack", "p", "--seed", "-1"}, {"--pack", "p", "extra"}, {"--nope"}} {
		if _, err := ParseFlags(bad, &sink); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestDefaultSessionExistsAtStartup(t *testing.T) {
	e := newEnv(t)
	r := e.ctl("GET", "/sessions/default", nil)
	if r.status != 200 || r.json()["seed"].(json.Number).String() != "42" || r.json()["scenario"] != nil { // the pack seed
		t.Fatalf("default session: %d %s", r.status, r.body)
	}
	if o := e.req("POST", "/__svc/shop-api/orders", orderBody, nil); o.status != 201 {
		t.Fatalf("order without session header: %d %s", o.status, o.body)
	}
	if r := e.ctl("DELETE", "/sessions/default", nil); r.status != 400 {
		t.Fatalf("deleting default: %d", r.status)
	}
	if r := e.ctl("POST", "/sessions/default/reset", nil); r.status != 200 {
		t.Fatalf("reset default: %d", r.status)
	}
	// a malformed or unknown session header never falls back to the default
	if r := e.req("GET", "/__svc/shop-api/ping", nil, map[string]string{"X-TT-Session": "no such/session"}); r.status != 400 {
		t.Fatalf("malformed: %d", r.status)
	}
	if r := e.req("GET", "/__svc/shop-api/ping", nil, map[string]string{"X-TT-Session": "ghost"}); r.status != 404 {
		t.Fatalf("unknown: %d", r.status)
	}
}

func TestWrongContentTypeAndOversizeBody(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	r := e.req("POST", "/__svc/shop-api/orders", "email=a", map[string]string{"X-TT-Session": sid, "Content-Type": "text/plain"})
	if r.status != 400 {
		t.Fatalf("text/plain body: %d", r.status)
	}
	big := `{"email":"` + strings.Repeat("a", 2<<20) + `"}`
	if r := e.req("POST", "/__svc/shop-api/orders", big, sess(sid)); r.status != 413 {
		t.Fatalf("oversize: %d", r.status)
	}
}

func TestAdvanceToAndSameInstantOrder(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(nil)
	e.force(sid, "r-0007", "happy")
	id := e.order(sid)
	// jump straight over the early lifecycle: effects still apply one by one, in order;
	// at 00:05 the pending effect of the world comes before the one queued by the session
	r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"to": "2026-10-19T04:05:00Z"})
	got := strings.Join(appliedLines(r.json()["applied"].([]any)), "|")
	want := strings.Join([]string{
		"2026-10-19T00:05:00Z r-0007 shipment-created SHP-SYN-0093", // world
		"2026-10-19T00:05:00Z r-0007 shipment-created SHP-SYN-0094", // session
		"2026-10-19T01:00:00Z r-0007 shipment-delivered SHP-SYN-0092",
		"2026-10-19T02:00:00Z r-0012 batch SHP-SYN-0091",
		"2026-10-19T02:05:00Z r-0007 shipment-in-transit SHP-SYN-0093",
		"2026-10-19T04:05:00Z r-0007 shipment-in-transit SHP-SYN-0094",
	}, "|")
	if got != want {
		t.Fatalf("applied =\n%s\nwant\n%s", strings.ReplaceAll(got, "|", "\n"), strings.ReplaceAll(want, "|", "\n"))
	}
	if s := e.shipments(sid, id)[0].(map[string]any); s["status"] != "IN_TRANSIT" {
		t.Fatalf("shipment = %v", s)
	}
	if nd := e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()["next_due"]; nd != "2026-10-20T01:00:00Z" {
		t.Fatalf("next_due = %v", nd)
	}
}
