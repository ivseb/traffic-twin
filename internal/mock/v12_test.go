package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// editFile rewrites a JSON file of a pack spec.
func editFile(sp *packtest.Spec, name string, f func(m map[string]any)) {
	v := packtest.JSON(string(sp.Files[name])).(map[string]any)
	f(v)
	sp.Files[name] = packtest.CJSON(v)
}

func obj(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		m = m[k].(map[string]any)
	}
	return m
}

func errCode(r resp) any { return r.json()["error"].(map[string]any)["code"] }

func TestCustomerScopedReads(t *testing.T) {
	e := newEnv(t)
	own := e.newSession(map[string]any{"customer": "CUS-SYN-0007"})
	h := sess(own)

	if r := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0042", nil, h); r.status != 200 {
		t.Fatalf("own order: %d %s", r.status, r.body)
	}
	// somebody else's order is indistinguishable from a missing one
	other := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0060", nil, h)
	missing := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-9999", nil, h)
	if other.status != 404 || missing.status != 404 || errCode(other) != "ORDER_NOT_FOUND" || !bytes.Equal(other.body, missing.body) {
		t.Fatalf("foreign vs missing: %d %s / %d %s", other.status, other.body, missing.status, missing.body)
	}

	// the customer's own list; another customer's list is forbidden (foreign: forbidden)
	l := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0007/orders", nil, h)
	e.conforms("shop-api", "GET /customers/{id}/orders", 200, l)
	lj := l.json()
	if lj["customerId"] != "CUS-SYN-0007" || lj["count"].(json.Number).String() != "1" || lj["items"].([]any)[0].(map[string]any)["id"] != "ORD-SYN-0042" {
		t.Fatalf("list = %s", l.body)
	}
	if f := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0009/orders", nil, h); f.status != 403 || errCode(f) != "FORBIDDEN" {
		t.Fatalf("foreign list: %d %s", f.status, f.body)
	}

	// shipment exposed by the shop: the foreign answer uses foreign_example
	if r := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0060/shipment", nil, h); r.status != 404 || errCode(r) != "ORDER_NOT_FOUND" {
		t.Fatalf("foreign tracking: %d %s", r.status, r.body)
	}
	tr := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0042/shipment", nil, h)
	e.conforms("shop-api", "GET /orders/{id}/shipment", 200, tr)
	if j := tr.json(); j["status"] != "IN_TRANSIT" || j["updatedAt"] != "2026-10-18T12:30:00Z" || j["shipmentId"] != "SHP-SYN-0091" {
		t.Fatalf("tracking = %s", tr.body) // updatedAt comes from the history of the world
	}

	// without a customer in the session nothing is filtered
	anon := e.newSession(nil)
	if r := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0060", nil, sess(anon)); r.status != 200 {
		t.Fatalf("no customer: %d", r.status)
	}
	if r := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0009/orders", nil, sess(anon)); r.status != 200 || r.json()["customerId"] != "CUS-SYN-0009" {
		t.Fatalf("no customer list: %d %s", r.status, r.body)
	}

	// hidden: a PENDING shipment is "not found", not "foreign"
	c1 := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if r := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0070/shipment", nil, sess(c1)); r.status != 404 || errCode(r) != "SHIPMENT_NOT_FOUND" {
		t.Fatalf("hidden: %d %s", r.status, r.body)
	}
	if items := e.shipments(c1, "ORD-SYN-0070"); len(items) != 0 {
		t.Fatalf("hidden shipment listed: %v", items)
	}
}

// Entities belong to the customer of the session at the instant of the cause,
// also when the effect fires later.
func TestOwnerIsFixedAtTheCause(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(map[string]any{"customer": "CUS-SYN-0007"})
	e.force(sid, "r-0007", "happy")
	id := e.order(sid)
	e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"customer": "CUS-SYN-0009"})
	e.advance(sid, "5m")
	var views []map[string]any
	_ = json.Unmarshal(e.ctl("GET", "/sessions/"+sid+"/entities?entity=shipment&id=SHP-SYN-0094", nil).body, &views)
	if len(views) != 1 || views[0]["customer_id"] != "CUS-SYN-0007" || views[0]["state"].(map[string]any)["status"] != "CREATED" {
		t.Fatalf("entities = %v", views)
	}
	// the new customer cannot read it, the old one can
	if r := e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid)); r.status != 404 {
		t.Fatalf("foreign now: %d", r.status)
	}
	e.ctl("POST", "/sessions/"+sid+"/customer", map[string]any{"customer": "CUS-SYN-0007"})
	if r := e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid)); r.status != 200 {
		t.Fatalf("owner: %d", r.status)
	}
}

func TestListOrderingAndPagination(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(map[string]any{"customer": "CUS-SYN-0007"})
	for i := 0; i < 4; i++ {
		e.order(sid) // ORD-SYN-0071..0074, all created at t0
	}
	ids := func(q string) []string {
		r := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0007/orders"+q, nil, sess(sid))
		if r.status != 200 {
			t.Fatalf("%s: %d %s", q, r.status, r.body)
		}
		var out []string
		for _, it := range r.json()["items"].([]any) {
			out = append(out, it.(map[string]any)["id"].(string))
		}
		if n := r.json()["count"].(json.Number).String(); n != fmt.Sprint(len(out)) {
			t.Fatalf("%s: count %s for %d items", q, n, len(out))
		}
		return out
	}
	// order_by createdAt asc: the world's order first, then ties by id
	all := "ORD-SYN-0042,ORD-SYN-0071,ORD-SYN-0072,ORD-SYN-0073,ORD-SYN-0074"
	for q, want := range map[string]string{
		"":                      all,
		"?limit=2":              "ORD-SYN-0042,ORD-SYN-0071",
		"?limit=2&offset=1":     "ORD-SYN-0071,ORD-SYN-0072",
		"?limit=2&offset=4":     "ORD-SYN-0074",
		"?limit=2&offset=9":     "",
		"?offset=3":             "ORD-SYN-0073,ORD-SYN-0074",
		"?limit=100&offset=0":   all,
		"?limit=100&unknown=zz": all,
	} {
		if got := strings.Join(ids(q), ","); got != want {
			t.Errorf("%q: %s, want %s", q, got, want)
		}
	}
	for _, q := range []string{"?limit=0", "?limit=abc", "?offset=-1", "?limit=1.5"} {
		r := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0007/orders"+q, nil, sess(sid))
		name := strings.Split(strings.TrimPrefix(q, "?"), "=")[0]
		if r.status != 400 || r.json()["pointer"] != "/query/"+name {
			t.Errorf("%s: %d %s", q, r.status, r.body)
		}
	}
	// max_limit 100 clamps a larger limit
	if got := ids("?limit=100000"); len(got) != 5 {
		t.Errorf("clamped: %v", got)
	}
}

func TestCursorPagination(t *testing.T) {
	e := newEnv(t, exact(), withSpec(func(sp *packtest.Spec) {
		editFile(sp, "rules.json", func(m map[string]any) {
			list := obj(m["entities"].([]any)[0].(map[string]any)["read_by"].([]any)[1].(map[string]any), "list")
			delete(list, "offset")
			list["cursor"] = map[string]any{"from": "req.query", "name": "cursor"}
			list["next_cursor"] = "$.next"
			list["total"] = "$.total"
			list["default_limit"] = packtest.JSON("2")
		})
		editFile(sp, "contracts/shop-api.openapi.json", func(m map[string]any) {
			ps := obj(m, "components", "schemas", "OrderList", "properties")
			ps["next"] = map[string]any{"type": []any{"string", "null"}}
			ps["total"] = map[string]any{"type": "integer"}
			get := obj(m, "paths", "/customers/{id}/orders", "get")
			get["parameters"] = []any{
				map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 1}},
				map[string]any{"name": "cursor", "in": "query", "schema": map[string]any{"type": "string"}},
			}
		})
	}))
	sid := e.newSession(map[string]any{"customer": "CUS-SYN-0007"})
	for i := 0; i < 4; i++ {
		e.order(sid)
	}
	var seen []string
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		q := ""
		if cursor != "" {
			q = "?cursor=" + cursor
		}
		r := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0007/orders"+q, nil, sess(sid))
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		j := r.json()
		if j["total"].(json.Number).String() != "5" {
			t.Fatalf("total = %v", j["total"])
		}
		for _, it := range j["items"].([]any) {
			seen = append(seen, it.(map[string]any)["id"].(string))
		}
		if j["next"] == nil {
			break
		}
		cursor = j["next"].(string)
	}
	if strings.Join(seen, ",") != "ORD-SYN-0042,ORD-SYN-0071,ORD-SYN-0072,ORD-SYN-0073,ORD-SYN-0074" {
		t.Fatalf("pages: %v", seen)
	}
	if r := e.req("GET", "/__svc/shop-api/customers/CUS-SYN-0007/orders?cursor=bogus", nil, sess(sid)); r.status != 400 || r.json()["pointer"] != "/query/cursor" {
		t.Fatalf("bad cursor: %d %s", r.status, r.body)
	}
}

func TestParameterPointersFollowTheDocumentOrder(t *testing.T) {
	e := newEnv(t, withSpec(func(sp *packtest.Spec) {
		editFile(sp, "contracts/shipping-ext.openapi.json", func(m map[string]any) {
			get := obj(m, "paths", "/v1/shipments", "get")
			get["parameters"] = append(get["parameters"].([]any),
				map[string]any{"name": "X-Api-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "sid", "in": "cookie", "required": true, "schema": map[string]any{"type": "string"}})
		})
	}))
	sid := e.newSession(nil)
	get := func(q string, hdr map[string]string) resp {
		hdr["X-TT-Session"] = sid
		return e.req("GET", "/__svc/shipping-ext/v1/shipments"+q, nil, hdr)
	}
	for _, c := range []struct {
		q    string
		hdr  map[string]string
		ptr  string
		code int
	}{
		{"", map[string]string{}, "/query/orderId", 400},
		{"?orderId=x", map[string]string{}, "/headers/x-api-key", 400},
		{"?orderId=x", map[string]string{"X-Api-Key": "k"}, "/cookies/sid", 400},
		{"?orderId=x", map[string]string{"X-Api-Key": "k", "Cookie": "sid=1"}, "", 200},
	} {
		r := get(c.q, c.hdr)
		if r.status != c.code || (c.ptr != "" && r.json()["pointer"] != c.ptr) {
			t.Errorf("%s %v: %d %s", c.q, c.hdr, r.status, r.body)
		}
	}
}

func TestPendingEffectsOfTheWorld(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	var views []map[string]any
	_ = json.Unmarshal(e.ctl("GET", "/sessions/"+sid+"/entities?entity=shipment&id=SHP-SYN-0092", nil).body, &views)
	pe := views[0]["pending_effects"].([]any)[0].(map[string]any)
	if pe["effect"] != "shipment-delivered" || pe["due"] != "2026-10-19T01:00:00Z" || pe["source"] != "world" || pe["outcome"] != "happy" {
		t.Fatalf("pending = %v", pe)
	}
	if nd := e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()["next_due"]; nd != "2026-10-19T00:05:00Z" {
		t.Fatalf("next_due = %v", nd)
	}

	// SHP-SYN-0093 is PENDING in the world and becomes visible by itself
	if items := e.shipments(sid, "ORD-SYN-0070"); len(items) != 0 {
		t.Fatalf("pending shipment visible: %v", items)
	}
	applied := appliedLines(e.advance(sid, "5m"))
	if len(applied) != 1 || applied[0] != "2026-10-19T00:05:00Z r-0007 shipment-created SHP-SYN-0093" {
		t.Fatalf("applied = %v", applied)
	}
	s := e.shipments(sid, "ORD-SYN-0070")[0].(map[string]any)
	if s["status"] != "CREATED" || s["updatedAt"] != "2026-10-19T00:05:00Z" || s["service"] != "STANDARD" {
		t.Fatalf("shipment = %v", s)
	}
	e.advance(sid, "1h")
	tr := e.req("GET", "/__svc/shop-api/orders/ORD-SYN-0060/shipment", nil, sess(sid))
	if tr.json()["status"] != "DELIVERED" || tr.json()["updatedAt"] != "2026-10-19T01:00:00Z" {
		t.Fatalf("tracking = %s", tr.body)
	}
	e.advance(sid, "3d") // everything pending drained; the id counters were not disturbed
	if nd := e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()["next_due"]; nd != nil {
		t.Fatalf("next_due = %v", nd)
	}

	// reset puts the pending lines back
	e.ctl("POST", "/sessions/"+sid+"/reset", nil)
	if nd := e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()["next_due"]; nd != "2026-10-19T00:05:00Z" {
		t.Fatalf("next_due after reset = %v", nd)
	}
	if items := e.shipments(sid, "ORD-SYN-0070"); len(items) != 0 {
		t.Fatalf("state not restored: %v", items)
	}

	// offsets are relative to the t0 of the session
	late := e.newSession(map[string]any{"t0": "2026-11-01T00:00:00Z"})
	if nd := e.ctl("GET", "/sessions/"+late+"/clock", nil).json()["next_due"]; nd != "2026-11-01T00:05:00Z" {
		t.Fatalf("shifted next_due = %v", nd)
	}
}

func TestScenarioPresets(t *testing.T) {
	e := newEnv(t, exact())
	var list []map[string]any
	_ = json.Unmarshal(e.ctl("GET", "/scenarios", nil).body, &list)
	if len(list) != 2 || list[0]["id"] != "shipment-cancelled" || list[0]["customer"] != "CUS-SYN-0007" || list[1]["archetype"] != "arch-03" {
		t.Fatalf("scenarios = %v", list)
	}

	// created from a preset: customer, seed and two forced outcomes
	sid := e.newSession(map[string]any{"scenario": "shipment-cancelled"})
	v := e.ctl("GET", "/sessions/"+sid, nil).json()
	if v["customer"] != "CUS-SYN-0007" || v["seed"].(json.Number).String() != "7" || v["scenario"] != "shipment-cancelled" {
		t.Fatalf("session = %v", v)
	}
	ids := []string{e.order(sid), e.order(sid)}
	e.advance(sid, "2h")
	for _, id := range ids {
		if s := e.shipments(sid, id)[0].(map[string]any); s["status"] != "CANCELLED" {
			t.Fatalf("shipment of %s = %v", id, s)
		}
	}
	// reset restores the baseline, forced outcomes included
	e.ctl("POST", "/sessions/"+sid+"/reset", nil)
	id := e.order(sid)
	e.advance(sid, "2h")
	if s := e.shipments(sid, id)[0].(map[string]any); s["status"] != "CANCELLED" {
		t.Fatalf("after reset: %v", s)
	}

	// the request wins over the preset
	s2 := e.newSession(map[string]any{"scenario": "shipment-cancelled", "seed": 99, "customer": "CUS-SYN-0001"})
	v = e.ctl("GET", "/sessions/"+s2, nil).json()
	if v["customer"] != "CUS-SYN-0001" || v["seed"].(json.Number).String() != "99" {
		t.Fatalf("session = %v", v)
	}

	// applying a preset to a session: reset + new baseline
	s3 := e.newSession(map[string]any{"seed": 5})
	e.advance(s3, "1h")
	r := e.ctl("POST", "/sessions/"+s3+"/scenario", map[string]any{"preset": "tracking-down"})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	sv := r.json()["session"].(map[string]any)
	if sv["customer"] != "CUS-SYN-0007" || sv["seed"].(json.Number).String() != "5" || sv["now"] != "2026-10-19T00:00:00Z" || sv["scenario"] != "tracking-down" {
		t.Fatalf("session = %v", sv)
	}
	if sv["faults"].(map[string]any)["mode"] != "custom" {
		t.Fatalf("faults = %v", sv["faults"])
	}
	for i, want := range []int{503, 200} {
		if got := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=x", nil, sess(s3)).status; got != want {
			t.Fatalf("call %d: %d, want %d", i, got, want)
		}
	}
	e.ctl("POST", "/sessions/"+s3+"/reset", nil)
	if got := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=x", nil, sess(s3)).status; got != 503 {
		t.Fatalf("reset must restore the preset faults: %d", got)
	}
	// a preset without faults goes back to the faults given at creation
	e.ctl("POST", "/sessions/"+s3+"/scenario", map[string]any{"preset": "shipment-cancelled"})
	if m := e.ctl("GET", "/sessions/"+s3+"/faults", nil).json()["mode"]; m != "off" {
		t.Fatalf("faults mode = %v", m)
	}

	for _, c := range []struct {
		path string
		body map[string]any
		code string
	}{
		{"/sessions", map[string]any{"scenario": "nope"}, "preset_not_found"},
		{"/sessions/" + s3 + "/scenario", map[string]any{"preset": "nope"}, "preset_not_found"},
		{"/sessions/" + s3 + "/scenario", map[string]any{"preset": "tracking-down", "rule": "r-0007"}, "bad_request"},
	} {
		if r := e.ctl("POST", c.path, c.body); r.json()["code"] != c.code {
			t.Errorf("%s %v: %d %s", c.path, c.body, r.status, r.body)
		}
	}
}

func TestStrictControlBodiesCarryPointers(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	rules := func(r map[string]any) map[string]any {
		base := map[string]any{"service": "shipping-ext", "op": "GET /v1/shipments", "status": 503, "p": 1}
		for k, v := range r {
			base[k] = v
		}
		return map[string]any{"mode": "custom", "rules": []any{base}}
	}
	for _, c := range []struct {
		method, path string
		body         any
		ptr          string
	}{
		{"PUT", "/sessions/" + sid + "/faults", rules(map[string]any{"p": 2}), "/rules/0/p"},
		{"PUT", "/sessions/" + sid + "/faults", rules(map[string]any{"service": "nope"}), "/rules/0/service"},
		{"PUT", "/sessions/" + sid + "/faults", rules(map[string]any{"net_error": "reset"}), "/rules/0/net_error"},
		{"PUT", "/sessions/" + sid + "/faults", `{"mode":"off","sedd":1}`, "/sedd"},
		{"PUT", "/sessions/" + sid + "/faults", `{"mode":"custom","rules":[{"service":"x","op":"*","p":"x"}]}`, "/rules/0/p"},
		{"PUT", "/sessions/" + sid + "/faults", `{"mode":"sometimes"}`, "/mode"},
		{"POST", "/sessions", map[string]any{"faults": rules(map[string]any{"service": "nope"})}, "/faults/rules/0/service"},
		{"POST", "/sessions", `{"seed":"a"}`, "/seed"},
		{"POST", "/sessions", `{"seed":-1}`, "/seed"},
		{"POST", "/sessions", `{"t0":"yesterday"}`, "/t0"},
		{"POST", "/sessions", `{"id":"bad id"}`, "/id"},
		{"POST", "/sessions/" + sid + "/scenario", `{"rule":"r-0007","outcome":"happy","times":"x"}`, "/times"},
		{"POST", "/sessions/" + sid + "/scenario", `{"rule":"r-0007"}`, "/outcome"},
		{"POST", "/sessions/" + sid + "/clock/advance", `{"by":"1h","extra":true}`, "/extra"},
		{"POST", "/sessions", `{not json`, ""},
		{"POST", "/sessions", `{} {}`, ""},
	} {
		r := e.ctl(c.method, c.path, c.body)
		j := r.json()
		got, _ := j["pointer"].(string)
		if r.status != 400 || j["code"] != "bad_request" || got != c.ptr {
			t.Errorf("%s %s %v: %d %s (want pointer %q)", c.method, c.path, c.body, r.status, r.body, c.ptr)
		}
	}
}

// rawGet sends a GET on a fresh TCP connection and returns what comes back.
func rawGet(t *testing.T, e *env, sid string) (got []byte, err error, elapsed time.Duration) {
	t.Helper()
	conn, derr := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if derr != nil {
		t.Fatal(derr)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	fmt.Fprintf(conn, "GET /__svc/shipping-ext/v1/shipments?orderId=x HTTP/1.1\r\nHost: mock\r\nX-TT-Session: %s\r\nConnection: close\r\n\r\n", sid)
	got, err = io.ReadAll(conn)
	return got, err, time.Since(start)
}

func TestNetworkFaultKinds(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	set := func(kind string, latency int) {
		rule := map[string]any{"service": "shipping-ext", "op": "GET /v1/shipments", "net_error": kind, "p": 1, "times": 1}
		if latency > 0 {
			rule["latency_ms"] = latency
		}
		if r := e.ctl("PUT", "/sessions/"+sid+"/faults", map[string]any{"mode": "custom", "rules": []any{rule}}); r.status != 200 {
			t.Fatal(r.body)
		}
	}
	// tls: a fatal handshake_failure alert record, then close
	set("tls", 0)
	if got, _, _ := rawGet(t, e, sid); !bytes.Equal(got, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) {
		t.Fatalf("tls: % x", got)
	}
	// other: orderly close without a byte
	set("other", 0)
	if got, err, _ := rawGet(t, e, sid); len(got) != 0 || err != nil {
		t.Fatalf("other: %q %v", got, err)
	}
	// reset, refused, dns: RST without a byte
	for _, kind := range []string{"reset", "refused", "dns"} {
		set(kind, 0)
		if got, err, _ := rawGet(t, e, sid); len(got) != 0 || err == nil {
			t.Fatalf("%s: %q %v", kind, got, err)
		}
	}
	// a healthy call afterwards
	if r := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId=x", nil, sess(sid)); r.status != 200 {
		t.Fatalf("status = %d", r.status)
	}

	// the journal: null status, the kind, and a latency only where the spec adds it
	journalFault := func(kind string, latency int) map[string]any {
		e.ctl("POST", "/sessions/"+sid+"/reset", nil)
		set(kind, latency)
		rawGet(t, e, sid)
		var m map[string]any
		_ = json.Unmarshal(bytes.TrimSpace(e.ctl("GET", "/sessions/"+sid+"/journal", nil).body), &m)
		if m["status"] != nil || m["matched"] != true {
			t.Fatalf("journal = %v", m)
		}
		return m["fault"].(map[string]any)
	}
	for kind, wantLatency := range map[string]bool{"reset": true, "other": true, "refused": false, "dns": false, "tls": false, "timeout": false} {
		f := journalFault(kind, 40)
		if f["net_error"] != kind {
			t.Errorf("%s: fault = %v", kind, f)
		}
		if _, has := f["latency_ms"]; has != wantLatency {
			t.Errorf("%s: latency recorded = %v, want %v (%v)", kind, has, wantLatency, f)
		}
	}
}

func TestNetworkTimeoutHoldsTheConnection(t *testing.T) {
	e := newEnv(t, withLatency(LatencyReal), func(_ *packtest.Spec, c *Config) { c.NetTimeout = 250 * time.Millisecond })
	sid := e.newSession(map[string]any{"faults": map[string]any{"mode": "custom", "rules": []any{
		map[string]any{"service": "shipping-ext", "op": "GET /v1/shipments", "net_error": "timeout", "p": 1, "times": 1}}}})
	got, err, elapsed := rawGet(t, e, sid)
	if len(got) != 0 || err != nil {
		t.Fatalf("timeout: %q %v", got, err)
	}
	if elapsed < 230*time.Millisecond {
		t.Fatalf("connection closed after %v, want at least the net timeout", elapsed)
	}
}

func TestPackWithBrokenWorldIsRefused(t *testing.T) {
	broken := func(mut func(world string) string) error {
		spec := packtest.DemoSpec()
		spec.Files["world.jsonl"] = []byte(mut(string(spec.Files["world.jsonl"])))
		b, err := packtest.Build(t.TempDir()+"/p", spec)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(Config{Pack: b.Dir, GatePubKeys: b.Keys})
		return err
	}
	if err := broken(func(w string) string { return w }); err != nil {
		t.Fatal(err)
	}
	// an order pointing at a shipment that does not exist
	if err := broken(func(w string) string {
		return strings.Replace(w, `"shipmentId":"SHP-SYN-0092"`, `"shipmentId":"SHP-SYN-0555"`, 1)
	}); err == nil {
		t.Fatal("dangling relation accepted")
	}
	if err := broken(func(w string) string {
		return strings.Replace(w, `"customer_id":"CUS-SYN-0009"`, `"customer_id":"CUS-SYN-0555"`, 1)
	}); err == nil {
		t.Fatal("unknown owner accepted")
	}
	if err := broken(func(w string) string {
		return strings.Replace(w, `"effect_id":"shipment-delivered"`, `"effect_id":"shipment-cancelled"`, 1)
	}); err == nil {
		t.Fatal("pending effect outside its outcome accepted")
	}
}
