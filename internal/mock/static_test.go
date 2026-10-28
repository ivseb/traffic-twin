package mock

import (
	"encoding/json"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// withReturns adds to shop-api a collection no rule describes (static mode):
// POST /returns (201, an id) and GET /returns/{id} (200 or 404 observed),
// plus a read-only GET /coupons/{code} (no create, no 404).
func withReturns(sp *packtest.Spec) {
	var doc map[string]any
	if err := json.Unmarshal(sp.Files["contracts/shop-api.openapi.json"], &doc); err != nil {
		panic(err)
	}
	obj := func(v string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			panic(err)
		}
		return m
	}
	ret := `{"type":"object","required":["id","orderRef","reason","status"],"properties":{
		"id":{"type":"string"},"orderRef":{"type":"string"},"reason":{"type":"string"},
		"status":{"type":"string","enum":["OPEN","CLOSED"]},"parcels":{"type":"integer"}},
		"example":{"id":"sample","orderRef":"synthetic","reason":"synthetic","status":"OPEN"}}`
	paths := doc["paths"].(map[string]any)
	paths["/returns"] = obj(`{"post":{"operationId":"createReturn",
		"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{
			"orderRef":{"type":"string"},"reason":{"type":"string"},"status":{"type":"string"},"parcels":{"type":"integer"}}}}}},
		"responses":{"201":{"description":"created","content":{"application/json":{"schema":` + ret + `}}}}}}`)
	paths["/returns/{id}"] = obj(`{"get":{"operationId":"getReturn",
		"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
		"responses":{"200":{"description":"ok","content":{"application/json":{"schema":` + ret + `}}},
			"404":{"description":"not found","content":{"application/json":{"schema":{"type":"object","properties":{"error":{"type":"string"}}}}}}}}}`)
	paths["/coupons/{code}"] = obj(`{"get":{"operationId":"getCoupon",
		"parameters":[{"name":"code","in":"path","required":true,"schema":{"type":"string"}}],
		"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["id","percent"],
			"properties":{"id":{"type":"string"},"percent":{"type":"integer"}}}}}}}}}`)
	b, _ := json.Marshal(doc)
	sp.Files["contracts/shop-api.openapi.json"] = packtest.Canon(string(b))
}

// Usability test 4: without rules the mock answered 200 "synthetic" to any
// id and the id of a POST was always the same.
func TestStaticModeCreatesAndFinds(t *testing.T) {
	e := newEnv(t, withSpec(withReturns))
	sid := e.newSession(map[string]any{"seed": 3})
	create := func(ref string) map[string]any {
		r := e.req("POST", "/__svc/shop-api/returns", map[string]any{"orderRef": ref, "reason": "damaged", "status": "WHATEVER", "parcels": 2}, sess(sid))
		if r.status != 201 || r.header.Get("X-TT-Static") != "true" {
			t.Fatalf("create: %d %s %v", r.status, r.body, r.header)
		}
		e.conforms("shop-api", "POST /returns", 201, r)
		return r.json()
	}
	a, b := create("ORD-1"), create("ORD-2")
	if a["id"] == b["id"] || a["id"] != "RTR-SYN-0001" || b["id"] != "RTR-SYN-0002" {
		t.Fatalf("ids per call: %v %v", a["id"], b["id"])
	}
	if a["orderRef"] != "ORD-1" || a["reason"] != "damaged" || b["orderRef"] != "ORD-2" {
		t.Fatalf("request not echoed: %v", a)
	}
	if a["status"] != "OPEN" {
		t.Fatalf("an enum is never echoed: %v", a["status"])
	}
	// The object comes back in the session.
	g := e.req("GET", "/__svc/shop-api/returns/RTR-SYN-0002", nil, sess(sid))
	if g.status != 200 || g.json()["orderRef"] != "ORD-2" || g.json()["id"] != "RTR-SYN-0002" || g.header.Get("X-TT-Static") != "true" {
		t.Fatalf("get created: %d %s", g.status, g.body)
	}
	e.conforms("shop-api", "GET /returns/{id}", 200, g)
	// An id nobody created: the observed not-found.
	if n := e.req("GET", "/__svc/shop-api/returns/nonexistent-id", nil, sess(sid)); n.status != 404 || n.header.Get("X-TT-Static") != "true" {
		t.Fatalf("unknown id: %d %s", n.status, n.body)
	}
	// Another session does not see them.
	other := e.newSession(map[string]any{"seed": 3})
	if n := e.req("GET", "/__svc/shop-api/returns/RTR-SYN-0002", nil, sess(other)); n.status != 404 {
		t.Fatalf("other session: %d", n.status)
	}
	// A reset forgets them.
	e.ctl("POST", "/sessions/"+sid+"/reset", nil)
	if n := e.req("GET", "/__svc/shop-api/returns/RTR-SYN-0001", nil, sess(sid)); n.status != 404 {
		t.Fatalf("after reset: %d", n.status)
	}
	// A read-only collection keeps answering 200, marked static, with the
	// id of the path.
	c := e.req("GET", "/__svc/shop-api/coupons/WELCOME10", nil, sess(sid))
	if c.status != 200 || c.header.Get("X-TT-Static") != "true" || c.json()["id"] != "WELCOME10" {
		t.Fatalf("read-only: %d %s %v", c.status, c.body, c.header)
	}
}

func TestEntityPrefix(t *testing.T) {
	for in, want := range map[string]string{"shipment": "SHP-SYN-", "order": "ORD-SYN-", "return": "RTR-SYN-", "ox": "OX-SYN-", "a": "AX-SYN-"} {
		if got := entityPrefix(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{"shipments": "shipment", "categories": "category", "boxes": "box", "address": "address"} {
		if got := singularWord(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
