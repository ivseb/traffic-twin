package mock

import (
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// An invented app (rules v1.7): customers own contracts (seeds of the
// world) that writes change without creating anything — a PATCH copies
// the plan and the address id of the request, a POST toggles a favourite —
// and orders, created PENDING, are confirmed on their own unless the user
// cancelled them first (the spontaneous step is guarded with where). A
// GraphQL query lists the contracts of a product (by field) in a nested
// list.

const wave2Contract = `{
  "openapi":"3.1.0","info":{"title":"app-api","version":"1.0.0"},
  "paths":{
    "/contracts":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["items"],
      "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/Contract"}}}}}}}}}},
    "/contracts/{id}":{
      "get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Contract"}}}},
          "404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}},
      "patch":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"plan":{"type":"string"},"addressId":{"type":"string"}}}}}},
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Contract"}}}}}}},
    "/contracts/{id}/favorite":{"post":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/orders":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"sku":{"type":"string"}}}}}},
        "responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}}}}},
    "/orders/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}},
          "404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}}},
    "/orders/{id}/cancel":{"post":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}}
  },
  "components":{"schemas":{
    "Error":{"type":"object","properties":{"error":{"type":"object","properties":{"code":{"type":"string"}}}}},
    "Contract":{"type":"object","required":["id","status"],"properties":{
      "id":{"type":"string","x-tt-value":{"kind":"id","domain":"contract"}},
      "status":{"type":"string"},"plan":{"type":"string"},"favorite":{"type":"boolean"},
      "addressId":{"type":"string"}}},
    "Order":{"type":"object","required":["id","status"],"properties":{
      "id":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},"status":{"type":"string"},"sku":{"type":"string"}}}
  }}}`

const wave2Rules = `{
  "format":"tt.rules/v1",
  "entities":[
    {"name":"contract","service":"app-api","id_domain":"contract","id_field":"id","id_prefix":"CNT-SYN-",
     "seed":{"per_customer":[{"n":"1-2","share":1}],"subjects":40},
     "read_by":[
       {"op":"GET /contracts","at":{"from":"resp.body","path":"$.items[*]"},"scope":"owner"},
       {"op":"GET /contracts/{id}","by":{"from":"req.path","name":"id"},"at":{"from":"resp.body","path":"$"},"scope":"owner"}]},
    {"name":"order","service":"app-api","id_domain":"order","id_field":"id","id_prefix":"ORD-SYN-",
     "created_by":{"op":"POST /orders","id":{"from":"resp.body","path":"$.id"},"state":{"from":"req.body","path":"$"},"defaults":{"status":"PENDING"}},
     "read_by":[{"op":"GET /orders/{id}","by":{"from":"req.path","name":"id"},"at":{"from":"resp.body","path":"$"},"scope":"owner"}]}
  ],
  "rules":[
    {"id":"r-0001","kind":"causal","status":"approved","title":"PATCH copies the plan and the address of the request",
     "cause":{"service":"app-api","op":"PATCH /contracts/{id}","when":{"status":[200]},
       "bind":{"contract":{"from":"req.path","name":"id"},"plan":{"from":"req.body","path":"$.plan"},"addressid":{"from":"req.body","path":"$.addressId"}}},
     "effects":[{"id":"contract-updated","entity":"contract","target_id":"${contract}","set":{"plan":"${plan}","addressId":"${addressid}"},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["contract-updated"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0002","kind":"causal","status":"approved","title":"POST favorite toggles the favourite",
     "cause":{"service":"app-api","op":"POST /contracts/{id}/favorite","when":{"status":[200]},"bind":{"contract":{"from":"req.path","name":"id"}}},
     "effects":[{"id":"contract-updated","entity":"contract","target_id":"${contract}","set":{"favorite":"${not:favorite}"},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["contract-updated"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0003","kind":"causal","status":"approved","title":"An order is confirmed on its own",
     "cause":{"service":"app-api","op":"POST /orders","when":{"status":[201]},"bind":{"order":{"from":"resp.body","path":"$.id"}}},
     "effects":[{"id":"order-confirmed","entity":"order","target_id":"${order}","set":{"status":"CONFIRMED"},"where":{"status":"PENDING"},"after":"1h"}],
     "outcomes":[{"name":"happy","p":1,"effects":["order-confirmed"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"happy":40}}}},
    {"id":"r-0004","kind":"causal","status":"approved","title":"POST cancel cancels the order",
     "cause":{"service":"app-api","op":"POST /orders/{id}/cancel","when":{"status":[200]},"bind":{"order":{"from":"req.path","name":"id"}}},
     "effects":[{"id":"order-updated","entity":"order","target_id":"${order}","set":{"status":"CANCELLED"},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["order-updated"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}}
  ]}`

func wave2World() []byte {
	return packtest.Lines(
		packtest.JSON(`{"format":"tt.world/v1","seed":42,"t0":"2026-10-19T00:00:00Z","type":"meta"}`),
		packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0001","profile":{"email":"anna.rossi@example.com","name":"Anna Rossi"},"type":"customer"}`),
		packtest.JSON(`{"customer_id":"CUS-SYN-0001","entity":"contract","id":"CNT-SYN-0001","state":{"id":"CNT-SYN-0001","status":"ACTIVE","plan":"BRONZE","favorite":false,"addressId":"ADR-1"},"type":"entity"}`),
	)
}

func withWave2(sp *packtest.Spec) {
	sp.Files = map[string][]byte{
		"contracts/app-api.openapi.json": packtest.Canon(wave2Contract),
		"rules.json":                     packtest.Canon(wave2Rules),
		"gate-report.json":               sp.Files["gate-report.json"],
		"world.jsonl":                    wave2World(),
		"faults.json":                    packtest.Canon(`{"format":"tt.faults/v1","ops":[]}`),
		"scenarios.json":                 packtest.Canon(`{"format":"tt.scenarios/v1","scenarios":[]}`),
	}
	sp.Manifest["services"] = packtest.JSON(`[{"name":"app-api","contract":"contracts/app-api.openapi.json","upstream_alias":"app"}]`)
	sp.Manifest["rules"] = packtest.JSON(`{"path":"rules.json","approved":["r-0001","r-0002","r-0003","r-0004"]}`)
	sp.Manifest["world"] = packtest.JSON(`{"path":"world.jsonl","customers":1}`)
}

// An update copies the values the test sends: a clear code and an id.
func TestWave2UpdateCopiesTheRequest(t *testing.T) {
	e := newEnv(t, withSpec(withWave2))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	r := e.req("PATCH", "/__svc/app-api/contracts/CNT-SYN-0001", map[string]any{"plan": "GOLD", "addressId": "ADR-77"}, sess(anna))
	if r.status != 200 {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	got := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0001", nil, sess(anna)).json()
	if got["plan"] != "GOLD" || got["addressId"] != "ADR-77" || got["status"] != "ACTIVE" {
		t.Fatalf("after the update: %v", got)
	}
}

// ${not:field} toggles a boolean, call after call.
func TestWave2Toggle(t *testing.T) {
	e := newEnv(t, withSpec(withWave2))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	for _, want := range []bool{true, false, true} {
		if r := e.req("POST", "/__svc/app-api/contracts/CNT-SYN-0001/favorite", nil, sess(anna)); r.status != 200 {
			t.Fatalf("toggle: %d %s", r.status, r.body)
		}
		if got := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0001", nil, sess(anna)).json(); got["favorite"] != want {
			t.Fatalf("favorite: %v, want %v", got, want)
		}
	}
}

// A spontaneous step guarded by where does not undo what a write set.
func TestWave2WhereGuard(t *testing.T) {
	e := newEnv(t, withSpec(withWave2))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	a := e.req("POST", "/__svc/app-api/orders", map[string]any{"sku": "A"}, sess(anna))
	b := e.req("POST", "/__svc/app-api/orders", map[string]any{"sku": "B"}, sess(anna))
	if a.status != 201 || b.status != 201 {
		t.Fatalf("create: %d %d", a.status, b.status)
	}
	ida, idb := a.json()["id"].(string), b.json()["id"].(string)
	if r := e.req("POST", "/__svc/app-api/orders/"+ida+"/cancel", nil, sess(anna)); r.status != 200 {
		t.Fatalf("cancel: %d %s", r.status, r.body)
	}
	if r := e.ctl("POST", "/sessions/"+anna+"/clock/advance", map[string]any{"by": "2h"}); r.status != 200 {
		t.Fatalf("advance: %d %s", r.status, r.body)
	}
	if got := e.req("GET", "/__svc/app-api/orders/"+ida, nil, sess(anna)).json(); got["status"] != "CANCELLED" {
		t.Fatalf("the cancelled order: %v", got)
	}
	if got := e.req("GET", "/__svc/app-api/orders/"+idb, nil, sess(anna)).json(); got["status"] != "CONFIRMED" {
		t.Fatalf("the other order: %v", got)
	}
}
