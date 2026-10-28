package mock

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// An invented app (rules v1.8): a profile per user (a keyed singleton) and
// a consent per document (keyed by documentId) changed by writes that are
// not their upserted_by; accounts unique by email; a quote endpoint
// limited to three calls a minute; and a request whose ticket appears
// later, replacing it.

const wave3Contract = `{
  "openapi":"3.1.0","info":{"title":"app-api","version":"1.0.0"},
  "paths":{
    "/me/profile":{
      "get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}}}},
      "put":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}},
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}}}}},
    "/notifications/read-all":{"post":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/consents/{documentId}":{"get":{"parameters":[{"name":"documentId","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Consent"}}}}}}},
    "/documents/{documentId}/sign":{"post":{"parameters":[{"name":"documentId","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/accounts":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"email":{"type":"string"}}}}}},
        "responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Account"}}}},
          "409":{"description":"taken","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
            "examples":{"email-taken":{"value":{"error":{"code":"EMAIL_TAKEN"}}}}}}}}}},
    "/quotes":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"price":{"type":"integer"}}}}}},
          "429":{"description":"slow down","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}}},
    "/requests":{"post":{"responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Req"}}}}}}},
    "/requests/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Req"}}}},
          "404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}}},
    "/tickets":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["items"],
      "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/Ticket"}}}}}}}}}}
  },
  "components":{"schemas":{
    "Error":{"type":"object","properties":{"error":{"type":"object","properties":{"code":{"type":"string"}}}}},
    "Profile":{"type":"object","properties":{"name":{"type":"string"},"unread":{"type":"integer"}}},
    "Consent":{"type":"object","properties":{"documentId":{"type":"string"},"signed":{"type":"boolean"}}},
    "Account":{"type":"object","required":["id"],"properties":{"id":{"type":"string","x-tt-value":{"kind":"id","domain":"account"}},"email":{"type":"string"}}},
    "Req":{"type":"object","required":["id"],"properties":{"id":{"type":"string","x-tt-value":{"kind":"id","domain":"request"}},"status":{"type":"string"}}},
    "Ticket":{"type":"object","required":["id"],"properties":{"id":{"type":"string","x-tt-value":{"kind":"id","domain":"ticket"}},
      "requestId":{"type":"string"},"status":{"type":"string"}}}
  }}}`

const wave3Rules = `{
  "format":"tt.rules/v1",
  "entities":[
    {"name":"profile","service":"app-api","id_domain":"profile","id_field":"id","id_prefix":"PRF-SYN-",
     "key":{"owner":true},
     "upserted_by":[{"op":"PUT /me/profile","state":{"from":"req.body","path":"$"}}],
     "read_by":[{"op":"GET /me/profile","at":{"from":"resp.body","path":"$"}}]},
    {"name":"consent","service":"app-api","id_domain":"consent","id_field":"id","id_prefix":"CNS-SYN-",
     "key":{"owner":true,"fields":["documentId"]},
     "read_by":[{"op":"GET /consents/{documentId}","key":{"documentId":{"from":"req.path","name":"documentId"}},"at":{"from":"resp.body","path":"$"}}]},
    {"name":"account","service":"app-api","id_domain":"account","id_field":"id","id_prefix":"ACC-SYN-",
     "created_by":{"op":"POST /accounts","id":{"from":"resp.body","path":"$.id"},"state":{"from":"req.body","path":"$"}}},
    {"name":"request","service":"app-api","id_domain":"request","id_field":"id","id_prefix":"REQ-SYN-",
     "created_by":{"op":"POST /requests","id":{"from":"resp.body","path":"$.id"},"defaults":{"status":"OPEN"}},
     "read_by":[{"op":"GET /requests/{id}","by":{"from":"req.path","name":"id"},"at":{"from":"resp.body","path":"$"},"scope":"owner"}]},
    {"name":"ticket","service":"app-api","id_domain":"ticket","id_field":"id","id_prefix":"TKT-SYN-",
     "relations":[{"field":"requestId","entity":"request"}],
     "read_by":[{"op":"GET /tickets","at":{"from":"resp.body","path":"$.items[*]"},"scope":"owner"}]}
  ],
  "rules":[
    {"id":"r-0001","kind":"causal","status":"approved","title":"read-all clears the unread counter of the profile",
     "cause":{"service":"app-api","op":"POST /notifications/read-all","when":{"status":[200]}},
     "effects":[{"id":"profile-updated","entity":"profile","target_key":{},"set":{"unread":0},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["profile-updated"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0002","kind":"causal","status":"approved","title":"signing a document gives its consent",
     "cause":{"service":"app-api","op":"POST /documents/{documentId}/sign","when":{"status":[200]},"bind":{"document":{"from":"req.path","name":"documentId"}}},
     "effects":[{"id":"consent-updated","entity":"consent","target_key":{"documentId":"${document}"},"set":{"signed":true},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["consent-updated"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0003","kind":"causal","status":"approved","title":"one account per email",
     "cause":{"service":"app-api","op":"POST /accounts","when":{"status":[201]},"bind":{"email":{"from":"req.body","path":"$.email"}}},
     "effects":[{"id":"account-unique","respond":{"service":"app-api","op":"POST /accounts","status":409,"example":"email-taken","limit":{"n":1,"key":"${email}"}},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["account-unique"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0004","kind":"causal","status":"approved","title":"three quotes a minute",
     "cause":{"service":"app-api","op":"GET /quotes","when":{"status":[200]}},
     "effects":[{"id":"quotes-limited","respond":{"service":"app-api","op":"GET /quotes","status":429,"limit":{"n":3,"window":"1m"}},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["quotes-limited"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0005","kind":"causal","status":"approved","title":"a request becomes a ticket later",
     "cause":{"service":"app-api","op":"POST /requests","when":{"status":[201]},"bind":{"request":{"from":"resp.body","path":"$.id"}}},
     "effects":[
       {"id":"ticket-created","entity":"ticket","create":{"requestId":"${request}","status":"NEW"},"after":"10m"},
       {"id":"request-replaced","entity":"request","target_id":"${request}","remove":true,"after_effect":"ticket-created","after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["ticket-created","request-replaced"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}}
  ]}`

func withWave3(sp *packtest.Spec) {
	sp.Files = map[string][]byte{
		"contracts/app-api.openapi.json": packtest.Canon(wave3Contract),
		"rules.json":                     packtest.Canon(wave3Rules),
		"gate-report.json":               sp.Files["gate-report.json"],
		"world.jsonl": packtest.Lines(
			packtest.JSON(`{"format":"tt.world/v1","seed":42,"t0":"2026-10-19T00:00:00Z","type":"meta"}`),
			packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0001","profile":{"email":"anna.rossi@example.com","name":"Anna Rossi"},"type":"customer"}`),
			packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0002","profile":{"email":"bruno.neri@example.com","name":"Bruno Neri"},"type":"customer"}`),
		),
		"faults.json":    packtest.Canon(`{"format":"tt.faults/v1","ops":[]}`),
		"scenarios.json": packtest.Canon(`{"format":"tt.scenarios/v1","scenarios":[]}`),
	}
	sp.Manifest["services"] = packtest.JSON(`[{"name":"app-api","contract":"contracts/app-api.openapi.json","upstream_alias":"app"}]`)
	sp.Manifest["rules"] = packtest.JSON(`{"path":"rules.json","approved":["r-0001","r-0002","r-0003","r-0004","r-0005"]}`)
	sp.Manifest["world"] = packtest.JSON(`{"path":"world.jsonl","customers":2}`)
}

// A write that is not upserted_by changes the customer's keyed singleton,
// creating it when missing; another customer's record is untouched.
func TestWave3TargetKeySingleton(t *testing.T) {
	e := newEnv(t, withSpec(withWave3))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if r := e.req("PUT", "/__svc/app-api/me/profile", map[string]any{"name": "Anna", "unread": 4}, sess(anna)); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	if r := e.req("POST", "/__svc/app-api/notifications/read-all", nil, sess(anna)); r.status != 200 {
		t.Fatalf("read-all: %d %s", r.status, r.body)
	}
	got := e.req("GET", "/__svc/app-api/me/profile", nil, sess(anna)).json()
	if fmt.Sprint(got["unread"]) != "0" || got["name"] != "Anna" {
		t.Fatalf("profile after read-all: %v", got)
	}
	bruno := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	if r := e.req("POST", "/__svc/app-api/notifications/read-all", nil, sess(bruno)); r.status != 200 {
		t.Fatalf("read-all: %d %s", r.status, r.body)
	}
	if got := e.req("GET", "/__svc/app-api/me/profile", nil, sess(bruno)).json(); fmt.Sprint(got["unread"]) != "0" {
		t.Fatalf("a missing record is created by the set: %v", got)
	}
}

// target_key with a field: the record of that key only.
func TestWave3TargetKeyField(t *testing.T) {
	e := newEnv(t, withSpec(withWave3))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if r := e.req("POST", "/__svc/app-api/documents/DOC-1/sign", nil, sess(anna)); r.status != 200 {
		t.Fatalf("sign: %d %s", r.status, r.body)
	}
	if got := e.req("GET", "/__svc/app-api/consents/DOC-1", nil, sess(anna)).json(); got["signed"] != true || got["documentId"] != "DOC-1" {
		t.Fatalf("consent of DOC-1: %v", got)
	}
	if n := entityCount(t, e, anna, "consent"); n != 1 {
		t.Fatalf("one consent record expected: %d", n)
	}
}

func entityCount(t *testing.T, e *env, sid, entity string) int {
	t.Helper()
	r := e.ctl("GET", "/sessions/"+sid+"/entities?entity="+entity, nil)
	var items []any
	if err := json.Unmarshal(r.body, &items); err != nil {
		t.Fatalf("entities: %v %s", err, r.body)
	}
	return len(items)
}

// limit n=1 per key: the second creation with the same email answers the
// observed conflict with its example; another email still creates.
func TestWave3Unique(t *testing.T) {
	e := newEnv(t, withSpec(withWave3))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if r := e.req("POST", "/__svc/app-api/accounts", map[string]any{"email": "a@example.com"}, sess(anna)); r.status != 201 {
		t.Fatalf("first: %d %s", r.status, r.body)
	}
	r := e.req("POST", "/__svc/app-api/accounts", map[string]any{"email": "a@example.com"}, sess(anna))
	if r.status != 409 {
		t.Fatalf("second: %d %s", r.status, r.body)
	}
	if er, _ := r.json()["error"].(map[string]any); er["code"] != "EMAIL_TAKEN" {
		t.Fatalf("conflict body: %s", r.body)
	}
	if r := e.req("POST", "/__svc/app-api/accounts", map[string]any{"email": "b@example.com"}, sess(anna)); r.status != 201 {
		t.Fatalf("another email: %d %s", r.status, r.body)
	}
	if n := entityCount(t, e, anna, "account"); n != 2 {
		t.Fatalf("the conflict creates nothing: %d accounts", n)
	}
	// reset forgets the counts
	if r := e.ctl("POST", "/sessions/"+anna+"/reset", nil); r.status != 200 {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if r := e.req("POST", "/__svc/app-api/accounts", map[string]any{"email": "a@example.com"}, sess(anna)); r.status != 201 {
		t.Fatalf("after reset: %d %s", r.status, r.body)
	}
}

// limit n=3 in 1m without a key: the fourth call within the minute answers
// 429; after the window the calls pass again.
func TestWave3RateLimit(t *testing.T) {
	e := newEnv(t, withSpec(withWave3))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	for i := 0; i < 3; i++ {
		if r := e.req("GET", "/__svc/app-api/quotes", nil, sess(anna)); r.status != 200 {
			t.Fatalf("call %d: %d %s", i, r.status, r.body)
		}
	}
	if r := e.req("GET", "/__svc/app-api/quotes", nil, sess(anna)); r.status != 429 {
		t.Fatalf("fourth call: %d %s", r.status, r.body)
	}
	// another customer has its own count
	bruno := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	if r := e.req("GET", "/__svc/app-api/quotes", nil, sess(bruno)); r.status != 200 {
		t.Fatalf("another session: %d %s", r.status, r.body)
	}
	if r := e.ctl("POST", "/sessions/"+anna+"/clock/advance", map[string]any{"by": "2m"}); r.status != 200 {
		t.Fatalf("advance: %d %s", r.status, r.body)
	}
	if r := e.req("GET", "/__svc/app-api/quotes", nil, sess(anna)); r.status != 200 {
		t.Fatalf("after the window: %d %s", r.status, r.body)
	}
}

// An object created later by the rule of another one, which it replaces.
func TestWave3CreatedLaterReplaces(t *testing.T) {
	e := newEnv(t, withSpec(withWave3))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	r := e.req("POST", "/__svc/app-api/requests", nil, sess(anna))
	if r.status != 201 {
		t.Fatalf("request: %d %s", r.status, r.body)
	}
	id, _ := r.json()["id"].(string)
	if items, _ := e.req("GET", "/__svc/app-api/tickets", nil, sess(anna)).json()["items"].([]any); len(items) != 0 {
		t.Fatalf("no ticket yet: %v", items)
	}
	if g := e.req("GET", "/__svc/app-api/requests/"+id, nil, sess(anna)); g.status != 200 {
		t.Fatalf("the request is visible: %d", g.status)
	}
	if r := e.ctl("POST", "/sessions/"+anna+"/clock/advance", map[string]any{"by": "15m"}); r.status != 200 {
		t.Fatalf("advance: %d %s", r.status, r.body)
	}
	items, _ := e.req("GET", "/__svc/app-api/tickets", nil, sess(anna)).json()["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("one ticket: %v", items)
	}
	if tk, _ := items[0].(map[string]any); tk["requestId"] != id {
		t.Fatalf("the ticket cites the request: %v", tk)
	}
	if g := e.req("GET", "/__svc/app-api/requests/"+id, nil, sess(anna)); g.status != 404 {
		t.Fatalf("the request is replaced: %d %s", g.status, g.body)
	}
}
