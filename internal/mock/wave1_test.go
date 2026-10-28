package mock

import (
	"encoding/json"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// An invented app (rules v1.6): customers own contracts nobody creates in
// a session (seeds of the world), a profile and consents without an id
// (keyed records), contracts are removed by a DELETE (rule r-0001, 410
// afterwards) and found by a POST search; notes have no entity (static
// mode).

const wave1Contract = `{
  "openapi":"3.1.0","info":{"title":"app-api","version":"1.0.0"},
  "paths":{
    "/contracts":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ContractList"}}}}}}},
    "/contracts/{id}":{
      "get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Contract"}}}},
          "404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}},
          "410":{"description":"gone","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}},
      "delete":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"204":{"description":"removed"}}}},
    "/contracts/{id}/suspend":{"put":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/contracts/search":{"post":{
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"filters":{"type":"object","properties":{"contractId":{"type":"string"}}}}}}}},
      "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"contract":{"$ref":"#/components/schemas/Contract"}}}}}},
        "404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}}},
    "/me/profile":{
      "get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"},
        "example":{"language":"it","newsletter":false}}}}}},
      "put":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}},
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}}}}},
    "/consents":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["documentId","accepted"],
        "properties":{"documentId":{"type":"string"},"accepted":{"type":"boolean"}}}}}},
      "responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/consents/{documentId}":{"get":{"parameters":[{"name":"documentId","in":"path","required":true,"schema":{"type":"string"}}],
      "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["accepted"],
        "properties":{"accepted":{"type":"boolean"},"documentId":{"type":"string"}}},"example":{"accepted":false,"documentId":"DOC-1"}}}}}}},
    "/notes":{
      "get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["items","count"],
        "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/Note"}},"count":{"type":"integer"}}}}}}}},
      "post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"text":{"type":"string"}}}}}},
        "responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Note"}}}}}}},
    "/notes/{id}":{"delete":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
      "responses":{"204":{"description":"removed"},"404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}}}
  },
  "components":{"schemas":{
    "Error":{"type":"object","properties":{"error":{"type":"object","properties":{"code":{"type":"string"},"message":{"type":"string"}}}}},
    "Contract":{"type":"object","required":["id","status"],"properties":{
      "id":{"type":"string","x-tt-value":{"kind":"id","domain":"contract"}},
      "status":{"type":"string","enum":["ACTIVE","SUSPENDED"]},
      "customerId":{"type":["string","null"]}}},
    "ContractList":{"type":"object","required":["items","count"],"properties":{
      "items":{"type":"array","items":{"$ref":"#/components/schemas/Contract"}},"count":{"type":"integer"}}},
    "Profile":{"type":"object","required":["language","newsletter"],"properties":{
      "language":{"type":"string"},"newsletter":{"type":"boolean"}}},
    "Note":{"type":"object","required":["id","text"],"properties":{"id":{"type":"string"},"text":{"type":"string"}}}
  }}}`

const wave1Rules = `{
  "format":"tt.rules/v1",
  "entities":[
    {"name":"contract","service":"app-api","id_domain":"contract","id_field":"id","id_prefix":"CNT-SYN-",
     "seed":{"per_customer":[{"n":"1-2","share":1}],"subjects":40},
     "read_by":[
       {"op":"GET /contracts","at":{"from":"resp.body","path":"$.items[*]"},"scope":"owner","list":{"count":"$.count"}},
       {"op":"GET /contracts/{id}","by":{"from":"req.path","name":"id"},"at":{"from":"resp.body","path":"$"},"scope":"owner","removed_status":410},
       {"op":"POST /contracts/search","by":{"from":"req.body","path":"$.filters.contractId"},"at":{"from":"resp.body","path":"$.contract"},"scope":"owner"}]},
    {"name":"profile","service":"app-api","id_domain":"profile","id_field":"id","id_prefix":"PRF-SYN-",
     "key":{"owner":true},
     "upserted_by":[{"op":"PUT /me/profile","state":{"from":"req.body","path":"$"}}],
     "read_by":[{"op":"GET /me/profile","at":{"from":"resp.body","path":"$"}}]},
    {"name":"consent","service":"app-api","id_domain":"consent","id_field":"id","id_prefix":"CNS-SYN-",
     "key":{"owner":true,"fields":["documentId"]},
     "upserted_by":[{"op":"POST /consents","key":{"documentId":{"from":"req.body","path":"$.documentId"}},"state":{"from":"req.body","path":"$"}}],
     "read_by":[{"op":"GET /consents/{documentId}","key":{"documentId":{"from":"req.path","name":"documentId"}},"at":{"from":"resp.body","path":"$"}}]}
  ],
  "rules":[
    {"id":"r-0001","kind":"causal","status":"approved","title":"DELETE removes the contract",
     "cause":{"service":"app-api","op":"DELETE /contracts/{id}","when":{"status":[204]},"bind":{"contract":{"from":"req.path","name":"id"}}},
     "effects":[{"id":"contract-removed","entity":"contract","target_id":"${contract}","remove":true,"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["contract-removed"]}],
     "evidence":{"counts":{"causes":40,"distinct_subjects":40,"outcomes":{"always":40}}}},
    {"id":"r-0002","kind":"causal","status":"approved","title":"A suspension changes a pre-existing contract","origin":"manual",
     "cause":{"service":"app-api","op":"PUT /contracts/{id}/suspend","when":{"status":[200]},"bind":{"contract":{"from":"req.path","name":"id"}}},
     "effects":[{"id":"contract-suspended","entity":"contract","target_id":"${contract}","set":{"status":"SUSPENDED"},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["contract-suspended"]}],
     "evidence":{"counts":{"causes":0,"distinct_subjects":0,"outcomes":{"always":0}}}}
  ]}`

func wave1World() []byte {
	ent := func(id, cust, status string) any {
		return packtest.JSON(`{"customer_id":"` + cust + `","entity":"contract","id":"` + id + `","state":{"id":"` + id + `","status":"` + status + `"},"type":"entity"}`)
	}
	return packtest.Lines(
		packtest.JSON(`{"format":"tt.world/v1","seed":42,"t0":"2026-10-19T00:00:00Z","type":"meta"}`),
		packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0001","profile":{"email":"anna.rossi@example.com","name":"Anna Rossi"},"type":"customer"}`),
		packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0002","profile":{"email":"marco.bianchi@example.com","name":"Marco Bianchi"},"type":"customer"}`),
		ent("CNT-SYN-0001", "CUS-SYN-0001", "ACTIVE"),
		ent("CNT-SYN-0002", "CUS-SYN-0001", "SUSPENDED"),
		ent("CNT-SYN-0003", "CUS-SYN-0002", "ACTIVE"),
	)
}

func withWave1(sp *packtest.Spec) {
	sp.Files = map[string][]byte{
		"contracts/app-api.openapi.json": packtest.Canon(wave1Contract),
		"rules.json":                     packtest.Canon(wave1Rules),
		"gate-report.json":               sp.Files["gate-report.json"],
		"world.jsonl":                    wave1World(),
		"faults.json":                    packtest.Canon(`{"format":"tt.faults/v1","ops":[]}`),
		"scenarios.json":                 packtest.Canon(`{"format":"tt.scenarios/v1","scenarios":[]}`),
	}
	sp.Manifest["services"] = packtest.JSON(`[{"name":"app-api","contract":"contracts/app-api.openapi.json","upstream_alias":"app"}]`)
	sp.Manifest["rules"] = packtest.JSON(`{"path":"rules.json","approved":["r-0001","r-0002"]}`)
	sp.Manifest["world"] = packtest.JSON(`{"path":"world.jsonl","customers":2}`)
}

func items(t *testing.T, r resp) []any {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	return r.json()["items"].([]any)
}

func TestWave1SeedsListAndByID(t *testing.T) {
	e := newEnv(t, withSpec(withWave1))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	got := items(t, e.req("GET", "/__svc/app-api/contracts", nil, sess(anna)))
	if len(got) != 2 {
		t.Fatalf("anna's contracts: %v", got)
	}
	r := e.req("GET", "/__svc/app-api/contracts", nil, sess(anna))
	if n, _ := r.json()["count"].(json.Number).Int64(); n != 2 {
		t.Fatalf("count: %s", r.body)
	}
	for _, it := range got {
		id := it.(map[string]any)["id"].(string)
		one := e.req("GET", "/__svc/app-api/contracts/"+id, nil, sess(anna))
		if one.status != 200 || one.json()["id"] != id || one.json()["status"] != it.(map[string]any)["status"] {
			t.Fatalf("by id %s: %d %s (list said %v)", id, one.status, one.body, it)
		}
	}
	// Another customer's contract is not Anna's.
	if r := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0003", nil, sess(anna)); r.status != 404 {
		t.Fatalf("foreign contract: %d %s", r.status, r.body)
	}
	// POST read with a body selector.
	if r := e.req("POST", "/__svc/app-api/contracts/search", map[string]any{"filters": map[string]any{"contractId": "CNT-SYN-0002"}}, sess(anna)); r.status != 200 ||
		r.json()["contract"].(map[string]any)["status"] != "SUSPENDED" {
		t.Fatalf("search: %d %s", r.status, r.body)
	}
	if r := e.req("POST", "/__svc/app-api/contracts/search", map[string]any{"filters": map[string]any{"contractId": "CNT-SYN-0009"}}, sess(anna)); r.status != 404 {
		t.Fatalf("search of an unknown contract: %d %s", r.status, r.body)
	}
}

// A pre-existing object of the world is a target of the rules.
func TestWave1SeedIsARuleTarget(t *testing.T) {
	e := newEnv(t, withSpec(withWave1))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if r := e.req("PUT", "/__svc/app-api/contracts/CNT-SYN-0001/suspend", nil, sess(anna)); r.status != 200 {
		t.Fatalf("suspend: %d %s", r.status, r.body)
	}
	if r := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0001", nil, sess(anna)); r.json()["status"] != "SUSPENDED" {
		t.Fatalf("after the rule: %s", r.body)
	}
}

func TestWave1Removal(t *testing.T) {
	e := newEnv(t, withSpec(withWave1))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if r := e.req("DELETE", "/__svc/app-api/contracts/CNT-SYN-0001", nil, sess(anna)); r.status != 204 {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}
	if got := items(t, e.req("GET", "/__svc/app-api/contracts", nil, sess(anna))); len(got) != 1 {
		t.Fatalf("the removed contract is still listed: %v", got)
	}
	if r := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0001", nil, sess(anna)); r.status != 410 {
		t.Fatalf("removed contract by id: %d %s", r.status, r.body)
	}
	if r := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0077", nil, sess(anna)); r.status != 404 {
		t.Fatalf("unknown contract by id: %d %s", r.status, r.body)
	}
	// Another session still has it (sessions are isolated); a reset brings it back.
	other := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if got := items(t, e.req("GET", "/__svc/app-api/contracts", nil, sess(other))); len(got) != 2 {
		t.Fatalf("other session: %v", got)
	}
	if r := e.ctl("POST", "/sessions/"+anna+"/reset", nil); r.status != 200 {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if r := e.req("GET", "/__svc/app-api/contracts/CNT-SYN-0001", nil, sess(anna)); r.status != 200 {
		t.Fatalf("after reset: %d %s", r.status, r.body)
	}
}

func TestWave1KeyedUpsert(t *testing.T) {
	e := newEnv(t, withSpec(withWave1))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	marco := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	// No record yet: the contract's default answer.
	if r := e.req("GET", "/__svc/app-api/me/profile", nil, sess(anna)); r.status != 200 || r.json()["language"] != "it" {
		t.Fatalf("default profile: %d %s", r.status, r.body)
	}
	for _, lang := range []string{"en", "de"} {
		if r := e.req("PUT", "/__svc/app-api/me/profile", map[string]any{"language": lang, "newsletter": true}, sess(anna)); r.status != 200 || r.json()["language"] != lang {
			t.Fatalf("put: %d %s", r.status, r.body)
		}
		if r := e.req("GET", "/__svc/app-api/me/profile", nil, sess(anna)); r.json()["language"] != lang || r.json()["newsletter"] != true {
			t.Fatalf("profile after put %s: %s", lang, r.body)
		}
	}
	ents := e.ctl("GET", "/sessions/"+anna+"/entities?entity=profile", nil)
	var list []any
	if err := json.Unmarshal(ents.body, &list); err != nil || len(list) != 1 {
		t.Fatalf("one record per owner, got %s", ents.body)
	}
	// Per key: two documents, two records.
	for doc, acc := range map[string]bool{"DOC-A": true, "DOC-B": false} {
		if r := e.req("POST", "/__svc/app-api/consents", map[string]any{"documentId": doc, "accepted": acc}, sess(anna)); r.status != 201 {
			t.Fatalf("consent: %d %s", r.status, r.body)
		}
	}
	if r := e.req("POST", "/__svc/app-api/consents", map[string]any{"documentId": "DOC-B", "accepted": true}, sess(anna)); r.status != 201 {
		t.Fatalf("consent again: %d %s", r.status, r.body)
	}
	for doc, want := range map[string]bool{"DOC-A": true, "DOC-B": true} {
		if r := e.req("GET", "/__svc/app-api/consents/"+doc, nil, sess(anna)); r.json()["accepted"] != want || r.json()["documentId"] != doc {
			t.Fatalf("consent %s: %s", doc, r.body)
		}
	}
	// Marco never wrote: the default answer, not Anna's record.
	if r := e.req("GET", "/__svc/app-api/me/profile", nil, sess(marco)); r.json()["language"] != "it" {
		t.Fatalf("marco sees anna's profile: %s", r.body)
	}
}

func TestWave1StaticListAndDelete(t *testing.T) {
	e := newEnv(t, withSpec(withWave1))
	sid := e.newSession(nil)
	var ids []string
	for _, txt := range []string{"uno", "due"} {
		r := e.req("POST", "/__svc/app-api/notes", map[string]any{"text": txt}, sess(sid))
		if r.status != 201 {
			t.Fatalf("note: %d %s", r.status, r.body)
		}
		ids = append(ids, r.json()["id"].(string))
	}
	r := e.req("GET", "/__svc/app-api/notes", nil, sess(sid))
	if got := items(t, r); len(got) != 2 || r.header.Get(hdrStatic) != "true" {
		t.Fatalf("static list: %s", r.body)
	}
	if r := e.req("DELETE", "/__svc/app-api/notes/"+ids[0], nil, sess(sid)); r.status != 204 {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}
	r = e.req("GET", "/__svc/app-api/notes", nil, sess(sid))
	got := items(t, r)
	if len(got) != 1 || got[0].(map[string]any)["id"] != ids[1] {
		t.Fatalf("after delete: %s", r.body)
	}
	if n, _ := r.json()["count"].(json.Number).Int64(); n != 1 {
		t.Fatalf("count after delete: %s", r.body)
	}
	if r := e.req("DELETE", "/__svc/app-api/notes/"+ids[0], nil, sess(sid)); r.status != 404 {
		t.Fatalf("delete again: %d %s", r.status, r.body)
	}
}
