package mock

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// An invented app (rules v1.9): orders whose outcome depends on the
// channel of the request and on the customer's segment; a customer
// attribute carried by two responses; a summary of unread notifications,
// their amounts and the messages sent; a "mark all read"; a filtered list;
// a catalog answered statically with a full page; a checkout that answers
// 409 until an item was put in the cart.

const wave4Contract = `{
  "openapi":"3.1.0","info":{"title":"app-api","version":"1.0.0"},
  "paths":{
    "/orders":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"channel":{"type":"string"},"amount":{"type":"integer"}}}}}},
        "responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}}}}},
    "/orders/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}},
          "404":{"description":"nf","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}}}},
    "/me":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["segment","vip"],
        "properties":{"segment":{"type":"string"},"vip":{"type":"boolean"}}}}}}}}},
    "/me/profile":{
      "get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}}}},
      "put":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}},
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Profile"}}}}}}},
    "/me/summary":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["unread","due","messages"],
        "properties":{"unread":{"type":"integer"},"due":{"type":"number"},"messages":{"type":"integer"}}},
        "example":{"unread":7,"due":1.5,"messages":2}}}}}}},
    "/messages":{"post":{"responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/notifications":{"get":{"parameters":[{"name":"read","in":"query","schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["items"],
        "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/Notification"}}}}}}}}}},
    "/notifications/read-all":{"post":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/catalog":{"get":{"parameters":[{"name":"page","in":"query","schema":{"type":"integer"}},{"name":"size","in":"query","schema":{"type":"integer"}},{"name":"cursor","in":"query","schema":{"type":"string"}}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["items","count","total"],
        "properties":{"items":{"type":"array","items":{"type":"object","properties":{"sku":{"type":"string"}}}},"count":{"type":"integer"},"total":{"type":"integer"},"next":{"type":["string","null"]}}},
        "example":{"items":[{"sku":"A"},{"sku":"B"},{"sku":"C"}],"count":3,"total":3,"next":"more"}}}}}}},
    "/cart/items":{"post":{"responses":{"201":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}},
    "/checkout":{"post":{"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}},
        "409":{"description":"empty cart","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},"examples":{"empty-cart":{"value":{"error":{"code":"EMPTY_CART"}}}}}}}}}}
  },
  "components":{"schemas":{
    "Error":{"type":"object","properties":{"error":{"type":"object","properties":{"code":{"type":"string"}}}}},
    "Order":{"type":"object","required":["id"],"properties":{"id":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},"status":{"type":"string"},"path":{"type":"string"}}},
    "Profile":{"type":"object","properties":{"name":{"type":"string"},"segment":{"type":"string"}}},
    "Notification":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"read":{"type":"boolean"},"amount":{"type":"number"}}}
  }}}`

const wave4Rules = `{
  "format":"tt.rules/v1",
  "attributes":[
    {"name":"segment","values":{"GOLD":0.5,"STANDARD":0.5},"subjects":40,
     "fields":[{"service":"app-api","op":"GET /me","at":{"from":"resp.body","path":"$.segment"}},
               {"service":"app-api","op":"GET /me/profile","at":{"from":"resp.body","path":"$.segment"}}]},
    {"name":"vip","values":{"true":0.5,"false":0.5},"subjects":40,
     "fields":[{"service":"app-api","op":"GET /me","at":{"from":"resp.body","path":"$.vip"}}]}
  ],
  "aggregates":[
    {"service":"app-api","op":"GET /me/summary","at":{"from":"resp.body","path":"$.unread"},"count":{"entity":"notification","where":{"read":false}},"subjects":40},
    {"service":"app-api","op":"GET /me/summary","at":{"from":"resp.body","path":"$.due"},"sum":{"entity":"notification","field":"amount"},"subjects":40},
    {"service":"app-api","op":"GET /me/summary","at":{"from":"resp.body","path":"$.messages"},"delta":[{"op":"POST /messages","by":1}],"subjects":40}
  ],
  "lists":[
    {"service":"app-api","op":"GET /catalog","at":{"from":"resp.body","path":"$.items[*]"},
     "list":{"count":"$.count","total":"$.total","limit":{"from":"req.query","name":"size"},"cursor":{"from":"req.query","name":"cursor"},"next_cursor":"$.next"}}
  ],
  "entities":[
    {"name":"order","service":"app-api","id_domain":"order","id_field":"id","id_prefix":"ORD-SYN-",
     "created_by":{"op":"POST /orders","id":{"from":"resp.body","path":"$.id"},"defaults":{"status":"NEW"}},
     "read_by":[{"op":"GET /orders/{id}","by":{"from":"req.path","name":"id"},"at":{"from":"resp.body","path":"$"}}]},
    {"name":"profile","service":"app-api","id_domain":"profile","id_field":"id","id_prefix":"PRF-SYN-",
     "key":{"owner":true},
     "upserted_by":[{"op":"PUT /me/profile","state":{"from":"req.body","path":"$"}}],
     "read_by":[{"op":"GET /me/profile","at":{"from":"resp.body","path":"$"}}]},
    {"name":"notification","service":"app-api","id_domain":"notification","id_field":"id","id_prefix":"NTF-SYN-",
     "seed":{"per_customer":[{"n":"2","share":1}],"subjects":40},
     "read_by":[{"op":"GET /notifications","at":{"from":"resp.body","path":"$.items[*]"},"scope":"owner",
       "list":{"filters":[{"param":{"from":"req.query","name":"read"},"field":"read"}]}}]}
  ],
  "rules":[
    {"id":"r-0001","kind":"causal","status":"approved","title":"the outcome of an order depends on the channel and the segment",
     "cause":{"service":"app-api","op":"POST /orders","when":{"status":[201]},"bind":{"order":{"from":"resp.body","path":"$.id"}}},
     "effects":[
       {"id":"order-web","entity":"order","target_id":"${order}","set":{"path":"web"},"after":"0s"},
       {"id":"order-app","entity":"order","target_id":"${order}","set":{"path":"app"},"after":"0s"},
       {"id":"order-gold","entity":"order","target_id":"${order}","set":{"path":"gold"},"after":"0s"}],
     "outcomes":[
       {"name":"web","p":0.3,"effects":["order-web"],"when":[{"at":{"from":"req.body","path":"$.channel"},"in":["WEB"]}]},
       {"name":"app","p":0.3,"effects":["order-app"],"when":[{"at":{"from":"req.body","path":"$.channel"},"in":["APP"]}]},
       {"name":"gold","p":0.2,"effects":["order-gold"],"when":[{"customer":"segment","in":["GOLD"]},{"at":{"from":"req.body","path":"$.amount"},"min":100}]},
       {"name":"other","p":0.2,"effects":[]}]},
    {"id":"r-0002","kind":"causal","status":"approved","title":"orders from the kiosk header are confirmed",
     "cause":{"service":"app-api","op":"POST /orders","when":{"status":[201],"match":[{"at":{"from":"req.headers","name":"x-kiosk"},"in":["yes"]}]},"bind":{"order":{"from":"resp.body","path":"$.id"}}},
     "effects":[{"id":"order-confirmed","entity":"order","target_id":"${order}","set":{"status":"CONFIRMED"},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["order-confirmed"]}]},
    {"id":"r-0003","kind":"causal","status":"approved","title":"read-all marks every notification read",
     "cause":{"service":"app-api","op":"POST /notifications/read-all","when":{"status":[200]}},
     "effects":[{"id":"all-read","entity":"notification","target_all":true,"where":{"read":false},"set":{"read":true},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["all-read"]}]},
    {"id":"r-0004","kind":"causal","status":"approved","title":"checkout needs an item in the cart",
     "cause":{"service":"app-api","op":"POST /cart/items","when":{"status":[201]}},
     "effects":[{"id":"cart-filled","respond":{"service":"app-api","op":"POST /checkout","status":409,"example":"empty-cart","until":true},"after":"0s"}],
     "outcomes":[{"name":"always","p":1,"effects":["cart-filled"]}]}
  ]}`

func wave4World() []byte {
	ntf := func(id, cust string, read bool, amount string) any {
		return packtest.JSON(fmt.Sprintf(`{"customer_id":%q,"entity":"notification","id":%q,"state":{"amount":%s,"id":%q,"read":%t},"type":"entity"}`, cust, id, amount, id, read))
	}
	return packtest.Lines(
		packtest.JSON(`{"format":"tt.world/v1","seed":42,"t0":"2026-10-19T00:00:00Z","type":"meta"}`),
		packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0001","profile":{"email":"anna.rossi@example.com","name":"Anna Rossi","segment":"GOLD","vip":"true"},"type":"customer"}`),
		packtest.JSON(`{"archetype":null,"id":"CUS-SYN-0002","profile":{"email":"bruno.neri@example.com","name":"Bruno Neri","segment":"STANDARD","vip":"false"},"type":"customer"}`),
		ntf("NTF-SYN-0001", "CUS-SYN-0001", false, "2.5"),
		ntf("NTF-SYN-0002", "CUS-SYN-0001", false, "1"),
		ntf("NTF-SYN-0003", "CUS-SYN-0001", true, "4"),
		ntf("NTF-SYN-0004", "CUS-SYN-0002", false, "10"),
	)
}

func withWave4(sp *packtest.Spec) {
	sp.Files = map[string][]byte{
		"contracts/app-api.openapi.json": packtest.Canon(wave4Contract),
		"rules.json":                     packtest.Canon(wave4Rules),
		"gate-report.json":               sp.Files["gate-report.json"],
		"world.jsonl":                    wave4World(),
		"faults.json":                    packtest.Canon(`{"format":"tt.faults/v1","ops":[]}`),
		"scenarios.json":                 packtest.Canon(`{"format":"tt.scenarios/v1","scenarios":[]}`),
	}
	sp.Manifest["services"] = packtest.JSON(`[{"name":"app-api","contract":"contracts/app-api.openapi.json","upstream_alias":"app"}]`)
	sp.Manifest["rules"] = packtest.JSON(`{"path":"rules.json","approved":["r-0001","r-0002","r-0003","r-0004"]}`)
	sp.Manifest["world"] = packtest.JSON(`{"path":"world.jsonl","customers":2}`)
}

func (e *env) orderPath(sid string, body map[string]any, hdr map[string]string) (string, map[string]any) {
	e.t.Helper()
	h := sess(sid)
	for k, v := range hdr {
		h[k] = v
	}
	r := e.req("POST", "/__svc/app-api/orders", body, h)
	if r.status != 201 {
		e.t.Fatalf("order: %d %s", r.status, r.body)
	}
	got := e.req("GET", "/__svc/app-api/orders/"+r.json()["id"].(string), nil, sess(sid)).json()
	p, _ := got["path"].(string)
	return p, got
}

// The outcome follows the conditions of the request and of the customer;
// a request no conditional outcome matches falls back to the outcomes
// without when; a forced outcome wins over when.
func TestWave4ConditionalOutcomes(t *testing.T) {
	e := newEnv(t, withSpec(withWave4))
	bruno := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	for range 5 {
		if p, _ := e.orderPath(bruno, map[string]any{"channel": "WEB"}, nil); p != "web" {
			t.Fatalf("WEB order took %q", p)
		}
		if p, _ := e.orderPath(bruno, map[string]any{"channel": "APP"}, nil); p != "app" {
			t.Fatalf("APP order took %q", p)
		}
		// A STANDARD customer with a big amount: no conditional outcome.
		if p, _ := e.orderPath(bruno, map[string]any{"channel": "FAX", "amount": 500}, nil); p != "" {
			t.Fatalf("an order no condition matches took %q", p)
		}
	}
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	if p, _ := e.orderPath(anna, map[string]any{"channel": "FAX", "amount": 150}, nil); p != "gold" {
		t.Fatalf("a GOLD customer above 100 takes gold, got %q", p)
	}
	if p, _ := e.orderPath(anna, map[string]any{"channel": "FAX", "amount": 99}, nil); p != "" {
		t.Fatalf("below the range: %q", p)
	}
	e.force(bruno, "r-0001", "app")
	if p, _ := e.orderPath(bruno, map[string]any{"channel": "WEB"}, nil); p != "app" {
		t.Fatalf("a forced outcome wins over when, got %q", p)
	}
}

// cause.when.match: the rule fires only when the header matches.
func TestWave4CauseMatch(t *testing.T) {
	e := newEnv(t, withSpec(withWave4))
	s := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	if _, got := e.orderPath(s, map[string]any{"channel": "WEB"}, nil); got["status"] != "NEW" {
		t.Fatalf("without the header the rule must not fire: %v", got)
	}
	if _, got := e.orderPath(s, map[string]any{"channel": "WEB"}, map[string]string{"X-Kiosk": "no"}); got["status"] != "NEW" {
		t.Fatalf("another header value must not fire: %v", got)
	}
	if _, got := e.orderPath(s, map[string]any{"channel": "WEB"}, map[string]string{"X-Kiosk": "yes"}); got["status"] != "CONFIRMED" {
		t.Fatalf("the matching header fires the rule: %v", got)
	}
}

// Customer attributes: the customer's value when the world has it, else
// one value per session kept across calls and resets; converted to the
// schema type; the entity state wins.
func TestWave4Attributes(t *testing.T) {
	e := newEnv(t, withSpec(withWave4))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	got := e.req("GET", "/__svc/app-api/me", nil, sess(anna)).json()
	if got["segment"] != "GOLD" || got["vip"] != true {
		t.Fatalf("anna's attributes: %v", got)
	}
	if p := e.req("GET", "/__svc/app-api/me/profile", nil, sess(anna)).json(); p["segment"] != "GOLD" {
		t.Fatalf("the same attribute in another response: %v", p)
	}
	e.req("PUT", "/__svc/app-api/me/profile", map[string]any{"name": "Anna", "segment": "BRONZE"}, sess(anna))
	if p := e.req("GET", "/__svc/app-api/me/profile", nil, sess(anna)).json(); p["segment"] != "BRONZE" {
		t.Fatalf("the entity state wins over the attribute: %v", p)
	}
	bruno := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	if got := e.req("GET", "/__svc/app-api/me", nil, sess(bruno)).json(); got["segment"] != "STANDARD" || got["vip"] != false {
		t.Fatalf("bruno's attributes: %v", got)
	}
	// No customer: drawn once for the session, the same after a reset.
	anon := e.newSession(nil)
	first := e.req("GET", "/__svc/app-api/me", nil, sess(anon)).json()
	seg := first["segment"]
	if seg != "GOLD" && seg != "STANDARD" {
		t.Fatalf("a drawn value must be one of the attribute's: %v", first)
	}
	if _, isBool := first["vip"].(bool); !isBool {
		t.Fatalf("vip must be a boolean: %v", first)
	}
	for range 3 {
		if again := e.req("GET", "/__svc/app-api/me", nil, sess(anon)).json(); again["segment"] != seg {
			t.Fatalf("the value changed within the session: %v then %v", seg, again["segment"])
		}
	}
	e.ctl("POST", "/sessions/"+anon+"/reset", nil)
	if again := e.req("GET", "/__svc/app-api/me", nil, sess(anon)).json(); again["segment"] != seg {
		t.Fatalf("the value changed after a reset: %v then %v", seg, again["segment"])
	}
}

// Aggregates, target_all and list filters.
func TestWave4AggregatesAndTargetAll(t *testing.T) {
	e := newEnv(t, withSpec(withWave4))
	anna := e.newSession(map[string]any{"customer": "CUS-SYN-0001"})
	sum := e.req("GET", "/__svc/app-api/me/summary", nil, sess(anna)).json()
	if fmt.Sprint(sum["unread"]) != "2" || fmt.Sprint(sum["due"]) != "7.5" || fmt.Sprint(sum["messages"]) != "2" {
		t.Fatalf("summary: %v", sum)
	}
	e.req("POST", "/__svc/app-api/messages", nil, sess(anna))
	e.req("POST", "/__svc/app-api/messages", nil, sess(anna))
	if sum := e.req("GET", "/__svc/app-api/me/summary", nil, sess(anna)).json(); fmt.Sprint(sum["messages"]) != "4" {
		t.Fatalf("delta: two messages more than the base: %v", sum)
	}
	unread := items(t, e.req("GET", "/__svc/app-api/notifications?read=false", nil, sess(anna)))
	if len(unread) != 2 {
		t.Fatalf("filtered list: %v", unread)
	}
	if all := items(t, e.req("GET", "/__svc/app-api/notifications", nil, sess(anna))); len(all) != 3 {
		t.Fatalf("no filter parameter, no filter: %v", all)
	}
	if r := e.req("POST", "/__svc/app-api/notifications/read-all", nil, sess(anna)); r.status != 200 {
		t.Fatalf("read-all: %d", r.status)
	}
	if sum := e.req("GET", "/__svc/app-api/me/summary", nil, sess(anna)).json(); fmt.Sprint(sum["unread"]) != "0" {
		t.Fatalf("after read-all: %v", sum)
	}
	if unread := items(t, e.req("GET", "/__svc/app-api/notifications?read=false", nil, sess(anna))); len(unread) != 0 {
		t.Fatalf("after read-all the filtered list is empty: %v", unread)
	}
	// Another customer's notifications are untouched.
	bruno := e.newSession(map[string]any{"customer": "CUS-SYN-0002"})
	e.req("POST", "/__svc/app-api/notifications/read-all", nil, sess(anna))
	if sum := e.req("GET", "/__svc/app-api/me/summary", nil, sess(bruno)).json(); fmt.Sprint(sum["unread"]) != "1" || fmt.Sprint(sum["messages"]) != "2" {
		t.Fatalf("bruno's summary: %v", sum)
	}
}

// A list no entity reads is paged: a full static page never paginates
// forever.
func TestWave4StaticListPaging(t *testing.T) {
	e := newEnv(t, withSpec(withWave4))
	s := e.newSession(nil)
	all := e.req("GET", "/__svc/app-api/catalog", nil, sess(s)).json()
	if len(all["items"].([]any)) != 3 || all["next"] != nil {
		t.Fatalf("first page: %v", all)
	}
	p := e.req("GET", "/__svc/app-api/catalog?size=2", nil, sess(s)).json()
	if len(p["items"].([]any)) != 2 || p["next"] != "c2" || fmt.Sprint(p["count"]) != "2" || fmt.Sprint(p["total"]) != "3" {
		t.Fatalf("a limit truncates: %v", p)
	}
	p = e.req("GET", "/__svc/app-api/catalog?size=2&cursor=c2", nil, sess(s)).json()
	if len(p["items"].([]any)) != 1 || p["next"] != nil {
		t.Fatalf("the cursor of the mock: %v", p)
	}
	p = e.req("GET", "/__svc/app-api/catalog?cursor=more", nil, sess(s)).json()
	if len(p["items"].([]any)) != 0 || fmt.Sprint(p["count"]) != "0" || fmt.Sprint(p["total"]) != "3" {
		t.Fatalf("a cursor of the example ends the list: %v", p)
	}
}

// A precondition answers until its cause was seen, and again after a
// reset.
func TestWave4Until(t *testing.T) {
	e := newEnv(t, withSpec(withWave4))
	s := e.newSession(nil)
	r := e.req("POST", "/__svc/app-api/checkout", nil, sess(s))
	if r.status != 409 || fmt.Sprint(r.json()["error"]) != "map[code:EMPTY_CART]" {
		t.Fatalf("before the cart: %d %s", r.status, r.body)
	}
	e.req("POST", "/__svc/app-api/cart/items", nil, sess(s))
	if r := e.req("POST", "/__svc/app-api/checkout", nil, sess(s)); r.status != 200 {
		t.Fatalf("after the cart: %d %s", r.status, r.body)
	}
	other := e.newSession(nil)
	if r := e.req("POST", "/__svc/app-api/checkout", nil, sess(other)); r.status != 409 {
		t.Fatalf("another session keeps its precondition: %d", r.status)
	}
	e.ctl("POST", "/sessions/"+s+"/reset", nil)
	if r := e.req("POST", "/__svc/app-api/checkout", nil, sess(s)); r.status != 409 {
		t.Fatalf("a reset restores the precondition: %d", r.status)
	}
	// A fault forced by the test wins over the precondition.
	e.ctl("PUT", "/sessions/"+s+"/faults", map[string]any{"mode": "custom", "rules": []any{map[string]any{"service": "app-api", "op": "POST /checkout", "status": 503, "p": 1}}})
	if r := e.req("POST", "/__svc/app-api/checkout", nil, sess(s)); r.status != 503 {
		t.Fatalf("a forced fault wins: %d", r.status)
	}
}

// The identity claim walks a header whose value is a JSON object, plain or
// base64 encoded; a value that is neither gives no identity.
func TestWave4IdentityJSONHeader(t *testing.T) {
	e := newEnv(t, withIdentity(IdentityConfig{Header: "x-user-context", Claim: "user.id"}))
	plain := `{"user":{"id":"u-77","roles":["a"]},"tenant":"t1"}`
	r1 := e.req("GET", "/__svc/shop-api/orders/none", nil, userHdr("X-User-Context", plain))
	s1 := e.sessionOf(r1)
	if s1 == "default" || s1 == "" {
		t.Fatalf("a JSON header must give an identity session, got %q", s1)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"tenant":"t2","user":{"id":"u-77"}}`))
	if s := e.sessionOf(e.req("GET", "/__svc/shop-api/orders/none", nil, userHdr("X-User-Context", b64))); s != s1 {
		t.Fatalf("the same user in base64 JSON: %q, want %q", s, s1)
	}
	url := base64.RawURLEncoding.EncodeToString([]byte(`{"user":{"id":"u-78"}}`))
	if s := e.sessionOf(e.req("GET", "/__svc/shop-api/orders/none", nil, userHdr("X-User-Context", url))); s == s1 || s == "default" {
		t.Fatalf("another user in base64url JSON: %q", s)
	}
	for _, bad := range []string{`{"user":{"name":"x"}}`, `{"user":`, "not json", `{"user":{"id":"u-77"}} trailing`} {
		if s := e.req("GET", "/__svc/shop-api/orders/none", nil, userHdr("X-User-Context", bad)).header.Get("X-TT-Session"); s != "default" {
			t.Fatalf("%q must give no identity, got %q", bad, s)
		}
	}
}
