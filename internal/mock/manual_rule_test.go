package mock

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// manualRules are rules written by hand in the rule editor (origin manual,
// rules v1.4), validated by the miner's model and exported like mined ones.
func manualRules(t *testing.T) []miner.Rule {
	t.Helper()
	one := `{"id":"r-0101","kind":"causal","status":"approved","origin":"manual","title":"Dopo un ordine la prima lettura risponde 404",
	  "cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201]},"bind":{"order":{"from":"resp.body","path":"$.id"}}},
	  "effects":[
	    {"id":"first-read-missing","respond":{"service":"shop-api","op":"GET /orders/{id}","status":404,"times":1,"example":"order-not-found"},"after":"0s"},
	    {"id":"order-created","entity":"order","target_id":"${order}","set":{"status":"CREATED"},"after":"1h"},
	    {"id":"carrier-flaky","respond":{"service":"shipping-ext","op":"GET /v1/shipments","status":503,"p":0.5},"after_effect":"order-created","after":"0s"}],
	  "outcomes":[{"name":"always","p":1,"effects":["first-read-missing","order-created","carrier-flaky"]}],
	  "evidence":{"counts":{"causes":0,"distinct_subjects":0,"outcomes":{"always":0}}}}`
	var r miner.Rule
	if err := json.Unmarshal([]byte(one), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(nil); err != nil {
		t.Fatal(err)
	}
	return []miner.Rule{r}
}

func withManualRules(t *testing.T) func(*packtest.Spec) {
	rules := manualRules(t)
	return func(sp *packtest.Spec) {
		var doc map[string]any
		if err := json.Unmarshal(sp.Files["rules.json"], &doc); err != nil {
			panic(err)
		}
		approved := sp.Manifest["rules"].(map[string]any)["approved"].([]any)
		for _, r := range rules {
			b, _ := json.Marshal(r)
			var m any
			_ = json.Unmarshal(b, &m)
			doc["rules"] = append(doc["rules"].([]any), m)
			approved = append(approved, r.ID())
		}
		sp.Manifest["rules"].(map[string]any)["approved"] = approved
		b, _ := json.Marshal(doc)
		sp.Files["rules.json"] = packtest.Canon(string(b))
	}
}

func TestManualRuleHonouredByTheMock(t *testing.T) {
	e := newEnv(t, exact(), withSpec(withManualRules(t)))
	sid := e.newSession(map[string]any{"seed": 3})
	id := e.order(sid)

	// "The next call returns Y": the first read of the order answers 404 with
	// the contract example, the second one is normal.
	r := e.req("GET", "/__svc/shop-api/orders/"+id, nil, sess(sid))
	if r.status != 404 || r.json()["error"].(map[string]any)["code"] != "ORDER_NOT_FOUND" {
		t.Fatalf("first read: %d %s", r.status, r.body)
	}
	if r := e.req("GET", "/__svc/shop-api/orders/"+id, nil, sess(sid)); r.status != 200 {
		t.Fatalf("second read: %d %s", r.status, r.body)
	}
	// Before the delay the carrier never fails (faults are off).
	for i := 0; i < 20; i++ {
		if r := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+id, nil, sess(sid)); r.status != 200 {
			t.Fatalf("carrier before the effect: %d", r.status)
		}
	}
	// "The state becomes X after a figurative delay".
	applied := e.advance(sid, "1h")
	got := map[string]bool{}
	for _, a := range applied {
		got[a.(map[string]any)["effect"].(string)] = true
	}
	if !got["order-created"] || !got["carrier-flaky"] {
		t.Fatalf("applied: %v", applied)
	}
	if r := e.req("GET", "/__svc/shop-api/orders/"+id, nil, sess(sid)); r.json()["status"] != "CREATED" {
		t.Fatalf("state: %s", r.body)
	}
	// "Error with frequency p": about half of the carrier calls fail now.
	fails := 0
	for i := 0; i < 400; i++ {
		r := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+id, nil, sess(sid))
		switch r.status {
		case 503:
			fails++
		case 200:
		default:
			t.Fatalf("carrier: %d", r.status)
		}
	}
	if fails < 140 || fails > 260 {
		t.Fatalf("failures with p=0.5: %d of 400", fails)
	}
	// The journal says which rule decided the answer.
	j := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	if j.status != 200 || !strings.Contains(string(j.body), `"rule":"r-0101"`) {
		t.Fatalf("journal: %d %.500s", j.status, j.body)
	}
}
