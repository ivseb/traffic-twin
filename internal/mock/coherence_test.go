package mock

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// lab-style pack (as mined from real traffic): the shop's single read of a
// shipment has no hidden_when of its own, and the cancelled outcome sets only
// the status. The contract ties cancelReason to status CANCELLED (x-tt-when).
func labStylePack() envOpt {
	return func(sp *packtest.Spec, _ *Config) {
		*sp = packtest.ExactDemoSpec()
		rules := packtest.JSON(string(sp.Files["rules.json"])).(map[string]any)
		for _, ent := range rules["entities"].([]any) {
			em := ent.(map[string]any)
			if em["name"] != "shipment" {
				continue
			}
			for _, rb := range em["read_by"].([]any) {
				if m := rb.(map[string]any); m["op"] == "GET /orders/{id}/shipment" {
					delete(m, "hidden_when")
				}
			}
		}
		for _, r := range rules["rules"].([]any) {
			rm := r.(map[string]any)
			effs, _ := rm["effects"].([]any)
			for _, e := range effs {
				if set, ok := e.(map[string]any)["set"].(map[string]any); ok {
					delete(set, "cancelReason")
				}
			}
		}
		sp.Files["rules.json"] = packtest.CJSON(rules)
		for _, f := range []string{"contracts/shipping-ext.openapi.json", "contracts/shop-api.openapi.json"} {
			ct := string(sp.Files[f])
			ct = strings.ReplaceAll(ct, `"cancelReason":{"type":"string"}`, `"cancelReason":{"enum":["ADDRESS_UNREACHABLE","DAMAGED_IN_WAREHOUSE"],"type":"string","x-tt-when":{"status":["CANCELLED"]}}`)
			sp.Files[f] = []byte(ct)
		}
	}
}

func TestShopShipmentFollowsHiddenWhenOfTheCarrierRead(t *testing.T) {
	e := newEnv(t, labStylePack())
	sid := e.newSession(nil)
	id := e.order(sid)
	// PENDING: invisible on the carrier read and, inherited, on the shop read
	r := e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid))
	if r.status != 404 {
		t.Fatalf("shop shipment while PENDING: %d %s", r.status, r.body)
	}
	e.advance(sid, "5m")
	r = e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid))
	if r.status != 200 || r.json()["status"] != "CREATED" {
		t.Fatalf("shop shipment once CREATED: %d %s", r.status, r.body)
	}
	if _, has := r.json()["cancelReason"]; has {
		t.Fatalf("a CREATED shipment must not carry cancelReason: %s", r.body)
	}
}

func TestCancelledShipmentCarriesConditionalField(t *testing.T) {
	e := newEnv(t, labStylePack())
	sid := e.newSession(nil)
	e.force(sid, "r-0007", "cancelled")
	id := e.order(sid)
	e.advance(sid, "5m")
	if s := e.shipments(sid, id)[0].(map[string]any); s["status"] != "CREATED" || s["cancelReason"] != nil {
		t.Fatalf("created shipment = %v", s)
	}
	e.advance(sid, "1h")
	s := e.shipments(sid, id)[0].(map[string]any)
	reason, _ := s["cancelReason"].(string)
	if s["status"] != "CANCELLED" || (reason != "ADDRESS_UNREACHABLE" && reason != "DAMAGED_IN_WAREHOUSE") {
		t.Fatalf("cancelled shipment = %v", s)
	}
	r := e.req("GET", "/__svc/shop-api/orders/"+id+"/shipment", nil, sess(sid))
	if r.status != 200 || r.json()["cancelReason"] != reason {
		t.Fatalf("shop view of the cancelled shipment: %d %s", r.status, r.body)
	}
}
