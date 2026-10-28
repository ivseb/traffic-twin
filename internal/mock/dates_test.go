package mock

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// withPolicies adds an operation whose dates are relative to the clock
// (x-tt-value.date_offset, pack.md 4.4).
func withPolicies(sp *packtest.Spec) {
	var doc map[string]any
	if err := json.Unmarshal(sp.Files["contracts/shop-api.openapi.json"], &doc); err != nil {
		panic(err)
	}
	var op map[string]any
	if err := json.Unmarshal([]byte(`{"get":{"operationId":"getPolicy",
		"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
		"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["renewalDate","withdrawBy","issuedAt"],
			"properties":{
				"renewalDate":{"type":"string","format":"date","x-tt-value":{"kind":"bucket","unit":"day","date_offset":{"min":"+30d","max":"+365d"}}},
				"withdrawBy":{"type":"string","format":"date-time","x-tt-value":{"kind":"shape","format":"datetime","date_offset":{"min":"+15d","max":"+15d"}}},
				"issuedAt":{"type":"string","format":"date-time"}}}}}}}}}`), &op); err != nil {
		panic(err)
	}
	doc["paths"].(map[string]any)["/policies/{id}"] = op
	b, _ := json.Marshal(doc)
	sp.Files["contracts/shop-api.openapi.json"] = packtest.Canon(string(b))
}

func TestRelativeDates(t *testing.T) {
	e := newEnv(t, withSpec(withPolicies))
	sid := e.newSession(map[string]any{"seed": 2})
	check := func() {
		t.Helper()
		now, _ := time.Parse(time.RFC3339, e.ctl("GET", "/sessions/"+sid+"/clock", nil).json()["now"].(string))
		r := e.req("GET", "/__svc/shop-api/policies/POL-1", nil, sess(sid))
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		e.conforms("shop-api", "GET /policies/{id}", 200, r)
		b := r.json()
		ren, err := time.Parse("2006-01-02", b["renewalDate"].(string))
		day0 := now.Truncate(24 * time.Hour)
		if err != nil || ren.Before(day0.AddDate(0, 0, 30)) || ren.After(day0.AddDate(0, 0, 365)) {
			t.Fatalf("renewalDate %v not in clock + 30..365 days (clock %s)", b["renewalDate"], now)
		}
		if w := b["withdrawBy"]; w != now.AddDate(0, 0, 15).Format(time.RFC3339) {
			t.Fatalf("withdrawBy %v, clock %s", w, now)
		}
		if b["issuedAt"] != now.Format(time.RFC3339) {
			t.Fatalf("issuedAt %v", b["issuedAt"])
		}
	}
	check()
	e.advance(sid, "400d")
	check() // the dates move with the virtual clock
}
