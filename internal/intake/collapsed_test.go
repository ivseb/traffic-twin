package intake

import (
	"strings"
	"testing"
)

// Values under the collapsed key {*} come from members whose original name is
// no longer known: the intake accepts them only if some matching rule of the
// right kind could have produced them (".*" rules, or ".name" rules for names
// that the sanitizer itself would collapse).
func TestCollapsedKeys(t *testing.T) {
	const body = `{
 "format":"tt.policy.body/v1","policy_id":"p-star","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 "global":{
  "request":{
    "query":{"order123456":{"action":"keep"}},
    "body":[{"path":"$.attrs.*","action":{"action":"keep"}},{"path":"$.refs.order123456","action":{"action":"hmac","domain":"order"}}]},
  "response":{"body":[{"path":"$.plain","action":{"action":"keep"}}]}
 },
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},"ops":[]}]
}`
	pol, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.policies.Add(pol)
	mk := func(extraReq string) string {
		// "a|b": b goes after path (query), a alone goes before (body).
		pre, post, found := strings.Cut(extraReq, "|")
		if !found {
			pre, post = extraReq, ""
		} else {
			pre = ""
		}
		req := `"req":{` + pre + `"path":"/",` + post + `"size":"l32"},"resp":{"size":"l8"},`
		s := eventJSON(pol.Hash, "inbound", "shop-api", "GET /", "raw", req)
		s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-star","version":1`, 1)
		return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
	}
	body2 := func(b string) string { return `"body":` + b + `,"ct":"application/json",` }
	cases := []struct {
		name string
		req  string
		want Reason
	}{
		{"kept value under a collapsed key with a .* rule", body2(`{"attrs":{"{*}":["keep:blue","drop:int"]}}`), ReasonNone},
		{"kept value under a literal key with a .* rule", body2(`{"attrs":{"color":"keep:blue"}}`), ReasonNone},
		{"no .* rule at another parent", body2(`{"other":{"{*}":["keep:blue"]}}`), ReasonValueNotAllowed},
		{"hmac under a collapsed key where only a collapsed .name rule exists", body2(`{"refs":{"{*}":["` + tokOrder1 + `"]}}`), ReasonNone},
		{"keep under that same key is not allowed", body2(`{"refs":{"{*}":["keep:x"]}}`), ReasonValueNotAllowed},
		{"literal name that the sanitizer would have collapsed cannot appear", body2(`{"refs":{"order123456":"` + tokOrder1 + `"}}`), ReasonSchema},
		{"kept query value under {*} (a rule exists for a collapsible name)", `|"query":{"{*}":["keep:abc"]},`, ReasonNone},
		{"hmac query value under {*}", `|"query":{"{*}":["` + tokOrder1 + `"]},`, ReasonValueNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := mk(c.req)
			rej := h.ingest(t, ev)
			if rej.Reason != c.want {
				t.Fatalf("got %s (%s), want %s", rej.Reason, rej.Detail, c.want)
			}
		})
	}
}
