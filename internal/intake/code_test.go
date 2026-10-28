package intake

import (
	"strings"
	"testing"
)

// A code rule (docs/spec/sanitizer.md 5.6, spec v1.11) admits only keep:
// tokens with the code shape, and never numbers, booleans or null.
func TestCodeRuleTokens(t *testing.T) {
	const body = `{
 "format":"tt.policy.body/v1","policy_id":"p-code","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 "global":{},
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},
   "ops":[{"op":"POST /x","request":{"body":[{"path":"$.status","action":{"action":"code"}}]}}]}]
}`
	pol, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.policies.Add(pol)
	mk := func(reqBody string) string {
		req := `"req":{"body":` + reqBody + `,"ct":"application/json","path":"/x","size":"l32"},"resp":{"size":"l8"},`
		s := eventJSON(pol.Hash, "inbound", "shop-api", "POST /x", "policy", req)
		s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-code","version":1`, 1)
		return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
	}
	for _, c := range []struct {
		name, body string
		want       Reason
	}{
		{"code value", `{"status":"keep:DELIVERED"}`, ReasonNone},
		{"code with separators", `{"status":"keep:in_transit"}`, ReasonNone},
		{"shape", `{"status":"drop:str:l32"}`, ReasonNone},
		{"digits", `{"status":"keep:E404"}`, ReasonValueNotAllowed},
		{"space", `{"status":"keep:in transit"}`, ReasonValueNotAllowed},
		{"too short", `{"status":"keep:A"}`, ReasonValueNotAllowed},
		{"too long", `{"status":"keep:` + strings.Repeat("Q", 33) + `"}`, ReasonValueNotAllowed},
		{"number", `{"status":1}`, ReasonValueNotAllowed},
		{"boolean", `{"status":true}`, ReasonValueNotAllowed},
		{"token", `{"status":"` + tokOrder1 + `"}`, ReasonValueNotAllowed},
	} {
		t.Run(c.name, func(t *testing.T) {
			if rej := h.ingest(t, mk(c.body)); rej.Reason != c.want {
				t.Fatalf("got %s (%s), want %s", rej.Reason, rej.Detail, c.want)
			}
		})
	}
}
