package intake

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// canonicalReq re-serializes a req fragment with sorted keys (tt-cjson for
// these ASCII test values).
func canonicalReq(t *testing.T, fields string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte("{"+fields+`,"path":"/x"}`), &m); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Spec v1.19 (docs/spec/sanitizer.md 5.6 alnum and 22): the intake accepts
// the new event forms only under the policy switches that produce them, and
// still accepts the v1.11 forms of older sources.
func TestBodiesV119Forms(t *testing.T) {
	policyBody := func(bodies string) string {
		return `{
 "format":"tt.policy.body/v1","policy_id":"p-bodies","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":2048,"max_depth":32,"max_array":2,"max_keys":256,"keep_max_bytes":64},` + bodies + `
 "global":{},
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},
   "ops":[{"op":"POST /x","request":{"body":[
     {"path":"$.code","action":{"action":"code","shape":"alnum"}},
     {"path":"$.Envelope.Body.Get.@type","action":{"action":"code","shape":"alnum"}},
     {"path":"$.version","action":{"action":"code"}}]}}]}]
}`
	}
	on := policyBody(`"bodies":{"xml":true,"multipart":true,"docs":true,"max_large_body_bytes":65536,"large_array":5,"large_nested_array":1},`)
	off := policyBody("")
	for _, pc := range []struct {
		name, body string
		on         bool
	}{{"on", on, true}, {"off", off, false}} {
		pol, err := ParsePolicy([]byte(pc.body))
		if err != nil {
			t.Fatal(err)
		}
		h := newHarness(t)
		h.policies.Add(pol)
		mk := func(req string) string {
			s := eventJSON(pol.Hash, "inbound", "shop-api", "POST /x", "policy", `"req":`+canonicalReq(t, req)+`,"resp":{"size":"l8"},`)
			s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-bodies","version":1`, 1)
			return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
		}
		ifOn := func(r Reason) Reason {
			if pc.on {
				return ReasonNone
			}
			return r
		}
		for _, c := range []struct {
			name, req string
			want      Reason
		}{
			{"alnum code", `"body":{"code":"keep:0000123450"},"ct":"application/json","size":"l32"`, ReasonNone},
			{"alnum code with space", `"body":{"code":"keep:2 1"},"ct":"application/json","size":"l32"`, ReasonValueNotAllowed},
			{"alnum code too long", `"body":{"code":"keep:` + strings.Repeat("1", 17) + `"},"ct":"application/json","size":"l32"`, ReasonValueNotAllowed},
			{"alpha code refuses digits", `"body":{"version":"keep:2.1"},"ct":"application/json","size":"l32"`, ReasonValueNotAllowed},
			{"document shape", `"body":{"file":"drop:doc:pdf:l1m"},"ct":"application/json","size":"lmax"`, ReasonNone},
			{"bad document kind", `"body":{"file":"drop:doc:exe:l1m"},"ct":"application/json","size":"lmax"`, ReasonSchema},
			{"xml key in json", `"body":{"@type":"drop:str:l8"},"ct":"application/json","size":"l32"`, ReasonBodyShape},
			{"soap body", `"body":{"Envelope":{"Body":{"Get":{"@type":"keep:R1","#text":"drop:str:l8"}}}},"ct":"text/xml","fmt":"soap11","size":"l128","soap_action":"Get","xmlns":{"$.Envelope":"ns:http://schemas.xmlsoap.org/soap/envelope/"}`, ifOn(ReasonBodyShape)},
			{"bucket(num) never on xml", `"body":{"Envelope":{"Body":{"Get":{"@type":"num:0-50"}}}},"ct":"text/xml","fmt":"soap11","size":"l128"`, map[bool]Reason{true: ReasonValueNotAllowed, false: ReasonBodyShape}[pc.on]},
			{"invalid xml marker", `"body":"trunc:invalid-xml","ct":"application/xml","fmt":"xml","size":"l32"`, ifOn(ReasonBodyShape)},
			{"invalid xml marker on json", `"body":"trunc:invalid-xml","ct":"application/json","size":"l32"`, ReasonBodyShape},
			{"xml without fmt (older source)", `"body":"drop:bytes:l128","ct":"text/xml","size":"l128"`, ReasonNone},
			{"xmlns without xml", `"body":{"a":"drop:str:l8"},"ct":"application/json","size":"l32","xmlns":{"$.a":"ns:urn:a"}`, ReasonBodyShape},
			{"xml fmt on json", `"body":{"a":"drop:str:l8"},"ct":"application/json","fmt":"xml","size":"l32"`, ReasonBodyShape},
			{"fmt without body", `"ct":"text/xml","fmt":"xml","size":"l8"`, ReasonBodyShape},
			{"soap action without xml", `"body":{"a":"drop:str:l8"},"ct":"application/json","size":"l32","soap_action":"Get"`, ReasonBodyShape},
			{"multipart", `"body":{"f":["drop:file:pdf:l128k"],"kind":["drop:str:l8"]},"ct":"multipart/form-data","fmt":"multipart","size":"lmax"`, ifOn(ReasonBodyShape)},
			{"file token in json", `"body":{"f":"drop:file:pdf:l128k"},"ct":"application/json","size":"l32"`, ReasonNone},
			{"large body arrays", `"body":{"items":["drop:str:l8","drop:str:l8","drop:str:l8","drop:str:l8","drop:str:l8","trunc:n:l128"]},"ct":"application/json","size":"lmax"`, ifOn(ReasonLimits)},
			{"normal body arrays", `"body":{"items":["drop:str:l8","drop:str:l8","drop:str:l8","drop:str:l8","trunc:n:l8"]},"ct":"application/json","size":"l128"`, ReasonLimits},
		} {
			t.Run(pc.name+"/"+c.name, func(t *testing.T) {
				if rej := h.ingest(t, mk(c.req)); rej.Reason != c.want {
					t.Fatalf("got %s (%s), want %s", rej.Reason, rej.Detail, c.want)
				}
			})
		}
		if !pc.on {
			continue
		}
		// event.md 6 (spec v1.19): a SOAP exchange is stored under its
		// logical op, named by soap_action or by the only Body element.
		for _, req := range []string{
			`"body":{"Envelope":{"Body":{"Find":{"#text":"drop:str:l8"}}}},"ct":"text/xml","fmt":"soap11","size":"l128"`,
			`"body":{"Envelope":{"Body":{"A":"drop:str:l8","B":"drop:str:l8"}}},"ct":"text/xml","fmt":"soap11","size":"l128"`,
		} {
			if rej := h.ingest(t, mk(req)); rej.Reason != ReasonNone {
				t.Fatalf("soap: %s (%s)", rej.Reason, rej.Detail)
			}
		}
		h.idle(t)
		ops := map[string]bool{}
		if err := h.in.Store().Scan(context.Background(), Query{Service: "shop-api"}, func(se *StoredEvent) error {
			ops[se.Event.Op] = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"POST /x#Get", "POST /x#Find", "POST /x"} {
			if !ops[want] {
				t.Fatalf("%s not stored: %v", want, ops)
			}
		}
	}
}
