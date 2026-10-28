package intake

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

func member(v *event.Value, key string) *event.Value {
	m, ok := v.Get(key)
	if !ok {
		panic("no member " + key)
	}
	return m
}

func setHeader(m *event.Multi, name string, toks ...string) {
	*m = append(*m, event.MultiEntry{Name: name, Values: toks})
	sort.SliceStable(*m, func(i, j int) bool { return (*m)[i].Name < (*m)[j].Name })
}

func at(t time.Time) func(*event.Event) {
	return func(e *event.Event) {
		e.Time = t
		e.TS = t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
}

// TestEveryIntakeCheck is the table of the checks of docs/spec/event.md 5.1
// (and policy.md): every row starts from a valid event and breaks exactly one
// rule; the event must be dropped with the expected reason.
func TestEveryIntakeCheck(t *testing.T) {
	h := newHarness(t)
	hash, hashOff, hashStrict := h.pol.Hash, h.polOff.Hash, h.polStrict.Hash
	h.sources.Set(SourceInfo{ID: "src-staging", Group: "staging", ServiceName: "shop-api", AllowedServices: []string{"shop-api"}})

	type tc struct {
		name   string
		source string // default: testSource
		ev     func() string
		want   Reason
	}
	post := func(f func(*event.Event)) func() string {
		return func() string { return mutate(t, orderPost(hash), f) }
	}
	get := func(f func(*event.Event)) func() string {
		return func() string { return mutate(t, orderGet(hash), f) }
	}
	ship := func(f func(*event.Event)) func() string {
		return func() string { return mutate(t, shipmentPost(hash), f) }
	}
	raw := func(f func(*event.Event)) func() string {
		return func() string { return mutate(t, rawPromo(hash), f) }
	}
	respBody := func(e *event.Event) *event.Value { return e.Resp.Body }

	cases := []tc{
		// --- accepted fixtures
		{"order post", "", post(func(*event.Event) {}), ReasonNone},
		{"order get", "", get(func(*event.Event) {}), ReasonNone},
		{"shipment post", "", ship(func(*event.Event) {}), ReasonNone},
		{"raw route with an automatic word", "", raw(func(*event.Event) {}), ReasonNone},
		{"old accepted kid", "", post(func(e *event.Event) { *member(respBody(e), "id") = event.Str(tokOldKid) }), ReasonNone},
		{"keep number where the rule is keep", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Value{Kind: event.Number, S: "42"} }), ReasonNone},
		{"keep bool where the rule is keep", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Value{Kind: event.Bool, B: true} }), ReasonNone},
		{"drop forms anywhere", "", post(func(e *event.Event) { *member(respBody(e), "id") = event.Str("drop:str:uuid") }), ReasonNone},
		{"trunc markers anywhere", "", post(func(e *event.Event) { e.Req.Body = &event.Value{Kind: event.String, S: "trunc:size"} }), ReasonNone},
		{"op with bucket lower edge", "", post(func(e *event.Event) { *member(respBody(e), "total") = event.Str("num:<0") }), ReasonNone},
		{"op with bucket upper edge", "", post(func(e *event.Event) { *member(respBody(e), "total") = event.Str("num:>=250") }), ReasonNone},
		{"error rule on a 5xx response", "", post(func(e *event.Event) {
			e.Status = 500
			e.Resp.Body = &event.Value{Kind: event.Object, O: []event.Member{{K: "error", V: event.Obj(event.Member{K: "code", V: event.Str("keep:E_BUSY")})}}}
		}), ReasonNone},
		// --- 5.1 point 3: policy
		{"unknown policy hash", "", post(func(e *event.Event) { e.Policy.Hash = "sha256:" + strings.Repeat("f", 64) }), ReasonPolicyUnknown},
		{"policy version differs", "", post(func(e *event.Event) { e.Policy.Version = 8 }), ReasonPolicyMismatch},
		{"policy id differs", "", post(func(e *event.Event) { e.Policy.ID = "p-other" }), ReasonPolicyMismatch},
		{"policy not assigned to the group", "src-staging", post(func(e *event.Event) { e.Source.ID = "src-staging" }), ReasonPolicyGroup},
		{"event after not_after", "", post(at(time.Date(2026, 11, 18, 8, 10, 0, 0, time.UTC))), ReasonPolicyTime},
		{"event before the policy existed", "", post(at(time.Date(2026, 10, 19, 7, 0, 0, 0, time.UTC))), ReasonPolicyTime},

		// --- 5.1 point 4: identity
		{"source id differs from the certificate", "", post(func(e *event.Event) { e.Source.ID = "src-ZZZZ" }), ReasonSourceMismatch},
		{"inbound service not allowed for the group", "", post(func(e *event.Event) { e.Service = "payments" }), ReasonServiceNotAllowed},
		{"inbound service allowed but not the assigned one", "", post(func(e *event.Event) { e.Service = "billing"; e.RouteSource = "raw"; e.Op = "POST /orders" }), ReasonServiceNotAllowed},
		{"inbound with a host service", "", post(func(e *event.Event) { e.Service = "host:unlisted" }), ReasonServiceNotAllowed},
		{"outbound service not declared", "", ship(func(e *event.Event) { e.Service = "ghost-ext" }), ReasonServiceNotAllowed},
		{"outbound to an inbound service name", "", ship(func(e *event.Event) { e.Service = "shop-api" }), ReasonServiceNotAllowed},

		// --- 5.1 point 6: types of values
		{"keep where the rule is drop (default)", "", post(func(e *event.Event) {
			member(e.Req.Body, "items").A[0].O[0].V = event.Str("keep:3")
		}), ReasonValueNotAllowed},
		{"keep on a field without rule", "", post(func(e *event.Event) { *member(e.Req.Body, "note") = event.Str("keep:please call me") }), ReasonValueNotAllowed},
		{"keep number on a field without rule", "", post(func(e *event.Event) { *member(e.Req.Body, "note") = event.Value{Kind: event.Number, S: "7"} }), ReasonValueNotAllowed},
		{"null on a field without rule", "", post(func(e *event.Event) { *member(e.Req.Body, "note") = event.Value{Kind: event.Null} }), ReasonValueNotAllowed},
		{"tk1 where the rule is keep", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Str(tokOrder2) }), ReasonValueNotAllowed},
		{"keep where the rule is hmac", "", post(func(e *event.Event) { *member(respBody(e), "id") = event.Str("keep:ORD-2026-000184") }), ReasonValueNotAllowed},
		{"number where the rule is hmac", "", post(func(e *event.Event) { *member(respBody(e), "id") = event.Value{Kind: event.Number, S: "184"} }), ReasonValueNotAllowed},
		{"hmac with an unknown kid", "", post(func(e *event.Event) { *member(respBody(e), "id") = event.Str(tokOtherKid) }), ReasonValueNotAllowed},
		{"num where the rule is keep", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Str("num:0-50") }), ReasonValueNotAllowed},
		{"num with bounds that are not consecutive", "", post(func(e *event.Event) { *member(respBody(e), "total") = event.Str("num:0-100") }), ReasonValueNotAllowed},
		{"num with bounds not in the rule", "", post(func(e *event.Event) { *member(respBody(e), "total") = event.Str("num:50-101") }), ReasonValueNotAllowed},
		{"num below the first bound but written as an interval", "", post(func(e *event.Event) { *member(respBody(e), "total") = event.Str("num:-5-0") }), ReasonValueNotAllowed},
		{"JSON number where the rule is bucket(num)", "", post(func(e *event.Event) { *member(respBody(e), "total") = event.Value{Kind: event.Number, S: "73.4"} }), ReasonValueNotAllowed},
		{"time where the rule is keep", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Str("time:2026-10-19") }), ReasonValueNotAllowed},
		{"time bucket of another unit", "", get(func(e *event.Event) { *member(respBody(e), "eta") = event.Str("time:2026-10") }), ReasonValueNotAllowed},
		{"keep longer than keep_max_bytes", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Str("keep:" + strings.Repeat("x", 65)) }), ReasonValueNotAllowed},
		{"keep exactly keep_max_bytes", "", post(func(e *event.Event) { *member(respBody(e), "status") = event.Str("keep:" + strings.Repeat("x", 64)) }), ReasonNone},
		{"header value kept without rule", "", post(func(e *event.Event) { setHeader(&e.Req.Headers, "x-tenant", "keep:acme") }), ReasonValueNotAllowed},
		{"header kept on a rule: ok", "", post(func(e *event.Event) { setHeader(&e.Resp.Headers, "x-ignored", "drop:str:l8") }), ReasonNone},
		{"query kept by rule", "", post(func(e *event.Event) {}), ReasonNone},
		{"query hmac where the rule is keep", "", post(func(e *event.Event) { e.Req.Query[0].Values[0] = tokOrder1 }), ReasonValueNotAllowed},
		{"query value kept without rule", "", post(func(e *event.Event) {
			e.Req.Query = append(e.Req.Query, event.MultiEntry{Name: "zip", Values: []string{"keep:00100"}})
		}), ReasonValueNotAllowed},
		{"query num never applies", "", post(func(e *event.Event) { e.Req.Query[0].Values[0] = "num:0-50" }), ReasonValueNotAllowed},
		{"cookie value kept without rule", "", post(func(e *event.Event) {
			e.Req.Cookies = event.Multi{{Name: "sid", Values: []string{"keep:abc"}}}
		}), ReasonValueNotAllowed},
		{"header with two values", "", post(func(e *event.Event) { e.Req.Headers[0].Values = []string{"keep:application/json", "keep:text/plain"} }), ReasonLimits},
		{"kept value under a collapsed key without any matching rule", "", post(func(e *event.Event) {
			e.Req.Body = &event.Value{Kind: event.Object, O: []event.Member{{K: "{*}", V: event.Arr(event.Str("keep:Roma"))}}}
		}), ReasonValueNotAllowed},
		{"kept value in an error body outside an error response", "", post(func(e *event.Event) {
			e.Resp.Body = &event.Value{Kind: event.Object, O: []event.Member{{K: "error", V: event.Obj(event.Member{K: "code", V: event.Str("keep:E_BUSY")})}}}
		}), ReasonValueNotAllowed},
		{"hmac path parameter where the rule is hmac: ok", "", get(func(e *event.Event) {}), ReasonNone},
		{"keep path parameter where the rule is hmac", "", get(func(e *event.Event) { e.Req.Path = "/orders/{keep:ORD1}" }), ReasonValueNotAllowed},
		{"num path parameter", "", get(func(e *event.Event) { e.Req.Path = "/orders/{num:1-2}" }), ReasonValueNotAllowed},
		{"hmac path parameter with a foreign kid", "", get(func(e *event.Event) { e.Req.Path = "/orders/{" + tokOtherKid + "}" }), ReasonValueNotAllowed},
		{"keep path parameter where the rule is keep", "", func() string {
			return mutate(t, shipmentPost(hash), func(e *event.Event) {
				e.Op = "GET /v1/rates/{zone}"
				e.Req.Path = "/v1/rates/{keep:EU-NORD}"
				e.Req.Body = nil
				e.Req.CT = ""
				e.Req.Size = "l8"
				e.Resp.Body = nil
			})
		}, ReasonNone},
		{"keep path parameter not in the rule's charset is impossible: too long", "", func() string {
			return mutate(t, shipmentPost(hash), func(e *event.Event) {
				e.Op = "GET /v1/rates/{zone}"
				e.Req.Path = "/v1/rates/{keep:" + strings.Repeat("a", 64) + "}"
				e.Req.Body = nil
				e.Req.CT = ""
				e.Req.Size = "l8"
				e.Resp.Body = nil
			})
		}, ReasonNone},
		{"subject with a foreign kid", "", post(func(e *event.Event) { e.Subject = tokOtherKid }), ReasonValueNotAllowed},

		// --- route / op / path
		{"op not declared", "", post(func(e *event.Event) { e.Op = "POST /ghost" }), ReasonOpUnknown},
		{"OTHER method on a policy route", "", post(func(e *event.Event) { e.Op = "OTHER /orders" }), ReasonOpUnknown},
		{"path longer than the template", "", get(func(e *event.Event) { e.Req.Path = "/orders/{drop:str:l8}/items" }), ReasonPathShape},
		{"literal differs from the template", "", get(func(e *event.Event) { e.Req.Path = "/order/{" + tokOrder1 + "}" }), ReasonPathShape},
		{"parameter position holds a literal", "", get(func(e *event.Event) { e.Req.Path = "/orders/abc" }), ReasonPathShape},
		{"outbound path does not start with the base", "", ship(func(e *event.Event) { e.Req.Path = "/v2/shipments" }), ReasonPathShape},
		{"raw op differs from the path", "", raw(func(e *event.Event) { e.Op = "GET /promo/{drop:str:l32}" }), ReasonPathShape},
		{"raw segment not allowed", "", raw(func(e *event.Event) {
			e.Op = "GET /secret2/{drop:str:l8}"
			e.Req.Path = "/secret2/{drop:str:l8}"
		}), ReasonSegmentNotAllowed},
		{"raw segment that looks like a name but is an identifier", "", raw(func(e *event.Event) {
			e.Op = "GET /promo/mario-rossi-1985"
			e.Req.Path = "/promo/mario-rossi-1985"
		}), ReasonSegmentNotAllowed},
		{"raw segment allowed by segments.allow", "", raw(func(e *event.Event) {
			e.Op = "GET /v2/{drop:str:l8}"
			e.Req.Path = "/v2/{drop:str:l8}"
		}), ReasonNone},
		{"raw segment: automatic words expired", "", raw(func(e *event.Event) {
			at(time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC))(e)
		}), ReasonSegmentNotAllowed},
		{"raw path carries a kept value", "", raw(func(e *event.Event) {
			e.Op = "GET /promo/{keep:summer}"
			e.Req.Path = "/promo/{keep:summer}"
		}), ReasonValueNotAllowed},
		{"raw path carries a token", "", raw(func(e *event.Event) {
			e.Op = "GET /promo/{" + tokOrder1 + "}"
			e.Req.Path = "/promo/{" + tokOrder1 + "}"
		}), ReasonValueNotAllowed},

		// --- hosts, discovery, subject
		{"unlisted host is always fine", "", func() string {
			return mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:unlisted"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
		}, ReasonNone},
		{"host not listed, discovery and hosts.discovery off", "", func() string {
			ev := mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:api.evil.example"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
			return strings.Replace(ev, hash, hashStrict, 1)
		}, ReasonHostNotAllowed},
		{"ip pattern in strict mode", "", func() string {
			ev := mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:ip:private:8080"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
			return strings.Replace(ev, hash, hashStrict, 1)
		}, ReasonHostNotAllowed},
		{"host pattern with hosts.discovery auto", "", func() string {
			ev := mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:{*}.tracking.example:8443"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
			return strings.Replace(ev, hash, hashOff, 1)
		}, ReasonNone},
		{"ip pattern with hosts.discovery auto", "", func() string {
			ev := mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:ip:public"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
			return strings.Replace(ev, hash, hashOff, 1)
		}, ReasonNone},
		{"host label with six digits", "", func() string {
			ev := mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:t-3912345678.tenant.example"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
			return strings.Replace(ev, hash, hashOff, 1)
		}, ReasonHostNotAllowed},
		{"host label with a hex run during discovery", "", func() string {
			return mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:cdn-9f8e7d6c5b4a.assets.example"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
		}, ReasonHostNotAllowed},
		{"host listed in hosts_allow", "", func() string {
			ev := mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:partner.example"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
			return strings.Replace(ev, hash, hashOff, 1)
		}, ReasonNone},
		{"host seen during discovery", "", func() string {
			return mutate(t, rawPromo(hash), func(e *event.Event) {
				e.Dir = "outbound"
				e.Service = "host:api.new.example"
				e.Op = "GET /v1/{drop:str:l8}"
				e.Req.Path = "/v1/{drop:str:l8}"
			})
		}, ReasonNone},
		{"disc while discovery is off", "", func() string {
			ev := mutate(t, orderPost(hash), func(e *event.Event) {
				e.Disc = []event.DiscEntry{{Path: "req.body.note", Token: "tkd:AbC123"}}
			})
			return strings.Replace(ev, hash, hashOff, 1)
		}, ReasonDiscNotAllowed},
		{"disc while discovery is on", "", post(func(e *event.Event) {
			e.Disc = []event.DiscEntry{{Path: "req.body.note", Token: "tkd:AbC123"}}
		}), ReasonNone},
		{"disc after discovery expired", "", post(func(e *event.Event) {
			at(time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC))(e)
			e.Disc = []event.DiscEntry{{Path: "req.body.note", Token: "tkd:AbC123"}}
		}), ReasonDiscNotAllowed},

		// --- body shape and limits
		{"structured body with a content type that is not parsed", "", post(func(e *event.Event) { e.Req.CT = "text/plain" }), ReasonBodyShape},
		{"kept body token with a content type that is not parsed", "", post(func(e *event.Event) {
			e.Req.CT = "text/plain"
			e.Req.Body = &event.Value{Kind: event.String, S: "keep:hello"}
		}), ReasonBodyShape},
		{"drop:bytes for a text body", "", post(func(e *event.Event) {
			e.Req.CT = "text/plain"
			e.Req.Body = &event.Value{Kind: event.String, S: "drop:bytes:l128"}
		}), ReasonNone},
		{"array longer than max_array", "", post(func(e *event.Event) {
			el := make([]event.Value, 40)
			for i := range el {
				el[i] = event.Str("drop:int")
			}
			*member(e.Req.Body, "items") = event.Value{Kind: event.Array, A: el}
		}), ReasonLimits},
		{"nesting deeper than max_depth", "", post(func(e *event.Event) {
			v := event.Str("drop:int")
			for i := 0; i < 40; i++ {
				v = event.Arr(v)
			}
			*member(e.Req.Body, "items") = v
		}), ReasonLimits},

		// --- not an event
		{"unknown field", "", func() string {
			return strings.Replace(orderPost(hash), `{"dir":"inbound",`, `{"dir":"inbound","dirx":"hello",`, 1)
		}, ReasonSchema},
		{"whitespace between tokens", "", func() string { return strings.Replace(orderPost(hash), `"dir":"inbound"`, `"dir": "inbound"`, 1) }, ReasonNonCanonical},
		{"newline at the end", "", func() string { return orderPost(hash) + "\n" }, ReasonNonCanonical},
		{"keys out of order", "", func() string {
			return strings.Replace(orderPost(hash), `{"dir":"inbound","latency_ms":184,`, `{"latency_ms":184,"dir":"inbound",`, 1)
		}, ReasonNonCanonical},
		{"truncated JSON", "", func() string { return orderPost(hash)[:100] }, ReasonJSON},
		{"string outside the token grammar", "", func() string {
			return strings.Replace(orderPost(hash), `"drop:str:email"`, `"giulia.neri@example.com"`, 1)
		}, ReasonSchema},
		{"event larger than 512 KiB", "", func() string {
			return strings.Replace(orderPost(hash), `"drop:str:l8"`, `"keep:`+strings.Repeat("a", 600*1024)+`"`, 1)
		}, ReasonTooLarge},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := c.source
			if src == "" {
				src = testSource
			}
			rej := h.ingestAs(t, src, c.ev())
			if rej.Reason != c.want {
				t.Fatalf("reason = %s (%s), want %s", rej.Reason, rej.Detail, c.want)
			}
		})
	}
	// Rejected events are counted per reason and never stored.
	st := h.in.SourceStats(testSource)
	if st.RejectedTotal == 0 || st.Rejected["value_not_allowed"] == 0 || st.Rejected["non_canonical"] == 0 {
		t.Fatalf("counters: %+v", st)
	}
	accepted := int64(st.Accepted)
	if got := h.count(t); got != accepted {
		t.Fatalf("stored %d events, accepted %d", got, accepted)
	}
}

// A value that the policy does not allow is rejected, and the stored data
// never contains it (S9, G4).
func TestDisallowedValueNeverStored(t *testing.T) {
	h := newHarness(t)
	bad := mutate(t, orderPost(h.pol.Hash), func(e *event.Event) {
		*member(e.Req.Body, "note") = event.Str("keep:giulia.neri call me")
	})
	if rej := h.ingest(t, bad); rej.Reason != ReasonValueNotAllowed {
		t.Fatalf("got %s", rej.Reason)
	}
	if rej := h.ingest(t, orderPost(h.pol.Hash)); rej.Reason != ReasonNone {
		t.Fatalf("valid event rejected: %s %s", rej.Reason, rej.Detail)
	}
	h.idle(t)
	n := 0
	err := h.in.Store().Scan(t.Context(), Query{}, func(se *StoredEvent) error {
		n++
		if strings.Contains(string(se.Event.Canonical()), "giulia") {
			t.Fatal("rejected value reached the store")
		}
		return nil
	})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

// The unknown source and the revoked source are refused before any event is
// looked at.
func TestUnknownAndRevokedSources(t *testing.T) {
	h := newHarness(t)
	if _, err := h.in.IngestEvent(t.Context(), "src-nobody", []byte("{}")); err != ErrUnknownSource {
		t.Fatalf("unknown source: %v", err)
	}
	h.sources.Revoke(testSource)
	if _, err := h.in.IngestEvent(t.Context(), testSource, []byte("{}")); err != ErrUnknownSource {
		t.Fatalf("revoked source: %v", err)
	}
}

// Precedence of docs/spec/sanitizer.md 5.0 as seen by the intake.
func TestRulePrecedenceAndContainers(t *testing.T) {
	const body = `{
 "format":"tt.policy.body/v1","policy_id":"p-prec","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 "global":{
  "request":{"body":[
    {"path":"$.items","action":{"action":"drop"}},
    {"path":"$.card","action":{"action":"drop"}},
    {"path":"$.card.holder","action":{"action":"keep"}},
    {"path":"$.mode","action":{"action":"keep"}},
    {"path":"$.tag","action":{"action":"keep"}},
    {"path":"$.*","action":{"action":"drop"}}]},
  "response":{"body":[{"path":"$.v","action":{"action":"keep"}}]}
 },
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},
   "request":{"body":[{"path":"$.mode","action":{"action":"drop"}},{"path":"$.tag","action":{"action":"hmac","domain":"tag"}}]},
   "ops":[{"op":"POST /x",
     "request":{"body":[{"path":"$.items[*].orderId","action":{"action":"hmac","domain":"order"}},
                         {"path":"$.mode","action":{"action":"keep"}}]}}]}]
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
		s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-prec","version":1`, 1)
		return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
	}
	cases := []struct {
		name string
		body string
		want Reason
	}{
		// Operation rule (group 1) reaches into $.items, so the global drop of
		// the container is ignored and orderId is traversed.
		{"op rule reaches a descendant of a dropped container", `{"items":[{"orderId":"` + tokOrder1 + `"}]}`, ReasonNone},
		{"other fields of that container stay dropped", `{"items":[{"orderId":"drop:str:l32","sku":"keep:A1"}]}`, ReasonValueNotAllowed},
		// Operation keep (group 1) beats the service drop (group 3).
		{"operation rule beats service rule", `{"mode":"keep:fast"}`, ReasonNone},
		// Service hmac (group 3) beats the global keep (group 4).
		{"service rule beats global rule", `{"tag":"keep:red"}`, ReasonValueNotAllowed},
		{"service hmac accepted", `{"tag":"` + tokOrder2 + `"}`, ReasonNone},
		// $.card is dropped globally and the only deeper rule ($.card.holder)
		// is in the same group, so it can reach a descendant: not collapsed.
		{"same-group descendant rule keeps the container open", `{"card":{"holder":"keep:G NERI"}}`, ReasonNone},
		// $.* drop vs $.mode keep in the same group: more .name steps win.
		{"more specific global rule wins", `{"mode":"keep:fast"}`, ReasonNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rej := h.ingest(t, mk(c.body)); rej.Reason != c.want {
				t.Fatalf("got %s (%s), want %s", rej.Reason, rej.Detail, c.want)
			}
		})
	}
}

// A drop on a container that no rule of the same or a stronger group can
// reach collapses it: nothing below may be kept, even if a weaker group has
// a keep rule for a descendant.
func TestContainerCollapsedByDrop(t *testing.T) {
	const body = `{
 "format":"tt.policy.body/v1","policy_id":"p-coll","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 "global":{"request":{"body":[{"path":"$.user.name","action":{"action":"keep"}},{"path":"$.ok","action":{"action":"keep"}}]}},
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},
   "request":{"body":[{"path":"$.user","action":{"action":"drop"}}]},"ops":[]}]
}`
	pol, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.policies.Add(pol)
	mk2 := func(reqBody string) string {
		req := `"req":{"body":` + reqBody + `,"ct":"application/json","path":"/","size":"l32"},"resp":{"size":"l8"},`
		s := eventJSON(pol.Hash, "inbound", "shop-api", "GET /", "raw", req)
		s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-coll","version":1`, 1)
		return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
	}
	if rej := h.ingest(t, mk2(`{"ok":"keep:yes","user":"drop:obj:l8"}`)); rej.Reason != ReasonNone {
		t.Fatalf("collapsed form rejected: %s %s", rej.Reason, rej.Detail)
	}
	if rej := h.ingest(t, mk2(`{"user":{"name":"keep:Giulia"}}`)); rej.Reason != ReasonValueNotAllowed {
		t.Fatalf("a drop at the service level must collapse $.user: got %s", rej.Reason)
	}
}

// Form bodies use names only: $.name and $.* rules apply to every value.
func TestFormBody(t *testing.T) {
	const body = `{
 "format":"tt.policy.body/v1","policy_id":"p-form","version":1,"issued_seq":1,
 "created_at":"2026-10-19T08:00:00Z","not_after":"2026-11-18T08:00:00Z",
 "targets":{"groups":["prod"]},
 "hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},
 "sampling":{"rate_bp":0,"trust_baggage":false,"propagate_to":[]},
 "segments":{"auto_words":false,"allow":[],"hosts_allow":[]},
 "limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},
 "global":{"request":{"body":[{"path":"$.channel","action":{"action":"keep"}},{"path":"$.order.id","action":{"action":"keep"}}]}},
 "services":[{"name":"shop-api","match":{"inbound":true,"internal":false},"ops":[]}]
}`
	pol, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.policies.Add(pol)
	mk := func(reqBody string) string {
		req := `"req":{"body":` + reqBody + `,"ct":"application/x-www-form-urlencoded","path":"/","size":"l32"},"resp":{"size":"l8"},`
		s := eventJSON(pol.Hash, "inbound", "shop-api", "POST /", "raw", req)
		s = strings.Replace(s, `"id":"p-shop","version":7`, `"id":"p-form","version":1`, 1)
		return strings.Replace(s, `"ts":`, `"status":200,"ts":`, 1)
	}
	for _, c := range []struct {
		name, body string
		want       Reason
	}{
		{"kept form value with a rule", `{"channel":["keep:web","keep:app"]}`, ReasonNone},
		{"form value without a rule", `{"coupon":["keep:SUMMER"]}`, ReasonValueNotAllowed},
		{"deep path rules never apply to forms", `{"order":["keep:1"]}`, ReasonValueNotAllowed},
		{"drop forms", `{"coupon":["drop:str:l8"]}`, ReasonNone},
		{"form body must be a name map", `["drop:int"]`, ReasonBodyShape},
		{"form values are arrays of tokens", `{"channel":"keep:web"}`, ReasonBodyShape},
	} {
		t.Run(c.name, func(t *testing.T) {
			if rej := h.ingest(t, mk(c.body)); rej.Reason != c.want {
				t.Fatalf("got %s (%s) want %s", rej.Reason, rej.Detail, c.want)
			}
		})
	}
}
