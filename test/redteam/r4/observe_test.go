package r4_rt

// Red team round 4, area 1: the observe phase (policy.md 7, keyguard.md
// 3.2). Property: keyguard signs without approvals only changes that cannot
// make any value leave in clear. Each case compiles a previous and a next
// policy, runs the real sanitizer on the same exchange and checks that when
// the next policy lets a value out that the previous one did not,
// policy.ClassifyValues (the function keyguard uses) says the change opens
// values.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// secretValue is the "real" value of the exchanges: it must never appear in
// a sanitizer output unless a person approved it.
const secretValue = "giulia.neri@example.com"

var (
	compiledAt = time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	srcNow     = compiledAt.Add(time.Hour)
)

func compileAuthor(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(doc))
	d.UseNumber()
	var g any
	if err := d.Decode(&g); err != nil {
		t.Fatalf("author json: %v\n%s", err, doc)
	}
	a, err := policy.AuthorFromGeneric(g)
	if err != nil {
		t.Fatalf("author: %v\n%s", err, doc)
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: compiledAt, Groups: []string{"shop"}})
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, doc)
	}
	return p
}

// pol builds an author policy with the given global and services blocks.
func pol(t *testing.T, global, services string) *policy.Policy {
	t.Helper()
	doc := `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1}`
	if global != "" {
		doc += `,"global":` + global
	}
	if services != "" {
		doc += `,"services":` + services
	}
	return compileAuthor(t, doc+"}")
}

func sanitize(t *testing.T, p *policy.Policy, ex *sanitizer.Exchange) string {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	k, err := sanitizer.NewKey("k1", secret)
	if err != nil {
		t.Fatal(err)
	}
	e, err := sanitizer.NewEngineWithKey(p, k)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Sanitize(ex, srcNow, sanitizer.ByRandom)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	b, err := out.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func leaks(t *testing.T, p *policy.Policy, ex *sanitizer.Exchange, value string) bool {
	t.Helper()
	return strings.Contains(sanitize(t, p, ex), value)
}

// assertObserveProperty: if next lets value out on ex and prev did not,
// the change must open values.
func assertObserveProperty(t *testing.T, prev, next *policy.Policy, ex *sanitizer.Exchange, value string) {
	t.Helper()
	if leaks(t, prev, ex, value) {
		t.Fatalf("setup: the previous policy already lets the value out:\n%s", sanitize(t, prev, ex))
	}
	if !leaks(t, next, ex, value) {
		t.Fatalf("setup: the next policy does not let the value out:\n%s", sanitize(t, next, ex))
	}
	c := policy.ClassifyValues(prev, next)
	if !c.OpensValues {
		t.Fatalf("the change lets %q out in clear but ClassifyValues says it opens no value (keyguard would sign it without approvals)", value)
	}
	t.Logf("reasons: %+v", c.Reasons)
}

func jsonResp(ex *sanitizer.Exchange, respBody string) *sanitizer.Exchange {
	ex.Status = 200
	ex.RespHeaders = []sanitizer.Header{{Name: "content-type", Value: []byte("application/json")}}
	ex.RespBody = []byte(respBody)
	return ex
}

func outbound(urlBase, path, respBody string) *sanitizer.Exchange {
	return jsonResp(&sanitizer.Exchange{Dir: sanitizer.Outbound, URLBase: urlBase, Method: "GET", RawPath: []byte(path)}, respBody)
}

func inbound(method, path, respBody string) *sanitizer.Exchange {
	return jsonResp(&sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: method, RawPath: []byte(path)}, respBody)
}

var emailBody = `{"email":"` + secretValue + `"}`

// Hypothesis (a): routing traffic onto keep rules already approved by
// declaring, removing or re-matching services and operations without
// rules.
func TestR4ObserveRoutingOntoKeepRules(t *testing.T) {
	t.Run("service removed", func(t *testing.T) {
		// carrier-v2 (no rules) shadows carrier (keep) on /v2.
		prev := pol(t, "", `{"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"keep"}},
			"carrier-v2":{"match":{"base":"https://api.carrier.example/v2"}}}`)
		next := pol(t, "", `{"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"keep"}}}`)
		assertObserveProperty(t, prev, next, outbound("https://api.carrier.example", "/v2/track", emailBody), secretValue)
	})
	t.Run("service added", func(t *testing.T) {
		// The service drop overrides a global keep; a new service without
		// rules takes the traffic away from it.
		prev := pol(t, `{"response":{"$.email":"keep"}}`, `{"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"drop"}}}`)
		next := pol(t, `{"response":{"$.email":"keep"}}`, `{"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"drop"}},
			"carrier-v2":{"match":{"base":"https://api.carrier.example/v2"}}}`)
		assertObserveProperty(t, prev, next, outbound("https://api.carrier.example", "/v2/track", emailBody), secretValue)
	})
	t.Run("match changed on a service without values", func(t *testing.T) {
		prev := pol(t, `{"response":{"$.email":"keep"}}`, `{"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"drop"}}}`)
		next := pol(t, `{"response":{"$.email":"keep"}}`, `{"carrier":{"match":{"base":"https://api.other.example"},"response":{"$.email":"drop"}}}`)
		assertObserveProperty(t, prev, next, outbound("https://api.carrier.example", "/track", emailBody), secretValue)
	})
	t.Run("operation removed", func(t *testing.T) {
		// GET /orders/export (no rules) wins over GET /orders/{id} (keep).
		prev := pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{
			"GET /orders/export":{},
			"GET /orders/{id}":{"response":{"$.email":"keep"}}}}}`)
		next := pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{
			"GET /orders/{id}":{"response":{"$.email":"keep"}}}}}`)
		assertObserveProperty(t, prev, next, inbound("GET", "/orders/export", emailBody), secretValue)
	})
	t.Run("operation added", func(t *testing.T) {
		// GET /orders/{id} drops the email that the service keeps; a new,
		// more literal operation without rules takes /orders/export away
		// from it.
		prev := pol(t, "", `{"shop-api":{"match":{"inbound":true},"response":{"$.email":"keep"},"ops":{
			"GET /orders/{id}":{"response":{"$.email":"drop"}}}}}`)
		next := pol(t, "", `{"shop-api":{"match":{"inbound":true},"response":{"$.email":"keep"},"ops":{
			"GET /orders/{id}":{"response":{"$.email":"drop"}},
			"GET /orders/export":{}}}}`)
		assertObserveProperty(t, prev, next, inbound("GET", "/orders/export", emailBody), secretValue)
	})
}

// Hypothesis (b): container drop precedence (sanitizer.md 5.0).
func TestR4ObserveContainerDropPrecedence(t *testing.T) {
	body := `{"profile":{"email":"` + secretValue + `","phone":"+39 333 1234567"}}`
	ex := func() *sanitizer.Exchange { return inbound("GET", "/me", body) }
	global := `{"response":{"$.profile.email":"keep"}}`
	t.Run("container drop to hmac", func(t *testing.T) {
		prev := pol(t, global, `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}}}`)
		next := pol(t, global, `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"hmac(profile)"}}}}}`)
		assertObserveProperty(t, prev, next, ex(), secretValue)
	})
	t.Run("hmac rule reaching a descendant added", func(t *testing.T) {
		prev := pol(t, global, `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}}}`)
		next := pol(t, global, `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop","$.profile.phone":"hmac(phone)"}}}}}`)
		assertObserveProperty(t, prev, next, ex(), secretValue)
	})
	t.Run("drop rule reaching a descendant added in a stronger group", func(t *testing.T) {
		prev := pol(t, global, `{"shop-api":{"match":{"inbound":true},"response":{"$.profile":"drop"},"ops":{"GET /me":{}}}}`)
		next := pol(t, global, `{"shop-api":{"match":{"inbound":true},"response":{"$.profile":"drop"},"ops":{"GET /me":{"response":{"$.profile.phone":"drop"}}}}}`)
		assertObserveProperty(t, prev, next, ex(), secretValue)
	})
}

// With values, declarations that take traffic from no other service or
// operation stay observe-safe (the "Gemella" host twin declares a new
// external host while the policy keeps values).
func TestR4ObserveNonCompetingDeclarationsWithValues(t *testing.T) {
	svcs := `"carrier":{"match":{"base":"https://api.carrier.example"},"response":{"$.email":"keep"}},
		"shop-api":{"match":{"inbound":true},"ops":{"GET /orders/{id}":{"response":{"$.status":"keep"}}}}`
	prev := pol(t, "", "{"+svcs+"}")
	for name, next := range map[string]*policy.Policy{
		"other host":      pol(t, "", "{"+svcs+`,"payments":{"match":{"base":"https://api.payments.example"}}}`),
		"other port":      pol(t, "", "{"+svcs+`,"carrier-admin":{"match":{"base":"https://api.carrier.example:8443/v2"}}}`),
		"other method op": pol(t, "", "{"+strings.Replace(svcs, `"GET /orders/{id}":{"response":{"$.status":"keep"}}`, `"GET /orders/{id}":{"response":{"$.status":"keep"}},"POST /orders":{}`, 1)+"}"),
		"other length op": pol(t, "", "{"+strings.Replace(svcs, `"GET /orders/{id}":{"response":{"$.status":"keep"}}`, `"GET /orders/{id}":{"response":{"$.status":"keep"}},"GET /orders/{id}/items":{}`, 1)+"}"),
	} {
		if c := policy.ClassifyValues(prev, next); c.OpensValues {
			t.Errorf("%s: a declaration that takes no traffic from rules must stay observe-safe, got %+v", name, c.Reasons)
		}
	}
	// The same declarations next to a competitor open values.
	next := pol(t, "", "{"+svcs+`,"carrier-v2":{"match":{"base":"https://api.carrier.example/v2"}}}`)
	if c := policy.ClassifyValues(prev, next); !c.OpensValues {
		t.Error("a service under the base of a service with values must open values")
	}
}

// The fix must not touch the observe phase without values: declaring
// services and operations, hmac on containers and new hmac rules stay
// observe-safe when no rule lets a value out.
func TestR4ObserveWithoutValuesUnchanged(t *testing.T) {
	prev := pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}}}`)
	for name, next := range map[string]*policy.Policy{
		"service added":     pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}}}},"carrier":{"match":{"base":"https://api.carrier.example"}}}`),
		"service removed":   pol(t, "", ""),
		"op added":          pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}}}}`),
		"hmac on container": pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"hmac(profile)"}}}}}`),
		"descendant rule":   pol(t, "", `{"shop-api":{"match":{"inbound":true},"ops":{"GET /me":{"response":{"$.profile":"drop","$.profile.id":"hmac(user)"}}}}}`),
	} {
		if c := policy.ClassifyValues(prev, next); c.OpensValues {
			t.Errorf("%s: a policy without values must stay observe-safe, got %+v", name, c.Reasons)
		}
	}
}
