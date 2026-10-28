package policy

import (
	"strings"
	"testing"
)

// obsPolicy compiles an author policy made of the base (default drop, the
// onboarding windows, one inbound service) plus extra top-level members.
func obsPolicy(t *testing.T, groups []string, extra string) *Policy {
	t.Helper()
	doc := `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},` +
		`"segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T10:00:00Z"},` +
		`"discovery":{"enabled":true,"expires_at":"2026-10-22T10:00:00Z"}`
	if extra != "" {
		doc += "," + extra
	}
	if !strings.Contains(extra, `"services"`) {
		doc += `,"services":{"shop-api":{"match":{"inbound":true}}}`
	}
	doc += "}"
	if !strings.Contains(extra, `"sampling"`) {
		doc = strings.Replace(doc, `"default":"drop",`, `"default":"drop","sampling":{"rate":0.05},`, 1)
	}
	m := meta(1, 1)
	m.Groups = groups
	_, p, err := Compile(author(t, doc), m)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, doc)
	}
	return p
}

const obsOps = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
 "POST /orders":{"response":{"$.id":"hmac(order)","$.items[*].sku":"drop"}},
 "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"},"headers":{"x-tenant":"hmac(tenant)"}}}}}}`

func reasons(c ValueClass) []string {
	out := make([]string, 0, len(c.Reasons))
	for _, r := range c.Reasons {
		out = append(out, r.Code+"@"+r.Where)
	}
	return out
}

func TestObserveSafeStarterAndAuto(t *testing.T) {
	g := []string{"shop"}
	starter := obsPolicy(t, g, "")
	if c := ClassifyValues(nil, starter); c.OpensValues {
		t.Fatalf("the starter policy must be observe-safe: %v", reasons(c))
	}
	if !ObserveSafe(starter) {
		t.Fatal("ObserveSafe(starter) = false")
	}
	auto := obsPolicy(t, g, `"identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},`+obsOps)
	if c := ClassifyValues(starter, auto); c.OpensValues {
		t.Fatalf("hmac on ids and the JWT subject must be observe-safe: %v", reasons(c))
	}
	xuser := obsPolicy(t, g, `"identity":{"subject":{"from":"header","name":"x-user-id"}}`)
	if c := ClassifyValues(starter, xuser); c.OpensValues {
		t.Fatalf("a header that is not a credential is observe-safe: %v", reasons(c))
	}
	// Going back to the starter (dropping the hmac rules) closes.
	if c := ClassifyValues(auto, starter); c.OpensValues {
		t.Fatalf("removing hmac rules without values must be safe: %v", reasons(c))
	}
	// A new epoch, a new kid and more sampling only change tokens and volume.
	more := obsPolicy(t, g, `"sampling":{"rate":0.5},`+obsOps)
	if c := ClassifyValues(auto, more); c.OpensValues {
		t.Fatalf("more sampling without values must be safe: %v", reasons(c))
	}
}

func TestClassifyValuesOpens(t *testing.T) {
	g := []string{"shop"}
	base := obsPolicy(t, g, obsOps)
	cases := []struct {
		name, extra string
		want        string
	}{
		{"keep", `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.status":"keep"}}}}}`,
			"keep@services.shop-api.ops.POST /orders.response.body.$.status"},
		{"hmac to keep", `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.id":"keep"}}}}}`,
			"keep@services.shop-api.ops.POST /orders.response.body.$.id"},
		{"bucket", `"services":{"shop-api":{"match":{"inbound":true},"response":{"$.total":"bucket(num, [0, 50, 100])"}}}`,
			"bucket@services.shop-api.response.body.$.total"},
		{"identity cookie", `"identity":{"subject":{"from":"cookie","name":"sid"}}`, "identity@identity.subject"},
		{"identity bearer without claim", `"identity":{"subject":{"from":"header","name":"authorization"}}`, "identity@identity.subject"},
		{"identity credential-like header", `"identity":{"subject":{"from":"header","name":"x-session-id"}}`, "identity@identity.subject"},
		{"allow", `"segments":{"allow":["v1"]}`, "literals@segments.allow[v1]"},
		{"hosts allow", `"segments":{"hosts_allow":["api.carrier.example"]}`, "literals@segments.hosts_allow[api.carrier.example]"},
		{"propagate", `"sampling":{"rate":0.05,"propagate_to":["billing.internal"]}`, "propagate_to@sampling.propagate_to[billing.internal]"},
		{"global keep", `"global":{"request":{"headers":{"content-type":"keep"}}}`, "keep@global.request.headers.content-type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := obsPolicy(t, g, tc.extra)
			c := ClassifyValues(base, next)
			if !c.OpensValues || !contains(reasons(c), tc.want) {
				t.Fatalf("want %s, got %v", tc.want, reasons(c))
			}
		})
	}
	// Strict hosts mode back to auto.
	strict := obsPolicy(t, g, `"hosts":{"discovery":"off"}`)
	if c := ClassifyValues(strict, base); !contains(reasons(c), "hosts_discovery@hosts.discovery") {
		t.Fatalf("off -> auto: %v", reasons(c))
	}
	if c := ClassifyValues(base, strict); c.OpensValues {
		t.Fatalf("auto -> off closes: %v", reasons(c))
	}
}

func TestClassifyValuesWithKeptValues(t *testing.T) {
	g := []string{"shop"}
	vals := `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.status":"keep","$.id":"hmac(order)","$.total":"bucket(num, [0, 50, 100])"}}}}}`
	with := obsPolicy(t, g, vals)
	// Unchanged: nothing opens.
	if c := ClassifyValues(with, obsPolicy(t, g, vals)); c.OpensValues {
		t.Fatalf("same policy: %v", reasons(c))
	}
	// keep -> hmac, bucket coarser, keep removed: closing.
	closing := obsPolicy(t, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.id":"hmac(order)","$.total":"bucket(num, [0, 100])"}}}}}`)
	if c := ClassifyValues(with, closing); c.OpensValues {
		t.Fatalf("closing changes: %v", reasons(c))
	}
	// Finer bounds open.
	finer := obsPolicy(t, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.status":"keep","$.id":"hmac(order)","$.total":"bucket(num, [0, 25, 50, 100])"}}}}}`)
	if c := ClassifyValues(with, finer); !contains(reasons(c), "bucket@services.shop-api.ops.POST /orders.response.body.$.total") {
		t.Fatalf("finer bounds: %v", reasons(c))
	}
	// More sampling with values kept opens; removing the hmac rule too.
	more := obsPolicy(t, g, `"sampling":{"rate":0.5},`+vals)
	if c := ClassifyValues(with, more); !contains(reasons(c), "volume_with_values@sampling.rate") {
		t.Fatalf("sampling: %v", reasons(c))
	}
	noHmac := obsPolicy(t, g, `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.status":"keep","$.total":"bucket(num, [0, 50, 100])"}}}}}`)
	if c := ClassifyValues(with, noHmac); !contains(reasons(c), "rule_removed_with_values@services.shop-api.ops.POST /orders.response.body.$.id") {
		t.Fatalf("hmac removed: %v", reasons(c))
	}
	// A group added to a policy that keeps values opens them for it.
	two := obsPolicy(t, []string{"shop", "edge"}, vals)
	if c := ClassifyValues(with, two); !contains(reasons(c), "group_with_values@targets.groups[edge]") {
		t.Fatalf("group: %v", reasons(c))
	}
	// Without values, a group added is observe-safe.
	if c := ClassifyValues(obsPolicy(t, g, obsOps), obsPolicy(t, []string{"shop", "edge"}, obsOps)); c.OpensValues {
		t.Fatalf("group without values: %v", reasons(c))
	}
}

func TestIdentityObserveSafe(t *testing.T) {
	for _, tc := range []struct {
		s    *Subject
		want bool
	}{
		{nil, true},
		// Any claim of the bearer JWT: the claim is an identifier.
		{&Subject{From: "header", Name: "authorization", JWTClaim: "sub"}, true},
		{&Subject{From: "header", Name: "Authorization", JWTClaim: "member_no"}, true},
		{&Subject{From: "header", Name: "authorization"}, false},
		// Any header that is not a credential, whatever its name or case.
		{&Subject{From: "header", Name: "x-user-id"}, true},
		{&Subject{From: "header", Name: "x-user-id", JWTClaim: "sub"}, true},
		{&Subject{From: "header", Name: "x-kunden-nr"}, true},
		{&Subject{From: "header", Name: "X-Codice-Utente"}, true},
		{&Subject{From: "header", Name: "x-qz-7"}, true},
		{&Subject{From: "header", Name: "personname"}, true},
		// Cookies carry session secrets.
		{&Subject{From: "cookie", Name: "uid"}, false},
		{&Subject{From: "cookie", Name: "uid", JWTClaim: "sub"}, false},
		// Credential headers never; credential-like names only with a claim.
		{&Subject{From: "header", Name: "cookie"}, false},
		{&Subject{From: "header", Name: "cookie", JWTClaim: "sub"}, false},
		{&Subject{From: "header", Name: "set-cookie"}, false},
		{&Subject{From: "header", Name: "proxy-authorization"}, false},
		{&Subject{From: "header", Name: "proxy-authorization", JWTClaim: "sub"}, false},
		{&Subject{From: "header", Name: "x-api-key"}, false},
		{&Subject{From: "header", Name: "x-api-key", JWTClaim: "sub"}, false},
		{&Subject{From: "header", Name: "x-session"}, false},
		{&Subject{From: "header", Name: "x-auth-token"}, false},
		{&Subject{From: "header", Name: "x-id-token", JWTClaim: "sub"}, true},
		{&Subject{From: "header", Name: "x-csrf-token"}, false},
		{&Subject{From: "header", Name: "x-signature"}, false},
		{&Subject{From: "header", Name: "x-client-secret"}, false},
		{&Subject{From: "header", Name: "x-password"}, false},
		{&Subject{From: "header", Name: "x-tenant-key"}, false},
		{&Subject{From: "query", Name: "user"}, false},
	} {
		if got := IdentityObserveSafe(tc.s); got != tc.want {
			t.Errorf("IdentityObserveSafe(%+v) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestCredentialLikeName(t *testing.T) {
	for _, n := range []string{"authorization", "cookie", "x-api-key", "apikey", "x-access-token", "accesstoken", "x-session-id", "sessionid",
		"x-xsrf-token", "x-hub-signature", "x-sig", "sid", "x-otp", "x-pin", "x-client-secret", "password", "x-auth", "x-jwt", "x-key"} {
		if !CredentialLikeName(n) {
			t.Errorf("%q looks like a credential", n)
		}
	}
	for _, n := range []string{"x-user-id", "personid", "customer-id", "x-member", "x-tenant", "x-device-id", "x-utente", "monkey-id", "x-keyboard-layout"} {
		if CredentialLikeName(n) {
			t.Errorf("%q does not look like a credential", n)
		}
	}
}

func TestClassifyIdentityAnyHeader(t *testing.T) {
	g := []string{"shop"}
	starter := obsPolicy(t, g, "")
	// Any header name the application uses: the value leaves only as a token.
	for _, name := range []string{"x-user-id", "x-kunden-nr", "x-codice-utente", "x-qz-7", "personid", "x-member"} {
		p := obsPolicy(t, g, `"identity":{"subject":{"from":"header","name":"`+name+`"}}`)
		if c := ClassifyValues(starter, p); c.OpensValues {
			t.Errorf("%s is observe-safe: %v", name, reasons(c))
		}
	}
	// Any claim of the bearer JWT.
	jwt := obsPolicy(t, g, `"identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"member_no"}}`)
	if c := ClassifyValues(starter, jwt); c.OpensValues {
		t.Errorf("a JWT claim is observe-safe: %v", reasons(c))
	}
	// Credentials and cookies open values.
	for _, sub := range []string{
		`{"from":"header","name":"x-session"}`,
		`{"from":"header","name":"authorization"}`,
		`{"from":"header","name":"x-api-key"}`,
		`{"from":"header","name":"proxy-authorization","jwt_claim":"sub"}`,
		`{"from":"cookie","name":"uid"}`,
	} {
		p := obsPolicy(t, g, `"identity":{"subject":`+sub+`}`)
		if c := ClassifyValues(starter, p); !c.OpensValues || !contains(reasons(c), "identity@identity.subject") {
			t.Errorf("%s opens values: %v", sub, reasons(c))
		}
	}
	// Changing from one safe header to another stays safe.
	a := obsPolicy(t, g, `"identity":{"subject":{"from":"header","name":"x-user-id"}}`)
	b := obsPolicy(t, g, `"identity":{"subject":{"from":"header","name":"x-member"}}`)
	if c := ClassifyValues(a, b); c.OpensValues {
		t.Errorf("safe to safe: %v", reasons(c))
	}
}
