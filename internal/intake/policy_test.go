package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestParsePolicy(t *testing.T) {
	p := mustPolicy(t, discoveryOn)
	sum := sha256.Sum256([]byte(strings.Replace(policyTemplate, "DISCOVERY", discoveryOn, 1)))
	if p.Hash != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("hash %s", p.Hash)
	}
	if p.ID != "p-shop" || p.Version != 7 || p.IssuedSeq != 31 || p.Epoch != "2026-10" || p.HMACKID != "k1" || !p.HasSubject {
		t.Fatalf("%+v", p)
	}
	if !p.TargetsGroup("prod") || p.TargetsGroup("staging") {
		t.Fatal("groups")
	}
	if !p.AcceptsKID("k1") || !p.AcceptsKID("k0") || p.AcceptsKID("k2") {
		t.Fatal("kids")
	}
	if got := strings.Join(p.ServiceNames(), ","); got != "shipping-ext,shop-api" {
		t.Fatalf("services %s", got)
	}
	// bucket(num, [0, 50, 100, 250]) accepts exactly these tokens.
	a := p.services["shop-api"].ops["POST /orders"].resp.body.named["total"].rules[0].act
	want := []string{"num:<0", "num:0-50", "num:50-100", "num:100-250", "num:>=250"}
	if len(a.tokens) != len(want) {
		t.Fatalf("%v", a.tokens)
	}
	for _, w := range want {
		if _, ok := a.tokens[w]; !ok {
			t.Fatalf("missing %s in %v", w, a.tokens)
		}
	}
	// Limits default when the document omits them.
	if p.Limits != (Limits{MaxBodyBytes: 1048576, MaxDepth: 32, MaxArray: 32, MaxKeys: 256, KeepMaxBytes: 64}) {
		t.Fatalf("%+v", p.Limits)
	}
}

func TestBucketBoundsAreCanonical(t *testing.T) {
	body := `{"format":"tt.policy.body/v1","policy_id":"p-b","version":1,"hmac":{"kid":"k1","epoch":"e"},
	 "global":{"response":{"body":[{"path":"$.v","action":{"action":"bucket","kind":"num","bounds":[-1.50,0,1e21,0.0000001]}}]}},"services":[]}`
	p, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	a := p.global.resp.body.named["v"].rules[0].act
	for _, w := range []string{"num:<-1.5", "num:-1.5-0", "num:0-1e+21", "num:1e+21-1e-7", "num:>=1e-7"} {
		if _, ok := a.tokens[w]; !ok {
			t.Errorf("missing %s in %v", w, a.tokens)
		}
	}
}

func TestParsePolicyRejectsGarbage(t *testing.T) {
	for name, body := range map[string]string{
		"not json":     `{`,
		"wrong format": `{"format":"tt.policy/v1","policy_id":"p","hmac":{"kid":"k1","epoch":"e"}}`,
		"no policy id": `{"format":"tt.policy.body/v1","hmac":{"kid":"k1","epoch":"e"}}`,
		"no kid":       `{"format":"tt.policy.body/v1","policy_id":"p","hmac":{"epoch":"e"}}`,
		"bad action":   `{"format":"tt.policy.body/v1","policy_id":"p","hmac":{"kid":"k1","epoch":"e"},"global":{"request":{"headers":{"x":{"action":"leak"}}}}}`,
		"bad path":     `{"format":"tt.policy.body/v1","policy_id":"p","hmac":{"kid":"k1","epoch":"e"},"global":{"request":{"body":[{"path":"a.b","action":{"action":"keep"}}]}}}`,
		"bad op":       `{"format":"tt.policy.body/v1","policy_id":"p","hmac":{"kid":"k1","epoch":"e"},"services":[{"name":"s","match":{"inbound":true},"ops":[{"op":"get /x"}]}]}`,
		"bad time":     `{"format":"tt.policy.body/v1","policy_id":"p","hmac":{"kid":"k1","epoch":"e"},"not_after":"tomorrow"}`,
		"bad unit":     `{"format":"tt.policy.body/v1","policy_id":"p","hmac":{"kid":"k1","epoch":"e"},"global":{"request":{"headers":{"x":{"action":"bucket","kind":"time","unit":"week"}}}}}`,
	} {
		if _, err := ParsePolicy([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPolicyWindows(t *testing.T) {
	p := mustPolicy(t, discoveryOn)
	skew := 5 * time.Minute
	in := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	out := time.Date(2026, 10, 22, 8, 10, 0, 0, time.UTC)
	if !p.AutoWordsActive(in, skew) || p.AutoWordsActive(out, skew) {
		t.Fatal("auto words window")
	}
	if !p.DiscoveryActive(in, skew) || p.DiscoveryActive(out, skew) {
		t.Fatal("discovery window")
	}
	// The expiry is capped at created_at + 7 days even if the field says more.
	long := strings.Replace(policyTemplate, "DISCOVERY", `"discovery":{"enabled":true,"expires_at":"2027-01-01T00:00:00Z"},`, 1)
	q, err := ParsePolicy([]byte(long))
	if err != nil {
		t.Fatal(err)
	}
	if q.DiscoveryActive(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC), skew) {
		t.Fatal("discovery active beyond 7 days from the creation of the policy")
	}
	off := mustPolicy(t, discoveryOff)
	if off.DiscoveryActive(in, skew) {
		t.Fatal("disabled discovery reported active")
	}
}

func TestAutoWord(t *testing.T) {
	for _, s := range []string{"orders", "order-items", "order_items", "a-b_c", "v1", "v999", "a", "x"} {
		if !autoWord(s) {
			t.Errorf("%q should be an automatic word", s)
		}
	}
	for _, s := range []string{"", "v1000", "V1", "Orders", "order--items", "-orders", "orders-", "ord3rs", "v1a", strings.Repeat("a", 41), "a b", "é"} {
		if autoWord(s) {
			t.Errorf("%q should not be an automatic word", s)
		}
	}
	if !autoWord(strings.Repeat("a", 40)) {
		t.Error("40 bytes are allowed")
	}
}
