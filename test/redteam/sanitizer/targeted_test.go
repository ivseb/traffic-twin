package sanitizer_rt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

func author(extra string) string {
	return `{"format":"tt.policy/v1","policy_id":"p-rt","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1}` + extra + `}`
}

// keep_max_bytes must bound the kept value in bytes, also with multi-byte
// UTF-8 and escapes (sanitizer.md §5.3).
func TestRT_Sanitizer_Holds_KeepMaxBytes(t *testing.T) {
	e := engine(t, author(`,"services":{"shop-api":{"match":{"inbound":true},"request":{"body":{"$.note":"keep"}}}}`))
	long := strings.Repeat("é", 33) // 66 bytes, 33 runes
	esc := strings.Repeat(`q`, 65)  // 65 bytes once decoded
	for _, body := range []string{`{"note":"` + long + `"}`, `{"note":"` + esc + `"}`} {
		ex := in("/orders")
		ex.Method = "POST"
		ex.ReqHeaders = hdr("content-type", "application/json")
		ex.ReqBody = []byte(body)
		s := out(t, e, ex)
		if strings.Contains(s, "keep:") {
			t.Errorf("kept value over keep_max_bytes: %s", s)
		}
	}
}

// The raw subject (bearer token or JWT claim) must never appear in the
// output (sanitizer.md §11).
func TestRT_Sanitizer_Holds_SubjectNeverRaw(t *testing.T) {
	jwt := func(payload string) string {
		return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}
	cases := []struct{ pol, val string }{
		{`,"identity":{"subject":{"from":"header","name":"x-user"}}`, mWord},
		{`,"identity":{"subject":{"from":"header","name":"x-user","jwt_claim":"sub"}}`, "Bearer " + jwt(`{"sub":"`+mWord+`"}`)},
		{`,"identity":{"subject":{"from":"header","name":"x-user","jwt_claim":"sub"}}`, "Bearer " + jwt(`{"sub":`+mDigit+`}`)},
	}
	for _, c := range cases {
		e := engine(t, author(c.pol))
		ex := in("/me")
		ex.ReqHeaders = hdr("x-user", c.val)
		s := out(t, e, ex)
		if !strings.Contains(s, `"subject":"tk1:`) {
			t.Errorf("no subject token: %s", s)
		}
		if f := leaks(s, mWord, mDigit); f != "" {
			t.Errorf("subject raw fragment %q in output: %s", f, s)
		}
	}
}

// Discovery tokens are emitted only while discovery is active on the source
// clock (sanitizer.md §15) and auto_words only before expiry (§4.3).
func TestRT_Sanitizer_Holds_DiscoveryAndAutoWordsExpire(t *testing.T) {
	exp := compiledAt.Add(48 * time.Hour).Format(time.RFC3339)
	e := engine(t, author(`,"discovery":{"enabled":true,"expires_at":"`+exp+`"},"segments":{"auto_words":true,"auto_words_expires_at":"`+exp+`"}`))
	ex := in("/orders/" + mWord)
	ex.RawQuery = []byte("q=" + mWord)
	late := compiledAt.Add(72 * time.Hour)
	o, err := e.Sanitize(ex, late, sanitizer.ByRandom)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := o.Canonical()
	if strings.Contains(string(b), "tkd:") || strings.Contains(string(b), mWord) {
		t.Errorf("discovery/auto_words active after expiry: %s", b)
	}
	// While active: the word goes out in clear (documented), never the query value.
	o, _ = e.Sanitize(ex, compiledAt.Add(time.Hour), sanitizer.ByRandom)
	b, _ = o.Canonical()
	if strings.Contains(string(b), `"q":["`+mWord) {
		t.Errorf("query value in clear during discovery: %s", b)
	}
}

// SEVERITY: medium (hard-safety gap, policy.md §1.4 / hardening.md H2)
// policy.md §1.4 forbids keep/hmac/bucket on a GLOBAL tt-path that contains
// ".*", and hardening.md H2 restates it, because a global wildcard opens
// every request and response of every service at once. That guard is meant
// to hold regardless of approvals. The array wildcard "$[*]" (and "$.a[*]"
// etc. at global scope) has the same "applies to everything" reach for JSON
// bodies with an array root — common for batch endpoints,
// ["mail1","mail2",...] — yet it is accepted by policy.Validate (the strict
// guard used by tt-core AND keyguard, per hardening.md §2.3), by
// ValidateSource and by the compiler. So keyguard will SIGN a policy with a
// global "$[*]: keep" and every source will accept it, keeping every scalar
// element of every top-level array body verbatim, everywhere.
// REPRODUCER: compile {"global":{"request":{"body":{"$[*]":"keep"}}}} and
// call policy.Validate — it returns nil instead of an ErrUnsafe/invalid.
// FIX: in the global-rule guard of policy.validate/CheckUnsafe, reject a
// global keep/hmac/bucket whose tt-path contains ANY wildcard step (".*"
// OR "[*]"), not only the literal ".*" substring. One-liner-ish: replace
// strings.Contains(r.Path, ".*") with a check for ".*" || "[*]".
func TestRT_Policy_GlobalArrayWildcardKeepRejected(t *testing.T) {
	for _, act := range []string{"keep", "hmac"} {
		doc := mustGeneric(t, author(`,"global":{"request":{"body":{"$[*]":"`+act+`"}}}`))
		aa, err := policy.AuthorFromGeneric(doc)
		if err != nil {
			continue // refused at parse: secure
		}
		_, p, err := policy.Compile(aa, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: compiledAt, Groups: []string{"shop"}})
		if err != nil {
			continue // refused at compile: secure
		}
		if err := policy.Validate(p); err == nil {
			t.Errorf("policy.Validate accepts global $[*] %s (keyguard would sign it)", act)
		}
		if err := policy.ValidateSource(p); err == nil {
			t.Errorf("policy.ValidateSource accepts global $[*] %s (sources would apply it)", act)
		}
	}
}
