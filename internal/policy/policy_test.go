package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

const shopAuthor = `{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"Authorization","jwt_claim":"sub"}},
 "sampling":{"rate":0.05},
 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T10:00:00Z","allow":["v2","v1"]},
 "discovery":{"enabled":false,"expires_at":"2026-10-26T10:00:00Z"},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}},"errors":{"body":{"$.error.code":"keep"}}},
 "services":{
  "shop-api":{"match":{"inbound":true},"ops":{
    "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},
    "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}}},
  "shipping-ext":{"match":{"base":"https://API.carrier.example:443"},"errors":{"body":{"$.error.code":"keep"}},"ops":{
    "POST /v1/shipments":{"request":{"body":{"$.orderId":"hmac(order)"}},"response":{"$.shipmentId":"hmac(shipment)","$.status":"keep"}},
    "GET /v1/shipments":{"request":{"query":{"orderId":"hmac(order)"}},"response":{"$.items[*].orderId":"hmac(order)","$.items[*].shipmentId":"hmac(shipment)","$.items[*].status":"keep","$.items[*].eta":"bucket(time, day)"}}}}
 }}`

var created = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

func meta(version, seq int64) CompileMeta {
	return CompileMeta{Version: version, IssuedSeq: seq, CreatedAt: created, Groups: []string{"shop", "edge"}}
}

func author(t *testing.T, s string) *Author {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCompileShop(t *testing.T) {
	body, p, err := Compile(author(t, shopAuthor), meta(7, 31))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"created_at":"2026-10-19T10:00:00Z","discovery":{"enabled":false,"expires_at":"2026-10-26T10:00:00Z"},"format":"tt.policy.body/v1",` +
		`"global":{"errors":{"body":[{"action":{"action":"keep"},"path":"$.error.code"}]},"request":{"headers":{"content-type":{"action":"keep"}}},"response":{"headers":{"content-type":{"action":"keep"}}}},` +
		`"hmac":{"accept_kids":[],"epoch":"2026-10","kid":"k1"},"identity":{"subject":{"from":"header","jwt_claim":"sub","name":"authorization"}},"issued_seq":31,` +
		`"limits":{"keep_max_bytes":64,"max_array":32,"max_body_bytes":1048576,"max_depth":32,"max_keys":256},"not_after":"2026-11-18T10:00:00Z","policy_id":"p-shop",` +
		`"sampling":{"propagate_to":[],"rate_bp":500,"trust_baggage":false},` +
		`"segments":{"allow":["v1","v2"],"auto_words":true,"auto_words_expires_at":"2026-10-22T10:00:00Z","hosts_allow":[]},"services":[` +
		`{"errors":{"body":[{"action":{"action":"keep"},"path":"$.error.code"}]},"match":{"base":"https://api.carrier.example"},"name":"shipping-ext","ops":[` +
		`{"op":"GET /v1/shipments","request":{"query":{"orderId":{"action":"hmac","domain":"order"}}},"response":{"body":[{"action":{"action":"bucket","kind":"time","unit":"day"},"path":"$.items[*].eta"},{"action":{"action":"hmac","domain":"order"},"path":"$.items[*].orderId"},{"action":{"action":"hmac","domain":"shipment"},"path":"$.items[*].shipmentId"},{"action":{"action":"keep"},"path":"$.items[*].status"}]}},` +
		`{"op":"POST /v1/shipments","request":{"body":[{"action":{"action":"hmac","domain":"order"},"path":"$.orderId"}]},"response":{"body":[{"action":{"action":"hmac","domain":"shipment"},"path":"$.shipmentId"},{"action":{"action":"keep"},"path":"$.status"}]}}]},` +
		`{"match":{"inbound":true,"internal":false},"name":"shop-api","ops":[` +
		`{"op":"GET /orders/{id}","request":{"path":{"id":{"action":"hmac","domain":"order"}}}},` +
		`{"op":"POST /orders","response":{"body":[{"action":{"action":"hmac","domain":"order"},"path":"$.id"},{"action":{"action":"keep"},"path":"$.status"},{"action":{"action":"bucket","bounds":[0,50,100,250],"kind":"num"},"path":"$.total"}]}}]}],` +
		`"targets":{"groups":["edge","shop"]},"version":7}`
	if string(body) != want {
		t.Fatalf("got\n%s\nwant\n%s", body, want)
	}
	if !ttjson.IsCanonical(body) {
		t.Fatal("not canonical")
	}
	if p.Sampling.RateBP != 500 || p.Subject.Name != "authorization" || len(p.Services) != 2 || p.IssuedSeq != 31 {
		t.Fatalf("decoded: %+v", p)
	}
	body2, _, _ := Compile(author(t, shopAuthor), CompileMeta{Version: 7, IssuedSeq: 31, CreatedAt: created.Add(500 * time.Millisecond), Groups: []string{"edge", "shop"}})
	if !bytes.Equal(body, body2) {
		t.Fatal("compile not deterministic")
	}
}

func TestCompileRejects(t *testing.T) {
	base := func(extra string) string {
		return `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"e"},"sampling":{"rate":1}` + extra + `}`
	}
	cases := map[string]string{
		"no sampling":          `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"e"}}`,
		"reserved domain":      base(`,"global":{"request":{"$.a":"hmac(subject)"}}`),
		"reserved discovery":   base(`,"global":{"request":{"$.a":"hmac(discovery)"}}`),
		"keep authorization":   base(`,"global":{"request":{"headers":{"authorization":"keep"}}}`),
		"keep x-api-key":       base(`,"services":{"s":{"match":{"inbound":true},"ops":{"GET /":{"request":{"headers":{"x-api-key":"keep"}}}}}}`),
		"upper header":         base(`,"global":{"request":{"headers":{"Accept":"keep"}}}`),
		"bad query name":       base(`,"global":{"request":{"query":{"1abc":"keep"}}}`),
		"bad tt-path":          base(`,"global":{"request":{"$.a[0]":"keep"}}`),
		"bad action":           base(`,"global":{"request":{"$.a":"hash"}}`),
		"global .* keep":       base(`,"global":{"request":{"$.*":"keep"}}`),
		"global .*.x hmac":     base(`,"global":{"response":{"$.*.x":"hmac"}}`),
		"global [*] keep":      base(`,"global":{"request":{"$[*]":"keep"}}`),
		"global [*].x hmac":    base(`,"global":{"response":{"$[*].x":"hmac"}}`),
		"global a[*] bucket":   base(`,"global":{"request":{"$.a[*]":"bucket(num, [0, 1])"}}`),
		"global a[*][*] keep":  base(`,"global":{"request":{"$.a[*][*]":"keep"}}`),
		"bucket decreasing":    base(`,"global":{"request":{"$.a":"bucket(num, [0, 0])"}}`),
		"bucket same double":   base(`,"global":{"request":{"$.a":"bucket(num, [0.1, 0.10000000000000001])"}}`),
		"bucket 33":            base(`,"global":{"request":{"$.a":"bucket(num, [` + strings.TrimSuffix(strings.Repeat("1,", 33), ",") + `])"}}`),
		"bucket long lexeme":   base(`,"global":{"request":{"$.a":"bucket(num, [0.` + strings.Repeat("1", 64) + `])"}}`),
		"bucket unit":          base(`,"global":{"request":{"$.a":"bucket(time, minute)"}}`),
		"equivalent ops":       base(`,"services":{"s":{"match":{"inbound":true},"ops":{"GET /a/{x}":{},"GET /a/{y}":{}}}}`),
		"param not in tmpl":    base(`,"services":{"s":{"match":{"inbound":true},"ops":{"GET /a/{x}":{"request":{"path":{"y":"keep"}}}}}}`),
		"path outside op":      base(`,"global":{"request":{"path":{"x":"keep"}}}`),
		"rate too precise":     base(`,"sampling":{"rate":0.00005}`),
		"rate > 1":             base(`,"sampling":{"rate":1.5}`),
		"rate float noise":     base(`,"sampling":{"rate":0.30000000000000004}`),
		"default keep":         `{"format":"tt.policy/v1","policy_id":"p","default":"keep","hmac":{"kid":"k1","epoch":"e"},"sampling":{"rate":1}}`,
		"unknown field":        base(`,"extra":1`),
		"disc no expiry":       base(`,"discovery":{"enabled":true}`),
		"disc beyond 7 days":   base(`,"discovery":{"enabled":true,"expires_at":"2026-10-26T10:00:01Z"}`),
		"disc in the past":     base(`,"discovery":{"enabled":true,"expires_at":"2026-10-19T10:00:00Z"}`),
		"auto words no expiry": base(`,"segments":{"auto_words":true}`),
		"auto words 8 days":    base(`,"segments":{"auto_words":true,"auto_words_expires_at":"2026-10-27T10:00:00Z"}`),
		"limits too high":      base(`,"limits":{"max_depth":1000}`),
		"bad base":             base(`,"services":{"s":{"match":{"base":"ftp://x"},"ops":{}}}`),
		"base port 0":          base(`,"services":{"s":{"match":{"base":"https://x.example:0"},"ops":{}}}`),
		"dup base":             base(`,"services":{"a":{"match":{"base":"https://x.example"},"ops":{}},"b":{"match":{"base":"https://X.example:443"},"ops":{}}}}`),
		"propagate to base":    base(`,"sampling":{"rate":1,"propagate_to":["x.example"]},"services":{"a":{"match":{"base":"https://x.example"},"ops":{}}}`),
		"accept own kid":       `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"e","accept_kids":["k1"]},"sampling":{"rate":1}}`,
		"accept 5 kids":        `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"e","accept_kids":["a","b","c","d","f"]},"sampling":{"rate":1}}`,
		"bad op key":           base(`,"services":{"s":{"match":{"inbound":true},"ops":{"get /a":{}}}}`),
		"literal too long":     base(`,"services":{"s":{"match":{"inbound":true},"ops":{"GET /` + strings.Repeat("a", 65) + `":{}}}}`),
		"bad allow":            base(`,"segments":{"allow":["a/b"]}`),
		"bad hosts_allow":      base(`,"segments":{"hosts_allow":["API.example"]}`),
		"dup shorthand":        base(`,"global":{"request":{"$.a":"keep","body":{"$.a":"drop"}}}`),
		"internal on base":     base(`,"services":{"s":{"match":{"base":"https://x.example","internal":true},"ops":{}}}`),
	}
	for name, s := range cases {
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		var doc any
		if err := d.Decode(&doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a, err := AuthorFromGeneric(doc)
		if err == nil {
			_, _, err = Compile(a, meta(1, 1))
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := Compile(author(t, shopAuthor), CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: created}); err == nil {
		t.Error("compile without groups accepted")
	}
}

func TestParseAction(t *testing.T) {
	ok := map[string]string{
		"bucket(num,[0,50])":         "0,50",
		"bucket(num, [ -1.50 , 2 ])": "-1.5,2",
		"bucket(num, [0])":           "0",
		"bucket(time,day)":           "",
		"hmac":                       "",
	}
	for s, b := range ok {
		a, err := ParseAction(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		var got []string
		for _, x := range a.Bounds {
			got = append(got, x.Lexeme)
		}
		if strings.Join(got, ",") != b {
			t.Errorf("%s: bounds %v", s, got)
		}
	}
	if a, _ := ParseAction("hmac"); a.Domain != "id" {
		t.Error("default domain")
	}
	for _, s := range []string{"bucket(num, [])", "bucket(num,  [0])", "bucket(num, [01])", "bucket(num, [.5])", "hmac()", "hmac(Order)", "keep ", "bucket(time,  day)"} {
		if _, err := ParseAction(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestRateToBP(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "1": 10000, "0.05": 500, "0.0001": 1, "1.0000": 10000, "0.12340": 1234} {
		if got, err := RateToBP(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"-0.1", "1.0001", "0.00001", "abc", ".5", "1e-2", ""} {
		if _, err := RateToBP(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(100 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func signed(t *testing.T, version, seq int64) []byte {
	t.Helper()
	body, _, err := Compile(author(t, shopAuthor), meta(version, seq))
	if err != nil {
		t.Fatal(err)
	}
	_, priv := keys()
	env, err := Sign(body, "policy-2026-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func ring(t *testing.T) *KeyRing {
	pub, _ := keys()
	r := NewKeyRing()
	if err := r.Pin("policy-2026-1", pub); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignVerify(t *testing.T) {
	env := signed(t, 7, 31)
	r := ring(t)
	v, err := Verify(env, r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Policy.Version != 7 || v.Policy.IssuedSeq != 31 || v.Hash != Hash(v.Body) || v.SignerKid != "policy-2026-1" {
		t.Fatalf("%+v", v)
	}
	if !ttjson.IsCanonical(env) {
		t.Fatal("envelope not canonical")
	}
	// The signature covers "tt.policy.body/v1" || 0x00 || body, not the bare body.
	_, priv := keys()
	sigEnc := func(sig []byte) []byte {
		var m map[string]any
		_ = json.Unmarshal(env, &m)
		m["signature"].(map[string]any)["sig"] = base64.RawURLEncoding.EncodeToString(sig)
		b, _ := json.Marshal(m)
		return b
	}
	if _, err := Verify(sigEnc(ed25519.Sign(priv, v.Body)), r); !errors.Is(err, ErrBadSignature) {
		t.Errorf("bare-body signature accepted: %v", err)
	}
	if _, err := Verify(sigEnc(ed25519.Sign(priv, SignedMessage(v.Body))), r); err != nil {
		t.Errorf("prefixed signature: %v", err)
	}

	reenc := func(mut func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(env, &m)
		mut(m)
		b, _ := json.Marshal(m)
		return b
	}
	b64 := base64.RawURLEncoding
	tampered := bytes.Replace(v.Body, []byte(`"rate_bp":500`), []byte(`"rate_bp":900`), 1)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	other, _ := Sign(v.Body, "policy-2026-1", otherPriv)
	cases := map[string]struct {
		env  []byte
		want error
	}{
		"tampered body": {reenc(func(m map[string]any) { m["body_b64"] = b64.EncodeToString(tampered) }), ErrBadSignature},
		"unknown kid":   {reenc(func(m map[string]any) { m["signature"].(map[string]any)["kid"] = "other" }), ErrUnknownKid},
		"other signer":  {other, ErrBadSignature},
		"hash":          {reenc(func(m map[string]any) { m["hash"] = "sha256:" + strings.Repeat("0", 64) }), ErrHashMismatch},
		"version":       {reenc(func(m map[string]any) { m["version"] = 8 }), ErrIDMismatch},
		"issued_seq":    {reenc(func(m map[string]any) { m["issued_seq"] = 32 }), ErrIDMismatch},
		"policy id":     {reenc(func(m map[string]any) { m["policy_id"] = "p-other" }), ErrIDMismatch},
		"no issued_seq": {reenc(func(m map[string]any) { delete(m, "issued_seq") }), ErrEnvelope},
		"alg":           {reenc(func(m map[string]any) { m["signature"].(map[string]any)["alg"] = "RS256" }), ErrEnvelope},
		"extra field":   {reenc(func(m map[string]any) { m["x"] = 1 }), ErrEnvelope},
		"padding":       {reenc(func(m map[string]any) { m["body_b64"] = m["body_b64"].(string) + "=" }), ErrEnvelope},
		"newline in b64": {reenc(func(m map[string]any) {
			s := m["body_b64"].(string)
			m["body_b64"] = s[:10] + "\n" + s[10:]
		}), ErrEnvelope},
		"not json": {[]byte("{"), ErrEnvelope},
		"dup key":  {append(append([]byte(nil), bytes.TrimSuffix(env, []byte("}"))...), []byte(`,"version":7}`)...), ErrEnvelope},
	}
	for name, c := range cases {
		if _, err := Verify(c.env, r); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
	// A reserved domain inside a validly signed body is rejected.
	bad := bytes.Replace(v.Body, []byte(`"domain":"shipment"`), []byte(`"domain":"subject"`), 1)
	p := *v.Policy
	hand, _ := Envelope(bad, &p, "policy-2026-1", ed25519.Sign(priv, SignedMessage(bad)))
	if _, err := Verify(hand, r); !errors.Is(err, ErrInvalid) {
		t.Errorf("reserved domain in signed body: %v", err)
	}
	// Revocation.
	r.Revoke("policy-2026-1")
	if _, err := Verify(env, r); !errors.Is(err, ErrUnknownKid) {
		t.Errorf("revoked key accepted: %v", err)
	}
	pub, _ := keys()
	if err := r.Pin("policy-2026-1", pub); err == nil {
		t.Error("revoked kid pinned again")
	}
}

func TestSourceAcceptsCompileOnlyViolations(t *testing.T) {
	// A source checks the schema, the reserved domains and the v1.3 safety
	// subset (hardening.md 2): the rest of policy.md 1.4 is tt-core's. Here a
	// duplicated operation shape and an unsorted-looking base are fine.
	body, p, err := Compile(author(t, shopAuthor), meta(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	// bucket on a global .* is tt-core's alone (hardening.md 2.1 H2).
	b := bytes.Replace(body, []byte(`"global":{`), []byte(`"global":{"request":{"body":[{"action":{"action":"bucket","kind":"time","unit":"day"},"path":"$.*"}]},"x":{`), 1)
	b = bytes.Replace(b, []byte(`,"x":{"errors"`), []byte(`,"errors"`), 1)
	b = bytes.Replace(b, []byte(`"request":{"headers":{"content-type":{"action":"keep"}}},"response"`), []byte(`"response"`), 1)
	if _, err := DecodeBody(b); err != nil {
		t.Fatalf("source rejected a compile-only violation: %v\n%s", err, b)
	}
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
}

// TestSourceRefusesUnsafe covers hardening.md 2.1 H1 to H3 and the
// alignment of Validate (tt-core, keyguard) with them.
func TestSourceRefusesUnsafe(t *testing.T) {
	fresh := func() *Policy {
		_, p, err := Compile(author(t, shopAuthor), meta(1, 1))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	kinds := map[string]Action{"keep": {Kind: ActKeep}, "hmac": {Kind: ActHMAC, Domain: "d"}}
	for _, h := range []string{"authorization", "cookie", "set-cookie", "proxy-authorization"} {
		for kn, act := range kinds {
			muts := map[string]func(p *Policy){
				"global request":  func(p *Policy) { p.Global.Request.Headers = map[string]Action{h: act} },
				"global response": func(p *Policy) { p.Global.Response.Headers = map[string]Action{h: act} },
				"global errors":   func(p *Policy) { p.Global.Errors.Headers = map[string]Action{h: act} },
				"service errors":  func(p *Policy) { p.Services[0].Errors.Headers = map[string]Action{h: act} },
				"service request": func(p *Policy) { p.Services[0].Request.Headers = map[string]Action{h: act} },
				"op request":      func(p *Policy) { p.Services[1].Ops[0].Request.Headers = map[string]Action{h: act} },
				"op response":     func(p *Policy) { p.Services[1].Ops[0].Response.Headers = map[string]Action{h: act} },
			}
			for where, mut := range muts {
				p := fresh()
				mut(p)
				if err := ValidateSource(p); !errors.Is(err, ErrUnsafe) || !errors.Is(err, ErrInvalid) {
					t.Errorf("%s %s %s: source accepted or wrong error: %v", kn, h, where, err)
				}
				if err := Validate(p); err == nil {
					t.Errorf("%s %s %s: Validate accepted", kn, h, where)
				}
			}
		}
	}
	// Not in the subset: bucket/drop on those headers (drop is the default),
	// hmac on x-api-key.
	p := fresh()
	p.Global.Request.Headers = map[string]Action{"authorization": {Kind: ActDrop}, "x-api-key": {Kind: ActHMAC, Domain: "d"}}
	if err := ValidateSource(p); err != nil {
		t.Errorf("drop / hmac x-api-key refused: %v", err)
	}
	for kn, act := range kinds {
		for _, path := range []string{"$.*", "$.a.*", "$.a.*.b", "$[*]", "$[*].x", "$.a[*]", "$.a[*][*].b"} {
			for _, part := range []string{"request", "response", "errors"} {
				p := fresh()
				rules := []BodyRule{{Path: path, Action: act}}
				switch part {
				case "request":
					p.Global.Request.Body = rules
				case "response":
					p.Global.Response.Body = rules
				default:
					p.Global.Errors.Body = rules
				}
				if err := ValidateSource(p); !errors.Is(err, ErrUnsafe) {
					t.Errorf("global %s %s %s accepted: %v", part, kn, path, err)
				}
			}
		}
		// service and operation rules may use .*
		p := fresh()
		p.Services[0].Request.Body = []BodyRule{{Path: "$.*", Action: act}}
		p.Services[1].Ops[0].Response.Body = []BodyRule{{Path: "$.a.*", Action: act}}
		if err := ValidateSource(p); err != nil {
			t.Errorf("%s .* in service/op refused: %v", kn, err)
		}
	}
	// H3: exactly 7 days is fine, one second more is not.
	for _, kind := range []string{"discovery", "auto_words"} {
		set := func(p *Policy, d time.Duration) {
			at := p.CreatedAt.Add(d)
			if kind == "discovery" {
				p.Discovery = &Discovery{Enabled: true, ExpiresAt: at}
			} else {
				p.Segments.AutoWords, p.Segments.AutoWordsExpiresAt = true, at
			}
		}
		p := fresh()
		set(p, MaxOpenWindow)
		if err := ValidateSource(p); err != nil {
			t.Errorf("%s at exactly 7 days refused: %v", kind, err)
		}
		p = fresh()
		set(p, MaxOpenWindow+time.Second)
		if err := ValidateSource(p); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s at 7 days + 1 s accepted: %v", kind, err)
		}
		if err := Validate(p); err == nil {
			t.Errorf("%s at 7 days + 1 s: Validate accepted", kind)
		}
	}
	p = fresh()
	p.Discovery = &Discovery{Enabled: false, ExpiresAt: p.CreatedAt.Add(30 * 24 * time.Hour)}
	if err := ValidateSource(p); err != nil {
		t.Errorf("disabled discovery refused: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	pub, priv := keys()
	r := NewKeyRing()
	if err := r.PinEncoded("k-old", "Ed25519", base64.RawURLEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	end := Endorse(priv, "k-new", newPub)
	enc := base64.RawURLEncoding.EncodeToString(newPub)
	if err := r.PinEndorsed("k-new", "Ed25519", enc, "k-old", end); err != nil {
		t.Fatal(err)
	}
	if err := r.PinEndorsed("k-evil", "Ed25519", enc, "k-old", end); err == nil {
		t.Error("endorsement reused for another kid")
	}
	if err := r.PinEndorsed("k-x", "Ed25519", enc, "k-unknown", end); err == nil {
		t.Error("unknown endorser accepted")
	}
	body, _, _ := Compile(author(t, shopAuthor), meta(1, 1))
	env, _ := Sign(body, "k-new", newPriv)
	if _, err := Verify(env, r); err != nil {
		t.Fatal(err)
	}
}

func TestAccept(t *testing.T) {
	env := signed(t, 7, 31)
	r := ring(t)
	cases := []struct {
		group         string
		now           time.Time
		last, minimum int64
		want          error
	}{
		{"shop", created, 0, 0, nil},
		{"other", created, 0, 0, ErrGroup},
		{"shop", created.Add(30 * 24 * time.Hour), 0, 0, ErrNotAfter},
		{"shop", created, 31, 0, ErrStale},
		{"shop", created, 30, 32, ErrStale},
		{"edge", created, 30, 31, nil},
	}
	for i, c := range cases {
		if _, err := Accept(env, r, c.group, c.now, c.last, c.minimum); !errors.Is(err, c.want) {
			t.Errorf("case %d: %v want %v", i, err, c.want)
		}
	}
}

func TestStoreFailClosed(t *testing.T) {
	r := ring(t)
	s := NewStore(r, "shop", time.Hour)
	now := created
	if st := s.Current(now); st.Capture || st.State != StateNoPolicy {
		t.Fatalf("empty: %+v", st)
	}
	if err := s.Offer([]byte("garbage"), now); err == nil {
		t.Fatal("garbage accepted")
	}
	if st := s.Current(now); st.Capture || st.State != StatePolicyRejected {
		t.Fatalf("rejected without previous: %+v", st)
	}
	env7 := signed(t, 7, 31)
	if err := s.Offer(env7, now); err != nil {
		t.Fatal(err)
	}
	if st := s.Current(now); st.Capture {
		t.Fatalf("captured before the first heartbeat: %+v", st)
	}
	s.Heartbeat(false, 0, now)
	if st := s.Current(now); !st.Capture || st.State != StateCapturing || st.Policy.Policy.Version != 7 {
		t.Fatalf("capturing: %+v", st)
	}
	if err := s.Offer(bytes.Replace(env7, []byte(`"version":7`), []byte(`"version":9`), 1), now); err == nil {
		t.Fatal("tampered accepted")
	}
	if st := s.Current(now); !st.Capture || st.State != StatePolicyRejected || st.Policy.Policy.Version != 7 {
		t.Fatalf("rejected with previous: %+v", st)
	}
	if err := s.Offer(signed(t, 6, 30), now); !errors.Is(err, ErrStale) {
		t.Fatalf("replay: %v", err)
	}
	if st := s.Current(now.Add(61 * time.Minute)); st.Capture || st.State != StateExpiredPolicy {
		t.Fatalf("expired: %+v", st)
	}
	s.Confirm(now.Add(50 * time.Minute))
	if st := s.Current(now.Add(61 * time.Minute)); !st.Capture {
		t.Fatalf("confirmed: %+v", st)
	}
	if st := s.Current(created.Add(31 * 24 * time.Hour)); st.Capture {
		t.Fatalf("captured after not_after: %+v", st)
	}
	// Kill switch, persisted through the cache.
	s.Heartbeat(true, 0, now)
	if st := s.Current(now); st.Capture || st.State != StateKilled {
		t.Fatalf("killed: %+v", st)
	}
	raw, err := MarshalCache(s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	c, err := UnmarshalCache(raw)
	if err != nil {
		t.Fatal(err)
	}
	s2 := NewStore(r, "shop", time.Hour)
	if err := s2.Restore(c, now); err != nil {
		t.Fatal(err)
	}
	if st := s2.Current(now); st.Capture || st.State != StateKilled {
		t.Fatalf("restored kill switch: %+v", st)
	}
	s2.Heartbeat(false, 0, now)
	if st := s2.Current(now); !st.Capture {
		t.Fatalf("restored: %+v", st)
	}
	// min_issued_seq supersedes the current policy.
	s2.Heartbeat(false, 40, now)
	if st := s2.Current(now); st.Capture {
		t.Fatalf("superseded policy still used: %+v", st)
	}
	if err := s2.Offer(signed(t, 8, 39), now); !errors.Is(err, ErrStale) {
		t.Fatalf("below min_issued_seq: %v", err)
	}
	if err := s2.Offer(signed(t, 8, 40), now); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeBodyStrict(t *testing.T) {
	body, _, _ := Compile(author(t, shopAuthor), meta(1, 1))
	for name, b := range map[string][]byte{
		"unknown field":        bytes.Replace(body, []byte(`"format"`), []byte(`"x":1,"format"`), 1),
		"bad action":           bytes.Replace(body, []byte(`{"action":"keep"}`), []byte(`{"action":"keep","domain":"x"}`), 1),
		"float version":        bytes.Replace(body, []byte(`"version":1}`), []byte(`"version":1.0}`), 1),
		"bad op":               bytes.Replace(body, []byte(`"op":"GET /orders/{id}"`), []byte(`"op":"GET /files/{*}"`), 1),
		"inbound false":        bytes.Replace(body, []byte(`"inbound":true`), []byte(`"inbound":false`), 1),
		"no internal":          bytes.Replace(body, []byte(`,"internal":false`), nil, 1),
		"no targets":           bytes.Replace(body, []byte(`,"targets":{"groups":["edge","shop"]}`), nil, 1),
		"empty groups":         bytes.Replace(body, []byte(`"groups":["edge","shop"]`), []byte(`"groups":[]`), 1),
		"dup groups":           bytes.Replace(body, []byte(`"groups":["edge","shop"]`), []byte(`"groups":["shop","shop"]`), 1),
		"no accept_kids":       bytes.Replace(body, []byte(`"accept_kids":[],`), nil, 1),
		"reserved domain":      bytes.Replace(body, []byte(`"domain":"order"`), []byte(`"domain":"sample"`), 1),
		"auto words no expiry": bytes.Replace(body, []byte(`,"auto_words_expires_at":"2026-10-22T10:00:00Z"`), nil, 1),
	} {
		if _, err := DecodeBody(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSigningKeyErrorCodes(t *testing.T) {
	pub, priv := keys()
	r := NewKeyRing()
	if err := r.PinEncoded("k-old", "Ed25519", base64.RawURLEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	newPub, _, _ := ed25519.GenerateKey(nil)
	enc := base64.RawURLEncoding.EncodeToString(newPub)
	end := Endorse(priv, "k-new", newPub)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := r.PinEndorsed("k-new", "Ed25519", enc, "k-old", end); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, kid, alg, key, by, endorsement, wantCode string
	}{
		{"malformed kid", "bad kid", "Ed25519", enc, "k-old", end, "signing_key_rejected"},
		{"wrong alg", "k-a", "RSA", enc, "k-old", end, "signing_key_rejected"},
		{"short key", "k-b", "Ed25519", "AAAA", "k-old", end, "signing_key_rejected"},
		{"short endorsement", "k-c", "Ed25519", enc, "k-old", "AAAA", "signing_key_rejected"},
		{"conflict", "k-new", "Ed25519", base64.RawURLEncoding.EncodeToString(otherPub), "k-old", end, "signing_key_conflict"},
		{"unknown endorser", "k-d", "Ed25519", enc, "k-nobody", end, "signing_key_endorser_unknown"},
		{"bad signature", "k-evil", "Ed25519", enc, "k-old", end, "signing_key_endorsement_invalid"},
	}
	for _, c := range cases {
		err := r.PinEndorsed(c.kid, c.alg, c.key, c.by, c.endorsement)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if got := SigningKeyErrorCode(err); got != c.wantCode {
			t.Errorf("%s: code %s, want %s (%v)", c.name, got, c.wantCode, err)
		}
	}
}
