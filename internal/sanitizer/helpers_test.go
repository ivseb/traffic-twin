package sanitizer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// testSecret is the key of the spec example: 32 bytes 0x00 … 0x1f.
func testSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func testKey(t testing.TB) Key {
	k, err := NewKey("k1", testSecret())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// specToken computes the tk1 token straight from the formula of section 7.2,
// independently of the implementation.
func specToken(domain, value string) string {
	m := hmac.New(sha256.New, testSecret())
	m.Write([]byte("2026-10"))
	m.Write([]byte{0})
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return "tk1:k1:" + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

func specDisc(path, value string) string {
	m := hmac.New(sha256.New, testSecret())
	m.Write([]byte("2026-10\x00discovery\x00" + path + "\x00"))
	m.Write([]byte(value))
	return "tkd:" + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:4])
}

// compileJSON compiles an author policy written as JSON (the core agent
// will feed YAML through the same AuthorFromGeneric path).
func compileJSON(t testing.TB, author string) *policy.Policy {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(author)))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("author json: %v", err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatalf("author: %v", err)
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: compiledAt, Groups: []string{"shop"}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// t0 is the source clock of the tests (one hour after compiledAt).
var t0 = time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

// compiledAt is the compilation time of every test policy.
var compiledAt = time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)

const emptyAuthor = `{"format":"tt.policy/v1","policy_id":"p-empty","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1}}`

func limitsAuthor(limits string) string {
	return `{"format":"tt.policy/v1","policy_id":"p","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1},"limits":` + limits + `}`
}

func engine(t testing.TB, author string) *Engine {
	t.Helper()
	e, err := NewEngineWithKey(compileJSON(t, author), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func canon(t testing.TB, e *Engine, ex *Exchange, now time.Time) string {
	t.Helper()
	out, err := e.Sanitize(ex, now, ByRandom)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	b, err := out.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return string(b)
}

func hdr(kv ...string) []Header {
	var hs []Header
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, Header{Name: kv[i], Value: []byte(kv[i+1])})
	}
	return hs
}

func b64url(s string) string   { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func b64nopad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func specMAC(domain, value string) []byte {
	m := hmac.New(sha256.New, testSecret())
	m.Write([]byte("2026-10\x00" + domain + "\x00" + value))
	return m.Sum(nil)
}

// in builds a simple inbound GET exchange with status 200.
func in(path string) *Exchange {
	return &Exchange{Dir: Inbound, ServiceName: "shop-api", Method: "GET", RawPath: []byte(path), Status: 200}
}
