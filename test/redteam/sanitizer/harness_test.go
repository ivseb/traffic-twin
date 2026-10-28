// Package sanitizer_rt holds red-team tests for internal/sanitizer.
// Every value used here is invented.
package sanitizer_rt

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

var compiledAt = time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
var t0 = compiledAt.Add(time.Hour)

const emptyAuthor = `{"format":"tt.policy/v1","policy_id":"p-empty","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1}}`

func secret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 7)
	}
	return b
}

func mustGeneric(t testing.TB, author string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(author))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("author json: %v", err)
	}
	return doc
}

func compile(t testing.TB, author string) *policy.Policy {
	t.Helper()
	a, err := policy.AuthorFromGeneric(mustGeneric(t, author))
	if err != nil {
		t.Fatalf("author: %v", err)
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: compiledAt, Groups: []string{"shop"}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func engine(t testing.TB, author string) *sanitizer.Engine {
	t.Helper()
	k, err := sanitizer.NewKey("k1", secret())
	if err != nil {
		t.Fatal(err)
	}
	e, err := sanitizer.NewEngineWithKey(compile(t, author), k)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// out returns the canonical sanitizer output, or "" when Sanitize refuses
// the exchange (no event: nothing leaks).
func out(t testing.TB, e *sanitizer.Engine, ex *sanitizer.Exchange) string {
	t.Helper()
	o, err := e.Sanitize(ex, t0, sanitizer.ByRandom)
	if err != nil {
		return ""
	}
	b, err := o.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return string(b)
}

func hdr(kv ...string) []sanitizer.Header {
	var hs []sanitizer.Header
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, sanitizer.Header{Name: kv[i], Value: []byte(kv[i+1])})
	}
	return hs
}

func in(path string) *sanitizer.Exchange {
	return &sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: "GET", RawPath: []byte(path), Status: 200}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// leaks reports the first marker fragment (5 bytes) found in s.
func leaks(s string, markers ...string) string {
	for _, m := range markers {
		for i := 0; i+5 <= len(m); i++ {
			if strings.Contains(s, m[i:i+5]) {
				return m[i : i+5]
			}
		}
	}
	return ""
}
