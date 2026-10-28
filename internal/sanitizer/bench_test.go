package sanitizer

import (
	"fmt"
	"strings"
	"testing"
)

const benchAuthor = `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":1},
 "segments":{"auto_words":true,"auto_words_expires_at":"2026-10-22T00:00:00Z"},
 "global":{"request":{"headers":{"content-type":"keep","accept":"keep"}},"response":{"headers":{"content-type":"keep"}}},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])",
     "$.items[*].sku":"hmac(sku)","$.items[*].qty":"keep","$.customer.email":"hmac(email)","$.created_at":"bucket(time, day)"}}}}}}`

// orderJSON builds an invented order document with n items.
func orderJSON(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"id":"ORD-2026-000184","status":"CREATED","total":73.40,"currency":"EUR","created_at":"2026-10-19T10:00:00.412Z",`)
	b.WriteString(`"customer":{"id":"550e8400-e29b-41d4-a716-446655440000","email":"giulia.neri@example.com","name":"Giulia Neri","phone":"+393331234567"},`)
	b.WriteString(`"shipping":{"street":"Via Roma 1","city":"Torino","zip":"10100","country":"IT"},"items":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"sku":"TSHIRT-RED-%03d","qty":%d,"price":19.90,"note":"gift wrap please","tags":["summer","sale"]}`, i, i%5+1)
	}
	b.WriteString(`],"meta":{"source":"web","ab":"variant-b","trace":"4bf92f3577b34da6a3ce929d0e0e4736"}}`)
	return []byte(b.String())
}

func benchExchange(body []byte) *Exchange {
	return &Exchange{
		Dir: Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/orders"), RawQuery: []byte("promo=AUTUMN10&ref=mail"),
		ReqHeaders: hdr("Content-Type", "application/json", "Accept", "application/json", "Cookie", "sid=9f8e7d6c5b4a; lang=it",
			"User-Agent", "Mozilla/5.0 (invented)", "Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1LTQyIn0.c2ln"),
		ReqBody: []byte(`{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com","note":""}`),
		Status:  201, RespHeaders: hdr("Content-Type", "application/json; charset=utf-8"),
		RespBody: body,
	}
}

func benchSanitize(b *testing.B, items int) {
	e := engine(b, benchAuthor)
	body := orderJSON(items)
	ex := benchExchange(body)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := e.Sanitize(ex, t0, ByRandom)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := out.Canonical(); err != nil {
			b.Fatal(err)
		}
	}
}

// ~2 KB response body (max_array 32 keeps everything).
func BenchmarkSanitize2KB(b *testing.B) { benchSanitize(b, 16) }

// ~64 KB response body; arrays beyond max_array are validated and skipped.
func BenchmarkSanitize64KB(b *testing.B) { benchSanitize(b, 620) }

func TestBenchBodySizes(t *testing.T) {
	if n := len(orderJSON(16)); n < 1800 || n > 2600 {
		t.Errorf("2KB body is %d bytes", n)
	}
	if n := len(orderJSON(620)); n < 60000 || n > 70000 {
		t.Errorf("64KB body is %d bytes", n)
	}
}
