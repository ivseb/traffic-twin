package ttsdk

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Overhead of the SDK on the request path. Run with
//
//	go test ./sdk/go -run xxx -bench . -benchmem
//
// Baseline is the bare handler / transport; "unsampled" is a source whose
// policy samples nothing (the common case at low rates: one decision, one
// context value); "sampled" copies the bodies and hands the exchange to the
// workers (sanitizing happens off the request path, so its cost is not in
// these numbers; a saturated queue drops events and costs the same).

type discardWriter struct {
	h    http.Header
	code int
}

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardWriter) WriteHeader(c int)           { d.code = c }

var benchBody = []byte(`{"sku":"TSHIRT-RED-M","qty":2,"note":"hello","items":[{"sku":"A","qty":1},{"sku":"B","qty":3}]}`)

func benchApp() http.Handler {
	resp := []byte(`{"status":"CREATED","id":"ORD-1"}`)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write(resp)
	})
}

func benchServe(b *testing.B, h http.Handler) {
	b.Helper()
	b.ReportAllocs()
	w := &discardWriter{h: http.Header{}}
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "http://shop.example/orders", bytes.NewReader(benchBody))
		req.RequestURI = "/orders"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Customer-Id", "c-10042")
		clear(w.h)
		h.ServeHTTP(w, req)
	}
}

func benchAgent(b *testing.B, rate string) (*Agent, *fakeSource) {
	fs := &fakeSource{}
	fs.set(captureFor(b, shopPolicy(rate, true), "shop-api"), true)
	// Events are dropped by the source: only the request path is measured.
	return testAgent(b, fs, func(c *Config) { c.Workers = 1 }), fs
}

func BenchmarkHandlerBaseline(b *testing.B) { benchServe(b, benchApp()) }

func BenchmarkHandlerInert(b *testing.B) {
	a, _ := New(Config{})
	benchServe(b, a.Handler(benchApp()))
}

func BenchmarkHandlerUnsampled(b *testing.B) {
	a, _ := benchAgent(b, "0")
	benchServe(b, a.Handler(benchApp()))
}

func BenchmarkHandlerSampled(b *testing.B) {
	a, _ := benchAgent(b, "1")
	benchServe(b, a.Handler(benchApp()))
}

type benchRT struct{ resp []byte }

func (r *benchRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(r.resp)), ContentLength: int64(len(r.resp)), Request: req}, nil
}

func benchCall(b *testing.B, rt http.RoundTripper) {
	b.Helper()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "https://api.carrier.example/v1/shipments", strings.NewReader(`{"orderId":"ORD-1"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := rt.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkTransportBaseline(b *testing.B) {
	benchCall(b, &benchRT{resp: []byte(`{"status":"OK"}`)})
}

func BenchmarkTransportUnsampled(b *testing.B) {
	a, _ := benchAgent(b, "0")
	benchCall(b, a.Transport(&benchRT{resp: []byte(`{"status":"OK"}`)}))
}

func BenchmarkTransportSampled(b *testing.B) {
	a, _ := benchAgent(b, "1")
	benchCall(b, a.Transport(&benchRT{resp: []byte(`{"status":"OK"}`)}))
}
