package obi

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// The two real_obi_* fixtures are batches exported by OBI v0.15.2 (protocol
// http/json) for an invented Node.js and a Python app, captured on a Docker
// Desktop (linuxkit 6.12) VM with the configuration "tt obi" generates. They
// show what the real exporter writes: upper-case hex ids, header attributes
// as arrays, http.{request,response}.body.content, no http.*.body.size, the
// extra "in queue" and "processing" internal spans, and, for a TLS client,
// spans without status or body.

func mappedAll(t *testing.T, name string, o MapOptions) (events []string, mapped, httpSpans int) {
	t.Helper()
	cp := testCapture(t, shopPolicy)
	for _, r := range fixture(t, name) {
		for _, ss := range r.ScopeSpans {
			for i := range ss.Spans {
				sp := &ss.Spans[i]
				if !IsHTTP(sp) {
					continue
				}
				httpSpans++
				m, ok := Map(sp, o)
				if !ok {
					continue
				}
				mapped++
				ev, sampled, err := Exchange(cp, m, time.Now(), nil)
				if err != nil || !sampled {
					t.Fatalf("exchange: sampled=%v err=%v", sampled, err)
				}
				events = append(events, string(ev))
			}
		}
	}
	return events, mapped, httpSpans
}

func TestRealOBIHTTPCapture(t *testing.T) {
	events, mapped, httpSpans := mappedAll(t, "real_obi_http_server.json", MapOptions{ServiceName: "shop-api", CaptureLimit: 8192})
	// Two spans of the Node.js inspector (port 9229, same process as the
	// app) and three order creations.
	if httpSpans != 5 || mapped != 5 {
		t.Fatalf("http spans %d mapped %d, want 5/5", httpSpans, mapped)
	}
	orders := 0
	for _, ev := range events {
		for _, leak := range []string{"ORD-000042", "SKU-1001", "anna.rossi", "CUS-000001", "4ddfde76", "nodejs", "json/list", "node.js instance"} {
			if strings.Contains(ev, leak) {
				t.Errorf("event contains %q: %s", leak, ev)
			}
		}
		if !strings.Contains(ev, `"kind":"obi"`) || !strings.Contains(ev, `"dir":"inbound"`) || !strings.Contains(ev, `"service":"shop-api"`) {
			t.Errorf("unexpected event: %s", ev)
		}
		if strings.Contains(ev, `"op":"POST /orders"`) {
			orders++
			for _, want := range []string{`"status":"keep:CREATED"`, `"total":"num:50-100"`, `"qty":"num:0-5"`, `"sampled_by":"subject"`} {
				if !strings.Contains(ev, want) {
					t.Errorf("order event lacks %s: %s", want, ev)
				}
			}
			if strings.Contains(ev, `"card"`) && !strings.Contains(ev, `"card":{"number":"drop:str:l8"}`) {
				t.Errorf("card number not dropped: %s", ev)
			}
		}
	}
	if orders != 3 {
		t.Errorf("order events = %d, want 3", orders)
	}
}

func TestRealOBITLSClientSpansHaveNoExchange(t *testing.T) {
	events, mapped, httpSpans := mappedAll(t, "real_obi_tls_client.json", MapOptions{ServiceName: "shop-api", CaptureLimit: 8192})
	// Per iteration: a CONNECT client span (no HTTP method), a client span
	// without status or body (nothing to describe) and the server span with
	// the decrypted bodies. Only the server side becomes an event.
	if httpSpans != 6 || mapped != 3 {
		t.Fatalf("http spans %d mapped %d, want 6 and 3", httpSpans, mapped)
	}
	for _, ev := range events {
		if !strings.Contains(ev, `"dir":"inbound"`) || strings.Contains(ev, "ORD-000042") {
			t.Errorf("unexpected event: %s", ev)
		}
	}
}

func TestRealOBIServiceFilter(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	sink := newFakeSink(cp)
	br := NewBridge(BridgeConfig{Sink: sink, ServiceFilter: "shop-api"})
	br.Submit(fixture(t, "real_obi_http_server.json")) // OBI named the service "app"
	br.Close()
	if len(sink.all()) != 0 || br.filtered.Load() == 0 {
		t.Fatalf("events %d filtered %d", len(sink.all()), br.filtered.Load())
	}
}

func TestExchangeBytesAreCanonicalAndEqualDirect(t *testing.T) {
	// The first order of the real capture, built by hand for the reference.
	cp := testCapture(t, shopPolicy)
	rs := fixture(t, "real_obi_http_server.json")
	var sp *Span
	for r := range rs {
		for i := range rs[r].ScopeSpans[0].Spans {
			if s := &rs[r].ScopeSpans[0].Spans[i]; sp == nil && s.Name == "POST /orders" {
				sp = s
			}
		}
	}
	m, ok := Map(sp, MapOptions{ServiceName: "shop-api", CaptureLimit: 8192})
	if !ok {
		t.Fatal("not mapped")
	}
	got, _, _ := Exchange(cp, m, time.Now(), nil)
	if m.TraceID != strings.ToLower(sp.TraceID) || m.SpanID != strings.ToLower(sp.SpanID) {
		t.Fatalf("ids not lower-cased: %s %s", m.TraceID, m.SpanID)
	}
	want := direct(t, cp, &sanitizer.Exchange{
		Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/orders"), TraceID: m.TraceID,
		ReqHeaders:  []sanitizer.Header{hdr("content-type", "application/json"), hdr("x-customer-id", "CUS-000001"), hdr("content-length", "108")},
		ReqBody:     []byte(m.Exchange.ReqBody),
		Status:      201,
		RespHeaders: []sanitizer.Header{hdr("content-type", "application/json"), hdr("content-length", "51")},
		RespBody:    []byte(`{"id":"ORD-000042","status":"CREATED","total":79.9}`),
	}, m.Start, m.Latency, m.TraceID, m.SpanID, "")
	if !bytes.Equal(got, want) {
		t.Fatalf("event differs from the direct sanitizer output\n got: %s\nwant: %s", got, want)
	}
}
