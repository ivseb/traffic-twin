package obi

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

var (
	t0 = time.Unix(0, 1792404000412000000).UTC()
)

// rawSecrets are values that appear in the fixtures and must never leave.
var rawSecrets = []string{"anna.rossi@example.com", "ORD-000042", "ORD-000043", "SHP-777", "CUS-000001", "SKU-1001", "Milano"}

func noRaw(t *testing.T, ev []byte) {
	t.Helper()
	for _, s := range rawSecrets {
		if bytes.Contains(ev, []byte(s)) {
			t.Errorf("event contains the raw value %q: %s", s, ev)
		}
	}
}

func TestInboundSpanEqualsDirectSanitizer(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	rs := fixture(t, "server_post_orders.json")
	got, m := viaBridge(t, cp, rs, 0, 8192)

	want := direct(t, cp, &sanitizer.Exchange{
		Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: "POST", RawPath: []byte("/orders"),
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		ReqHeaders: []sanitizer.Header{hdr("content-type", "application/json"), hdr("content-length", "112"),
			hdr("x-customer-id", "CUS-000001")},
		ReqBody:     []byte(`{"items":[{"sku":"SKU-1001","qty":2}],"email":"anna.rossi@example.com","card":{"number":"***"}}`),
		Status:      201,
		RespHeaders: []sanitizer.Header{hdr("content-type", "application/json; charset=utf-8")},
		RespBody:    []byte(`{"id":"ORD-000042","status":"CREATED","total":79.9}`),
	}, t0, 184*time.Millisecond, "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", "")
	if !bytes.Equal(got, want) {
		t.Fatalf("event differs from the direct sanitizer output\n got: %s\nwant: %s", got, want)
	}
	noRaw(t, got)
	s := string(got)
	for _, frag := range []string{`"source":{"id":"src-01TESTOBI","kind":"obi","version":"0.1.0"}`, `"dir":"inbound"`, `"op":"POST /orders"`,
		`"service":"shop-api"`, `"status":201`, `"latency_ms":184`, `"sampled_by":"subject"`, `"total":"num:50-100"`, `"status":"keep:CREATED"`} {
		if !strings.Contains(s, frag) {
			t.Errorf("event lacks %s: %s", frag, s)
		}
	}
	if m.BodyBytes == 0 {
		t.Error("body bytes not accounted")
	}
}

func TestOutboundSpanEqualsDirectSanitizer(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	rs := fixture(t, "client_post_shipments.json")
	got, _ := viaBridge(t, cp, rs, 0, 8192)

	want := direct(t, cp, &sanitizer.Exchange{
		Dir: sanitizer.Outbound, URLBase: "https://api.carrier.example", Method: "POST", RawPath: []byte("/v1/shipments"),
		TraceID:     "4bf92f3577b34da6a3ce929d0e0e4736",
		ReqHeaders:  []sanitizer.Header{hdr("content-type", "application/json")},
		ReqBody:     []byte(`{"orderId":"ORD-000042","address":{"city":"Milano"}}`),
		Status:      200,
		RespHeaders: []sanitizer.Header{hdr("content-type", "application/json")},
		RespBody:    []byte(`{"shipmentId":"SHP-777","status":"LABEL_CREATED"}`),
	}, time.Unix(0, 1792404000450000000).UTC(), 80*time.Millisecond, "4bf92f3577b34da6a3ce929d0e0e4736", "b7ad6b7169203331", "00f067aa0ba902b7")
	if !bytes.Equal(got, want) {
		t.Fatalf("event differs from the direct sanitizer output\n got: %s\nwant: %s", got, want)
	}
	noRaw(t, got)
	if s := string(got); !strings.Contains(s, `"dir":"outbound"`) || !strings.Contains(s, `"service":"shipping-ext"`) ||
		!strings.Contains(s, `"parent_span_id":"00f067aa0ba902b7"`) || !strings.Contains(s, `"status":"keep:LABEL_CREATED"`) {
		t.Errorf("unexpected event: %s", s)
	}
}

func TestTransportErrorSpan(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	rs := fixture(t, "client_refused.json")
	got, _ := viaBridge(t, cp, rs, 0, 8192)
	want := direct(t, cp, &sanitizer.Exchange{
		Dir: sanitizer.Outbound, URLBase: "https://api.carrier.example", Method: "GET", RawPath: []byte("/v1/shipments/SHP-777"),
		TraceID: "0af7651916cd43dd8448eb211c80319c", NetError: "refused",
	}, time.Unix(0, 1792404001000000000).UTC(), 3*time.Millisecond, "0af7651916cd43dd8448eb211c80319c", "00f067aa0ba902b8", "")
	if !bytes.Equal(got, want) {
		t.Fatalf("event differs\n got: %s\nwant: %s", got, want)
	}
	noRaw(t, got)
	if !strings.Contains(string(got), `"net_error":"refused"`) || strings.Contains(string(got), `"resp"`) {
		t.Errorf("unexpected event: %s", got)
	}
}

func TestTruncatedAndNonJSONBodies(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	rs := fixture(t, "server_get_order_text.json")

	// 40000 bytes announced, 8192 captured: the JSON is cut, only trunc:size.
	got, _ := viaBridge(t, cp, rs, 0, 8192)
	want := direct(t, cp, &sanitizer.Exchange{
		Dir: sanitizer.Inbound, ServiceName: "shop-api", Method: "GET", RawPath: []byte("/orders/ORD-000042"), RawQuery: []byte("expand=items"),
		TraceID: "5b8aa5a2d2c872e8321cf37308d69df2", Status: 200,
		RespHeaders:   []sanitizer.Header{hdr("content-type", "application/json"), hdr("content-length", "40000")},
		RespBody:      []byte(`{"id":"ORD-000042","items":[{"sku":"SKU-10`),
		RespBodyTotal: 40000,
	}, time.Unix(0, 1792404002000000000).UTC(), 12*time.Millisecond, "5b8aa5a2d2c872e8321cf37308d69df2", "051581bf3cb55c13", "")
	if !bytes.Equal(got, want) {
		t.Fatalf("event differs\n got: %s\nwant: %s", got, want)
	}
	if !strings.Contains(string(got), `"body":"trunc:size"`) {
		t.Errorf("a cut JSON body must give trunc:size: %s", got)
	}
	noRaw(t, got)

	// text/plain: shape only.
	got, _ = viaBridge(t, cp, rs, 1, 8192)
	if !strings.Contains(string(got), `"body":"drop:bytes:l128"`) {
		t.Errorf("non-JSON body must give drop:bytes:<class>: %s", got)
	}
	noRaw(t, got)
}

func TestUnknownSizeFillingTheBufferIsTruncated(t *testing.T) {
	// No size attribute and a body as long as the OBI buffer: it may have
	// been cut, so the length is unknown.
	sp := &Span{Kind: kindServer, StartNano: 1792404000412000000, EndNano: 1792404000413000000, Attributes: []keyValue{
		attr("http.request.method", "POST"), attr("url.path", "/orders"), attrInt("http.response.status_code", 200),
		attr("http.request.header.content-type", "application/json"),
		attr("http.request.body.content", `{"items":[{"qty":1}]}`+strings.Repeat(" ", 20)),
	}}
	m, ok := Map(sp, MapOptions{ServiceName: "shop-api", CaptureLimit: 41})
	if !ok || m.Exchange.ReqBodyTotal != sanitizer.UnknownLength {
		t.Fatalf("ok=%v total=%d, want UnknownLength", ok, m.Exchange.ReqBodyTotal)
	}
	m, _ = Map(sp, MapOptions{ServiceName: "shop-api", CaptureLimit: 4096})
	if m.Exchange.ReqBodyTotal != 0 {
		t.Fatalf("total = %d, want 0 (whole body)", m.Exchange.ReqBodyTotal)
	}
	// A known size without the body text: shape only.
	sp.Attributes = []keyValue{attr("http.request.method", "POST"), attr("url.path", "/orders"), attrInt("http.response.status_code", 200),
		attr("http.request.header.content-type", "application/json"), attrInt("http.request.body.size", 900)}
	m, _ = Map(sp, MapOptions{ServiceName: "shop-api", CaptureLimit: 4096})
	if len(m.Exchange.ReqBody) != 0 || m.Exchange.ReqBodyTotal != 900 {
		t.Fatalf("body %q total %d", m.Exchange.ReqBody, m.Exchange.ReqBodyTotal)
	}
}

func attr(k, v string) keyValue { return keyValue{Key: k, Value: anyValue{StringValue: &v}} }
func attrInt(k string, v int64) keyValue {
	n := flexInt(v)
	return keyValue{Key: k, Value: anyValue{IntValue: &n}}
}

func TestOlderSemconvAndMissingParts(t *testing.T) {
	sp := &Span{Kind: kindClient, TraceID: "00000000000000000000000000000000", StartNano: 1792404000000000000, EndNano: 1792404000050000000, Attributes: []keyValue{
		attr("http.method", "GET"), attr("http.url", "http://carrier.internal:8080/v1/x?a=1"), attrInt("http.status_code", 502),
	}}
	m, ok := Map(sp, MapOptions{ServiceName: "shop-api"})
	if !ok {
		t.Fatal("not mapped")
	}
	ex := m.Exchange
	if ex.Dir != sanitizer.Outbound || ex.URLBase != "http://carrier.internal:8080" || string(ex.RawPath) != "/v1/x" || string(ex.RawQuery) != "a=1" || ex.Status != 502 {
		t.Fatalf("exchange = %+v", ex)
	}
	if m.TraceID != "" || ex.TraceID != "" {
		t.Fatal("an all-zero trace id must be ignored")
	}
	// Neither status nor error: nothing to describe.
	sp.Attributes = []keyValue{attr("http.method", "GET"), attr("url.path", "/")}
	if _, ok := Map(sp, MapOptions{}); ok {
		t.Fatal("span without status or error was mapped")
	}
	// Not HTTP, or an internal span.
	if _, ok := Map(&Span{Kind: kindInternal, Attributes: []keyValue{attr("http.method", "GET")}}, MapOptions{}); ok {
		t.Fatal("internal span mapped")
	}
	// A scheme-less client span on port 443 is https.
	sp = &Span{Kind: kindClient, StartNano: 1, Attributes: []keyValue{attr("http.request.method", "GET"), attr("server.address", "API.Carrier.example"),
		attrInt("server.port", 443), attr("url.path", "/v1/x"), attrInt("http.response.status_code", 200)}}
	if m, _ := Map(sp, MapOptions{}); m.Exchange.URLBase != "https://API.Carrier.example:443" {
		t.Fatalf("url base = %q", m.Exchange.URLBase)
	}
}

func TestIDsBase64Tolerated(t *testing.T) {
	if got := normID("S/kvNXezTaajzpKdDg5HNg==", 16); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("base64 trace id = %q", got)
	}
	if normID("zz", 16) != "" || normID("4bf92f3577b34da6a3ce929d0e0e47zz", 16) != "" {
		t.Fatal("garbage id accepted")
	}
}

func post(h http.Handler, ct, enc string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/traces", bytes.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	if enc != "" {
		r.Header.Set("Content-Encoding", enc)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func TestReceiverEndToEndWithFakeSink(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	sink := newFakeSink(cp)
	br := NewBridge(BridgeConfig{Sink: sink, ServiceFilter: "shop-api", CaptureLimit: 8192})
	defer br.Close()
	h := br.Handler()

	for _, f := range []string{"server_post_orders.json", "client_post_shipments.json", "client_refused.json"} {
		if w := post(h, "application/json", "", fixtureBytes(t, f)); w.Code != 200 {
			t.Fatalf("%s: status %d", f, w.Code)
		}
	}
	// Gzip, and a charset on the content type.
	if w := post(h, "application/json; charset=utf-8", "gzip", gz(t, fixtureBytes(t, "server_get_order_text.json"))); w.Code != 200 {
		t.Fatalf("gzip: status %d", w.Code)
	}
	// 3 + the two HTTP spans of the last file (the SQL span is ignored).
	waitFor(t, "5 events", func() bool { return len(sink.all()) == 5 })
	for _, ev := range sink.all() {
		noRaw(t, []byte(ev))
		if !strings.Contains(ev, `"kind":"obi"`) {
			t.Errorf("not an obi event: %s", ev)
		}
	}
	c := sink.counters.Snapshot()
	if c.ExchangesSeen != 5 || c.ExchangesSampled != 5 || c.SanitizerErrors != 0 {
		t.Errorf("counters = %+v", c)
	}

	// The same bytes as the mapping gives directly.
	rs := fixture(t, "server_post_orders.json")
	want, _ := viaBridge(t, cp, rs, 0, 8192)
	found := false
	for _, ev := range sink.all() {
		if ev == string(want) {
			found = true
		}
	}
	if !found {
		t.Errorf("the receiver did not produce the mapped event %s", want)
	}

	// Protobuf is refused with a pointer to the fix.
	w := post(h, "application/x-protobuf", "", []byte{0x0a, 0x00})
	if w.Code != http.StatusUnsupportedMediaType || !strings.Contains(w.Body.String(), "http/json") {
		t.Errorf("protobuf: %d %s", w.Code, w.Body.String())
	}
	// Malformed JSON: 400, and the error does not echo the payload.
	w = post(h, "application/json", "", []byte(`{"resourceSpans": [secret-looking-text`))
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "secret") {
		t.Errorf("malformed: %d %s", w.Code, w.Body.String())
	}
	// Another service on the same host is not ours.
	other := bytes.ReplaceAll(fixtureBytes(t, "server_post_orders.json"), []byte(`"stringValue": "shop-api"`), []byte(`"stringValue": "billing"`))
	before := len(sink.all())
	post(h, "application/json", "", other)
	time.Sleep(50 * time.Millisecond)
	if len(sink.all()) != before {
		t.Error("a span of another service was captured")
	}
	// Kill switch / no policy: accepted but not even parsed, no event.
	sink.setActive(false)
	post(h, "application/json", "", fixtureBytes(t, "server_post_orders.json"))
	time.Sleep(50 * time.Millisecond)
	if len(sink.all()) != before {
		t.Error("captured while the source is not active")
	}
}

func TestOverloadDropsInsteadOfBlocking(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	sink := newFakeSink(cp)
	var once sync.Once
	gate := make(chan struct{})
	br := NewBridge(BridgeConfig{Sink: sink, Workers: 1, QueueSize: 2, OnSanitize: func() { once.Do(func() { <-gate }) }})
	h := br.Handler()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			post(h, "application/json", "", fixtureBytes(t, "server_post_orders.json"))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver blocked on a full queue")
	}
	if sink.counters.EventsDroppedQueue.Load() == 0 {
		t.Error("no drop counted")
	}
	close(gate)
	br.Close()
}

func TestSanitizerPanicOrErrorGivesNoEvent(t *testing.T) {
	cp := testCapture(t, shopPolicy)
	sink := newFakeSink(cp)
	br := NewBridge(BridgeConfig{Sink: sink, OnSanitize: func() { panic("boom") }})
	post(br.Handler(), "application/json", "", fixtureBytes(t, "server_post_orders.json"))
	br.Close()
	if len(sink.all()) != 0 || sink.counters.SanitizerErrors.Load() != 1 {
		t.Fatalf("events=%d sanitizer_errors=%d", len(sink.all()), sink.counters.SanitizerErrors.Load())
	}
}

// TestWithFleetSource drives a real sourceclient.Source against the fake
// tt-core: enrollment as kind "obi", signed policy, OTLP/JSON log export.
func TestWithFleetSource(t *testing.T) {
	core := fakecore.New(t, "shop")
	keys, kids := fakecore.HMACKeys()
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: core.URL, Token: core.Token, StateDir: t.TempDir(),
		Kind: "obi", Version: "0.1.0", ServiceName: "shop-api", Keys: keys, KeyKids: kids,
		HeartbeatInterval: 30 * time.Millisecond, PolicyPollInterval: 30 * time.Millisecond,
		Exporter: sourceclient.ExporterOptions{FlushInterval: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	src.Start(ctx)
	defer func() {
		cctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = src.Close(cctx)
		cancel()
	}()
	br := NewBridge(BridgeConfig{Sink: src, CaptureLimit: 8192})
	defer br.Close()
	h := br.Handler()

	// No policy yet: nothing is captured.
	post(h, "application/json", "", fixtureBytes(t, "server_post_orders.json"))
	time.Sleep(100 * time.Millisecond)
	if len(core.Events()) != 0 {
		t.Fatal("event exported without a policy")
	}

	core.SetPolicy(core.Compile(shopPolicy, 1, 1))
	core.Eventually(5*time.Second, "capture active", func() bool { _, ok := src.Active(); return ok })
	post(h, "application/json", "", fixtureBytes(t, "server_post_orders.json"))
	post(h, "application/json", "", fixtureBytes(t, "client_post_shipments.json"))
	evs := core.WaitEvents(2, 5*time.Second)
	for _, ev := range evs {
		noRaw(t, ev)
		if !bytes.Contains(ev, []byte(`"kind":"obi"`)) {
			t.Errorf("not an obi event: %s", ev)
		}
	}

	// Kill switch: the bridge stops producing events.
	core.Kill(true)
	core.Eventually(5*time.Second, "capture stopped", func() bool { _, ok := src.Active(); return !ok })
	n := len(core.Events())
	post(h, "application/json", "", fixtureBytes(t, "server_post_orders.json"))
	time.Sleep(150 * time.Millisecond)
	if len(core.Events()) != n {
		t.Fatal("event exported with the kill switch on")
	}
}
