package ttsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// shopPolicy: shop-api is an internal inbound service (baggage is trusted),
// the subject is the x-customer-id header, inventory.internal is an
// instrumented internal service that gets tt.s, the carrier is external.
func shopPolicy(rateBP string, trustBaggage bool) string {
	return fmt.Sprintf(`{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"x-customer-id"}},
 "sampling":{"rate":%s,"trust_baggage":%v,"propagate_to":["inventory.internal"]},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}}},
 "services":{
  "shop-api":{"match":{"inbound":true,"internal":true},"ops":{
    "POST /orders":{"request":{"body":{"$.sku":"keep"}},"response":{"$.status":"keep"}},
    "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}},"response":{"$.status":"keep"}},
    "GET /files/{name}":{"response":{"$.status":"keep"}}}},
  "shipping-ext":{"match":{"base":"https://api.carrier.example"},"ops":{
    "POST /v1/shipments":{"request":{"body":{"$.orderId":"hmac(order)"}},"response":{"$.status":"keep"}}}}
 }}`, rateBP, trustBaggage)
}

type event map[string]any

func (e event) str(path ...string) string {
	var cur any = map[string]any(e)
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

func (e event) get(path ...string) any {
	var cur any = map[string]any(e)
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func parseEvents(t testing.TB, raw [][]byte) []event {
	t.Helper()
	var out []event
	for _, b := range raw {
		var e event
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("event is not JSON: %v\n%s", err, b)
		}
		out = append(out, e)
	}
	return out
}

type fixture struct {
	fs *fakeSource
	a  *Agent
}

func newFixture(t *testing.T, author string, mod func(*Config)) *fixture {
	t.Helper()
	fs := &fakeSource{}
	fs.set(captureFor(t, author, "shop-api"), true)
	return &fixture{fs: fs, a: testAgent(t, fs, mod)}
}

// events closes the agent (draining the workers) and returns what was emitted.
func (f *fixture) events(t *testing.T) []event {
	t.Helper()
	drain(t, f.a)
	return parseEvents(t, f.fs.taken())
}

func get(t *testing.T, h http.Handler, method, target string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Add(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestInertAgentIsPassThrough(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	next := &marker{}
	if a.Handler(next) != http.Handler(next) {
		t.Fatal("inert Handler must return next itself")
	}
	if a.Transport(nil) != http.DefaultTransport {
		t.Fatal("inert Transport(nil) must be the default transport")
	}
	rt := &stubRT{}
	if a.Transport(rt) != http.RoundTripper(rt) {
		t.Fatal("inert Transport must return base itself")
	}
	if a.Enabled() || a.Capturing() || a.Stats().State != "disabled" {
		t.Fatal("inert agent reports activity")
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{EnrollToken: "tte_x.y"}); err == nil {
		t.Fatal("token without url must be an error")
	}
	if _, err := New(Config{EnrollURL: "https://core.example:4318"}); err == nil {
		t.Fatal("enrollment without service name must be an error")
	}
	if a, err := New(Config{Disabled: true, EnrollURL: "https://core.example:4318"}); err != nil || a.Enabled() {
		t.Fatal("Disabled must give an inert agent")
	}
}

type marker struct{}

func (*marker) ServeHTTP(http.ResponseWriter, *http.Request) {}

type stubRT struct {
	mu   sync.Mutex
	last *http.Request
	fn   func(*http.Request) (*http.Response, error)
}

func (s *stubRT) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.last = r
	s.mu.Unlock()
	if r.Body != nil { // a real transport sends the whole body
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	if s.fn != nil {
		return s.fn(r)
	}
	return jsonResp(r, 200, `{"status":"OK"}`), nil
}

func jsonResp(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvEnrollURL, " https://core.example:4318 ")
	t.Setenv(EnvEnrollToken, "tte_abc.def")
	t.Setenv(EnvOTelServiceName, "Shop-API")
	t.Setenv(EnvDisabled, "")
	t.Setenv(EnvDebug, "true")
	t.Setenv(EnvHeartbeatMS, "250")
	t.Setenv(EnvPolicyPollMS, "abc")
	c := ConfigFromEnv()
	if c.EnrollURL != "https://core.example:4318" || c.EnrollToken != "tte_abc.def" || c.ServiceName != "shop-api" || !c.Debug || c.Disabled {
		t.Fatalf("config = %+v", c)
	}
	if c.HeartbeatInterval != 250*time.Millisecond || c.PolicyPollInterval != 0 {
		t.Fatalf("intervals = %v %v", c.HeartbeatInterval, c.PolicyPollInterval)
	}
	t.Setenv(EnvServiceName, "explicit")
	if ConfigFromEnv().ServiceName != "explicit" {
		t.Fatal("TT_SERVICE_NAME must win over OTEL_SERVICE_NAME")
	}
}

func TestHandlerCapturesAndDoesNotAlterTheExchange(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	var seenBody string
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seenBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-App", "1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"CREATED","secret":"mario.rossi@example.com"}`))
	}))
	rec := get(t, h, "POST", "/orders?coupon=A1", strings.NewReader(`{"sku":"TSHIRT","note":"hello"}`), "Content-Type", "application/json", "X-Customer-Id", "c-10042")
	if rec.Code != 201 || rec.Header().Get("X-App") != "1" || rec.Body.String() != `{"status":"CREATED","secret":"mario.rossi@example.com"}` {
		t.Fatalf("response altered: %d %v %q", rec.Code, rec.Header(), rec.Body.String())
	}
	if seenBody != `{"sku":"TSHIRT","note":"hello"}` {
		t.Fatalf("request body altered: %q", seenBody)
	}
	evs := f.events(t)
	if len(evs) != 1 {
		t.Fatalf("%d events", len(evs))
	}
	e := evs[0]
	if e.str("dir") != "inbound" || e.str("service") != "shop-api" || e.str("op") != "POST /orders" || e.str("sampled_by") != "subject" ||
		e.get("status") != float64(201) || e.str("source", "kind") != "sdk-go" || e.str("req", "body", "sku") != "keep:TSHIRT" ||
		e.str("resp", "body", "status") != "keep:CREATED" || !strings.HasPrefix(e.str("subject"), "tk1:k1:") {
		t.Fatalf("event = %v", e)
	}
	raw := string(mustJSON(e))
	for _, leak := range []string{"mario", "example.com", "hello", "c-10042", "A1"} {
		if strings.Contains(raw, leak) {
			t.Errorf("event leaks %q: %s", leak, raw)
		}
	}
	if len(e.str("trace_id")) != 32 || len(e.str("span_id")) != 16 {
		t.Errorf("own trace ids missing: %q %q", e.str("trace_id"), e.str("span_id"))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestNetHTTPPatternBecomesFrameworkRoute(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	}
	mux.HandleFunc("GET /orders/{id}", ok)
	mux.HandleFunc("GET /files/{name}/{$}", ok)
	mux.HandleFunc("GET /tree/{rest...}", ok)
	mux.HandleFunc("shop.example/orders/{oid}/lines", ok) // host pattern, other name for the parameter
	h := f.a.Handler(mux)
	get(t, h, "GET", "/orders/ORD-9", nil, "X-Customer-Id", "c1")
	get(t, h, "GET", "/files/report.pdf/", nil, "X-Customer-Id", "c1")
	get(t, h, "GET", "/tree/a/b/c", nil, "X-Customer-Id", "c1")
	get(t, h, "GET", "/nothing/here", nil, "X-Customer-Id", "c1")
	evs := f.events(t)
	if len(evs) != 4 {
		t.Fatalf("%d events", len(evs))
	}
	byOp := map[string]string{}
	for _, e := range evs {
		byOp[e.str("op")] = e.str("route_source")
	}
	// The mux pattern decides: the same literal in the policy is found through
	// the framework (route_source=framework), a {rest...} wildcard is not
	// normalizable and falls back to the policy templates, a 404 has no
	// pattern at all.
	if byOp["GET /orders/{id}"] != "framework" {
		t.Errorf("orders: %v", byOp)
	}
	if byOp["GET /files/{name}"] != "framework" {
		t.Errorf("files with {$}: %v", byOp)
	}
	for op, src := range byOp {
		if strings.HasPrefix(op, "GET /tree") || strings.HasPrefix(op, "GET /nothing") {
			if src != "raw" {
				t.Errorf("%s: route_source %s, want raw", op, src)
			}
		}
	}
}

func TestPatternRoute(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "/": "/", "GET /orders/{id}": "/orders/{id}", "POST  /a/{b}/{$}": "/a/{b}/{$}",
		"example.com/x": "/x", "GET example.com/x/{y...}": "/x/{y...}", "GET": "",
	} {
		if got := patternRoute(in); got != want {
			t.Errorf("patternRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOutboundInheritsDecisionAndLinksTrace(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	rt := &stubRT{}
	client := &http.Client{Transport: f.a.Transport(rt)}
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), "POST", "https://api.carrier.example/v1/shipments", strings.NewReader(`{"orderId":"ORD-1"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		// A call made without the request context is a different flow.
		req2, _ := http.NewRequest("POST", "https://api.carrier.example/v1/shipments", strings.NewReader(`{"orderId":"ORD-2"}`))
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(req2)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp2.Body)
			_ = resp2.Body.Close()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	}))
	get(t, h, "POST", "/orders", strings.NewReader(`{"sku":"A"}`), "Content-Type", "application/json", "X-Customer-Id", "c1",
		"Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	evs := f.events(t)
	if len(evs) != 3 {
		t.Fatalf("%d events", len(evs))
	}
	var in, linked, free event
	for _, e := range evs {
		switch {
		case e.str("dir") == "inbound":
			in = e
		case e.str("sampled_by") == "inherited":
			linked = e
		default:
			free = e
		}
	}
	if in == nil || linked == nil || free == nil {
		t.Fatalf("events: %v", evs)
	}
	if in.str("trace_id") != "4bf92f3577b34da6a3ce929d0e0e4736" || in.str("parent_span_id") != "00f067aa0ba902b7" || len(in.str("span_id")) != 16 {
		t.Errorf("inbound trace: %v", in)
	}
	if linked.str("trace_id") != in.str("trace_id") || linked.str("parent_span_id") != in.str("span_id") || linked.str("span_id") == in.str("span_id") {
		t.Errorf("outbound not linked to inbound: %v / %v", linked, in)
	}
	if linked.str("service") != "shipping-ext" || linked.str("op") != "POST /v1/shipments" {
		t.Errorf("outbound event: %v", linked)
	}
	if free.str("sampled_by") != "random" || free.str("trace_id") == in.str("trace_id") {
		t.Errorf("a call without the request context must not be linked: %v", free)
	}
	// The SDK never injects traceparent: the app's requests are untouched.
	if rt.last.Header.Get("Traceparent") != "" {
		t.Error("traceparent was injected")
	}
}

func TestUnsampledInboundMakesOutboundInheritNo(t *testing.T) {
	f := newFixture(t, shopPolicy("0", false), nil)
	client := &http.Client{Transport: f.a.Transport(&stubRT{})}
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), "POST", "https://api.carrier.example/v1/shipments", strings.NewReader(`{}`))
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}))
	get(t, h, "POST", "/orders", strings.NewReader(`{}`), "X-Customer-Id", "c1")
	if evs := f.events(t); len(evs) != 0 {
		t.Fatalf("rate 0 captured %d events", len(evs))
	}
	if f.fs.counters.ExchangesSeen.Load() != 2 || f.fs.counters.ExchangesSampled.Load() != 0 {
		t.Fatalf("counters seen/sampled = %d/%d", f.fs.counters.ExchangesSeen.Load(), f.fs.counters.ExchangesSampled.Load())
	}
}

func TestSamplingIsPerSubjectAndStable(t *testing.T) {
	f := newFixture(t, shopPolicy("0.5", false), nil)
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	decided := map[string]bool{}
	const users, rounds = 200, 3
	for round := 0; round < rounds; round++ {
		for u := 0; u < users; u++ {
			get(t, h, "GET", "/orders/1", nil, "X-Customer-Id", fmt.Sprintf("user-%d", u))
		}
	}
	evs := f.events(t)
	perUser := map[string]int{}
	for _, e := range evs {
		if e.str("sampled_by") != "subject" {
			t.Fatalf("sampled_by = %s", e.str("sampled_by"))
		}
		perUser[e.str("subject")]++
	}
	for u, n := range perUser {
		if n != rounds {
			t.Fatalf("subject %s sampled %d times of %d: the decision is not stable", u, n, rounds)
		}
		decided[u] = true
	}
	if len(decided) < users*30/100 || len(decided) > users*70/100 {
		t.Fatalf("%d of %d users sampled at 50%%", len(decided), users)
	}
}

func TestBaggageRules(t *testing.T) {
	// D-M8: tt.s decides only on a service declared internal and only with
	// trust_baggage.
	cases := []struct {
		name         string
		rate         string
		trust        bool
		service      string
		baggage      string
		wantSampled  bool
		wantSampleBy string
	}{
		{"trusted tt.s=0 beats rate 1", "1", true, "shop-api", "a=b, tt.s=0", false, ""},
		{"trusted tt.s=1 beats rate 0", "0", true, "shop-api", "tt.s=1;prop=x,a=b", true, "baggage"},
		{"first valid tt.s wins", "0", true, "shop-api", "tt.s=1,tt.s=0", true, "baggage"},
		{"invalid tt.s ignored", "1", true, "shop-api", "tt.s=2", true, "random"},
		{"not trusted by policy", "0", false, "shop-api", "tt.s=1", false, ""},
		{"edge service never trusts it", "0", true, "edge-api", "tt.s=1", false, ""},
		{"edge service can not avoid capture", "1", true, "edge-api", "tt.s=0", true, "random"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := &fakeSource{}
			fs.set(captureFor(t, shopPolicy(c.rate, c.trust), c.service), true)
			a := testAgent(t, fs, nil)
			get(t, a.Handler(&marker{}), "GET", "/orders/1", nil, "Baggage", c.baggage)
			drain(t, a)
			evs := parseEvents(t, fs.taken())
			if (len(evs) == 1) != c.wantSampled {
				t.Fatalf("sampled = %v, want %v", len(evs) == 1, c.wantSampled)
			}
			if c.wantSampled && evs[0].str("sampled_by") != c.wantSampleBy {
				t.Fatalf("sampled_by = %s, want %s", evs[0].str("sampled_by"), c.wantSampleBy)
			}
		})
	}
}

func TestPropagationOfTTBaggage(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	rt := &stubRT{}
	client := &http.Client{Transport: f.a.Transport(rt)}
	var inboundCtx context.Context
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { inboundCtx = r.Context() }))
	get(t, h, "GET", "/orders/1", nil, "X-Customer-Id", "c1")

	do := func(ctx context.Context, url string, hdr ...string) *http.Request {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Add(hdr[i], hdr[i+1])
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return rt.last
	}
	// Towards a propagate_to host: added, in front, other members untouched.
	if got := do(inboundCtx, "http://inventory.internal/stock", "Baggage", "userId=42,region=eu").Header.Get("Baggage"); got != "tt.s=1,userId=42,region=eu" {
		t.Errorf("baggage = %q", got)
	}
	if got := do(inboundCtx, "http://inventory.internal:80/stock").Header.Get("Baggage"); got != "tt.s=1" {
		t.Errorf("baggage (default port) = %q", got)
	}
	// A forged tt.s forwarded by the app can not override ours (first wins).
	if got := do(inboundCtx, "http://inventory.internal/stock", "Baggage", "tt.s=0").Header.Get("Baggage"); got != "tt.s=1,tt.s=0" {
		t.Errorf("baggage = %q", got)
	}
	// Never towards an external service of the policy, nor towards unlisted hosts.
	if got := do(inboundCtx, "https://api.carrier.example/v1/x", "Baggage", "a=b").Header.Get("Baggage"); got != "a=b" {
		t.Errorf("external baggage = %q", got)
	}
	if got := do(inboundCtx, "http://other.internal/x").Header.Get("Baggage"); got != "" {
		t.Errorf("unlisted baggage = %q", got)
	}
	// Without an inbound context there is no decision to propagate.
	if got := do(context.Background(), "http://inventory.internal/stock").Header.Get("Baggage"); got != "" {
		t.Errorf("no context baggage = %q", got)
	}
	// The caller's request is not modified.
	req, _ := http.NewRequestWithContext(inboundCtx, "GET", "http://inventory.internal/stock", nil)
	req.Header.Set("Baggage", "k=v")
	resp, _ := client.Do(req)
	_ = resp.Body.Close()
	if req.Header.Get("Baggage") != "k=v" {
		t.Errorf("the application's request was modified: %q", req.Header.Get("Baggage"))
	}
}

func TestFailClosed(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	var ran int
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ran++; _, _ = w.Write([]byte("ok")) }))
	f.fs.set(sourceclient.Capture{}, false) // no policy / key / heartbeat, kill switch...
	rec := get(t, h, "GET", "/orders/1", nil, "X-Customer-Id", "c1")
	if rec.Body.String() != "ok" || ran != 1 {
		t.Fatal("the application must keep working")
	}
	if evs := f.events(t); len(evs) != 0 {
		t.Fatalf("captured %d events while inactive", len(evs))
	}
}

func TestSanitizerPanicOrErrorNeverBreaksTheApp(t *testing.T) {
	fs := &fakeSource{}
	c := captureFor(t, shopPolicy("1", true), "shop-api")
	c.Kind = "not-a-kind" // BuildEvent refuses it: no event, sanitizer_errors
	fs.set(c, true)
	a := testAgent(t, fs, nil)
	rec := get(t, a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fine")) })), "GET", "/orders/1", nil)
	drain(t, a)
	if rec.Body.String() != "fine" || len(fs.taken()) != 0 || fs.counters.SanitizerErrors.Load() != 1 {
		t.Fatalf("body %q events %d errors %d", rec.Body.String(), len(fs.taken()), fs.counters.SanitizerErrors.Load())
	}
}

func TestHandlerPanicAbandonsTheExchangeAndPropagates(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) }))
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("the panic must propagate unchanged")
			}
		}()
		get(t, h, "GET", "/orders/1", nil)
	}()
	if evs := f.events(t); len(evs) != 0 {
		t.Fatal("an aborted exchange must not produce an event")
	}
	if f.a.inflight.Load() != 0 {
		t.Fatalf("inflight = %d", f.a.inflight.Load())
	}
}

func TestBodiesAreBoundedAndTruncated(t *testing.T) {
	author := strings.Replace(shopPolicy("1", true), `"sampling"`, `"limits":{"max_body_bytes":1024},"sampling"`, 1)
	f := newFixture(t, author, nil)
	var seen int
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		seen = int(n)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
	}))
	big := `{"sku":"` + strings.Repeat("a", 1<<20) + `"}`
	rec := get(t, h, "POST", "/orders", strings.NewReader(big), "Content-Type", "application/json")
	if seen != len(big) || rec.Body.Len() != 1<<20 {
		t.Fatalf("the exchange was truncated for the app: %d %d", seen, rec.Body.Len())
	}
	evs := f.events(t)
	if len(evs) != 1 || evs[0].str("req", "body") != "trunc:size" || evs[0].str("req", "size") != "lmax" || evs[0].str("resp", "body") != "trunc:size" {
		t.Fatalf("events = %v", evs)
	}
}

func TestUnreadRequestBodyIsReportedNotConsumed(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	get(t, h, "POST", "/orders", strings.NewReader(`{"sku":"A"}`), "Content-Type", "application/json")
	evs := f.events(t)
	if len(evs) != 1 || evs[0].str("req", "body") != "trunc:size" {
		t.Fatalf("events = %v", evs)
	}
}

func TestSlowPipelineNeverBlocksTheApp(t *testing.T) {
	// The exporter side is stuck: Emit blocks. Workers fill up, the bounded
	// queue drops whole events and counts them; requests are never delayed.
	release := make(chan struct{})
	fs := &fakeSource{}
	fs.set(captureFor(t, shopPolicy("1", true), "shop-api"), true)
	blocked := &blockingSource{fakeSource: fs, release: release}
	a := newAgent(Config{Workers: 1, QueueSize: 2})
	a.attach(blocked)
	t.Cleanup(func() {
		close(release)
		drain(t, a)
	})
	h := a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	start := time.Now()
	for i := 0; i < 200; i++ {
		if rec := get(t, h, "GET", "/orders/1", nil); rec.Body.String() != "ok" {
			t.Fatal("bad response")
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("200 requests took %v with a stuck pipeline", d)
	}
	if fs.counters.EventsDroppedQueue.Load() < 100 {
		t.Fatalf("dropped = %d, want most of the events", fs.counters.EventsDroppedQueue.Load())
	}
}

type blockingSource struct {
	*fakeSource
	release chan struct{}
}

func (b *blockingSource) Emit(ev sourceclient.Event) {
	<-b.release
	b.fakeSource.Emit(ev)
}

func TestMaxInflightDropsEvents(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), func(c *Config) { c.MaxInflight = 1 })
	gate, entered := make(chan struct{}), make(chan struct{})
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orders/slow" {
			close(entered)
			<-gate
		}
	}))
	done := make(chan struct{})
	go func() { get(t, h, "GET", "/orders/slow", nil); close(done) }()
	<-entered
	get(t, h, "GET", "/orders/fast", nil) // second concurrent exchange: over the bound
	close(gate)
	<-done
	evs := f.events(t)
	if len(evs) != 1 || f.fs.counters.EventsDroppedQueue.Load() != 1 {
		t.Fatalf("events %d dropped %d", len(evs), f.fs.counters.EventsDroppedQueue.Load())
	}
}

func TestStreamingAndInterfacesSurvive(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Error("Flusher lost")
		}
		rc := http.NewResponseController(w)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("one"))
		if err := rc.Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
		_, _ = w.Write([]byte("two"))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/orders/1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "onetwo" {
		t.Fatalf("body %q", b)
	}
	if evs := f.events(t); len(evs) != 1 || evs[0].get("status") != float64(200) {
		t.Fatalf("events %v", evs)
	}
}

func TestSniffedContentTypeMatchesTheServer(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	h := f.a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"OK"}`)) // no Content-Type: the server sniffs text/plain
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/orders/1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	wire := resp.Header.Get("Content-Type")
	evs := f.events(t)
	if len(evs) != 1 {
		t.Fatalf("events %v", evs)
	}
	// The policy keeps content-type: the event shows what the client got.
	if want := "keep:" + wire; evs[0].get("resp", "headers", "content-type") == nil || evs[0].get("resp", "headers", "content-type").([]any)[0] != want {
		t.Fatalf("content-type in event %v, wire %q", evs[0].get("resp", "headers"), wire)
	}
}

func TestTransportClassifiesErrorsAndKeepsResponse(t *testing.T) {
	f := newFixture(t, shopPolicy("1", true), nil)
	rt := &stubRT{fn: func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "boom") {
			return nil, context.DeadlineExceeded
		}
		return jsonResp(r, 201, `{"status":"CREATED"}`), nil
	}}
	tr := f.a.Transport(rt)
	req, _ := http.NewRequest("POST", "https://api.carrier.example/v1/shipments", strings.NewReader(`{"orderId":"ORD-5"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.Request != req {
		t.Fatalf("err %v req %v", err, resp.Request == req)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != `{"status":"CREATED"}` || resp.StatusCode != 201 {
		t.Fatalf("response altered: %d %s", resp.StatusCode, b)
	}
	req2, _ := http.NewRequest("POST", "https://api.carrier.example/v1/boom", nil)
	if _, err := tr.RoundTrip(req2); err != context.DeadlineExceeded {
		t.Fatalf("error not returned unchanged: %v", err)
	}
	evs := f.events(t)
	if len(evs) != 2 {
		t.Fatalf("%d events", len(evs))
	}
	var ok, bad event
	for _, e := range evs {
		if e.get("net_error") != nil {
			bad = e
		} else {
			ok = e
		}
	}
	if ok.str("op") != "POST /v1/shipments" || ok.str("resp", "body", "status") != "keep:CREATED" || !strings.HasPrefix(ok.str("req", "body", "orderId"), "tk1:k1:") {
		t.Errorf("ok event %v", ok)
	}
	if bad.str("net_error") != "timeout" || bad.get("resp") != nil {
		t.Errorf("error event %v", bad)
	}
}

func TestOuterMiddlewareStillSeesTheMuxPattern(t *testing.T) {
	// The mux sets Request.Pattern on the request it receives, which is the
	// copy the SDK passes down; middleware outside the SDK (otelhttp names its
	// span with it) must see the pattern on its own request.
	for _, rate := range []string{"1", "0"} { // sampled and not sampled
		f := newFixture(t, shopPolicy(rate, true), nil)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, r *http.Request) {})
		inner := f.a.Handler(mux)
		var seen string
		outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner.ServeHTTP(w, r)
			seen = r.Pattern
		})
		get(t, outer, "GET", "/orders/7", nil, "X-Customer-Id", "c1")
		if seen != "GET /orders/{id}" {
			t.Errorf("rate %s: outer middleware saw pattern %q", rate, seen)
		}
	}
}

func TestTransportDoesNotWaitForTheBodyReader(t *testing.T) {
	// The event is produced when the body is closed, even if the app stopped
	// reading half way.
	f := newFixture(t, shopPolicy("1", true), nil)
	tr := f.a.Transport(&stubRT{})
	req, _ := http.NewRequest("GET", "https://api.carrier.example/v1/shipments", nil)
	resp, _ := tr.RoundTrip(req)
	_, _ = resp.Body.Read(make([]byte, 3))
	_ = resp.Body.Close()
	_ = resp.Body.Close() // idempotent
	evs := f.events(t)
	if len(evs) != 1 || evs[0].str("resp", "body") != "trunc:size" {
		t.Fatalf("events %v", evs)
	}
}
