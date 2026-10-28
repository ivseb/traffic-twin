package otelctx_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
	ttsdk "github.com/ivseb/traffic-twin/sdk/go"
	"github.com/ivseb/traffic-twin/sdk/go/otelctx"
)

// The OpenTelemetry Go SDK is a test-only dependency here: it drives a real
// instrumented application (otelhttp server and client) with and without the
// traffic-twin SDK and checks that the application's traces and traffic are
// exactly the same, and that the events use the application's own ids.

const (
	incomingTrace  = "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingParent = "00f067aa0ba902b7"
)

const policyJSON = `{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "sampling":{"rate":1},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}}},
 "segments":{"hosts_allow":["127.0.0.1"]},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"request":{"body":{"$.sku":"keep"}},"response":{"$.status":"keep"}}}}}}`

type normSpan struct {
	Name, Kind, Status string
	Parent             int // index in the sorted list, -1: remote or none
	Attrs              []string
	Events             int
}

type result struct {
	spans    []normSpan
	rawSpans []sdktrace.ReadOnlySpan
	upstream http.Header // what the carrier received
	body     string      // what the client of the shop received
	status   int
}

// stable attributes: the ones that do not contain a random port or address.
var stableAttr = map[string]bool{"http.request.method": true, "http.response.status_code": true, "url.path": true, "app.k": true, "http.route": true}

func normalize(spans []sdktrace.ReadOnlySpan) []normSpan {
	sort.Slice(spans, func(i, j int) bool { return spans[i].Name() < spans[j].Name() })
	idx := map[trace.SpanID]int{}
	for i, s := range spans {
		idx[s.SpanContext().SpanID()] = i
	}
	var out []normSpan
	for _, s := range spans {
		n := normSpan{Name: s.Name(), Kind: s.SpanKind().String(), Status: s.Status().Code.String(), Parent: -1, Events: len(s.Events())}
		if p, ok := idx[s.Parent().SpanID()]; ok {
			n.Parent = p
		}
		for _, kv := range s.Attributes() {
			if stableAttr[string(kv.Key)] {
				n.Attrs = append(n.Attrs, fmt.Sprintf("%s=%v", kv.Key, kv.Value.Emit()))
			}
		}
		sort.Strings(n.Attrs)
		out = append(out, n)
	}
	return out
}

// scenario runs the instrumented shop once. agent is nil for the control run.
func scenario(t *testing.T, agent *ttsdk.Agent) result {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)) // never made global
	prop := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

	var upstream http.Header
	carrier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream = r.Header.Clone()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	}))
	defer carrier.Close()

	var base http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	if agent != nil {
		base = agent.Transport(base)
	}
	client := &http.Client{Transport: otelhttp.NewTransport(base, otelhttp.WithTracerProvider(tp), otelhttp.WithPropagators(prop))}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /orders", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("app.k", "v"))
		ctx, span := tp.Tracer("shop").Start(r.Context(), "business")
		req, _ := http.NewRequestWithContext(ctx, "POST", carrier.URL+"/v1/shipments", strings.NewReader(`{"orderId":"ORD-9"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		span.End()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"CREATED"}`))
	})
	var h http.Handler = mux
	if agent != nil {
		h = agent.Handler(h)
	}
	srv := httptest.NewServer(otelhttp.NewHandler(h, "shop", otelhttp.WithTracerProvider(tp), otelhttp.WithPropagators(prop)))
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/orders", strings.NewReader(`{"sku":"TSHIRT","email":"mario.rossi@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Traceparent", "00-"+incomingTrace+"-"+incomingParent+"-01")
	req.Header.Set("Baggage", "userId=42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	srv.Close() // waits for the handlers
	_ = tp.ForceFlush(context.Background())
	var ended []sdktrace.ReadOnlySpan
	ended = append(ended, rec.Ended()...)
	return result{spans: normalize(append([]sdktrace.ReadOnlySpan(nil), ended...)), rawSpans: ended, upstream: upstream, body: string(b), status: resp.StatusCode}
}

func TestCoexistenceWithOpenTelemetrySDK(t *testing.T) {
	provider0, prop0 := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	fields0 := append([]string(nil), prop0.Fields()...)

	control := scenario(t, nil)

	core := fakecore.New(t, "shop")
	cfg := ttsdk.Config{
		EnrollURL: core.URL, EnrollToken: core.Token, ServiceName: "shop-api", StateDir: t.TempDir(),
		HMACKeys:          "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		HeartbeatInterval: 30 * time.Millisecond, PolicyPollInterval: 30 * time.Millisecond, ExportFlushEvery: 20 * time.Millisecond,
		TraceContext: otelctx.FromContext,
	}
	agent, err := ttsdk.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Close(context.Background()) })
	core.SetPolicy(core.Compile(policyJSON, 1, 1))
	core.Eventually(10*time.Second, "capture active", agent.Capturing)

	with := scenario(t, agent)

	// 1. The application's traces are exactly the same.
	if !reflect.DeepEqual(control.spans, with.spans) {
		t.Errorf("spans changed by the SDK\n control %+v\n with    %+v", control.spans, with.spans)
	}
	if len(with.spans) != 3 {
		t.Errorf("expected server, business and client spans, got %d", len(with.spans))
	}
	for _, s := range with.rawSpans {
		if s.SpanContext().TraceID().String() != incomingTrace {
			t.Errorf("span %s left the incoming trace", s.Name())
		}
	}

	// 2. The traffic is exactly the same: status, body, and the headers the
	// carrier received (traceparent is the app's own, baggage is untouched,
	// nothing was added).
	if control.status != with.status || control.body != with.body {
		t.Errorf("response changed: %d %q vs %d %q", control.status, control.body, with.status, with.body)
	}
	if got, want := headerNames(with.upstream), headerNames(control.upstream); !reflect.DeepEqual(got, want) {
		t.Errorf("upstream headers changed: %v vs %v", got, want)
	}
	if with.upstream.Get("Baggage") != "userId=42" || strings.Contains(with.upstream.Get("Baggage"), "tt.s") {
		t.Errorf("baggage = %q", with.upstream.Get("Baggage"))
	}
	if tp := with.upstream.Get("Traceparent"); !strings.HasPrefix(tp, "00-"+incomingTrace+"-") {
		t.Errorf("traceparent = %q", tp)
	}

	// 3. Nothing was registered globally.
	if otel.GetTracerProvider() != provider0 {
		t.Error("the global TracerProvider was replaced")
	}
	if _, span := otel.GetTracerProvider().Tracer("x").Start(context.Background(), "s"); span.IsRecording() {
		t.Error("a global provider that records appeared")
	}
	if fmt.Sprint(otel.GetTextMapPropagator().Fields()) != fmt.Sprint(fields0) {
		t.Errorf("the global propagator changed: %v", otel.GetTextMapPropagator().Fields())
	}

	// 4. The events carry the application's own ids.
	var server, client sdktrace.ReadOnlySpan
	for _, s := range with.rawSpans {
		switch s.SpanKind() {
		case trace.SpanKindServer:
			server = s
		case trace.SpanKindClient:
			client = s
		}
	}
	evs := map[string]map[string]any{}
	for _, raw := range core.WaitEvents(2, 10*time.Second) {
		var ev map[string]any
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		evs[ev["dir"].(string)] = ev
		if strings.Contains(string(raw), "mario") {
			t.Errorf("event leaks a value: %s", raw)
		}
	}
	in, out := evs["inbound"], evs["outbound"]
	if in == nil || out == nil {
		t.Fatalf("events: %v", evs)
	}
	if in["trace_id"] != incomingTrace || in["span_id"] != server.SpanContext().SpanID().String() || in["parent_span_id"] != incomingParent {
		t.Errorf("inbound ids: %v (server span %s)", in, server.SpanContext().SpanID())
	}
	if out["trace_id"] != incomingTrace || out["span_id"] != client.SpanContext().SpanID().String() || out["parent_span_id"] != server.SpanContext().SpanID().String() {
		t.Errorf("outbound ids: %v (client span %s, server span %s)", out, client.SpanContext().SpanID(), server.SpanContext().SpanID())
	}
	if out["sampled_by"] != "inherited" {
		t.Errorf("outbound sampled_by = %v", out["sampled_by"])
	}
}

func headerNames(h http.Header) []string {
	var out []string
	for k := range h {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestFromContext(t *testing.T) {
	if _, _, ok := otelctx.FromContext(context.Background()); ok {
		t.Fatal("no span, no ids")
	}
	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("t").Start(context.Background(), "s")
	defer span.End()
	tid, sid, ok := otelctx.FromContext(ctx)
	if !ok || tid != span.SpanContext().TraceID().String() || sid != span.SpanContext().SpanID().String() || len(tid) != 32 || len(sid) != 16 {
		t.Fatalf("ids %q %q %v", tid, sid, ok)
	}
}
