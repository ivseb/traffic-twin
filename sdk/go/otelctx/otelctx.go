// Package otelctx lets the traffic-twin Go SDK read the OpenTelemetry span
// that is active in a context, so that the events carry the same trace and
// span ids as the application's own traces.
//
// It only reads: it never creates a span, never registers a TracerProvider or
// a propagator (no otel.Set* call), never injects headers. It lives in its
// own module so that applications without OpenTelemetry never depend on it.
//
//	cfg := ttsdk.ConfigFromEnv()
//	cfg.TraceContext = otelctx.FromContext
//	agent, _ := ttsdk.New(cfg)
//
// or, with the zero-config package-level functions, before the first use:
//
//	otelctx.Use()
//
// The SDK must run where the span is already in the context: wrap it inside
// the OpenTelemetry middleware (otelhttp.NewHandler(ttsdk.Handler(mux), ...))
// and give the outbound transport the span through the request context
// (otelhttp.NewTransport(ttsdk.Transport(base))).
package otelctx

import (
	"context"

	ttsdk "github.com/ivseb/traffic-twin/sdk/go"
	"go.opentelemetry.io/otel/trace"
)

// FromContext returns the trace and span ids of the active span of ctx, or
// ok=false when there is none (or it is not valid). It is a
// ttsdk.TraceContextFunc.
func FromContext(ctx context.Context) (traceID, spanID string, ok bool) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", "", false
	}
	return sc.TraceID().String(), sc.SpanID().String(), true
}

// Use makes the default agent read the active span with FromContext. Call it
// before the first use of ttsdk.Handler or ttsdk.Transport.
func Use() { ttsdk.SetDefaultTraceContext(FromContext) }
