// Package ttsdk is the Go capture SDK of traffic-twin (docs/ARCHITECTURE.md
// section 3). It observes the HTTP calls a Go service receives (an
// http.Handler middleware) and makes (an http.RoundTripper wrapper),
// sanitizes them in the process with the reference sanitizer
// (docs/spec/sanitizer.md) under the signed policy distributed by tt-core,
// and sends tt-core only shapes, HMAC tokens and the values the policy
// allows, as OTLP/HTTP JSON logs over mTLS.
//
// # Zero configuration
//
// With the TT_* environment variables set (TT_ENROLL_URL, TT_ENROLL_TOKEN,
// TT_HMAC_KEY or TT_HMAC_KEY_FILE, TT_SERVICE_NAME, see ConfigFromEnv) the
// package-level functions are all that is needed:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("POST /orders/{id}", createOrder)
//	srv := &http.Server{Handler: ttsdk.Handler(mux)}
//
//	client := &http.Client{Transport: ttsdk.Transport(nil)}
//
// Without TT_ENROLL_URL (or with TT_DISABLED=1) the SDK is inert: Handler
// and Transport return their argument unchanged, no goroutine is started.
//
// # What it guarantees
//
//   - Fail closed: without a valid signed policy, HMAC key, first heartbeat,
//     or with the kill switch on, nothing is captured and the application
//     carries on unchanged.
//   - The application is never made to wait for tt: the request path only
//     takes the sampling decision and copies at most max(max_body_bytes,
//     bodies.max_large_body_bytes)+1 body bytes; sanitizing, serialization
//     and delivery run on background goroutines with bounded queues that drop
//     whole events, never requests.
//   - OpenTelemetry coexistence: the SDK never registers a global
//     TracerProvider or propagator and does not import OpenTelemetry. It
//     reads traceparent from the request, or the active span through the
//     optional sub-module otelctx, and never injects traceparent. The only
//     header it may add is the tt.s baggage member towards the hosts of
//     sampling.propagate_to.
//   - No security-critical code of its own: sanitizing, sampling, policy
//     verification, enrollment and export are the shared packages of the
//     traffic-twin module (reference sanitizer, passes all conformance
//     vectors).
//
// # Other routers
//
// Go 1.22+ net/http patterns work out of the box (the pattern matched by the
// ServeMux becomes framework_route). Gin and chi have adapters in the
// separate modules sdk/go/gin and sdk/go/chi, so that this module does not
// depend on them.
package ttsdk

// Version is the SDK version reported in events and at enrollment.
const Version = "0.1.0"

// Kind is the source kind of the events (docs/spec/event.md).
const Kind = "sdk-go"
