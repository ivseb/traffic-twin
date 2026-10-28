package intake

import (
	"fmt"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Lab round 2: the SDK in the shop and tt-egress for the carrier. SDKs never
// inject a traceparent, so the two events are in different traces.

func hop(kind, id, service, op string, status int, at time.Time, latencyMS int64) *event.Event {
	return &event.Event{Dir: event.Outbound, Source: event.SourceRef{Kind: kind, ID: id}, Service: service, Op: op,
		Status: status, Time: at, LatencyMS: latencyMS}
}

func TestDoubleCaptureByTimeAndShapeWithoutSharedTrace(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	d := newDoubleCapture()
	for i := 0; i < doubleCapturePairs; i++ {
		at := now.Add(time.Duration(i) * 7 * time.Second)
		// The SDK hop to the proxy (unlisted host) wraps the call tt-egress forwards.
		sdk := hop("sdk-node", "src-shop", "host:unlisted", "POST /{s}/{s}", 202, at, 150)
		sdk.TraceID, sdk.SpanID = fmt.Sprintf("trace-sdk-%d", i), "span-sdk"
		egr := hop("egress", "src-egr", "shipping-ext", "POST /v1/shipments", 202, at.Add(3*time.Millisecond), 140)
		egr.TraceID = fmt.Sprintf("trace-egr-%d", i) // its own trace
		d.observe(sdk, now)
		if i < doubleCapturePairs-1 {
			d.observe(egr, now)
			if d.recent("src-shop", now) {
				t.Fatalf("flagged after %d match(es): a coincidence proves nothing", i+1)
			}
		} else {
			d.observe(egr, now)
		}
	}
	if !d.recent("src-shop", now) || !d.recent("src-egr", now) {
		t.Fatalf("not flagged after %d matches: %+v", doubleCapturePairs, d.flagged)
	}
}

func TestDoubleCaptureShapeNamedServiceMustAgree(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	d := newDoubleCapture()
	for i := 0; i < 2*doubleCapturePairs; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		// The SDK names a service (the proxy address is listed in its policy
		// under the carrier's name) but a different one than the egress call.
		d.observe(hop("sdk-node", "src-shop", "billing-ext", "POST /v1/shipments", 202, at, 100), now)
		d.observe(hop("egress", "src-egr", "shipping-ext", "POST /v1/shipments", 202, at.Add(time.Millisecond), 90), now)
	}
	if d.total != 0 {
		t.Fatalf("different services flagged: %+v", d.flagged)
	}
	// The same service name is the carrier reached through the proxy.
	for i := 0; i < doubleCapturePairs; i++ {
		at := now.Add(time.Minute + time.Duration(i)*time.Second)
		d.observe(hop("sdk-node", "src-shop", "shipping-ext", "POST /v1/shipments", 202, at, 100), now)
		d.observe(hop("egress", "src-egr", "shipping-ext", "POST /v1/shipments", 202, at.Add(time.Millisecond), 90), now)
	}
	if !d.recent("src-shop", now) || !d.recent("src-egr", now) {
		t.Fatalf("same service not flagged: %+v", d.flagged)
	}
}

func TestDoubleCaptureShapeIgnoresNonMatches(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	d := newDoubleCapture()
	for i := 0; i < 10; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		// Different status, different method, far apart in time, same-kind sources.
		d.observe(hop("sdk-node", "src-shop", "host:unlisted", "POST /{s}", 202, at, 100), now)
		d.observe(hop("egress", "src-egr", "x", "POST /v1/a", 500, at, 90), now)
		d.observe(hop("egress", "src-egr", "x", "GET /v1/a", 202, at, 90), now)
		d.observe(hop("egress", "src-egr", "x", "POST /v1/a", 202, at.Add(time.Hour), 90), now)
		d.observe(hop("sdk-go", "src-other", "host:unlisted", "POST /{s}", 202, at, 100), now)
	}
	if d.total != 0 {
		t.Fatalf("false positive: %+v", d.flagged)
	}
	// One egress call cannot be the counterpart of many SDK calls.
	d2 := newDoubleCapture()
	at := now
	for i := 0; i < 5; i++ {
		d2.observe(hop("sdk-node", "src-shop", "host:unlisted", "POST /{s}", 202, at, 100), now)
	}
	d2.observe(hop("egress", "src-egr", "x", "POST /v1/a", 202, at, 90), now)
	if d2.pairs[[2]string{"src-shop", "src-egr"}].n != 1 {
		t.Errorf("pairs: %+v", d2.pairs)
	}
}

func TestDoubleCaptureByKnownEgressHost(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	in := &Intake{dup: newDoubleCapture(), now: func() time.Time { return now }}
	in.SetEgressHosts(func() map[string][]string {
		return map[string][]string{"tt-egress-1": {"src-egr"}, "tt-egress:9090": {"src-egr"}}
	})
	// A call to an unrelated host, an unlisted one: nothing.
	in.dup.observe(hop("sdk-node", "src-shop", "host:api.carrier.example", "POST /v1/shipments", 202, now, 10), now)
	in.dup.observe(hop("sdk-node", "src-shop", "host:unlisted", "POST /{s}", 202, now, 10), now)
	if in.DoubleCaptured("src-shop") || in.DoubleCaptured("src-egr") {
		t.Fatal("false positive")
	}
	// One SDK call to the proxy is enough, by host:port or by hostname.
	in.dup.observe(hop("sdk-node", "src-shop", "host:tt-egress:9090", "POST /carrier/v1/shipments", 202, now, 10), now)
	if !in.DoubleCaptured("src-shop") || !in.DoubleCaptured("src-egr") {
		t.Fatalf("host not recognized: %+v", in.dup.flagged)
	}
	in2 := &Intake{dup: newDoubleCapture(), now: func() time.Time { return now }}
	in2.SetEgressHosts(func() map[string][]string { return map[string][]string{"tt-egress-1": {"src-egr"}} })
	in2.dup.observe(hop("sdk-java", "src-b", "host:tt-egress-1:9090", "GET /x", 200, now, 10), now)
	if !in2.DoubleCaptured("src-b") || !in2.DoubleCaptured("src-egr") {
		t.Fatalf("hostname without port not recognized: %+v", in2.dup.flagged)
	}
	// An egress event alone never flags anything through the host rule.
	in3 := &Intake{dup: newDoubleCapture(), now: func() time.Time { return now }}
	in3.SetEgressHosts(func() map[string][]string { return map[string][]string{"tt-egress-1": {"src-egr"}} })
	in3.dup.observe(hop("egress", "src-egr", "host:tt-egress-1", "GET /x", 200, now, 10), now)
	if in3.DoubleCaptured("src-egr") {
		t.Error("an egress event flagged itself")
	}
}

func TestDoubleCaptureShapeMemoryIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	d := newDoubleCapture()
	for i := 0; i < 5*doubleCaptureKeep; i++ {
		d.observe(hop("sdk-node", "src-shop", "host:unlisted", "POST /{s}", 202, now, 10), now)
	}
	if n := len(d.recentSDK[shapeKey{"POST", 202}]); n > doubleCaptureKeep {
		t.Fatalf("%d events kept", n)
	}
	// Old events are swept.
	d.observe(hop("sdk-node", "src-shop", "host:unlisted", "POST /{s}", 202, now, 10), now.Add(10*time.Minute))
	if n := len(d.recentSDK[shapeKey{"POST", 202}]); n != 1 {
		t.Fatalf("after the sweep: %d events kept", n)
	}
}
