package intake

import (
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

func capEv(kind, id, dir, trace, span, parent string) *event.Event {
	return &event.Event{Dir: dir, TraceID: trace, SpanID: span, ParentSpanID: parent, Source: event.SourceRef{Kind: kind, ID: id}}
}

func TestDoubleCaptureDetected(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for _, sdkFirst := range []bool{true, false} {
		d := newDoubleCapture()
		sdk := capEv("sdk-node", "src-sdk", event.Outbound, "t1", "s-out", "s-in")
		egr := capEv("egress", "src-egr", event.Outbound, "t1", "s-egr", "s-out")
		if sdkFirst {
			d.observe(sdk, now)
			d.observe(egr, now)
		} else {
			d.observe(egr, now)
			d.observe(sdk, now)
		}
		if !d.recent("src-sdk", now) || !d.recent("src-egr", now) || d.total != 1 {
			t.Fatalf("sdkFirst=%v: not flagged (total %d)", sdkFirst, d.total)
		}
		if d.recent("src-sdk", now.Add(2*time.Hour)) {
			t.Error("the warning must fade after an hour")
		}
	}
}

func TestDoubleCaptureIgnoresUnrelatedCalls(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	d := newDoubleCapture()
	d.observe(capEv("sdk-node", "src-sdk", event.Outbound, "t1", "s-out", "s-in"), now)
	// same trace, but the egress call descends from another span
	d.observe(capEv("egress", "src-egr", event.Outbound, "t1", "s-x", "s-other"), now)
	// same span ids in another trace
	d.observe(capEv("egress", "src-egr", event.Outbound, "t2", "s-y", "s-out"), now)
	// inbound events are never part of a hop
	d.observe(capEv("sdk-node", "src-sdk", event.Inbound, "t3", "s-a", ""), now)
	d.observe(capEv("egress", "src-egr", event.Inbound, "t3", "s-b", "s-a"), now)
	// two SDKs, or two egresses, are not a double capture
	d.observe(capEv("sdk-go", "src-sdk2", event.Outbound, "t4", "s-1", ""), now)
	d.observe(capEv("sdk-node", "src-sdk3", event.Outbound, "t4", "s-2", "s-1"), now)
	if d.total != 0 || d.recent("src-sdk", now) || d.recent("src-egr", now) {
		t.Fatalf("false positive: %+v", d.flagged)
	}
}

func TestDoubleCaptureMemoryIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	d := newDoubleCapture()
	for i := 0; i < doubleCaptureMaxSpans+10; i++ {
		d.observe(capEv("sdk-node", "src-sdk", event.Outbound, "t"+time.Duration(i).String(), "s", ""), now)
	}
	if n := len(d.sdk) + len(d.egress); n > doubleCaptureMaxSpans {
		t.Fatalf("%d spans kept", n)
	}
}
