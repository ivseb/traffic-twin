package contract

import (
	"testing"

	"github.com/ivseb/traffic-twin/internal/event"
)

func hdrParam(ps []*Param, name string) *Param {
	for _, p := range ps {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func TestTransportHeadersNeverRequired(t *testing.T) {
	var evs []*event.Event
	for _, e := range carrierEvents(t, 200) {
		e.Req.Headers = event.Multi{
			{Name: "accept-encoding", Values: []string{"gzip"}},
			{Name: "host", Values: []string{"shipping.example"}},
			{Name: "idempotency-key", Values: []string{tok(1)}},
			{Name: "sec-fetch-mode", Values: []string{"cors"}},
			{Name: "user-agent", Values: []string{"client/1"}},
			{Name: "x-forwarded-for", Values: []string{"10.0.0.1"}},
			{Name: "x-tenant", Values: []string{"acme"}},
		}
		evs = append(evs, e)
	}
	c := inferAll(t, DefaultConfig(), nil, evs)
	op := c.Op("GET /v1/shipments")
	for _, n := range []string{"host", "user-agent", "accept-encoding", "sec-fetch-mode", "x-forwarded-for", "idempotency-key"} {
		p := hdrParam(op.Headers, n)
		if p == nil {
			t.Fatalf("header %s missing from contract", n)
		}
		if p.Required {
			t.Errorf("header %s must not be required", n)
		}
		if p.Presence != 1 {
			t.Errorf("header %s presence %v", n, p.Presence)
		}
	}
	if p := hdrParam(op.Headers, "x-tenant"); p == nil || !p.Required {
		t.Errorf("application header x-tenant should stay required: %+v", p)
	}
}

func TestIsTransportHeader(t *testing.T) {
	for _, n := range []string{"Host", "Cookie", "Sec-CH-UA", "TRACEPARENT", "X-Forwarded-Proto", "Baggage"} {
		if !IsTransportHeader(n) {
			t.Errorf("%s should be transport", n)
		}
	}
	if IsTransportHeader("authorization") || IsTransportHeader("x-tenant") {
		t.Error("application headers misclassified")
	}
}
