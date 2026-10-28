package intake

import (
	"fmt"
	"strings"
	"testing"
)

// Spec v1.5: the literal labels at one position under one registrable
// domain collapse to {*} beyond the threshold (alarm host_cardinality).
func TestHostLabelQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.polOff.Hash // hosts.discovery auto, discovery off
	mk := func(i int) string {
		ev := mutate(t, rawPromo(h.pol.Hash), func(e eventT) {
			e.Dir = "outbound"
			e.Service = fmt.Sprintf("host:api.c%s.tracking.example:8443", twoLetters(i))
			e.Op = "GET /v1/{drop:str:l8}"
			e.Req.Path = "/v1/{drop:str:l8}"
		})
		return strings.Replace(ev, h.pol.Hash, hash, 1)
	}
	for i := 0; i < 80; i++ {
		if rej := h.ingest(t, mk(i)); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	var q Quarantine
	for _, c := range h.in.Quarantines(false) {
		switch c.Kind {
		case QuarantineHostLabel:
			q = c
		case QuarantineHost:
			t.Fatalf("one registrable domain must not raise the per-source host quarantine: %+v", c)
		}
	}
	if q.ID == 0 || q.Domain != "tracking.example" || q.Position != 1 || q.Service != "host:*" {
		t.Fatalf("quarantines: %+v", h.in.Quarantines(false))
	}
	h.waitRewrite(t, q.ID)
	bodies := h.storedBodies(t)
	if countContaining(bodies, `"service":"host:api.{*}.tracking.example:8443"`) != 80 {
		t.Fatal("position 1 was not rewritten to {*}")
	}
	if rej := h.ingest(t, mk(85)); rej.Reason != ReasonNone {
		t.Fatalf("event after quarantine: %s", rej.Reason)
	}
	h.idle(t)
	if n := countContaining(h.storedBodies(t), `"service":"host:api.{*}.tracking.example:8443"`); n != 81 {
		t.Fatalf("future event not rewritten: %d", n)
	}
	found := false
	for _, a := range h.alarms.Snapshot() {
		found = found || a.Kind == QuarantineHostLabel
	}
	if !found {
		t.Fatal("no alarm for the host-label quarantine")
	}
}

func TestRewriteHost(t *testing.T) {
	labels := map[string]map[int]struct{}{"tracking.example": {1: {}, 3: {}}}
	cases := []struct {
		in     string
		source bool
		want   string
		ok     bool
	}{
		{"a.b.c.tracking.example", false, "host:{*}.b.{*}.tracking.example", true},
		{"{*}.tracking.example:8443", false, "", false},
		{"x.tracking.example", true, "host:{*}.{*}.example", true},
		{"api.carrier.example", true, "host:api.{*}.example", true},
		{"api.carrier.example", false, "", false},
		{"ip:private:8080", true, "", false},
	}
	for _, c := range cases {
		got, ok := rewriteHost(c.in, labels, c.source)
		if got != c.want || ok != c.ok {
			t.Errorf("rewriteHost(%q, %v) = %q, %v; want %q, %v", c.in, c.source, got, ok, c.want, c.ok)
		}
	}
}
