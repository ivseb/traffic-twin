package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// statusEvents builds GET /v1/shipments exchanges whose items follow the
// carrier: cancelReason exists only for CANCELLED, eta for some of the others.
func statusEvents(t *testing.T, n int) []*event.Event {
	var evs []*event.Event
	states := []string{"CREATED", "IN_TRANSIT", "DELIVERED", "CANCELLED"}
	for i := 0; i < n; i++ {
		st := states[i%4]
		extra := ""
		if st == "CANCELLED" {
			extra = fmt.Sprintf(`"cancelReason":"keep:%s",`, []string{"ADDRESS_UNREACHABLE", "DAMAGED"}[(i/4)%2])
		} else if i%3 == 0 {
			extra = `"eta":"time:2026-10-21",`
		}
		item := fmt.Sprintf(`{%s"orderId":"%s","shipmentId":"%s","status":"keep:%s"}`, extra, tok(i), tok(5000+i), st)
		evs = append(evs, mkEv(t, evSpec{service: "shipping-ext", op: "GET /v1/shipments", dir: event.Outbound, status: 200,
			subject: tok(1000 + (i/4)%40), path: "/v1/shipments", at: t0.Add(time.Duration(i) * time.Second),
			resBody: `{"items":[` + item + `]}`, query: event.Multi{{Name: "orderId", Values: []string{tok(i)}}}}))
	}
	return evs
}

func TestConditionalPresence(t *testing.T) {
	c := inferAll(t, DefaultConfig(), nil, statusEvents(t, 400))
	op := c.Op("GET /v1/shipments")
	items := op.Response(200).Body[0].Schema.Prop("items").Schema.Items
	cr := items.Prop("cancelReason")
	if cr == nil || cr.Required || cr.When == nil || cr.When.Prop != "status" || len(cr.When.In) != 1 || cr.When.In[0] != "CANCELLED" {
		t.Fatalf("cancelReason: %+v", cr)
	}
	if eta := items.Prop("eta"); eta == nil || eta.When != nil {
		t.Fatalf("eta is not tied to one status: %+v", eta)
	}

	b, err := c.JSON(RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"x-tt-when":{"status":["CANCELLED"]}`) {
		t.Fatalf("x-tt-when missing from the render: %.2000s", b)
	}
	// Every example is coherent: cancelReason iff status is CANCELLED, and the
	// CANCELLED state has an example of its own.
	exs := collectExamples(doc)
	if len(exs) < 2 {
		t.Fatalf("examples: %d", len(exs))
	}
	seenCancelled := false
	for _, it := range exs {
		_, hasReason := it["cancelReason"]
		if st, _ := it["status"].(string); hasReason != (st == "CANCELLED") {
			t.Errorf("incoherent example: %v", it)
		} else if hasReason {
			seenCancelled = true
		}
	}
	if !seenCancelled {
		t.Error("no example shows a CANCELLED shipment")
	}
}

// collectExamples returns the items of every example value found in doc.
func collectExamples(doc any) []map[string]any {
	var out []map[string]any
	var walk func(v any, inExamples bool)
	walk = func(v any, inExamples bool) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if k == "value" && inExamples {
					if m, ok := c.(map[string]any); ok {
						if arr, ok := m["items"].([]any); ok {
							for _, e := range arr {
								if im, ok := e.(map[string]any); ok {
									out = append(out, im)
								}
							}
						}
					}
				}
				walk(c, inExamples || k == "examples")
			}
		case []any:
			for _, c := range x {
				walk(c, inExamples)
			}
		}
	}
	walk(doc, false)
	return out
}
