package world

import (
	"bytes"
	"encoding/json"
	"testing"
)

// A contract that ties cancelReason to status CANCELLED (x-tt-when): every
// CANCELLED shipment of the world carries a synthetic cancelReason, no other
// shipment does.
func TestConditionalPropertiesFollowState(t *testing.T) {
	in := demoInput(t, 11, 300)
	for i, c := range in.Contracts {
		if c.Service != "shipping-ext" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(c.Doc, &m); err != nil {
			t.Fatal(err)
		}
		cr := m["components"].(map[string]any)["schemas"].(map[string]any)["Shipment"].(map[string]any)["properties"].(map[string]any)["cancelReason"].(map[string]any)
		cr["enum"] = []any{"ADDRESS_UNREACHABLE", "DAMAGED_IN_WAREHOUSE"}
		cr["x-tt-when"] = map[string]any{"status": []any{"CANCELLED"}}
		b, _ := json.Marshal(m)
		in.Contracts[i].Doc = b
	}
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	cancelled := 0
	for _, line := range bytes.Split(out.World, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Type   string         `json:"type"`
			Entity string         `json:"entity"`
			State  map[string]any `json:"state"`
		}
		if json.Unmarshal(line, &row) != nil || row.Entity != "shipment" || row.State == nil {
			continue
		}
		_, has := row.State["cancelReason"]
		isCancelled := row.State["status"] == "CANCELLED"
		if has != isCancelled {
			t.Fatalf("incoherent shipment (%s): %s", row.Type, line)
		}
		if isCancelled {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Fatal("no CANCELLED shipment in the world: the test proves nothing")
	}
}
