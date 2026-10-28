package export

import "testing"

func TestCoherentFollowsConditionalProperties(t *testing.T) {
	op := &operation{Responses: []response{{Status: 200, Schema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"status": map[string]any{"type": "string"},
			"cancelReason": map[string]any{
				"type": "string", "enum": []any{"ADDRESS_UNREACHABLE", "DAMAGED"},
				"x-tt-when": map[string]any{"status": []any{"CANCELLED"}},
			},
		},
	}}}}
	in := []map[string]any{
		{"status": "CANCELLED"},
		{"status": "IN_TRANSIT", "cancelReason": "DAMAGED"},
		{"status": "DELIVERED"},
	}
	out := op.coherent(Ref{From: "resp.body", Path: "$"}, in)
	if out[0]["cancelReason"] != "ADDRESS_UNREACHABLE" {
		t.Errorf("cancelled: %v", out[0])
	}
	if _, has := out[1]["cancelReason"]; has {
		t.Errorf("in transit with cancelReason: %v", out[1])
	}
	if _, has := out[2]["cancelReason"]; has {
		t.Errorf("delivered with cancelReason: %v", out[2])
	}
	if _, has := in[1]["cancelReason"]; !has {
		t.Error("input was modified")
	}
}

func TestShareHiddenWhenIsPerField(t *testing.T) {
	rbs := []ReadBy{
		{Op: "GET /v1/shipments", By: &Ref{From: "req.query", Name: "orderId", Field: "orderId"}, HiddenWhen: map[string]any{"status": "PENDING"}},
		{Op: "GET /orders/{id}/shipment", By: &Ref{From: "req.path", Name: "id", Field: "orderId"}},
		{Op: "GET /shipments/{id}", By: &Ref{From: "req.path", Name: "id"}},
	}
	out := shareHiddenWhen(rbs)
	if out[1].HiddenWhen["status"] != "PENDING" {
		t.Errorf("shop read does not inherit: %+v", out[1])
	}
	if out[2].HiddenWhen != nil {
		t.Errorf("a read by id must not inherit: %+v", out[2])
	}
	if rbs[1].HiddenWhen != nil {
		t.Error("input was modified")
	}
}
