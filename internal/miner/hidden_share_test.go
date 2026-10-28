package miner

import "testing"

func TestShareHiddenWhen(t *testing.T) {
	carrier := ReadBy{Op: "GET /v1/shipments", By: &Ref{From: "req.query", Name: "orderId", Field: "orderId"}, HiddenWhen: map[string]any{"status": "PENDING"}}
	shop := ReadBy{Op: "GET /orders/{id}/shipment", Service: "shop-api", By: &Ref{From: "req.path", Name: "id", Field: "orderId"}}
	byID := ReadBy{Op: "GET /shipments/{id}", By: &Ref{From: "req.path", Name: "id"}}
	exposes := ReadBy{Op: "GET /orders/{id}/tracking", By: &Ref{From: "req.path", Name: "id", Field: "orderId"}}

	rbs := []ReadBy{carrier, shop, byID, exposes}
	stats := []*readStats{
		{states: map[string]int{"CREATED": 5}},
		{states: map[string]int{"CREATED": 5}},
		{states: map[string]int{"PENDING": 3}},
		{states: map[string]int{"PENDING": 2}}, // exposes PENDING: contradicts the sibling
	}
	(&miner{}).shareHiddenWhen(rbs, stats)
	if rbs[1].HiddenWhen["status"] != "PENDING" {
		t.Errorf("shop read should inherit hidden_when: %+v", rbs[1])
	}
	if rbs[2].HiddenWhen != nil {
		t.Errorf("a read by id has no shared selection: %+v", rbs[2])
	}
	if rbs[3].HiddenWhen != nil {
		t.Errorf("a read that exposes the state must not inherit: %+v", rbs[3])
	}
}
