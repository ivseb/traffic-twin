package fakecore

import "github.com/ivseb/traffic-twin/internal/sanitizer"

// AuthorPolicy is the author policy (JSON form of tt.policy/v1) used by the
// tests of the sources: an internal service named "egress-svc" (baggage is
// trusted there), a subject read from the x-customer-id header, 100 percent
// sampling and the external carrier service of the demo.
const AuthorPolicy = `{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"x-customer-id"}},
 "sampling":{"rate":1,"trust_baggage":true},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}},"errors":{"body":{"$.error.code":"keep"}}},
 "services":{
  "egress-svc":{"match":{"inbound":true,"internal":true}},
  "shipping-ext":{"match":{"base":"https://api.carrier.example"},"ops":{
    "POST /v1/shipments":{"request":{"body":{"$.orderId":"hmac(order)"}},"response":{"$.shipmentId":"hmac(shipment)","$.status":"keep"}},
    "GET /v1/shipments/{id}":{"request":{"path":{"id":"hmac(shipment)"}},"response":{"$.shipmentId":"hmac(shipment)","$.status":"keep"}}}}
 }}`

// HMACKeys returns the HMAC key set used by the tests (kid "k1") and the kids.
func HMACKeys() (sanitizer.KeySet, []string) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	k, err := sanitizer.NewKey("k1", secret)
	if err != nil {
		panic(err)
	}
	return sanitizer.NewKeySet(k), []string{"k1"}
}
