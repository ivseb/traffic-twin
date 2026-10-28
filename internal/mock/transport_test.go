package mock

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Older packs list transport headers as required parameters (the demo pack's
// GET /v1/shipments requires host and user-agent). The mock must not reject a
// client that does not send them.
func TestTransportHeadersAreNotValidated(t *testing.T) {
	e := newEnv(t)
	sid := e.newSession(nil)
	req := httptest.NewRequest("GET", "/__svc/shipping-ext/v1/shipments?orderId=o1", nil)
	req.Header.Set("X-TT-Session", sid)
	req.Header.Del("User-Agent")
	rec := httptest.NewRecorder()
	e.m.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("transport headers must not be required: %d %s", rec.Code, rec.Body.String())
	}
	if !isTransportHeader("Host") || !isTransportHeader("sec-fetch-mode") || isTransportHeader("x-tenant") {
		t.Fatal("transport header classification")
	}
}
