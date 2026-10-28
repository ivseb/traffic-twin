// Package sdkgo_rt red-teams the Go SDK (sdk/go) as a zone-A source: it must
// fail CLOSED (capture nothing) whenever it is not fully enrolled with a
// valid policy, key and heartbeat, and it must never register itself in the
// OpenTelemetry global registry or make outbound calls on its own.
// Invented data only. Run: go test ./test/redteam/go/
package sdkgo_rt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	tt "github.com/ivseb/traffic-twin/sdk/go"
)

// An agent built from an empty config (no enrollment URL) is inert: it never
// captures, and its Handler/Transport are pass-through. This is the
// fail-closed default when tt-core is absent or misconfigured.
func TestRT_SDKGo_Holds_InertWithoutEnrollment(t *testing.T) {
	a, err := tt.New(tt.Config{})
	if err != nil {
		t.Fatalf("empty config should give an inert agent, got error: %v", err)
	}
	if a == nil {
		t.Fatal("New returned nil agent")
	}
	if a.Enabled() {
		t.Error("agent with no enrollment reports Enabled")
	}
	if a.Capturing() {
		t.Error("inert agent reports Capturing")
	}
	// Begin must not capture; the request passes through unchanged.
	r := httptest.NewRequest("POST", "/orders", http.NoBody)
	in, out := a.Begin(r)
	if in != nil {
		t.Error("inert agent captured an inbound request")
	}
	if out != r {
		t.Error("inert agent altered the request")
	}
}

// A token without a URL is a misconfiguration and must be an error, not a
// silently-capturing agent.
func TestRT_SDKGo_Holds_TokenWithoutURLErrors(t *testing.T) {
	if _, err := tt.New(tt.Config{EnrollToken: "tok-rt"}); err == nil {
		t.Error("token without enroll URL was accepted")
	}
}

// The Handler wrapper of an inert agent forwards every request to the next
// handler untouched and adds no headers of its own (no traceparent
// injection, no outbound side effect).
func TestRT_SDKGo_Holds_HandlerPassThrough(t *testing.T) {
	a, _ := tt.New(tt.Config{})
	called := false
	var gotTP string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		gotTP = r.Header.Get("Traceparent")
		w.WriteHeader(204)
	})
	rr := httptest.NewRecorder()
	a.Handler(next).ServeHTTP(rr, httptest.NewRequest("GET", "/x", http.NoBody))
	if !called {
		t.Fatal("handler did not forward the request")
	}
	if gotTP != "" {
		t.Errorf("SDK injected a traceparent header: %q", gotTP)
	}
	if rr.Code != 204 {
		t.Errorf("status changed: %d", rr.Code)
	}
}
