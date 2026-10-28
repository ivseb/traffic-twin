package ttchi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	ttsdk "github.com/ivseb/traffic-twin/sdk/go"
	ttchi "github.com/ivseb/traffic-twin/sdk/go/chi"

	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

const policyJSON = `{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "sampling":{"rate":1},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}}},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{
    "GET /api/v1/orders/{id}":{"request":{"path":{"id":"hmac(order)"}},"response":{"$.status":"keep"}},
    "GET /api/v1/files/{name}":{"response":{"$.status":"keep"}}}}}}`

func TestChiMiddlewareFullRoutePattern(t *testing.T) {
	core := fakecore.New(t, "shop")
	a, err := ttsdk.New(ttsdk.Config{
		EnrollURL: core.URL, EnrollToken: core.Token, ServiceName: "shop-api", StateDir: t.TempDir(),
		HMACKeys:          "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		HeartbeatInterval: 30 * time.Millisecond, PolicyPollInterval: 30 * time.Millisecond, ExportFlushEvery: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	core.SetPolicy(core.Compile(policyJSON, 1, 1))
	core.Eventually(10*time.Second, "capture active", a.Capturing)

	r := chi.NewRouter()
	r.Use(ttchi.MiddlewareFor(a))
	sub := chi.NewRouter() // mounted: the pattern must include the /api/v1 prefix
	sub.Get("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"OK","who":"mario.rossi@example.com"}`))
	})
	sub.Get("/files/*", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	})
	r.Mount("/api/v1", sub)
	srv := httptest.NewServer(r)
	defer srv.Close()

	for _, p := range []string{"/api/v1/orders/ORD-42", "/api/v1/files/report.pdf"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"status":"OK"`) {
			t.Fatalf("response altered: %d %s", resp.StatusCode, b)
		}
	}
	got := map[string]map[string]any{}
	for _, e := range core.WaitEvents(2, 10*time.Second) {
		var ev map[string]any
		if err := json.Unmarshal(e, &ev); err != nil {
			t.Fatal(err)
		}
		got[ev["op"].(string)] = ev
		if strings.Contains(string(e), "mario") || strings.Contains(string(e), "ORD-42") {
			t.Errorf("event leaks a value: %s", e)
		}
	}
	if ev := got["GET /api/v1/orders/{id}"]; ev == nil || ev["route_source"] != "framework" {
		t.Errorf("mounted route: %v", got)
	}
	// "/*" is not normalizable: the template of the policy decides.
	if ev := got["GET /api/v1/files/{name}"]; ev == nil || ev["route_source"] != "policy" {
		t.Errorf("wildcard route: %v", got)
	}
}

func TestChiInertWithoutConfiguration(t *testing.T) {
	a, _ := ttsdk.New(ttsdk.Config{})
	r := chi.NewRouter()
	r.Use(ttchi.MiddlewareFor(a))
	r.Get("/x", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Body.String() != "ok" {
		t.Fatal(rec.Body.String())
	}
}
