package ttgin_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	ttsdk "github.com/ivseb/traffic-twin/sdk/go"
	ttgin "github.com/ivseb/traffic-twin/sdk/go/gin"

	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

const policyJSON = `{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "sampling":{"rate":1},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}}},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{
    "POST /api/orders":{"request":{"body":{"$.sku":"keep"}},"response":{"$.status":"keep"}},
    "GET /api/orders/{id}":{"request":{"path":{"id":"hmac(order)"}},"response":{"$.status":"keep"}},
    "GET /api/files/{name}":{"response":{"$.status":"keep"}}}}}}`

func newAgent(t *testing.T, core *fakecore.Core) *ttsdk.Agent {
	t.Helper()
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
	return a
}

func TestGinMiddlewareRoutesAndPassThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core := fakecore.New(t, "shop")
	a := newAgent(t, core)

	r := gin.New()
	r.Use(ttgin.MiddlewareFor(a))
	api := r.Group("/api")
	api.GET("/orders/:id", func(c *gin.Context) { c.JSON(200, gin.H{"status": "OK", "who": "mario.rossi@example.com"}) })
	api.POST("/orders", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		c.Header("X-Echo", string(b))
		c.JSON(http.StatusCreated, gin.H{"status": "CREATED"})
	})
	api.GET("/files/*name", func(c *gin.Context) { c.String(200, "%s", `{"status":"OK"}`) })
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/orders/ORD-42")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "mario.rossi@example.com") {
		t.Fatalf("response altered: %d %s", resp.StatusCode, b)
	}
	resp, err = http.Post(srv.URL+"/api/orders", "application/json", strings.NewReader(`{"sku":"TSHIRT"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 201 || resp.Header.Get("X-Echo") != `{"sku":"TSHIRT"}` {
		t.Fatalf("response altered: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = http.Get(srv.URL + "/api/files/report.pdf")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	raw := core.WaitEvents(3, 10*time.Second)
	got := map[string]map[string]any{}
	for _, e := range raw {
		var ev map[string]any
		if err := json.Unmarshal(e, &ev); err != nil {
			t.Fatal(err)
		}
		got[ev["op"].(string)] = ev
		if strings.Contains(string(e), "mario") || strings.Contains(string(e), "ORD-42") || strings.Contains(string(e), "example.com") {
			t.Errorf("event leaks a value: %s", e)
		}
	}
	// c.FullPath() carries the group prefix: the framework finds the template.
	if ev := got["GET /api/orders/{id}"]; ev == nil || ev["route_source"] != "framework" || ev["status"] != float64(200) {
		t.Errorf("GET /api/orders/:id: %v", got)
	}
	if ev := got["POST /api/orders"]; ev == nil || ev["route_source"] != "framework" || ev["status"] != float64(201) {
		t.Errorf("POST /api/orders: %v", got)
	} else if body := ev["req"].(map[string]any)["body"].(map[string]any); body["sku"] != "keep:TSHIRT" {
		t.Errorf("request body: %v", body)
	}
	// A catch-all can not be normalized: the policy template decides.
	if ev := got["GET /api/files/{name}"]; ev == nil || ev["route_source"] != "policy" {
		t.Errorf("GET /api/files/*name: %v", got)
	}
}

func TestGinInertWithoutConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a, err := ttsdk.New(ttsdk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(ttgin.MiddlewareFor(a))
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
