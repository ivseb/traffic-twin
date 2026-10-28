package core_rt

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
	"github.com/ivseb/traffic-twin/internal/drift"
)

// Deliveries from the composed product (quarantine, admin approval, event
// export, kill switch) carry a correct X-TT-Signature and no value: no real
// identifier, no quarantined value, no reason text, no canary.
func TestRT_Webhook_Holds_SignedAndValueFree(t *testing.T) {
	e := getEnv(t)
	olga := e.u(t, "olga")
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "rt-wh", "allowed_service_names": []string{"rt-wh-svc"}})
	olga.must(204, "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"group": "rt-wh"}})
	olga.must(204, "POST", "/api/v1/fleet/kill", map[string]any{"active": false, "scope": map[string]any{"group": "rt-wh"}})
	types := map[string]int{}
	eventually(t, 15*time.Second, "kill.changed delivery", func() bool {
		for _, h := range e.hooks.get() {
			if h.path == "/hook" && h.header.Get("X-TT-Event") == "kill.changed" {
				return true
			}
		}
		return false
	})
	bad := []string{"RTQSTATE", "RTQCU", "single-maintainer", canaryText, "qz4242", e.orderIDs[0], e.hookSec, keyB64(e.keyFiles["hmac.keys"])}
	for _, h := range e.hooks.get() {
		if h.path != "/hook" {
			continue
		}
		ev := h.header.Get("X-TT-Event")
		types[ev]++
		if !drift.VerifySignature(e.hookSec, h.header.Get("X-TT-Signature"), h.body, time.Now(), 0) {
			t.Errorf("%s: signature does not verify", ev)
		}
		if drift.VerifySignature(e.hookSec, h.header.Get("X-TT-Signature"), append([]byte(" "), h.body...), time.Now(), 0) {
			t.Errorf("%s: signature verifies a modified body", ev)
		}
		for _, v := range bad {
			if strings.Contains(string(h.body), v) {
				t.Errorf("%s payload contains %q: %.300s", ev, v, h.body)
			}
		}
	}
	t.Logf("deliveries by type: %v", types)
	for _, want := range []string{"quarantine.opened", "keyguard.alert", "kill.changed"} {
		if types[want] == 0 {
			t.Errorf("no %s delivery", want)
		}
	}
}

// A 3xx answer is a failed delivery: the redirect target is never called.
func TestRT_Webhook_Holds_RedirectNotFollowed(t *testing.T) {
	e := getEnv(t)
	eventually(t, 15*time.Second, "a delivery to the redirecting hook", func() bool {
		for _, h := range e.hooks.get() {
			if h.path == "/redirect" {
				return true
			}
		}
		return false
	})
	time.Sleep(500 * time.Millisecond)
	for _, h := range e.hooks.get() {
		if h.path == "/landing" {
			t.Fatalf("redirect followed")
		}
	}
	var ds []map[string]any
	e.u(t, "ada").json(200, "GET", "/api/v1/webhooks/"+e.redirHook+"/deliveries", nil, &ds)
	for _, d := range ds {
		if d["state"] == "delivered" {
			t.Errorf("redirect counted as delivered: %v", d)
		}
	}
}

// Destinations outside the allow list, other schemes, userinfo and
// look-alike hosts are refused at creation.
func TestRT_Webhook_Holds_URLValidation(t *testing.T) {
	e := getEnv(t)
	_, port, _ := net.SplitHostPort(e.hooks.addr)
	for _, u := range []string{
		"http://127.0.0.1:1/x", "http://localhost:" + port + "/x", "http://[::1]:" + port + "/x",
		"http://u:p@" + e.hooks.addr + "/x", "http://" + e.hooks.addr + "@evil.example/x",
		"http://evil.example/" + e.hooks.addr, "http://evil.example?h=" + e.hooks.addr, "file:///etc/passwd",
		"gopher://" + e.hooks.addr + "/x", "http://0x7f000001:" + port + "/x", "http://2130706433:" + port + "/x",
		"http://127.0.0.1.:" + port + "/x", "http://" + e.hooks.addr + "#frag", "//" + e.hooks.addr + "/x",
		"http://169.254.169.254/latest/meta-data/",
	} {
		code, b := e.u(t, "ada").do("POST", "/api/v1/webhooks", map[string]any{"name": "rt-bad", "url": u, "events": []string{"rule.stale"}})
		if code < 400 {
			t.Errorf("webhook to %q accepted: %d %s", u, code, b)
			id := field(b, "webhook_id")
			e.u(t, "ada").do("DELETE", "/api/v1/webhooks/"+id, nil)
		}
	}
	// https only unless webhook_allow_http (set in this env): checked on a
	// manager with the default.
	m, err := drift.New(drift.Config{Allow: []string{"hooks.rt.example"}}, drift.Deps{DB: contracttest.New(t).DB})
	if err != nil {
		t.Fatal(err)
	}
	if m.CheckURL("http://hooks.rt.example/x") == nil {
		t.Error("http accepted without webhook_allow_http")
	}
	if m.CheckURL("https://hooks.rt.example/x") != nil {
		t.Error("https refused")
	}
}

// FIXED (was low, red team round 2; now a regression test). The allow list is matched on the host NAME only; the
// address it resolves to at delivery time is never checked. An allow-listed
// name (or any name under a "*.suffix" entry) whose DNS points at
// 127.0.0.1, an RFC 1918 address or 169.254.169.254 receives tt-core's
// signed POSTs (DNS rebinding / SSRF towards internal services); delivery
// also goes through HTTP(S)_PROXY from the environment (http.DefaultTransport).
// "rt.localhost" stands in for such a name: it resolves to loopback.
func TestRT_Webhook_Fixed_AllowedNameResolvingToInternalAddress(t *testing.T) {
	var hits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) })}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	m, err := drift.New(drift.Config{Allow: []string{"*.localhost"}, AllowHTTP: true}, drift.Deps{DB: contracttest.New(t).DB})
	if err != nil {
		t.Fatal(err)
	}
	w, err := m.CreateWebhook(context.Background(), drift.Webhook{Name: "rt-ssrf", URL: fmt.Sprintf("http://metadata.localhost:%s/latest", port), Events: []string{"rule.stale"}})
	if err != nil {
		t.Fatal(err)
	}
	err = m.SendTest(context.Background(), w.ID)
	if err == nil || hits.Load() > 0 {
		t.Fatalf("delivery to an allow-listed name resolving to 127.0.0.1 went through (%d request(s) received by the internal service)", hits.Load())
	}
}
