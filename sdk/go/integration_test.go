package ttsdk

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

const refKey = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func integrationConfig(core *fakecore.Core, dir string) Config {
	return Config{
		EnrollURL: core.URL, EnrollToken: core.Token, ServiceName: "shop-api", StateDir: dir, HMACKeys: refKey,
		HeartbeatInterval: 30 * time.Millisecond, PolicyPollInterval: 30 * time.Millisecond, ExportFlushEvery: 20 * time.Millisecond,
	}
}

// TestEndToEndWithFakeCore runs the real stack: enrollment with a pinned
// token over TLS, signed policy, heartbeat, mTLS OTLP export, kill switch.
func TestEndToEndWithFakeCore(t *testing.T) {
	core := fakecore.New(t, "shop")
	state := filepath.Join(t.TempDir(), "state")
	a, err := New(integrationConfig(core, state))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	// Carrier stub reached through the SDK transport.
	carrier := &stubRT{fn: func(r *http.Request) (*http.Response, error) { return jsonResp(r, 201, `{"status":"CREATED"}`), nil }}
	client := &http.Client{Transport: a.Transport(carrier)}
	app := a.Handler(func() http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /orders", func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			req, _ := http.NewRequestWithContext(r.Context(), "POST", "https://api.carrier.example/v1/shipments", strings.NewReader(`{"orderId":"ORD-77"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(append([]byte(`{"status":"CREATED","echo":`), append(b, '}')...))
		})
		return mux
	}())
	srv := httptest.NewServer(app)
	defer srv.Close()
	order := func() {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/orders", strings.NewReader(`{"sku":"TSHIRT","email":"mario.rossi@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Customer-Id", "c-10042")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}

	// Fail closed: enrolled or not, without a policy nothing is captured and
	// the application works.
	order()
	if a.Capturing() {
		t.Fatal("capturing without a policy")
	}
	if a.Stats().ExchangesSampled != 0 {
		t.Fatal("sampled without a policy")
	}

	core.SetPolicy(core.Compile(shopPolicy("1", true), 1, 1))
	core.Eventually(10*time.Second, "capture active", a.Capturing)
	if core.Enrollments() != 1 {
		t.Fatalf("enrollments = %d", core.Enrollments())
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state dir: %v %v", fi, err)
	}

	order()
	evs := parseEvents(t, core.WaitEvents(2, 10*time.Second))
	var in, out event
	for _, e := range evs {
		if e.str("dir") == "inbound" {
			in = e
		} else {
			out = e
		}
	}
	if in == nil || out == nil {
		t.Fatalf("events: %v", evs)
	}
	if in.str("op") != "POST /orders" || in.str("route_source") != "framework" || in.str("service") != "shop-api" || in.str("req", "body", "sku") != "keep:TSHIRT" {
		t.Errorf("inbound event: %v", in)
	}
	if out.str("service") != "shipping-ext" || out.str("sampled_by") != "inherited" || out.str("trace_id") != in.str("trace_id") ||
		!strings.HasPrefix(out.str("req", "body", "orderId"), "tk1:k1:") {
		t.Errorf("outbound event: %v", out)
	}
	for _, e := range evs {
		raw := string(mustJSON(e))
		for _, leak := range []string{"mario", "example.com\"", "10042", "ORD-77"} {
			if strings.Contains(raw, leak) {
				t.Errorf("event leaks %q: %s", leak, raw)
			}
		}
	}

	// The kill switch stops the capture; the application is not touched.
	n := len(core.Events())
	core.Kill(true)
	core.Eventually(10*time.Second, "capture stopped", func() bool { return !a.Capturing() })
	order()
	order()
	time.Sleep(150 * time.Millisecond)
	if got := len(core.Events()); got != n {
		t.Fatalf("%d events after the kill switch", got-n)
	}
	core.Kill(false)
	core.Eventually(10*time.Second, "capture resumed", a.Capturing)
	order()
	core.WaitEvents(n+2, 10*time.Second)

	core.Eventually(10*time.Second, "events counted as sent", func() bool { return a.Stats().EventsSent >= int64(n+2) })
	st := a.Stats()
	if st.State != "capturing" || st.SanitizerErrors != 0 {
		t.Errorf("stats = %+v", st)
	}
	// Close flushes what is queued.
	order()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(core.Events()); got < n+4 {
		t.Fatalf("Close did not flush: %d events", got)
	}
}

func TestMissingKeyCapturesNothing(t *testing.T) {
	core := fakecore.New(t, "shop")
	cfg := integrationConfig(core, t.TempDir())
	cfg.HMACKeys = "" // and no TT_HMAC_KEY / TT_HMAC_KEY_FILE in the environment
	t.Setenv(EnvHMACKey, "")
	t.Setenv(EnvHMACKeyFile, "")
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	core.SetPolicy(core.Compile(shopPolicy("1", true), 1, 1))
	core.Eventually(10*time.Second, "heartbeat", func() bool { return len(core.Heartbeats()) > 1 })
	if a.Capturing() {
		t.Fatal("capturing without an HMAC key")
	}
	rec := httptest.NewRecorder()
	a.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })).
		ServeHTTP(rec, httptest.NewRequest("GET", "/orders/1", nil))
	if rec.Body.String() != "ok" || len(core.Events()) != 0 {
		t.Fatal("app must work, nothing may be captured")
	}
}

func TestKeyFileFromEnvironment(t *testing.T) {
	f := filepath.Join(t.TempDir(), "hmac")
	if err := os.WriteFile(f, []byte(refKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvHMACKey, "")
	t.Setenv(EnvHMACKeyFile, f)
	ks, kids, err := loadKeys(Config{})
	if err != nil || ks.Len() != 1 || len(kids) != 1 || kids[0] != "k1" {
		t.Fatalf("keys %v kids %v err %v", ks, kids, err)
	}
}
