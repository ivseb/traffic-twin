package obi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

// TestLab is a manual smoke test against a real OBI, skipped unless
// TT_OBI_LAB is set. It starts a fake tt-core with the demo policy
// (example/policy.demo-shop.yaml), the bridge receiver on TT_OBI_LAB_LISTEN
// (default 0.0.0.0:4318) and writes the generated OBI configuration to
// TT_OBI_LAB_CONFIG, then collects events for TT_OBI_LAB_SECONDS (default 60)
// and writes them, one per line, to TT_OBI_LAB_EVENTS. See README.md.
func TestLab(t *testing.T) {
	if os.Getenv("TT_OBI_LAB") == "" {
		t.Skip("set TT_OBI_LAB=1 to run against a real OBI")
	}
	raw, err := os.ReadFile(filepath.Join("example", "policy.demo-shop.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	author := toJSONString(t, doc)

	core := fakecore.New(t, "shop")
	keys, kids := fakecore.HMACKeys()
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: core.URL, Token: core.Token, StateDir: t.TempDir(),
		Kind: "obi", Version: "0.1.0", ServiceName: "shop-api", Keys: keys, KeyKids: kids,
		HeartbeatInterval: 200 * time.Millisecond, PolicyPollInterval: 200 * time.Millisecond,
		Exporter: sourceclient.ExporterOptions{FlushInterval: 200 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	core.SetPolicy(core.Compile(author, 1, 1))
	ctx, cancel := context.WithCancel(context.Background())
	src.Start(ctx)
	defer func() {
		cctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = src.Close(cctx)
		cancel()
	}()
	core.Eventually(10*time.Second, "capture active", func() bool { _, ok := src.Active(); return ok })

	cp, _ := src.Active()
	if out := os.Getenv("TT_OBI_LAB_CONFIG"); out != "" {
		g, err := GenerateConfig(cp.Policy.Policy, ConfigOptions{ServiceName: "shop-api", Endpoint: os.Getenv("TT_OBI_LAB_ENDPOINT"),
			OpenPorts: os.Getenv("TT_OBI_LAB_PORTS"), CaptureBytes: DefaultCaptureSize})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, g.YAML, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	addr := os.Getenv("TT_OBI_LAB_LISTEN")
	if addr == "" {
		addr = "0.0.0.0:4318"
	}
	br := NewBridge(BridgeConfig{Sink: src, ServiceFilter: "shop-api", CaptureLimit: DefaultCaptureSize})
	defer br.Close()
	srv := startHTTP(t, addr, br)
	defer srv()

	secs, _ := strconv.Atoi(os.Getenv("TT_OBI_LAB_SECONDS"))
	if secs <= 0 {
		secs = 60
	}
	time.Sleep(time.Duration(secs) * time.Second)
	evs := core.Events()
	t.Logf("%d events, bridge stats: %+v", len(evs), src.Stats().Counters)
	if out := os.Getenv("TT_OBI_LAB_EVENTS"); out != "" {
		var b []byte
		for _, e := range evs {
			b = append(append(b, e...), '\n')
		}
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func toJSONString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// startHTTP serves the bridge receiver and returns the stop function.
func startHTTP(t *testing.T, addr string, br *Bridge) func() {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: br.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Close() }
}
