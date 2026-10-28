package egress_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/egress"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestCLIProxyOnlyMode(t *testing.T) {
	for _, k := range []string{"TT_ENROLL_URL", "TT_ENROLL_TOKEN", "TT_EGRESS_UPSTREAMS", "TT_EGRESS_CONFIG", "TT_EGRESS_LISTEN"} {
		t.Setenv(k, "")
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hi "+r.URL.Path) }))
	defer up.Close()
	cfg := filepath.Join(t.TempDir(), "egress.yaml")
	if err := os.WriteFile(cfg, []byte("upstreams:\n  - alias: from-file\n    url: http://127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuf
	done := make(chan int, 1)
	go func() {
		done <- egress.RunCLI(ctx, []string{"--config", cfg, "--listen", "127.0.0.1:0", "--upstream", "app=" + up.URL}, &out, &errb, "v1.2.3")
	}()
	re := regexp.MustCompile(`listening on (\S+)`)
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			addr = m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("no listen line: %q %q", out.String(), errb.String())
	}
	resp, err := http.Get("http://" + addr + "/app/x/y")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hi /x/y" {
		t.Fatalf("body %q", b)
	}
	resp, err = http.Get("http://" + addr + egress.HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"capture":"disabled"`) || !strings.Contains(string(b), "from-file") {
		t.Fatalf("health %s", b)
	}
	if !strings.Contains(errb.String(), "capture disabled") {
		t.Fatalf("no proxy-only warning: %s", errb.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop")
	}
}

func TestCLIRejectsBadUsage(t *testing.T) {
	for _, k := range []string{"TT_ENROLL_URL", "TT_ENROLL_TOKEN", "TT_EGRESS_UPSTREAMS", "TT_EGRESS_CONFIG", "TT_SERVICE_NAME"} {
		t.Setenv(k, "")
	}
	for _, args := range [][]string{
		{"--upstream", "nope"},
		{"--upstream", "Bad=https://x.example"},
		{"--upstream", "a=https://x.example", "--capture-origin", "zzz=https://y.example"},
		{"--upstream", "a=https://x.example", "extra"},
		{"--upstream", "a=https://x.example", "--enroll-url", "https://core.example:4318"}, // no service name
	} {
		var out, errb bytes.Buffer
		if code := egress.RunCLI(context.Background(), args, &out, &errb, "dev"); code != 2 {
			t.Errorf("%v: exit %d (%s)", args, code, errb.String())
		}
	}
	t.Setenv("TT_ENROLL_TOKEN", "tte_x")
	var out, errb bytes.Buffer
	if code := egress.RunCLI(context.Background(), []string{"--upstream", "a=https://x.example"}, &out, &errb, "dev"); code != 2 {
		t.Errorf("token without url: exit %d", code)
	}
}
