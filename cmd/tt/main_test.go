package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/config"
)

func runArgs(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runArgs("version")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{version, commit, date} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q does not contain %q", out, want)
		}
	}
}

func TestEgressRequiresUpstream(t *testing.T) {
	t.Setenv("TT_EGRESS_UPSTREAMS", "")
	t.Setenv("TT_EGRESS_CONFIG", "")
	code, _, errOut := runArgs("egress")
	if code != 2 || !strings.Contains(errOut, "no upstream configured") {
		t.Errorf("egress: code=%d stderr=%q", code, errOut)
	}
}

func TestPackCommandsRequirePack(t *testing.T) {
	for _, name := range []string{"mock", "export"} {
		code, _, errOut := runArgs(name)
		if code != 2 || !strings.Contains(errOut, "--pack is required") {
			t.Errorf("%s: code=%d stderr=%q", name, code, errOut)
		}
	}
}

func TestExportRefusesUnverifiedPack(t *testing.T) {
	t.Setenv("TT_GATE_PUBKEYS", "")
	code, _, errOut := runArgs("export", "--pack", "../../internal/export/testdata/carrier-pack", "--out", t.TempDir())
	if code != 1 {
		t.Fatalf("code=%d stderr=%q, want refusal", code, errOut)
	}
}

func TestUsageAndUnknown(t *testing.T) {
	if code, _, _ := runArgs(); code != 2 {
		t.Errorf("no args: code = %d, want 2", code)
	}
	if code, out, _ := runArgs("help"); code != 0 || !strings.Contains(out, "core") {
		t.Errorf("help: code=%d out=%q", code, out)
	}
	if code, _, errOut := runArgs("nope"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Errorf("unknown: code=%d stderr=%q", code, errOut)
	}
	if code, _, _ := runArgs("version", "extra"); code != 2 {
		t.Errorf("extra args: code = %d, want 2", code)
	}
	if code, _, _ := runArgs("core", "-h"); code != 0 {
		t.Errorf("core -h: code = %d, want 0", code)
	}
}

func TestCoreConfigErrors(t *testing.T) {
	if code, _, errOut := runArgs("core", "-config", filepath.Join(t.TempDir(), "missing.yaml")); code != 1 || !strings.Contains(errOut, "config") {
		t.Errorf("missing config: code=%d stderr=%q", code, errOut)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(bad, []byte("admin:\n  addr: 0.0.0.0:7070\n"), 0o600)
	if code, _, errOut := runArgs("core", "-config", bad); code != 1 || !strings.Contains(errOut, "admin.tls") {
		t.Errorf("non-loopback without TLS: code=%d stderr=%q", code, errOut)
	}
	if code, _, _ := runArgs("core", "-addr", "0.0.0.0:7070"); code != 1 {
		t.Errorf("-addr non-loopback without TLS accepted: %d", code)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func waitHTTP(t *testing.T, hc *http.Client, url string) {
	t.Helper()
	var err error
	for range 100 {
		var resp *http.Response
		if resp, err = hc.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("%s: %v", url, err)
}

// tt dev up: keyguard on a Unix socket and core on loopback, ready, with
// the setup token on the console and never in the log.
func TestDevUp(t *testing.T) {
	dir, err := os.MkdirTemp("", "ttdev")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	admin, intake := freeAddr(t), freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr lockedBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"dev", "up", "-dir", dir, "-admin", admin, "-intake", intake}, &stdout, &stderr)
	}()
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // self-signed test certificate
	waitHTTP(t, hc, "https://"+admin+"/readyz")
	resp, err := hc.Get("https://" + admin + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("UI served without CSP")
	}
	resp.Body.Close()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("dev up exit %d: %s", code, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("dev up did not stop")
	}
	out := stdout.String()
	if !strings.Contains(out, "https://"+admin) || !strings.Contains(out, "TT_HMAC_KEY_FILE=") || !strings.Contains(out, "tts_") {
		t.Errorf("stdout = %q", out)
	}
	tok := strings.Fields(out[strings.Index(out, "tts_"):])[0]
	if strings.Contains(stderr.String(), tok) {
		t.Error("setup token written to the log")
	}
	if fi, err := os.Stat(filepath.Join(dir, "keys", "hmac.keys")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("hmac key file: %v %v", fi, err)
	}
	if code, _, errOut := runArgs("dev", "up", "-admin", "0.0.0.0:7070"); code != 2 || !strings.Contains(errOut, "loopback") {
		t.Errorf("non-loopback dev up: %d %q", code, errOut)
	}
}

func TestCoreInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	code, out, errOut := runArgs("core", "init", "-dir", dir)
	if code != 0 {
		t.Fatalf("init: %d %s", code, errOut)
	}
	cfgFile := filepath.Join(dir, "core.yaml")
	if !strings.Contains(out, cfgFile) || !strings.Contains(out, "tt keyguard -socket") {
		t.Errorf("stdout = %q", out)
	}
	fi, err := os.Stat(cfgFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", fi, err)
	}
	if _, err := config.Load(cfgFile, nil); err != nil {
		t.Fatalf("written configuration does not load: %v", err)
	}
	if code, _, errOut := runArgs("core", "init", "-dir", dir); code != 1 || !strings.Contains(errOut, "never overwritten") {
		t.Errorf("second init: %d %q", code, errOut)
	}
}

func TestCoreNeedsKeyguard(t *testing.T) {
	t.Setenv("TT_CORE_CONFIG", "")
	if code, _, errOut := runArgs("core"); code != 1 || !strings.Contains(errOut, "keyguard.url") || !strings.Contains(errOut, "tt dev up") {
		t.Errorf("core without keyguard: code=%d stderr=%q", code, errOut)
	}
}
