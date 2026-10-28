package mock

import (
	"context"
	"encoding/pem"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/packwriter"
)

// Security review of console mode (mock.md 6.2): the console is not trusted
// to sign, so what it sends is verified exactly like a file.

// withoutSignature drops manifest.sig.json from a .ttpack.
func withoutSignature(t *testing.T, archive []byte) []byte {
	t.Helper()
	files, err := packwriter.ReadArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	delete(files, "manifest.sig.json")
	b, err := packwriter.Archive(files)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConsoleModeRefusesUnsignedUngroupedAndRevoked(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	good, built := signedArchive(t, "pk-sec-0001", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	fc.set("pk-sec-0001", withoutSignature(t, good))
	_, _ = startConsoleMock(t, fc, "", "shop")

	// Unsigned: refused, nothing served.
	waitFor(t, "the unsigned pack refused", func() bool { return strings.HasPrefix(fc.last().PackError, "pk-sec-0001") })
	if r := fc.last(); r.Status != "waiting" || r.PackID != "" {
		t.Fatalf("unsigned pack served: %+v", r)
	}

	// Signed with a trusted key but without manifest.group (a pack for
	// every group): refused in console mode.
	nogroup, _ := signedArchive(t, "pk-sec-0002", "", built)
	fc.set("pk-sec-0002", nogroup)
	waitFor(t, "the pack without group refused", func() bool { return strings.HasPrefix(fc.last().PackError, "pk-sec-0002") })
	if r := fc.last(); r.Status != "waiting" || !strings.Contains(r.PackError, "every group") {
		t.Fatalf("pack without group: %+v", r)
	}
}

func TestConsoleModeRefusesRevokedGateKey(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	a, built := signedArchive(t, "pk-sec-0003", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	kid, _, _ := strings.Cut(built.Keys, ":")
	t.Setenv("TT_GATE_REVOKED_KIDS", kid) // still in TT_GATE_PUBKEYS, but revoked
	fc.set("pk-sec-0003", a)
	_, _ = startConsoleMock(t, fc, "", "shop")
	waitFor(t, "the revoked key refused", func() bool { return strings.Contains(fc.last().PackError, "revoked") })
	if r := fc.last(); r.Status != "waiting" {
		t.Fatalf("pack signed by a revoked key served: %+v", r)
	}
}

// noIDConsole answers the pack download without X-TT-Pack-Id.
type noIDConsole struct {
	*fakeConsole
	downloads *int
}

func (n noIDConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == AgentPackPath {
		n.mu.Lock()
		a := n.archive
		*n.downloads++
		n.mu.Unlock()
		_, _ = w.Write(a)
		return
	}
	n.fakeConsole.ServeHTTP(w, r)
}

func TestConsoleModeRefusesPackWithoutAnnouncedID(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	a, built := signedArchive(t, "pk-sec-0004", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	fc.set("pk-sec-0004", a)
	downloads := 0
	srv := httptest.NewServer(noIDConsole{fc, &downloads})
	t.Cleanup(srv.Close)
	runConsoleAt(t, srv.URL, "shop")
	waitFor(t, "the pack without id refused", func() bool { return strings.HasPrefix(fc.last().PackError, "pk-sec-0004: ") })
	if r := fc.last(); r.Status != "waiting" {
		t.Fatalf("pack without announced id served: %+v", r)
	}
	// Remembered as refused: not downloaded again at every report.
	fc.mu.Lock()
	n := len(fc.reports)
	fc.mu.Unlock()
	waitFor(t, "more reports", func() bool { fc.mu.Lock(); defer fc.mu.Unlock(); return len(fc.reports) > n+3 })
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if downloads != 1 {
		t.Fatalf("the refused pack was downloaded %d times", downloads)
	}
}

func runConsoleAt(t *testing.T, consoleURL, group string) chan error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	cfg := Config{Listener: ln, Latency: LatencyOff, Faults: "off", MaxPackAge: -1, Logger: slog.New(slog.NewTextHandler(testWriter{t}, nil))}
	go func() {
		done <- RunConsole(ctx, cfg, ConsoleConfig{URL: consoleURL, Token: testMockToken, Group: group, Instance: "ci-1",
			Interval: 20 * time.Millisecond, TempDir: t.TempDir()})
	}()
	return done
}

// The mock token never follows a redirect (to plain http, another port or
// another origin).
func TestConsoleModeDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	t.Cleanup(sink.Close)
	var hits int
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		http.Redirect(w, r, sink.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)
	_, built := signedArchive(t, "pk-sec-0005", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	runConsoleAt(t, redir.URL, "shop")
	waitFor(t, "a report attempt", func() bool { mu.Lock(); defer mu.Unlock(); return hits > 0 })
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(leaked) != 0 {
		t.Fatalf("the mock followed a redirect with headers %q", leaked)
	}
}

// The console's TLS certificate is verified: an untrusted certificate gets
// no token and no report; with TT_MOCK_CONSOLE_CA the same console works.
func TestConsoleModeVerifiesConsoleTLS(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	_, built := signedArchive(t, "pk-sec-0006", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	srv := httptest.NewTLSServer(fc)
	t.Cleanup(srv.Close)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	start := func(ca string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		cfg := Config{Listener: ln, Latency: LatencyOff, Faults: "off", MaxPackAge: -1, Logger: slog.New(slog.NewTextHandler(testWriter{t}, nil))}
		go func() {
			_ = RunConsole(ctx, cfg, ConsoleConfig{URL: srv.URL, Token: testMockToken, Group: "shop", Instance: "ci-tls", CAFile: ca,
				Interval: 20 * time.Millisecond, TempDir: t.TempDir()})
		}()
	}
	start("")
	time.Sleep(300 * time.Millisecond)
	fc.mu.Lock()
	n := len(fc.reports)
	fc.mu.Unlock()
	if n != 0 {
		t.Fatalf("the mock talked to a console with an untrusted certificate (%d reports)", n)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	start(caFile)
	waitFor(t, "a report over verified TLS", func() bool { fc.mu.Lock(); defer fc.mu.Unlock(); return len(fc.reports) > 0 })
}
