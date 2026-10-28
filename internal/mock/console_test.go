package mock

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
	"github.com/ivseb/traffic-twin/internal/packwriter"
)

// fakeConsole is the agent API of tt-core as a mock in console mode sees it.
type fakeConsole struct {
	t     *testing.T
	token string

	mu       sync.Mutex
	packID   string
	archive  []byte
	refuse   bool
	reports  []Report
	commands []Command
	results  map[string]CommandResult
	identity *IdentityWire
}

func (f *fakeConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse || r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"code":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case AgentPackPath:
		if f.archive == nil {
			http.Error(w, `{"code":"no_pack"}`, http.StatusNotFound)
			return
		}
		w.Header().Set(HeaderPackID, f.packID)
		_, _ = w.Write(f.archive)
	case AgentReportPath:
		var rep Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			f.t.Errorf("report: %v", err)
			http.Error(w, "bad", 400)
			return
		}
		f.reports = append(f.reports, rep)
		for _, res := range rep.Results {
			f.results[res.ID] = res
		}
		cmds := f.commands
		f.commands = nil
		if cmds == nil {
			cmds = []Command{}
		}
		_ = json.NewEncoder(w).Encode(ReportAnswer{PackID: f.packID, Commands: cmds, Identity: f.identity})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeConsole) set(id string, archive []byte) {
	f.mu.Lock()
	f.packID, f.archive = id, archive
	f.mu.Unlock()
}

func (f *fakeConsole) last() Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		return Report{}
	}
	return f.reports[len(f.reports)-1]
}

func (f *fakeConsole) allCalls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Call
	for _, r := range f.reports {
		out = append(out, r.Calls...)
	}
	return out
}

// signedArchive builds a demo pack with this id and group, signed with key
// (a fresh one when nil), as a .ttpack.
func signedArchive(t *testing.T, id, group string, b *packtest.Built) ([]byte, *packtest.Built) {
	t.Helper()
	spec := packtest.DemoSpec()
	spec.Manifest["pack_id"] = id
	var rep map[string]any
	if err := json.Unmarshal(spec.Files["gate-report.json"], &rep); err != nil {
		t.Fatal(err)
	}
	rep["pack_id"] = id
	spec.Files["gate-report.json"] = packtest.CJSON(rep)
	if group != "" {
		spec.Manifest["group"] = group
	}
	dir := filepath.Join(t.TempDir(), id)
	var err error
	if b == nil {
		if b, err = packtest.Build(dir, spec); err != nil {
			t.Fatal(err)
		}
	} else {
		b2 := *b
		b2.Dir = dir
		if err := b2.Write(spec); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{}
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)], err = os.ReadFile(p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := packwriter.Archive(files)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(b)))
	return len(b), nil
}

const testMockToken = "ttm_0123456789abcdef01234567.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func startConsoleMock(t *testing.T, fc *fakeConsole, keys, group string) (string, chan error) {
	t.Helper()
	srv := httptest.NewServer(fc)
	t.Cleanup(srv.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	cfg := Config{Listener: ln, GatePubKeys: keys, Latency: LatencyOff, Faults: "off", MaxPackAge: -1,
		Logger: slog.New(slog.NewTextHandler(testWriter{t}, nil))}
	go func() {
		done <- RunConsole(ctx, cfg, ConsoleConfig{URL: srv.URL, Token: testMockToken, Group: group, Instance: "ci-1",
			Interval: 20 * time.Millisecond, TempDir: t.TempDir(), PublicURL: "http://mock.test:8480"})
	}()
	return "http://" + ln.Addr().String(), done
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConsoleModeFetchReportReload(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	a1, built := signedArchive(t, "pk-test-0001", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	base, _ := startConsoleMock(t, fc, "", "shop")

	// Before the first pack: health only, the data plane says why.
	resp, err := http.Get(base + "/__tt/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health before the pack: %v %v", resp, err)
	}
	resp.Body.Close()
	waitFor(t, "a waiting report", func() bool { return fc.last().Status == "waiting" })
	if r, _ := http.Get(base + "/__svc/shop-api/orders"); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("data plane before the pack: %d", r.StatusCode)
	}

	fc.set("pk-test-0001", a1)
	waitFor(t, "serving pk-test-0001", func() bool { r := fc.last(); return r.Status == "serving" && r.PackID == "pk-test-0001" })
	rep := fc.last()
	if rep.Group != "shop" || rep.Instance != "ci-1" || rep.PublicURL != "http://mock.test:8480" || len(rep.Services) == 0 {
		t.Fatalf("report: %+v", rep)
	}
	if !strings.HasPrefix(rep.Services[0].BaseURL, "http://mock.test:8480/__svc/") {
		t.Fatalf("service URL: %+v", rep.Services[0])
	}

	// A call is summarized: method, path, status, no query string, no body.
	r, err := http.Post(base+"/__svc/shop-api/nowhere?secret=1", "application/json", strings.NewReader(`{"card":"4111"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	waitFor(t, "the call in a report", func() bool { return len(fc.allCalls()) > 0 })
	c := fc.allCalls()[0]
	if c.Method != "POST" || c.Session != "default" || c.Status != 404 || strings.Contains(c.Path, "secret") {
		t.Fatalf("call: %+v", c)
	}
	raw, _ := json.Marshal(fc.allCalls())
	if strings.Contains(string(raw), "4111") {
		t.Fatalf("a body reached the console: %s", raw)
	}

	// Commands from the console run on the control API.
	fc.mu.Lock()
	fc.commands = []Command{
		{ID: "cmd_1", Method: "POST", Path: "/__tt/sessions", Body: json.RawMessage(`{"id":"t1","seed":7}`)},
		{ID: "cmd_2", Method: "GET", Path: "/__tt/sessions/t1/journal"},
	}
	fc.mu.Unlock()
	waitFor(t, "command results", func() bool { fc.mu.Lock(); defer fc.mu.Unlock(); return len(fc.results) == 2 })
	if res := fc.results["cmd_1"]; res.Status != http.StatusCreated {
		t.Fatalf("create session: %+v", res)
	}
	if res := fc.results["cmd_2"]; res.Status != http.StatusBadRequest {
		t.Fatalf("journal from the console must be refused: %+v", res)
	}
	waitFor(t, "session t1 reported", func() bool {
		for _, s := range fc.last().Sessions {
			if s.ID == "t1" {
				return true
			}
		}
		return false
	})

	// A newer pack is swapped in without a restart.
	a2, _ := signedArchive(t, "pk-test-0002", "shop", built)
	fc.set("pk-test-0002", a2)
	waitFor(t, "serving pk-test-0002", func() bool { return fc.last().PackID == "pk-test-0002" })
	resp, err = http.Get(base + "/__tt/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health after reload: %v", err)
	}
	resp.Body.Close()
}

func TestConsoleModeRefusesWrongGroupAndBadSignature(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	other, built := signedArchive(t, "pk-test-0003", "other-team", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	fc.set("pk-test-0003", other)
	base, _ := startConsoleMock(t, fc, "", "shop")
	waitFor(t, "the refusal reported", func() bool { return strings.Contains(fc.last().PackError, "other-team") })
	if r := fc.last(); r.Status != "waiting" || r.PackID != "" {
		t.Fatalf("a pack of another group was served: %+v", r)
	}
	if r, _ := http.Get(base + "/__svc/shop-api/orders"); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("data plane: %d", r.StatusCode)
	}

	// Signed by another key: refused the same way.
	forged, _ := signedArchive(t, "pk-test-0004", "shop", nil)
	fc.set("pk-test-0004", forged)
	waitFor(t, "the forged pack refused", func() bool { return strings.HasPrefix(fc.last().PackError, "pk-test-0004") })
	if fc.last().Status != "waiting" {
		t.Fatal("forged pack served")
	}
}

func TestConsoleModeStopsOnRefusedToken(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	a, built := signedArchive(t, "pk-test-0005", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	fc.set("pk-test-0005", a)
	_, done := startConsoleMock(t, fc, "", "shop")
	waitFor(t, "serving", func() bool { return fc.last().Status == "serving" })
	fc.mu.Lock()
	fc.refuse = true // the token was revoked
	fc.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTokenRefused) {
			t.Fatalf("stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the mock kept running with a refused token")
	}
}

func TestConsoleFlags(t *testing.T) {
	t.Setenv(EnvMockToken, testMockToken)
	c, err := ParseFlags([]string{"--console", "https://tt.example.internal/", "--group", "shop"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Console == nil || c.Console.URL != "https://tt.example.internal" || c.Console.Token != testMockToken || c.Console.Group != "shop" {
		t.Fatalf("console config: %+v", c.Console)
	}
	for _, bad := range [][]string{
		{"--console", "http://tt.example.internal", "--group", "shop"}, // plain http off the loopback
		{"--console", "https://tt.example.internal"},                   // no group
		{"--console", "https://tt.example.internal", "--group", "shop", "--pack", "x.ttpack"},
	} {
		if _, err := ParseFlags(bad, io.Discard); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	t.Setenv(EnvMockToken, "not-a-token")
	if _, err := ParseFlags([]string{"--console", "https://tt.example.internal", "--group", "shop"}, io.Discard); err == nil {
		t.Error("accepted a malformed token")
	}
}

// The console's "session per user" reaches the mock live, also across a
// pack change, and an off setting turns it off.
func TestConsoleModeIdentity(t *testing.T) {
	fc := &fakeConsole{t: t, token: testMockToken, results: map[string]CommandResult{}}
	a1, built := signedArchive(t, "pk-test-0001", "shop", nil)
	t.Setenv("TT_GATE_PUBKEYS", built.Keys)
	base, _ := startConsoleMock(t, fc, "", "shop")
	key := []byte(strings.Repeat("q", 32))
	fc.mu.Lock()
	fc.identity = &IdentityWire{Header: "X-Caller", Key: base64.RawURLEncoding.EncodeToString(key),
		Map: map[string]string{"h:" + IdentityHash(key, "tester-1"): "CUS-SYN-0009"}}
	fc.mu.Unlock()
	fc.set("pk-test-0001", a1)
	waitFor(t, "serving", func() bool { return fc.last().Status == "serving" })
	session := func(user string) string {
		req, _ := http.NewRequest("GET", base+"/__svc/shop-api/ping", nil)
		if user != "" {
			req.Header.Set("X-Caller", user)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.Header.Get("X-TT-Session")
	}
	want := "u-" + IdentityHash(key, "tester-1")[:16]
	waitFor(t, "the identity session", func() bool { return session("tester-1") == want })
	if session("") != "default" {
		t.Fatal("no identity: default session")
	}
	// A new pack keeps the setting.
	a2, _ := signedArchive(t, "pk-test-0002", "shop", built)
	fc.set("pk-test-0002", a2)
	waitFor(t, "serving pk-test-0002", func() bool { return fc.last().PackID == "pk-test-0002" })
	if got := session("tester-1"); got != want {
		t.Fatalf("after a pack change: %q, want %q", got, want)
	}
	// Turned off by the console.
	fc.mu.Lock()
	fc.identity = &IdentityWire{Header: ""}
	fc.mu.Unlock()
	waitFor(t, "identity off", func() bool { return session("tester-1") == "default" })
}
