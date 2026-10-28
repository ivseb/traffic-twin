package ttsdk

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// fakeSource is a source that is always active with a fixed capture, and
// keeps the events it is given. It lets the tests drive the real capture
// path (Handler, Transport, workers, sanitizer, event builder) without a
// network.
type fakeSource struct {
	mu       sync.Mutex
	cap      sourceclient.Capture
	active   bool
	events   [][]byte
	counters sourceclient.Counters
	errs     []string
}

func (f *fakeSource) Start(context.Context)       {}
func (f *fakeSource) Close(context.Context) error { return nil }
func (f *fakeSource) Active() (sourceclient.Capture, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cap, f.active
}
func (f *fakeSource) Emit(ev sourceclient.Event) {
	f.mu.Lock()
	f.events = append(f.events, append([]byte(nil), ev.JSON...))
	f.mu.Unlock()
}
func (f *fakeSource) Counters() *sourceclient.Counters { return &f.counters }
func (f *fakeSource) ObserveOverhead(time.Duration)    {}
func (f *fakeSource) RecordError(c string) {
	f.mu.Lock()
	f.errs = append(f.errs, c)
	f.mu.Unlock()
}
func (f *fakeSource) Stats() sourceclient.Stats {
	return sourceclient.Stats{State: "capturing", Counters: f.counters.Snapshot()}
}
func (f *fakeSource) set(c sourceclient.Capture, active bool) {
	f.mu.Lock()
	f.cap, f.active = c, active
	f.mu.Unlock()
}
func (f *fakeSource) taken() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.events...)
}

// testKeys returns the reference key of the conformance suite (kid k1).
func testKeys(t testing.TB) sanitizer.KeySet {
	t.Helper()
	ks, err := sanitizer.ParseKeys("k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// captureFor builds the Capture of a source with this author policy.
func captureFor(t testing.TB, authorJSON, service string) sourceclient.Capture {
	t.Helper()
	p := mustPolicy(t, authorJSON)
	eng, err := sanitizer.NewEngine(p, testKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	return sourceclient.Capture{Engine: eng, Policy: &policy.Verified{Policy: p, Hash: "sha256:" + strings.Repeat("ab", 32)},
		OverrideBP: -1, SourceID: "src-TEST0001", ServiceName: service, Kind: Kind, Version: Version}
}

// testAgent builds an agent on a fake source.
func testAgent(t testing.TB, fs *fakeSource, mod func(*Config)) *Agent {
	t.Helper()
	cfg := Config{Workers: 2}
	if mod != nil {
		mod(&cfg)
	}
	a := newAgent(cfg)
	a.attach(fs)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = a.Close(ctx)
	})
	return a
}

// drain closes the agent, which lets the workers finish what is queued.
func drain(t testing.TB, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// mustPolicy compiles an author policy (JSON form of tt.policy/v1).
func mustPolicy(t testing.TB, authorJSON string) *policy.Policy {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(authorJSON))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: time.Now(), Groups: []string{"shop"}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
