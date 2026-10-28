package obi

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

// shopPolicy is an author policy (JSON form of tt.policy/v1) for the
// invented shop: one inbound service, one external carrier, the subject in
// x-customer-id, every exchange sampled.
const shopPolicy = `{
 "format":"tt.policy/v1","policy_id":"p-shop","default":"drop",
 "hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"x-customer-id"}},
 "sampling":{"rate":1},
 "global":{"request":{"headers":{"content-type":"keep"}},"response":{"headers":{"content-type":"keep"}},"errors":{"body":{"$.error.code":"keep"}}},
 "services":{
  "shop-api":{"match":{"inbound":true},"ops":{
    "POST /orders":{
      "request":{"body":{"$.items[*].qty":"bucket(num, [0, 5, 10])","$.card.number":"drop"}},
      "response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},
    "GET /orders/{id}":{
      "request":{"path":{"id":"hmac(order)"},"query":{"expand":"keep"}},
      "response":{"$.id":"hmac(order)"}}}},
  "shipping-ext":{"match":{"base":"https://api.carrier.example"},"ops":{
    "POST /v1/shipments":{"request":{"body":{"$.orderId":"hmac(order)"}},"response":{"$.shipmentId":"hmac(shipment)","$.status":"keep"}},
    "GET /v1/shipments/{id}":{"request":{"path":{"id":"hmac(shipment)"}},"response":{"$.shipmentId":"hmac(shipment)","$.status":"keep"}}}}
 }}`

func compile(t testing.TB, author string) (*policy.Verified, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal([]byte(author), &doc); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := policy.Compile(a, policy.CompileMeta{Version: 7, IssuedSeq: 31, CreatedAt: time.Now(), Groups: []string{"shop"}})
	if err != nil {
		t.Fatal(err)
	}
	env, err := policy.Sign(body, "policy-test-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	ring := policy.NewKeyRing()
	if err := ring.Pin("policy-test-1", pub); err != nil {
		t.Fatal(err)
	}
	v, err := policy.Verify(env, ring)
	if err != nil {
		t.Fatal(err)
	}
	return v, pub
}

// testCapture builds what the Fleet source would hand to the bridge.
func testCapture(t testing.TB, author string) sourceclient.Capture {
	t.Helper()
	v, _ := compile(t, author)
	keys, _ := fakecore.HMACKeys()
	eng, err := sanitizer.NewEngine(v.Policy, keys)
	if err != nil {
		t.Fatal(err)
	}
	return sourceclient.Capture{Engine: eng, Policy: v, OverrideBP: -1, SourceID: "src-01TESTOBI", ServiceName: "shop-api", Kind: "obi", Version: "0.1.0"}
}

func fixture(t testing.TB, name string) []ResourceSpans {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := ParseExport(f, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func fixtureBytes(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeSink records what the bridge emits.
type fakeSink struct {
	mu       sync.Mutex
	cp       sourceclient.Capture
	active   bool
	events   [][]byte
	errs     []string
	counters sourceclient.Counters
}

func newFakeSink(cp sourceclient.Capture) *fakeSink { return &fakeSink{cp: cp, active: true} }

func (s *fakeSink) Active() (sourceclient.Capture, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cp, s.active
}
func (s *fakeSink) setActive(on bool) { s.mu.Lock(); s.active = on; s.mu.Unlock() }
func (s *fakeSink) Emit(e sourceclient.Event) {
	s.mu.Lock()
	s.events = append(s.events, append([]byte(nil), e.JSON...))
	s.mu.Unlock()
}
func (s *fakeSink) Counters() *sourceclient.Counters { return &s.counters }
func (s *fakeSink) RecordError(code string) {
	s.mu.Lock()
	s.errs = append(s.errs, code)
	s.mu.Unlock()
}
func (s *fakeSink) ObserveOverhead(time.Duration) {}
func (s *fakeSink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.events))
	for i, e := range s.events {
		out[i] = string(e)
	}
	return out
}

func waitFor(t testing.TB, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func hdr(name, value string) sanitizer.Header {
	return sanitizer.Header{Name: name, Value: []byte(strings.TrimSpace(value))}
}

// direct is the reference: the event the sanitizer produces for an exchange
// that the application's own SDK would have captured, without OBI, OTLP or
// the mapping in between.
func direct(t testing.TB, cp sourceclient.Capture, ex *sanitizer.Exchange, start time.Time, latency time.Duration, trace, span, parent string) []byte {
	t.Helper()
	d := cp.Engine.Sample(ex, sanitizer.SampleOptions{RateBP: -1})
	if !d.Sampled {
		t.Fatal("reference exchange not sampled")
	}
	out, err := cp.Engine.Sanitize(ex, time.Now(), d.By)
	if err != nil {
		t.Fatal(err)
	}
	meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{
		SourceKind: cp.Kind, SourceVersion: cp.Version, SourceID: cp.SourceID,
		TS: start, LatencyMS: latency.Milliseconds(), Status: ex.Status, NetError: ex.NetError,
		TraceID: trace, SpanID: span, ParentSpanID: parent,
	}, cp.Policy)
	ev, err := sanitizer.BuildEvent(meta, out)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// viaBridge runs span number n of a fixture through Map and Exchange.
func viaBridge(t testing.TB, cp sourceclient.Capture, rs []ResourceSpans, n int, limit int64) ([]byte, *Mapped) {
	t.Helper()
	sp := &rs[0].ScopeSpans[0].Spans[n]
	m, ok := Map(sp, MapOptions{ServiceName: cp.ServiceName, CaptureLimit: limit})
	if !ok {
		t.Fatal("span not mapped")
	}
	ev, sampled, err := Exchange(cp, m, time.Now(), nil)
	if err != nil || !sampled {
		t.Fatalf("exchange: sampled=%v err=%v", sampled, err)
	}
	return ev, m
}
