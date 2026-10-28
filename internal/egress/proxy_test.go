package egress_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/egress"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

func (e *env) do(method, path string, hdr map[string]string, body io.Reader) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.front.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "app-under-test/1.0")
	}
	resp, err := e.cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, b
}

func parseEvent(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("event is not JSON: %v", err)
	}
	return m
}

func hdrs(h http.Header) []sanitizer.Header {
	var out []sanitizer.Header
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, sanitizer.Header{Name: k, Value: []byte(v)})
		}
	}
	return out
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestForwardingIsTransparent(t *testing.T) {
	e := newEnv(t, envOpts{upstreams: func(u string) []egress.Upstream {
		return []egress.Upstream{{Alias: "carrier", URL: u, CaptureOrigin: carrierOrigin}, {Alias: "api", URL: u + "/base/"}}
	}})
	type seen struct {
		method, uri, host string
		hdr               http.Header
		body              []byte
	}
	var got atomic.Pointer[seen]
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(&seen{r.Method, r.RequestURI, r.Host, r.Header.Clone(), b})
		w.Header().Set("X-Upstream", "yes")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(418)
		_, _ = w.Write([]byte("short and stout"))
	})
	hdr := map[string]string{"X-Custom": "v1", "Content-Type": "application/octet-stream", "X-Forwarded-For": "10.1.2.3", "Authorization": "Bearer abc"}
	resp, body := e.do("PUT", "/carrier/v1/a%2Fb/c%20d?x=1;y=2&z=%41", hdr, strings.NewReader("payload-bytes"))
	if resp.StatusCode != 418 || string(body) != "short and stout" || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("response altered: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if c := resp.Header.Values("Set-Cookie"); len(c) != 2 || c[0] != "a=1" || c[1] != "b=2" {
		t.Fatalf("set-cookie: %v", c)
	}
	s := got.Load()
	if s.method != "PUT" || s.uri != "/v1/a%2Fb/c%20d?x=1;y=2&z=%41" || string(s.body) != "payload-bytes" {
		t.Fatalf("upstream saw %s %s %q", s.method, s.uri, s.body)
	}
	if !strings.HasPrefix(s.host, "127.0.0.1:") {
		t.Fatalf("upstream host %q", s.host)
	}
	// Exactly what the application sent, nothing added.
	want := map[string]string{"X-Custom": "v1", "Content-Type": "application/octet-stream", "X-Forwarded-For": "10.1.2.3",
		"Authorization": "Bearer abc", "User-Agent": "app-under-test/1.0", "Content-Length": "13"}
	if len(s.hdr) != len(want) {
		t.Fatalf("upstream headers %v, want %v", s.hdr, want)
	}
	for k, v := range want {
		if s.hdr.Get(k) != v {
			t.Errorf("header %s = %q, want %q", k, s.hdr.Get(k), v)
		}
	}
	// A base path on the upstream, and the bare alias.
	e.do("GET", "/api/v1/x?q=1", nil, nil)
	if u := got.Load().uri; u != "/base/v1/x?q=1" {
		t.Fatalf("base path join: %s", u)
	}
	e.do("GET", "/api", nil, nil)
	if u := got.Load().uri; u != "/base" {
		t.Fatalf("bare alias: %s", u)
	}
	// Unknown alias and CONNECT never reach an upstream.
	if resp, _ := e.do("GET", "/nope/x", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("unknown alias: %d", resp.StatusCode)
	}
	// No traceparent is ever invented.
	e.do("POST", "/carrier/v1/shipments", nil, strings.NewReader("{}"))
	if tp := got.Load().hdr.Get("Traceparent"); tp != "" {
		t.Fatalf("traceparent injected: %s", tp)
	}
}

func TestCaptureMatchesSanitizerDirectly(t *testing.T) {
	for _, gzipped := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%v", gzipped), func(t *testing.T) {
			e := newEnv(t, envOpts{})
			e.waitCapturing()
			respJSON := []byte(`{"shipmentId":"shp-77","status":"CREATED","eta":"2026-10-24"}`)
			var seenHdr atomic.Pointer[http.Header]
			e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				h := r.Header.Clone()
				seenHdr.Store(&h)
				w.Header().Set("Content-Type", "application/json")
				out := respJSON
				if gzipped {
					w.Header().Set("Content-Encoding", "gzip")
					out = gz(respJSON)
				}
				w.WriteHeader(201)
				_, _ = w.Write(out)
			})
			reqBody := []byte(`{"orderId":"ord-1001","note":"fragile"}`)
			tid, parent := "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
			resp, wire := e.do("POST", "/carrier/v1/shipments", map[string]string{
				"Content-Type": "application/json", "X-Customer-Id": "cust-42", "Traceparent": "00-" + tid + "-" + parent + "-01",
			}, bytes.NewReader(reqBody))
			if resp.StatusCode != 201 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if gzipped && !bytes.Equal(wire, gz(respJSON)) && resp.Header.Get("Content-Encoding") != "gzip" {
				t.Fatal("response was decoded by the proxy")
			}
			evs := e.core.WaitEvents(1, 5*time.Second)
			if len(evs) != 1 {
				t.Fatalf("%d events", len(evs))
			}
			ev := parseEvent(t, evs[0])

			c, ok := e.src.Active()
			if !ok {
				t.Fatal("capture stopped")
			}
			ex := &sanitizer.Exchange{
				Dir: sanitizer.Outbound, URLBase: carrierOrigin, Method: "POST", RawPath: []byte("/v1/shipments"), TraceID: tid,
				ReqHeaders: hdrs(*seenHdr.Load()), ReqBody: reqBody, ReqBodyTotal: int64(len(reqBody)),
				Status: 201, RespHeaders: hdrs(resp.Header), RespBody: wire, RespBodyTotal: int64(len(wire)),
			}
			out, err := c.Engine.Sanitize(ex, time.Now(), sanitizer.BySubject)
			if err != nil {
				t.Fatal(err)
			}
			ts, err := time.Parse("2006-01-02T15:04:05.000Z", ev["ts"].(string))
			if err != nil {
				t.Fatal(err)
			}
			span, _ := ev["span_id"].(string)
			if len(span) != 16 || span == parent {
				t.Fatalf("span_id %q", span)
			}
			meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{
				SourceKind: "egress", SourceVersion: "0.1.0", SourceID: e.src.Identity().SourceID,
				TS: ts, LatencyMS: int64(ev["latency_ms"].(float64)), Status: 201,
				TraceID: tid, SpanID: span, ParentSpanID: parent,
			}, c.Policy)
			want, err := sanitizer.BuildEvent(meta, out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(evs[0], want) {
				t.Fatalf("event differs from the sanitizer's output\n got: %s\nwant: %s", evs[0], want)
			}
			for _, sub := range []string{`"dir":"outbound"`, `"service":"shipping-ext"`, `"op":"POST /v1/shipments"`, `"sampled_by":"subject"`,
				`"kind":"egress"`, `"shipmentId":"tk1:k1:`, `"orderId":"tk1:k1:`, `"status":"keep:CREATED"`} {
				if !strings.Contains(string(evs[0]), sub) {
					t.Errorf("event lacks %s: %s", sub, evs[0])
				}
			}
			for _, leak := range []string{"ord-1001", "shp-77", "cust-42", "fragile"} {
				if strings.Contains(string(evs[0]), leak) {
					t.Errorf("event leaks %q", leak)
				}
			}
		})
	}
}

func TestStreamingLargeBodiesAreNotBuffered(t *testing.T) {
	const total = 64 << 20
	e := newEnv(t, envOpts{plainUp: true})
	e.waitCapturing()
	var upHash, clHash [sha256.Size]byte
	var upN int64
	chunk := func(i int) []byte {
		b := make([]byte, 64<<10)
		for k := range b {
			b[k] = byte(i*31 + k)
		}
		return b
	}
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		copy(upHash[:], h.Sum(nil))
		upN = n
		w.Header().Set("Content-Type", "application/octet-stream")
		fl := w.(http.Flusher)
		for i := 0; i < total/(64<<10); i++ {
			_, _ = w.Write(chunk(i))
			if i%64 == 0 {
				fl.Flush()
			}
		}
	})
	pr, pw := io.Pipe()
	reqHash := sha256.New()
	go func() {
		for i := 0; i < total/(64<<10); i++ {
			b := chunk(i)
			reqHash.Write(b)
			if _, err := pw.Write(b); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()

	req, _ := http.NewRequest("POST", e.front.URL+"/carrier/v1/shipments", pr)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := e.cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	resp.Body.Close()
	copy(clHash[:], h.Sum(nil))
	close(stop)
	wg.Wait()
	if err != nil || n != total {
		t.Fatalf("response: %d bytes, err %v", n, err)
	}
	var want [sha256.Size]byte
	copy(want[:], reqHash.Sum(nil))
	if upN != total || upHash != want {
		t.Fatalf("request body altered in transit: %d bytes", upN)
	}
	// The response is the same deterministic stream.
	exp := sha256.New()
	for i := 0; i < total/(64<<10); i++ {
		exp.Write(chunk(i))
	}
	var expSum [sha256.Size]byte
	copy(expSum[:], exp.Sum(nil))
	if clHash != expSum {
		t.Fatal("response body altered in transit")
	}
	if grown := int64(peak.Load()) - int64(base); grown > 48<<20 {
		t.Fatalf("heap grew by %d MiB while moving %d MiB each way: the proxy buffers", grown>>20, total>>20)
	}
	evs := e.core.WaitEvents(1, 10*time.Second)
	ev := parseEvent(t, evs[0])
	for _, side := range []string{"req", "resp"} {
		m := ev[side].(map[string]any)
		if m["body"] != "trunc:size" || m["size"] != "lmax" {
			t.Errorf("%s = %v", side, m)
		}
	}
}

func TestStreamingResponseIsFlushedIncrementally(t *testing.T) {
	e := newEnv(t, envOpts{plainUp: true})
	e.waitCapturing()
	release := make(chan struct{})
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: one\n\n"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("data: two\n\n"))
	})
	resp, err := e.cl.Get(e.front.URL + "/carrier/v1/shipments/s1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make(chan string, 1)
	go func() {
		b := make([]byte, 11)
		_, _ = io.ReadFull(resp.Body, b)
		first <- string(b)
	}()
	select {
	case s := <-first:
		if s != "data: one\n\n" {
			t.Fatalf("first chunk %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first chunk not delivered before the response ended: the proxy buffers")
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if string(rest) != "data: two\n\n" {
		t.Fatalf("rest %q", rest)
	}
}

func okUpstream(e *env) {
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shipmentId":"s","status":"CREATED"}`))
	})
}

func (e *env) post() *http.Response {
	e.t.Helper()
	r, _ := e.do("POST", "/carrier/v1/shipments", map[string]string{"Content-Type": "application/json", "X-Customer-Id": "c1"}, strings.NewReader(`{"orderId":"o1"}`))
	return r
}

func TestKillSwitchStopsCaptureNotForwarding(t *testing.T) {
	e := newEnv(t, envOpts{})
	okUpstream(e)
	e.waitCapturing()
	e.post()
	e.core.WaitEvents(1, 5*time.Second)

	e.core.Kill(true)
	e.core.Eventually(5*time.Second, "kill", func() bool { _, ok := e.src.Active(); return !ok })
	before := len(e.core.Events())
	for i := 0; i < 20; i++ {
		if r := e.post(); r.StatusCode != 200 {
			t.Fatalf("forwarding stopped with the kill switch: %d", r.StatusCode)
		}
	}
	time.Sleep(250 * time.Millisecond)
	if n := len(e.core.Events()); n != before {
		t.Fatalf("%d events captured while killed", n-before)
	}
	e.core.Kill(false)
	e.waitCapturing()
	e.post()
	e.core.WaitEvents(before+1, 5*time.Second)
}

func TestNoValidPolicyOrKeyMeansNoCapture(t *testing.T) {
	cases := map[string]envOpts{
		"no policy": {noPolicy: true},
		"policy signed by an unknown key": {policy: func(c *fakecore.Core, _ string) []byte {
			return c.CompileWith(fakecore.AuthorPolicy, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: time.Now(), Groups: []string{"shop"}}, "policy-evil", fakecore.ForeignKey())
		}},
		"policy for another group": {policy: func(c *fakecore.Core, _ string) []byte {
			return c.CompileWith(fakecore.AuthorPolicy, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: time.Now(), Groups: []string{"other"}}, fakecore.SigningKid, c.SigningPrivateKey())
		}},
		"no hmac key": {noKeys: true},
		"no source":   {noSource: true},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, o)
			okUpstream(e)
			if e.src != nil {
				e.core.Eventually(5*time.Second, "heartbeats", func() bool { return len(e.core.Heartbeats()) >= 3 })
			}
			for i := 0; i < 10; i++ {
				if r := e.post(); r.StatusCode != 200 {
					t.Fatalf("not forwarded: %d", r.StatusCode)
				}
			}
			time.Sleep(250 * time.Millisecond)
			if n := len(e.core.Events()); n != 0 {
				t.Fatalf("%d events without a valid policy and key", n)
			}
			if e.src != nil {
				if _, ok := e.src.Active(); ok {
					t.Fatal("source allows capture")
				}
			}
		})
	}
}

func TestKeyMissingIsReported(t *testing.T) {
	e := newEnv(t, envOpts{noKeys: true})
	e.core.Eventually(5*time.Second, "key_missing heartbeat", func() bool {
		hs := e.core.Heartbeats()
		return len(hs) > 0 && hs[len(hs)-1].State == "key_missing"
	})
}

func TestOverloadDropsEventsNeverTraffic(t *testing.T) {
	t.Run("sanitizer backlog", func(t *testing.T) {
		e := newEnv(t, envOpts{
			capture:    egress.CaptureConfig{Workers: 1, QueueSize: 2},
			onSanitize: func() { time.Sleep(30 * time.Millisecond) },
		})
		okUpstream(e)
		e.waitCapturing()
		start := time.Now()
		var wg sync.WaitGroup
		var bad atomic.Int32
		for i := 0; i < 80; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if e.post().StatusCode != 200 {
					bad.Add(1)
				}
			}()
		}
		wg.Wait()
		if bad.Load() != 0 {
			t.Fatalf("%d requests failed", bad.Load())
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("80 requests took %v: traffic waited for the sanitizer", d)
		}
		if dropped := e.src.Counters().EventsDroppedQueue.Load(); dropped == 0 {
			t.Fatal("no drops counted under overload")
		}
	})
	t.Run("pending bytes budget", func(t *testing.T) {
		e := newEnv(t, envOpts{capture: egress.CaptureConfig{MaxPendingBytes: 4}})
		okUpstream(e)
		e.waitCapturing()
		for i := 0; i < 5; i++ {
			e.post()
		}
		time.Sleep(200 * time.Millisecond)
		if n := len(e.core.Events()); n != 0 {
			t.Fatalf("%d events over the byte budget", n)
		}
		if d := e.src.Counters().EventsDroppedQueue.Load(); d != 5 {
			t.Fatalf("drops = %d, want 5", d)
		}
	})
	t.Run("tt-core down", func(t *testing.T) {
		e := newEnv(t, envOpts{srcMod: func(c *sourceclient.Config) { c.Exporter.MaxEvents = 5 }})
		okUpstream(e)
		e.waitCapturing()
		block := make(chan struct{})
		defer close(block)
		e.core.BlockLogs(block)
		for i := 0; i < 60; i++ {
			if e.post().StatusCode != 200 {
				t.Fatal("request failed while the intake was blocked")
			}
		}
		e.core.Eventually(5*time.Second, "export drops", func() bool { return e.src.Counters().EventsDroppedQueue.Load() > 0 })
	})
}

func TestSamplingBaggageAndOverride(t *testing.T) {
	e := newEnv(t, envOpts{})
	var seen atomic.Pointer[http.Header]
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Clone()
		seen.Store(&h)
		_, _ = w.Write([]byte("{}"))
	})
	e.waitCapturing()
	call := func(baggage string) {
		h := map[string]string{"X-Customer-Id": "c1", "Content-Type": "application/json"}
		if baggage != "" {
			h["Baggage"] = baggage
		}
		e.do("POST", "/carrier/v1/shipments", h, strings.NewReader("{}"))
	}
	// tt.s=0 on an internal service wins over the 100% rate; and it is never forwarded.
	call("userId=alice, tt.s=0")
	if b := seen.Load().Get("Baggage"); b != "userId=alice" {
		t.Fatalf("forwarded baggage %q", b)
	}
	time.Sleep(150 * time.Millisecond)
	if n := len(e.core.Events()); n != 0 {
		t.Fatalf("captured despite tt.s=0: %d", n)
	}
	call("tt.s=1")
	if _, ok := (*seen.Load())["Baggage"]; ok {
		t.Fatal("empty baggage header forwarded")
	}
	evs := e.core.WaitEvents(1, 5*time.Second)
	if !strings.Contains(string(evs[0]), `"sampled_by":"baggage"`) {
		t.Fatalf("event: %s", evs[0])
	}
	if strings.Contains(string(evs[0]), "tt.s") {
		t.Fatal("tt.s reached the event")
	}
	// Fleet sampling override (can only lower the rate).
	e.core.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { v := 0; r.SamplingOverrideBP = &v })
	e.core.Eventually(5*time.Second, "override", func() bool { c, ok := e.src.Active(); return ok && c.OverrideBP == 0 })
	for i := 0; i < 10; i++ {
		call("")
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(e.core.Events()); n != 1 {
		t.Fatalf("events after override to 0: %d", n)
	}
}

func TestBaggageStrippedEvenWithoutCapture(t *testing.T) {
	e := newEnv(t, envOpts{noSource: true})
	var seen atomic.Pointer[http.Header]
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) { h := r.Header.Clone(); seen.Store(&h) })
	e.do("GET", "/carrier/v1/shipments/x", map[string]string{"Baggage": "a=1,tt.s=1", "Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}, nil)
	h := seen.Load()
	if h.Get("Baggage") != "a=1" || h.Get("Traceparent") != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("headers: %v", *h)
	}
}

func TestNetErrorEvent(t *testing.T) {
	e := newEnv(t, envOpts{upstreams: func(u string) []egress.Upstream {
		return []egress.Upstream{{Alias: "carrier", URL: u, CaptureOrigin: carrierOrigin}, {Alias: "dead", URL: "http://127.0.0.1:1", CaptureOrigin: carrierOrigin}}
	}})
	e.waitCapturing()
	resp, _ := e.do("POST", "/dead/v1/shipments", map[string]string{"Content-Type": "application/json", "X-Customer-Id": "c1"}, strings.NewReader(`{"orderId":"o1"}`))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
	evs := e.core.WaitEvents(1, 5*time.Second)
	s := string(evs[0])
	if !strings.Contains(s, `"net_error":"refused"`) || strings.Contains(s, `"status"`) || strings.Contains(s, `"resp"`) || !strings.Contains(s, `"op":"POST /v1/shipments"`) {
		t.Fatalf("event: %s", s)
	}
}

func TestUpstreamTLSIsVerified(t *testing.T) {
	// The proxy trusts the system roots (plus configured CAs): the test
	// upstream's certificate is not trusted here, so the call fails with a tls
	// net_error and the client sees 502.
	e := newEnv(t, envOpts{})
	e.waitCapturing()
	p2, err := egress.New(egress.Config{Source: e.src, Upstreams: []egress.Upstream{{Alias: "carrier", URL: e.up.URL, CaptureOrigin: carrierOrigin}}})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close(t.Context())
	front := httptest.NewServer(p2)
	defer front.Close()
	resp, err := http.Post(front.URL+"/carrier/v1/shipments", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d: untrusted upstream certificate accepted", resp.StatusCode)
	}
}

func TestAliasFromPolicy(t *testing.T) {
	e := newEnv(t, envOpts{
		aliasPol:  true,
		upstreams: func(string) []egress.Upstream { return nil },
		policy: func(c *fakecore.Core, upURL string) []byte {
			return c.Compile(strings.ReplaceAll(fakecore.AuthorPolicy, carrierOrigin, upURL), 1, 1)
		},
	})
	okUpstream(e)
	e.core.Eventually(5*time.Second, "policy route", func() bool {
		resp, err := e.cl.Get(e.front.URL + "/shipping-ext/v1/shipments/s1")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	evs := e.core.WaitEvents(1, 5*time.Second)
	if !strings.Contains(string(evs[0]), `"service":"shipping-ext"`) || !strings.Contains(string(evs[0]), `"route_source":"policy"`) {
		t.Fatalf("event: %s", evs[0])
	}
}

func TestHealthEndpoint(t *testing.T) {
	e := newEnv(t, envOpts{})
	okUpstream(e)
	e.waitCapturing()
	e.post()
	e.core.WaitEvents(1, 5*time.Second)
	resp, body := e.do("GET", egress.HealthPath, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var h map[string]any
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatal(err)
	}
	if h["status"] != "ok" || h["capture"] != "capturing" || h["exchanges_seen"].(float64) < 1 {
		t.Fatalf("health: %s", body)
	}
	// Overhead and counters reach the heartbeat too.
	e.core.Eventually(5*time.Second, "heartbeat with counters", func() bool {
		hs := e.core.Heartbeats()
		l := hs[len(hs)-1]
		return l.Counters.ExchangesSeen >= 1 && l.Counters.EventsSent >= 1 && l.OverheadUS != nil
	})
}
