package intake

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// --- a tiny PKI -------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tt test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) issue(t testing.TB, cn string, dns []string, uris []string, server bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns,
	}
	for _, u := range uris {
		p, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, p)
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type tlsRig struct {
	h      *harness
	ca     *testCA
	server *httptest.Server
}

func newTLSRig(t testing.TB, opts ...harnessOpt) *tlsRig {
	t.Helper()
	h := newHarness(t, opts...)
	ca := newTestCA(t)
	srv := httptest.NewUnstartedServer(h.in.Handler())
	sc := ca.issue(t, "tt-core", nil, nil, true)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{sc}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &tlsRig{h: h, ca: ca, server: srv}
}

// client returns an HTTP client presenting the certificate (nil: none).
func (r *tlsRig) client(cert *tls.Certificate) *http.Client {
	serverPool := x509.NewCertPool()
	serverPool.AddCert(r.server.Certificate())
	cfg := &tls.Config{RootCAs: serverPool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func (r *tlsRig) sourceCert(t testing.TB, id string) *tls.Certificate {
	c := r.ca.issue(t, "ignored-"+id, []string{id}, nil, false)
	return &c
}

// --- OTLP bodies --------------------------------------------------------------

func strAttr(k, v string) kvPair {
	p := kvPair{Key: k}
	p.Value.StringValue = &v
	return p
}

func otlpRecordFor(t testing.TB, canonical string) logRecord {
	// Lenient on purpose: tests also wrap events that are not canonical.
	var ev struct {
		TS      string `json:"ts"`
		TraceID string `json:"trace_id"`
		SpanID  string `json:"span_id"`
		Policy  struct {
			Hash string `json:"hash"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(canonical), &ev); err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339Nano, ev.TS)
	if err != nil {
		t.Fatal(err)
	}
	var rec logRecord
	rec.TimeUnixNano = strconv.FormatInt(ts.UnixMilli()*1_000_000, 10)
	rec.ObservedTimeUnixNano = strconv.FormatInt(ts.UnixMilli()*1_000_000+288_000_000, 10)
	rec.SeverityNumber, rec.SeverityText, rec.EventName = 9, "INFO", "tt.http.exchange"
	rec.TraceID, rec.SpanID = ev.TraceID, ev.SpanID
	rec.Attributes = []kvPair{strAttr("tt.schema", event.Schema), strAttr("tt.policy.hash", ev.Policy.Hash)}
	body := canonical
	rec.Body.StringValue = &body
	return rec
}

func otlpFor(t testing.TB, events ...string) otlpRequest {
	var rl resourceLogs
	rl.Resource.Attributes = []kvPair{
		strAttr("service.name", "shop-api"), strAttr("tt.source.kind", "sdk-node"),
		strAttr("tt.source.version", "0.1.0"), strAttr("tt.source.id", testSource),
	}
	var sl scopeLogs
	sl.Scope.Name, sl.Scope.Version = "traffic-twin", "0.1.0"
	for _, e := range events {
		sl.LogRecords = append(sl.LogRecords, otlpRecordFor(t, e))
	}
	rl.ScopeLogs = []scopeLogs{sl}
	return otlpRequest{ResourceLogs: []resourceLogs{rl}}
}

func marshalOTLP(t testing.TB, r otlpRequest) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type httpResult struct {
	code   int
	body   string
	header http.Header
}

func (r *tlsRig) post(t testing.TB, c *http.Client, body []byte, hdr map[string]string) httpResult {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, r.server.URL+Path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResult{resp.StatusCode, string(b), resp.Header}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// --- tests -------------------------------------------------------------------

func TestOTLPHappyPathOverMTLS(t *testing.T) {
	r := newTLSRig(t)
	hash := r.h.pol.Hash
	cert := r.sourceCert(t, testSource)
	c := r.client(cert)

	res := r.post(t, c, marshalOTLP(t, otlpFor(t, orderPost(hash), orderGet(hash), shipmentPost(hash))), nil)
	if res.code != 200 || strings.TrimSpace(res.body) != "{}" {
		t.Fatalf("%d %s", res.code, res.body)
	}
	if n := r.h.count(t); n != 3 {
		t.Fatalf("stored %d", n)
	}
	if st := r.h.in.SourceStats(testSource); st.Accepted != 3 || st.Requests != 1 || st.Bytes == 0 || st.LastSeen.IsZero() {
		t.Fatalf("%+v", st)
	}

	// gzip is accepted.
	res = r.post(t, c, gz(marshalOTLP(t, otlpFor(t, orderPost(hash)))), map[string]string{"Content-Encoding": "gzip"})
	if res.code != 200 {
		t.Fatalf("gzip: %d %s", res.code, res.body)
	}
	// JSON with a charset parameter is accepted.
	res = r.post(t, c, marshalOTLP(t, otlpFor(t, orderPost(hash))), map[string]string{"Content-Type": "application/json; charset=utf-8"})
	if res.code != 200 {
		t.Fatalf("charset: %d", res.code)
	}
	// An empty request is fine.
	if res = r.post(t, c, []byte(`{"resourceLogs":[]}`), nil); res.code != 200 {
		t.Fatalf("empty: %d", res.code)
	}
}

func TestOTLPPartialSuccess(t *testing.T) {
	r := newTLSRig(t)
	hash := r.h.pol.Hash
	c := r.client(r.sourceCert(t, testSource))
	bad := mutate(t, orderPost(hash), func(e eventT) { *member(e.Req.Body, "note") = event.Str("keep:secret") })
	res := r.post(t, c, marshalOTLP(t, otlpFor(t, orderPost(hash), bad, strings.Replace(orderPost(hash), `"dir":"inbound"`, `"dir": "inbound"`, 1))), nil)
	if res.code != 200 {
		t.Fatalf("%d %s", res.code, res.body)
	}
	var out otlpResponse
	if err := json.Unmarshal([]byte(res.body), &out); err != nil || out.PartialSuccess == nil || out.PartialSuccess.RejectedLogRecords != "2" {
		t.Fatalf("response: %s", res.body)
	}
	// The error message carries no event data.
	if strings.Contains(res.body, "secret") {
		t.Fatal("rejected value echoed to the source")
	}
	if n := r.h.count(t); n != 1 {
		t.Fatalf("stored %d", n)
	}
	st := r.h.in.SourceStats(testSource)
	if st.Accepted != 1 || st.Rejected["value_not_allowed"] != 1 || st.Rejected["non_canonical"] != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestOTLPIdentity(t *testing.T) {
	r := newTLSRig(t)
	hash := r.h.pol.Hash
	r.h.sources.Set(SourceInfo{ID: "src-OTHER", Group: "prod", ServiceName: "shop-api", AllowedServices: []string{"shop-api"}})
	req := marshalOTLP(t, otlpFor(t, orderPost(hash)))

	t.Run("certificate of another source: events claim a source.id that is not the certificate's", func(t *testing.T) {
		res := r.post(t, r.client(r.sourceCert(t, "src-OTHER")), req, nil)
		if res.code != 200 || !strings.Contains(res.body, `"rejectedLogRecords":"1"`) {
			t.Fatalf("%d %s", res.code, res.body)
		}
		if st := r.h.in.SourceStats("src-OTHER"); st.Rejected["source_mismatch"] != 1 {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("unknown source", func(t *testing.T) {
		if res := r.post(t, r.client(r.sourceCert(t, "src-NOBODY")), req, nil); res.code != 401 {
			t.Fatalf("%d %s", res.code, res.body)
		}
	})
	t.Run("revoked source", func(t *testing.T) {
		r.h.sources.Revoke("src-OTHER")
		if res := r.post(t, r.client(r.sourceCert(t, "src-OTHER")), req, nil); res.code != 403 {
			t.Fatalf("%d %s", res.code, res.body)
		}
	})
	t.Run("certificate without a source identity; the common name does not count", func(t *testing.T) {
		c := r.ca.issue(t, testSource, []string{"collector.internal"}, nil, false)
		if res := r.post(t, r.client(&c), req, nil); res.code != 401 {
			t.Fatalf("%d %s", res.code, res.body)
		}
	})
	t.Run("certificate with two different source ids", func(t *testing.T) {
		c := r.ca.issue(t, "x", []string{testSource, "src-OTHER"}, nil, false)
		if res := r.post(t, r.client(&c), req, nil); res.code != 401 {
			t.Fatalf("%d %s", res.code, res.body)
		}
	})
	t.Run("identity in a URI SAN", func(t *testing.T) {
		c := r.ca.issue(t, "x", nil, []string{"tt://sources/" + testSource}, false)
		if res := r.post(t, r.client(&c), req, nil); res.code != 200 {
			t.Fatalf("%d %s", res.code, res.body)
		}
	})
	t.Run("no certificate", func(t *testing.T) {
		if res := r.post(t, r.client(nil), req, nil); res.code != 403 {
			t.Fatalf("%d %s", res.code, res.body)
		}
	})
}

func TestOTLPEnvelopeChecks(t *testing.T) {
	r := newTLSRig(t)
	hash := r.h.pol.Hash
	c := r.client(r.sourceCert(t, testSource))
	rejectedWith := func(t *testing.T, req otlpRequest, reason string) {
		t.Helper()
		before := r.h.in.SourceStats(testSource).Rejected[reason]
		res := r.post(t, c, marshalOTLP(t, req), nil)
		if res.code != 200 || !strings.Contains(res.body, `"rejectedLogRecords":"1"`) {
			t.Fatalf("%d %s", res.code, res.body)
		}
		if got := r.h.in.SourceStats(testSource).Rejected[reason]; got != before+1 {
			t.Fatalf("reason %s counted %d times (was %d)", reason, got, before)
		}
	}
	good := orderPost(hash)

	t.Run("service.name differs from the assigned one", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].Resource.Attributes[0] = strAttr("service.name", "billing")
		rejectedWith(t, req, "resource_mismatch")
	})
	t.Run("tt.source.version differs from the event", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].Resource.Attributes[2] = strAttr("tt.source.version", "9.9.9")
		rejectedWith(t, req, "resource_mismatch")
	})
	t.Run("tt.policy.hash attribute differs", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes[1] = strAttr("tt.policy.hash", "sha256:"+strings.Repeat("0", 64))
		rejectedWith(t, req, "resource_mismatch")
	})
	t.Run("traceId differs", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].TraceID = strings.Repeat("a", 32)
		rejectedWith(t, req, "resource_mismatch")
	})
	t.Run("timeUnixNano differs from ts", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].TimeUnixNano = "1"
		rejectedWith(t, req, "resource_mismatch")
	})
	t.Run("extra attribute: a side channel", func(t *testing.T) {
		req := otlpFor(t, good)
		lr := &req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
		lr.Attributes = append(lr.Attributes, strAttr("user.email", "giulia.neri@example.com"))
		rejectedWith(t, req, "otlp_shape")
	})
	t.Run("extra resource attribute", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].Resource.Attributes = append(req.ResourceLogs[0].Resource.Attributes, strAttr("k8s.pod.name", "pod-1"))
		rejectedWith(t, req, "otlp_shape")
	})
	t.Run("wrong event name", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].EventName = "something.else"
		rejectedWith(t, req, "otlp_shape")
	})
	t.Run("wrong scope", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].ScopeLogs[0].Scope.Name = "other"
		rejectedWith(t, req, "otlp_shape")
	})
	t.Run("body is not a string", func(t *testing.T) {
		req := otlpFor(t, good)
		req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Body.StringValue = nil
		rejectedWith(t, req, "otlp_shape")
	})
	t.Run("unknown field in the request is refused outright", func(t *testing.T) {
		raw := strings.Replace(string(marshalOTLP(t, otlpFor(t, good))), `"resourceLogs"`, `"extra":1,"resourceLogs"`, 1)
		if res := r.post(t, c, []byte(raw), nil); res.code != 400 {
			t.Fatalf("%d", res.code)
		}
	})
}

func TestOTLPRequestLimitsAndHeaders(t *testing.T) {
	r := newTLSRig(t)
	hash := r.h.pol.Hash
	c := r.client(r.sourceCert(t, testSource))
	ok := marshalOTLP(t, otlpFor(t, orderPost(hash)))

	if res := r.post(t, c, ok, map[string]string{"Content-Type": "text/plain"}); res.code != 415 {
		t.Fatalf("content type: %d", res.code)
	}
	if res := r.post(t, c, ok, map[string]string{"Content-Encoding": "br"}); res.code != 415 {
		t.Fatalf("encoding: %d", res.code)
	}
	if res := r.post(t, c, []byte(`{"resourceLogs":`), nil); res.code != 400 {
		t.Fatalf("truncated JSON: %d", res.code)
	}
	if res := r.post(t, c, append(append([]byte{}, ok...), []byte(`{}`)...), nil); res.code != 400 {
		t.Fatalf("trailing data: %d", res.code)
	}
	if res := r.post(t, c, []byte("not gzip"), map[string]string{"Content-Encoding": "gzip"}); res.code != 400 {
		t.Fatalf("bad gzip: %d", res.code)
	}
	// GET is refused.
	req, _ := http.NewRequest(http.MethodGet, r.server.URL+Path, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("GET: %d", resp.StatusCode)
	}

	// More than 512 records.
	var recs []string
	for i := 0; i < 513; i++ {
		recs = append(recs, orderPost(hash))
	}
	if res := r.post(t, c, marshalOTLP(t, otlpFor(t, recs...)), nil); res.code != 413 {
		t.Fatalf("513 records: %d", res.code)
	}
	if n := r.h.count(t); n != 0 {
		t.Fatalf("a refused request stored %d events", n)
	}
	// Exactly 512 are fine.
	if res := r.post(t, c, marshalOTLP(t, otlpFor(t, recs[:512]...)), nil); res.code != 200 {
		t.Fatalf("512 records: %d %s", res.code, res.body)
	}

	// Larger than 4 MiB.
	big := bytes.Repeat([]byte(" "), 4<<20+1)
	if res := r.post(t, c, big, nil); res.code != 413 {
		t.Fatalf("5 MiB: %d", res.code)
	}
	// A small gzip body that inflates beyond 4 MiB.
	if res := r.post(t, c, gz(big), map[string]string{"Content-Encoding": "gzip"}); res.code != 413 {
		t.Fatalf("gzip bomb: %d", res.code)
	}
	// An event larger than 512 KiB is rejected alone, the rest is kept.
	huge := strings.Replace(orderPost(hash), `"drop:str:l8"`, `"keep:`+strings.Repeat("a", 600*1024)+`"`, 1)
	before := r.h.count(t)
	res := r.post(t, c, marshalOTLP(t, otlpFor(t, huge, orderPost(hash))), nil)
	if res.code != 200 || !strings.Contains(res.body, `"rejectedLogRecords":"1"`) {
		t.Fatalf("%d %s", res.code, res.body)
	}
	if got := r.h.count(t); got != before+1 {
		t.Fatalf("stored %d events, want %d", got, before+1)
	}
	if r.h.in.SourceStats(testSource).Rejected["event_too_large"] != 1 {
		t.Fatalf("%+v", r.h.in.SourceStats(testSource))
	}
}

func TestOTLPBackpressure(t *testing.T) {
	r := newTLSRig(t, withConfig(func(c *Config) { c.QueueEvents = 600; c.MaxRecords = 512 }))
	hash := r.h.pol.Hash
	c := r.client(r.sourceCert(t, testSource))
	req := marshalOTLP(t, otlpFor(t, orderPost(hash), orderPost(hash)))
	in := r.h.in

	// Queue full: 429 with Retry-After, nothing consumed, nothing stored.
	in.queued.Store(int64(in.cfg.QueueEvents))
	res := r.post(t, c, req, nil)
	if res.code != 429 {
		t.Fatalf("full queue: %d", res.code)
	}
	if ra, err := strconv.Atoi(res.header.Get("Retry-After")); err != nil || ra < 1 || ra > 30 {
		t.Fatalf("Retry-After %q", res.header.Get("Retry-After"))
	}
	// Room for one event but not for two: the whole request is pushed back,
	// not half of it.
	in.queued.Store(int64(in.cfg.QueueEvents) - 1)
	if res = r.post(t, c, req, nil); res.code != 429 {
		t.Fatalf("insufficient room: %d", res.code)
	}
	if got := in.queued.Load(); got != int64(in.cfg.QueueEvents)-1 {
		t.Fatalf("a refused request leaked a reservation: %d", got)
	}
	in.queued.Store(0)
	// Byte budget.
	in.queuedBytes.Store(in.cfg.QueueBytes)
	if res = r.post(t, c, req, nil); res.code != 429 {
		t.Fatalf("byte budget: %d", res.code)
	}
	in.queuedBytes.Store(0)
	// Per-source concurrency.
	sc := in.stats.source(testSource)
	sc.inflight.Store(int32(in.cfg.MaxInflightPerSource))
	if res = r.post(t, c, req, nil); res.code != 429 {
		t.Fatalf("concurrency: %d", res.code)
	}
	sc.inflight.Store(0)

	// Back to normal: the reservation is fully returned after the commit.
	if res = r.post(t, c, req, nil); res.code != 200 {
		t.Fatalf("recovered: %d %s", res.code, res.body)
	}
	r.h.idle(t)
	if q, b := in.queued.Load(), in.queuedBytes.Load(); q != 0 || b != 0 {
		t.Fatalf("queue accounting leaked: %d events, %d bytes", q, b)
	}
	tot := in.Totals()
	if tot.Throttled != 4 || tot.Stored != 2 {
		t.Fatalf("%+v", tot)
	}

	// Storage failure: 503 with Retry-After.
	in.writer.failing.Store(true)
	if res = r.post(t, c, req, nil); res.code != 503 || res.header.Get("Retry-After") == "" {
		t.Fatalf("failing storage: %d", res.code)
	}
	in.writer.failing.Store(false)
}

func TestOTLPAfterClose(t *testing.T) {
	r := newTLSRig(t)
	c := r.client(r.sourceCert(t, testSource))
	if err := r.h.in.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	res := r.post(t, c, marshalOTLP(t, otlpFor(t, orderPost(r.h.pol.Hash))), nil)
	if res.code != 503 || res.header.Get("Retry-After") == "" {
		t.Fatalf("%d", res.code)
	}
}

// Without a verified client certificate the handler refuses (the listener is
// configured to verify certificates when presented; the route requires one).
func TestHandlerWithoutTLS(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.in.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestSourceIDFromCert(t *testing.T) {
	ca := newTestCA(t)
	parse := func(dns, uris []string) (string, bool) {
		c := ca.issue(t, "cn", dns, uris, false)
		x, _ := x509.ParseCertificate(c.Certificate[0])
		return SourceIDFromCert(x)
	}
	if id, ok := parse([]string{"src-01JB7Q2W"}, nil); !ok || id != "src-01JB7Q2W" {
		t.Fatal(id, ok)
	}
	if id, ok := parse([]string{"host.example", "src-A1"}, nil); !ok || id != "src-A1" {
		t.Fatal(id, ok)
	}
	if id, ok := parse([]string{"src-A1"}, []string{"spiffe://tt.example/src/src-A1"}); !ok || id != "src-A1" {
		t.Fatal(id, ok)
	}
	for _, c := range [][2][]string{{{"src-A1", "src-B2"}, nil}, {{"host.example"}, nil}, {nil, nil}, {{"src-"}, nil}, {{"SRC-A1"}, nil}} {
		if id, ok := parse(c[0], c[1]); ok {
			t.Fatalf("%v accepted as %s", c, id)
		}
	}
}
