package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

type env struct {
	t     *testing.T
	m     *Mock
	srv   *httptest.Server
	built *packtest.Built
}

type envOpt func(*packtest.Spec, *Config)

func withFaults(mode string) envOpt { return func(_ *packtest.Spec, c *Config) { c.Faults = mode } }
func withToken(tok string) envOpt   { return func(_ *packtest.Spec, c *Config) { c.ControlToken = tok } }

// exact uses the demo pack with degenerate delay ranges: created 5m after the
// cause, in transit 4h later, delivered 2d later, cancelled 1h after creation.
func exact() envOpt {
	return func(sp *packtest.Spec, _ *Config) { *sp = packtest.ExactDemoSpec() }
}

func withLatency(mode string) envOpt { return func(_ *packtest.Spec, c *Config) { c.Latency = mode } }
func withSpec(f func(*packtest.Spec)) envOpt {
	return func(sp *packtest.Spec, _ *Config) { f(sp) }
}

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	spec := packtest.DemoSpec()
	cfg := Config{Latency: LatencyRecord, Faults: "off", NetTimeout: 50 * time.Millisecond, MaxPackAge: -1} // fixture packs are dated 2026-10-19
	for _, o := range opts {
		o(&spec, &cfg)
	}
	built, err := packtest.Build(filepath.Join(t.TempDir(), "pack"), spec)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Pack, cfg.GatePubKeys = built.Dir, built.Keys
	var tick atomic.Int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg.Wall = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Second) }
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, m: m, srv: srv, built: built}
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json() map[string]any {
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		panic(fmt.Sprintf("response is not a JSON object: %q", r.body))
	}
	return v
}

func (e *env) req(method, path string, body any, hdr map[string]string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		var b []byte
		switch x := body.(type) {
		case string:
			b = []byte(x)
		default:
			b, _ = json.Marshal(x)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func (e *env) ctl(method, path string, body any) resp {
	e.t.Helper()
	return e.req(method, "/__tt"+path, body, nil)
}

func (e *env) newSession(body map[string]any) string {
	e.t.Helper()
	r := e.ctl("POST", "/sessions", body)
	if r.status != 201 {
		e.t.Fatalf("create session: %d %s", r.status, r.body)
	}
	return r.json()["id"].(string)
}

func (e *env) force(sid, rule, outcome string) {
	e.t.Helper()
	if r := e.ctl("POST", "/sessions/"+sid+"/scenario", map[string]any{"rule": rule, "outcome": outcome}); r.status != 200 {
		e.t.Fatalf("force: %d %s", r.status, r.body)
	}
}

func (e *env) advance(sid, by string) []any {
	e.t.Helper()
	r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"by": by})
	if r.status != 200 {
		e.t.Fatalf("advance: %d %s", r.status, r.body)
	}
	return r.json()["applied"].([]any)
}

func sess(sid string) map[string]string { return map[string]string{"X-TT-Session": sid} }

var orderBody = map[string]any{
	"items": []any{map[string]any{"sku": "SKU-AAAA0001", "qty": 2}},
	"email": "anna.rossi@example.com",
}

func (e *env) order(sid string) string {
	e.t.Helper()
	r := e.req("POST", "/__svc/shop-api/orders", orderBody, sess(sid))
	if r.status != 201 {
		e.t.Fatalf("order: %d %s", r.status, r.body)
	}
	return r.json()["id"].(string)
}

func (e *env) shipments(sid, orderID string) []any {
	e.t.Helper()
	r := e.req("GET", "/__svc/shipping-ext/v1/shipments?orderId="+orderID, nil, sess(sid))
	if r.status != 200 {
		e.t.Fatalf("shipments: %d %s", r.status, r.body)
	}
	return r.json()["items"].([]any)
}

// conforms checks a response body against the contract schema of an operation.
func (e *env) conforms(service, opKey string, status int, r resp) {
	e.t.Helper()
	svc := e.m.model.byName[service]
	op := svc.c.byKey[opKey]
	rs := op.responses[status]
	if rs == nil || rs.schema == nil {
		e.t.Fatalf("no schema for %s %d", opKey, status)
	}
	v, err := decodeJSON(r.body)
	if err != nil {
		e.t.Fatal(err)
	}
	if viol := svc.c.sc.validate(rs.schema, v, "", 0); viol != nil {
		e.t.Fatalf("response of %s does not match its contract: %s (%s)", opKey, viol, r.body)
	}
}
