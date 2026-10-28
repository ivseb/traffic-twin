package ttsdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// The sanitizer itself is the shared reference one and passes all 422
// conformance vectors in internal/sanitizer. This test proves that the SDK
// feeds it the same input: every vector whose exchange can be expressed over
// real HTTP is replayed through the real capture path (a net/http server
// behind Handler, or a RoundTripper behind Transport, workers, event
// builder) and the sanitizer part of the emitted event must be byte for
// byte the expected canonical output.
//
// Not expressible over HTTP, hence not replayed: policies/keys that must be
// refused (they are about the policy store, covered by internal/sourceclient),
// bytes that net/http itself refuses (invalid header names or values, bad
// request targets, control characters), headers that the HTTP stack
// generates or consumes (Content-Length, Transfer-Encoding, Connection,
// Expect...), request bodies "decoded" by the runtime, unknown body lengths.
// The Host and Content-Length headers that the test client adds are
// removed from both sides before comparing.

const conformanceRoot = "../../conformance"

type vFile struct {
	ID             string          `json:"id"`
	Policy         json.RawMessage `json:"policy"`
	PolicyRef      string          `json:"policy_ref"`
	PolicyEnvelope json.RawMessage `json:"policy_envelope"`
	HMACKey        *string         `json:"hmac_key"`
	Now            string          `json:"now"`
	Input          json.RawMessage `json:"input"`
	Expected       struct {
		Outcome   string `json:"outcome"`
		Canonical string `json:"canonical"`
	} `json:"expected"`
}

type vHeader struct{ name, value []byte }

type vInput struct {
	dir, serviceName, urlBase, method, traceID, netError string
	framework, frameworkRoute                            string
	inherited                                            *bool
	rawPath, rawQuery                                    []byte
	hasQuery                                             bool
	reqHeaders, respHeaders                              []vHeader
	reqBody, respBody                                    []byte
	reqTotal, respTotal                                  int64 // -2 absent, -1 unknown
	reqConsumed, respConsumed                            bool
	reqDecoded, respDecoded                              bool
	status                                               int
}

func vBytes(raw json.RawMessage) ([]byte, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s), true
	}
	var o struct {
		B64 *string `json:"b64"`
	}
	if json.Unmarshal(raw, &o) != nil || o.B64 == nil {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(*o.B64)
	if err != nil {
		return nil, false
	}
	return b, true
}

func vHeaders(raw json.RawMessage) []vHeader {
	var pairs [][2]json.RawMessage
	if json.Unmarshal(raw, &pairs) != nil {
		return nil
	}
	var out []vHeader
	for _, p := range pairs {
		var name string
		_ = json.Unmarshal(p[0], &name)
		v, _ := vBytes(p[1])
		out = append(out, vHeader{[]byte(name), v})
	}
	return out
}

func vTotal(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return -2
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return -1
	}
	var n int64
	_ = json.Unmarshal(raw, &n)
	return n
}

func parseVInput(raw json.RawMessage) (*vInput, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	flag := func(k string, def bool) bool {
		b := def
		if r, ok := m[k]; ok {
			_ = json.Unmarshal(r, &b)
		}
		return b
	}
	in := &vInput{dir: str("dir"), serviceName: str("service_name"), urlBase: str("url_base"), method: str("method"),
		traceID: str("trace_id"), netError: str("net_error"), framework: str("framework"), frameworkRoute: str("framework_route"),
		reqConsumed: flag("req_body_consumed", true), respConsumed: flag("resp_body_consumed", true),
		reqDecoded: flag("req_body_decoded", false), respDecoded: flag("resp_body_decoded", false),
		reqTotal: vTotal(m["req_body_total"]), respTotal: vTotal(m["resp_body_total"])}
	_ = json.Unmarshal(m["status"], &in.status)
	if r, ok := m["inherited"]; ok {
		var b bool
		if err := json.Unmarshal(r, &b); err != nil {
			return nil, err
		}
		in.inherited = &b
	}
	in.rawPath, _ = vBytes(m["raw_path"])
	in.rawQuery, in.hasQuery = vBytes(m["raw_query"])
	in.reqBody, _ = vBytes(m["req_body"])
	in.respBody, _ = vBytes(m["resp_body"])
	in.reqHeaders, in.respHeaders = vHeaders(m["req_headers"]), vHeaders(m["resp_headers"])
	return in, nil
}

func isToken(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func validValue(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// transportHeaders are consumed or generated by the HTTP stack.
var transportHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"expect": true, "upgrade": true, "te": true, "trailer": true, "keep-alive": true, "proxy-connection": true}

// fill returns body padded with filler bytes up to total, when the vector
// describes a body longer than the prefix it carries.
func fill(body []byte, total int64) ([]byte, bool) {
	switch {
	case total == -2 || total == int64(len(body)):
		return body, true
	case total > int64(len(body)) && total <= 32<<20:
		out := make([]byte, total)
		copy(out, body)
		for i := len(body); i < len(out); i++ {
			out[i] = 'x'
		}
		return out, true
	}
	return nil, false
}

// vectorOutput keeps the sanitizer part of an event (or of an expected
// canonical output) without the headers the test client adds.
func vectorOutput(doc []byte) (string, error) {
	v, err := ttjson.Parse(doc, ttjson.ParseOptions{})
	if err != nil {
		return "", err
	}
	keep := map[string]bool{"disc": true, "op": true, "req": true, "resp": true, "route_source": true, "sampled_by": true, "service": true, "subject": true}
	out := ttjson.Obj()
	for _, m := range v.Obj {
		if !keep[m.Key] {
			continue
		}
		if m.Key == "disc" {
			d := ttjson.Obj()
			for _, dm := range m.Value.Obj {
				if dm.Key != "req.headers.host" && dm.Key != "req.headers.content-length" {
					d.Obj = append(d.Obj, dm)
				}
			}
			if len(d.Obj) == 0 {
				continue
			}
			m.Value = d
		}
		if m.Key == "req" || m.Key == "resp" {
			part := ttjson.Obj()
			for _, pm := range m.Value.Obj {
				if pm.Key == "headers" {
					h := ttjson.Obj()
					for _, hm := range pm.Value.Obj {
						if hm.Key != "host" && hm.Key != "content-length" {
							h.Obj = append(h.Obj, hm)
						}
					}
					if len(h.Obj) == 0 {
						continue
					}
					pm.Value = h
				}
				part.Obj = append(part.Obj, pm)
			}
			m.Value = part
		}
		out.Obj = append(out.Obj, m)
	}
	b, err := ttjson.Encode(out)
	return string(b), err
}

func TestSDKPathMatchesConformanceVectors(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(conformanceRoot, "vectors", "*.json"))
	if len(files) == 0 {
		t.Skip("conformance/vectors not present")
	}
	sort.Strings(files)
	compared, skipped := 0, map[string]int{}
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		var reason string
		ran := false
		t.Run(id, func(t *testing.T) { reason, ran = runSDKVector(t, f) })
		if ran {
			compared++
		} else {
			skipped[reason]++
		}
	}
	total := 0
	for _, n := range skipped {
		total += n
	}
	t.Logf("%d vectors replayed through the SDK path and identical to the reference output; %d not expressible over HTTP: %v", compared, total, skipped)
	if compared < 300 {
		t.Fatalf("only %d vectors replayed, expected at least 300", compared)
	}
}

func runSDKVector(t *testing.T, file string) (skip string, ran bool) {
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var v vFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Expected.Outcome != "event" && v.Expected.Outcome != "not_sampled" {
		return "refused outcome (policy store)", false
	}
	if len(v.PolicyEnvelope) > 0 || v.HMACKey == nil {
		return "envelope or key handling", false
	}
	var body []byte
	if len(v.Policy) > 0 {
		body = v.Policy
	} else if body, err = os.ReadFile(filepath.Join(conformanceRoot, v.PolicyRef)); err != nil {
		t.Fatal(err)
	}
	p, err := policy.DecodeBody(body)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	keys, err := sanitizer.ParseKeys(*v.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := sanitizer.NewEngine(p, keys)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	in, err := parseVInput(v.Input)
	if err != nil {
		t.Fatal(err)
	}
	// A vector whose source kept only a prefix of a body that the SDK
	// would keep whole (total below the capture limit, spec v1.19 22.5)
	// cannot be replayed: fill would make the rest of the body up.
	for _, b := range []struct {
		body  []byte
		total int64
	}{{in.reqBody, in.reqTotal}, {in.respBody, in.respTotal}} {
		if b.total > int64(len(b.body)) && b.total < p.CaptureLimit() {
			return "prefix-only body within the capture limit", false
		}
	}

	fs := &fakeSource{}
	fs.set(sourceclient.Capture{Engine: eng, Policy: &policy.Verified{Policy: p, Hash: "sha256:" + strings.Repeat("cd", 32)},
		OverrideBP: -1, SourceID: "src-TEST0001", ServiceName: in.serviceName, Kind: Kind, Version: Version}, true)
	a := testAgent(t, fs, func(c *Config) {
		c.TraceContext = func(context.Context) (string, string, bool) {
			if in.traceID == "" {
				return "", "", false
			}
			return in.traceID, "00f067aa0ba902b7", true
		}
	})
	a.now = func() time.Time { return now }

	switch in.dir {
	case "inbound":
		if skip = replayInbound(t, a, in); skip != "" {
			return skip, false
		}
	case "outbound":
		if skip = replayOutbound(t, a, in); skip != "" {
			return skip, false
		}
	default:
		t.Fatalf("dir %q", in.dir)
	}
	drain(t, a)

	events := fs.taken()
	if v.Expected.Outcome == "not_sampled" {
		if len(events) != 0 {
			t.Errorf("not_sampled vector produced %d events", len(events))
		}
		return "", true
	}
	if len(events) != 1 {
		t.Fatalf("%d events, want 1 (errors: %v)", len(events), fs.errs)
	}
	got, err := vectorOutput(events[0])
	if err != nil {
		t.Fatal(err)
	}
	want, err := vectorOutput([]byte(v.Expected.Canonical))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("SDK output differs from the reference\n got  %s\n want %s", got, want)
	}
	return "", true
}

func replayInbound(t *testing.T, a *Agent, in *vInput) (skip string) {
	if in.reqDecoded || in.respDecoded {
		return "runtime-decoded body"
	}
	if !isToken([]byte(in.method)) {
		return "method not a token"
	}
	if len(in.rawPath) == 0 || in.rawPath[0] != '/' || !validTarget(in.rawPath) || (in.hasQuery && !validTarget(in.rawQuery)) || bytes.IndexByte(in.rawQuery, '#') >= 0 {
		return "request target"
	}
	if len(in.reqHeaders) >= 60 {
		return "header count at the sanitizer limit (the client adds Host)"
	}
	for _, h := range in.reqHeaders {
		if !isToken(h.name) || !validValue(h.value) || transportHeaders[strings.ToLower(string(h.name))] {
			return "request header not expressible"
		}
	}
	for _, h := range in.respHeaders {
		if !isToken(h.name) || !validValue(h.value) || transportHeaders[strings.ToLower(string(h.name))] {
			return "response header not expressible"
		}
	}
	reqBody, ok := fill(in.reqBody, in.reqTotal)
	if !ok {
		return "request body length"
	}
	respBody, ok := fill(in.respBody, in.respTotal)
	if !ok {
		return "response body length"
	}
	if in.status < 200 || in.status > 599 || ((in.status == 204 || in.status == 304) && len(respBody) > 0) {
		return "response status"
	}
	if len(respBody) > 0 && !hasVHeader(in.respHeaders, "content-type") {
		return "server would sniff a content type (covered by TestSniffedContentType)"
	}
	if strings.EqualFold(in.method, "HEAD") && len(respBody) > 0 {
		return "HEAD with a body"
	}

	invoked := make(chan struct{}, 1)
	done := make(chan struct{})
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invoked <- struct{}{}
		if in.reqConsumed {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		for _, h := range in.respHeaders {
			w.Header().Add(string(h.name), string(h.value))
		}
		w.WriteHeader(in.status)
		_, _ = w.Write(respBody)
	})
	// The route comes from the vector; the real net/http, chi and gin routes
	// are covered by their own tests.
	h := a.Handler(app, WithRoute(func(*http.Request) (string, string) { return in.framework, in.frameworkRoute }))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	var req bytes.Buffer
	target := string(in.rawPath)
	if in.hasQuery {
		target += "?" + string(in.rawQuery)
	}
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\nHost: vector.example\r\n", in.method, target)
	for _, h := range in.reqHeaders {
		req.Write(h.name)
		req.WriteString(": ")
		req.Write(h.value)
		req.WriteString("\r\n")
	}
	if len(reqBody) > 0 {
		fmt.Fprintf(&req, "Content-Length: %d\r\n", len(reqBody))
	}
	req.WriteString("\r\n")
	req.Write(reqBody)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	_, _ = bufio.NewReader(conn).ReadString('\n')
	select {
	case <-invoked: // the answer is only sent after the handler started
	default:
		return "refused by net/http"
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not finish")
	}
	return ""
}

func validTarget(b []byte) bool {
	for _, c := range b {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func hasVHeader(hs []vHeader, name string) bool {
	for _, h := range hs {
		if strings.EqualFold(string(h.name), name) {
			return true
		}
	}
	return false
}

// stubTransport answers like a server whose answer is the vector's.
type stubTransport struct {
	in       *vInput
	respBody []byte
	read     bool // read the request body
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil && s.read {
		_, _ = io.Copy(io.Discard, req.Body)
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	if s.in.netError != "" {
		switch s.in.netError {
		case "timeout":
			return nil, context.DeadlineExceeded
		case "reset":
			return nil, &net.OpError{Op: "read", Err: syscall.ECONNRESET}
		case "refused":
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		case "dns":
			return nil, &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}
		case "tls":
			return nil, x509.UnknownAuthorityError{}
		}
		return nil, errors.New("something else")
	}
	h := http.Header{}
	for _, v := range s.in.respHeaders {
		h.Add(string(v.name), string(v.value))
	}
	return &http.Response{StatusCode: s.in.status, Header: h, Body: io.NopCloser(bytes.NewReader(s.respBody)), ContentLength: -1,
		Uncompressed: s.in.respDecoded, Request: req}, nil
}

func replayOutbound(t *testing.T, a *Agent, in *vInput) (skip string) {
	if in.reqDecoded {
		return "runtime-decoded body"
	}
	reqBody, ok := fill(in.reqBody, in.reqTotal)
	if !ok {
		return "request body length"
	}
	respBody, ok := fill(in.respBody, in.respTotal)
	if !ok {
		return "response body length"
	}
	target := in.urlBase + string(in.rawPath)
	if in.hasQuery {
		target += "?" + string(in.rawQuery)
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme+"://"+u.Host != in.urlBase {
		return "url_base not preserved by net/url"
	}
	if p := u.EscapedPath(); p != string(in.rawPath) && !(p == "" && string(in.rawPath) == "/") {
		return "raw path not preserved by net/url"
	}
	if in.hasQuery && (u.RawQuery != string(in.rawQuery) || (len(in.rawQuery) == 0 && !u.ForceQuery)) {
		return "raw query not preserved by net/url"
	}
	ctx := context.Background()
	if in.inherited != nil {
		ctx = withInherited(ctx, *in.inherited)
	}
	var rb io.Reader
	if len(reqBody) > 0 {
		rb = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, in.method, target, rb)
	if err != nil {
		return "request refused by net/http"
	}
	for _, h := range in.reqHeaders {
		req.Header.Add(string(h.name), string(h.value))
	}
	rt := a.Transport(&stubTransport{in: in, respBody: respBody, read: in.reqConsumed})
	resp, err := rt.RoundTrip(req)
	if in.netError != "" {
		if err == nil {
			t.Fatal("expected a transport error")
		}
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	if in.respConsumed {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	_ = resp.Body.Close()
	return ""
}
