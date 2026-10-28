package core_rt

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/egress"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

type upstreamRec struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (u *upstreamRec) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	u.mu.Lock()
	u.reqs = append(u.reqs, r.Clone(context.Background()))
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (u *upstreamRec) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		return nil
	}
	return u.reqs[len(u.reqs)-1]
}

func (u *upstreamRec) count() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.reqs) }

// startEgress runs tt-egress with one upstream alias "ext" in front of a
// recording server; src may be nil (forward-only mode).
func startEgress(t *testing.T, src *sourceclient.Source) (*upstreamRec, *httptest.Server, *httptest.Server) {
	t.Helper()
	up := &upstreamRec{}
	us := httptest.NewServer(up)
	t.Cleanup(us.Close)
	p, err := egress.New(egress.Config{Upstreams: []egress.Upstream{{Alias: "ext", URL: us.URL}}, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(p)
	t.Cleanup(func() { ps.Close(); _ = p.Close(context.Background()) })
	return up, us, ps
}

// tt-egress removes every tt.s baggage member before forwarding, keeps the
// other members byte for byte, never writes traceparent / tracestate /
// baggage / X-Forwarded-* / Via, refuses CONNECT, and routes an
// absolute-form request only to the configured upstream.
func TestRT_Egress_Holds_HeadersBaggageConnect(t *testing.T) {
	up, us, ps := startEgress(t, nil)
	cases := []struct {
		in   []string
		want []string // baggage lines expected at the upstream (nil = no header)
	}{
		{[]string{"tt.s=1"}, nil},
		{[]string{"tt.s=1,userId=alice"}, []string{"userId=alice"}},
		{[]string{"a=1, tt.s=0 ,b=2"}, []string{"a=1,b=2"}},
		{[]string{"\ttt.s\t=\t1;prop=x, c=3"}, []string{"c=3"}},
		{[]string{"tt.s;p=1"}, nil},
		{[]string{"x=1", "tt.s=1", "y=2,tt.s=0"}, []string{"x=1", "y=2"}},
		{[]string{"tt.sx=1"}, []string{"tt.sx=1"}},
	}
	for _, c := range cases {
		req, _ := http.NewRequest("GET", ps.URL+"/ext/v1/things", nil)
		for _, v := range c.in {
			req.Header.Add("Baggage", v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		got := up.last().Header.Values("Baggage")
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("baggage %q forwarded as %q (want %q)", c.in, got, c.want)
		}
		for _, h := range []string{"Traceparent", "Tracestate", "Via", "X-Forwarded-For", "X-Forwarded-Host", "Forwarded"} {
			if v := up.last().Header.Get(h); v != "" {
				t.Errorf("egress added %s: %q", h, v)
			}
		}
	}
	// traceparent passes unchanged.
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	req, _ := http.NewRequest("GET", ps.URL+"/ext/x", nil)
	req.Header.Set("traceparent", tp)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if up.last().Header.Get("Traceparent") != tp {
		t.Errorf("traceparent changed: %q", up.last().Header.Get("Traceparent"))
	}
	// CONNECT and absolute-form requests (raw TCP).
	n := up.count()
	addr := strings.TrimPrefix(ps.URL, "http://")
	raw := func(s string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(c, s)
		line, _ := bufio.NewReader(c).ReadString('\n')
		return line
	}
	if l := raw("CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254:443\r\n\r\n"); !strings.Contains(l, "405") {
		t.Errorf("CONNECT answered %q", l)
	}
	if up.count() != n {
		t.Error("CONNECT reached the upstream")
	}
	l := raw("GET http://169.254.169.254/ext/meta HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n")
	if !strings.Contains(l, "200") || up.count() != n+1 || up.last().Host != strings.TrimPrefix(us.URL, "http://") {
		t.Errorf("absolute-form request: %q, upstream host %q", l, up.last().Host)
	}
	if l := raw("GET http://169.254.169.254/latest/meta-data HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n"); !strings.Contains(l, "404") {
		t.Errorf("absolute-form request to an unknown alias: %q", l)
	}
}

// A source enrolled in a group without a policy never captures: requests
// are forwarded (tt.s still stripped), nothing is sampled or sent, health
// says no_policy.
func TestRT_Egress_Holds_NoCaptureWithoutPolicy(t *testing.T) {
	e := getEnv(t)
	olga := e.u(t, "olga")
	olga.must(201, "POST", "/api/v1/fleet/groups", map[string]any{"name": "rt-eg", "allowed_service_names": []string{"rt-eg-svc"}})
	var tok struct {
		Token string `json:"token"`
	}
	olga.json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "egress", "group": "rt-eg", "token_type": "one_time"}, &tok)
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: e.core.Config().Fleet.PublicURL, Token: tok.Token, StateDir: filepath.Join(t.TempDir(), "eg"),
		Kind: "egress", Version: "0.1.0", ServiceName: "rt-eg-svc", Instance: "rt-eg-1", Keys: e.hmacKeys, KeyKids: []string{core.DevHMACKid},
		HeartbeatInterval: 40 * time.Millisecond, PolicyPollInterval: 40 * time.Millisecond, Now: e.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	src.Start(e.ctx)
	t.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = src.Close(ctx)
	})
	eventually(t, 10*time.Second, "enrollment", func() bool { return src.Identity() != nil })
	time.Sleep(300 * time.Millisecond) // a few heartbeats and policy polls
	up, _, ps := startEgress(t, src)
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("POST", ps.URL+"/ext/v1/orders", strings.NewReader(`{"email":"anna.rossi@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Baggage", "tt.s=1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if up.count() != 20 || up.last().Header.Get("Baggage") != "" {
		t.Errorf("forwarded %d, last baggage %q", up.count(), up.last().Header.Get("Baggage"))
	}
	if _, ok := src.Active(); ok {
		t.Fatal("source active without a policy")
	}
	c := src.Counters().Snapshot()
	if c.ExchangesSampled != 0 || c.EventsSent != 0 {
		t.Errorf("captured without policy: %+v", c)
	}
	resp, err := http.Get(ps.URL + egress.HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	t.Logf("health: status=%v capture=%v", h["status"], h["capture"])
	// Fixed (red team round 2, info): without a policy the health says
	// no_policy, not starting (also while heartbeats fail).
	if h["capture"] != "no_policy" {
		t.Errorf("health capture = %v without a policy (want no_policy)", h["capture"])
	}
	if st := e.core.Intake().SourceStats(src.Identity().SourceID); st.Accepted != 0 {
		t.Errorf("intake accepted %d events from a source without policy", st.Accepted)
	}
}
