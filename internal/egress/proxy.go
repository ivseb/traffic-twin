// Package egress implements tt-egress, the outbound reverse proxy for stacks
// without an SDK (docs/ARCHITECTURE.md section 3, decision D2): the
// application is given http://tt-egress:PORT/<alias> as the base URL of an
// external service, and the proxy continues over TLS to the real service.
//
// The proxy never changes the traffic: methods, paths, queries, headers,
// bodies and responses go through as they are (only the hop-by-hop headers
// of RFC 9110 and the tt.s baggage member, which docs/spec/sanitizer.md
// section 12 requires to be removed, are not forwarded). Capture happens on
// a copy: request and response bodies are teed up to max_body_bytes + 1,
// the rest is only counted, and sanitizing runs asynchronously on bounded
// worker queues. When the policy, the key or the heartbeat is missing, when
// the kill switch is on, or when anything is overloaded, the proxy keeps
// forwarding and captures nothing (events are dropped, requests never wait).
//
// MITM (a proxy with an internal CA that reads TLS traffic of unchanged
// URLs) is NOT implemented: it is an explicit opt-in option of the threat
// model (M15) and out of scope for this version.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// HealthPath is the health endpoint served by the proxy itself. It cannot
// collide with an alias (aliases start with a letter or digit).
const HealthPath = "/_tt/health"

type route struct {
	alias    string
	target   *url.URL
	basePath string // decoded path of the upstream base, no trailing slash
	baseRaw  string // escaped
	origin   string // scheme://host[:port] the sanitizer sees
	proxy    *httputil.ReverseProxy
	tr       *http.Transport
	fromPol  bool
}

// Proxy is the egress reverse proxy.
type Proxy struct {
	cfg Config
	src *sourceclient.Source

	routes atomic.Pointer[map[string]*route]
	expl   map[string]*route // explicit routes (never change)
	polMu  sync.Mutex
	pol    map[string]*route // routes derived from the policy

	jobs     chan *job
	done     chan struct{}
	wg       sync.WaitGroup
	closed   atomic.Bool
	pending  atomic.Int64
	inflight atomic.Int64

	nullCounters sourceclient.Counters
	bufPool      bufPool
	started      time.Time
}

// New builds the proxy and starts its sanitizer workers.
func New(cfg Config) (*Proxy, error) {
	cfg.defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Proxy{cfg: cfg, src: cfg.Source, expl: map[string]*route{}, pol: map[string]*route{},
		jobs: make(chan *job, cfg.Capture.QueueSize), done: make(chan struct{}), started: time.Now()}
	for _, u := range cfg.Upstreams {
		rt, err := p.newRoute(u, false)
		if err != nil {
			return nil, err
		}
		p.expl[u.Alias] = rt
	}
	p.publish()
	if p.src != nil {
		workers := cfg.Capture.Workers
		if workers <= 0 {
			workers = min(4, runtime.GOMAXPROCS(0))
		}
		for i := 0; i < workers; i++ {
			p.wg.Add(1)
			go p.worker()
		}
		if cfg.AliasFromPolicy {
			if v := p.src.AcceptedPolicy(); v != nil {
				p.SetPolicy(v)
			}
		}
	}
	return p, nil
}

// Close stops accepting captures, lets the workers drain what is queued and
// closes the idle upstream connections. It does not stop the HTTP server.
func (p *Proxy) Close(ctx context.Context) error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(p.done)
	ch := make(chan struct{})
	go func() { p.wg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-ctx.Done():
	}
	for _, r := range *p.routes.Load() {
		r.tr.CloseIdleConnections()
	}
	return nil
}

// rootCAs returns the system roots plus the extra CAs (Config.ExtraCAPEM and
// the upstream's own CA file).
func (p *Proxy) rootCAs(extraFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if len(p.cfg.ExtraCAPEM) > 0 && !pool.AppendCertsFromPEM(p.cfg.ExtraCAPEM) {
		return nil, errors.New("extra CA: no certificate found")
	}
	if extraFile != "" {
		pemData, err := os.ReadFile(extraFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("ca_file %s: no certificate found", extraFile)
		}
	}
	return pool, nil
}

func (p *Proxy) newRoute(u Upstream, fromPolicy bool) (*route, error) {
	target, err := parseTarget(u.URL)
	if err != nil {
		return nil, err
	}
	pool, err := p.rootCAs(u.CAFile)
	if err != nil {
		return nil, err
	}
	c := &p.cfg
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: c.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:   c.TLSHandshakeTimeout,
		ResponseHeaderTimeout: c.ResponseHeaderTimeout,
		IdleConnTimeout:       c.IdleConnTimeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          c.MaxIdleConnsPerHost * 2,
		MaxIdleConnsPerHost:   c.MaxIdleConnsPerHost,
		// The proxy never asks for gzip on its own: bodies and
		// content-encoding reach the application exactly as the service sent
		// them, and the sanitizer decodes its own copy.
		DisableCompression: true,
	}
	origin := u.CaptureOrigin
	if origin == "" {
		origin = target.Scheme + "://" + target.Host
	}
	origin = strings.TrimSuffix(origin, "/")
	rt := &route{alias: u.Alias, target: target, origin: origin, tr: tr, fromPol: fromPolicy,
		basePath: strings.TrimRight(target.Path, "/"), baseRaw: strings.TrimRight(target.EscapedPath(), "/")}
	rt.proxy = &httputil.ReverseProxy{
		Rewrite:        rt.rewrite,
		Transport:      captureRT{tr},
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler(rt),
		BufferPool:     &p.bufPool,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	return rt, nil
}

// bufPool lends 32 KiB copy buffers to the reverse proxy.
type bufPool struct{ p sync.Pool }

func (b *bufPool) Get() []byte {
	if v, ok := b.p.Get().(*[]byte); ok {
		return *v
	}
	return make([]byte, 32<<10)
}

func (b *bufPool) Put(x []byte) { b.p.Put(&x) }

// rewrite points the outbound request at the upstream and leaves everything
// else as the application sent it.
func (rt *route) rewrite(pr *httputil.ProxyRequest) {
	in, out := pr.In, pr.Out
	rest := strings.TrimPrefix(in.URL.Path, "/"+rt.alias)
	restRaw := strings.TrimPrefix(in.URL.EscapedPath(), "/"+rt.alias)
	out.URL.Scheme, out.URL.Host = rt.target.Scheme, rt.target.Host
	out.URL.Path, out.URL.RawPath = rt.basePath+rest, rt.baseRaw+restRaw
	if out.URL.Path == "" {
		out.URL.Path, out.URL.RawPath = "/", ""
	}
	// ReverseProxy cleans queries it cannot parse; the proxy forwards the
	// query exactly as received.
	out.URL.RawQuery, out.URL.ForceQuery = in.URL.RawQuery, in.URL.ForceQuery
	out.Host = rt.target.Host
	// ReverseProxy strips client forwarding headers in Rewrite mode; they
	// belong to the application's request, so they are put back.
	for _, h := range [...]string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if v, ok := in.Header[h]; ok {
			out.Header[h] = v
		}
	}
}

func (p *Proxy) modifyResponse(res *http.Response) error {
	x := fromCtx(res.Request.Context())
	if x == nil {
		return nil
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		x.abandon() // upgraded streams (websocket) are not captured
		return nil
	}
	x.status = res.StatusCode
	x.respHeaders = toHeaders(res.Header)
	if res.Body == nil || res.Body == http.NoBody {
		x.finish()
		return nil
	}
	x.resp = newTee(res.Body, x.limit)
	x.resp.onClose = x.finish
	res.Body = x.resp
	return nil
}

func (p *Proxy) errorHandler(rt *route) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		// Only the error class is logged: URLs and payloads never are.
		p.cfg.Logger.Warn("upstream error", "alias", rt.alias, "class", classifyNetError(err))
		w.WriteHeader(http.StatusBadGateway)
	}
}

func (p *Proxy) publish() {
	m := make(map[string]*route, len(p.expl)+len(p.pol))
	for a, r := range p.pol {
		m[a] = r
	}
	for a, r := range p.expl {
		m[a] = r
	}
	p.routes.Store(&m)
}

// SetPolicy derives routes from the external services of an accepted policy
// (Config.AliasFromPolicy). Explicit upstreams keep their aliases.
func (p *Proxy) SetPolicy(v *policy.Verified) {
	if !p.cfg.AliasFromPolicy || v == nil {
		return
	}
	p.polMu.Lock()
	defer p.polMu.Unlock()
	next := map[string]*route{}
	for _, s := range v.Policy.Services {
		if s.Match.Base == "" || p.expl[s.Name] != nil || !AliasRE.MatchString(s.Name) {
			continue
		}
		if old := p.pol[s.Name]; old != nil && old.target.String() == strings.TrimRight(s.Match.Base, "/") {
			next[s.Name] = old
			continue
		}
		rt, err := p.newRoute(Upstream{Alias: s.Name, URL: s.Match.Base}, true)
		if err != nil {
			p.cfg.Logger.Warn("policy service not routable", "service", s.Name, "error", err.Error())
			continue
		}
		next[s.Name] = rt
	}
	for a, r := range p.pol {
		if next[a] != r {
			r.tr.CloseIdleConnections()
		}
	}
	p.pol = next
	p.publish()
}

func splitAlias(esc string) (alias string) {
	if len(esc) < 2 || esc[0] != '/' {
		return ""
	}
	rest := esc[1:]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// ServeHTTP routes /<alias>/... to the upstream.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	if r.URL.Path == HealthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		p.health(w)
		return
	}
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported: tt-egress is a reverse proxy, not a MITM proxy", http.StatusMethodNotAllowed)
		return
	}
	esc := r.URL.EscapedPath()
	alias := splitAlias(esc)
	rt := (*p.routes.Load())[alias]
	if rt == nil {
		http.Error(w, "unknown upstream alias", http.StatusNotFound)
		return
	}

	var x *exchange
	if p.src != nil {
		p.src.Counters().ExchangesSeen.Add(1)
		x = p.begin(r, rt, t0)
	} else {
		stripTTBaggage(r.Header)
	}
	if x != nil {
		defer x.finish()
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, x))
		if r.Body != nil && r.Body != http.NoBody {
			x.req = newTee(r.Body, x.limit)
			r.Body = x.req
		}
		x.pre = time.Since(t0)
	} else if p.src != nil {
		p.observe(time.Since(t0))
	}
	rt.proxy.ServeHTTP(w, r)
}

// begin decides whether to capture the exchange (policy, key, kill switch,
// sampling, load) and prepares its record. It also removes the tt.s baggage
// member from the forwarded request.
func (p *Proxy) begin(r *http.Request, rt *route, t0 time.Time) *exchange {
	cp, ok := p.src.Active()
	if !ok {
		stripTTBaggage(r.Header)
		return nil
	}
	var tc traceContext
	hasTrace := false
	if v := r.Header.Get("Traceparent"); v != "" {
		tc, hasTrace = parseTraceparent(v)
	}
	// tt-egress decides like an inbound internal service (sanitizer
	// section 12): baggage if trusted, subject, trace, random.
	var from, name string
	if s := cp.Engine.Policy().Subject; s != nil {
		from, name = s.From, s.Name
	}
	view := &sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: cp.ServiceName, TraceID: tc.traceID,
		ReqHeaders: samplingHeaders(r.Header, from, name)}
	d := cp.Engine.Sample(view, sanitizer.SampleOptions{RateBP: cp.OverrideBP})
	stripTTBaggage(r.Header)
	if !d.Sampled {
		return nil
	}
	c := p.src.Counters()
	c.ExchangesSampled.Add(1)
	if p.inflight.Add(1) > int64(p.cfg.Capture.MaxInflight) {
		p.inflight.Add(-1)
		c.EventsDroppedQueue.Add(1)
		return nil
	}
	esc := r.URL.EscapedPath()
	rest := strings.TrimPrefix(esc, "/"+rt.alias)
	raw := rt.baseRaw + rest
	if raw == "" {
		raw = "/"
	}
	x := &exchange{p: p, cap: cp, by: d.By, limit: int(cp.Engine.Policy().CaptureLimit()), start: t0,
		method: r.Method, rawPath: []byte(raw), urlBase: rt.origin, reqCL: r.ContentLength,
		reqHeaders: toHeaders(r.Header)}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		x.rawQuery = []byte(r.URL.RawQuery)
	}
	if hasTrace {
		x.traceID, x.parentID, x.spanID = tc.traceID, tc.parentID, randomSpanID()
	}
	return x
}

type healthBody struct {
	Status       string   `json:"status"`
	Version      string   `json:"version,omitempty"`
	Capture      string   `json:"capture"`
	Upstreams    []string `json:"upstreams"`
	UptimeS      int64    `json:"uptime_s"`
	EventsPerMin int64    `json:"events_per_min"`
	Seen         int64    `json:"exchanges_seen"`
	Sampled      int64    `json:"exchanges_sampled"`
	Sent         int64    `json:"events_sent"`
	Dropped      int64    `json:"events_dropped_queue"`
	Rejected     int64    `json:"events_rejected"`
	SendErrors   int64    `json:"send_errors"`
	SanitizerErr int64    `json:"sanitizer_errors"`
	OverheadP50  int64    `json:"overhead_us_p50"`
	OverheadP99  int64    `json:"overhead_us_p99"`
	QueueEvents  int      `json:"queue_events"`
}

func (p *Proxy) health(w http.ResponseWriter) {
	b := healthBody{Status: "ok", Version: p.cfg.Version, Capture: "disabled", UptimeS: int64(time.Since(p.started).Seconds())}
	for a := range *p.routes.Load() {
		b.Upstreams = append(b.Upstreams, a)
	}
	if p.src != nil {
		st := p.src.Stats()
		b.Capture, b.EventsPerMin = st.State, st.EventsPerMin
		if b.Capture == sourceclient.StateStarting && !p.src.HasPolicy() {
			// Not "starting": without a policy nothing will be captured
			// until tt-core sends one (also while it cannot be reached).
			b.Capture = string(policy.StateNoPolicy)
		}
		b.Seen, b.Sampled, b.Sent = st.Counters.ExchangesSeen, st.Counters.ExchangesSampled, st.Counters.EventsSent
		b.Dropped, b.Rejected, b.SendErrors, b.SanitizerErr = st.Counters.EventsDroppedQueue, st.Counters.EventsRejected, st.Counters.SendErrors, st.Counters.SanitizerErrors
		b.OverheadP50, b.OverheadP99, b.QueueEvents = st.OverheadP50, st.OverheadP99, st.QueueEvents
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b)
}
