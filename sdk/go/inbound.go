package ttsdk

import (
	"bufio"
	"net"
	"net/http"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// HandlerOption configures Agent.Handler.
type HandlerOption func(*handlerOptions)

type handlerOptions struct {
	route func(r *http.Request) (framework, route string)
}

// WithRoute sets how the route template (framework_route) of a request is
// found. The function runs after the wrapped handler returned, with the
// request that was passed to it, so a router that stores the matched route
// in the request or its context (chi, for example) can answer. It returns
// the framework (one of the names of docs/spec/sanitizer.md section 3.4:
// "nethttp", "gin", "chi", ...) and the route complete with its mount
// prefixes; return "" when it can not be rebuilt completely.
//
// The default reads Request.Pattern, which the Go 1.22+ http.ServeMux fills
// in with the pattern it matched.
func WithRoute(f func(r *http.Request) (framework, route string)) HandlerOption {
	return func(o *handlerOptions) { o.route = f }
}

func defaultRoute(r *http.Request) (string, string) {
	if route := patternRoute(r.Pattern); route != "" {
		return "nethttp", route
	}
	return "", ""
}

// Handler wraps next so that the requests it serves are captured. When the
// agent is inert it returns next itself.
//
// The matched ServeMux pattern ("GET /orders/{id}") is passed to the
// sanitizer as framework_route, so the operation is the one the application
// routed to. Use it outside the mux (Handler(mux)) or around a single
// handler; only a pattern the mux sets on the request this middleware passed
// down is seen, which keeps routes of nested routers (http.StripPrefix plus
// an inner mux) out: a partial route is never reported.
func (a *Agent) Handler(next http.Handler, opts ...HandlerOption) http.Handler {
	if !a.Enabled() {
		return next
	}
	o := handlerOptions{route: defaultRoute}
	for _, f := range opts {
		f(&o)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, r2 := a.Begin(r)
		if r2 != r {
			// The mux fills Request.Pattern in on the request it receives,
			// which is our copy; middleware outside us (otelhttp names its
			// span with it) must still see it on theirs.
			defer func() {
				if r2.Pattern != "" {
					r.Pattern = r2.Pattern
				}
			}()
		}
		if in == nil {
			next.ServeHTTP(w, r2)
			return
		}
		completed := false
		defer func() {
			if !completed { // panic or runtime.Goexit in the handler
				in.Abandon()
			}
		}()
		next.ServeHTTP(in.WrapWriter(w), r2)
		completed = true
		if o.route != nil {
			in.SetRoute(o.route(r2))
		}
		in.End()
	})
}

// Inbound is one inbound exchange that is being captured. It is the building
// block of the framework adapters (the gin and chi modules); applications
// use Handler. All methods are safe to call on a nil *Inbound.
type Inbound struct {
	x *exchange
	w http.ResponseWriter
}

// Begin decides, for an inbound request, whether to capture it. It returns
// the request to hand to the application (its context carries the sampling
// decision for the outbound calls made while serving it, and when the
// exchange is captured its body is copied as the application reads it) and
// the Inbound to feed with the response, or nil when the exchange is not
// captured (no policy, kill switch, not sampled, overload): the application
// then runs untouched. Begin never panics and never blocks.
func (a *Agent) Begin(r *http.Request) (in *Inbound, out *http.Request) {
	if !a.Enabled() || r == nil {
		return nil, r
	}
	out = r
	defer func() {
		if p := recover(); p != nil { // the application must not suffer from a bug of ours
			a.counters().SanitizerErrors.Add(1)
			in, out = nil, r
		}
	}()
	t0 := time.Now()
	a.counters().ExchangesSeen.Add(1)
	cp, ok := a.src.Active()
	if !ok {
		return nil, r
	}
	// Trace context: read, never written.
	tc, fromSpan, haveTC := a.readContext(r.Context(), r.Header)
	var hdr traceContext
	if v := r.Header.Get("Traceparent"); v != "" {
		hdr, _ = parseTraceparent(v)
	}
	var from, name string
	if s := cp.Engine.Policy().Subject; s != nil {
		from, name = s.From, s.Name
	}
	view := &sanitizer.Exchange{Dir: sanitizer.Inbound, ServiceName: cp.ServiceName, ReqHeaders: samplingHeaders(r.Header, from, name)}
	if haveTC {
		view.TraceID = tc.traceID
	}
	d := cp.Engine.Sample(view, sanitizer.SampleOptions{RateBP: cp.OverrideBP})

	// The identifiers of the event: those of the context, else our own
	// (random, W3C format, kept in the context and never injected).
	fl := &flow{sampled: d.Sampled}
	var parent string
	switch {
	case fromSpan:
		fl.traceID, fl.spanID = tc.traceID, tc.spanID
		if hdr.traceID == tc.traceID && hdr.spanID != tc.spanID {
			parent = hdr.spanID
		}
	case haveTC:
		fl.traceID, fl.spanID, parent = tc.traceID, randomHex(8), tc.spanID
	default:
		fl.traceID, fl.spanID = randomHex(16), randomHex(8)
	}
	out = r.WithContext(contextWith(r.Context(), fl))
	if !d.Sampled {
		a.observe(time.Since(t0))
		return nil, out
	}
	c := a.counters()
	c.ExchangesSampled.Add(1)
	if a.inflight.Add(1) > int64(a.cfg.MaxInflight) {
		a.inflight.Add(-1)
		c.EventsDroppedQueue.Add(1)
		return nil, out
	}
	x := &exchange{a: a, cap: cp, dir: sanitizer.Inbound, by: d.By, limit: int(cp.Engine.Policy().CaptureLimit()),
		start: t0, method: r.Method, reqCL: r.ContentLength, reqHeaders: requestHeaders(r), sniff: true,
		traceID: fl.traceID, spanID: fl.spanID, parentID: parent}
	if haveTC {
		x.sampleTrace = tc.traceID
	}
	x.rawPath, x.rawQuery = rawTarget(r)
	x.respBuf = &capBuf{limit: x.limit}
	if r.Body != nil && r.Body != http.NoBody {
		x.reqBuf = &capBuf{limit: x.limit}
		x.reqTee = &teeReader{rc: r.Body, cb: x.reqBuf}
		out.Body = x.reqTee
	}
	x.pre = time.Since(t0)
	return &Inbound{x: x}, out
}

// WrapWriter returns the ResponseWriter to give to the application: it
// passes everything through and observes status, headers and body. It keeps
// http.Flusher, http.Hijacker and http.Pusher (when w has them) and
// Unwrap, so http.ResponseController keeps working.
func (in *Inbound) WrapWriter(w http.ResponseWriter) http.ResponseWriter {
	if in == nil {
		return w
	}
	in.w = w
	return &respWriter{w: w, in: in}
}

// SetRoute sets the route template and framework of the exchange; call it
// before End, once the router has resolved the request. An empty route
// leaves the sanitizer to use the policy templates.
func (in *Inbound) SetRoute(framework, route string) {
	if in == nil || route == "" {
		return
	}
	in.x.mu.Lock()
	in.x.framework, in.x.route = framework, route
	in.x.mu.Unlock()
}

// ResponseStarted records the status and a copy of the headers of the
// response, the first time it is called (adapters call it when the
// response is committed). Writers that go through WrapWriter do it by
// themselves.
func (in *Inbound) ResponseStarted(status int, h http.Header) {
	if in == nil {
		return
	}
	in.x.responseStarted(status, func() []sanitizer.Header { return toHeaders(h) })
}

// ResponseBytes records body bytes that were written to the client.
func (in *Inbound) ResponseBytes(p []byte) {
	if in == nil || in.x.method == http.MethodHead || in.x.finished.Load() {
		return
	}
	in.x.respBuf.add(p)
}

// Abandon drops the exchange: no event is produced (hijacked connection,
// panic).
func (in *Inbound) Abandon() {
	if in != nil {
		in.x.abandon()
	}
}

// End finishes the exchange and hands it to the sanitizer workers. If the
// application wrote nothing, the response is the implicit 200.
func (in *Inbound) End() {
	if in == nil {
		return
	}
	var h http.Header
	if in.w != nil {
		h = in.w.Header()
	}
	in.x.responseStarted(http.StatusOK, func() []sanitizer.Header { return toHeaders(h) })
	in.x.finish()
}

// respWriter observes a response without changing it.
type respWriter struct {
	w  http.ResponseWriter
	in *Inbound
}

func (rw *respWriter) Header() http.Header { return rw.w.Header() }

func (rw *respWriter) WriteHeader(code int) {
	switch {
	case code == http.StatusSwitchingProtocols:
		rw.in.Abandon()
	case code >= 100 && code <= 199:
		// Informational: the final status comes later.
	default:
		rw.in.ResponseStarted(code, rw.w.Header())
	}
	rw.w.WriteHeader(code)
}

func (rw *respWriter) Write(p []byte) (int, error) {
	rw.in.ResponseStarted(http.StatusOK, rw.w.Header())
	n, err := rw.w.Write(p)
	rw.in.ResponseBytes(p[:n])
	return n, err
}

func (rw *respWriter) Flush() {
	rw.in.ResponseStarted(http.StatusOK, rw.w.Header())
	if f, ok := rw.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rw.w.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	rw.in.Abandon()
	return h.Hijack()
}

func (rw *respWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := rw.w.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (rw *respWriter) Unwrap() http.ResponseWriter { return rw.w }
