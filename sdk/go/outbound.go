package ttsdk

import (
	"net/http"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Transport wraps base (nil: http.DefaultTransport) so that the calls made
// through it are captured, like the inbound ones. It sees the exchange
// before TLS encrypts it, so calls to HTTPS services are readable by the
// sanitizer. When the agent is inert it returns base itself.
//
// A call made with the context of an inbound request (the request.Context()
// the application got from Handler) inherits that request's sampling
// decision and is linked to its trace; any other call is sampled by trace
// id or at random (docs/spec/sanitizer.md section 12). The request and
// response are never altered, with one opt-in exception: towards the hosts
// of sampling.propagate_to, and never towards an external service of the
// policy, the tt.s baggage member is added, in front of the others.
//
// Put it as the outermost transport that still sees the final request, for
// example around otelhttp.NewTransport(base) when traceparent should be
// read from the request, or inside it when the span is read through the
// otelctx module.
func (a *Agent) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if !a.Enabled() {
		return base
	}
	return &transport{a: a, base: base}
}

type transport struct {
	a    *Agent
	base http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	x, out := t.a.beginOut(req)
	resp, err := t.base.RoundTrip(out)
	if resp != nil && resp.Request == out {
		resp.Request = req
	}
	if x == nil {
		return resp, err
	}
	x.endOut(resp, err)
	return resp, err
}

// beginOut decides whether to capture an outbound call and prepares its
// record. It returns the request to send, which is req itself unless the
// body is copied or tt.s is added. It never panics.
func (a *Agent) beginOut(req *http.Request) (x *exchange, out *http.Request) {
	out = req
	defer func() {
		if p := recover(); p != nil {
			a.counters().SanitizerErrors.Add(1)
			x, out = nil, req
		}
	}()
	t0 := time.Now()
	a.counters().ExchangesSeen.Add(1)
	cp, ok := a.src.Active()
	if !ok || req.URL == nil {
		return nil, req
	}
	fl := flowFrom(req.Context())
	tc, _, haveTC := a.readContext(req.Context(), req.Header)

	var d sanitizer.Decision
	var inherited *bool
	if fl != nil {
		inherited = &fl.sampled
		d = sanitizer.Decision{Sampled: fl.sampled, By: sanitizer.ByInherited}
	} else {
		view := &sanitizer.Exchange{Dir: sanitizer.Outbound}
		if haveTC {
			view.TraceID = tc.traceID
		}
		d = cp.Engine.Sample(view, sanitizer.SampleOptions{RateBP: cp.OverrideBP})
	}

	if fl != nil && a.mayPropagate(cp, req.URL.Scheme, req.URL.Host) {
		out = shallowCopy(req)
		out.Header = req.Header.Clone()
		if out.Header == nil {
			out.Header = http.Header{}
		}
		if v := out.Header["Baggage"]; len(v) > 0 {
			v[0] = withTTBaggage(v[0], fl.sampled)
		} else {
			out.Header["Baggage"] = []string{withTTBaggage("", fl.sampled)}
		}
	}
	if !d.Sampled || req.URL.Host == "" {
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

	x = &exchange{a: a, cap: cp, dir: sanitizer.Outbound, by: d.By, limit: int(cp.Engine.Policy().CaptureLimit()),
		start: t0, method: req.Method, reqCL: req.ContentLength, inherited: inherited,
		urlBase: req.URL.Scheme + "://" + req.URL.Host, reqHeaders: toHeaders(req.Header), respNeedsEOF: true, respCL: -1}
	if x.method == "" {
		x.method = http.MethodGet
	}
	p := req.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	x.rawPath = []byte(p)
	if req.URL.RawQuery != "" || req.URL.ForceQuery {
		x.rawQuery = []byte(req.URL.RawQuery)
	}
	if haveTC {
		x.sampleTrace = tc.traceID
	}
	switch {
	case haveTC:
		x.traceID, x.spanID = tc.traceID, tc.spanID
		if fl != nil && fl.traceID == tc.traceID && fl.spanID != tc.spanID {
			x.parentID = fl.spanID
		}
	case fl != nil:
		x.traceID, x.spanID, x.parentID = fl.traceID, randomHex(8), fl.spanID
	default:
		x.traceID, x.spanID = randomHex(16), randomHex(8)
	}
	if req.Body != nil && req.Body != http.NoBody {
		if out == req {
			out = shallowCopy(req)
		}
		x.reqBuf = &capBuf{limit: x.limit}
		x.reqTee = &teeReader{rc: req.Body, cb: x.reqBuf}
		out.Body = x.reqTee
	}
	x.pre = time.Since(t0)
	return x, out
}

func shallowCopy(r *http.Request) *http.Request {
	c := new(http.Request)
	*c = *r
	return c
}

// endOut records the outcome of a call and arranges for the exchange to be
// finished when the response body ends or is closed.
func (x *exchange) endOut(resp *http.Response, err error) {
	if err != nil || resp == nil {
		x.mu.Lock()
		x.netErr = "other"
		if err != nil {
			x.netErr = classifyNetError(err)
		}
		x.mu.Unlock()
		x.finish()
		return
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		x.abandon() // upgraded streams (websocket) are not captured
		return
	}
	x.mu.Lock()
	x.started = true
	x.status = resp.StatusCode
	x.respHeaders = toHeaders(resp.Header)
	x.respDecoded = resp.Uncompressed
	x.mu.Unlock()
	if resp.Body == nil || resp.Body == http.NoBody || x.method == http.MethodHead {
		x.finish()
		return
	}
	x.respBuf = &capBuf{limit: x.limit}
	tr := &teeReader{rc: resp.Body, cb: x.respBuf, onEOF: x.finish, onClose: x.finish}
	x.respTee = tr
	x.respCL = resp.ContentLength
	resp.Body = tr
}
