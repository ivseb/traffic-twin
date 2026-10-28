package egress

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// tee copies the first limit bytes of a body that flows through it and counts
// the rest. It never holds more than limit bytes (docs/spec/sanitizer.md
// sections 9.0 and 22.5: policy CaptureLimit): the proxy streams, it does not buffer.
type tee struct {
	rc    io.ReadCloser
	limit int

	mu  sync.Mutex
	buf []byte
	n   int64 // bytes that went through
	eof bool

	spent   atomic.Int64 // nanoseconds spent copying
	onClose func()
}

func newTee(rc io.ReadCloser, limit int) *tee { return &tee{rc: rc, limit: limit} }

func (t *tee) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 || err != nil {
		t0 := time.Now()
		t.mu.Lock()
		t.n += int64(n)
		if room := t.limit - len(t.buf); n > 0 && room > 0 {
			take := min(n, room)
			t.reserve(take)
			t.buf = append(t.buf, p[:take]...)
		}
		if err == io.EOF {
			t.eof = true
		}
		t.mu.Unlock()
		t.spent.Add(int64(time.Since(t0)))
	}
	return n, err
}

// reserve grows the buffer geometrically but never past limit.
func (t *tee) reserve(extra int) {
	need := len(t.buf) + extra
	if need <= cap(t.buf) {
		return
	}
	nc := max(2*cap(t.buf), need, 512)
	nc = min(nc, t.limit)
	nb := make([]byte, len(t.buf), nc)
	copy(nb, t.buf)
	t.buf = nb
}

func (t *tee) Close() error {
	err := t.rc.Close()
	if t.onClose != nil {
		t.onClose()
	}
	return err
}

// snapshot returns the kept prefix, the total length and whether the body was
// read to its end.
func (t *tee) snapshot() (b []byte, total int64, eof bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf, t.n, t.eof
}

type ctxKey struct{}

// exchange is one sampled request/response pair being captured. Its fields
// are written by the goroutine serving the request (headers, status), except
// the request tee which the transport goroutine fills under its own lock.
type exchange struct {
	p     *Proxy
	cap   sourceclient.Capture
	by    sanitizer.SampledBy
	limit int
	start time.Time

	method   string
	rawPath  []byte
	rawQuery []byte // nil when the URL has no '?'
	urlBase  string
	reqCL    int64

	reqHeaders  []sanitizer.Header
	respHeaders []sanitizer.Header
	status      int
	netErr      string

	traceID, parentID, spanID string

	req, resp *tee
	pre       time.Duration

	finished atomic.Bool
}

// job is a finished exchange waiting for a sanitizer worker.
type job struct {
	x            *exchange
	reqBody      []byte
	reqTotal     int64
	reqConsumed  bool
	respBody     []byte
	respTotal    int64
	respConsumed bool
	latency      time.Duration
	bytes        int64
}

// finish ends the exchange exactly once: it hands the copied bodies to the
// sanitizer workers, or drops them when the pipeline is overloaded. It never
// blocks.
func (x *exchange) finish() {
	if !x.finished.CompareAndSwap(false, true) {
		return
	}
	p := x.p
	defer p.inflight.Add(-1)
	t0 := time.Now()
	if x.status == 0 && x.netErr == "" {
		return // no response and no transport error: nothing to describe
	}
	j := &job{x: x, latency: t0.Sub(x.start), reqConsumed: true, respConsumed: true}
	var spent int64
	if x.req != nil {
		b, n, eof := x.req.snapshot()
		j.reqBody, j.reqTotal = b, n
		j.reqConsumed = eof || (x.reqCL >= 0 && n == x.reqCL)
		spent += x.req.spent.Load()
	}
	if x.resp != nil {
		b, n, eof := x.resp.snapshot()
		j.respBody, j.respTotal, j.respConsumed = b, n, eof
		spent += x.resp.spent.Load()
	}
	j.bytes = int64(len(j.reqBody) + len(j.respBody))
	p.submit(j)
	p.observe(x.pre + time.Duration(spent) + time.Since(t0))
}

func (x *exchange) abandon() {
	if x.finished.CompareAndSwap(false, true) {
		x.p.inflight.Add(-1)
	}
}

// submit queues a job or drops it: traffic is never held back by tt.
func (p *Proxy) submit(j *job) {
	c := p.counters()
	if p.closed.Load() || p.pending.Add(j.bytes) > p.cfg.Capture.MaxPendingBytes {
		p.pending.Add(-j.bytes)
		c.EventsDroppedQueue.Add(1)
		return
	}
	select {
	case p.jobs <- j:
	default:
		p.pending.Add(-j.bytes)
		c.EventsDroppedQueue.Add(1)
	}
}

func (p *Proxy) worker() {
	defer p.wg.Done()
	for {
		select {
		case j := <-p.jobs:
			p.process(j)
		case <-p.done:
			for {
				select {
				case j := <-p.jobs:
					p.process(j)
				default:
					return
				}
			}
		}
	}
}

// process sanitizes one exchange and queues the event. Any failure (error or
// panic) means: no event, and sanitizer_errors is incremented.
func (p *Proxy) process(j *job) {
	defer p.pending.Add(-j.bytes)
	c := p.counters()
	defer func() {
		if r := recover(); r != nil {
			c.SanitizerErrors.Add(1)
			p.src.RecordError("sanitizer_panic")
		}
	}()
	if p.cfg.OnSanitize != nil {
		p.cfg.OnSanitize()
	}
	x := j.x
	ex := &sanitizer.Exchange{
		Dir: sanitizer.Outbound, URLBase: x.urlBase, Method: x.method, RawPath: x.rawPath, RawQuery: x.rawQuery,
		TraceID:    x.traceID,
		ReqHeaders: x.reqHeaders, ReqBody: j.reqBody, ReqBodyTotal: j.reqTotal, ReqBodyNotConsumed: !j.reqConsumed,
		Status: x.status, NetError: x.netErr,
		RespHeaders: x.respHeaders, RespBody: j.respBody, RespBodyTotal: j.respTotal, RespBodyNotConsumed: !j.respConsumed,
	}
	out, err := x.cap.Engine.Sanitize(ex, time.Now(), x.by)
	if err != nil {
		c.SanitizerErrors.Add(1)
		p.src.RecordError("sanitizer_error")
		return
	}
	meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{
		SourceKind: x.cap.Kind, SourceVersion: x.cap.Version, SourceID: x.cap.SourceID,
		TS: x.start, LatencyMS: j.latency.Milliseconds(), Status: x.status, NetError: x.netErr,
		TraceID: x.traceID, SpanID: x.spanID, ParentSpanID: x.parentID,
	}, x.cap.Policy)
	ev, err := sanitizer.BuildEvent(meta, out)
	if err != nil {
		c.SanitizerErrors.Add(1)
		p.src.RecordError("event_build_error")
		return
	}
	p.src.Emit(sourceclient.Event{JSON: ev, TS: x.start, TraceID: x.traceID, SpanID: x.spanID, PolicyHash: x.cap.Policy.Hash})
}

func (p *Proxy) counters() *sourceclient.Counters {
	if p.src == nil {
		return &p.nullCounters
	}
	return p.src.Counters()
}

func (p *Proxy) observe(d time.Duration) {
	if p.src != nil {
		p.src.ObserveOverhead(d)
	}
}

func fromCtx(ctx context.Context) *exchange {
	x, _ := ctx.Value(ctxKey{}).(*exchange)
	return x
}

// captureRT reports transport errors (no response at all) to the exchange.
type captureRT struct{ tr http.RoundTripper }

func (c captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.tr.RoundTrip(req)
	if err != nil {
		if x := fromCtx(req.Context()); x != nil {
			x.netErr = classifyNetError(err)
			x.finish()
		}
	}
	return resp, err
}
