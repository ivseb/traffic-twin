package ttsdk

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

type ctxKey struct{}

// flow is the sampling and trace state of the inbound exchange being served.
// It travels in the request context, so that the calls the application makes
// while serving it (with that context) inherit the decision and are linked to
// it (docs/spec/sanitizer.md section 12, docs/spec/event.md section 1).
type flow struct {
	sampled bool
	traceID string
	spanID  string // span id of the inbound event
}

func flowFrom(ctx context.Context) *flow {
	f, _ := ctx.Value(ctxKey{}).(*flow)
	return f
}

func contextWith(ctx context.Context, f *flow) context.Context {
	return context.WithValue(ctx, ctxKey{}, f)
}

// withInherited returns ctx as if an inbound exchange with this decision
// were being served (tests).
func withInherited(ctx context.Context, sampled bool) context.Context {
	return context.WithValue(ctx, ctxKey{}, &flow{sampled: sampled})
}

// exchange is one sampled request/response pair being captured. The fields
// before "finished" are filled while the exchange runs, the others by
// finish, which hands the exchange to the sanitizer workers.
type exchange struct {
	a   *Agent
	cap sourceclient.Capture
	dir sanitizer.Direction
	by  sanitizer.SampledBy

	limit int
	start time.Time

	method      string
	rawPath     []byte
	rawQuery    []byte // nil when the URL has no '?'
	urlBase     string // outbound only
	reqCL       int64
	reqHeaders  []sanitizer.Header
	framework   string
	route       string
	sampleTrace string // trace id read from the context, "" if none
	inherited   *bool

	traceID, spanID, parentID string

	reqBuf  *capBuf
	reqTee  *teeReader
	respBuf *capBuf
	respTee *teeReader // outbound only
	pre     time.Duration

	// Response side.
	mu           sync.Mutex // protects the fields below while the handler runs
	started      bool
	status       int
	respHeaders  []sanitizer.Header
	netErr       string
	respDecoded  bool
	respNeedsEOF bool  // outbound: the body counts as consumed only at EOF ...
	respCL       int64 // ... or when this many bytes were read (-1: unknown)
	sniff        bool  // inbound: the server adds a sniffed Content-Type

	finished atomic.Bool

	// Filled by finish.
	reqBody, respBody         []byte
	reqTotal, respTotal       int64
	reqConsumed, respConsumed bool
	latency                   time.Duration
	bytes                     int64
}

// responseStarted records the status and a copy of the response headers, once.
func (x *exchange) responseStarted(status int, h func() []sanitizer.Header) {
	x.mu.Lock()
	if !x.started {
		x.started = true
		x.status = status
		x.respHeaders = h()
	}
	x.mu.Unlock()
}

// finish ends the exchange exactly once: it hands the copied bodies to the
// sanitizer workers, or drops them when the pipeline is overloaded. It never
// blocks.
func (x *exchange) finish() {
	if !x.finished.CompareAndSwap(false, true) {
		return
	}
	a := x.a
	defer a.inflight.Add(-1)
	t0 := time.Now()
	x.mu.Lock()
	noResponse := x.status == 0 && x.netErr == ""
	x.mu.Unlock()
	if noResponse {
		return // no response and no transport error: nothing to describe
	}
	x.latency = t0.Sub(x.start)
	x.reqConsumed, x.respConsumed = true, true
	var spent int64
	if x.reqBuf != nil {
		b, n, eof := x.reqBuf.snapshot()
		x.reqBody, x.reqTotal = b, n
		x.reqConsumed = eof || (x.reqCL >= 0 && n == x.reqCL)
		if x.reqTee != nil {
			spent += x.reqTee.spent.Load()
		}
	}
	if x.respBuf != nil {
		b, n, eof := x.respBuf.snapshot()
		x.respBody, x.respTotal = b, n
		if x.respNeedsEOF {
			x.respConsumed = eof || (x.respCL >= 0 && n == x.respCL)
		}
		if x.respTee != nil {
			spent += x.respTee.spent.Load()
		}
	}
	x.bytes = int64(len(x.reqBody) + len(x.respBody))
	a.submit(x)
	a.observe(x.pre + time.Duration(spent) + time.Since(t0))
}

// abandon drops the exchange without an event (hijacked or upgraded
// connection, panic in the handler).
func (x *exchange) abandon() {
	if x.finished.CompareAndSwap(false, true) {
		x.a.inflight.Add(-1)
	}
}
