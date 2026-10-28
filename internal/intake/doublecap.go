package intake

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Double capture: an application instrumented with an SDK calls a service
// through tt-egress. The SDK records the hop to the proxy and tt-egress
// records the call it forwards, so the same outbound call is captured twice
// (the SDK's hop shows up as a host:<proxy> or host:unlisted service). It is
// a warning, not a filter: both events are stored. v1 rule: use either the
// SDK or tt-egress for a given outbound call.
//
// SDKs never inject a traceparent into their outbound requests, and tt-egress
// only reads one, so the two events usually do not share a trace. Three
// signals are used, from the most to the least specific:
//
//  1. Span link: an outbound egress event whose parent span is the span of an
//     outbound SDK event of the same trace (when the application does
//     propagate a trace context).
//  2. Host: an outbound event of an SDK whose target is the host of a known
//     tt-egress source (the fleet knows where its egress sources run; see
//     SetEgressHosts). One such event is enough.
//  3. Time and shape: an outbound event of an SDK and an outbound event of
//     tt-egress, same HTTP method, same status, the egress call inside the
//     SDK call (within doubleCaptureSkew) and, if the SDK event names a
//     service (the policy lists the proxy address under the carrier's name),
//     the same service. A single coincidence proves nothing, so a pair of
//     sources is flagged after doubleCapturePairs matches.

const (
	doubleCaptureTTL      = 2 * time.Minute
	doubleCaptureMaxSpans = 50000
	doubleCaptureShowFor  = time.Hour

	// doubleCaptureSkew is how far apart (clock skew, buffering) the start of
	// the egress call may be from the SDK call that wraps it.
	doubleCaptureSkew = 2 * time.Second
	// doubleCapturePairs matches of one (SDK source, egress source) pair
	// within doubleCapturePairTTL raise the warning.
	doubleCapturePairs   = 3
	doubleCapturePairTTL = 10 * time.Minute
	// doubleCaptureKeep bounds the recent events kept per method and status,
	// and how long they wait for their counterpart (arrival time).
	doubleCaptureKeep    = 256
	doubleCaptureKeepFor = 30 * time.Second
	doubleCaptureHostTTL = 10 * time.Second
)

type spanKey struct{ trace, span string }

type shapeKey struct {
	method string
	status int
}

type doubleCapture struct {
	mu      sync.Mutex
	sdk     map[spanKey]capSeen // SDK outbound spans
	egress  map[spanKey]capSeen // egress outbound spans, by parent span
	flagged map[string]int64    // source id -> unix ms of the last double capture
	total   uint64
	swept   time.Time

	// Time and shape matching.
	recentSDK  map[shapeKey][]shapeSeen
	recentEgr  map[shapeKey][]shapeSeen
	pairs      map[[2]string]*pairCount
	shapeTotal int

	// Known egress hosts (host or host:port -> egress source ids).
	hostsFn    atomic.Pointer[func() map[string][]string]
	hosts      map[string][]string
	hostsAt    time.Time
	hostsFlagN uint64
}

type capSeen struct {
	source string
	at     time.Time
}

type shapeSeen struct {
	source     string
	service    string
	start, end time.Time
	arrived    time.Time
}

type pairCount struct {
	n     int
	since time.Time
}

func newDoubleCapture() *doubleCapture {
	return &doubleCapture{sdk: map[spanKey]capSeen{}, egress: map[spanKey]capSeen{}, flagged: map[string]int64{},
		recentSDK: map[shapeKey][]shapeSeen{}, recentEgr: map[shapeKey][]shapeSeen{}, pairs: map[[2]string]*pairCount{}}
}

// methodOf returns the HTTP method of an operation ("POST /orders" -> "POST").
func methodOf(op string) string {
	m, _, _ := strings.Cut(op, " ")
	for i := 0; i < len(m); i++ {
		if m[i] < 'A' || m[i] > 'Z' {
			return ""
		}
	}
	return m
}

// observe looks at one accepted event.
func (d *doubleCapture) observe(ev *event.Event, now time.Time) {
	if ev.Dir != event.Outbound {
		return
	}
	isSDK := strings.HasPrefix(ev.Source.Kind, "sdk-")
	isEgress := ev.Source.Kind == "egress"
	if !isSDK && !isEgress {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.sdk)+len(d.egress)+d.shapeTotal > doubleCaptureMaxSpans || now.Sub(d.swept) > doubleCaptureTTL {
		d.sweepLocked(now)
	}
	if ev.TraceID != "" && !((isSDK && ev.SpanID == "") || (isEgress && ev.ParentSpanID == "")) {
		if d.observeSpansLocked(ev, isSDK, now) {
			return
		}
	}
	if isSDK {
		d.observeHostLocked(ev, now)
	}
	d.observeShapeLocked(ev, isSDK, now)
}

// observeSpansLocked is signal 1; it reports whether the event completed a
// pair (and so needs no further look).
func (d *doubleCapture) observeSpansLocked(ev *event.Event, isSDK bool, now time.Time) bool {
	if isSDK {
		k := spanKey{ev.TraceID, ev.SpanID}
		if e, ok := d.egress[k]; ok {
			d.flagLocked(ev.Source.ID, e.source, now)
			delete(d.egress, k)
			return true
		}
		d.sdk[k] = capSeen{ev.Source.ID, now}
		return false
	}
	k := spanKey{ev.TraceID, ev.ParentSpanID}
	if s, ok := d.sdk[k]; ok {
		d.flagLocked(s.source, ev.Source.ID, now)
		delete(d.sdk, k)
		return true
	}
	d.egress[k] = capSeen{ev.Source.ID, now}
	return false
}

// observeHostLocked is signal 2: the target of an SDK call is the host of a
// known tt-egress source.
func (d *doubleCapture) observeHostLocked(ev *event.Event, now time.Time) {
	h, ok := strings.CutPrefix(ev.Service, "host:")
	if !ok || h == "unlisted" || h == "invalid" {
		return
	}
	fn := d.hostsFn.Load()
	if fn == nil {
		return
	}
	if d.hosts == nil || now.Sub(d.hostsAt) > doubleCaptureHostTTL {
		d.hosts, d.hostsAt = (*fn)(), now
	}
	ids, ok := d.hosts[h]
	if !ok {
		host := h
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			host = h[:i]
		}
		ids, ok = d.hosts[host]
	}
	if !ok {
		return
	}
	d.hostsFlagN++
	d.flagLocked(ev.Source.ID, ev.Source.ID, now)
	for _, id := range ids {
		d.flagged[id] = now.UnixMilli()
	}
}

// observeShapeLocked is signal 3.
func (d *doubleCapture) observeShapeLocked(ev *event.Event, isSDK bool, now time.Time) {
	m := methodOf(ev.Op)
	if m == "" || ev.Status == 0 || ev.Time.IsZero() {
		return
	}
	k := shapeKey{m, ev.Status}
	me := shapeSeen{source: ev.Source.ID, service: ev.Service, start: ev.Time, end: ev.Time.Add(time.Duration(ev.LatencyMS) * time.Millisecond), arrived: now}
	mine, other := d.recentSDK, d.recentEgr
	if !isSDK {
		mine, other = d.recentEgr, d.recentSDK
	}
	// Look for the counterpart: the candidate that started closest.
	list := other[k]
	best, bestGap := -1, time.Duration(0)
	for i := len(list) - 1; i >= 0; i-- {
		o := list[i]
		sdk, egr := me, o
		if !isSDK {
			sdk, egr = o, me
		}
		if !wraps(sdk, egr) {
			continue
		}
		// A service named by the SDK event must be the one the egress
		// forwards to; a host:* hop has no service to compare.
		if !strings.HasPrefix(sdk.service, "host:") && sdk.service != egr.service {
			continue
		}
		gap := egr.start.Sub(sdk.start)
		if gap < 0 {
			gap = -gap
		}
		if best < 0 || gap < bestGap {
			best, bestGap = i, gap
		}
	}
	if best >= 0 {
		o := list[best]
		sdkSrc, egrSrc := me.source, o.source
		if !isSDK {
			sdkSrc, egrSrc = o.source, me.source
		}
		list = append(list[:best], list[best+1:]...)
		d.shapeTotal--
		if len(list) == 0 {
			delete(other, k)
		} else {
			other[k] = list
		}
		d.pairLocked(sdkSrc, egrSrc, now)
		return
	}
	l := mine[k]
	if len(l) >= doubleCaptureKeep {
		l = l[1:]
		d.shapeTotal--
	}
	mine[k] = append(l, me)
	d.shapeTotal++
}

// wraps reports whether the egress call lies inside the SDK call, give or
// take the clock skew.
func wraps(sdk, egr shapeSeen) bool {
	return !egr.start.Before(sdk.start.Add(-doubleCaptureSkew)) && !egr.start.After(sdk.end.Add(doubleCaptureSkew)) &&
		!egr.end.After(sdk.end.Add(doubleCaptureSkew))
}

func (d *doubleCapture) pairLocked(sdkSrc, egrSrc string, now time.Time) {
	k := [2]string{sdkSrc, egrSrc}
	p := d.pairs[k]
	if p == nil || now.Sub(p.since) > doubleCapturePairTTL {
		p = &pairCount{since: now}
		d.pairs[k] = p
	}
	p.n++
	if p.n >= doubleCapturePairs {
		d.flagLocked(sdkSrc, egrSrc, now)
	}
}

func (d *doubleCapture) flagLocked(a, b string, now time.Time) {
	d.total++
	ms := now.UnixMilli()
	d.flagged[a], d.flagged[b] = ms, ms
}

func (d *doubleCapture) sweepLocked(now time.Time) {
	d.swept = now
	for k, v := range d.sdk {
		if now.Sub(v.at) > doubleCaptureTTL {
			delete(d.sdk, k)
		}
	}
	for k, v := range d.egress {
		if now.Sub(v.at) > doubleCaptureTTL {
			delete(d.egress, k)
		}
	}
	if len(d.sdk)+len(d.egress) > doubleCaptureMaxSpans {
		clear(d.sdk)
		clear(d.egress)
	}
	d.shapeTotal = 0
	for _, m := range []map[shapeKey][]shapeSeen{d.recentSDK, d.recentEgr} {
		for k, l := range m {
			keep := l[:0]
			for _, s := range l {
				if now.Sub(s.arrived) <= doubleCaptureKeepFor {
					keep = append(keep, s)
				}
			}
			if len(keep) == 0 {
				delete(m, k)
				continue
			}
			m[k] = keep
			d.shapeTotal += len(keep)
		}
	}
	for k, p := range d.pairs {
		if now.Sub(p.since) > doubleCapturePairTTL {
			delete(d.pairs, k)
		}
	}
	for id, ms := range d.flagged {
		if now.UnixMilli()-ms > 2*doubleCaptureShowFor.Milliseconds() {
			delete(d.flagged, id)
		}
	}
}

func (d *doubleCapture) recent(id string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ms, ok := d.flagged[id]
	return ok && now.UnixMilli()-ms <= doubleCaptureShowFor.Milliseconds()
}

// SetEgressHosts tells the intake where the tt-egress sources run: fn returns
// the hosts (host or host:port, lower case) the applications reach them at,
// mapped to the source ids. The fleet provides it from the enrolled egress
// sources. An SDK event whose target host is one of them raises the
// double_capture warning of the SDK source and of those egress sources.
func (in *Intake) SetEgressHosts(fn func() map[string][]string) {
	if fn == nil {
		in.dup.hostsFn.Store(nil)
		return
	}
	in.dup.hostsFn.Store(&fn)
}

// DoubleCaptured reports whether, within the last hour, an outbound call of
// this source was also captured by a source of the other kind (an SDK and
// tt-egress on the same call). Fleet shows it as a warning on the source.
func (in *Intake) DoubleCaptured(sourceID string) bool {
	return in.dup.recent(sourceID, in.now())
}

// DoubleCaptures counts the double captures detected since start.
func (in *Intake) DoubleCaptures() uint64 {
	in.dup.mu.Lock()
	defer in.dup.mu.Unlock()
	return in.dup.total
}
