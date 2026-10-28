package obi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// Sink is what the bridge needs from the Fleet source. *sourceclient.Source
// implements it; tests use a fake.
type Sink interface {
	Active() (sourceclient.Capture, bool)
	Emit(sourceclient.Event)
	Counters() *sourceclient.Counters
	RecordError(code string)
	ObserveOverhead(time.Duration)
}

// BridgeConfig configures a Bridge.
type BridgeConfig struct {
	Sink Sink
	// ServiceFilter, when set, drops the spans whose resource service.name
	// differs: one bridge is enrolled as one service, so spans of other
	// services that OBI instruments on the same host must not be mapped to
	// it. Empty: accept every service.
	ServiceFilter string
	// CaptureLimit is the OBI HTTP buffer size (ebpf.buffer_sizes.http).
	CaptureLimit int64

	Workers         int   // sanitizer workers (default min(4, GOMAXPROCS))
	QueueSize       int   // spans waiting for a worker (default 2048)
	MaxPendingBytes int64 // captured body bytes waiting (default 64 MiB)
	MaxRequestBytes int64 // OTLP request bound, compressed and decompressed (default 32 MiB)

	Logger *slog.Logger
	Now    func() time.Time
	// Rand is the random sampling source ([0, 10000)); nil: math/rand.
	Rand func() int
	// OnSanitize is a test hook called by a worker before it sanitizes.
	OnSanitize func()
}

// Bridge receives OBI's OTLP/JSON traces and turns the HTTP spans into
// tt.http.exchange events.
type Bridge struct {
	cfg  BridgeConfig
	log  *slog.Logger
	jobs chan *job
	done chan struct{}
	wg   sync.WaitGroup

	pending atomic.Int64
	closed  atomic.Bool

	spans    atomic.Int64 // HTTP spans accepted from OBI
	notHTTP  atomic.Int64
	filtered atomic.Int64 // spans of other services
	badBatch atomic.Int64
	warnOnce sync.Once
	started  time.Time
}

type job struct {
	span  Span
	bytes int64
}

// NewBridge starts the sanitizer workers.
func NewBridge(cfg BridgeConfig) *Bridge {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 2048
	}
	if cfg.MaxPendingBytes <= 0 {
		cfg.MaxPendingBytes = 64 << 20
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 32 << 20
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	b := &Bridge{cfg: cfg, log: cfg.Logger, jobs: make(chan *job, cfg.QueueSize), done: make(chan struct{}), started: cfg.Now()}
	for i := 0; i < cfg.Workers; i++ {
		b.wg.Add(1)
		go b.worker()
	}
	return b
}

// Close stops accepting spans and waits for the queued ones.
func (b *Bridge) Close() {
	if b.closed.Swap(true) {
		return
	}
	close(b.done)
	b.wg.Wait()
}

// Handler returns the HTTP handler of the receiver: POST /v1/traces
// (OTLP/HTTP, JSON) and GET /healthz.
func (b *Bridge) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/traces", b.handleTraces)
	mux.HandleFunc("GET /healthz", b.handleHealth)
	return mux
}

func (b *Bridge) handleTraces(w http.ResponseWriter, r *http.Request) {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if ct != "application/json" {
		// Protobuf is not decoded here: OBI must export JSON
		// (protocol: http/json; see internal/obi/README.md).
		b.log.Warn("otlp request rejected: content-type is not application/json; set the OBI traces protocol to http/json", "content_type", ct)
		http.Error(w, "unsupported media type: OBI must export traces as OTLP/JSON (protocol http/json)", http.StatusUnsupportedMediaType)
		return
	}
	// Not capturing (no policy, kill switch, missing key): do not even parse
	// what OBI sends.
	if _, ok := b.cfg.Sink.Active(); !ok {
		writeOK(w)
		return
	}
	gz := strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip")
	r.Body = http.MaxBytesReader(w, r.Body, b.cfg.MaxRequestBytes)
	rs, err := ParseExport(r.Body, gz, b.cfg.MaxRequestBytes)
	if err != nil {
		b.badBatch.Add(1)
		b.log.Warn("otlp request rejected", "error", err.Error())
		status := http.StatusBadRequest
		if err == ErrTooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "bad request", status)
		return
	}
	b.Submit(rs)
	writeOK(w)
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

// Submit queues the HTTP spans of a decoded export. It never blocks: when the
// queue or the byte bound is full the span is dropped and counted.
func (b *Bridge) Submit(rs []ResourceSpans) {
	c := b.cfg.Sink.Counters()
	for i := range rs {
		if f := b.cfg.ServiceFilter; f != "" && rs[i].ServiceName() != f {
			b.filtered.Add(1)
			b.warnOnce.Do(func() {
				b.log.Warn("spans of another service are being dropped: OBI names services in resource service.name and only the enrolled one is captured; "+
					"use the generated OBI configuration (discovery name) or --service-filter",
					"expected", f, "got", clip(rs[i].ServiceName(), 64))
			})
			continue
		}
		for _, ss := range rs[i].ScopeSpans {
			for k := range ss.Spans {
				sp := &ss.Spans[k]
				if !IsHTTP(sp) {
					b.notHTTP.Add(1)
					continue
				}
				b.spans.Add(1)
				c.ExchangesSeen.Add(1)
				j := &job{span: *sp, bytes: approxBytes(sp)}
				if b.closed.Load() || b.pending.Add(j.bytes) > b.cfg.MaxPendingBytes {
					b.pending.Add(-j.bytes)
					c.EventsDroppedQueue.Add(1)
					continue
				}
				select {
				case b.jobs <- j:
				default:
					b.pending.Add(-j.bytes)
					c.EventsDroppedQueue.Add(1)
				}
			}
		}
	}
}

// approxBytes is the memory a queued span holds that grows with the payload.
func approxBytes(sp *Span) int64 {
	n := int64(256)
	for i := range sp.Attributes {
		n += int64(len(sp.Attributes[i].Key)) + 32
		if s := sp.Attributes[i].Value.StringValue; s != nil {
			n += int64(len(*s))
		}
	}
	return n
}

func (b *Bridge) worker() {
	defer b.wg.Done()
	for {
		select {
		case j := <-b.jobs:
			b.process(j)
		case <-b.done:
			for {
				select {
				case j := <-b.jobs:
					b.process(j)
				default:
					return
				}
			}
		}
	}
}

// process maps, samples and sanitizes one span. Any failure (error or panic)
// means: no event, and sanitizer_errors is incremented.
func (b *Bridge) process(j *job) {
	defer b.pending.Add(-j.bytes)
	sink := b.cfg.Sink
	c := sink.Counters()
	defer func() {
		if r := recover(); r != nil {
			c.SanitizerErrors.Add(1)
			sink.RecordError("sanitizer_panic")
		}
	}()
	if b.cfg.OnSanitize != nil {
		b.cfg.OnSanitize()
	}
	t0 := b.cfg.Now()
	cp, ok := sink.Active()
	if !ok {
		return
	}
	m, ok := Map(&j.span, MapOptions{ServiceName: cp.ServiceName, CaptureLimit: b.cfg.CaptureLimit})
	if !ok {
		return
	}
	ev, sampled, err := Exchange(cp, m, b.cfg.Now(), b.cfg.Rand)
	if err != nil {
		c.SanitizerErrors.Add(1)
		sink.RecordError("sanitizer_error")
		return
	}
	if !sampled {
		return
	}
	c.ExchangesSampled.Add(1)
	sink.Emit(sourceclient.Event{JSON: ev, TS: m.Start, TraceID: m.TraceID, SpanID: m.SpanID, PolicyHash: cp.Policy.Hash})
	sink.ObserveOverhead(b.cfg.Now().Sub(t0))
}

// Exchange runs sampling and the sanitizer on a mapped span and returns the
// canonical event bytes. sampled is false (and ev nil) when the exchange is
// not sampled. It is the whole "second filter" and the only way a span turns
// into something that can leave the process.
func Exchange(cp sourceclient.Capture, m *Mapped, now time.Time, rnd func() int) (ev []byte, sampled bool, err error) {
	ex := &m.Exchange
	d := cp.Engine.Sample(ex, sanitizer.SampleOptions{RateBP: cp.OverrideBP, Rand: rnd})
	if !d.Sampled {
		return nil, false, nil
	}
	out, err := cp.Engine.Sanitize(ex, now, d.By)
	if err != nil {
		return nil, true, err
	}
	meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{
		SourceKind: cp.Kind, SourceVersion: cp.Version, SourceID: cp.SourceID,
		TS: m.Start, LatencyMS: m.Latency.Milliseconds(), Status: ex.Status, NetError: ex.NetError,
		TraceID: m.TraceID, SpanID: m.SpanID, ParentSpanID: m.ParentID,
	}, cp.Policy)
	ev, err = sanitizer.BuildEvent(meta, out)
	if err != nil {
		return nil, true, err
	}
	return ev, true, nil
}

type healthBody struct {
	Status      string `json:"status"`
	Capture     string `json:"capture"`
	UptimeS     int64  `json:"uptime_s"`
	Spans       int64  `json:"http_spans"`
	NotHTTP     int64  `json:"ignored_spans"`
	Filtered    int64  `json:"other_service_spans"`
	BadRequests int64  `json:"bad_requests"`
	Seen        int64  `json:"exchanges_seen"`
	Sampled     int64  `json:"exchanges_sampled"`
	Sent        int64  `json:"events_sent"`
	Dropped     int64  `json:"events_dropped_queue"`
	SanErrors   int64  `json:"sanitizer_errors"`
}

// handleHealth reports counters only, never values.
func (b *Bridge) handleHealth(w http.ResponseWriter, _ *http.Request) {
	h := healthBody{Status: "ok", Capture: "disabled", UptimeS: int64(b.cfg.Now().Sub(b.started).Seconds()),
		Spans: b.spans.Load(), NotHTTP: b.notHTTP.Load(), Filtered: b.filtered.Load(), BadRequests: b.badBatch.Load()}
	if s, ok := b.cfg.Sink.(interface{ Stats() sourceclient.Stats }); ok {
		st := s.Stats()
		h.Capture = st.State
		h.Seen, h.Sampled, h.Sent = st.Counters.ExchangesSeen, st.Counters.ExchangesSampled, st.Counters.EventsSent
		h.Dropped, h.SanErrors = st.Counters.EventsDroppedQueue, st.Counters.SanitizerErrors
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
