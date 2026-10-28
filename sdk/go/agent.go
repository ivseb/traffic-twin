package ttsdk

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
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

// source is what the SDK needs from the Fleet source. *sourceclient.Source
// implements it; the tests use a fake to drive the conformance vectors
// through the real capture path.
type source interface {
	Start(ctx context.Context)
	Close(ctx context.Context) error
	Active() (sourceclient.Capture, bool)
	Emit(ev sourceclient.Event)
	Counters() *sourceclient.Counters
	ObserveOverhead(d time.Duration)
	RecordError(code string)
	Stats() sourceclient.Stats
}

// Stats is a point-in-time view of the agent, for health endpoints and logs.
type Stats struct {
	// State is starting, capturing, killed, no_policy, ... (the heartbeat
	// states of the Fleet API); "disabled" for an inert agent.
	State            string
	ExchangesSeen    int64
	ExchangesSampled int64
	EventsSent       int64
	EventsDropped    int64 // dropped because a queue was full
	EventsRejected   int64 // refused by tt-core
	SendErrors       int64
	SanitizerErrors  int64
	QueueEvents      int
	OverheadP50us    int64 // microseconds the SDK spent on the request path
	OverheadP99us    int64
}

// Agent is the SDK runtime: the Fleet source (enrollment, policy, heartbeat,
// export) and the bounded pipeline that sanitizes exchanges off the request
// path. It is safe for concurrent use.
type Agent struct {
	cfg Config
	src source // nil: inert
	log *slog.Logger
	now func() time.Time

	jobs     chan *exchange
	done     chan struct{}
	wg       sync.WaitGroup
	closed   atomic.Bool
	pending  atomic.Int64
	inflight atomic.Int64

	nullCounters sourceclient.Counters
	prop         atomic.Pointer[propEntry]
	start        time.Time
}

var (
	defOnce sync.Once
	def     *Agent
	defTC   TraceContextFunc
)

// SetDefaultTraceContext makes the default agent read the active span of a
// context with f (for example otelctx.FromContext). Call it before the first
// use of Default, Handler or Transport; later calls have no effect.
func SetDefaultTraceContext(f TraceContextFunc) { defTC = f }

// Default returns the process-wide agent, built on first use from the
// environment (ConfigFromEnv). It never returns nil: if the environment does
// not enable the SDK, or is invalid, the agent is inert.
func Default() *Agent {
	defOnce.Do(func() {
		cfg := ConfigFromEnv()
		cfg.TraceContext = defTC
		a, err := New(cfg)
		if err != nil {
			// A configuration that was meant to enable the SDK but is wrong:
			// say so once, with the error class only, and carry on without it.
			fmt.Fprintf(os.Stderr, "traffic-twin: SDK disabled: %v\n", err)
			a, _ = New(Config{Disabled: true})
		}
		def = a
	})
	return def
}

// Shutdown flushes and stops the default agent (if it was ever started).
func Shutdown(ctx context.Context) error {
	if def == nil {
		return nil
	}
	return def.Close(ctx)
}

// Handler wraps next with the default agent. See (*Agent).Handler.
func Handler(next http.Handler) http.Handler { return Default().Handler(next) }

// Transport wraps base with the default agent. See (*Agent).Transport.
func Transport(base http.RoundTripper) http.RoundTripper { return Default().Transport(base) }

// New builds an agent and starts its background work (enrollment, heartbeat,
// policy polling, sanitizer workers, export). It returns immediately: the
// application never waits for tt-core. A config without EnrollURL, or with
// Disabled, gives an inert agent (no goroutines, Handler and Transport are
// pass-through). An error means the configuration is unusable; callers that
// want to carry on can use an inert agent.
func New(cfg Config) (*Agent, error) {
	a := newAgent(cfg)
	if cfg.Disabled || cfg.EnrollURL == "" {
		if cfg.EnrollToken != "" && cfg.EnrollURL == "" && !cfg.Disabled {
			return nil, fmt.Errorf("%s is set but %s is not", EnvEnrollToken, EnvEnrollURL)
		}
		return a, nil
	}
	if cfg.ServiceName == "" {
		return nil, fmt.Errorf("service name required to enroll (%s or %s)", EnvServiceName, EnvOTelServiceName)
	}
	keys, kids, kerr := loadKeys(cfg)
	if kerr != nil {
		// Not fatal: the SDK runs, the application too, nothing is captured
		// until a valid key is configured (key_missing).
		a.log.Warn("no usable HMAC key: nothing will be captured", "error", kerr.Error())
	}
	inst := cfg.Instance
	if inst == "" {
		inst, _ = os.Hostname()
	}
	eo := sourceclient.ExporterOptions{FlushInterval: cfg.ExportFlushEvery}
	src, err := sourceclient.New(sourceclient.Config{
		EnrollURL: cfg.EnrollURL, Token: cfg.EnrollToken, StateDir: cfg.StateDir,
		Kind: Kind, Version: Version, ServiceName: cfg.ServiceName, Instance: inst,
		Keys: keys, KeyKids: kids, Logger: a.log,
		HeartbeatInterval: cfg.HeartbeatInterval, PolicyPollInterval: cfg.PolicyPollInterval,
		Exporter: eo,
	})
	if err != nil {
		return nil, err
	}
	a.attach(src)
	return a, nil
}

func newAgent(cfg Config) *Agent {
	if cfg.Workers <= 0 {
		cfg.Workers = min(4, runtime.GOMAXPROCS(0))
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.MaxPendingBytes <= 0 {
		cfg.MaxPendingBytes = 64 << 20
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 512
	}
	lg := cfg.Logger
	if lg == nil {
		if cfg.Debug {
			lg = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		} else {
			lg = slog.New(slog.DiscardHandler)
		}
	}
	return &Agent{cfg: cfg, log: lg, now: time.Now, start: time.Now(),
		jobs: make(chan *exchange, cfg.QueueSize), done: make(chan struct{})}
}

// attach connects the source and starts the control loop and the workers.
func (a *Agent) attach(src source) {
	a.src = src
	src.Start(context.Background())
	for i := 0; i < a.cfg.Workers; i++ {
		a.wg.Add(1)
		go a.worker()
	}
}

// loadKeys reads the HMAC keys from the config or the environment. The kids
// (never the secrets) are also returned for the enrollment request.
func loadKeys(cfg Config) (sanitizer.KeySet, []string, error) {
	text := cfg.HMACKeys
	if text == "" {
		text = os.Getenv(EnvHMACKey)
	}
	if text == "" {
		f := cfg.HMACKeyFile
		if f == "" {
			f = os.Getenv(EnvHMACKeyFile)
		}
		if f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return sanitizer.KeySet{}, nil, sanitizer.ErrKeyMissing
			}
			text = string(b)
		}
	}
	ks, err := sanitizer.ParseKeys(text)
	if err != nil {
		return sanitizer.KeySet{}, nil, err
	}
	var kids []string
	for _, line := range strings.Split(text, "\n") {
		if kid, _, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ":"); ok && kid != "" {
			kids = append(kids, kid)
		}
	}
	return ks, kids, nil
}

// Enabled reports whether the agent is a live one (not inert).
func (a *Agent) Enabled() bool { return a != nil && a.src != nil }

// Capturing reports whether the agent would capture right now: it has a
// valid policy, key and heartbeat and the kill switch is off.
func (a *Agent) Capturing() bool {
	if !a.Enabled() {
		return false
	}
	_, ok := a.src.Active()
	return ok
}

// Stats returns a snapshot of the agent counters.
func (a *Agent) Stats() Stats {
	if !a.Enabled() {
		return Stats{State: "disabled"}
	}
	s := a.src.Stats()
	return Stats{State: s.State,
		ExchangesSeen: s.Counters.ExchangesSeen, ExchangesSampled: s.Counters.ExchangesSampled,
		EventsSent: s.Counters.EventsSent, EventsDropped: s.Counters.EventsDroppedQueue,
		EventsRejected: s.Counters.EventsRejected, SendErrors: s.Counters.SendErrors,
		SanitizerErrors: s.Counters.SanitizerErrors, QueueEvents: s.QueueEvents,
		OverheadP50us: s.OverheadP50, OverheadP99us: s.OverheadP99}
}

// Close stops capturing, lets the workers drain what is queued, flushes the
// export queue until ctx ends and persists the local state. It does not
// stop the application's HTTP servers or clients.
func (a *Agent) Close(ctx context.Context) error {
	if !a.Enabled() || !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(a.done)
	ch := make(chan struct{})
	go func() { a.wg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-ctx.Done():
	}
	return a.src.Close(ctx)
}

func (a *Agent) counters() *sourceclient.Counters {
	if a.src == nil {
		return &a.nullCounters
	}
	return a.src.Counters()
}

func (a *Agent) observe(d time.Duration) {
	if a.src != nil {
		a.src.ObserveOverhead(d)
	}
}

// submit queues a finished exchange for a worker, or drops it: traffic is
// never held back by tt.
func (a *Agent) submit(x *exchange) {
	c := a.counters()
	if a.closed.Load() || a.pending.Add(x.bytes) > a.cfg.MaxPendingBytes {
		a.pending.Add(-x.bytes)
		c.EventsDroppedQueue.Add(1)
		return
	}
	select {
	case a.jobs <- x:
	default:
		a.pending.Add(-x.bytes)
		c.EventsDroppedQueue.Add(1)
	}
}

func (a *Agent) worker() {
	defer a.wg.Done()
	for {
		select {
		case x := <-a.jobs:
			a.process(x)
		case <-a.done:
			for {
				select {
				case x := <-a.jobs:
					a.process(x)
				default:
					return
				}
			}
		}
	}
}

// process sanitizes one exchange and queues the event. Any failure (error or
// panic) means: no event, and sanitizer_errors is incremented.
func (a *Agent) process(x *exchange) {
	defer a.pending.Add(-x.bytes)
	c := a.counters()
	defer func() {
		if r := recover(); r != nil {
			c.SanitizerErrors.Add(1)
			a.src.RecordError("sanitizer_panic")
		}
	}()
	respHeaders := x.respHeaders
	if x.sniff {
		if ct := sniffedType(x.status, x.method, respHeaders, x.respBody); ct != "" {
			respHeaders = append(respHeaders[:len(respHeaders):len(respHeaders)], sanitizer.Header{Name: "Content-Type", Value: []byte(ct)})
		}
	}
	ex := &sanitizer.Exchange{
		Dir: x.dir, URLBase: x.urlBase, Method: x.method, RawPath: x.rawPath, RawQuery: x.rawQuery,
		FrameworkRoute: x.route, Framework: x.framework, TraceID: x.sampleTrace, Inherited: x.inherited,
		ReqHeaders: x.reqHeaders, ReqBody: x.reqBody, ReqBodyTotal: x.reqTotal, ReqBodyNotConsumed: !x.reqConsumed,
		Status: x.status, NetError: x.netErr,
		RespHeaders: respHeaders, RespBody: x.respBody, RespBodyTotal: x.respTotal, RespBodyNotConsumed: !x.respConsumed,
		RespBodyDecoded: x.respDecoded,
	}
	if x.dir == sanitizer.Inbound {
		ex.ServiceName = x.cap.ServiceName
	}
	out, err := x.cap.Engine.Sanitize(ex, a.now(), x.by)
	if err != nil {
		c.SanitizerErrors.Add(1)
		a.src.RecordError("sanitizer_error")
		return
	}
	meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{
		SourceKind: x.cap.Kind, SourceVersion: x.cap.Version, SourceID: x.cap.SourceID,
		TS: x.start, LatencyMS: x.latency.Milliseconds(), Status: x.status, NetError: x.netErr,
		TraceID: x.traceID, SpanID: x.spanID, ParentSpanID: x.parentID,
	}, x.cap.Policy)
	ev, err := sanitizer.BuildEvent(meta, out)
	if err != nil {
		c.SanitizerErrors.Add(1)
		a.src.RecordError("event_build_error")
		return
	}
	a.src.Emit(sourceclient.Event{JSON: ev, TS: x.start, TraceID: x.traceID, SpanID: x.spanID, PolicyHash: x.cap.Policy.Hash})
}

// ---- propagation of the sampling decision (docs/spec/sanitizer.md section 12) ----

type propEntry struct {
	v         *policy.Verified
	propagate map[string]bool // lower-case host or host:port of sampling.propagate_to
	bases     map[string]bool // hosts of the external services of the policy
}

func (a *Agent) propFor(v *policy.Verified) *propEntry {
	if e := a.prop.Load(); e != nil && e.v == v {
		return e
	}
	e := &propEntry{v: v, propagate: map[string]bool{}, bases: map[string]bool{}}
	for _, h := range v.Policy.Sampling.PropagateTo {
		e.propagate[strings.ToLower(h)] = true
	}
	for i := range v.Policy.Services {
		if b := v.Policy.Services[i].Match.Base; b != "" {
			if pb, ok := policy.ParseBase(b); ok {
				e.bases[pb.Host] = true
				e.bases[pb.HostPort()] = true
			}
		}
	}
	a.prop.Store(e)
	return e
}

// mayPropagate reports whether tt.s can be added to a call to scheme://host:
// the host is listed in sampling.propagate_to and never matches the base of
// an external service of the policy (D-M8).
func (a *Agent) mayPropagate(cp sourceclient.Capture, scheme, hostport string) bool {
	if len(cp.Policy.Policy.Sampling.PropagateTo) == 0 {
		return false
	}
	hostport = strings.ToLower(hostport)
	host := hostport
	if h, _, ok := strings.Cut(hostport, ":"); ok && !strings.HasPrefix(hostport, "[") {
		host = h
	}
	if (scheme == "http" && strings.HasSuffix(hostport, ":80")) || (scheme == "https" && strings.HasSuffix(hostport, ":443")) {
		hostport = host
	}
	e := a.propFor(cp.Policy)
	if e.bases[hostport] || e.bases[host] {
		return false
	}
	return e.propagate[hostport] || e.propagate[host]
}
