package sourceclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Event is one canonical tt.http.exchange/v1 event ready to be exported.
type Event struct {
	JSON       []byte // canonical event bytes (docs/spec/event.md)
	TS         time.Time
	TraceID    string // 32 lower-case hex or ""
	SpanID     string // 16 lower-case hex or ""
	PolicyHash string
}

// ExporterOptions configure the OTLP/HTTP exporter. Zero values take the
// defaults of docs/spec/event.md section 4.
type ExporterOptions struct {
	// URL and Client are the intake endpoint (".../v1/logs") and an mTLS
	// client; both can be replaced later with SetTarget.
	URL    string
	Client *http.Client

	ServiceName   string
	SourceKind    string
	SourceVersion string
	SourceID      string

	MaxEvents     int           // queue bound, default 10000
	MaxBytes      int64         // queue bound, default 16 MiB
	BatchEvents   int           // default 512
	BatchBytes    int           // before compression, default 4 MiB
	FlushInterval time.Duration // default 1s
	MaxRetries    int           // default 5
	BaseBackoff   time.Duration // default 1s
	MaxBackoff    time.Duration // default 30s
	MaxRetryAfter time.Duration // cap for Retry-After, default 2 minutes
	GzipMinBytes  int           // compress bodies larger than this, default 1 KiB

	Counters *Counters
	// OnError receives stable error codes (never payload values).
	OnError func(code string)
	Now     func() time.Time
}

// Exporter sends events to tt-core as OTLP/HTTP JSON logs. The queue is
// bounded: when full the oldest events are dropped and counted, and nobody
// ever waits for the network.
type Exporter struct {
	o ExporterOptions

	mu     sync.Mutex
	queue  []Event
	head   int
	bytes  int64
	url    string
	client *http.Client
	gen    uint64 // bumped by Clear: batches of an older generation are discarded
	cancel context.CancelFunc

	sendMu sync.Mutex // one sender at a time (worker or Flush)
	wake   chan struct{}
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

// NewExporter builds the exporter and starts its worker.
func NewExporter(o ExporterOptions) *Exporter {
	if o.MaxEvents <= 0 {
		o.MaxEvents = 10000
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 16 << 20
	}
	if o.BatchEvents <= 0 || o.BatchEvents > 512 {
		o.BatchEvents = 512
	}
	if o.BatchBytes <= 0 || o.BatchBytes > 4<<20 {
		o.BatchBytes = 4 << 20
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = time.Second
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	} else if o.MaxRetries == 0 {
		o.MaxRetries = 5
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.MaxRetryAfter <= 0 {
		o.MaxRetryAfter = 2 * time.Minute
	}
	if o.GzipMinBytes <= 0 {
		o.GzipMinBytes = 1024
	}
	if o.Counters == nil {
		o.Counters = &Counters{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	e := &Exporter{o: o, url: o.URL, client: o.Client,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go e.run()
	return e
}

// SetTarget replaces the endpoint and client (certificate renewal).
func (e *Exporter) SetTarget(url string, c *http.Client) {
	e.mu.Lock()
	e.url, e.client = url, c
	e.mu.Unlock()
}

// Size returns the queued events and bytes.
func (e *Exporter) Size() (events int, bytes int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.queue) - e.head, e.bytes
}

// Enqueue adds an event; it never blocks. When the queue is over its bounds
// the oldest events are dropped and counted.
func (e *Exporter) Enqueue(ev Event) {
	if len(ev.JSON) == 0 {
		return
	}
	e.mu.Lock()
	e.queue = append(e.queue, ev)
	e.bytes += int64(len(ev.JSON))
	for len(e.queue)-e.head > e.o.MaxEvents || e.bytes > e.o.MaxBytes {
		old := e.queue[e.head]
		e.queue[e.head] = Event{}
		e.head++
		e.bytes -= int64(len(old.JSON))
		e.o.Counters.EventsDroppedQueue.Add(1)
	}
	if e.head > 1024 && e.head*2 > len(e.queue) {
		e.queue = append([]Event(nil), e.queue[e.head:]...)
		e.head = 0
	}
	full := len(e.queue)-e.head >= e.o.BatchEvents
	e.mu.Unlock()
	if full {
		select {
		case e.wake <- struct{}{}:
		default:
		}
	}
}

// Clear drops everything queued and abandons the batch being sent (kill
// switch, revocation). Dropped events are counted.
func (e *Exporter) Clear() {
	e.mu.Lock()
	n := len(e.queue) - e.head
	e.queue, e.head, e.bytes = nil, 0, 0
	e.gen++
	if e.cancel != nil {
		e.cancel()
	}
	e.mu.Unlock()
	e.o.Counters.EventsDroppedQueue.Add(int64(n))
}

// Close stops the worker, then makes one best-effort attempt to deliver what
// is left until ctx ends.
func (e *Exporter) Close(ctx context.Context) {
	e.once.Do(func() { close(e.stop) })
	select {
	case <-e.done:
	case <-ctx.Done():
		return
	}
	e.flush(ctx, false)
}

// Flush delivers the queue, with the normal retry policy, until it is empty,
// a batch is abandoned or ctx ends.
func (e *Exporter) Flush(ctx context.Context) { e.flush(ctx, true) }

func (e *Exporter) flush(ctx context.Context, retry bool) {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	for ctx.Err() == nil {
		batch, gen := e.take()
		if len(batch) == 0 {
			return
		}
		if !e.deliver(ctx, batch, gen, retry) {
			return
		}
	}
}

func (e *Exporter) run() {
	defer close(e.done)
	t := time.NewTicker(e.o.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-e.wake:
		case <-t.C:
		}
		e.sendMu.Lock()
		for {
			select {
			case <-e.stop:
				e.sendMu.Unlock()
				return
			default:
			}
			batch, gen := e.take()
			if len(batch) == 0 {
				break
			}
			if !e.deliver(context.Background(), batch, gen, true) {
				break
			}
		}
		e.sendMu.Unlock()
	}
}

// take removes the next batch from the queue.
func (e *Exporter) take() ([]Event, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	size := 0
	for e.head < len(e.queue) && len(out) < e.o.BatchEvents {
		ev := e.queue[e.head]
		// Escaping inside the OTLP string can at most double the event.
		est := 2*len(ev.JSON) + 1024
		if len(out) > 0 && size+est > e.o.BatchBytes {
			break
		}
		out = append(out, ev)
		size += est
		e.queue[e.head] = Event{}
		e.head++
		e.bytes -= int64(len(ev.JSON))
	}
	if e.head == len(e.queue) {
		e.queue, e.head = e.queue[:0], 0
	}
	return out, e.gen
}

func (e *Exporter) report(code string) {
	if e.o.OnError != nil {
		e.o.OnError(code)
	}
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// deliver sends one batch, retrying per event.md 4.4. It returns false when
// the batch was abandoned because of an outage (so the caller stops for now).
func (e *Exporter) deliver(ctx context.Context, batch []Event, gen uint64, retry bool) bool {
	body, err := e.otlpBody(batch)
	if err != nil {
		e.o.Counters.EventsRejected.Add(int64(len(batch)))
		e.report("export_encode")
		return true
	}
	c := e.o.Counters
	e.mu.Lock()
	if e.gen != gen {
		e.mu.Unlock()
		c.EventsDroppedQueue.Add(int64(len(batch)))
		return true
	}
	actx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		e.cancel = nil
		e.mu.Unlock()
	}()
	cleared := func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.gen != gen
	}
	for attempt := 0; ; attempt++ {
		e.mu.Lock()
		url, client := e.url, e.client
		e.mu.Unlock()

		status, retryAfter, rejected, err := e.post(actx, client, url, body)
		if cleared() {
			c.EventsDroppedQueue.Add(int64(len(batch)))
			return true
		}

		switch {
		case err == nil && status == http.StatusOK:
			if rejected > int64(len(batch)) {
				rejected = int64(len(batch))
			}
			c.EventsSent.Add(int64(len(batch)) - rejected)
			if rejected > 0 {
				c.EventsRejected.Add(rejected)
				e.report("export_partial_rejected")
			}
			return true
		case err == nil && !retryable(status):
			// 400, 401, 403, 413 and anything unexpected: drop without retry.
			c.EventsRejected.Add(int64(len(batch)))
			c.SendErrors.Add(1)
			e.report("export_http_" + strconv.Itoa(status))
			return true
		}
		// Retryable status or network error.
		c.SendErrors.Add(1)
		if err != nil {
			e.report("export_network")
		} else {
			e.report("export_http_" + strconv.Itoa(status))
		}
		if !retry || attempt >= e.o.MaxRetries || actx.Err() != nil {
			c.EventsDroppedQueue.Add(int64(len(batch)))
			return false
		}
		wait := e.backoff(attempt)
		if retryAfter > 0 {
			wait = min(retryAfter, e.o.MaxRetryAfter)
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-e.stop:
			t.Stop()
			c.EventsDroppedQueue.Add(int64(len(batch)))
			return false
		case <-actx.Done():
			t.Stop()
			c.EventsDroppedQueue.Add(int64(len(batch)))
			return cleared()
		}
	}
}

// backoff is exponential from BaseBackoff to MaxBackoff with +-25% jitter.
func (e *Exporter) backoff(attempt int) time.Duration {
	d := e.o.BaseBackoff
	for i := 0; i < attempt && d < e.o.MaxBackoff; i++ {
		d *= 2
	}
	if d > e.o.MaxBackoff {
		d = e.o.MaxBackoff
	}
	j := 0.75 + rand.Float64()*0.5
	return time.Duration(float64(d) * j)
}

func (e *Exporter) post(ctx context.Context, client *http.Client, url string, body []byte) (status int, retryAfter time.Duration, rejected int64, err error) {
	if client == nil || url == "" {
		return 0, 0, 0, io.ErrClosedPipe
	}
	payload, enc := body, ""
	if len(body) > e.o.GzipMinBytes {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write(body)
		if zw.Close() == nil {
			payload, enc = b.Bytes(), "gzip"
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK && len(bytes.TrimSpace(raw)) > 0 {
		var r struct {
			PartialSuccess struct {
				Rejected json.Number `json:"rejectedLogRecords"`
			} `json:"partialSuccess"`
		}
		if json.Unmarshal(raw, &r) == nil {
			if n, err := r.PartialSuccess.Rejected.Int64(); err == nil && n > 0 {
				rejected = n
			}
		}
	}
	return resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After"), e.o.Now()), rejected, nil
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// otlpBody writes the OTLP/HTTP JSON logs request of docs/spec/event.md 4.2
// by hand: the event stays an opaque string.
func (e *Exporter) otlpBody(batch []Event) ([]byte, error) {
	now := e.o.Now()
	observed := strconv.FormatInt(now.UnixNano(), 10)
	str := func(s string) []byte { b, _ := json.Marshal(s); return b }
	attr := func(k, v string) []byte {
		return []byte(`{"key":` + string(str(k)) + `,"value":{"stringValue":` + string(str(v)) + `}}`)
	}
	var b bytes.Buffer
	b.WriteString(`{"resourceLogs":[{"resource":{"attributes":[`)
	for i, a := range [][]byte{
		attr("service.name", e.o.ServiceName), attr("tt.source.kind", e.o.SourceKind),
		attr("tt.source.version", e.o.SourceVersion), attr("tt.source.id", e.o.SourceID),
	} {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(a)
	}
	b.WriteString(`]},"scopeLogs":[{"scope":{"name":"traffic-twin","version":` + string(str(e.o.SourceVersion)) + `},"logRecords":[`)
	for i, ev := range batch {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"timeUnixNano":"` + strconv.FormatInt(ev.TS.Truncate(time.Millisecond).UnixNano(), 10) + `","observedTimeUnixNano":"` + observed +
			`","severityNumber":9,"severityText":"INFO","eventName":"tt.http.exchange"`)
		if ev.TraceID != "" {
			b.WriteString(`,"traceId":"` + ev.TraceID + `"`)
		}
		if ev.SpanID != "" {
			b.WriteString(`,"spanId":"` + ev.SpanID + `"`)
		}
		b.WriteString(`,"attributes":[` + string(attr("tt.schema", "tt.http.exchange/v1")) + `,` + string(attr("tt.policy.hash", ev.PolicyHash)) +
			`],"body":{"stringValue":` + string(str(string(ev.JSON))) + `}}`)
	}
	b.WriteString(`]}]}]}`)
	return b.Bytes(), nil
}
