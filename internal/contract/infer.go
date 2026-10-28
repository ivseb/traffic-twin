package contract

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

// EventSource is the read side of the event store used for inference. It is
// implemented by *intake.Store.
type EventSource interface {
	Scan(ctx context.Context, q intake.Query, fn func(*intake.StoredEvent) error) error
	OpSummaries(ctx context.Context, from, to time.Time) ([]intake.OpSummary, error)
}

var _ EventSource = (*intake.Store)(nil)

// InferOptions selects what InferFromStore reads.
type InferOptions struct {
	// From (inclusive) and To (exclusive) bound the event time; zero values
	// are open ends.
	From, To time.Time
	// Services restricts inference to these services (empty: all).
	Services []string
	// Sources restricts inference to the events of these sources (nil:
	// every source; the sources of one group for its contracts).
	Sources []string
	Config  Config
	Hints   Hints
}

// serviceSummaries is implemented by event sources that can summarize one
// service without reading the others (*intake.Store).
type serviceSummaries interface {
	OpSummariesOf(ctx context.Context, service string, from, to time.Time) ([]intake.OpSummary, error)
}

// sourceSummaries is implemented by event sources that can restrict the
// summaries to some sources (*intake.Store).
type sourceSummaries interface {
	OpSummariesFor(ctx context.Context, from, to time.Time, sources []string) ([]intake.OpSummary, error)
	OpSummariesOfFor(ctx context.Context, service string, from, to time.Time, sources []string) ([]intake.OpSummary, error)
}

// summaries returns the op summaries of the window restricted to sources
// (nil: every source).
func summaries(ctx context.Context, src EventSource, from, to time.Time, services, sources []string) ([]intake.OpSummary, error) {
	if sources != nil {
		ss, ok := src.(sourceSummaries)
		if !ok {
			return nil, errors.New("contract: the event source cannot filter by source")
		}
		if len(services) == 1 {
			return ss.OpSummariesOfFor(ctx, services[0], from, to, sources)
		}
		return ss.OpSummariesFor(ctx, from, to, sources)
	}
	if one, ok := src.(serviceSummaries); ok && len(services) == 1 {
		// One service (POST .../snapshots, the API): its own groups only,
		// not the window of every service.
		return one.OpSummariesOf(ctx, services[0], from, to)
	}
	return src.OpSummaries(ctx, from, to)
}

// InferFromStore runs the inferrer over the stored events of the window and
// returns one contract per service. Groups larger than Config.SampleCap are
// sampled with a fixed stride; exact counts come from the store summaries.
func InferFromStore(ctx context.Context, src EventSource, o InferOptions) ([]*Contract, error) {
	in := NewInferrer(o.Config, o.Hints)
	cfg := in.Config()
	if o.Sources != nil && len(o.Sources) == 0 {
		return nil, nil // a group without sources has no traffic
	}
	sums, err := summaries(ctx, src, o.From, o.To, o.Services, o.Sources)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, s := range o.Services {
		want[s] = true
	}
	ts := newTraceSubjects(src, 20_000)
	subject := func(ev *event.Event) string { return ts.lookup(ctx, ev.TraceID) }

	// Raw ops (no declared template) are grouped into inferred templates.
	keys := map[string][]string{}
	seenKey := map[string]bool{}
	for _, s := range sums {
		if (len(want) == 0 || want[s.Service]) && !seenKey[s.Service+" "+s.Op] {
			seenKey[s.Service+" "+s.Op] = true
			keys[s.Service] = append(keys[s.Service], s.Op)
		}
	}
	tmpl := templatesBySummary(keys)

	for _, s := range sums {
		if len(want) > 0 && !want[s.Service] {
			continue
		}
		opKey, inferred := tmpl[s.Service][s.Op]
		stride := int64(1)
		if cap := int64(cfg.SampleCap); s.Count > cap {
			stride = (s.Count + cap - 1) / cap
		}
		q := intake.Query{Service: s.Service, Op: s.Op, From: o.From, To: o.To, ByTime: true, SourceIDs: o.Sources}
		if s.Status == 0 {
			q.NetErrorOnly = true
		} else {
			q.Status = s.Status
		}
		// A large group is sampled in the store (about one event in stride,
		// by a hash of the id): the rows left out are not read nor decoded.
		q.SampleEvery = stride
		var seen int64
		addEv := func(ev *event.Event) error {
			if inferred && (ev.RouteSource == event.RouteRaw || opKey != ev.Op) {
				e := *ev
				e.Op, e.RouteSource = opKey, RouteInferred
				ev = &e
			}
			in.Add(ev, subject)
			return ctx.Err()
		}
		err := src.Scan(ctx, q, func(se *intake.StoredEvent) error {
			seen++
			return addEv(se.Event)
		})
		if err == nil && seen == 0 && stride > 1 {
			// The hash missed the whole group (tiny chance): the plain
			// strided scan.
			q.SampleEvery = 0
			err = src.Scan(ctx, q, func(se *intake.StoredEvent) error {
				if seen++; (seen-1)%stride != 0 {
					return nil
				}
				return addEv(se.Event)
			})
		}
		if err != nil {
			return nil, err
		}
		if !inferred {
			opKey = s.Op
		}
		in.SetGroup(s.Service, opKey, s.Status, s.Count, s.FirstTS, s.LastTS)
	}
	w := Window{From: o.From, To: o.To}
	return in.Contracts(w), nil
}

// traceSubjects resolves the subject of outbound events (which carry none)
// from the inbound event of the same trace, through the store, with a
// bounded cache.
type traceSubjects struct {
	src   EventSource
	mu    sync.Mutex
	cache map[string]string
	max   int
}

func newTraceSubjects(src EventSource, max int) *traceSubjects {
	return &traceSubjects{src: src, cache: map[string]string{}, max: max}
}

func (t *traceSubjects) lookup(ctx context.Context, trace string) string {
	if trace == "" {
		return ""
	}
	t.mu.Lock()
	s, ok := t.cache[trace]
	t.mu.Unlock()
	if ok {
		return s
	}
	var subj string
	_ = t.src.Scan(ctx, intake.Query{TraceID: trace, Dir: event.Inbound, Limit: 8}, func(se *intake.StoredEvent) error {
		if se.Event.Subject != "" {
			subj = se.Event.Subject
			return intake.ErrStop
		}
		return nil
	})
	t.mu.Lock()
	if len(t.cache) >= t.max {
		t.cache = map[string]string{}
	}
	t.cache[trace] = subj
	t.mu.Unlock()
	return subj
}
