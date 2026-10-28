package miner

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

// traffic builds masked events directly (tokens tk1:…, clear values keep:…),
// without a policy: domains are guessed from the field names, as for
// sources without a resolver. Invented data only.
type traffic struct {
	evs []*intake.StoredEvent
	now time.Time
	n   int
}

func newTraffic() *traffic {
	return &traffic{now: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}
}

// tok is a well-formed token (tk1:<kid>:<22 characters>) for an object of
// kind number n.
func tok(kind string, n int) string {
	k := (kind + "xxxxxxxxxxxx")[:12]
	return fmt.Sprintf("tk1:k1:%s_%09d", k, n)
}
func keep(v string) string { return "keep:" + v }

// val converts a Go value into an event body value.
func val(v any) event.Value {
	switch x := v.(type) {
	case nil:
		return event.Value{Kind: event.Null}
	case string:
		return event.Str(x)
	case bool:
		return event.Value{Kind: event.Bool, B: x}
	case int:
		return event.Value{Kind: event.Number, S: fmt.Sprint(x)}
	case json.Number:
		return event.Value{Kind: event.Number, S: string(x)}
	case []any:
		out := make([]event.Value, len(x))
		for i := range x {
			out[i] = val(x[i])
		}
		return event.Arr(out...)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ms := make([]event.Member, 0, len(keys))
		for _, k := range keys {
			ms = append(ms, event.Member{K: k, V: val(x[k])})
		}
		return event.Obj(ms...)
	}
	panic(fmt.Sprintf("val: %T", v))
}

type xcall struct {
	svc, op string
	path    string // request path with tokens in braces: /contracts/{tk1:…}
	query   map[string]string
	status  int
	user    string
	req     any
	resp    any
}

// add appends one inbound exchange, a minute after the previous one.
func (tr *traffic) add(c xcall) {
	tr.n++
	tr.now = tr.now.Add(time.Minute)
	if c.svc == "" {
		c.svc = "app-api"
	}
	if c.status == 0 {
		c.status = 200
	}
	if c.path == "" {
		_, p, _ := strings.Cut(c.op, " ")
		p, _, _ = strings.Cut(p, "#")
		c.path = p
	}
	ev := &event.Event{Time: tr.now, TS: tr.now.Format(time.RFC3339Nano), LatencyMS: 20, Dir: event.Inbound, Service: c.svc, Op: c.op,
		Status: c.status, TraceID: fmt.Sprintf("%032x", tr.n), SpanID: fmt.Sprintf("%016x", tr.n), Req: event.Request{Path: c.path},
		Resp: &event.Response{}}
	ev.Source.ID = "src-1"
	if c.user != "" {
		ev.Subject = c.user
	}
	if len(c.query) > 0 {
		names := make([]string, 0, len(c.query))
		for k := range c.query {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			ev.Req.Query = append(ev.Req.Query, event.MultiEntry{Name: k, Values: []string{c.query[k]}})
		}
	}
	if c.req != nil {
		b := val(c.req)
		ev.Req.Body = &b
	}
	if c.resp != nil {
		b := val(c.resp)
		ev.Resp.Body = &b
	}
	tr.evs = append(tr.evs, &intake.StoredEvent{ID: int64(tr.n), ReceivedAt: tr.now, Event: ev})
}

func (tr *traffic) Scan(_ context.Context, _ intake.Query, fn func(*intake.StoredEvent) error) error {
	for _, e := range tr.evs {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (tr *traffic) mine(t *testing.T, cfg Config, opt MineOptions) *Result {
	t.Helper()
	res, err := MineIn(context.Background(), tr, time.Time{}, time.Time{}, nil, cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Document(time.Time{}, nil).Validate(); err != nil {
		t.Fatalf("mined document: %v", err)
	}
	return res
}

func entOf(res *Result, name string) *Entity {
	for i := range res.Entities {
		if res.Entities[i].Name == name {
			return &res.Entities[i]
		}
	}
	return nil
}

func readOf(e *Entity, op string) *ReadBy {
	for i := range e.ReadBy {
		if e.ReadBy[i].Op == op {
			return &e.ReadBy[i]
		}
	}
	return nil
}

func smallK() Config {
	cfg := DefaultConfig()
	cfg.KMin = 5
	cfg.MinDistinct = 5
	return cfg
}

func user(n int) string { return tok("user", n) }
