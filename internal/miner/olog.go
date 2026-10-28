package miner

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

// This file builds the object-centric view of the stored events (an
// OCEL 2.0 compatible log, docs/ARCHITECTURE.md 7.2): objects are HMAC tokens
// typed by their domain, events are exchanges, and event-object links carry
// the field where the token was seen as qualifier. Exchanges of one trace are
// nested (outbound calls made while serving an inbound request), which is
// what tells who minted an identifier.

type side uint8

const (
	sideReq side = iota
	sideResp
)

// Value is a scalar kept in clear by the policy (keep action).
type Value struct {
	Kind byte // 's' string, 'n' number, 'b' boolean, 'z' null
	S    string
}

// Any returns the JSON value (json.Number for numbers).
func (v Value) Any() any {
	switch v.Kind {
	case 's':
		return v.S
	case 'n':
		return json.Number(v.S)
	case 'b':
		return v.S == "true"
	}
	return nil
}

type attr struct {
	name string
	val  Value
}

type recField struct {
	name string
	tok  int32
	loc  int32
}

// record is one JSON object node of a body that holds at least one token:
// the projection of a business object in an exchange.
type record struct {
	side  side
	path  string // tt-path of the node: "$", "$.items[*]"
	ids   []recField
	attrs []attr // keep scalars
	// times are the time: buckets (Kind 's', val.S is the token) and, Kind
	// 'q', the number buckets (num:50-100) of the node: a number seen only
	// as its bucket (rules v1.7, C2). One slice: an event costs no more.
	times []attr
}

// bucket returns the number bucket of a member.
func (r *record) bucket(name string) (Value, bool) {
	for _, a := range r.times {
		if a.name == name && a.val.Kind == 'q' {
			return a.val, true
		}
	}
	return Value{}, false
}

func (r *record) id(name string) (recField, bool) {
	for _, f := range r.ids {
		if f.name == name {
			return f, true
		}
	}
	return recField{}, false
}

func (r *record) attr(name string) (Value, bool) {
	for _, a := range r.attrs {
		if a.name == name {
			return a.val, true
		}
	}
	return Value{}, false
}

func (r *record) time(name string) (string, bool) {
	for _, a := range r.times {
		if a.name == name && a.val.Kind == 's' {
			return a.val.S, true
		}
	}
	return "", false
}

type tokAt struct {
	tok int32
	loc int32
}

type arrLen struct {
	path string
	n    int
}

type evt struct {
	id      int64
	ts, end time.Time // request start, response end (ts + latency)
	op      int32
	inbound bool
	status  int
	subject int32 // token index, -1 when absent
	// trace is the index of the trace id (Log.traceIdx), -1 when absent;
	// span and parent are hashes of the span ids (0: absent). They only
	// serve to build the trace trees (finish): a string each per event
	// was ~100 bytes of the ~1.4 KB an event costs at the peak of a run.
	trace   int32
	span    uint64
	parent  uint64
	pev     int32 // parent event, -1
	root    int32 // root event of the trace tree (itself when no parent)
	depth   int
	toks    []tokAt
	recs    []record
	arrays  []arrLen // response arrays and their length
	reqKeys []string // member names of the request body root object
	nums    []attr   // number members of the response body root object
	// reqState and respState are the clear scalar members of the "state
	// node" of the request and response bodies (stateNode): what a keyed
	// record is written with and read as (rules v1.6).
	reqState, respState stateObs
}

// stateObs is the state node of a body: its tt-path and clear members.
type stateObs struct {
	path  string
	attrs []attr
}

func (e *evt) ok() bool { return e.status >= 200 && e.status < 300 }

// at returns the time of a token occurrence: request side at ts, response
// side at the end of the exchange.
func (e *evt) at(s side) time.Time {
	if s == sideResp {
		return e.end
	}
	return e.ts
}

type opInfo struct {
	service string
	op      string
	method  string
	write   bool
	// read: the operation reads (a GET, a GraphQL query, a POST classified
	// as a read by its behaviour, or an operation a person marked as a read
	// in the console; rules v1.6). write and read never both hold once the
	// log is classified (classifyReads).
	read bool
	// readAuto tells that read was decided from the traffic, readSet that a
	// person decided it.
	readAuto, readSet bool
	gqlDone           bool // GraphQL kind resolved (graphql.go)
}

type loc struct {
	op     int32
	field  string // event.HMACToken.Where form
	side   side
	ref    Ref
	refOK  bool
	domain string
}

type occ struct {
	ev  int32
	loc int32
}

// Log is the object-centric view of a window of events.
type Log struct {
	From, To    time.Time // requested window
	First, Last time.Time // event times actually seen

	ops    []opInfo
	opIdx  map[[2]string]int32
	locs   []loc
	locIdx map[[2]string]int32 // service+" "+op, field
	toks   []string
	tokIdx map[string]int32
	evs    []evt
	occ    [][]occ  // per token, in event order
	tokDom []string // domain per token
	subj   map[int32]bool
	names  map[string]string // interned member names, paths and short values
	// reqVals are, per event, the clear scalars of a write's request (rules
	// v1.7, C2): body members outside arrays by tt-path ("$.status",
	// "$.variables.input.on") and query parameters ("?name"), what an update
	// may copy. A map: most events have none.
	reqVals map[int32][]attr
	// traceIdx numbers the trace ids while the log loads (dropped by
	// finish).
	traceIdx map[string]int32
	// extra are, per event, the clear values rules v1.9 reads besides
	// reqVals (header values, query values of reads, number buckets of the
	// response state node): a map, most events have none (reads19.go).
	extra map[int32]*evExtra
}

// maxInterned bounds the interning table; maxInternLen the strings it takes.
const (
	maxInterned  = 1 << 16
	maxInternLen = 64
)

// name returns a shared copy of s: the member names, tt-paths and keep
// values of a body repeat in every event, and the log keeps them for every
// event of the window (millions): one copy each instead of one per event.
func (l *Log) name(s string) string {
	if len(s) > maxInternLen {
		return s
	}
	if v, ok := l.names[s]; ok {
		return v
	}
	if len(l.names) < maxInterned {
		l.names[s] = s
	}
	return s
}

// ErrTooManyEvents is returned when a window holds more than Config.MaxEvents.
var ErrTooManyEvents = errors.New("miner: too many events in the window")

// EventSource is the read side of the event storage (intake.Store).
type EventSource interface {
	Scan(ctx context.Context, q intake.Query, fn func(*intake.StoredEvent) error) error
}

// windowCounter is implemented by event sources that count a window
// without reading it (*intake.Store).
type windowCounter interface {
	CountWindow(ctx context.Context, from, to time.Time, service string) (int, error)
}

// Load builds the object-centric log of the events in [from, to) (zero =
// open), optionally for one service only. Domains come from res (nil:
// heuristic names only).
func Load(ctx context.Context, src EventSource, from, to time.Time, service string, res DomainResolver, maxEvents int) (*Log, error) {
	l := newLog(from, to)
	// The events array is the largest structure of the log: sized once from
	// the count when the source can tell it (growing it by doubling keeps
	// the old and the new array alive at once, three times its size).
	if wc, ok := src.(windowCounter); ok {
		if n, err := wc.CountWindow(ctx, from, to, service); err == nil && n > 0 {
			if maxEvents > 0 && n > maxEvents {
				n = maxEvents
			}
			l.evs = make([]evt, 0, n)
		}
	}
	err := src.Scan(ctx, intake.Query{From: from, To: to, Service: service, ByTime: true}, func(se *intake.StoredEvent) error {
		if maxEvents > 0 && len(l.evs) >= maxEvents {
			return ErrTooManyEvents
		}
		l.add(se, res)
		return nil
	})
	if err != nil {
		return nil, err
	}
	l.finish()
	return l, nil
}

func newLog(from, to time.Time) *Log {
	return &Log{
		From: from, To: to,
		opIdx: map[[2]string]int32{}, locIdx: map[[2]string]int32{}, tokIdx: map[string]int32{},
		subj: map[int32]bool{}, names: map[string]string{}, traceIdx: map[string]int32{}, reqVals: map[int32][]attr{},
		extra: map[int32]*evExtra{},
	}
}

// LoadGroups is Load split by group: the events of each group (the group of
// their source, groupOf; "" for sources of no group) go to a log of their
// own, so that nothing mined from one team's traffic (entities, references,
// relayed identifiers, rules) mixes with another team's (multi-team
// isolation, docs/spec/rules.md 2.7). maxEvents bounds the events of all
// the logs together. A nil groupOf gives one log, under "". oneGroup tells
// that the sources are of one group at most (the log is sized up front).
func LoadGroups(ctx context.Context, src EventSource, from, to time.Time, res DomainResolver, maxEvents int, groupOf func(source string) string, oneGroup bool) (map[string]*Log, error) {
	logs, _, err := loadGroups(ctx, src, from, to, res, maxEvents, groupOf, oneGroup, false)
	return logs, err
}

// errWindowFull stops a scan that reached maxEvents when the caller already
// narrowed the window (stop): events keep arriving between the count of the
// window and its scan, so the newest few are left out instead of failing.
var errWindowFull = errors.New("miner: window full")

// loadGroups is LoadGroups; with stop, reaching maxEvents ends the scan (the
// newest events are left out, truncated is true) instead of ErrTooManyEvents.
func loadGroups(ctx context.Context, src EventSource, from, to time.Time, res DomainResolver, maxEvents int, groupOf func(source string) string, oneGroup, stop bool) (logs map[string]*Log, truncated bool, err error) {
	if groupOf == nil {
		groupOf = func(string) string { return "" }
		oneGroup = true
	}
	logs = map[string]*Log{}
	n := 0
	// One group (the usual case): its log is sized once from the count, as
	// Load does.
	var prealloc int
	if wc, ok := src.(windowCounter); ok && oneGroup {
		if c, err := wc.CountWindow(ctx, from, to, ""); err == nil && c > 0 {
			if maxEvents > 0 && c > maxEvents {
				c = maxEvents
			}
			prealloc = c
		}
	}
	err = src.Scan(ctx, intake.Query{From: from, To: to, ByTime: true}, func(se *intake.StoredEvent) error {
		if maxEvents > 0 && n >= maxEvents {
			if stop {
				truncated = true
				return errWindowFull
			}
			return ErrTooManyEvents
		}
		n++
		g := groupOf(se.Event.Source.ID)
		l := logs[g]
		if l == nil {
			l = newLog(from, to)
			if prealloc > 0 {
				l.evs, prealloc = make([]evt, 0, prealloc), 0
			}
			logs[g] = l
		}
		l.add(se, res)
		return nil
	})
	if errors.Is(err, errWindowFull) {
		err = nil
	}
	if err != nil {
		return nil, false, err
	}
	for _, l := range logs {
		l.finish()
	}
	if len(logs) == 0 {
		l := newLog(from, to)
		l.finish()
		logs[""] = l
	}
	return logs, truncated, nil
}

func (l *Log) intern(tok string) int32 {
	if i, ok := l.tokIdx[tok]; ok {
		return i
	}
	i := int32(len(l.toks))
	l.toks = append(l.toks, tok)
	l.tokIdx[tok] = i
	l.occ = append(l.occ, nil)
	return i
}

func (l *Log) opOf(service, op string) int32 {
	k := [2]string{service, op}
	if i, ok := l.opIdx[k]; ok {
		return i
	}
	i := int32(len(l.ops))
	m, _, _ := strings.Cut(op, " ")
	l.ops = append(l.ops, opInfo{service: service, op: op, method: m,
		write: m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE", read: m == "GET"})
	l.opIdx[k] = i
	return i
}

func (l *Log) locOf(op int32, field, policyHash string, status int, res DomainResolver) int32 {
	o := l.ops[op]
	k := [2]string{o.service + " " + o.op, field}
	if i, ok := l.locIdx[k]; ok {
		if l.locs[i].domain == "" && res != nil {
			if d, ok := res.Domain(policyHash, o.service, o.op, status, field); ok {
				l.locs[i].domain = d
			}
		}
		return i
	}
	lc := loc{op: op, field: field}
	if strings.HasPrefix(field, "resp.") {
		lc.side = sideResp
	}
	lc.ref, lc.refOK = refOfField(o.op, field)
	if res != nil {
		if d, ok := res.Domain(policyHash, o.service, o.op, status, field); ok {
			lc.domain = d
		}
	}
	i := int32(len(l.locs))
	l.locs = append(l.locs, lc)
	l.locIdx[k] = i
	return i
}

// refOfField converts an event field ("resp.body$.items[*].id",
// "req.path[1]", "req.query.orderId") into a rules ref.
func refOfField(op, field string) (Ref, bool) {
	sideName, rest, ok := strings.Cut(field, ".")
	if !ok {
		return Ref{}, false
	}
	switch {
	case strings.HasPrefix(rest, "body$"):
		return Ref{From: sideName + ".body", Path: rest[len("body"):]}, true
	case strings.HasPrefix(rest, "path["):
		name, ok := pathParamName(op, rest)
		return Ref{From: "req.path", Name: name}, ok
	default:
		part, name, ok := strings.Cut(rest, ".")
		if !ok {
			return Ref{}, false
		}
		switch part {
		case "query", "headers", "cookies":
			return Ref{From: sideName + "." + part, Name: name}, true
		}
	}
	return Ref{}, false
}

func valueOf(v *event.Value) (Value, bool) {
	switch v.Kind {
	case event.String:
		if s, ok := event.KeepValue(v.S); ok {
			return Value{Kind: 's', S: s}, true
		}
	case event.Number:
		return Value{Kind: 'n', S: v.S}, true
	case event.Bool:
		if v.B {
			return Value{Kind: 'b', S: "true"}, true
		}
		return Value{Kind: 'b', S: "false"}, true
	case event.Null:
		return Value{Kind: 'z'}, true
	}
	return Value{}, false
}

func (l *Log) add(se *intake.StoredEvent, res DomainResolver) {
	ev := se.Event
	op := l.opOf(ev.Service, ev.Op)
	l.graphqlKind(op, ev)
	e := evt{
		id: se.ID, ts: ev.Time, end: ev.Time.Add(time.Duration(ev.LatencyMS) * time.Millisecond),
		op: op, inbound: ev.Dir == event.Inbound, status: ev.Status, subject: -1,
		trace: l.traceOf(ev.TraceID), span: idHash(ev.SpanID), parent: idHash(ev.ParentSpanID), pev: -1,
	}
	if ev.Subject != "" {
		e.subject = l.intern(ev.Subject)
		l.subj[e.subject] = true
	}
	idx := int32(len(l.evs))
	ev.HMACTokens(func(t event.HMACToken) {
		if t.Where == "subject" {
			return
		}
		tok := l.intern(t.Token)
		lc := l.locOf(op, t.Where, ev.Policy.Hash, ev.Status, res)
		e.toks = append(e.toks, tokAt{tok, lc})
		l.occ[tok] = append(l.occ[tok], occ{idx, lc})
	})
	walk := func(s side, body *event.Value) {
		if body == nil {
			return
		}
		prefix := "req.body"
		if s == sideResp {
			prefix = "resp.body"
		}
		walkObjects(body, "$", func(path string, node *event.Value) {
			var r record
			for i := range node.O {
				m := &node.O[i]
				if m.K == "{*}" || m.K == "{trunc}" {
					continue
				}
				switch m.V.Kind {
				case event.String:
					switch {
					case strings.HasPrefix(m.V.S, "tk1:"):
						tok := l.intern(m.V.S)
						lc := l.locOf(op, prefix+path+"."+m.K, ev.Policy.Hash, ev.Status, res)
						r.ids = append(r.ids, recField{l.name(m.K), tok, lc})
					case strings.HasPrefix(m.V.S, "time:"):
						r.times = append(r.times, attr{l.name(m.K), Value{Kind: 's', S: l.name(m.V.S)}})
					case strings.HasPrefix(m.V.S, "num:"):
						if event.ValidNumToken(m.V.S) {
							r.times = append(r.times, attr{l.name(m.K), Value{Kind: 'q', S: l.name(m.V.S)}})
						}
					default:
						if v, ok := valueOf(&m.V); ok {
							v.S = l.name(v.S)
							r.attrs = append(r.attrs, attr{l.name(m.K), v})
						}
					}
				case event.Number, event.Bool, event.Null:
					v, _ := valueOf(&m.V)
					v.S = l.name(v.S)
					r.attrs = append(r.attrs, attr{l.name(m.K), v})
				}
			}
			if len(r.ids) > 0 {
				r.side, r.path = s, l.name(path)
				e.recs = append(e.recs, r)
			}
			if s == sideResp && path != "$" && !strings.Contains(path, "[*]") {
				// The numbers of a nested list envelope ($.data.orders
				// holding items and count, rules v1.7): "data.orders.count".
				hasArr := false
				for i := range node.O {
					hasArr = hasArr || node.O[i].V.Kind == event.Array
				}
				for i := 0; hasArr && i < len(node.O); i++ {
					if m := &node.O[i]; m.V.Kind == event.Number && reFieldName.MatchString(m.K) {
						e.nums = append(e.nums, attr{l.name(path[2:] + "." + m.K), Value{Kind: 'n', S: l.name(m.V.S)}})
					}
				}
			}
		}, func(path string, n int) {
			if s == sideResp {
				e.arrays = append(e.arrays, arrLen{l.name(path), n})
			}
		})
	}
	walk(sideReq, ev.Req.Body)
	if ev.Resp != nil {
		walk(sideResp, ev.Resp.Body)
		if b := ev.Resp.Body; b != nil && b.Kind == event.Object {
			for i := range b.O {
				if b.O[i].V.Kind == event.Number {
					e.nums = append(e.nums, attr{l.name(b.O[i].K), Value{Kind: 'n', S: l.name(b.O[i].V.S)}})
				}
			}
		}
	}
	if b := ev.Req.Body; b != nil && b.Kind == event.Object {
		for i := range b.O {
			e.reqKeys = append(e.reqKeys, l.name(b.O[i].K))
		}
		root := "$"
		node := b
		if isGraphQLOp(ev.Op) {
			if v := member(b, "variables"); v != nil && v.Kind == event.Object {
				root, node = "$.variables", v
			}
		}
		e.reqState = l.stateNode(node, root)
	}
	if l.ops[op].write {
		var vals []attr
		if b := ev.Req.Body; b != nil && b.Kind == event.Object {
			vals = l.requestValues(b, "$", 0, nil)
		}
		for _, q := range ev.Req.Query {
			if len(q.Values) != 1 || len(vals) >= maxReqVals {
				continue
			}
			if v, ok := clearString(q.Values[0]); ok {
				v.S = l.name(v.S)
				vals = append(vals, attr{l.name("?" + q.Name), v})
			}
		}
		if len(vals) > 0 {
			l.reqVals[int32(len(l.evs))] = exact(vals)
		}
	}
	if ev.Resp != nil && ev.Resp.Body != nil && ev.Resp.Body.Kind == event.Object {
		e.respState = l.stateNode(ev.Resp.Body, "$")
	}
	if x := l.extraValues(ev, op); x != nil {
		l.extra[int32(len(l.evs))] = x
	}
	if l.First.IsZero() || e.ts.Before(l.First) {
		l.First = e.ts
	}
	if e.end.After(l.Last) {
		l.Last = e.end
	}
	// Exact-size slices: append doubles their capacity, and they live as
	// long as the run (millions of events).
	e.toks, e.recs, e.arrays, e.reqKeys, e.nums = exact(e.toks), exact(e.recs), exact(e.arrays), exact(e.reqKeys), exact(e.nums)
	e.reqState.attrs, e.respState.attrs = exact(e.reqState.attrs), exact(e.respState.attrs)
	for i := range e.recs {
		r := &e.recs[i]
		r.ids, r.attrs, r.times = exact(r.ids), exact(r.attrs), exact(r.times)
	}
	l.evs = append(l.evs, e)
}

// member returns the value of an object member, nil.
func member(v *event.Value, k string) *event.Value {
	for i := range v.O {
		if v.O[i].K == k {
			return &v.O[i].V
		}
	}
	return nil
}

// maxStateAttrs bounds the clear members kept per state node.
const maxStateAttrs = 32

// stateNode finds the state node of a body: from the root, the only
// member while it is the only member and an object ({"data": {"profile":
// {...}}} → $.data.profile), at most three levels down; and keeps its clear
// scalar members (keep values, numbers, booleans; never tokens).
func (l *Log) stateNode(v *event.Value, path string) stateObs {
	for depth := 0; depth < 3 && len(v.O) == 1 && v.O[0].V.Kind == event.Object && v.O[0].K != "{*}" && v.O[0].K != "{trunc}"; depth++ {
		path += "." + v.O[0].K
		v = &v.O[0].V
	}
	st := stateObs{path: l.name(path)}
	for i := range v.O {
		m := &v.O[i]
		if m.K == "{*}" || m.K == "{trunc}" || len(st.attrs) >= maxStateAttrs {
			continue
		}
		switch m.V.Kind {
		case event.String, event.Number, event.Bool:
			if m.V.Kind == event.String && (strings.HasPrefix(m.V.S, "tk1:") || strings.HasPrefix(m.V.S, "time:")) {
				continue
			}
			if val, ok := valueOf(&m.V); ok {
				val.S = l.name(val.S)
				st.attrs = append(st.attrs, attr{l.name(m.K), val})
			}
		}
	}
	return st
}

// maxReqVals bounds the clear request values kept per event.
const maxReqVals = 16

// clearString is the value of a masked string in clear: a keep value or a
// number bucket; false for tokens, shapes and times.
func clearString(s string) (Value, bool) {
	if v, ok := event.KeepValue(s); ok {
		return Value{Kind: 's', S: v}, true
	}
	if strings.HasPrefix(s, "num:") && event.ValidNumToken(s) {
		return Value{Kind: 'q', S: s}, true
	}
	return Value{}, false
}

// requestValues appends the clear scalars of a request body below path,
// outside arrays, at most four members down (rules v1.7, C2).
func (l *Log) requestValues(v *event.Value, path string, depth int, out []attr) []attr {
	if v.Kind != event.Object || depth >= 4 {
		return out
	}
	for i := range v.O {
		m := &v.O[i]
		if m.K == "{*}" || m.K == "{trunc}" || len(out) >= maxReqVals || !reFieldName.MatchString(m.K) {
			continue
		}
		p := path + "." + m.K
		switch m.V.Kind {
		case event.Object:
			out = l.requestValues(&m.V, p, depth+1, out)
		case event.String:
			if val, ok := clearString(m.V.S); ok {
				val.S = l.name(val.S)
				out = append(out, attr{l.name(p), val})
			}
		case event.Number, event.Bool:
			val, _ := valueOf(&m.V)
			val.S = l.name(val.S)
			out = append(out, attr{l.name(p), val})
		}
	}
	return out
}

// exact returns s with no spare capacity (a copy when it has some).
func exact[S ~[]E, E any](s S) S {
	if len(s) == cap(s) {
		return s
	}
	if len(s) == 0 {
		return nil
	}
	return append(make(S, 0, len(s)), s...)
}

// walkObjects calls obj for every object node and arr for every array node
// of a body tree, with their tt-paths.
func walkObjects(v *event.Value, path string, obj func(string, *event.Value), arr func(string, int)) {
	switch v.Kind {
	case event.Object:
		obj(path, v)
		for i := range v.O {
			m := &v.O[i]
			if m.K == "{*}" || m.K == "{trunc}" {
				continue
			}
			walkObjects(&m.V, path+"."+m.K, obj, arr)
		}
	case event.Array:
		arr(path, len(v.A))
		for i := range v.A {
			walkObjects(&v.A[i], path+"[*]", obj, arr)
		}
	}
}

// traceOf numbers a trace id (-1: none).
func (l *Log) traceOf(id string) int32 {
	if id == "" {
		return -1
	}
	if i, ok := l.traceIdx[id]; ok {
		return i
	}
	i := int32(len(l.traceIdx))
	l.traceIdx[id] = i
	return i
}

// idHash is the FNV-1a hash of a span id (0: none). Spans are matched
// within one trace, where a collision of 64-bit hashes is negligible.
func idHash(id string) uint64 {
	if id == "" {
		return 0
	}
	h := uint64(14695981039346656037)
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	if h == 0 {
		h = 1
	}
	return h
}

// spanEnt is one span of the trace trees: sorted by trace, span and event.
type spanEnt struct {
	trace, ev int32
	span      uint64
}

func (l *Log) finish() {
	// Trace trees: parent by span id, else the enclosing inbound exchange of
	// the same trace for an outbound one. Sorted arrays instead of maps
	// keyed by strings: 16 bytes per event, not ~150, at the peak of the
	// run.
	ntr := len(l.traceIdx)
	l.traceIdx = nil
	spans := make([]spanEnt, 0, len(l.evs))
	start := make([]int32, ntr+1) // events of trace t: byTrace[start[t]:start[t+1]], in event order
	for i := range l.evs {
		e := &l.evs[i]
		if e.trace < 0 {
			continue
		}
		if e.span != 0 {
			spans = append(spans, spanEnt{e.trace, int32(i), e.span})
		}
		start[e.trace+1]++
	}
	for t := 1; t <= ntr; t++ {
		start[t] += start[t-1]
	}
	byTrace := make([]int32, start[ntr])
	fill := slices.Clone(start[:ntr])
	for i := range l.evs {
		if t := l.evs[i].trace; t >= 0 {
			byTrace[fill[t]] = int32(i)
			fill[t]++
		}
	}
	slices.SortFunc(spans, func(a, b spanEnt) int {
		if a.trace != b.trace {
			return cmp.Compare(a.trace, b.trace)
		}
		if a.span != b.span {
			return cmp.Compare(a.span, b.span)
		}
		return cmp.Compare(a.ev, b.ev)
	})
	// spanOf is the last event (in event order) with that span in trace t.
	spanOf := func(t int32, span uint64) (int32, bool) {
		k := sort.Search(len(spans), func(i int) bool {
			s := spans[i]
			return s.trace > t || (s.trace == t && s.span > span)
		})
		if k > 0 && spans[k-1].trace == t && spans[k-1].span == span {
			return spans[k-1].ev, true
		}
		return 0, false
	}
	for i := range l.evs {
		e := &l.evs[i]
		if e.trace < 0 {
			continue
		}
		if e.parent != 0 {
			if p, ok := spanOf(e.trace, e.parent); ok && p != int32(i) {
				e.pev = p
				continue
			}
		}
		if !e.inbound {
			for _, j := range byTrace[start[e.trace]:start[e.trace+1]] {
				p := &l.evs[j]
				if j != int32(i) && p.inbound && !p.ts.After(e.ts) && !p.end.Before(e.end) {
					e.pev = j
					break
				}
			}
		}
	}
	for i := range l.evs {
		e := &l.evs[i]
		r, d := int32(i), 0
		for l.evs[r].pev >= 0 && d < 16 {
			r = l.evs[r].pev
			d++
		}
		e.root, e.depth = r, d
	}
	l.assignDomains()
}

// tokIn reports where tok appears in event i.
func (l *Log) tokIn(i int32, tok int32) (inReq, inResp bool) {
	for _, t := range l.evs[i].toks {
		if t.tok == tok {
			if l.locs[t.loc].side == sideResp {
				inResp = true
			} else {
				inReq = true
			}
		}
	}
	return
}

// assignDomains fills unknown location domains: locations that share tokens
// form one class (equal tokens imply equal domains, since the domain is part
// of the HMAC input); the class takes the resolved domain of any member or a
// name guessed from the field and operation.
func (l *Log) assignDomains() {
	parent := make([]int32, len(l.locs))
	for i := range parent {
		parent[i] = int32(i)
	}
	var find func(int32) int32
	find = func(x int32) int32 {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	for _, os := range l.occ {
		for k := 1; k < len(os); k++ {
			a, b := find(os[0].loc), find(os[k].loc)
			if a != b {
				parent[a] = b
			}
		}
	}
	votes := map[int32]map[string]int{}
	guess := map[int32]map[string]int{}
	for i := range l.locs {
		c := find(int32(i))
		if d := l.locs[i].domain; d != "" {
			if votes[c] == nil {
				votes[c] = map[string]int{}
			}
			votes[c][d]++
		} else if g := guessDomain(l.ops[l.locs[i].op].op, l.locs[i].ref); g != "" {
			if guess[c] == nil {
				guess[c] = map[string]int{}
			}
			guess[c][g]++
		}
	}
	for i := range l.locs {
		if l.locs[i].domain != "" {
			continue
		}
		c := find(int32(i))
		if d := argmax(votes[c]); d != "" {
			l.locs[i].domain = d
		} else {
			l.locs[i].domain = argmax(guess[c])
		}
	}
	l.tokDom = make([]string, len(l.toks))
	for t, os := range l.occ {
		cnt := map[string]int{}
		for _, o := range os {
			if d := l.locs[o.loc].domain; d != "" {
				cnt[d]++
			}
		}
		l.tokDom[t] = argmax(cnt)
	}
}

func argmax(m map[string]int) string {
	best, n := "", -1
	for _, k := range sortedKeys(m) {
		if m[k] > n {
			best, n = k, m[k]
		}
	}
	return best
}

// guessDomain names a domain from a field: orderId → order, order_id →
// order, id → the resource segment before it (/orders/{id} → order).
func guessDomain(op string, r Ref) string {
	name := r.Name
	if r.Path != "" {
		ps := splitTTPath(r.Path)
		if len(ps) == 0 {
			return ""
		}
		name = ps[len(ps)-1]
		if name == "id" && len(ps) >= 2 {
			// $.items[*].id: use the operation path below.
			name = "id"
		}
	}
	lower := strings.ToLower(name)
	switch {
	case lower != "id" && strings.HasSuffix(lower, "_id"):
		return cleanDomain(lower[:len(lower)-3])
	case lower != "id" && strings.HasSuffix(name, "Id"):
		return cleanDomain(strings.ToLower(name[:len(name)-2]))
	case lower == "id" && isGraphQLOp(op):
		return graphqlDomain(op, r)
	case lower == "id":
		_, path, _ := strings.Cut(op, " ")
		segs, _ := event.OpSegments(path)
		var last string
		for _, s := range segs {
			if s.Literal {
				last = s.Inner
			}
			if !s.Literal && s.Inner == r.Name && r.From == "req.path" {
				break
			}
		}
		return cleanDomain(singular(strings.ToLower(last)))
	}
	return ""
}

func singular(s string) string {
	switch {
	case strings.HasSuffix(s, "ies") && len(s) > 3:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(s, "s") && len(s) > 1:
		return s[:len(s)-1]
	}
	return s
}

func cleanDomain(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || (b.Len() > 0 && (c >= '0' && c <= '9' || c == '_' || c == '-')) {
			b.WriteRune(c)
		}
	}
	out := b.String()
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// Events returns the number of events in the log.
func (l *Log) Events() int { return len(l.evs) }

// Objects returns the number of distinct tokens (subjects included).
func (l *Log) Objects() int { return len(l.toks) }

// sortInt32 sorts in place.
func sortInt32(s []int32) { sort.Slice(s, func(i, j int) bool { return s[i] < s[j] }) }
