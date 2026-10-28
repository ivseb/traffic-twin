package miner

import (
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Rules v1.9: the clear values the read-side analytics need besides the
// ones the log already keeps (reqVals of writes, the state nodes): the
// clear header values of every request ("^name"), the clear query values
// of the operations that are not writes at load time ("?name", writes have
// them in reqVals) and the number buckets of the response state node
// (name relative to the node, Kind 'q').

// evExtra holds the v1.9 clear values of one event.
type evExtra struct {
	req  []attr
	nums []attr
}

// maxExtraVals bounds the extra values kept per event.
const maxExtraVals = 16

func (l *Log) extraValues(ev *event.Event, op int32) *evExtra {
	var x evExtra
	for _, h := range ev.Req.Headers {
		if len(h.Values) != 1 || len(x.req) >= maxExtraVals || !reName.MatchString(h.Name) {
			continue
		}
		if v, ok := event.KeepValue(h.Values[0]); ok {
			x.req = append(x.req, attr{l.name("^" + strings.ToLower(h.Name)), Value{Kind: 's', S: l.name(v)}})
		}
	}
	if !l.ops[op].write {
		for _, q := range ev.Req.Query {
			if len(q.Values) != 1 || len(x.req) >= maxExtraVals {
				continue
			}
			if v, ok := clearString(q.Values[0]); ok {
				v.S = l.name(v.S)
				x.req = append(x.req, attr{l.name("?" + q.Name), v})
			}
		}
	}
	if ev.Resp != nil && ev.Resp.Body != nil && ev.Resp.Body.Kind == event.Object {
		v := ev.Resp.Body
		for depth := 0; depth < 3 && len(v.O) == 1 && v.O[0].V.Kind == event.Object && v.O[0].K != "{*}" && v.O[0].K != "{trunc}"; depth++ {
			v = &v.O[0].V
		}
		for i := range v.O {
			m := &v.O[i]
			if m.V.Kind == event.String && strings.HasPrefix(m.V.S, "num:") && event.ValidNumToken(m.V.S) &&
				reFieldName.MatchString(m.K) && len(x.nums) < maxExtraVals {
				x.nums = append(x.nums, attr{l.name(m.K), Value{Kind: 'q', S: l.name(m.V.S)}})
			}
		}
	}
	if len(x.req) == 0 && len(x.nums) == 0 {
		return nil
	}
	x.req, x.nums = exact(x.req), exact(x.nums)
	return &x
}

// reqClear returns the clear values of the request of event i: body
// members and query of a write (reqVals), headers and the query of a read.
func (l *Log) reqClear(i int32) []attr {
	out := l.reqVals[i]
	if x := l.extra[i]; x != nil && len(x.req) > 0 {
		out = append(append([]attr{}, out...), x.req...)
	}
	return out
}

// reqValue returns one clear request value of event i by its name.
func (l *Log) reqValue(i int32, name string) (Value, bool) {
	for _, a := range l.reqClear(i) {
		if a.name == name {
			return a.val, true
		}
	}
	return Value{}, false
}

// refOfReqVal is the rules reference of a clear request value name:
// "$.a.b" a body member, "?q" a query parameter, "^h" a header.
func refOfReqVal(name string) (Ref, bool) {
	switch {
	case strings.HasPrefix(name, "$."):
		return Ref{From: "req.body", Path: name}, reTTPath.MatchString(name)
	case strings.HasPrefix(name, "?"):
		return Ref{From: "req.query", Name: name[1:]}, reName.MatchString(name[1:])
	case strings.HasPrefix(name, "^"):
		return Ref{From: "req.headers", Name: name[1:]}, reName.MatchString(name[1:])
	}
	return Ref{}, false
}

// bucketRange returns the bounds of a number bucket: "num:50-100" →
// [50, 100), "num:>=250" → [250, ∞), "num:<0" → (−∞, 0).
func bucketRange(tok string) (lo, hi *float64, ok bool) {
	s, found := strings.CutPrefix(tok, "num:")
	if !found || s == "" {
		return nil, nil, false
	}
	num := func(x string) (*float64, bool) {
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return nil, false
		}
		return &f, true
	}
	switch {
	case strings.HasPrefix(s, "<"):
		hi, ok = num(s[1:])
		return nil, hi, ok
	case strings.HasPrefix(s, ">="):
		lo, ok = num(s[2:])
		return lo, nil, ok
	}
	i := strings.Index(s[1:], "-")
	if i < 0 {
		lo, ok = num(s)
		return lo, lo, ok
	}
	a, b := s[:i+1], s[i+2:]
	lo, ok1 := num(a)
	hi, ok2 := num(b)
	if !ok1 || !ok2 || !(*lo < *hi) {
		return nil, nil, false
	}
	return lo, hi, true
}

// numInBucket reports whether n falls in the bucket tok.
func numInBucket(n float64, tok string) bool {
	lo, hi, ok := bucketRange(tok)
	if !ok {
		return false
	}
	if lo != nil && hi != nil && *lo == *hi {
		return n == *lo
	}
	return (lo == nil || n >= *lo) && (hi == nil || n < *hi)
}

// valueAny is the typed JSON scalar of a clear value (strings stay
// strings, numbers json-like float, booleans bool).
func valueAny(v Value) any {
	switch v.Kind {
	case 'b':
		return v.S == "true"
	case 'n':
		if f, err := strconv.ParseFloat(v.S, 64); err == nil {
			return f
		}
	}
	return v.S
}

// readExtrasOut is what the read-side analytics of one group publish.
type readExtrasOut struct {
	attributes []Attribute
	aggregates []Aggregate
	lists      []ListOp
}

// mineReadExtras runs the read-side analytics of the group (after the
// entities): customer attributes (kept for the conditions), list
// parameters, aggregates. taken holds the attribute names of the run.
func (m *miner) mineReadExtras(taken map[string]bool) readExtrasOut {
	var out readExtrasOut
	attrs := m.mineAttributes(taken)
	m.rx = &readExtras{attrs: attrs}
	defer func() { m.rx.byOp = nil }() // the index is only for this pass
	for _, a := range attrs {
		out.attributes = append(out.attributes, a.def)
	}
	out.lists = m.mineLists()
	out.aggregates = m.mineAggregates()
	return out
}
