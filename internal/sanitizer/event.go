package sanitizer

import (
	"errors"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// EventSchema is the event format identifier.
const EventSchema = "tt.http.exchange/v1"

// ErrEventMeta reports event metadata that does not fit the event schema.
var ErrEventMeta = errors.New("sanitizer: invalid event metadata")

// EventMeta carries the service fields of a tt.http.exchange event
// (docs/spec/event.md section 1) that do not come from the sanitizer.
type EventMeta struct {
	PolicyID      string
	PolicyVersion int64
	PolicyHash    string

	SourceKind    string // sdk-node, sdk-go, egress, …
	SourceVersion string // semver
	SourceID      string // src-…

	TS        time.Time // request start
	LatencyMS int64
	Status    int    // 100–599; ignored when NetError is set
	NetError  string // timeout | reset | refused | dns | tls | other

	TraceID, SpanID, ParentSpanID string // lower-case hex, optional
}

var sourceKinds = map[string]bool{
	"sdk-node": true, "sdk-python": true, "sdk-java": true, "sdk-dotnet": true, "sdk-go": true, "sdk-php": true,
	"egress": true, "obi": true, "import-har": true, "import-otlp": true,
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		if !(isDigit(s[i]) || (s[i] >= 'a' && s[i] <= 'f')) {
			return false
		}
	}
	return true
}

// semver matches ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$.
func semver(s string) bool {
	i := 0
	for part := 0; part < 3; part++ {
		k := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i == k {
			return false
		}
		if part < 2 {
			if i >= len(s) || s[i] != '.' {
				return false
			}
			i++
		}
	}
	if i == len(s) {
		return true
	}
	if s[i] != '-' && s[i] != '+' || i+1 == len(s) {
		return false
	}
	for _, c := range []byte(s[i+1:]) {
		if !(isAlpha(c) || isDigit(c) || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func validSourceID(s string) bool {
	if len(s) < 5 || len(s) > 36 || s[:4] != "src-" {
		return false
	}
	for _, c := range []byte(s[4:]) {
		if !(isAlpha(c) || isDigit(c)) {
			return false
		}
	}
	return true
}

// MetaFromVerified fills the policy fields of m from a verified policy.
func MetaFromVerified(m EventMeta, v *policy.Verified) EventMeta {
	m.PolicyID, m.PolicyVersion, m.PolicyHash = v.Policy.PolicyID, v.Policy.Version, v.Hash
	return m
}

// BuildEvent builds the canonical tt.http.exchange/v1 event bytes from the
// sanitizer output and the metadata. It validates every service field
// against the event schema and fails rather than emitting an invalid event.
func BuildEvent(m EventMeta, o *Output) ([]byte, error) {
	if o == nil || !policy.ValidPolicyID(m.PolicyID) || m.PolicyVersion < 1 || len(m.PolicyHash) != 71 ||
		m.PolicyHash[:7] != "sha256:" || !lowerHex(m.PolicyHash[7:], 64) {
		return nil, ErrEventMeta
	}
	if !sourceKinds[m.SourceKind] || !semver(m.SourceVersion) || !validSourceID(m.SourceID) {
		return nil, ErrEventMeta
	}
	if m.TS.IsZero() || m.LatencyMS < 0 {
		return nil, ErrEventMeta
	}
	ts := m.TS.UTC().Truncate(time.Millisecond)
	if ts.Year() < 0 || ts.Year() > 9999 {
		return nil, ErrEventMeta
	}
	switch o.SampledBy {
	case ByBaggage, BySubject, ByTrace, ByRandom, ByInherited:
	default:
		return nil, ErrEventMeta
	}
	mem := func(k string, v ttjson.Value) ttjson.Member { return ttjson.Member{Key: k, Value: v} }
	ev := ttjson.Obj(
		mem("schema", ttjson.Str(EventSchema)),
		mem("policy", ttjson.Obj(
			mem("id", ttjson.Str(m.PolicyID)),
			mem("version", ttjson.Num(strconv.FormatInt(m.PolicyVersion, 10))),
			mem("hash", ttjson.Str(m.PolicyHash)),
		)),
		mem("source", ttjson.Obj(
			mem("kind", ttjson.Str(m.SourceKind)),
			mem("version", ttjson.Str(m.SourceVersion)),
			mem("id", ttjson.Str(m.SourceID)),
		)),
		mem("ts", ttjson.Str(ts.Format("2006-01-02T15:04:05.000Z"))),
		mem("latency_ms", ttjson.Num(strconv.FormatInt(m.LatencyMS, 10))),
		mem("dir", ttjson.Str(string(o.Dir))),
		mem("service", ttjson.Str(o.Service)),
		mem("op", ttjson.Str(o.Op)),
		mem("route_source", ttjson.Str(o.RouteSource)),
		mem("sampled_by", ttjson.Str(string(o.SampledBy))),
		mem("req", o.Req),
	)
	if m.NetError != "" {
		if !netErrors[m.NetError] || o.Resp != nil {
			return nil, ErrEventMeta
		}
		ev.Obj = append(ev.Obj, mem("net_error", ttjson.Str(m.NetError)))
	} else {
		if m.Status < 100 || m.Status > 599 || o.Resp == nil {
			return nil, ErrEventMeta
		}
		ev.Obj = append(ev.Obj, mem("status", ttjson.Num(strconv.Itoa(m.Status))), mem("resp", *o.Resp))
	}
	if o.Subject != "" {
		ev.Obj = append(ev.Obj, mem("subject", ttjson.Str(o.Subject)))
	}
	for _, f := range []struct {
		k, v string
		n    int
	}{{"trace_id", m.TraceID, 32}, {"span_id", m.SpanID, 16}, {"parent_span_id", m.ParentSpanID, 16}} {
		if f.v == "" {
			continue
		}
		if !lowerHex(f.v, f.n) {
			return nil, ErrEventMeta
		}
		ev.Obj = append(ev.Obj, mem(f.k, ttjson.Str(f.v)))
	}
	if len(o.Disc) > 0 {
		ev.Obj = append(ev.Obj, mem("disc", ttjson.Obj(o.Disc...)))
	}
	return encodeBounded(ev)
}

// MaxEventBytes is the event size limit (section 10.3).
const MaxEventBytes = 524288

// encodeBounded applies section 10.3: over 512 KiB, req.body then
// resp.body become trunc:size, then disc is removed; still too large ⇒ no
// event (ErrEventTooLarge).
func encodeBounded(ev ttjson.Value) ([]byte, error) {
	b, err := ttjson.Encode(ev)
	if err != nil || len(b) <= MaxEventBytes {
		return b, err
	}
	steps := []func() bool{
		func() bool { return replaceBody(&ev, "req") },
		func() bool { return replaceBody(&ev, "resp") },
		func() bool { return removeMember(&ev, "disc") },
	}
	for _, step := range steps {
		if !step() {
			continue
		}
		if b, err = ttjson.Encode(ev); err != nil || len(b) <= MaxEventBytes {
			return b, err
		}
	}
	return nil, ErrEventTooLarge
}

// ErrEventTooLarge means the event exceeds 512 KiB after every reduction.
var ErrEventTooLarge = errors.New("sanitizer: event larger than 512 KiB")

func replaceBody(ev *ttjson.Value, side string) bool {
	for i := range ev.Obj {
		if ev.Obj[i].Key != side {
			continue
		}
		part := &ev.Obj[i].Value
		for j := range part.Obj {
			if part.Obj[j].Key == "body" {
				part.Obj = append([]ttjson.Member(nil), part.Obj...)
				part.Obj[j].Value = tokTruncSize
				return true
			}
		}
	}
	return false
}

func removeMember(v *ttjson.Value, key string) bool {
	for i := range v.Obj {
		if v.Obj[i].Key == key {
			v.Obj = append(append([]ttjson.Member(nil), v.Obj[:i]...), v.Obj[i+1:]...)
			return true
		}
	}
	return false
}
