package packwriter

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Faults is faults.json (tt.faults/v1): observed error statuses, network
// errors and latency per operation.
type Faults struct {
	Ops []FaultOp
}

// FaultOp is one operation.
type FaultOp struct {
	Service, Op string
	Statuses    []FaultStatus
	NetErrors   []FaultNet
	// Latency percentiles in ms; zero P50 means unknown.
	P50, P95, P99 int64
}

// FaultStatus is an error status with its observed share.
type FaultStatus struct {
	Status  int
	P       float64
	Example string
}

// FaultNet is a network error kind with its observed share.
type FaultNet struct {
	Kind string
	P    float64
}

// Hints lists the faults for scenario presets.
func (f *Faults) Hints() []world.FaultHint {
	var out []world.FaultHint
	if f == nil {
		return nil
	}
	for _, op := range f.Ops {
		for _, s := range op.Statuses {
			out = append(out, world.FaultHint{Service: op.Service, Op: op.Op, Status: s.Status})
		}
		for _, n := range op.NetErrors {
			out = append(out, world.FaultHint{Service: op.Service, Op: op.Op, NetError: n.Kind})
		}
	}
	return out
}

func round4(x float64) float64 { return math.Round(x*10000) / 10000 }

func num(f float64) json.Number { return json.Number(strconv.FormatFloat(f, 'f', -1, 64)) }

func (f *Faults) file(rename func(string) string) ([]byte, error) {
	ops := []any{}
	list := append([]FaultOp(nil), f.Ops...)
	sort.Slice(list, func(i, j int) bool {
		if list[i].Service != list[j].Service {
			return list[i].Service < list[j].Service
		}
		return list[i].Op < list[j].Op
	})
	for _, op := range list {
		m := map[string]any{"service": rename(op.Service), "op": op.Op}
		if len(op.Statuses) > 0 {
			var st []any
			for _, s := range op.Statuses {
				e := map[string]any{"status": s.Status, "p": num(round4(s.P))}
				if s.Example != "" {
					e["example"] = s.Example
				}
				st = append(st, e)
			}
			m["statuses"] = st
		}
		if len(op.NetErrors) > 0 {
			var ne []any
			for _, n := range op.NetErrors {
				ne = append(ne, map[string]any{"kind": n.Kind, "p": num(round4(n.P))})
			}
			m["net_errors"] = ne
		}
		if op.P50 > 0 {
			lat := map[string]any{"p50": op.P50, "p95": op.P95, "p99": op.P99}
			if op.P95 > op.P50 {
				lat["lognormal"] = map[string]any{"median": op.P50, "sigma": num(math.Round(math.Log(float64(op.P95)/float64(op.P50))/1.6449*100) / 100)}
			}
			m["latency_ms"] = lat
		}
		ops = append(ops, m)
	}
	return world.CanonicalFile(map[string]any{"format": "tt.faults/v1", "ops": ops})
}

// FaultsSource returns the observed faults of the given services.
type FaultsSource interface {
	Faults(ctx context.Context, contracts []world.Contract, kMin int) (*Faults, error)
}

// EventFaults computes faults from stored events over a window. An entry
// is published only when it is backed by at least k_min events (and
// latency only for operations with k_min calls); the statuses of
// [FaultStatusCode] count as faults.
type EventFaults struct {
	Events   world.EventSource
	Window   time.Duration // default 14 days
	Now      func() time.Time
	MaxPerOp int // latency samples kept per operation (default 20000)
	// Groups, optional, attributes event sources to groups: the faults of
	// a group's contracts are counted on that group's calls only.
	Groups groupscope.Resolver
}

type opStats struct {
	total    int64
	statuses map[int]int64
	nets     map[string]int64
	lat      []int64
}

// contractsGroup is the group of the contracts when they all have the same
// one ("" otherwise).
func contractsGroup(cs []world.Contract) string {
	g := ""
	for i, c := range cs {
		if i > 0 && c.Group != g {
			return ""
		}
		g = c.Group
	}
	return g
}

// Faults implements FaultsSource.
func (e *EventFaults) Faults(ctx context.Context, contracts []world.Contract, kMin int) (*Faults, error) {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	win := e.Window
	if win <= 0 {
		win = 14 * 24 * time.Hour
	}
	maxS := e.MaxPerOp
	if maxS <= 0 {
		maxS = 20000
	}
	docs := map[string]map[string]any{}
	for _, c := range contracts {
		var d map[string]any
		if world.DecodeGeneric(c.Doc, &d) == nil {
			docs[c.Service] = d
		}
	}
	stats := map[string]*opStats{}
	to := now().UTC()
	visit := func(service, op string, status int, netErr string, latency int64) error {
		if docs[service] == nil || opExample(docs[service], op, 0) == "\x00" {
			return nil
		}
		k := service + "\x00" + op
		s := stats[k]
		if s == nil {
			s = &opStats{statuses: map[int]int64{}, nets: map[string]int64{}}
			stats[k] = s
		}
		s.total++
		if netErr != "" {
			s.nets[netErr]++
		} else if FaultStatusCode(status) {
			s.statuses[status]++
		}
		if len(s.lat) < maxS {
			s.lat = append(s.lat, latency)
		}
		return nil
	}
	// Only scalar columns are needed: no body is read or decoded when the
	// source can stream them, and the window comes in index order.
	q := intake.Query{From: to.Add(-win), To: to, ByTime: true}
	if g := contractsGroup(contracts); g != "" && e.Groups != nil {
		m, err := e.Groups.SourceGroups(ctx)
		if err != nil {
			return nil, err
		}
		q.SourceIDs = groupscope.Set{g}.Sources(m)
	}
	var err error
	if ms, ok := e.Events.(intake.MetaScanner); ok {
		err = ms.ScanMeta(ctx, q, func(m *intake.EventMeta) error {
			return visit(m.Service, m.Op, m.Status, m.NetError, m.LatencyMS)
		})
	} else {
		err = e.Events.Scan(ctx, q, func(se *intake.StoredEvent) error {
			ev := se.Event
			return visit(ev.Service, ev.Op, ev.Status, ev.NetError, ev.LatencyMS)
		})
	}
	if err != nil {
		return nil, err
	}
	out := &Faults{}
	k := int64(kMin)
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s := stats[key]
		svc, op, _ := strings.Cut(key, "\x00")
		fo := FaultOp{Service: svc, Op: op}
		for _, code := range sortedInts(s.statuses) {
			if n := s.statuses[code]; n >= k {
				fo.Statuses = append(fo.Statuses, FaultStatus{Status: code, P: float64(n) / float64(s.total), Example: opExample(docs[svc], op, code)})
			}
		}
		for _, kind := range sortedStr(s.nets) {
			if n := s.nets[kind]; n >= k {
				fo.NetErrors = append(fo.NetErrors, FaultNet{Kind: kind, P: float64(n) / float64(s.total)})
			}
		}
		if s.total >= k && len(s.lat) > 0 {
			sort.Slice(s.lat, func(i, j int) bool { return s.lat[i] < s.lat[j] })
			q := func(p float64) int64 { return s.lat[int(math.Ceil(p*float64(len(s.lat))))-1] }
			fo.P50, fo.P95, fo.P99 = max(1, q(0.5)), max(1, q(0.95)), max(1, q(0.99))
		}
		if len(fo.Statuses) > 0 || len(fo.NetErrors) > 0 || fo.P50 > 0 {
			out.Ops = append(out.Ops, fo)
		}
	}
	return out, nil
}

// FaultStatusCode reports whether a status is an outcome the caller does
// not decide, replayed by `tt mock --faults observed` at its observed
// frequency: server errors (>= 500), 408 and 429, and the business
// refusals of a dependency that the request alone does not explain — 402
// (payment declined), 409 (conflict: a book with no copies left), 423, 424
// and 425. Statuses that follow from the request or from the state (400,
// 401, 403, 404, 422) are the contract's and the rules' business, never
// random faults.
func FaultStatusCode(status int) bool {
	switch {
	case status >= 500 && status <= 599:
		return true
	}
	switch status {
	case 402, 408, 409, 423, 424, 425, 429:
		return true
	}
	return false
}

// opExample returns the first named example of status for op ("" if none);
// "\x00" when op is not in the contract.
func opExample(doc map[string]any, op string, status int) string {
	m, p, ok := strings.Cut(op, " ")
	paths, _ := doc["paths"].(map[string]any)
	item, _ := paths[p].(map[string]any)
	o, _ := item[strings.ToLower(m)].(map[string]any)
	if !ok || o == nil {
		return "\x00"
	}
	if status == 0 {
		return ""
	}
	resps, _ := o["responses"].(map[string]any)
	r, _ := resps[strconv.Itoa(status)].(map[string]any)
	content, _ := r["content"].(map[string]any)
	for _, ct := range sortedStr(content) {
		mt, _ := content[ct].(map[string]any)
		ex, _ := mt["examples"].(map[string]any)
		if names := sortedStr(ex); len(names) > 0 {
			return names[0]
		}
	}
	return ""
}

func sortedInts[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedStr[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
