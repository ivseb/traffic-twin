package packwriter

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Thresholds below which a pack is "poor": built on little traffic (the
// first minutes of a service). The pack is not refused: the answer carries
// the warnings, with the counts, so the console can say it before the mock
// is used (usability test 5: a pack built after a few minutes answered with
// the example status and a generic 402 body, and nothing said so).
const (
	// FewObservations is the least calls of an endpoint, or causes of a
	// rule, that make the pack reliable on it.
	FewObservations = 100
	// FewWindow is the least span of traffic behind a pack.
	FewWindow = time.Hour
	// maxPackWarnings bounds the list (PackInfo.WarningsTotal is the count).
	maxPackWarnings = 200
)

// observationWarnings lists what the pack rests on too little traffic for:
// the whole window, each approved rule (causes, and outcomes seen fewer
// than k times) and each endpoint (calls). Counts only, never values.
func observationWarnings(contracts []world.Contract, rules *world.Rules, kmin int, window [2]time.Time) []gate.PackWarning {
	var out []gate.PackWarning
	i64 := func(n int64) *int64 { return &n }
	if span := window[1].Sub(window[0]); !window[0].IsZero() && span < FewWindow {
		out = append(out, gate.PackWarning{Code: gate.WarnFewObservations, Scope: "pack", Unit: "minutes",
			Observed: i64(int64(span / time.Minute)), Needed: int64(FewWindow / time.Minute)})
	}
	if rules != nil {
		out = append(out, ruleWarnings(rules.Doc, kmin)...)
	}
	for _, c := range contracts {
		out = append(out, endpointWarnings(c)...)
	}
	return out
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func countOf(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

func ruleWarnings(doc map[string]any, kmin int) []gate.PackWarning {
	list, _ := doc["rules"].([]any)
	var out []gate.PackWarning
	i64 := func(n int64) *int64 { return &n }
	for _, it := range list {
		r := asMap(it)
		if st, ok := r["status"].(string); ok && st != "approved" {
			continue
		}
		id, _ := r["id"].(string)
		counts := asMap(asMap(r["evidence"])["counts"])
		cause := asMap(r["cause"])
		svc, _ := cause["service"].(string)
		op, _ := cause["op"].(string)
		if kind, _ := r["kind"].(string); kind == "batch" {
			if runs, ok := countOf(counts["runs"]); ok && runs < 3 {
				out = append(out, gate.PackWarning{Code: gate.WarnFewObservations, Scope: "rule", Rule: id, Unit: "runs", Observed: i64(runs), Needed: 3})
			}
			continue
		}
		if causes, ok := countOf(counts["causes"]); ok && causes < FewObservations {
			out = append(out, gate.PackWarning{Code: gate.WarnFewObservations, Scope: "rule", Rule: id, Service: svc, Op: op,
				Unit: "causes", Observed: i64(causes), Needed: FewObservations})
		}
		outs := asMap(counts["outcomes"])
		names := make([]string, 0, len(outs))
		for n := range outs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if c, ok := countOf(outs[n]); ok && c < int64(kmin) {
				out = append(out, gate.PackWarning{Code: gate.WarnFewObservations, Scope: "outcome", Rule: id, Service: svc, Op: op,
					Outcome: n, Unit: "outcomes", Observed: i64(c), Needed: int64(kmin)})
			}
		}
	}
	return out
}

// endpointWarnings reads the calls of each operation from the pack-safe
// contract: x-tt-observed.calls is there only when the operation was seen at
// least k times; its absence means "fewer than k".
func endpointWarnings(c world.Contract) []gate.PackWarning {
	var d struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(c.Doc, &d) != nil {
		return nil
	}
	var out []gate.PackWarning
	paths := make([]string, 0, len(d.Paths))
	for p := range d.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		methods := make([]string, 0, len(d.Paths[p]))
		for m := range d.Paths[p] {
			switch m {
			case "get", "put", "post", "delete", "patch", "head", "options":
				methods = append(methods, m)
			}
		}
		sort.Strings(methods)
		for _, m := range methods {
			var op struct {
				Observed struct {
					Calls *int64 `json:"calls"`
				} `json:"x-tt-observed"`
			}
			if json.Unmarshal(d.Paths[p][m], &op) != nil {
				continue
			}
			w := gate.PackWarning{Code: gate.WarnFewObservations, Scope: "endpoint", Service: c.Service, Op: strings.ToUpper(m) + " " + p,
				Unit: "calls", Needed: FewObservations}
			switch {
			case op.Observed.Calls == nil:
				w.BelowK = true
			case *op.Observed.Calls < FewObservations:
				w.Observed = op.Observed.Calls
			default:
				continue
			}
			out = append(out, w)
		}
	}
	return out
}

// capWarnings keeps the first maxPackWarnings (pack and rule warnings come
// first) and returns the total.
func capWarnings(ws []gate.PackWarning) ([]gate.PackWarning, int) {
	n := len(ws)
	if n > maxPackWarnings {
		ws = ws[:maxPackWarnings]
	}
	if ws == nil {
		ws = []gate.PackWarning{}
	}
	return ws, n
}
