package contract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Gap scopes: what a gap is about.
const (
	// ScopeOp: the operation as a whole (also gaps that have no finer place,
	// such as an entity nobody creates).
	ScopeOp = "op"
	// ScopeField: one field or parameter of a request or response.
	ScopeField = "field"
)

// Gap is a hole in what the contracts know ("buchi"): the admin API lists
// them so that people know what to capture or where the mock is guessing.
type Gap struct {
	// ID is stable across recomputations while the same hole exists: it
	// hashes the kind and where the hole is, not the counts.
	ID string `json:"id"`
	// Kind is one of the admin API kinds: few-samples, status-unseen,
	// rule-low-support, value-unknown, entity-without-creator.
	Kind    string `json:"kind"`
	Service string `json:"service"`
	// Group is the group of the contract the gap was found in ("" for the
	// gaps of the miner and of contracts of every group).
	Group string `json:"group,omitempty"`
	Op    string `json:"op,omitempty"`
	// Scope is ScopeOp or ScopeField.
	Scope  string `json:"scope"`
	Detail string `json:"detail"`
	Count  int64  `json:"count,omitempty"`
	// Threshold is the value Count is compared to (minimum samples, k, ...);
	// 0 when the kind has no numeric threshold.
	Threshold int64 `json:"threshold,omitempty"`
}

// NewGap builds a gap with its stable ID. at says where the hole is inside
// the operation (a field path, a message part); it is part of the ID.
func NewGap(kind, service, op, scope, at, detail string, count, threshold int64) Gap {
	h := sha256.Sum256([]byte(strings.Join([]string{kind, service, op, scope, at}, "\x00")))
	return Gap{ID: "gp-" + hex.EncodeToString(h[:6]), Kind: kind, Service: service, Op: op, Scope: scope, Detail: detail, Count: count, Threshold: threshold}
}

// GapSource lets other packages (the miner: rule-low-support,
// entity-without-creator) contribute gaps to the admin list.
type GapSource interface {
	Gaps(ctx context.Context) ([]Gap, error)
}

// Gaps computes the gaps of a contract:
//   - few-samples: operations with fewer than MinSamples calls, and optional
//     fields observed in fewer than MinSamples objects;
//   - status-unseen: operations with traffic that never returned a client
//     error (4xx) or a server error (5xx), so the KO scenarios are unknown;
//   - value-unknown: fields whose keep values are all hidden by the k
//     threshold (the mock has nothing to synthesize them from).
func (c *Contract) Gaps() []Gap {
	var out []Gap
	for _, op := range c.Ops {
		if op.RouteSource == "raw" {
			continue
		}
		if op.Calls < int64(c.MinSamples) {
			out = append(out, NewGap("few-samples", c.Service, op.Key, ScopeOp, "",
				fmt.Sprintf("only %d calls observed (minimum %d)", op.Calls, c.MinSamples), op.Calls, int64(c.MinSamples)))
			continue
		}
		var has4, has5 bool
		for _, r := range op.Responses {
			has4 = has4 || (r.Status >= 400 && r.Status < 500)
			has5 = has5 || r.Status >= 500
		}
		switch {
		case !has4 && !has5:
			out = append(out, NewGap("status-unseen", c.Service, op.Key, ScopeOp, "status", "no 4xx or 5xx response observed", op.Calls, 0))
		case !has4:
			out = append(out, NewGap("status-unseen", c.Service, op.Key, ScopeOp, "status", "no 4xx response observed", op.Calls, 0))
		case !has5:
			out = append(out, NewGap("status-unseen", c.Service, op.Key, ScopeOp, "status", "no 5xx response observed", op.Calls, 0))
		}
		for _, m := range op.Body {
			walkGaps(c, op, "req body", m.Schema, "$", &out)
		}
		for _, p := range op.Query {
			walkGaps(c, op, "req query "+p.Name, p.Schema, "", &out)
		}
		for _, r := range op.Responses {
			for _, m := range r.Body {
				walkGaps(c, op, fmt.Sprintf("resp %d body", r.Status), m.Schema, "$", &out)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Op != b.Op {
			return a.Op < b.Op
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
	// The same hole can be reached through several media types: one gap.
	seen := make(map[string]bool, len(out))
	uniq := out[:0]
	for _, g := range out {
		if !seen[g.ID] {
			seen[g.ID] = true
			uniq = append(uniq, g)
		}
	}
	return uniq
}

func walkGaps(c *Contract, op *Op, where string, s *Schema, path string, out *[]Gap) {
	if s == nil {
		return
	}
	loc := where
	if path != "" {
		loc += " " + path
	}
	if s.Kind == "shape" && s.EnumPartial && len(s.PublishedEnum()) == 0 && len(s.Enum) > 0 {
		*out = append(*out, NewGap("value-unknown", c.Service, op.Key, ScopeField, loc,
			loc+": every observed value is below the k threshold", s.Count, int64(c.KMin)))
	}
	for _, p := range s.Props {
		pp := ""
		if path != "" {
			pp = path + "." + p.Name
		}
		if !p.Required && p.Count < int64(c.MinSamples) && p.Count > 0 {
			*out = append(*out, NewGap("few-samples", c.Service, op.Key, ScopeField, where+" "+pp,
				fmt.Sprintf("%s: optional field observed in only %d objects", where+" "+pp, p.Count), p.Count, int64(c.MinSamples)))
		}
		walkGaps(c, op, where, p.Schema, pp, out)
	}
	if s.Items != nil {
		ip := ""
		if path != "" {
			ip = path + "[*]"
		}
		walkGaps(c, op, where, s.Items, ip, out)
	}
	if s.Additional != nil {
		ap := ""
		if path != "" {
			ap = path + ".*"
		}
		walkGaps(c, op, where, s.Additional, ap, out)
	}
}
