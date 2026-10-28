package contract

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Severity of a change.
const (
	Breaking    = "breaking"
	NonBreaking = "non-breaking"
)

// Change is one difference between two contracts.
type Change struct {
	// Op is the operation key; empty for service-level changes.
	Op string `json:"op,omitempty"`
	// Where locates the change: "resp 200 application/json $.items[*].eta",
	// "req query orderId", "status 503".
	Where    string `json:"where"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	// Text is the human-readable description. It never contains enum
	// values or other data values, only names, types and counts; it is the
	// text sent to webhooks.
	Text string `json:"change"`
	// Values lists the enum values involved (admin API only, never sent to
	// webhooks).
	Values []string `json:"values,omitempty"`
	// CallsAfter is the number of calls of the operation in the newer
	// contract.
	CallsAfter int64 `json:"calls_after"`
	// Params are the figures and names behind Text, for a console that
	// writes the sentence in its own language from Kind: scope (request or
	// response, with status), part, name, status, from, to, count, pct,
	// required, ct. Never data values (the enum values are in Values).
	Params map[string]string `json:"params,omitempty"`
	// Shift, for a required-changed or presence change, is how far the
	// presence moved (0..1): a tiny shift is a sampling effect, not a change
	// of the API.
	Shift float64 `json:"-"`
}

// P builds Params from name/value pairs.
func P(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// DiffResult is the structured diff of two snapshots.
type DiffResult struct {
	Service     string        `json:"service"`
	From        *SnapshotInfo `json:"from,omitempty"`
	To          *SnapshotInfo `json:"to,omitempty"`
	Breaking    int           `json:"breaking"`
	NonBreaking int           `json:"non_breaking"`
	Changes     []Change      `json:"changes"`
}

// Count fills the Breaking and NonBreaking counters.
func (d *DiffResult) Count() {
	d.Breaking, d.NonBreaking = 0, 0
	for _, c := range d.Changes {
		if c.Severity == Breaking {
			d.Breaking++
		} else {
			d.NonBreaking++
		}
	}
}

type differ struct {
	cfg  DiffConfig
	op   string
	out  []Change
	next *Op
	ctx  string
	// scope and rstatus are ctx in structured form.
	scope   string
	rstatus int
}

func (d *differ) add(where, kind, sev, text string, params map[string]string, values ...string) {
	d.addShift(where, kind, sev, text, params, 0, values...)
}

func (d *differ) addShift(where, kind, sev, text string, params map[string]string, shift float64, values ...string) {
	if d.ctx != "" {
		text = d.ctx + ": " + text
	}
	if params == nil {
		params = map[string]string{}
	}
	if d.scope != "" {
		params["scope"] = d.scope
		if d.scope == "response" && d.rstatus != 0 {
			params["status"] = strconv.Itoa(d.rstatus)
		}
	}
	d.out = append(d.out, Change{Op: d.op, Where: where, Kind: kind, Severity: sev, Text: text, Values: values, CallsAfter: d.next.Calls, Params: params, Shift: shift})
}

// Diff compares an older contract with a newer one. The result is sorted and
// deterministic. Operations with fewer than cfg.MinCalls calls in either
// contract are compared only for presence.
func Diff(prev, next *Contract, cfg DiffConfig) []Change {
	if cfg.MinCalls <= 0 {
		cfg = DefaultConfig().Diff
	}
	var out []Change
	keys := map[string]bool{}
	for _, o := range prev.Ops {
		keys[o.Key] = true
	}
	for _, o := range next.Ops {
		keys[o.Key] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		a, b := prev.Op(k), next.Op(k)
		switch {
		case a != nil && b == nil:
			if a.Calls >= cfg.MinCalls {
				out = append(out, Change{Op: k, Where: "operation", Kind: "op-removed", Severity: Breaking,
					Text: "operation no longer observed"})
			}
		case a == nil && b != nil:
			if b.Calls >= cfg.MinCalls {
				out = append(out, Change{Op: k, Where: "operation", Kind: "op-added", Severity: NonBreaking,
					Text: "new operation observed", CallsAfter: b.Calls})
			}
		default:
			if a.Calls < cfg.MinCalls || b.Calls < cfg.MinCalls {
				continue
			}
			d := &differ{cfg: cfg, op: k, next: b}
			d.diffOp(a, b)
			out = append(out, d.out...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.Op != y.Op {
			return x.Op < y.Op
		}
		if x.Where != y.Where {
			return x.Where < y.Where
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		return x.Text < y.Text
	})
	return out
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", f*100) }

func (d *differ) diffOp(a, b *Op) {
	d.scope, d.rstatus = "", 0
	d.diffStatuses(a, b)
	d.ctx, d.scope = "request", "request"
	d.diffParams("req path", a.PathParams, b.PathParams, "req")
	d.diffParams("req query", a.Query, b.Query, "req")
	d.diffParams("req header", a.Headers, b.Headers, "req")
	d.diffParams("req cookie", a.Cookies, b.Cookies, "req")
	d.diffMedia("req", a.Body, b.Body, "req")
	for _, ra := range a.Responses {
		rb := b.Response(ra.Status)
		if rb == nil {
			continue
		}
		pre := fmt.Sprintf("resp %d", ra.Status)
		d.ctx, d.scope, d.rstatus = fmt.Sprintf("response %d", ra.Status), "response", ra.Status
		d.diffParams(pre+" header", ra.Headers, rb.Headers, "resp")
		d.diffMedia(pre, ra.Body, rb.Body, "resp")
	}
}

func (d *differ) diffStatuses(a, b *Op) {
	seen := map[int]bool{}
	var codes []int
	for _, r := range a.Responses {
		seen[r.Status] = true
		codes = append(codes, r.Status)
	}
	for _, r := range b.Responses {
		if !seen[r.Status] {
			codes = append(codes, r.Status)
		}
	}
	sort.Ints(codes)
	for _, st := range codes {
		ra, rb := a.Response(st), b.Response(st)
		where := fmt.Sprintf("status %d", st)
		isErr := st >= 400
		switch {
		case ra == nil:
			switch {
			case isErr && rb.Frequency >= d.cfg.FrequentStatus:
				d.add(where, "status-added", Breaking, fmt.Sprintf("new error status %d (%s of calls)", st, pct(rb.Frequency)), P("status", strconv.Itoa(st), "pct", pct(rb.Frequency), "rarity", "frequent"))
			case isErr:
				d.add(where, "status-added", NonBreaking, fmt.Sprintf("new rare error status %d (%s of calls)", st, pct(rb.Frequency)), P("status", strconv.Itoa(st), "pct", pct(rb.Frequency), "rarity", "rare"))
			default:
				d.add(where, "status-added", NonBreaking, fmt.Sprintf("new status %d (%s of calls)", st, pct(rb.Frequency)), P("status", strconv.Itoa(st), "pct", pct(rb.Frequency), "rarity", "ok"))
			}
		case rb == nil:
			if isErr {
				d.add(where, "status-removed", NonBreaking, fmt.Sprintf("error status %d no longer observed", st), P("status", strconv.Itoa(st), "rarity", "error"))
			} else if ra.Frequency >= d.cfg.FrequentStatus {
				d.add(where, "status-removed", Breaking, fmt.Sprintf("success status %d no longer observed", st), P("status", strconv.Itoa(st), "rarity", "success"))
			} else {
				d.add(where, "status-removed", NonBreaking, fmt.Sprintf("rare status %d no longer observed", st), P("status", strconv.Itoa(st), "rarity", "rare"))
			}
		default:
			delta := rb.Frequency - ra.Frequency
			switch {
			case isErr && ra.Frequency < d.cfg.FrequentStatus && rb.Frequency >= d.cfg.FrequentStatus && rb.Frequency >= 2*ra.Frequency:
				d.add(where, "status-frequent", Breaking, fmt.Sprintf("error status %d became frequent (%s -> %s)", st, pct(ra.Frequency), pct(rb.Frequency)), P("status", strconv.Itoa(st), "from", pct(ra.Frequency), "to", pct(rb.Frequency)))
			case delta >= d.cfg.FrequencyShift || -delta >= d.cfg.FrequencyShift:
				d.add(where, "frequency-changed", NonBreaking, fmt.Sprintf("frequency of status %d changed (%s -> %s)", st, pct(ra.Frequency), pct(rb.Frequency)), P("status", strconv.Itoa(st), "from", pct(ra.Frequency), "to", pct(rb.Frequency)))
			}
		}
	}
}

func paramMap(ps []*Param) map[string]*Param {
	m := make(map[string]*Param, len(ps))
	for _, p := range ps {
		m[p.Name] = p
	}
	return m
}

func sortedNames(a, b map[string]*Param) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (d *differ) diffParams(prefix string, as, bs []*Param, side string) {
	am, bm := paramMap(as), paramMap(bs)
	for _, n := range sortedNames(am, bm) {
		pa, pb := am[n], bm[n]
		where := prefix + " " + n
		label := fmt.Sprintf("%s '%s'", prefix, n)
		switch {
		case pa == nil:
			sev := NonBreaking
			if side == "req" && pb.Required && !strings.HasPrefix(prefix, "req path") {
				sev = Breaking
			}
			d.add(where, "param-added", sev, label+" added", P("part", prefix, "name", n))
		case pb == nil:
			sev := NonBreaking
			if side == "resp" && pa.Required {
				sev = Breaking
			}
			d.add(where, "param-removed", sev, label+" removed", P("part", prefix, "name", n))
		default:
			if pa.Required != pb.Required {
				sev := NonBreaking
				if (side == "req") == pb.Required {
					sev = Breaking
				}
				d.addShift(where, "required-changed", sev, fmt.Sprintf("%s required changed: %t -> %t", label, pa.Required, pb.Required),
					P("part", prefix, "name", n, "from", strconv.FormatBool(pa.Required), "to", strconv.FormatBool(pb.Required)), math.Abs(pa.Presence-pb.Presence))
			}
			d.diffSchema(where, label, n, pa.Schema, pb.Schema, side, false)
		}
	}
}

func mediaMap(ms []*Media) map[string]*Media {
	m := make(map[string]*Media, len(ms))
	for _, x := range ms {
		m[x.CT] = x
	}
	return m
}

func (d *differ) diffMedia(prefix string, as, bs []*Media, side string) {
	am, bm := mediaMap(as), mediaMap(bs)
	set := map[string]bool{}
	for k := range am {
		set[k] = true
	}
	for k := range bm {
		set[k] = true
	}
	cts := make([]string, 0, len(set))
	for k := range set {
		cts = append(cts, k)
	}
	sort.Strings(cts)
	for _, ct := range cts {
		ma, mb := am[ct], bm[ct]
		where := prefix + " body " + mediaType(ct)
		label := prefix + " body"
		switch {
		case ma == nil:
			d.add(where, "content-added", NonBreaking, fmt.Sprintf("%s content type %s added", label, mediaType(ct)), P("part", prefix, "ct", mediaType(ct)))
		case mb == nil:
			sev := NonBreaking
			if side == "resp" {
				sev = Breaking
			}
			d.add(where, "content-removed", sev, fmt.Sprintf("%s content type %s removed", label, mediaType(ct)), P("part", prefix, "ct", mediaType(ct)))
		case ma.Schema != nil && mb.Schema != nil:
			d.diffSchema(where+" $", label, "", ma.Schema, mb.Schema, side, true)
		}
	}
}

func typeDesc(s *Schema) string {
	if s == nil || len(s.Types) == 0 {
		return "any"
	}
	t := strings.Join(s.Types, "|")
	switch {
	case s.Format != "":
		t += "(" + s.Format + ")"
	case s.Shape != "":
		t += "(" + s.Shape + ")"
	case s.Kind == "id":
		t += "(id)"
	}
	return t
}

func typeSet(s *Schema) map[string]bool {
	m := map[string]bool{}
	if s != nil {
		for _, t := range s.Types {
			m[t] = true
		}
	}
	return m
}

func subtract(a, b map[string]bool) []string {
	var out []string
	for t := range a {
		if !b[t] {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// diffSchema compares two schemas. where is the location key, label the
// text prefix ("resp 200 field 'eta'" is built from it).
func (d *differ) diffSchema(where, label, name string, a, b *Schema, side string, root bool) {
	if a == nil || b == nil {
		return
	}
	ta, tb := typeSet(a), typeSet(b)
	added, removed := subtract(tb, ta), subtract(ta, tb)
	// integer -> number is a widening, number -> integer a narrowing.
	if len(added) == 1 && len(removed) == 1 && added[0] == "number" && removed[0] == "integer" {
		removed = nil
	} else if len(added) == 1 && len(removed) == 1 && added[0] == "integer" && removed[0] == "number" {
		added = nil
	}
	typeChanged := false
	switch {
	case len(added) > 0 && len(removed) > 0:
		typeChanged = true
		d.add(where, "type-changed", Breaking, fmt.Sprintf("%s type changed: %s -> %s", label, typeDesc(a), typeDesc(b)), P("name", name, "from", typeDesc(a), "to", typeDesc(b)))
	case len(added) > 0:
		typeChanged = true
		sev := NonBreaking
		if side == "resp" {
			sev = Breaking
		}
		d.add(where, "type-widened", sev, fmt.Sprintf("%s type widened: %s -> %s", label, typeDesc(a), typeDesc(b)), P("name", name, "from", typeDesc(a), "to", typeDesc(b)))
	case len(removed) > 0:
		typeChanged = true
		d.add(where, "type-narrowed", NonBreaking, fmt.Sprintf("%s type narrowed: %s -> %s", label, typeDesc(a), typeDesc(b)), P("name", name, "from", typeDesc(a), "to", typeDesc(b)))
	}
	if !typeChanged && (a.Format != b.Format || a.Shape != b.Shape) && len(a.Types) > 0 && a.HasType("string") && b.HasType("string") {
		d.add(where, "format-changed", Breaking, fmt.Sprintf("%s format changed: %s -> %s", label, typeDesc(a), typeDesc(b)), P("name", name, "from", typeDesc(a), "to", typeDesc(b)))
	}
	d.diffEnum(where, label, name, a, b)

	// Properties.
	names := map[string]bool{}
	for _, p := range a.Props {
		names[p.Name] = true
	}
	for _, p := range b.Props {
		names[p.Name] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	enough := a.Objects >= d.cfg.MinCalls && b.Objects >= d.cfg.MinCalls
	for _, n := range sorted {
		pa, pb := a.Prop(n), b.Prop(n)
		pw := where + "." + n
		if root || strings.HasSuffix(where, "$") {
			pw = where + "." + n
		}
		fl := fmt.Sprintf("field '%s'", n)
		switch {
		case pa == nil:
			if !enough {
				continue
			}
			sev := NonBreaking
			if side == "req" && pb.Required {
				sev = Breaking
			}
			kind := "field-added"
			txt := fl + " added"
			if pb.Required {
				txt += " (required)"
			} else {
				txt += fmt.Sprintf(" (optional, presence %s)", pct(pb.Presence))
			}
			d.add(pw, kind, sev, txt, P("name", n, "required", strconv.FormatBool(pb.Required), "pct", pct(pb.Presence)))
		case pb == nil:
			if !enough {
				continue
			}
			sev := NonBreaking
			if side == "resp" && (pa.Required || pa.Presence >= 0.5) {
				sev = Breaking
			}
			d.add(pw, "field-removed", sev, fl+" removed", P("name", n))
		default:
			if enough {
				switch {
				case pa.Required != pb.Required:
					sev := NonBreaking
					if (side == "req") == pb.Required {
						sev = Breaking
					}
					d.addShift(pw, "required-changed", sev, fmt.Sprintf("%s required changed: %t -> %t", fl, pa.Required, pb.Required),
						P("name", n, "from", strconv.FormatBool(pa.Required), "to", strconv.FormatBool(pb.Required)), math.Abs(pa.Presence-pb.Presence))
				case !pa.Required && !pb.Required:
					switch {
					case pa.Presence >= 0.5 && pb.Presence <= d.cfg.PresenceVanish:
						sev := NonBreaking
						if side == "resp" {
							sev = Breaking
						}
						d.add(pw, "field-vanished", sev, fmt.Sprintf("%s almost never present now (%s -> %s)", fl, pct(pa.Presence), pct(pb.Presence)), P("name", n, "from", pct(pa.Presence), "to", pct(pb.Presence)))
					case pa.Presence-pb.Presence >= d.cfg.PresenceDrop:
						d.addShift(pw, "presence-dropped", NonBreaking, fmt.Sprintf("%s presence dropped (%s -> %s)", fl, pct(pa.Presence), pct(pb.Presence)), P("name", n, "from", pct(pa.Presence), "to", pct(pb.Presence)), pa.Presence-pb.Presence)
					case pb.Presence-pa.Presence >= d.cfg.PresenceDrop:
						d.addShift(pw, "presence-increased", NonBreaking, fmt.Sprintf("%s presence increased (%s -> %s)", fl, pct(pa.Presence), pct(pb.Presence)), P("name", n, "from", pct(pa.Presence), "to", pct(pb.Presence)), pb.Presence-pa.Presence)
					}
				}
			}
			d.diffSchema(pw, fl, n, pa.Schema, pb.Schema, side, false)
		}
	}
	if a.Items != nil && b.Items != nil {
		d.diffSchema(where+"[*]", label+" items", name+"[*]", a.Items, b.Items, side, false)
	}
	if a.Additional != nil && b.Additional != nil {
		d.diffSchema(where+".*", label+" map values", name+".*", a.Additional, b.Additional, side, false)
	}
}

func (d *differ) diffEnum(where, label, name string, a, b *Schema) {
	if len(a.Enum) == 0 && len(b.Enum) == 0 {
		return
	}
	bAll := map[string]bool{}
	for _, e := range b.Enum {
		bAll[e.Type+":"+e.Value] = true
	}
	aAll := map[string]bool{}
	for _, e := range a.Enum {
		aAll[e.Type+":"+e.Value] = true
	}
	var removed, added []string
	for _, e := range a.Enum {
		if e.Published && !bAll[e.Type+":"+e.Value] {
			removed = append(removed, e.Value)
		}
	}
	for _, e := range b.Enum {
		if e.Published && !aAll[e.Type+":"+e.Value] {
			added = append(added, e.Value)
		}
	}
	if len(removed) > 0 {
		d.add(where, "enum-removed", Breaking, fmt.Sprintf("%s enum: %d value(s) removed", label, len(removed)), P("name", name, "count", strconv.Itoa(len(removed))), removed...)
	}
	if len(added) > 0 {
		d.add(where, "enum-added", NonBreaking, fmt.Sprintf("%s enum: %d value(s) added", label, len(added)), P("name", name, "count", strconv.Itoa(len(added))), added...)
	}
}
