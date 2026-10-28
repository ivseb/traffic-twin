package fleet

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// Discovery for the policy assistant (ARCHITECTURE 3.4 step 5).
//
// Under the onboarding starter policy no operation is declared: every event
// is on a raw route, its op is the method plus the sanitized path, whose
// value segments already left the source as shapes
// ("GET /orders/{drop:str:l32}"). The assistant turns those into operation
// templates ("GET /orders/{id}"): a segment that is a shape is a parameter,
// and so is a literal position with more than templateLiteralMax distinct
// words among the paths of the same service, method, length and leading
// segments (path words that are really values). The route template of the framework never leaves
// the source unless the policy declares it (docs/spec/sanitizer.md 3.3), so
// the cardinality of the segments is what tt-core can use; a template that
// is structurally equal to a declared operation takes the declared key.

// DiscoveredField is what the intake knows about one discovery path of an
// operation.
type DiscoveredField struct {
	Service string // as in the events: a service name or host:<pattern>
	Op      string // operation template
	// Path is the discovery key (sanitizer.md 15), e.g.
	// "resp.body.items[*].status"; path segments are "req.path.<param>".
	Path string
	// Distinct is the HyperLogLog estimate of distinct values.
	Distinct int
	// Observed counts the stored events carrying the path (0 if unknown).
	Observed int64
	// Shape is the most frequent drop shape of the leaf, e.g.
	// "drop:str:l8", "drop:int", "drop:str:uuid" ("" if unknown).
	Shape string
}

// DiscoveredOp is one operation template seen under a policy.
type DiscoveredOp struct {
	Service string // as in the events
	Op      string // template, e.g. "GET /orders/{id}"
	Inbound bool
	// Calls counts the stored events of the operation.
	Calls int64
	// RawOps are some of the ops the template merges, as they left the
	// sources (shapes, never values).
	RawOps []string
	// GraphQL tells where the document of a GraphQL endpoint is when most
	// calls look like GraphQL exchanges (graphql.Candidate: json, query or
	// body); "" otherwise (sanitizer.md 5.7.5).
	GraphQL string
}

// AuthStat counts the inbound events of a service and those carrying an
// Authorization header (a candidate for identity.subject).
type AuthStat struct {
	Calls             int64
	WithAuthorization int64
}

// Discovery is what the assistant works from.
type Discovery struct {
	Ops    []DiscoveredOp
	Fields []DiscoveredField
	// Auth is keyed by inbound service.
	Auth map[string]AuthStat
	// Subjects is the number of distinct subject tokens among the inbound events
	// scanned (0 when the policy has no identity.subject): the users the sampling let through.
	Subjects int
	// LastSeen is the time of the last stored call of each service (the
	// sources the discovery covers); a host not called for a while next to
	// hosts called now is stale (an old port).
	LastSeen map[string]time.Time
}

// DiscoverySource provides the discovery data of a policy. declared lists
// the operation keys the policy declares per service. The intake implements
// it (IntakeDiscovery).
type DiscoverySource interface {
	Discover(ctx context.Context, policyID string, declared map[string][]string) (*Discovery, error)
}

// GroupDiscoverySource is a DiscoverySource that can restrict the traffic
// to some sources (one group's: the assistant never shows the hosts of
// another team). sources nil: every source.
type GroupDiscoverySource interface {
	DiscoverIn(ctx context.Context, policyID string, declared map[string][]string, sources []string) (*Discovery, error)
}

// templateLiteralMax is the number of distinct path words at one position
// above which the position is a parameter.
const templateLiteralMax = 10

// maxRawOps bounds the raw ops listed for a template.
const maxRawOps = 5

// MaxDiscoveryScan bounds the stored events scanned to compute operations,
// shapes and observation counts for the policy assistant.
const MaxDiscoveryScan = 20000

func splitSegs(path string) []string {
	p := strings.TrimPrefix(path, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func isParamSeg(s string) bool { return len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}' }

// singular turns a path word into a name: orders -> order, deliveries -> delivery.
func singular(w string) string {
	switch {
	case strings.HasSuffix(w, "ies") && len(w) > 3:
		return w[:len(w)-3] + "y"
	case strings.HasSuffix(w, "ss"):
		return w
	case strings.HasSuffix(w, "s") && len(w) > 1:
		return w[:len(w)-1]
	}
	return w
}

// paramName names a parameter after the closest literal before it
// ("/orders/{x}/items/{y}" -> orderId, itemId).
func paramName(segs []string, param []bool, i int) string {
	for j := i - 1; j >= 0; j-- {
		if param[j] {
			continue
		}
		var b strings.Builder
		for _, c := range singular(segs[j]) {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
				b.WriteRune(c)
			default:
				b.WriteByte('_')
			}
		}
		n := b.String() + "Id"
		if policy.ValidParamName(n) {
			return n
		}
		break
	}
	return "p" + strconv.Itoa(i)
}

// sameStructure reports whether two op keys have the same method, literals
// in the same positions and parameters in the same positions.
func sameStructure(a, b string) bool {
	ma, sa, ok1 := policy.ParseOpKey(a)
	mb, sb, ok2 := policy.ParseOpKey(b)
	if !ok1 || !ok2 || ma != mb || len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if (sa[i].Param != "") != (sb[i].Param != "") || sa[i].Literal != sb[i].Literal {
			return false
		}
	}
	return true
}

// templateOps maps (service, op as sent) to an operation template. Ops that
// cannot become a valid template are left out.
func templateOps(ops [][2]string, declared map[string][]string) map[[2]string]string {
	type parsed struct {
		key    [2]string
		method string
		segs   []string
	}
	groups := map[string][]parsed{}
	for _, k := range ops {
		method, path, ok := strings.Cut(k[1], " ")
		if !ok || method == "" {
			continue
		}
		segs := splitSegs(path)
		g := k[0] + "\x00" + method + "\x00" + strconv.Itoa(len(segs))
		groups[g] = append(groups[g], parsed{k, method, segs})
	}
	out := map[[2]string]string{}
	for _, ps := range groups {
		n := len(ps[0].segs)
		// Distinct words per position, among the paths with the same
		// segments before it (shapes counted as one).
		prefix := func(segs []string, i int) string {
			var b strings.Builder
			b.WriteString(strconv.Itoa(i))
			for _, s := range segs[:i] {
				if isParamSeg(s) {
					s = "{}"
				}
				b.WriteString("/" + s)
			}
			return b.String()
		}
		lits := map[string]map[string]bool{}
		for _, p := range ps {
			for i, s := range p.segs {
				if !isParamSeg(s) {
					k := prefix(p.segs, i)
					if lits[k] == nil {
						lits[k] = map[string]bool{}
					}
					lits[k][s] = true
				}
			}
		}
		for _, p := range ps {
			param := make([]bool, n)
			nparams := 0
			for i, s := range p.segs {
				if isParamSeg(s) || len(lits[prefix(p.segs, i)]) > templateLiteralMax {
					param[i] = true
					nparams++
				}
			}
			names := map[string]bool{}
			parts := make([]string, n)
			for i, s := range p.segs {
				if !param[i] {
					parts[i] = s
					continue
				}
				name := ""
				if isParamSeg(s) && policy.ValidParamName(s[1:len(s)-1]) {
					name = s[1 : len(s)-1] // already a template parameter
				}
				if name == "" {
					if nparams == 1 {
						name = "id"
					} else {
						name = paramName(p.segs, param, i)
					}
				}
				for base, j := name, 2; names[name]; j++ {
					name = base + strconv.Itoa(j)
				}
				names[name] = true
				parts[i] = "{" + name + "}"
			}
			tpl := p.method + " /" + strings.Join(parts, "/")
			if _, _, ok := policy.ParseOpKey(tpl); !ok {
				continue
			}
			for _, d := range declared[p.key[0]] {
				if sameStructure(tpl, d) {
					tpl = d
					break
				}
			}
			out[p.key] = tpl
		}
	}
	return out
}

// IntakeDiscovery adapts the intake to DiscoverySource: distinct counts
// come from the intake's HyperLogLog sketches (merged per template);
// operations, shapes and observation counts from the stored (already
// sanitized) events of the policy.
func IntakeDiscovery(in *intake.Intake) DiscoverySource { return intakeDiscovery{in} }

type intakeDiscovery struct{ in *intake.Intake }

type discStat struct {
	observed int64
	shapes   map[string]int64
}

func (st *discStat) add(o *discStat) {
	st.observed += o.observed
	for k, v := range o.shapes {
		st.shapes[k] += v
	}
}

func (st *discStat) best() string {
	var best int64
	shape := ""
	for sh, n := range st.shapes {
		if n > best || (n == best && sh < shape) {
			shape, best = sh, n
		}
	}
	return shape
}

func (d intakeDiscovery) Discover(ctx context.Context, policyID string, declared map[string][]string) (*Discovery, error) {
	return d.DiscoverIn(ctx, policyID, declared, nil)
}

// DiscoverIn implements GroupDiscoverySource.
func (d intakeDiscovery) DiscoverIn(ctx context.Context, policyID string, declared map[string][]string, sources []string) (*Discovery, error) {
	type opInfo struct {
		calls   int64
		inbound bool
		offset  int // req.path segments before the op path (a base path)
		seen    bool
		gql     map[string]int64 // graphql.Candidate -> calls
	}
	type fkey struct{ svc, op, path string }
	ops := map[[2]string]*opInfo{}
	pathsOf := map[[2]string][]string{}
	for _, s := range d.in.Discovery(policyID) {
		k := [2]string{s.Service, s.Op}
		pathsOf[k] = append(pathsOf[k], s.Path)
		if ops[k] == nil {
			ops[k] = &opInfo{}
		}
	}
	stats := map[fkey]*discStat{}
	auth := map[string]AuthStat{}
	subjects := map[string]struct{}{}
	// The intake never stores the disc field (docs/spec/event.md 5.3), so a
	// stored event no longer says which paths were discovered: look every
	// path the sketches know for its operation up in the body.
	err := d.in.Store().Scan(ctx, intake.Query{PolicyID: policyID, Limit: MaxDiscoveryScan, SourceIDs: sources}, func(se *intake.StoredEvent) error {
		ev := se.Event
		k := [2]string{ev.Service, event.HTTPOp(ev.Op)} // rules are per HTTP operation (event.md 6)
		oi := ops[k]
		if oi == nil {
			oi = &opInfo{}
			ops[k] = oi
		}
		oi.calls++
		if w := graphql.Candidate(ev); w != "" {
			if oi.gql == nil {
				oi.gql = map[string]int64{}
			}
			oi.gql[w]++
		}
		if !oi.seen {
			_, opPath, _ := strings.Cut(event.HTTPOp(ev.Op), " ")
			oi.offset, oi.seen = len(splitSegs(ev.Req.Path))-len(splitSegs(opPath)), true
		}
		if ev.Subject != "" {
			subjects[ev.Subject] = struct{}{}
		}
		if ev.Dir == event.Inbound {
			oi.inbound = true
			a := auth[ev.Service]
			a.Calls++
			if _, ok := ev.Req.Headers.Get("authorization"); ok {
				a.WithAuthorization++
			}
			auth[ev.Service] = a
		}
		for _, path := range pathsOf[k] {
			sh := ShapeAt(ev, path)
			if sh == "" {
				continue // the field is not a drop leaf of this event
			}
			fk := fkey{k[0], k[1], path}
			st := stats[fk]
			if st == nil {
				st = &discStat{shapes: map[string]int64{}}
				stats[fk] = st
			}
			st.observed++
			st.shapes[sh]++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	keys := make([][2]string, 0, len(ops))
	for k, oi := range ops {
		if sources != nil && oi.calls == 0 {
			continue // known to the sketches, never called by these sources
		}
		keys = append(keys, k)
	}
	tpl := templateOps(keys, declared)

	type agg struct {
		op     DiscoveredOp
		offset int
		segs   []policy.TemplateSeg
	}
	aggs := map[[2]string]*agg{}
	gqlOf := map[[2]string]map[string]int64{}
	for _, k := range keys {
		t, ok := tpl[k]
		if !ok {
			continue
		}
		ak := [2]string{k[0], t}
		a := aggs[ak]
		if a == nil {
			_, segs, _ := policy.ParseOpKey(t)
			a = &agg{op: DiscoveredOp{Service: k[0], Op: t}, segs: segs}
			aggs[ak] = a
		}
		oi := ops[k]
		a.op.Calls += oi.calls
		a.op.Inbound = a.op.Inbound || oi.inbound
		a.op.RawOps = append(a.op.RawOps, k[1])
		if oi.seen {
			a.offset = oi.offset
		}
		for w, n := range oi.gql {
			if gqlOf[ak] == nil {
				gqlOf[ak] = map[string]int64{}
			}
			gqlOf[ak][w] += n
		}
	}
	for ak, a := range aggs {
		// A GraphQL endpoint: most of its calls look like GraphQL exchanges.
		var best string
		var n int64
		for w, c := range gqlOf[ak] {
			if c > n || (c == n && w < best) {
				best, n = w, c
			}
		}
		if n > 0 && 2*n >= a.op.Calls {
			a.op.GraphQL = best
		}
	}
	tstats := map[fkey]*discStat{}
	for k, st := range stats {
		t, ok := tpl[[2]string{k.svc, k.op}]
		if !ok {
			continue
		}
		tk := fkey{k.svc, t, k.path}
		if tstats[tk] == nil {
			tstats[tk] = &discStat{shapes: map[string]int64{}}
		}
		tstats[tk].add(st)
	}
	out := &Discovery{Auth: auth, Subjects: len(subjects), LastSeen: map[string]time.Time{}}
	if hs, err := d.in.Store().HostStats(ctx); err == nil {
		in := map[string]bool{}
		for _, id := range sources {
			in[id] = true
		}
		for _, h := range hs {
			if h.PolicyID != policyID || (sources != nil && !in[h.SourceID]) {
				continue
			}
			if h.LastTS.After(out.LastSeen[h.Service]) {
				out.LastSeen[h.Service] = h.LastTS
			}
		}
	}
	for _, a := range aggs {
		sort.Strings(a.op.RawOps)
		if len(a.op.RawOps) > maxRawOps {
			a.op.RawOps = a.op.RawOps[:maxRawOps]
		}
		out.Ops = append(out.Ops, a.op)
	}
	sort.Slice(out.Ops, func(i, j int) bool {
		if out.Ops[i].Service != out.Ops[j].Service {
			return out.Ops[i].Service < out.Ops[j].Service
		}
		return out.Ops[i].Op < out.Ops[j].Op
	})
	merged := d.in.DiscoveryUnion(policyID, func(svc, op string) (string, bool) {
		if sources != nil && (ops[[2]string{svc, op}] == nil || ops[[2]string{svc, op}].calls == 0) {
			return "", false
		}
		t, ok := tpl[[2]string{svc, op}]
		return t, ok
	})
	for _, m := range merged {
		df := DiscoveredField{Service: m.Service, Op: m.Op, Path: m.Path, Distinct: m.Distinct}
		if st := tstats[fkey{m.Service, m.Op, m.Path}]; st != nil {
			df.Observed, df.Shape = st.observed, st.best()
		}
		if rest, ok := strings.CutPrefix(m.Path, "req.path."); ok {
			a := aggs[[2]string{m.Service, m.Op}]
			i, err := strconv.Atoi(rest)
			if a == nil || err != nil {
				continue
			}
			i -= a.offset
			if i < 0 || i >= len(a.segs) || a.segs[i].Param == "" {
				continue // a literal of the template (or of the base)
			}
			df.Path = "req.path." + a.segs[i].Param
		}
		out.Fields = append(out.Fields, df)
	}
	return out, nil
}
