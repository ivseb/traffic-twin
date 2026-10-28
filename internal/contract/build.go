package contract

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Inferrer aggregates events into contracts. It is a streaming accumulator:
// memory depends on the number of distinct (service, op, field) and not on
// the number of events. It is not safe for concurrent use.
type Inferrer struct {
	cfg      Config
	hints    Hints
	services map[string]*svcAcc
}

type svcAcc struct {
	ops map[string]*opAcc
}

// NewInferrer returns an empty inferrer. hints may be nil.
func NewInferrer(cfg Config, hints Hints) *Inferrer {
	cfg.setDefaults()
	if hints == nil {
		hints = NoHints
	}
	return &Inferrer{cfg: cfg, hints: hints, services: map[string]*svcAcc{}}
}

// Config returns the effective configuration.
func (in *Inferrer) Config() Config { return in.cfg }

// SubjectFunc returns the subject of an event; it may consult other events
// (the inbound event of the same trace) and is called lazily.
type SubjectFunc func(ev *event.Event) string

// Add records one event. subject may be nil: the event's own subject is used.
func (in *Inferrer) Add(ev *event.Event, subject SubjectFunc) {
	svc := in.services[ev.Service]
	if svc == nil {
		svc = &svcAcc{ops: map[string]*opAcc{}}
		in.services[ev.Service] = svc
	}
	op := svc.ops[ev.Op]
	if op == nil {
		op = &opAcc{service: ev.Service, key: ev.Op, dir: ev.Dir}
		svc.ops[ev.Op] = op
	}
	c := &obsCtx{cfg: &in.cfg, at: ev.Time}
	c.subject = func() string {
		if ev.Subject != "" {
			return ev.Subject
		}
		if subject != nil {
			return subject(ev)
		}
		return ""
	}
	op.add(ev, c)
	op.addGraphQL(ev)
}

// SetGroup overrides the sampled counts of a (service, op, status) group
// with the exact ones from the store summaries (status 0 = network errors).
func (in *Inferrer) SetGroup(service, op string, status int, count int64, first, last time.Time) {
	svc := in.services[service]
	if svc == nil {
		return
	}
	o := svc.ops[op]
	if o == nil {
		return
	}
	// Several raw ops grouped into one inferred template add up.
	if status == 0 {
		o.netTot += count
	} else if sa := o.status[status]; sa != nil {
		sa.total += count
	}
	if f := first.UnixMilli(); o.firstExact == 0 || f < o.firstExact {
		o.firstExact = f
	}
	if l := last.UnixMilli(); l > o.lastExact {
		o.lastExact = l
	}
}

// Contracts finalizes the accumulated state: one contract per service,
// sorted by name, operations sorted by path then method.
func (in *Inferrer) Contracts(w Window) []*Contract {
	names := make([]string, 0, len(in.services))
	for n := range in.services {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*Contract, 0, len(names))
	for _, n := range names {
		out = append(out, in.finalizeService(n, w))
	}
	return out
}

func (in *Inferrer) finalizeService(name string, w Window) *Contract {
	svc := in.services[name]
	c := &Contract{Service: name, Window: w, KMin: in.cfg.KMin, MinSamples: in.cfg.MinSamples}
	keys := make([]string, 0, len(svc.ops))
	for k := range svc.ops {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		mi, pi, _ := event.ParseOp(keys[i])
		mj, pj, _ := event.ParseOp(keys[j])
		if pi != pj {
			return pi < pj
		}
		return mi < mj
	})
	for _, k := range keys {
		c.Ops = append(c.Ops, in.finalizeOp(svc.ops[k]))
	}
	c.GraphQL = graphqlSchemas(svc)
	return c
}

func (in *Inferrer) finalizeOp(o *opAcc) *Op {
	method, path, _ := event.ParseOp(o.key)
	out := &Op{Key: o.key, Method: method, Path: path, Dir: o.dir, RouteSource: modeKey(o.route)}
	out.GraphQL = o.gql.finalize(o.key)

	// Exact counts when the summaries were supplied.
	var statusSum, sampledStatus int64
	for _, sa := range o.status {
		statusSum += sa.count()
		sampledStatus += sa.n
	}
	netErrs := o.netTot
	out.Calls = statusSum + netErrs
	if out.Calls == 0 {
		out.Calls = o.n
	}
	first, last := o.first, o.last
	if o.firstExact != 0 {
		first = o.firstExact
	}
	if o.lastExact != 0 {
		last = o.lastExact
	}
	out.FirstSeen, out.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
	out.Latency = o.lat.latency()
	if len(o.netErr) > 0 {
		var sampled int64
		for _, n := range o.netErr {
			sampled += n
		}
		out.NetErrors = map[string]int64{}
		for k, n := range o.netErr {
			v := n
			if sampled > 0 && netErrs > 0 && netErrs != sampled {
				v = int64(math.Round(float64(n) * float64(netErrs) / float64(sampled)))
			}
			out.NetErrors[k] = v
		}
	}

	set := &o.ok
	if set.calls == 0 {
		set = &o.bad
	}
	loc := func(side, part, name string) Location {
		return Location{Service: o.service, Op: o.key, Side: side, Part: part, Name: name}
	}
	fin := newFinalizer(&in.cfg, in.hints)
	out.PathParams = fin.params(set.path, set.calls, true, func(n string) Location { return loc("req", "path", n) })
	out.Query = fin.params(set.query, set.calls, false, func(n string) Location { return loc("req", "query", n) })
	out.Headers = fin.params(set.headers, set.calls, false, func(n string) Location { return loc("req", "headers", n) })
	out.Cookies = fin.params(set.cookies, set.calls, false, func(n string) Location { return loc("req", "cookies", n) })
	out.Body = fin.media(set.body, "req", o)
	out.BodyCalls = set.bodyN
	out.ReqCalls = set.calls

	codes := make([]int, 0, len(o.status))
	for st := range o.status {
		codes = append(codes, st)
	}
	sort.Ints(codes)
	for _, st := range codes {
		sa := o.status[st]
		r := &Response{Status: st, Calls: sa.count(), Latency: sa.lat.latency(), BodyCalls: sa.bodyN}
		if out.Calls > 0 {
			r.Frequency = float64(r.Calls) / float64(out.Calls)
		}
		stloc := func(part string) func(string) Location {
			return func(n string) Location { return loc("resp", part, n) }
		}
		r.Headers = fin.params(sa.headers, sa.n, false, stloc("headers"))
		r.Cookies = fin.params(sa.cookies, sa.n, false, stloc("cookies"))
		r.Body = fin.media(sa.body, "resp", o)
		out.Responses = append(out.Responses, r)
	}
	return out
}

func (sa *statusAcc) count() int64 {
	if sa.total > 0 {
		return sa.total
	}
	return sa.n
}

func modeKey(m map[string]int64) string {
	best, bn := "", int64(-1)
	for k, n := range m {
		if n > bn || (n == bn && k < best) {
			best, bn = k, n
		}
	}
	return best
}

// ---------------------------------------------------------------------------

type finalizer struct {
	cfg   *Config
	hints Hints
}

func newFinalizer(cfg *Config, h Hints) *finalizer { return &finalizer{cfg: cfg, hints: h} }

func (f *finalizer) params(m map[string]*accParam, total int64, alwaysRequired bool, loc func(string) Location) []*Param {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*Param, 0, len(names))
	for _, n := range names {
		ap := m[n]
		p := &Param{Name: n, Count: ap.n, Multi: ap.multi > 0}
		if total > 0 {
			p.Presence = float64(ap.n) / float64(total)
		}
		p.Required = alwaysRequired || (total >= int64(f.cfg.MinSamples) && ap.n == total)
		if l := loc(n); p.Required && !alwaysRequired && l.Side == "req" && l.Part == "headers" && neverRequiredHeader(n) {
			p.Required = false
		}
		p.Schema = f.schema(&ap.node, loc(n), "")
		out = append(out, p)
	}
	return out
}

func (f *finalizer) media(m map[string]*bodyAcc, side string, o *opAcc) []*Media {
	if len(m) == 0 {
		return nil
	}
	cts := make([]string, 0, len(m))
	for ct := range m {
		cts = append(cts, ct)
	}
	sort.Strings(cts)
	out := make([]*Media, 0, len(cts))
	for _, ct := range cts {
		b := m[ct]
		md := &Media{CT: ct, Calls: b.n, Opaque: b.opaque, XML: xmlInfo(b)}
		if b.node != nil {
			md.Schema = f.schema(b.node, Location{Service: o.service, Op: o.key, Side: side, Part: "body", Name: "$"}, "$")
		}
		out = append(out, md)
	}
	return out
}

// xmlInfo is the XML envelope of a body, nil when no body of the media
// type was XML.
func xmlInfo(b *bodyAcc) *XMLInfo {
	if len(b.fmts) == 0 {
		return nil
	}
	x := &XMLInfo{Format: modeKey(b.fmts)}
	for path, toks := range b.ns {
		if x.Namespaces == nil {
			x.Namespaces = map[string]string{}
		}
		x.Namespaces[path] = modeKey(toks)
	}
	return x
}

// schema finalizes a node. path is the tt-path for body nodes ("" for
// parameters, whose location Name is the parameter name).
func (f *finalizer) schema(a *accNode, loc Location, path string) *Schema {
	s := &Schema{Count: a.n}
	for _, t := range typeOrder {
		cnt := a.types[t]
		if cnt == 0 {
			continue
		}
		if t == tInt && a.types[tNum] > 0 {
			continue // integer is a number
		}
		s.Types = append(s.Types, typeNames[t])
	}
	// Containers.
	s.Objects = a.objN
	if a.objN > 0 || a.addl != nil {
		names := make([]string, 0, len(a.props))
		for n := range a.props {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			ch := a.props[n]
			p := &Prop{Name: n, Count: ch.n}
			if a.objN > 0 {
				p.Presence = float64(ch.n) / float64(a.objN)
			}
			p.Required = a.objN >= int64(f.cfg.MinSamples) && ch.n == a.objN
			cl := loc
			cp := ""
			if path != "" {
				cp = path + "." + n
				cl.Name = cp
			}
			p.Schema = f.schema(ch, cl, cp)
			s.Props = append(s.Props, p)
		}
		f.conditions(a, s)
		f.dependencies(a, s)
		if a.addl != nil {
			cl, cp := loc, ""
			if path != "" {
				cp = path + ".*"
				cl.Name = cp
			}
			s.Additional = f.schema(a.addl, cl, cp)
		}
	}
	if a.arrN > 0 && a.items != nil {
		cl, cp := loc, ""
		if path != "" {
			cp = path + "[*]"
			cl.Name = cp
		}
		s.Items = f.schema(a.items, cl, cp)
		if a.lenInit && a.minLen >= 1 && a.arrN >= int64(f.cfg.MinSamples) && a.arrTrunc == 0 {
			v := a.minLen
			s.MinItems = &v
		}
	}
	if a.opaque > 0 && a.objN == 0 && a.arrN == 0 && len(s.Types) > 0 && (a.types[tObj] > 0 || a.types[tArr] > 0) {
		s.Opaque = true
	}
	f.scalar(a, s, loc)
	return s
}

var tokenFormats = map[string]string{
	"uuid": "uuid", "jwt": "", "email": "email", "datetime": "date-time", "date": "date",
	"url": "uri", "ipv4": "ipv4", "phone": "", "digits": "", "hex": "",
}

func (f *finalizer) scalar(a *accNode, s *Schema, loc Location) {
	strN := a.types[tStr]
	numLeaf := a.types[tInt] + a.types[tNum]
	switch {
	case strN > 0 && a.nGQL*2 >= strN:
		s.Kind = "graphql"
	case strN > 0 && a.nHMAC*2 >= strN:
		s.Kind = "id"
		s.Domain = f.hints.Domain(loc)
		if s.Domain == "" {
			s.Domain = "id"
		}
		s.LenClass = modeKey(a.idLen)
	case strN > 0 && a.nKeep > 0 && a.nKeep*2 >= strN:
		f.enum(a, s)
	case strN > 0 && a.nTime > 0 && a.nTime*2 >= strN:
		s.Kind = "bucket"
		s.Unit = modeKey(a.units)
		s.Format = "date-time"
		s.DateOffset = a.offs.dateOffset(f.cfg.KMin)
	case strN > 0 && a.nDrop > 0:
		s.Kind = "shape"
		var fmtBest string
		var fmtN, total, docN int64
		lens := map[string]int64{}
		docTypes, docClasses := map[string]int64{}, map[string]int64{}
		for k, n := range a.shape {
			total += n
			if r, ok := strings.CutPrefix(k, "doc:"); ok {
				docN += n
				typ, class, _ := strings.Cut(r, ":")
				docTypes[typ] += n
				docClasses[class] += n
				continue
			}
			if _, ok := tokenFormats[k]; ok {
				if n > fmtN || (n == fmtN && k < fmtBest) {
					fmtBest, fmtN = k, n
				}
			} else if event.ValidLenClass(k) {
				lens[k] = n
			}
		}
		if docN > 0 && docN*100 >= total*95 {
			// documents (mock.md 2.9): the most frequent type and class
			s.Shape = "doc"
			s.DocType = modeKey(docTypes)
			s.DocClass = modeKey(docClasses)
		} else if fmtN > 0 && fmtN*100 >= total*95 {
			s.Shape = fmtBest
			s.Format = tokenFormats[fmtBest]
		} else {
			s.LenClass = modeKey(lens)
		}
	case numLeaf > 0 && a.nBand*2 >= numLeaf && a.nBand > 0:
		f.bucket(a, s, loc)
	case numLeaf > 0 && a.nKeepNum > 0 && a.nKeepNum*2 >= numLeaf:
		f.enum(a, s)
	}
}

func (f *finalizer) enum(a *accNode, s *Schema) {
	vals := make([]EnumValue, 0, len(a.keeps))
	for _, v := range a.keeps {
		ev := EnumValue{Value: v.val, Count: v.n, Subjects: len(v.subj)}
		ev.Published = ev.Subjects >= f.cfg.KMin
		switch v.typ {
		case "s":
			ev.Type = "string"
		default:
			if isIntLexeme(v.val) {
				ev.Type = "integer"
			} else {
				ev.Type = "number"
			}
		}
		vals = append(vals, ev)
	}
	sort.Slice(vals, func(i, j int) bool {
		if vals[i].Type != vals[j].Type {
			return vals[i].Type < vals[j].Type
		}
		if vals[i].Type != "string" {
			fi, _ := strconv.ParseFloat(vals[i].Value, 64)
			fj, _ := strconv.ParseFloat(vals[j].Value, 64)
			if fi != fj {
				return fi < fj
			}
		}
		return vals[i].Value < vals[j].Value
	})
	s.Enum = vals
	s.EnumPartial = a.keepOver
	published := 0
	for _, v := range vals {
		if v.Published {
			published++
		} else {
			s.EnumPartial = true
		}
	}
	if a.keepOver && published == len(vals) && len(vals) >= f.cfg.MaxEnumValues {
		// Too many distinct values: not an enum.
		s.Enum = nil
		s.Kind = "shape"
		s.EnumPartial = true
		return
	}
	if published == 0 {
		s.Kind = "shape"
		s.EnumPartial = true
		return
	}
	s.Kind = "enum"
}

// bandKey classifies a num: token: ("<", lexeme), (">=", lexeme) or ("-", lo, hi).
func parseBand(tok string) (kind, lo, hi string, ok bool) {
	r, found := strings.CutPrefix(tok, "num:")
	if !found {
		return "", "", "", false
	}
	if x, ok := strings.CutPrefix(r, "<"); ok {
		return "<", x, "", true
	}
	if x, ok := strings.CutPrefix(r, ">="); ok {
		return ">=", x, "", true
	}
	for i := 1; i < len(r); i++ {
		if r[i] == '-' && r[i-1] != 'e' && r[i-1] != 'E' {
			return "-", r[:i], r[i+1:], true
		}
	}
	return "", "", "", false
}

func (f *finalizer) bucket(a *accNode, s *Schema, loc Location) {
	s.Kind = "bucket"
	bounds := f.hints.Bounds(loc)
	if len(bounds) == 0 {
		set := map[string]float64{}
		for tok := range a.bands {
			kind, lo, hi, ok := parseBand(tok)
			if !ok {
				continue
			}
			add := func(l string) {
				if v, err := strconv.ParseFloat(l, 64); err == nil {
					set[l] = v
				}
			}
			add(lo)
			if kind == "-" {
				add(hi)
			}
		}
		for l := range set {
			bounds = append(bounds, l)
		}
		sort.Slice(bounds, func(i, j int) bool {
			if set[bounds[i]] != set[bounds[j]] {
				return set[bounds[i]] < set[bounds[j]]
			}
			return bounds[i] < bounds[j]
		})
	}
	if len(bounds) == 0 {
		return
	}
	s.Bounds = bounds
	idx := make(map[string]int, len(bounds))
	for i, b := range bounds {
		idx[b] = i
	}
	p := make([]float64, len(bounds)+1)
	var total int64
	for _, b := range a.bands {
		total += b.n
	}
	for tok, b := range a.bands {
		kind, lo, _, ok := parseBand(tok)
		if !ok || total == 0 || len(b.subj) < f.cfg.KMin {
			continue
		}
		pos := -1
		switch kind {
		case "<":
			pos = 0
		case ">=":
			pos = len(bounds)
		case "-":
			if i, ok := idx[lo]; ok {
				pos = i + 1
			}
		}
		if pos >= 0 && pos < len(p) {
			p[pos] += float64(b.n) / float64(total)
		}
	}
	for i := range p {
		p[i] = round4(p[i])
	}
	s.BucketP = p
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }

// conditions sets Prop.When on the optional properties that exist only for
// some published values of a sibling enum. Only published values (seen for
// at least KMin subjects) are ever named.
func (f *finalizer) conditions(a *accNode, s *Schema) {
	if len(a.co) == 0 || a.objN < int64(f.cfg.MinSamples) {
		return
	}
	discs := make([]string, 0, len(a.co))
	for d := range a.co {
		discs = append(discs, d)
	}
	sort.Strings(discs)
	for _, p := range s.Props {
		if p.Required || p.Count == 0 {
			continue
		}
		var best *When
		for _, d := range discs {
			if d == p.Name {
				continue
			}
			dp := s.Prop(d)
			if dp == nil || dp.Schema == nil || dp.Schema.Kind != "enum" || !dp.Schema.HasType("string") {
				continue
			}
			published := map[string]bool{}
			for _, e := range dp.Schema.PublishedEnum() {
				if e.Type == "string" {
					published[e.Value] = true
				}
			}
			var in []string
			var inCount int64
			for val, cv := range a.co[d].vals {
				if !published[val] || cv.n == 0 {
					continue
				}
				if c := cv.props[p.Name]; c*10 >= cv.n*9 {
					in = append(in, val)
					inCount += c
				}
			}
			if len(in) == 0 || len(in) >= len(published) || inCount*100 < p.Count*98 {
				continue
			}
			sort.Strings(in)
			if best == nil || len(in) < len(best.In) {
				best = &When{Prop: d, In: in}
			}
		}
		p.When = best
	}
}
