package contract

import (
	"hash/fnv"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// JSON type indexes of accNode.types.
const (
	tNull = iota
	tBool
	tInt
	tNum
	tStr
	tObj
	tArr
	nTypes
)

var typeNames = [nTypes]string{"null", "boolean", "integer", "number", "string", "object", "array"}

// typeOrder is the order types appear in a union.
var typeOrder = [...]int{tObj, tArr, tStr, tNum, tInt, tBool, tNull}

// obsCtx carries per-event facts into the accumulators.
type obsCtx struct {
	cfg *Config
	// at is the instant of the exchange (relative dates, dateoffset.go)
	at time.Time
	// subject returns the subject of the event ("" when unknown). It is
	// called lazily, only when a value still needs distinct subjects.
	subject func() string
	subj    string
	subjSet bool
	subjH   uint64
	subjHOK bool
}

// subjectHash is a 64-bit hash of the subject (0, false when unknown): the
// joint value accumulators keep hashes, not tokens, to stay small.
func (c *obsCtx) subjectHash() (uint64, bool) {
	if !c.subjHOK {
		c.subjHOK = true
		if s := c.subjectOf(); s != "" {
			h := fnv.New64a()
			_, _ = h.Write([]byte(s))
			c.subjH = h.Sum64() | 1
		}
	}
	return c.subjH, c.subjH != 0
}

func (c *obsCtx) subjectOf() string {
	if !c.subjSet {
		c.subjSet = true
		if c.subject != nil {
			c.subj = c.subject()
		}
	}
	return c.subj
}

// valAcc counts a value and the distinct subjects it was seen for (capped
// at KMin: only "at least k" matters).
type valAcc struct {
	typ  string // enum value type; "" for bands
	val  string
	n    int64
	subj map[string]struct{}
}

func (v *valAcc) add(c *obsCtx) {
	v.n++
	if len(v.subj) >= c.cfg.KMin {
		return
	}
	if s := c.subjectOf(); s != "" {
		if v.subj == nil {
			v.subj = map[string]struct{}{}
		}
		v.subj[s] = struct{}{}
	}
}

// accNode accumulates the observations of one schema node.
type accNode struct {
	n     int64
	types [nTypes]int64

	// string leaves
	shape map[string]int64 // drop:str:<format|class> -> format or class
	nDrop int64
	nKeep int64
	nHMAC int64
	nTime int64
	nGQL  int64 // gql: tokens (sanitizer.md 5.7)
	idLen map[string]int64
	units map[string]int64
	offs  *offsetAcc // offsets of time buckets from the exchange instant

	// keep values (strings and numbers) and bucket bands
	keeps    map[string]*valAcc
	keepOver bool
	nKeepNum int64
	bands    map[string]*valAcc
	nBand    int64

	// objects
	objN      int64
	props     map[string]*accNode
	co        map[string]*coAcc // per low-cardinality string property: sibling presence by value
	joint     *jointAcc         // joint values of low-cardinality properties (x-tt-dependencies)
	addl      *accNode
	truncKeys int64

	// arrays
	arrN     int64
	items    *accNode
	minLen   int
	lenInit  bool
	arrTrunc int64

	opaque int64
}

func newNode() *accNode { return &accNode{} }

func bump(m *map[string]int64, k string) {
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[k]++
}

// observe records one occurrence of v.
func (a *accNode) observe(v *event.Value, c *obsCtx, depth int) {
	a.n++
	if depth > c.cfg.MaxDepth {
		a.opaque++
		return
	}
	switch v.Kind {
	case event.Null:
		a.types[tNull]++
	case event.Bool:
		a.types[tBool]++
	case event.Number:
		if isIntLexeme(v.S) {
			a.types[tInt]++
		} else {
			a.types[tNum]++
		}
		a.nKeepNum++
		a.keepValue("n", v.S, c)
	case event.String:
		a.token(v.S, c)
	case event.Array:
		a.types[tArr]++
		a.arrN++
		if a.items == nil {
			a.items = newNode()
		}
		cnt, trunc := 0, false
		for i := range v.A {
			e := &v.A[i]
			if e.Kind == event.String && event.ClassifyToken(e.S) == event.TokTrunc && strings.HasPrefix(e.S, "trunc:n:") {
				trunc = true
				continue
			}
			a.items.observe(e, c, depth+1)
			cnt++
		}
		if trunc {
			a.arrTrunc++
		} else if !a.lenInit || cnt < a.minLen {
			a.minLen, a.lenInit = cnt, true
		}
	case event.Object:
		a.types[tObj]++
		a.objN++
		a.observeCo(v, c)
		a.observeJoint(v, c)
		for i := range v.O {
			m := &v.O[i]
			switch m.K {
			case "{trunc}":
				a.truncKeys++
			case "{*}":
				if a.addl == nil {
					a.addl = newNode()
				}
				if m.V.Kind == event.Array {
					for k := range m.V.A {
						a.addl.observe(&m.V.A[k], c, depth+1)
					}
				} else {
					a.addl.observe(&m.V, c, depth+1)
				}
			default:
				ch := a.props[m.K]
				if ch == nil {
					if len(a.props) >= c.cfg.MaxProps {
						a.truncKeys++
						continue
					}
					if a.props == nil {
						a.props = map[string]*accNode{}
					}
					ch = newNode()
					a.props[m.K] = ch
				}
				ch.observe(&m.V, c, depth+1)
			}
		}
	}
}

// observeForm records a form-urlencoded body (name -> [token]); only the
// first value of each name is observed.
func (a *accNode) observeForm(v *event.Value, c *obsCtx) {
	a.n++
	a.types[tObj]++
	a.objN++
	for i := range v.O {
		m := &v.O[i]
		if m.K == "{trunc}" {
			a.truncKeys++
			continue
		}
		if m.K == "{*}" || m.V.Kind != event.Array || len(m.V.A) == 0 {
			continue
		}
		ch := a.props[m.K]
		if ch == nil {
			if len(a.props) >= c.cfg.MaxProps {
				a.truncKeys++
				continue
			}
			if a.props == nil {
				a.props = map[string]*accNode{}
			}
			ch = newNode()
			a.props[m.K] = ch
		}
		ch.observe(&m.V.A[0], c, 1)
	}
}

func isIntLexeme(s string) bool {
	if strings.ContainsAny(s, ".eE") {
		return false
	}
	return true
}

func (a *accNode) keepValue(typ, val string, c *obsCtx) {
	if a.keeps == nil {
		a.keeps = map[string]*valAcc{}
	}
	k := typ + ":" + val
	e := a.keeps[k]
	if e == nil {
		if len(a.keeps) >= c.cfg.MaxEnumValues {
			a.keepOver = true
			return
		}
		e = &valAcc{typ: typ, val: val}
		a.keeps[k] = e
	}
	e.add(c)
}

// token records a string leaf (a sanitizer token).
func (a *accNode) token(s string, c *obsCtx) {
	switch event.ClassifyToken(s) {
	case event.TokDrop:
		a.drop(s[len("drop:"):])
	case event.TokKeep:
		a.types[tStr]++
		a.nKeep++
		v, _ := event.KeepValue(s)
		a.keepValue("s", v, c)
	case event.TokHMAC:
		a.types[tStr]++
		a.nHMAC++
		bump(&a.idLen, event.LenClass(len(s)))
	case event.TokNum:
		a.types[tNum]++
		a.nBand++
		if a.bands == nil {
			a.bands = map[string]*valAcc{}
		}
		b := a.bands[s]
		if b == nil {
			if len(a.bands) >= 4*c.cfg.MaxEnumValues {
				return
			}
			b = &valAcc{val: s}
			a.bands[s] = b
		}
		b.add(c)
	case event.TokTime:
		a.types[tStr]++
		a.nTime++
		if u, ok := event.TimeTokenUnit(s); ok {
			bump(&a.units, u)
			a.observeOffset(s, c)
		}
	case event.TokTrunc:
		a.opaque++
	case event.TokGQL:
		a.types[tStr]++
		a.nGQL++
	}
}

func (a *accNode) drop(rest string) {
	switch rest {
	case "null":
		a.types[tNull]++
		return
	case "bool":
		a.types[tBool]++
		return
	case "int":
		a.types[tInt]++
		return
	case "dec":
		a.types[tNum]++
		return
	}
	switch {
	case strings.HasPrefix(rest, "str:"):
		a.types[tStr]++
		a.nDrop++
		bump(&a.shape, rest[len("str:"):])
	case strings.HasPrefix(rest, "doc:"), strings.HasPrefix(rest, "file:"):
		// a document (base64 in JSON, or a multipart file part):
		// drop:doc:<type>:<class> (docs/spec/sanitizer.md 22.3, 22.4)
		a.types[tStr]++
		a.nDrop++
		_, r, _ := strings.Cut(rest, ":")
		bump(&a.shape, "doc:"+r)
	case strings.HasPrefix(rest, "obj:"):
		a.types[tObj]++
		a.opaque++
	case strings.HasPrefix(rest, "arr:"):
		a.types[tArr]++
		a.opaque++
	default: // bytes forms: not a value of a JSON tree
		a.opaque++
	}
}

// ---------------------------------------------------------------------------
// Parameters (query, headers, cookies, path)

type accParam struct {
	n     int64
	multi int64
	node  accNode
}

func (p *accParam) observe(values []string, c *obsCtx) {
	p.n++
	if len(values) == 0 {
		return
	}
	if len(values) > 1 {
		p.multi++
	}
	v := event.Value{Kind: event.String, S: values[0]}
	p.node.observe(&v, c, 1)
}

// ---------------------------------------------------------------------------
// Latency quantiles: log-scale histogram with 1% relative error.

const histGamma = 1.01

var histLog = math.Log(histGamma)

type hist struct {
	n    int64
	zero int64
	bins map[int32]int64
}

func (h *hist) add(ms int64) {
	h.n++
	if ms <= 0 {
		h.zero++
		return
	}
	if h.bins == nil {
		h.bins = map[int32]int64{}
	}
	h.bins[int32(math.Ceil(math.Log(float64(ms))/histLog))]++
}

func (h *hist) quantile(q float64) int64 {
	if h.n == 0 {
		return 0
	}
	rank := int64(math.Ceil(q * float64(h.n)))
	if rank < 1 {
		rank = 1
	}
	if rank <= h.zero {
		return 0
	}
	idx := make([]int32, 0, len(h.bins))
	for k := range h.bins {
		idx = append(idx, k)
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i] < idx[j] })
	acc := h.zero
	for _, k := range idx {
		acc += h.bins[k]
		if acc >= rank {
			return int64(math.Round(2 * math.Pow(histGamma, float64(k)) / (histGamma + 1)))
		}
	}
	return 0
}

func (h *hist) latency() *Latency {
	if h.n == 0 {
		return nil
	}
	return &Latency{P50: h.quantile(0.50), P95: h.quantile(0.95), P99: h.quantile(0.99)}
}

// ---------------------------------------------------------------------------
// Operation accumulators

type bodyAcc struct {
	n      int64
	node   *accNode
	opaque map[string]int64
	// XML bodies (sanitizer.md 22.2, spec v1.19): the fmt of each body and
	// the namespace pattern of each element path, for a mock that answers
	// with the same envelope and namespaces.
	fmts map[string]int64
	ns   map[string]map[string]int64
}

// maxXMLNSPaths bounds the element paths of the namespaces kept per body
// (the sanitizer sends at most 64 per event).
const maxXMLNSPaths = 64

// observeXML records the fmt and the namespaces of an XML body.
func (b *bodyAcc) observeXML(fmt string, xmlns []event.XMLNSEntry) {
	if !event.IsXMLFmt(fmt) {
		return
	}
	bump(&b.fmts, fmt)
	for _, e := range xmlns {
		if e.Path == "{trunc}" {
			continue
		}
		m := b.ns[e.Path]
		if m == nil {
			if len(b.ns) >= maxXMLNSPaths {
				continue
			}
			if b.ns == nil {
				b.ns = map[string]map[string]int64{}
			}
			m = map[string]int64{}
			b.ns[e.Path] = m
		}
		if _, seen := m[e.Token]; seen || len(m) < 8 {
			m[e.Token]++
		}
	}
}

func (b *bodyAcc) observe(body *event.Value, ct string, c *obsCtx) {
	b.n++
	if body.Kind == event.String {
		switch event.ClassifyToken(body.S) {
		case event.TokDrop, event.TokTrunc:
			if strings.HasPrefix(body.S, "drop:bytes") || strings.HasPrefix(body.S, "trunc:") {
				bump(&b.opaque, body.S)
				return
			}
		}
	}
	if b.node == nil {
		b.node = newNode()
	}
	if (event.IsFormContentType(ct) || ct == event.CTMultipart) && body.Kind == event.Object {
		// a form, or a multipart body (sanitizer.md 22.3): name -> [values]
		b.node.observeForm(body, c)
		return
	}
	b.node.observe(body, c, 1)
}

// reqSet accumulates the request side of an operation.
type reqSet struct {
	calls   int64
	path    map[string]*accParam
	query   map[string]*accParam
	headers map[string]*accParam
	cookies map[string]*accParam
	body    map[string]*bodyAcc
	bodyN   int64
}

type statusAcc struct {
	n       int64
	total   int64 // exact count from the store summaries (0 = unknown)
	lat     hist
	headers map[string]*accParam
	cookies map[string]*accParam
	body    map[string]*bodyAcc
	bodyN   int64
}

type opAcc struct {
	service string
	key     string
	dir     string
	route   map[string]int64
	n       int64
	first   int64
	last    int64
	lat     hist
	netErr  map[string]int64
	netTot  int64
	ok      reqSet // requests of exchanges that ended below 400 or in a network error
	bad     reqSet // requests of exchanges with status >= 400
	status  map[int]*statusAcc
	// exact info from the summaries
	firstExact, lastExact int64
	gql                   *gqlAcc // GraphQL operations (graphql.go)
}

func addParams(m *map[string]*accParam, mu event.Multi, c *obsCtx, skipContentType bool) {
	for i := range mu {
		name := mu[i].Name
		if name == "{*}" || name == "{trunc}" {
			continue
		}
		if skipContentType && name == "content-type" {
			continue
		}
		if *m == nil {
			*m = map[string]*accParam{}
		}
		p := (*m)[name]
		if p == nil {
			if len(*m) >= c.cfg.MaxProps {
				continue
			}
			p = &accParam{}
			(*m)[name] = p
		}
		p.observe(mu[i].Values, c)
	}
}

func addBody(m *map[string]*bodyAcc, n *int64, body *event.Value, ct, fmt string, xmlns []event.XMLNSEntry, c *obsCtx) {
	if body == nil {
		return
	}
	*n++
	if *m == nil {
		*m = map[string]*bodyAcc{}
	}
	b := (*m)[ct]
	if b == nil {
		b = &bodyAcc{}
		(*m)[ct] = b
	}
	b.observe(body, ct, c)
	b.observeXML(fmt, xmlns)
}

func (rs *reqSet) add(ev *event.Event, op *opAcc, c *obsCtx) {
	rs.calls++
	// Path parameters: align the template with the end of the full path.
	if _, p, ok := event.ParseOp(ev.Op); ok {
		if tsegs, ok := event.OpSegments(p); ok {
			if rsegs, ok := event.SplitPath(ev.Req.Path); ok && len(rsegs) >= len(tsegs) {
				off := len(rsegs) - len(tsegs)
				for i, ts := range tsegs {
					if ts.Literal {
						continue
					}
					name := paramName(ts.Inner, i)
					if rs.path == nil {
						rs.path = map[string]*accParam{}
					}
					pp := rs.path[name]
					if pp == nil {
						pp = &accParam{}
						rs.path[name] = pp
					}
					rseg := rsegs[off+i]
					if rseg.Literal && ev.RouteSource == RouteInferred {
						// A literal the sanitizer kept as a word but that the
						// template turned into a parameter: only its shape.
						pp.observe([]string{literalShape(rseg.Inner)}, c)
					} else if rseg.Literal {
						pp.observe([]string{"keep:" + rseg.Inner}, c)
					} else {
						pp.observe([]string{rseg.Inner}, c)
					}
				}
			}
		}
	}
	addParams(&rs.query, ev.Req.Query, c, false)
	addParams(&rs.headers, ev.Req.Headers, c, true)
	addParams(&rs.cookies, ev.Req.Cookies, c, false)
	addBody(&rs.body, &rs.bodyN, ev.Req.Body, ev.Req.CT, ev.Req.Fmt, ev.Req.XMLNS, c)
}

// paramName returns the name of a template parameter, or "p<i+1>" when the
// segment is a sanitized token (raw operations).
func paramName(inner string, idx int) string {
	if validParamName(inner) {
		return inner
	}
	return "p" + strconv.Itoa(idx+1)
}

func validParamName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func (o *opAcc) add(ev *event.Event, c *obsCtx) {
	o.n++
	ms := ev.Time.UnixMilli()
	if o.first == 0 || ms < o.first {
		o.first = ms
	}
	if ms > o.last {
		o.last = ms
	}
	bump(&o.route, ev.RouteSource)
	o.lat.add(ev.LatencyMS)
	if ev.NetError != "" {
		bump(&o.netErr, ev.NetError)
		o.netTot++
		o.ok.add(ev, o, c)
		return
	}
	if o.status == nil {
		o.status = map[int]*statusAcc{}
	}
	sa := o.status[ev.Status]
	if sa == nil {
		sa = &statusAcc{}
		o.status[ev.Status] = sa
	}
	sa.n++
	sa.lat.add(ev.LatencyMS)
	if ev.Status >= 400 {
		o.bad.add(ev, o, c)
	} else {
		o.ok.add(ev, o, c)
	}
	if r := ev.Resp; r != nil {
		addParams(&sa.headers, r.Headers, c, true)
		addParams(&sa.cookies, r.Cookies, c, false)
		addBody(&sa.body, &sa.bodyN, r.Body, r.CT, r.Fmt, r.XMLNS, c)
	}
}

// ---------------------------------------------------------------------------
// Conditional presence: which sibling properties exist for each value of a
// low-cardinality string property (status -> cancelReason).

const (
	maxCoDiscriminators = 6
	maxCoMembers        = 48
)

type coAcc struct {
	vals map[string]*coVal
}

type coVal struct {
	n     int64
	props map[string]int64
}

// observeCo records, for every keep-string member of the object, the
// siblings present with it.
func (a *accNode) observeCo(v *event.Value, c *obsCtx) {
	if len(v.O) < 2 || len(v.O) > maxCoMembers {
		return
	}
	for i := range v.O {
		d := &v.O[i]
		if d.K == "{trunc}" || d.K == "{*}" || d.V.Kind != event.String || event.ClassifyToken(d.V.S) != event.TokKeep {
			continue
		}
		val, _ := event.KeepValue(d.V.S)
		co := a.co[d.K]
		if co == nil {
			if len(a.co) >= maxCoDiscriminators {
				continue
			}
			if a.co == nil {
				a.co = map[string]*coAcc{}
			}
			co = &coAcc{vals: map[string]*coVal{}}
			a.co[d.K] = co
		}
		cv := co.vals[val]
		if cv == nil {
			if len(co.vals) >= c.cfg.MaxEnumValues {
				continue
			}
			cv = &coVal{props: map[string]int64{}}
			co.vals[val] = cv
		}
		cv.n++
		for j := range v.O {
			if j != i && v.O[j].K != "{trunc}" && v.O[j].K != "{*}" {
				cv.props[v.O[j].K]++
			}
		}
	}
}
