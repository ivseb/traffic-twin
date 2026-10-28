package mock

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/pack"
)

// model is the immutable, compiled form of a verified pack. It is shared by
// all sessions.
type model struct {
	pack     *pack.Pack
	services []*service
	byName   map[string]*service
	byHost   map[string]*service
	entities map[string]*entityDef
	entOrder []string
	causal   []*causalRule
	// limits are the response effects with a counter (rules v1.8).
	limits []*limitDef
	// Rules v1.9 (wave4.go): preconditions, customer attributes by name and
	// their response members by service\x00op, aggregates by service\x00op,
	// the operations that move a delta, list operations no entity reads.
	untils     []*untilDef
	attrBy     map[string]*pack.Attribute
	attrFields map[string][]attrField
	aggs       map[string][]*aggDef
	deltaOps   map[string]bool
	listOps    map[string]*listOpDef
	batch      []*batchRule
	ruleInfo   map[string]ruleInfo
	faults     map[string]*pack.FaultOp
	prefixes   map[string]string // id domain -> id prefix (the first entity of the domain)
	// svcPrefixes are the prefixes of each service's own entities: two
	// teams' entities can share a domain (docs/spec/rules.md 2.7).
	svcPrefixes map[string]map[string]string
	custs       []pack.Customer
	custByID    map[string]*pack.Customer
	t0          time.Time
	reads       map[string][]*readDef // service\x00op -> entities exposed by that operation
	presets     []*pack.Scenario
	presetBy    map[string]*pack.Scenario
	// causalBy maps a rule id to its compiled rule; histTimes holds the first
	// and last history instant of each world entity (entity\x00id).
	causalBy  map[string]*causalRule
	histTimes map[string][2]time.Time
	// fmts are the id formats by id domain (x-tt-value.id_format of the
	// contracts, docs/spec/pack.md 4.3).
	fmts map[string]*idfmt.Template
	// upserts are the writes of keyed entities by service\x00op (rules
	// v1.6); bodyRefs the request body members an operation selects or
	// keys with (exposed to the reads as parameters named by their path).
	upserts  map[string][]*upsertDef
	bodyRefs map[string][]compiledRef
}

// upsertDef is a write that creates or replaces a keyed record.
type upsertDef struct {
	ent       *entityDef
	key       map[string]compiledRef
	statePath []pathSeg
	hasState  bool
}

type ruleInfo struct {
	title    string
	outcomes []string
	causal   bool
}

type service struct {
	name  string
	alias string
	c     *contract
}

type compiledRef struct {
	ref  pack.Ref
	segs []pathSeg
}

type readDef struct {
	ent    *entityDef
	svc    *service // the service that exposes the operation
	rb     pack.ReadBy
	by     compiledRef
	hasBy  bool
	owner  bool // by.owner
	at     []pathSeg
	list   bool // at ends in [*]
	scoped bool // scope: owner
	forbid bool // foreign: forbidden
	// key selects the record of a keyed entity (rules v1.6).
	key map[string]compiledRef
	// list shape paths
	countSegs, totalSegs, nextSegs []pathSeg
}

type entityDef struct {
	def       pack.Entity
	svc       *service
	createOp  string
	statePath []pathSeg
	hasState  bool
	idSegs    []pathSeg // created_by.id when it points into resp.body
	relations map[string]bool
}

type causalRule struct {
	r        pack.CausalRule
	svc      *service
	binds    map[string]compiledRef
	bindKeys []string
	effByID  map[string]*pack.Effect
	inBranch map[string]map[string]bool // outcome -> effect ids
	// match and outWhen are the conditions of the cause and of the
	// outcomes (rules v1.9).
	match   []compiledMatch
	outWhen map[string][]compiledMatch
}

type batchRule struct {
	r    pack.BatchRule
	cron *cronSpec
}

func compileModel(p *pack.Pack) (*model, error) {
	m := &model{
		pack:     p,
		byName:   map[string]*service{},
		byHost:   map[string]*service{},
		entities: map[string]*entityDef{},
		ruleInfo: map[string]ruleInfo{},
		faults:   map[string]*pack.FaultOp{},
		prefixes: map[string]string{}, svcPrefixes: map[string]map[string]string{},
		custByID:  map[string]*pack.Customer{},
		t0:        p.World.T0,
		reads:     map[string][]*readDef{},
		presetBy:  map[string]*pack.Scenario{},
		causalBy:  map[string]*causalRule{},
		histTimes: map[string][2]time.Time{},
		fmts:      map[string]*idfmt.Template{},
		upserts:   map[string][]*upsertDef{},
		bodyRefs:  map[string][]compiledRef{},
	}
	names := make([]string, 0, len(p.Contracts))
	for n := range p.Contracts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for d, t := range idfmt.Templates(idfmt.Collect(p.Contracts[n])) {
			if m.fmts[d] == nil {
				m.fmts[d] = t
			}
		}
	}
	for _, h := range p.World.History {
		at, _ := time.Parse(time.RFC3339, h.At)
		k := h.Entity + "\x00" + h.ID
		ht, ok := m.histTimes[k]
		if !ok || at.Before(ht[0]) {
			ht[0] = at
		}
		if !ok || at.After(ht[1]) {
			ht[1] = at
		}
		m.histTimes[k] = ht
	}
	for _, ms := range p.Manifest.Services {
		c, err := compileContract(ms.Name, p.Contracts[ms.Name])
		if err != nil {
			return nil, fmt.Errorf("contract of %s: %w", ms.Name, err)
		}
		s := &service{name: ms.Name, alias: ms.UpstreamAlias, c: c}
		m.services = append(m.services, s)
		m.byName[ms.Name] = s
		for _, h := range hostKeys(ms) {
			m.byHost[h] = s
		}
	}

	for _, e := range p.Rules.Entities {
		svc := m.byName[e.Service]
		ed := &entityDef{def: e, svc: svc, relations: map[string]bool{}}
		for _, rel := range e.Relations {
			ed.relations[rel.Field] = true
		}
		m.entities[e.Name] = ed
		m.entOrder = append(m.entOrder, e.Name)
		if _, ok := m.prefixes[e.IDDomain]; !ok {
			m.prefixes[e.IDDomain] = e.IDPrefix
		}
		if m.svcPrefixes[e.Service] == nil {
			m.svcPrefixes[e.Service] = map[string]string{}
		}
		m.svcPrefixes[e.Service][e.IDDomain] = e.IDPrefix
		if cb := e.CreatedBy; cb != nil {
			if svc.c.byKey[cb.Op] == nil {
				return nil, fmt.Errorf("entity %s: created_by.op %q is not in the contract of %s", e.Name, cb.Op, e.Service)
			}
			ed.createOp = cb.Op
			if cb.State != nil {
				segs, err := parseTTPath(cb.State.Path)
				if err != nil {
					return nil, fmt.Errorf("entity %s: %w", e.Name, err)
				}
				ed.statePath, ed.hasState = segs, true
			}
			if cb.ID.From == "resp.body" {
				segs, err := parseTTPath(cb.ID.Path)
				if err != nil {
					return nil, fmt.Errorf("entity %s: %w", e.Name, err)
				}
				ed.idSegs = segs
			}
		}
		for _, rb := range shareHiddenWhen(e.ReadBy) {
			exp := svc
			if rb.Service != "" {
				exp = m.byName[rb.Service]
			}
			if exp == nil || exp.c.byKey[rb.Op] == nil {
				return nil, fmt.Errorf("entity %s: read_by.op %q is not in the contract of %s", e.Name, rb.Op, serviceName(exp, rb.Service))
			}
			at, err := parseTTPath(rb.At.Path)
			if err != nil {
				return nil, fmt.Errorf("entity %s: %w", e.Name, err)
			}
			rd := &readDef{ent: ed, svc: exp, rb: rb, at: at, scoped: rb.Scope == "owner", forbid: rb.Foreign == "forbidden"}
			key := exp.name + "\x00" + rb.Op
			if rb.By != nil {
				rd.hasBy = true
				rd.owner = rb.By.Owner
				rd.by = compiledRef{ref: *rb.By}
				if rb.By.Path != "" {
					if rd.by.segs, err = parseTTPath(rb.By.Path); err != nil {
						return nil, fmt.Errorf("entity %s: %w", e.Name, err)
					}
					m.bodyRefs[key] = append(m.bodyRefs[key], rd.by)
				}
			}
			if len(rb.Key) > 0 {
				if rd.key, err = compileKeyRefs(rb.Key); err != nil {
					return nil, fmt.Errorf("entity %s: %w", e.Name, err)
				}
				for _, f := range refKeys(rd.key) {
					if rd.key[f].segs != nil {
						m.bodyRefs[key] = append(m.bodyRefs[key], rd.key[f])
					}
				}
			}
			if n := len(at); n > 0 && at[n-1].kind == segAnyIdx {
				rd.list = true
			}
			if _, err := nest(at, nil); err != nil {
				return nil, fmt.Errorf("entity %s: read_by.at: %w", e.Name, err)
			}
			if l := rb.List; l != nil {
				for _, pp := range []struct {
					src string
					dst *[]pathSeg
				}{{l.Count, &rd.countSegs}, {l.Total, &rd.totalSegs}, {l.NextCursor, &rd.nextSegs}} {
					if pp.src == "" {
						continue
					}
					if *pp.dst, err = parseTTPath(pp.src); err != nil {
						return nil, fmt.Errorf("entity %s: %w", e.Name, err)
					}
				}
			}
			m.reads[key] = append(m.reads[key], rd)
		}
		for _, u := range e.UpsertedBy {
			if e.Key == nil {
				continue
			}
			exp := svc
			if u.Service != "" {
				exp = m.byName[u.Service]
			}
			if exp == nil || exp.c.byKey[u.Op] == nil {
				return nil, fmt.Errorf("entity %s: upserted_by.op %q is not in the contract of %s", e.Name, u.Op, serviceName(exp, u.Service))
			}
			ud := &upsertDef{ent: ed}
			var err error
			if ud.key, err = compileKeyRefs(u.Key); err != nil {
				return nil, fmt.Errorf("entity %s: %w", e.Name, err)
			}
			if u.State != nil {
				if ud.statePath, err = parseTTPath(u.State.Path); err != nil {
					return nil, fmt.Errorf("entity %s: %w", e.Name, err)
				}
				ud.hasState = true
			}
			key := exp.name + "\x00" + u.Op
			for _, f := range refKeys(ud.key) {
				if ud.key[f].segs != nil {
					m.bodyRefs[key] = append(m.bodyRefs[key], ud.key[f])
				}
			}
			m.upserts[key] = append(m.upserts[key], ud)
		}
	}

	for i := range p.Rules.Causal {
		r := p.Rules.Causal[i]
		svc := m.byName[r.Cause.Service]
		if svc.c.byKey[r.Cause.Op] == nil {
			return nil, fmt.Errorf("rule %s: cause op %q is not in the contract of %s", r.ID, r.Cause.Op, svc.name)
		}
		cr := &causalRule{r: r, svc: svc, binds: map[string]compiledRef{}, effByID: map[string]*pack.Effect{}, inBranch: map[string]map[string]bool{}}
		for name, ref := range r.Cause.Bind {
			cref := compiledRef{ref: ref}
			if ref.Path != "" {
				segs, err := parseTTPath(ref.Path)
				if err != nil {
					return nil, fmt.Errorf("rule %s: %w", r.ID, err)
				}
				cref.segs = segs
			}
			cr.binds[name] = cref
			cr.bindKeys = append(cr.bindKeys, name)
		}
		sort.Strings(cr.bindKeys)
		for j := range cr.r.Effects {
			cr.effByID[cr.r.Effects[j].ID] = &cr.r.Effects[j]
		}
		var names []string
		for _, o := range r.Outcomes {
			set := map[string]bool{}
			for _, id := range o.Effects {
				set[id] = true
			}
			cr.inBranch[o.Name] = set
			names = append(names, o.Name)
		}
		m.causal = append(m.causal, cr)
		m.ruleInfo[r.ID] = ruleInfo{title: r.Title, outcomes: names, causal: true}
	}
	sort.Slice(m.causal, func(i, j int) bool { return m.causal[i].r.ID < m.causal[j].r.ID })
	for _, c := range m.causal {
		m.causalBy[c.r.ID] = c
	}
	if err := m.compileResponds(); err != nil {
		return nil, err
	}
	m.compileLimits()
	if err := m.compileWave4(); err != nil {
		return nil, err
	}
	for _, b := range p.Rules.Batch {
		c, err := parseCron(b.Schedule)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", b.ID, err)
		}
		m.batch = append(m.batch, &batchRule{r: b, cron: c})
		m.ruleInfo[b.ID] = ruleInfo{title: b.Title}
	}

	for i := range p.Faults.Ops {
		op := &p.Faults.Ops[i]
		if m.byName[op.Service].c.byKey[op.Op] == nil {
			return nil, fmt.Errorf("faults: operation %q is not in the contract of %s", op.Op, op.Service)
		}
		m.faults[op.Service+"\x00"+op.Op] = op
	}
	if p.Scenarios != nil {
		for i := range p.Scenarios.Scenarios {
			sc := &p.Scenarios.Scenarios[i]
			if sc.Faults != nil {
				for _, fr := range sc.Faults.Rules {
					if fr.Op == "*" {
						continue
					}
					found := false
					for _, svc := range m.services {
						if (fr.Service == "*" || fr.Service == svc.name) && svc.c.byKey[fr.Op] != nil {
							found = true
						}
					}
					if !found {
						return nil, fmt.Errorf("preset %s: operation %q is not in the contracts", sc.ID, fr.Op)
					}
				}
			}
			m.presets = append(m.presets, sc)
			m.presetBy[sc.ID] = sc
		}
	}

	m.custs = append(m.custs, p.World.Customers...)
	sort.Slice(m.custs, func(i, j int) bool { return m.custs[i].ID < m.custs[j].ID })
	for i := range m.custs {
		m.custByID[m.custs[i].ID] = &m.custs[i]
	}
	// Each service's own entities' prefixes over the first entity of each
	// domain, computed once (the model is read by concurrent sessions).
	for svc, own := range m.svcPrefixes {
		merged := make(map[string]string, len(m.prefixes)+len(own))
		for d, p := range m.prefixes {
			merged[d] = p
		}
		for d, p := range own {
			merged[d] = p
		}
		m.svcPrefixes[svc] = merged
	}
	return m, nil
}

// compileKeyRefs compiles the request refs of a key (rules v1.6).
func compileKeyRefs(refs map[string]pack.Ref) (map[string]compiledRef, error) {
	out := map[string]compiledRef{}
	for f, r := range refs {
		c := compiledRef{ref: r}
		if r.Path != "" {
			segs, err := parseTTPath(r.Path)
			if err != nil {
				return nil, err
			}
			c.segs = segs
		}
		out[f] = c
	}
	return out, nil
}

// hostKeys are the Host header values that select a service: its name, its
// upstream alias, and the host part of a "host:" name.
func hostKeys(s pack.ManifestService) []string {
	var out []string
	if strings.HasPrefix(s.Name, "host:") {
		out = append(out, strings.TrimPrefix(s.Name, "host:"))
	} else {
		out = append(out, s.Name)
	}
	if s.UpstreamAlias != "" {
		out = append(out, s.UpstreamAlias)
	}
	return out
}

// serviceForHost picks the service for a Host header (port ignored, case
// insensitive). The first DNS label is accepted as a fallback so that
// "carrier.mock.internal" reaches the service aliased "carrier".
func (m *model) serviceForHost(host string) *service {
	host = strings.ToLower(host)
	if h, _, err := splitHostPort(host); err == nil {
		host = h
	}
	if s, ok := m.byHost[host]; ok {
		return s
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		if s, ok := m.byHost[host[:i]]; ok {
			return s
		}
	}
	return nil
}

func splitHostPort(h string) (string, string, error) {
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return h, "", fmt.Errorf("bad host")
		}
		return h[1:end], strings.TrimPrefix(h[end+1:], ":"), nil
	}
	i := strings.LastIndexByte(h, ':')
	if i < 0 || strings.Count(h, ":") > 1 {
		return h, "", fmt.Errorf("no port")
	}
	return h[:i], h[i+1:], nil
}

// exchange is what the rules can bind from: the request the mock received and
// the response it decided to give.
type exchange struct {
	reqBody    any
	pathParams map[string]string
	query      url.Values
	reqHeader  http.Header
	respBody   any
	respHeader http.Header
}

func evalRef(r compiledRef, ex *exchange) (any, bool) {
	switch r.ref.From {
	case "req.body":
		return first(evalPath(ex.reqBody, r.segs))
	case "resp.body":
		return first(evalPath(ex.respBody, r.segs))
	case "req.path":
		v, ok := ex.pathParams[r.ref.Name]
		return v, ok
	case "req.query":
		if !ex.query.Has(r.ref.Name) {
			return nil, false
		}
		return ex.query.Get(r.ref.Name), true
	case "req.headers":
		v := ex.reqHeader.Values(r.ref.Name)
		if len(v) == 0 {
			return nil, false
		}
		return v[0], true
	case "req.cookies":
		c, err := (&http.Request{Header: ex.reqHeader}).Cookie(r.ref.Name)
		if err != nil {
			return nil, false
		}
		return c.Value, true
	case "resp.headers":
		v := ex.respHeader.Values(r.ref.Name)
		if len(v) == 0 {
			return nil, false
		}
		return v[0], true
	}
	return nil, false
}

func first(vs []any) (any, bool) {
	if len(vs) == 0 {
		return nil, false
	}
	return vs[0], true
}

func serviceName(s *service, fallback string) string {
	if s != nil {
		return s.name
	}
	return fallback
}

// prefixesOf returns the id prefixes for the answers of a service: its own
// entities' prefixes over the first entity of each domain.
func (m *model) prefixesOf(svc string) map[string]string {
	if p := m.svcPrefixes[svc]; p != nil {
		return p
	}
	return m.prefixes
}
