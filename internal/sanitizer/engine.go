package sanitizer

import (
	"sort"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Engine is a verified policy prepared for sanitizing, bound to the local
// HMAC key selected for it (sanitizer 7.1). It is immutable and safe for
// concurrent use.
type Engine struct {
	p          *policy.Policy
	key        Key
	epoch      []byte
	allow      map[string]bool
	hostsAllow map[string]bool
	global     sides
	byName     map[string]*svcT // inbound services
	bases      []*svcT          // outbound services, most base segments first
}

// sides holds the rule sets for request, response and error response.
type sides struct {
	req, resp, respErr *ruleSet
}

type svcT struct {
	name     string
	internal bool
	base     policy.BaseURL
	origin   string
	ops      []*opT
	sides
}

type opT struct {
	key      string // "METHOD /template"
	method   string
	template string // "/template"
	segs     []policy.TemplateSeg
	literals int
	sides
}

// ruleSet is the merged view of every rule group that applies to one side
// of an exchange, in precedence order (section 5.0).
type ruleSet struct {
	path, query, headers, cookies map[string]*policy.Action
	body                          []cRule // sorted: the first match wins
}

type cRule struct {
	steps []policy.Step
	names int
	path  string
	group int
	act   *policy.Action
}

// NewEngine prepares a verified policy for sanitizing with the local keys.
// It fails with ErrKeyMissing or ErrKeyMismatch when no key can be used
// (the source must then not capture) and with a policy error when the body
// does not validate.
func NewEngine(p *policy.Policy, keys KeySet) (*Engine, error) {
	if p == nil {
		return nil, policy.ErrInvalid
	}
	if err := policy.ValidateSource(p); err != nil {
		return nil, err
	}
	k, err := keys.Select(p)
	if err != nil {
		return nil, err
	}
	e := &Engine{p: p, key: k, epoch: []byte(p.HMAC.Epoch), allow: map[string]bool{}, hostsAllow: map[string]bool{},
		byName: map[string]*svcT{}}
	for _, s := range p.Segments.Allow {
		e.allow[s] = true
	}
	for _, h := range p.Segments.HostsAllow {
		e.hostsAllow[h] = true
	}
	g := &p.Global
	e.global = sides{
		req:     buildRuleSet(&g.Request),
		resp:    buildRuleSet(&g.Response),
		respErr: buildRuleSet(nil, &g.Errors, &g.Response),
	}
	for i := range p.Services {
		s := &p.Services[i]
		st := &svcT{name: s.Name, internal: s.Match.Internal}
		st.sides = sides{
			req:     buildRuleSet(nil, &s.Request, &g.Request),
			resp:    buildRuleSet(nil, &s.Response, &g.Response),
			respErr: buildRuleSet(nil, &s.Errors, &g.Errors, &s.Response, &g.Response),
		}
		for j := range s.Ops {
			o := &s.Ops[j]
			method, segs, ok := policy.ParseOpKey(o.Op)
			if !ok {
				return nil, policy.ErrInvalid
			}
			ot := &opT{key: o.Op, method: method, template: o.Op[len(method)+1:], segs: segs}
			for _, sg := range segs {
				if sg.Param == "" {
					ot.literals++
				}
			}
			ot.sides = sides{
				req:     buildRuleSet(&o.Request, &s.Request, &g.Request),
				resp:    buildRuleSet(&o.Response, &s.Response, &g.Response),
				respErr: buildRuleSet(&o.Response, &s.Errors, &g.Errors, &s.Response, &g.Response),
			}
			st.ops = append(st.ops, ot)
		}
		if s.Match.Inbound {
			if _, dup := e.byName[s.Name]; !dup { // first entry wins (duplicates are a compile error)
				e.byName[s.Name] = st
			}
		} else {
			b, ok := policy.ParseBase(s.Match.Base)
			if !ok {
				return nil, policy.ErrInvalid
			}
			st.base, st.origin = b, b.Origin()
			e.bases = append(e.bases, st)
		}
	}
	sort.SliceStable(e.bases, func(i, j int) bool { return len(e.bases[i].base.Path) > len(e.bases[j].base.Path) })
	return e, nil
}

// NewEngineWithKey is NewEngine with a single key.
func NewEngineWithKey(p *policy.Policy, k Key) (*Engine, error) { return NewEngine(p, NewKeySet(k)) }

// Policy returns the policy of the engine.
func (e *Engine) Policy() *policy.Policy { return e.p }

// Kid returns the kid of the key in use (tokens carry it).
func (e *Engine) Kid() string { return e.key.Kid }

// buildRuleSet merges rule groups given in precedence order (1, 2a, 2b, 3,
// 4; a nil group keeps its number free so that group indexes stay stable):
// for named maps the first group that names the field wins; body rules are
// ordered so that the first matching rule is the winner (group, then more
// .name steps, then smaller path bytes).
func buildRuleSet(groups ...*policy.Part) *ruleSet {
	rs := &ruleSet{}
	merge := func(dst *map[string]*policy.Action, src map[string]policy.Action) {
		for k := range src {
			if *dst == nil {
				*dst = map[string]*policy.Action{}
			}
			if _, ok := (*dst)[k]; !ok {
				a := src[k]
				(*dst)[k] = &a
			}
		}
	}
	for gi, g := range groups {
		if g == nil {
			continue
		}
		merge(&rs.path, g.Path)
		merge(&rs.query, g.Query)
		merge(&rs.headers, g.Headers)
		merge(&rs.cookies, g.Cookies)
		for i := range g.Body {
			r := &g.Body[i]
			steps, ok := policy.ParseTTPath(r.Path)
			if !ok {
				continue // rejected by Validate; never reached
			}
			n := 0
			for _, s := range steps {
				if s.Kind == policy.StepName {
					n++
				}
			}
			a := r.Action
			rs.body = append(rs.body, cRule{steps: steps, names: n, path: r.Path, group: gi, act: &a})
		}
	}
	sort.SliceStable(rs.body, func(i, j int) bool {
		a, b := &rs.body[i], &rs.body[j]
		if a.group != b.group {
			return a.group < b.group
		}
		if a.names != b.names {
			return a.names > b.names
		}
		return a.path < b.path
	})
	return rs
}

func (rs *ruleSet) lookup(m map[string]*policy.Action, name string) *policy.Action {
	if m == nil {
		return nil
	}
	return m[name]
}
