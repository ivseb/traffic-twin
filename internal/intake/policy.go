package intake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Policy is the intake's read-only view of a compiled policy body
// (tt.policy.body/v1, docs/spec/policy.md section 2): everything the intake
// needs to decide whether a value in an event is allowed by "the effective
// rule of the right kind at that path" (docs/spec/event.md 5.1 point 6).
//
// A Policy is immutable after [ParsePolicy] and safe for concurrent use.
// The policy must already be signed and validated (by tt-core and keyguard):
// the intake does not re-verify signatures, it only reads the rules.
type Policy struct {
	ID        string
	Version   int64
	IssuedSeq int64
	// Hash is sha256:<hex> of the exact body bytes (the key under which a
	// [PolicyRegistry] returns the policy).
	Hash      string
	CreatedAt time.Time // zero if absent
	NotAfter  time.Time // zero if absent
	// Groups are the source groups the policy is assigned to.
	Groups []string

	// HMACKID and AcceptKIDs list the key ids that tokens may carry.
	HMACKID    string
	AcceptKIDs []string
	// Epoch is the HMAC epoch (used to route tokens to keyguard's filters).
	Epoch string
	// HasSubject is true if identity.subject is configured.
	HasSubject bool

	AutoWords          bool
	AutoWordsExpiresAt time.Time
	SegmentsAllow      map[string]struct{}
	HostsAllow         map[string]struct{}

	Limits Limits

	DiscoveryEnabled bool
	DiscoveryExpires time.Time

	// HostsAuto is hosts.discovery auto (or absent): outbound hosts without
	// a base leave as host patterns (docs/spec/sanitizer.md 3.5, v1.5).
	HostsAuto bool

	// Bodies mirrors policy.bodies (docs/spec/sanitizer.md 22, spec v1.19);
	// the zero value (field absent) turns every switch off.
	Bodies Bodies

	global   scopeRules
	services map[string]*serviceRules
}

// Limits mirrors policy.limits.
type Limits struct {
	MaxBodyBytes int
	MaxDepth     int
	MaxArray     int
	MaxKeys      int
	KeepMaxBytes int
}

// Bodies mirrors policy.bodies (spec v1.19).
type Bodies struct {
	XML, Multipart, Docs bool
	MaxLargeBytes        int
	LargeArray           int
	LargeNestedArray     int
}

// maxArrayFor is the longest array (elements kept, without the trunc:n
// marker) a body of size class size may hold: in a large body (sanitizer.md
// 22.5) the larger of the two large caps.
func (p *Policy) maxArrayFor(size string) int {
	n := p.Limits.MaxArray
	if size == "lmax" && p.Bodies.MaxLargeBytes > p.Limits.MaxBodyBytes {
		n = max(n, p.Bodies.LargeArray, p.Bodies.LargeNestedArray)
	}
	return n
}

// TargetsGroup reports whether the policy is assigned to group.
func (p *Policy) TargetsGroup(group string) bool {
	for _, g := range p.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// AcceptsKID reports whether tokens with the given kid are allowed.
func (p *Policy) AcceptsKID(kid string) bool {
	if kid == p.HMACKID {
		return true
	}
	for _, k := range p.AcceptKIDs {
		if k == kid {
			return true
		}
	}
	return false
}

// AutoWordsActive reports whether automatic words were on at time t.
func (p *Policy) AutoWordsActive(t time.Time, skew time.Duration) bool {
	if !p.AutoWords || p.AutoWordsExpiresAt.IsZero() {
		return false
	}
	end := p.AutoWordsExpiresAt
	if !p.CreatedAt.IsZero() {
		if c := p.CreatedAt.Add(7 * 24 * time.Hour); c.Before(end) {
			end = c
		}
	}
	return t.Before(end.Add(skew))
}

// DiscoveryActive reports whether discovery mode was on at time t.
func (p *Policy) DiscoveryActive(t time.Time, skew time.Duration) bool {
	if !p.DiscoveryEnabled || p.DiscoveryExpires.IsZero() {
		return false
	}
	end := p.DiscoveryExpires
	if !p.CreatedAt.IsZero() {
		if c := p.CreatedAt.Add(7 * 24 * time.Hour); c.Before(end) {
			end = c
		}
	}
	return t.Before(end.Add(skew))
}

// ---------------------------------------------------------------------------
// Parsing

type actionDoc struct {
	Action string        `json:"action"`
	Domain string        `json:"domain"`
	Kind   string        `json:"kind"`
	Bounds []json.Number `json:"bounds"`
	Unit   string        `json:"unit"`
	Shape  string        `json:"shape"` // code: "" or "alnum" (spec v1.19)
}

type bodyRuleDoc struct {
	Path   string    `json:"path"`
	Action actionDoc `json:"action"`
}

type partDoc struct {
	Path    map[string]actionDoc `json:"path"`
	Query   map[string]actionDoc `json:"query"`
	Headers map[string]actionDoc `json:"headers"`
	Cookies map[string]actionDoc `json:"cookies"`
	Body    []bodyRuleDoc        `json:"body"`
}

type scopeDoc struct {
	Request  *partDoc `json:"request"`
	Response *partDoc `json:"response"`
	Errors   *partDoc `json:"errors"`
}

type opDoc struct {
	Op       string   `json:"op"`
	Request  *partDoc `json:"request"`
	Response *partDoc `json:"response"`
}

type serviceDoc struct {
	Name  string `json:"name"`
	Match struct {
		Inbound  bool   `json:"inbound"`
		Internal bool   `json:"internal"`
		Base     string `json:"base"`
	} `json:"match"`
	Request  *partDoc `json:"request"`
	Response *partDoc `json:"response"`
	Errors   *partDoc `json:"errors"`
	Ops      []opDoc  `json:"ops"`
}

type policyDoc struct {
	Format    string `json:"format"`
	PolicyID  string `json:"policy_id"`
	Version   int64  `json:"version"`
	IssuedSeq int64  `json:"issued_seq"`
	CreatedAt string `json:"created_at"`
	NotAfter  string `json:"not_after"`
	Targets   struct {
		Groups []string `json:"groups"`
	} `json:"targets"`
	HMAC struct {
		KID        string   `json:"kid"`
		AcceptKIDs []string `json:"accept_kids"`
		Epoch      string   `json:"epoch"`
	} `json:"hmac"`
	Identity struct {
		Subject *json.RawMessage `json:"subject"`
	} `json:"identity"`
	Segments struct {
		AutoWords          bool     `json:"auto_words"`
		AutoWordsExpiresAt string   `json:"auto_words_expires_at"`
		Allow              []string `json:"allow"`
		HostsAllow         []string `json:"hosts_allow"`
	} `json:"segments"`
	Limits struct {
		MaxBodyBytes *int `json:"max_body_bytes"`
		MaxDepth     *int `json:"max_depth"`
		MaxArray     *int `json:"max_array"`
		MaxKeys      *int `json:"max_keys"`
		KeepMaxBytes *int `json:"keep_max_bytes"`
	} `json:"limits"`
	Discovery *struct {
		Enabled   bool   `json:"enabled"`
		ExpiresAt string `json:"expires_at"`
	} `json:"discovery"`
	Hosts *struct {
		Discovery string `json:"discovery"`
	} `json:"hosts"`
	Bodies *struct {
		XML              bool `json:"xml"`
		Multipart        bool `json:"multipart"`
		Docs             bool `json:"docs"`
		MaxLargeBodyByte int  `json:"max_large_body_bytes"`
		LargeArray       int  `json:"large_array"`
		LargeNestedArray int  `json:"large_nested_array"`
	} `json:"bodies"`
	Global   scopeDoc     `json:"global"`
	Services []serviceDoc `json:"services"`
}

// ParsePolicy builds a Policy from the exact bytes of a tt.policy.body/v1
// document. The hash is computed over those bytes.
func ParsePolicy(body []byte) (*Policy, error) {
	sum := sha256.Sum256(body)
	return ParsePolicyWithHash(body, "sha256:"+hex.EncodeToString(sum[:]))
}

// ParsePolicyWithHash is like ParsePolicy but takes the hash from the caller
// (for registries that already store it).
func ParsePolicyWithHash(body []byte, hash string) (*Policy, error) {
	var d policyDoc
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("intake: policy body: %w", err)
	}
	if d.Format != "tt.policy.body/v1" {
		return nil, errors.New("intake: policy body: unexpected format")
	}
	p := &Policy{
		ID: d.PolicyID, Version: d.Version, IssuedSeq: d.IssuedSeq, Hash: hash,
		Groups:  append([]string(nil), d.Targets.Groups...),
		HMACKID: d.HMAC.KID, AcceptKIDs: append([]string(nil), d.HMAC.AcceptKIDs...), Epoch: d.HMAC.Epoch,
		HasSubject:    d.Identity.Subject != nil && string(*d.Identity.Subject) != "null",
		AutoWords:     d.Segments.AutoWords,
		SegmentsAllow: map[string]struct{}{}, HostsAllow: map[string]struct{}{},
		services: map[string]*serviceRules{},
	}
	if p.ID == "" || p.HMACKID == "" || p.Epoch == "" {
		return nil, errors.New("intake: policy body: missing policy_id, hmac.kid or hmac.epoch")
	}
	var err error
	if p.CreatedAt, err = optTime(d.CreatedAt); err != nil {
		return nil, fmt.Errorf("intake: policy body: created_at: %w", err)
	}
	if p.NotAfter, err = optTime(d.NotAfter); err != nil {
		return nil, fmt.Errorf("intake: policy body: not_after: %w", err)
	}
	if p.AutoWordsExpiresAt, err = optTime(d.Segments.AutoWordsExpiresAt); err != nil {
		return nil, fmt.Errorf("intake: policy body: auto_words_expires_at: %w", err)
	}
	for _, s := range d.Segments.Allow {
		p.SegmentsAllow[s] = struct{}{}
	}
	for _, h := range d.Segments.HostsAllow {
		p.HostsAllow[h] = struct{}{}
	}
	p.Limits = Limits{MaxBodyBytes: 1 << 20, MaxDepth: 32, MaxArray: 32, MaxKeys: 256, KeepMaxBytes: 64}
	setInt(&p.Limits.MaxBodyBytes, d.Limits.MaxBodyBytes)
	setInt(&p.Limits.MaxDepth, d.Limits.MaxDepth)
	setInt(&p.Limits.MaxArray, d.Limits.MaxArray)
	setInt(&p.Limits.MaxKeys, d.Limits.MaxKeys)
	setInt(&p.Limits.KeepMaxBytes, d.Limits.KeepMaxBytes)
	p.HostsAuto = true
	if d.Hosts != nil {
		switch d.Hosts.Discovery {
		case "auto":
		case "off":
			p.HostsAuto = false
		default:
			return nil, errors.New("intake: policy body: hosts.discovery must be auto or off")
		}
	}
	if b := d.Bodies; b != nil {
		p.Bodies = Bodies{XML: b.XML, Multipart: b.Multipart, Docs: b.Docs, MaxLargeBytes: b.MaxLargeBodyByte,
			LargeArray: b.LargeArray, LargeNestedArray: b.LargeNestedArray}
	}
	if d.Discovery != nil {
		p.DiscoveryEnabled = d.Discovery.Enabled
		if p.DiscoveryExpires, err = optTime(d.Discovery.ExpiresAt); err != nil {
			return nil, fmt.Errorf("intake: policy body: discovery.expires_at: %w", err)
		}
	}

	if p.global, err = compileScope(&d.Global, "global"); err != nil {
		return nil, err
	}
	for i := range d.Services {
		sd := &d.Services[i]
		sv, err := compileService(sd)
		if err != nil {
			return nil, err
		}
		p.services[sv.name] = sv
	}
	return p, nil
}

func setInt(dst *int, v *int) {
	if v != nil {
		*dst = *v
	}
}

func optTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

// ---------------------------------------------------------------------------
// Rules

type actKind uint8

const (
	actDrop actKind = iota
	actKeep
	actHMAC
	actBucketNum
	actBucketTime
	actCode // keep: tokens with the code shape only (sanitizer.md 5.6)
	// actCodeAlnum: keep: tokens with the alnum code shape only
	// (sanitizer.md 5.6, spec v1.19).
	actCodeAlnum
	actGraphQL // gql: tokens (sanitizer.md 5.7)
)

type action struct {
	kind   actKind
	tokens map[string]struct{} // bucket(num): the allowed num: tokens
	unit   string              // bucket(time)
}

var (
	dropAction = &action{kind: actDrop}
	keepAction = &action{kind: actKeep}
	codeAction = &action{kind: actCode}
	alnumCode  = &action{kind: actCodeAlnum}
	gqlAction  = &action{kind: actGraphQL}
	hmacAction = &action{kind: actHMAC}
)

func compileAction(a *actionDoc) (*action, error) {
	switch a.Action {
	case "drop":
		return dropAction, nil
	case "keep":
		return keepAction, nil
	case "code":
		switch a.Shape {
		case "":
			return codeAction, nil
		case "alnum":
			return alnumCode, nil
		}
		return nil, errors.New("intake: policy body: unknown code shape")
	case "graphql":
		return gqlAction, nil
	case "hmac":
		return hmacAction, nil
	case "bucket":
		switch a.Kind {
		case "time":
			switch a.Unit {
			case "year", "month", "day", "hour":
				return &action{kind: actBucketTime, unit: a.Unit}, nil
			}
			return nil, errors.New("intake: policy body: bad bucket(time) unit")
		case "num":
			if len(a.Bounds) == 0 {
				return nil, errors.New("intake: policy body: bucket(num) without bounds")
			}
			lex := make([]string, len(a.Bounds))
			for i, b := range a.Bounds {
				c, ok := event.CanonicalNumber(b.String())
				if !ok {
					return nil, errors.New("intake: policy body: bad bucket bound")
				}
				lex[i] = c
			}
			toks := map[string]struct{}{"num:<" + lex[0]: {}, "num:>=" + lex[len(lex)-1]: {}}
			for i := 0; i+1 < len(lex); i++ {
				toks["num:"+lex[i]+"-"+lex[i+1]] = struct{}{}
			}
			return &action{kind: actBucketNum, tokens: toks}, nil
		}
	}
	return nil, errors.New("intake: policy body: unknown action")
}

type step struct {
	kind uint8 // stepName, stepStar, stepElem
	name string
}

const (
	stepName uint8 = iota
	stepStar
	stepElem
)

type bodyRule struct {
	act       *action
	nameSteps int
	path      string
}

type tnode struct {
	named  map[string]*tnode
	star   *tnode
	elem   *tnode
	rules  []*bodyRule
	deeper bool
}

type partRules struct {
	query, headers, cookies map[string]*action
	body                    *tnode // nil when the part has no body rules
	hasDrop                 bool   // any explicit drop body rule
}

type scopeRules struct {
	req, resp, errs *partRules
}

// parseTTPath parses "$.a.b[*].*".
func parseTTPath(p string) ([]step, bool) {
	if p == "" || p[0] != '$' {
		return nil, false
	}
	var out []step
	i := 1
	for i < len(p) {
		switch {
		case strings.HasPrefix(p[i:], "[*]"):
			out = append(out, step{kind: stepElem})
			i += 3
		case p[i] == '.':
			i++
			j := i
			for j < len(p) && p[j] != '.' && p[j] != '[' {
				j++
			}
			name := p[i:j]
			if name == "*" {
				out = append(out, step{kind: stepStar})
			} else if name != "" {
				out = append(out, step{kind: stepName, name: name})
			} else {
				return nil, false
			}
			i = j
		default:
			return nil, false
		}
	}
	return out, true
}

func (n *tnode) insert(steps []step, r *bodyRule) {
	cur := n
	for _, s := range steps {
		cur.deeper = true
		switch s.kind {
		case stepName:
			if cur.named == nil {
				cur.named = map[string]*tnode{}
			}
			nx := cur.named[s.name]
			if nx == nil {
				nx = &tnode{}
				cur.named[s.name] = nx
			}
			cur = nx
		case stepStar:
			if cur.star == nil {
				cur.star = &tnode{}
			}
			cur = cur.star
		default:
			if cur.elem == nil {
				cur.elem = &tnode{}
			}
			cur = cur.elem
		}
	}
	cur.rules = append(cur.rules, r)
}

func compileNames(m map[string]actionDoc) (map[string]*action, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]*action, len(m))
	for k, a := range m {
		a := a
		act, err := compileAction(&a)
		if err != nil {
			return nil, err
		}
		out[k] = act
	}
	return out, nil
}

func compilePart(d *partDoc) (*partRules, error) {
	if d == nil {
		return nil, nil
	}
	pr := &partRules{}
	var err error
	if pr.query, err = compileNames(d.Query); err != nil {
		return nil, err
	}
	if pr.headers, err = compileNames(d.Headers); err != nil {
		return nil, err
	}
	if pr.cookies, err = compileNames(d.Cookies); err != nil {
		return nil, err
	}
	if len(d.Body) > 0 {
		pr.body = &tnode{}
		// Deterministic order: by path.
		rules := append([]bodyRuleDoc(nil), d.Body...)
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Path < rules[j].Path })
		for i := range rules {
			steps, ok := parseTTPath(rules[i].Path)
			if !ok {
				return nil, errors.New("intake: policy body: bad tt-path")
			}
			act, err := compileAction(&rules[i].Action)
			if err != nil {
				return nil, err
			}
			n := 0
			for _, s := range steps {
				if s.kind == stepName {
					n++
				}
			}
			if act.kind == actDrop {
				pr.hasDrop = true
			}
			pr.body.insert(steps, &bodyRule{act: act, nameSteps: n, path: rules[i].Path})
		}
	}
	return pr, nil
}

func compileScope(d *scopeDoc, _ string) (scopeRules, error) {
	var s scopeRules
	var err error
	if s.req, err = compilePart(d.Request); err != nil {
		return s, err
	}
	if s.resp, err = compilePart(d.Response); err != nil {
		return s, err
	}
	s.errs, err = compilePart(d.Errors)
	return s, err
}

type tmplSeg struct {
	literal bool
	text    string // literal text or parameter name
}

type opRules struct {
	key    string
	method string
	segs   []tmplSeg
	path   map[string]*action
	req    *partRules
	resp   *partRules
}

type serviceRules struct {
	name     string
	inbound  bool
	internal bool
	base     string   // normalized base ("" for inbound)
	baseSegs []string // decoded path segments of the base
	scope    scopeRules
	ops      map[string]*opRules
}

func compileService(d *serviceDoc) (*serviceRules, error) {
	sv := &serviceRules{name: d.Name, inbound: d.Match.Inbound, internal: d.Match.Internal, ops: map[string]*opRules{}}
	if d.Match.Base != "" {
		sv.base = d.Match.Base
		rest := d.Match.Base
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			for _, s := range strings.Split(rest[i+1:], "/") {
				if s != "" {
					sv.baseSegs = append(sv.baseSegs, s)
				}
			}
		}
	}
	var err error
	if sv.scope.req, err = compilePart(d.Request); err != nil {
		return nil, err
	}
	if sv.scope.resp, err = compilePart(d.Response); err != nil {
		return nil, err
	}
	if sv.scope.errs, err = compilePart(d.Errors); err != nil {
		return nil, err
	}
	for i := range d.Ops {
		od := &d.Ops[i]
		method, path, ok := event.ParseOp(od.Op)
		if !ok {
			return nil, errors.New("intake: policy body: bad operation key")
		}
		segs, ok := event.OpSegments(path)
		if !ok {
			return nil, errors.New("intake: policy body: bad operation template")
		}
		or := &opRules{key: od.Op, method: method}
		for _, s := range segs {
			if s.Literal {
				or.segs = append(or.segs, tmplSeg{literal: true, text: s.Raw})
			} else {
				or.segs = append(or.segs, tmplSeg{text: strings.TrimSuffix(strings.TrimPrefix(s.Raw, "{"), "}")})
			}
		}
		if od.Request != nil {
			if or.path, err = compileNames(od.Request.Path); err != nil {
				return nil, err
			}
		}
		if or.req, err = compilePart(od.Request); err != nil {
			return nil, err
		}
		if or.resp, err = compilePart(od.Response); err != nil {
			return nil, err
		}
		sv.ops[od.Op] = or
	}
	return sv, nil
}

// ServiceNames returns the names of the services declared by the policy
// (inbound and external), sorted.
func (p *Policy) ServiceNames() []string {
	out := make([]string, 0, len(p.services))
	for n := range p.services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
