package obi

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Defaults of the generated OBI configuration.
const (
	DefaultEndpoint    = "http://127.0.0.1:4318"
	DefaultCaptureSize = 8192   // ebpf.buffer_sizes.http: "a few KB" (ARCHITECTURE.md 3.1)
	MaxCaptureSize     = 262144 // maximum HTTP capture size per direction in OBI v0.10
	DefaultObfuscation = "***"
	// DefaultWildcard completes a path prefix for rules that apply to every
	// operation of a service (service-level and global body rules). OBI's
	// glob semantics for url_path_patterns are not documented: verify on the
	// lab (README.md).
	DefaultWildcard = "/*"
)

// ConfigOptions parameterize GenerateConfig.
type ConfigOptions struct {
	// ServiceName is the service name assigned to the bridge at enrollment.
	// Inbound services of the policy with another name are ignored (they are
	// captured by their own bridge). Empty: every inbound service counts.
	ServiceName string
	// Endpoint is where OBI exports its traces (the bridge receiver).
	Endpoint string
	// OpenPorts, ExePath select the processes OBI instruments
	// (discovery.instrument). Both empty: nothing is written and the
	// selection must come from OBI's environment (OTEL_EBPF_OPEN_PORT, ...).
	OpenPorts string
	ExePath   string
	// CaptureBytes is ebpf.buffer_sizes.http (default DefaultCaptureSize,
	// at most MaxCaptureSize).
	CaptureBytes int64
	// Wildcard is the catch-all path suffix (default DefaultWildcard).
	Wildcard string
	// Obfuscation is the replacement string of obfuscated values.
	Obfuscation string
}

// Generated is the result of GenerateConfig.
type Generated struct {
	YAML         []byte
	CaptureBytes int64
	// Headers, per scope, are the header names the policy lets OBI attach.
	RequestHeaders, ResponseHeaders []string
}

// OBI configuration (Config v1, https://opentelemetry.io/docs/zero-code/obi/configure/).
type obiConfig struct {
	OTelTraces otelTraces    `yaml:"otel_traces_export"`
	Discovery  *obiDiscovery `yaml:"discovery,omitempty"`
	EBPF       obiEBPF       `yaml:"ebpf"`
}

type otelTraces struct {
	Endpoint         string   `yaml:"endpoint"`
	Protocol         string   `yaml:"protocol"`
	Instrumentations []string `yaml:"instrumentations"`
}

type obiDiscovery struct {
	Instrument []map[string]string `yaml:"instrument"`
}

type obiEBPF struct {
	BufferSizes       map[string]int64 `yaml:"buffer_sizes"`
	PayloadExtraction struct {
		HTTP struct {
			Enrichment enrichment `yaml:"enrichment"`
		} `yaml:"http"`
	} `yaml:"payload_extraction"`
}

type enrichment struct {
	Enabled bool         `yaml:"enabled"`
	Policy  enrichPolicy `yaml:"policy"`
	Rules   []enrichRule `yaml:"rules"`
}

type enrichPolicy struct {
	DefaultAction struct {
		Headers string `yaml:"headers"`
		Body    string `yaml:"body"`
	} `yaml:"default_action"`
	ObfuscationString string `yaml:"obfuscation_string"`
}

type enrichRule struct {
	Action string      `yaml:"action"`
	Type   string      `yaml:"type"`
	Scope  string      `yaml:"scope"`
	Match  enrichMatch `yaml:"match"`
}

type enrichMatch struct {
	// headers
	Patterns      []string `yaml:"patterns,omitempty"`
	CaseSensitive *bool    `yaml:"case_sensitive,omitempty"`
	// body
	Methods              []string `yaml:"methods,omitempty"`
	URLPathPatterns      []string `yaml:"url_path_patterns,omitempty"`
	ObfuscationJSONPaths []string `yaml:"obfuscation_json_paths,omitempty"`
}

// GenerateConfig builds the OBI configuration from a compiled policy. It is
// the first filter of the OBI path and works by exclusion of everything:
//
//   - headers and bodies are excluded by default (default_action exclude);
//   - a header is attached to spans only if the policy names it (a header or
//     cookie rule, the subject, the baggage if trusted) or if the sanitizer
//     cannot work without it (content-type, content-encoding,
//     content-length);
//   - a body is attached only for the operations of the policy that have a
//     body rule, and fields the policy drops explicitly are obfuscated by
//     OBI before the span even leaves the instrumented host;
//   - headers the policy forbids to keep (authorization, cookie, ...) and
//     that nothing needs are obfuscated explicitly, in case an operator
//     later widens the default.
//
// The sanitizer remains the authoritative filter: this configuration can
// only make OBI hand over less, never more than the policy allows.
func GenerateConfig(p *policy.Policy, o ConfigOptions) (*Generated, error) {
	if p == nil {
		return nil, errors.New("obi: no policy")
	}
	if o.Endpoint == "" {
		o.Endpoint = DefaultEndpoint
	}
	if o.CaptureBytes <= 0 {
		o.CaptureBytes = DefaultCaptureSize
	}
	if o.CaptureBytes > MaxCaptureSize {
		return nil, fmt.Errorf("obi: capture size %d exceeds the OBI maximum %d", o.CaptureBytes, MaxCaptureSize)
	}
	if o.Wildcard == "" {
		o.Wildcard = DefaultWildcard
	}
	if o.Obfuscation == "" {
		o.Obfuscation = DefaultObfuscation
	}

	hdr := collectHeaders(p, o)
	body := collectBodies(p, o)

	var cfg obiConfig
	cfg.OTelTraces = otelTraces{Endpoint: o.Endpoint, Protocol: "http/json", Instrumentations: []string{"http"}}
	if o.OpenPorts != "" || o.ExePath != "" {
		sel := map[string]string{}
		if o.OpenPorts != "" {
			sel["open_ports"] = o.OpenPorts
		}
		if o.ExePath != "" {
			sel["exe_path"] = o.ExePath
		}
		if o.ServiceName != "" {
			// OBI names the service in the spans' resource; the bridge
			// accepts only spans of the service it enrolled as.
			sel["name"] = o.ServiceName
		}
		cfg.Discovery = &obiDiscovery{Instrument: []map[string]string{sel}}
	}
	cfg.EBPF.BufferSizes = map[string]int64{"http": o.CaptureBytes}
	en := &cfg.EBPF.PayloadExtraction.HTTP.Enrichment
	en.Enabled = true
	en.Policy.DefaultAction.Headers = "exclude"
	en.Policy.DefaultAction.Body = "exclude"
	en.Policy.ObfuscationString = o.Obfuscation

	f := false
	// Headers: scope request, response, or all (names needed on both).
	req, resp := hdr.req, hdr.resp
	both := intersect(req, resp)
	reqOnly, respOnly := minus(req, both), minus(resp, both)
	if len(hdr.denied) > 0 {
		en.Rules = append(en.Rules, enrichRule{Action: "obfuscate", Type: "headers", Scope: "all",
			Match: enrichMatch{Patterns: hdr.denied, CaseSensitive: &f}})
	}
	for _, r := range []struct {
		scope string
		names []string
	}{{"all", both}, {"request", reqOnly}, {"response", respOnly}} {
		if len(r.names) > 0 {
			en.Rules = append(en.Rules, enrichRule{Action: "include", Type: "headers", Scope: r.scope,
				Match: enrichMatch{Patterns: r.names, CaseSensitive: &f}})
		}
	}
	en.Rules = append(en.Rules, body.rules()...)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Generated by \"tt obi\" from policy %s version %d (%s). Do not edit.\n", p.PolicyID, p.Version, "tt.policy.body/v1")
	buf.WriteString("# OBI is the first filter: it attaches only what the policy names. The sanitizer of\n")
	buf.WriteString("# the bridge is the second, authoritative one. OBI reads this file at start:\n")
	buf.WriteString("# restart it when the policy changes.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&cfg); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return &Generated{YAML: buf.Bytes(), CaptureBytes: o.CaptureBytes, RequestHeaders: req, ResponseHeaders: resp}, nil
}

// ---- headers ----

// alwaysHeaders are needed by the sanitizer to read any body: content type,
// content encoding, and the length that tells a cut body from a whole one.
var alwaysHeaders = []string{"content-type", "content-encoding", "content-length"}

type headerSets struct {
	req, resp []string
	denied    []string
}

func collectHeaders(p *policy.Policy, o ConfigOptions) headerSets {
	req, resp := map[string]bool{}, map[string]bool{}
	for _, h := range alwaysHeaders {
		req[h], resp[h] = true, true
	}
	addPart := func(part *policy.Part, set map[string]bool, cookieName string) {
		for h := range part.Headers {
			set[h] = true
		}
		if len(part.Cookies) > 0 {
			set[cookieName] = true
		}
	}
	scope := func(s *policy.Scope) {
		addPart(&s.Request, req, "cookie")
		addPart(&s.Response, resp, "set-cookie")
		addPart(&s.Errors, resp, "set-cookie")
	}
	scope(&p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		if !relevant(s, o) {
			continue
		}
		scope(&s.Scope)
		for k := range s.Ops {
			addPart(&s.Ops[k].Request, req, "cookie")
			addPart(&s.Ops[k].Response, resp, "set-cookie")
		}
	}
	// Subject (sanitizer section 11) and trusted baggage (section 12).
	needed := map[string]bool{}
	if s := p.Subject; s != nil {
		if s.From == "cookie" {
			req["cookie"], needed["cookie"] = true, true
		} else {
			req[s.Name], needed[s.Name] = true, true
		}
	}
	if p.Sampling.TrustBaggage {
		req["baggage"] = true
	}
	var hs headerSets
	hs.req, hs.resp = glob(req), glob(resp)
	// Forbidden-to-keep headers that nothing needs: obfuscate explicitly.
	for h := range policy.ForbiddenKeepHeaders {
		if !req[h] && !resp[h] && !needed[h] {
			hs.denied = append(hs.denied, h)
		}
	}
	sort.Strings(hs.denied)
	return hs
}

// glob returns the sorted names that can be written as a literal OBI
// pattern: names with glob characters are left out (fail closed).
func glob(set map[string]bool) []string {
	var out []string
	for h := range set {
		if strings.ContainsAny(h, "*?[]") {
			continue
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func intersect(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if in[x] {
			out = append(out, x)
		}
	}
	return out
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

// relevant reports whether a policy service can be captured by this bridge.
func relevant(s *policy.Service, o ConfigOptions) bool {
	if s.Match.Inbound {
		return o.ServiceName == "" || s.Name == o.ServiceName
	}
	return s.Match.Base != ""
}

// ---- bodies ----

type bodyKey struct {
	scope   string // request | response
	method  string // "" = any
	pattern string
}

type bodyTargets struct {
	m map[bodyKey]map[string]bool // key -> JSON paths to obfuscate
}

func (t *bodyTargets) add(k bodyKey) map[string]bool {
	if t.m == nil {
		t.m = map[bodyKey]map[string]bool{}
	}
	if _, ok := t.m[k]; !ok {
		t.m[k] = map[string]bool{}
	}
	return t.m[k]
}

// collectBodies lists, per scope, the operations whose body the policy may
// use. An operation is a target if any rule group that can apply to it has
// a body rule (sanitizer section 5.0): the operation's own rules, the
// service's, the errors rules, the global ones.
func collectBodies(p *policy.Policy, o ConfigOptions) *bodyTargets {
	t := &bodyTargets{}
	allRules := allBodyRules(p)
	obfuscate := func(acc map[string]bool, rules []policy.BodyRule) {
		for _, r := range rules {
			if r.Action.Kind == policy.ActDrop && !hasDeeperRule(allRules, r.Path) {
				acc[r.Path] = true
			}
		}
	}
	// Global rules apply to every operation, listed or not.
	g := &p.Global
	if len(g.Request.Body) > 0 {
		obfuscate(t.add(bodyKey{"request", "", o.Wildcard}), g.Request.Body)
	}
	if len(g.Response.Body) > 0 || len(g.Errors.Body) > 0 {
		acc := t.add(bodyKey{"response", "", o.Wildcard})
		obfuscate(acc, g.Response.Body)
		obfuscate(acc, g.Errors.Body)
	}
	for i := range p.Services {
		s := &p.Services[i]
		if !relevant(s, o) {
			continue
		}
		prefix := ""
		if s.Match.Base != "" {
			if b, ok := policy.ParseBase(s.Match.Base); ok {
				for _, seg := range b.Path {
					prefix += "/" + seg
				}
			}
		}
		// Service-level rules apply to every operation of the service,
		// including the ones the policy does not list.
		if len(s.Request.Body) > 0 {
			obfuscate(t.add(bodyKey{"request", "", prefix + o.Wildcard}), s.Request.Body)
		}
		if len(s.Response.Body) > 0 || len(s.Errors.Body) > 0 {
			acc := t.add(bodyKey{"response", "", prefix + o.Wildcard})
			obfuscate(acc, s.Response.Body)
			obfuscate(acc, s.Errors.Body)
		}
		for k := range s.Ops {
			op := &s.Ops[k]
			method, segs, ok := policy.ParseOpKey(op.Op)
			if !ok {
				continue
			}
			pat := prefix
			for _, sg := range segs {
				if sg.Param != "" {
					pat += "/*"
				} else {
					pat += "/" + sg.Literal
				}
			}
			if pat == "" {
				pat = "/"
			}
			reqRules := op.Request.Body
			respRules := op.Response.Body
			hasErr := len(s.Errors.Body) > 0 || len(g.Errors.Body) > 0
			if len(reqRules) > 0 || len(s.Request.Body) > 0 || len(g.Request.Body) > 0 {
				acc := t.add(bodyKey{"request", method, pat})
				obfuscate(acc, reqRules)
				obfuscate(acc, s.Request.Body)
				obfuscate(acc, g.Request.Body)
			}
			if len(respRules) > 0 || len(s.Response.Body) > 0 || len(g.Response.Body) > 0 || hasErr {
				acc := t.add(bodyKey{"response", method, pat})
				obfuscate(acc, respRules)
				obfuscate(acc, s.Response.Body)
				obfuscate(acc, s.Errors.Body)
				obfuscate(acc, g.Response.Body)
				obfuscate(acc, g.Errors.Body)
			}
		}
	}
	return t
}

// allBodyRules returns every body rule of the policy.
func allBodyRules(p *policy.Policy) []policy.BodyRule {
	var all []policy.BodyRule
	add := func(s *policy.Scope) {
		all = append(all, s.Request.Body...)
		all = append(all, s.Response.Body...)
		all = append(all, s.Errors.Body...)
	}
	add(&p.Global)
	for i := range p.Services {
		add(&p.Services[i].Scope)
		for k := range p.Services[i].Ops {
			all = append(all, p.Services[i].Ops[k].Request.Body...)
			all = append(all, p.Services[i].Ops[k].Response.Body...)
		}
	}
	return all
}

// hasDeeperRule reports whether another rule of the policy that keeps
// something has a path below path: obfuscating the container would destroy
// the value that rule wants, so OBI must not obfuscate it (the sanitizer
// collapses explicit drops by itself, section 5.0).
func hasDeeperRule(all []policy.BodyRule, path string) bool {
	for _, r := range all {
		if r.Action.Kind == policy.ActDrop || r.Path == path {
			continue
		}
		if strings.HasPrefix(r.Path, path) && len(r.Path) > len(path) && (r.Path[len(path)] == '.' || r.Path[len(path)] == '[') {
			return true
		}
	}
	return false
}

// rules renders the targets as OBI rules: first the include rules, then the
// obfuscation of explicit drops. The output is sorted, so the same policy
// always gives the same file.
func (t *bodyTargets) rules() []enrichRule {
	type group struct{ scope, method string }
	pats := map[group][]string{}
	for k := range t.m {
		g := group{k.scope, k.method}
		pats[g] = append(pats[g], k.pattern)
	}
	var groups []group
	for g := range pats {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].scope != groups[j].scope {
			return groups[i].scope < groups[j].scope
		}
		return groups[i].method < groups[j].method
	})
	var out []enrichRule
	for _, g := range groups {
		ps := pats[g]
		sort.Strings(ps)
		m := enrichMatch{URLPathPatterns: ps}
		if g.method != "" {
			m.Methods = []string{g.method}
		}
		out = append(out, enrichRule{Action: "include", Type: "body", Scope: g.scope, Match: m})
	}
	var keys []bodyKey
	for k := range t.m {
		if len(t.m[k]) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.scope != b.scope {
			return a.scope < b.scope
		}
		if a.method != b.method {
			return a.method < b.method
		}
		return a.pattern < b.pattern
	})
	for _, k := range keys {
		var paths []string
		for p := range t.m[k] {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		m := enrichMatch{URLPathPatterns: []string{k.pattern}, ObfuscationJSONPaths: paths}
		if k.method != "" {
			m.Methods = []string{k.method}
		}
		out = append(out, enrichRule{Action: "obfuscate", Type: "body", Scope: k.scope, Match: m})
	}
	return out
}
