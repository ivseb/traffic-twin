package fleet

import (
	"bytes"
	"context"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/hostpat"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// OriginHostTwin is the origin of a draft created from the hosts registry
// (admin-api twinHost, spec v1.5).
const OriginHostTwin = "host-twin"

// HostTwinRequest is the body of POST /api/v1/hosts/{pattern}/twin.
type HostTwinRequest struct {
	// PolicyID is the policy that receives the new service. Optional when
	// the caller (tt-core) knows a single policy under which the host was
	// seen.
	PolicyID string `json:"policy_id,omitempty"`
	// Service is the name of the new external service; default: the host
	// of the base (plus "-<port>" with a non-default port).
	Service string `json:"service,omitempty"`
	// Base is match.base, "http(s)://host[:port][/segment...]". Required for
	// a pattern with {*} labels or an IP class (tt-core cannot know the
	// value behind {*}: the person types it, and it must match the pattern).
	Base string `json:"base,omitempty"`
	// Scheme ("http" or "https") builds the base of an exact pattern when
	// Base is empty. The events do not carry the scheme of a host (the
	// default port of either is left out), so tt-core never guesses it:
	// without Base one of the two is required.
	Scheme string `json:"scheme,omitempty"`
	// Group is the group whose calls are twinned (the console's filter):
	// without PolicyID the policy is the one of that group's calls, never
	// another team's policy.
	Group string `json:"group,omitempty"`
}

// ProposeHostTwin creates a policy draft that adds an external service with
// match.base for a host seen as host:<pattern> (docs/spec/sanitizer.md 3.5).
// The same draft masks with hmac the identifiers already seen on the calls
// to that host (the observe-safe decisions of policy.md 7.4: the id fields
// and path parameters, never a value): the twin's ids link up from its
// first version. Declaring a service and masking open no value, so the
// draft applies at once when keyguard signs observe-safe changes;
// otherwise it follows the normal approval flow (policy.md 5). pattern has
// no "host:" prefix.
func (f *Fleet) ProposeHostTwin(ctx context.Context, p *auth.Principal, pattern string, req HostTwinRequest) (*PolicyVersion, error) {
	if !hostpat.Valid(pattern) && !event.ValidHostPort(pattern) {
		return nil, invalid("invalid_pattern", "not a host pattern of sanitizer.md 3.5")
	}
	if req.PolicyID == "" {
		return nil, invalid("policy_required", "policy_id is required: the host was seen under several policies or none")
	}
	base, err := twinBase(pattern, req.Base, req.Scheme)
	if err != nil {
		return nil, err
	}
	name := req.Service
	if name == "" {
		name = base.Host
		if base.Port != "" {
			name += "-" + base.Port
		}
	}
	if !policy.ValidServiceName(name) {
		return nil, invalid("invalid_service", "service must match ^[a-z0-9][a-z0-9._-]{0,62}$")
	}

	// The identifiers seen on the host's calls (shapes only): read before
	// the lock, the assistant reads the working draft itself.
	var seen *AssistResult
	f.mu.RLock()
	hasDisc := f.discovery != nil
	f.mu.RUnlock()
	if hasDisc && policy.ValidPolicyID(req.PolicyID) {
		seen, _ = f.AssistIn(ctx, req.PolicyID, req.Group)
	}

	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	author, folded, err := f.workingAuthor(ctx, req.PolicyID)
	if err != nil {
		return nil, err
	}
	a, err := ParseAuthor(author)
	if err != nil {
		return nil, err
	}
	if _, ok := a.Services[name]; ok {
		return nil, conflict("service_exists", "the policy already has a service with this name")
	}
	baseStr := base.String()
	for _, s := range a.Services {
		if s.Base == "" {
			continue
		}
		if ob, ok := policy.ParseBase(s.Base); ok && ob.String() == baseStr {
			return nil, conflict("already_declared", "the policy already declares a service with this base")
		}
	}
	doc, err := addServiceYAML(author, name, baseStr)
	if err != nil {
		return nil, invalid("invalid_policy", "the policy document cannot be extended")
	}
	if ops := twinIdentifierOps(seen, "host:"+pattern, base); len(ops) > 0 {
		withIDs, err := applyDecisionsYAML(doc, AssistDraftRequest{Services: []AssistDraftService{{Service: name, Name: name, Ops: ops}}})
		if err == nil && len(withIDs) <= MaxAuthorBytes {
			if na, err := ParseAuthor(withIDs); err == nil {
				if _, _, err := policy.Compile(na, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: f.now(), Groups: []string{"twin-check"}}); err == nil {
					doc = withIDs
				}
			}
		}
	}
	return f.createDraftFolding(ctx, p, doc, OriginHostTwin, "twin of external host "+pattern, folded)
}

// noteAssist is the note of the drafts the policy assistant proposes.
const noteAssist = "policy assistant"

// workingAuthor returns the author document a new twin or assistant proposal builds on, and the
// pending draft it folds in. Normally that is the active version; but when the policy already
// has a pending draft proposed the same way (an earlier "Gemella", an assistant draft) and it
// still builds on the active version (its diff against it removes nothing), the proposal adds to
// that draft: two drafts made one after the other from the same base would otherwise cancel each
// other, and approving one would make the other "remove" the first one's services.
func (f *Fleet) workingAuthor(ctx context.Context, pid string) ([]byte, []int64, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT version FROM fleet_policy_versions
		WHERE policy_id = ? AND status = ? AND (origin = ? OR (origin = ? AND note = ?)) ORDER BY version DESC`,
		pid, StatusDraft, OriginHostTwin, OriginPropose, noteAssist)
	if err != nil {
		return nil, nil, err
	}
	var vers []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, nil, err
		}
		vers = append(vers, v)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	for _, ver := range vers {
		v, err := f.GetPolicyVersion(ctx, pid, ver)
		if err != nil {
			return nil, nil, err
		}
		removes := false
		for _, d := range v.Diff {
			removes = removes || d.Change == "removed"
		}
		if !removes {
			return []byte(v.AuthorYAML), []int64{ver}, nil
		}
	}
	author, err := f.latestAuthor(ctx, pid)
	return author, nil, err
}

// twinBase picks match.base for a pattern: the explicit base (which must be
// described by the pattern) or scheme:// + the exact pattern. The scheme is
// never guessed: the events do not carry it.
func twinBase(pattern, explicit, scheme string) (policy.BaseURL, error) {
	host, port := hostpat.SplitPort(pattern)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return policy.BaseURL{}, invalid("invalid_scheme", "scheme must be http or https")
	}
	if explicit == "" {
		if !hostpat.Exact(pattern) {
			return policy.BaseURL{}, invalid("base_required", "the pattern has {*} labels or is an IP class: give the exact base")
		}
		if scheme == "" {
			return policy.BaseURL{}, invalid("scheme_required", "choose the scheme of the host (http or https): tt-core does not see it in the events")
		}
		explicit = scheme + "://" + pattern
	}
	b, ok := policy.ParseBase(explicit)
	if !ok {
		return policy.BaseURL{}, invalid("invalid_base", "base must be http(s)://host[:port][/segment...]")
	}
	if scheme != "" && b.Scheme != scheme {
		return policy.BaseURL{}, invalid("base_mismatch", "the base and the scheme differ")
	}
	hp := b.Host
	if b.Port != "" {
		hp += ":" + b.Port
	}
	switch {
	case hostpat.IsIP(host):
		a, isV4 := hostpat.ParseIPv4(b.Host)
		if !isV4 || hostpat.ClassIPv4(a) != host || b.Port != port {
			return policy.BaseURL{}, invalid("base_mismatch", "the base is not described by the pattern")
		}
	case !hostpat.Matches(pattern, hp) && hp != pattern:
		return policy.BaseURL{}, invalid("base_mismatch", "the base is not described by the pattern")
	}
	return b, nil
}

// latestAuthor returns the author document of the active version of pid,
// or of its latest version when none is active.
func (f *Fleet) latestAuthor(ctx context.Context, pid string) ([]byte, error) {
	f.mu.RLock()
	ap := f.active[pid]
	f.mu.RUnlock()
	if ap != nil {
		v, err := f.GetPolicyVersion(ctx, pid, ap.version)
		if err != nil {
			return nil, err
		}
		return []byte(v.AuthorYAML), nil
	}
	var author string
	err := f.db.QueryRowContext(ctx, `SELECT author FROM fleet_policy_versions WHERE policy_id = ? ORDER BY version DESC LIMIT 1`, pid).Scan(&author)
	if err != nil {
		return nil, errNotFound
	}
	return []byte(author), nil
}

// addServiceYAML adds services.<name>: {match: {base: <base>}} to an author
// document, keeping everything else (comments included) as written.
func addServiceYAML(doc []byte, name, base string) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errNotFound
	}
	top := root.Content[0]
	top.Style &^= yaml.FlowStyle
	var svcs *yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "services" {
			svcs = top.Content[i+1]
		}
	}
	if svcs == nil || svcs.Kind != yaml.MappingNode {
		svcs = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		top.Content = append(top.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "services"}, svcs)
	}
	svcs.Style &^= yaml.FlowStyle
	str := func(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
	match := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle, Content: []*yaml.Node{str("base"), str(base)}}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{str("match"), match}}
	svcs.Content = append(svcs.Content, str(name), entry)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n") + "\n"), nil
}

// twinIdentifierOps picks, from the assistant's view of the calls to an
// undeclared host (service host:<pattern>), the observe-safe decisions for
// its twin: hmac on the identifiers (reasons id and path_id), as the
// observe version would (observeDecisions). The operation templates become
// relative to the path of the base (sanitizer.md 3.1); an operation outside
// it is left out.
func twinIdentifierOps(res *AssistResult, hostService string, base policy.BaseURL) []AssistDraftOp {
	if res == nil {
		return nil
	}
	prefix := ""
	for _, seg := range base.Path {
		prefix += "/" + seg
	}
	for _, s := range res.Services {
		if s.Service != hostService {
			continue
		}
		view := AssistService{Service: s.Service, Name: "twin", Kind: "external", Declared: true}
		for _, o := range s.Ops {
			method, path, ok := strings.Cut(o.Op, " ")
			if !ok {
				continue
			}
			if prefix != "" {
				rest, under := strings.CutPrefix(path, prefix)
				if !under || (rest != "" && rest[0] != '/') {
					continue
				}
				if rest == "" {
					rest = "/"
				}
				path = rest
			}
			op := o
			op.Op = method + " " + path
			view.Ops = append(view.Ops, op)
		}
		// identifiers only: the codes of the new service come from the next observe pass
		req := observeDecisions(&AssistResult{Services: []AssistService{view}}, &policy.Author{}, nil, codeOptions{})
		if len(req.Services) == 1 {
			return req.Services[0].Ops
		}
	}
	return nil
}
