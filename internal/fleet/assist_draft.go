package fleet

import (
	"bytes"
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// AssistDraftRequest is the body of POST
// /api/v1/fleet/policies/{policy_id}/assist/draft: the decisions a person
// took on the assistant's proposals (operations to declare, one action per
// field, never a value). tt-core writes them into the latest author policy
// (comments and layout kept) and proposes the result as a draft, which
// follows the normal approval flow.
type AssistDraftRequest struct {
	// DryRun returns the policy text before and after, without a draft.
	DryRun bool `json:"dry_run,omitempty"`
	// HostsDiscovery is the new hosts.discovery ("auto", "off"; "" = unchanged).
	HostsDiscovery string `json:"hosts_discovery,omitempty"`
	// Identity sets identity.subject when the policy has none (or replaces
	// it with ReplaceIdentity).
	Identity *AssistIdentity `json:"identity,omitempty"`
	// ReplaceIdentity: Identity replaces the identity.subject of the policy.
	ReplaceIdentity bool `json:"replace_identity,omitempty"`
	// SamplingRateBP sets sampling.rate (basis points, 1..10000): the advice of the
	// assistant when too few distinct users are sampled for rules. Raising it opens
	// data, so the draft needs the opening approvals.
	SamplingRateBP *int                 `json:"sampling_rate_bp,omitempty"`
	Services       []AssistDraftService `json:"services"`
	// Family (spec v1.18) sets or removes one family of hmac.families.
	Family *FamilyChange `json:"family,omitempty"`
}

// FamilyChange sets the members of one HMAC domain family (Domains), or
// removes the family (Remove).
type FamilyChange struct {
	Family  string   `json:"family"`
	Domains []string `json:"domains,omitempty"`
	Remove  bool     `json:"remove,omitempty"`
}

// AssistIdentity is identity.subject: who the user is, from a request
// header or cookie, optionally a claim of the JWT it carries.
type AssistIdentity struct {
	From     string `json:"from"` // header (default) | cookie
	Name     string `json:"name"`
	JWTClaim string `json:"jwt_claim,omitempty"`
	// JSONPath (spec v1.18): a dotted path of members inside a header
	// whose value is a JSON object (header only, excludes JWTClaim).
	JSONPath string `json:"json_path,omitempty"`
}

// AssistDraftService is one service to declare or extend.
type AssistDraftService struct {
	// Service is the service as in the assistant (a name or host:<pattern>).
	Service string `json:"service"`
	// Name is the policy service name; default: Service (for host:<pattern>
	// the proposed name).
	Name string `json:"name,omitempty"`
	// Base is match.base of an external service the policy does not declare
	// yet: "http(s)://host[:port]". tt-core cannot see the scheme of a host,
	// so it is never guessed.
	Base string          `json:"base,omitempty"`
	Ops  []AssistDraftOp `json:"ops"`
}

// AssistDraftOp is one operation to declare, with its rules.
type AssistDraftOp struct {
	Op    string            `json:"op"`
	Rules []AssistDraftRule `json:"rules"`
}

// AssistDraftRule is one field decision. Path is as in the assistant:
// "$.status", "query.orderId", "headers.x-tenant", "cookies.sid", "path.id".
// A "drop" removes an existing rule (drop is the default).
type AssistDraftRule struct {
	Part   string `json:"part"` // request | response
	Path   string `json:"path"`
	Action string `json:"action"`
}

// AssistDraftResult is the answer of a dry run.
type AssistDraftResult struct {
	Before string `json:"before"`
	After  string `json:"after"`
	// OpensValues, ValueReasons and ApprovalsRequired classify the change
	// against the version active now (policy.md 7): false and 0 mean it
	// applies at once, without approval.
	OpensValues       bool                 `json:"opens_values"`
	ValueReasons      []policy.ValueReason `json:"value_reasons"`
	ApprovalsRequired int                  `json:"approvals_required"`
}

// Limits of a request (the document size is bounded by MaxAuthorBytes).
const (
	maxDraftServices = 64
	maxDraftOps      = 512
	maxDraftRules    = 4096
)

// AssistDraft builds the policy from the decisions and, unless DryRun,
// proposes it as a draft.
func (f *Fleet) AssistDraft(ctx context.Context, p *auth.Principal, pid string, req AssistDraftRequest) (*AssistDraftResult, *PolicyVersion, error) {
	return f.AssistDraftWith(ctx, p, pid, req, noteAssist)
}

// AssistDraftWith is AssistDraft with the note of the version.
func (f *Fleet) AssistDraftWith(ctx context.Context, p *auth.Principal, pid string, req AssistDraftRequest, note string) (*AssistDraftResult, *PolicyVersion, error) {
	if !policy.ValidPolicyID(pid) {
		return nil, nil, errNotFound
	}
	nOps, nRules := 0, 0
	for _, s := range req.Services {
		nOps += len(s.Ops)
		for _, o := range s.Ops {
			nRules += len(o.Rules)
		}
	}
	if len(req.Services) > maxDraftServices || nOps > maxDraftOps || nRules > maxDraftRules {
		return nil, nil, invalid("too_many", "too many services, operations or rules in one draft")
	}
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	res, folded, err := f.buildAssistDraft(ctx, pid, req)
	if err != nil {
		return nil, nil, err
	}
	if req.DryRun {
		return res, nil, nil
	}
	if res.After == res.Before {
		return nil, nil, invalid("no_change", "the decisions do not change the policy")
	}
	v, err := f.createDraftFolding(ctx, p, []byte(res.After), OriginPropose, note, folded)
	if err != nil {
		return nil, nil, err
	}
	return res, v, nil
}

// buildAssistDraft writes the decisions into the working author policy
// (workingAuthor) and classifies the result. Caller holds policyMu.
func (f *Fleet) buildAssistDraft(ctx context.Context, pid string, req AssistDraftRequest) (*AssistDraftResult, []int64, error) {
	before, folded, err := f.workingAuthor(ctx, pid)
	if err != nil {
		return nil, nil, err
	}
	afterDoc, err := applyDecisionsYAML(before, req)
	if err != nil {
		return nil, nil, err
	}
	after := string(afterDoc)
	if len(after) > MaxAuthorBytes {
		return nil, nil, apiErr(413, "too_large", "the policy document is too large")
	}
	// The result must be a valid policy, also for a dry run.
	na, err := ParseAuthor([]byte(after))
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := policy.Compile(na, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: f.now(), Groups: []string{"assist-check"}}); err != nil {
		return nil, nil, invalid("invalid_policy", policyErrMsg(err))
	}
	res := &AssistDraftResult{Before: string(before), After: after, ValueReasons: []policy.ValueReason{}}
	if c, err := f.ClassifyAuthor(ctx, []byte(after)); err == nil {
		res.OpensValues, res.ValueReasons, res.ApprovalsRequired = c.OpensValues, c.ValueReasons, c.ApprovalsRequired
	}
	return res, folded, nil
}

// applyDecisionsYAML writes the decisions into an author document, keeping
// its comments and layout.
func applyDecisionsYAML(doc []byte, req AssistDraftRequest) ([]byte, error) {
	a, err := ParseAuthor(doc)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil || root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, invalid("invalid_policy", "the policy document cannot be extended")
	}
	top := root.Content[0]
	top.Style &^= yaml.FlowStyle
	if err := applyDecisions(top, a, req); err != nil {
		return nil, err
	}
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

func applyDecisions(top *yaml.Node, a *policy.Author, req AssistDraftRequest) error {
	switch req.HostsDiscovery {
	case "":
	case "off":
		setScalar(ensureMap(top, "hosts"), "discovery", "off")
	case "auto":
		if h := mapGet(top, "hosts"); h != nil && h.Kind == yaml.MappingNode {
			mapDel(h, "discovery")
			if len(h.Content) == 0 {
				mapDel(top, "hosts")
			}
		}
	default:
		return invalid("invalid_hosts_discovery", "hosts_discovery must be auto or off")
	}
	if bp := req.SamplingRateBP; bp != nil {
		if *bp < 1 || *bp > 10000 {
			return invalid("invalid_sampling", "sampling_rate_bp must be between 1 and 10000")
		}
		rate := strconv.FormatFloat(float64(*bp)/10000, 'f', -1, 64)
		tag := "!!float"
		if *bp == 10000 {
			tag = "!!int"
		}
		mapSet(ensureMap(top, "sampling"), "rate", &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: rate})
	}
	if id := req.Identity; id != nil && (a.Subject == nil || req.ReplaceIdentity) {
		from, name := id.From, id.Name
		if from == "" {
			from = "header"
		}
		valid := id.JWTClaim == "" || policy.ValidJWTClaim(id.JWTClaim)
		if id.JSONPath != "" {
			valid = valid && from == "header" && id.JWTClaim == "" && policy.ValidJSONPath(id.JSONPath)
		}
		switch from {
		case "header":
			name = strings.ToLower(name)
			valid = valid && policy.ValidHeaderName(name)
		case "cookie":
			valid = valid && policy.ValidKeyName(name)
		default:
			valid = false
		}
		if !valid {
			return invalid("invalid_identity", "identity needs from (header or cookie), a valid name and, optionally, a valid JWT claim or (header only) a JSON path")
		}
		subj := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
		setScalar(subj, "from", from)
		setScalar(subj, "name", name)
		if id.JWTClaim != "" {
			setScalar(subj, "jwt_claim", id.JWTClaim)
		}
		if id.JSONPath != "" {
			setScalar(subj, "json_path", id.JSONPath)
		}
		mapSet(ensureMap(top, "identity"), "subject", subj)
	}
	if fc := req.Family; fc != nil {
		if err := applyFamily(top, a, fc); err != nil {
			return err
		}
	}
	if len(req.Services) == 0 {
		return nil
	}
	svcs := ensureMap(top, "services")
	names := map[string]bool{}
	for _, ds := range req.Services {
		name := ds.Name
		pattern, isHost := strings.CutPrefix(ds.Service, "host:")
		if name == "" {
			name = ds.Service
			if isHost {
				name = twinName(pattern)
			}
		}
		if !policy.ValidServiceName(name) {
			return invalid("invalid_service", "service names must match ^[a-z0-9][a-z0-9._-]{0,62}$: choose a name for "+ds.Service)
		}
		if names[name] {
			return invalid("duplicate_service", "two services of the request have the same name: "+name)
		}
		names[name] = true
		decl, exists := a.Services[name]
		switch {
		case exists && ds.Base != "":
			if b, ok := policy.ParseBase(ds.Base); !ok || decl.Base == "" {
				return invalid("service_exists", "the policy already declares "+name)
			} else if ob, _ := policy.ParseBase(decl.Base); ob.String() != b.String() {
				return invalid("service_exists", "the policy already declares "+name+" with another base")
			}
		case exists:
		case isHost:
			if ds.Base == "" {
				return invalid("base_required", "choose the scheme (http or https) of "+pattern+": tt-core cannot see it")
			}
			b, err := twinBase(pattern, ds.Base, "")
			if err != nil {
				return err
			}
			for other, s := range a.Services {
				if ob, ok := policy.ParseBase(s.Base); ok && s.Base != "" && ob.String() == b.String() {
					return conflict("already_declared", "the policy already declares this base as "+other)
				}
			}
			addService(svcs, name, "base", b.String())
		default:
			if ds.Base != "" {
				return invalid("invalid_base", "base is only for external services")
			}
			addService(svcs, name, "inbound", "true")
		}
		if len(ds.Ops) == 0 {
			continue
		}
		svc := mapGet(svcs, name)
		if svc == nil || svc.Kind != yaml.MappingNode {
			return invalid("invalid_policy", "the service "+name+" cannot be extended")
		}
		svc.Style &^= yaml.FlowStyle
		ops := ensureMap(svc, "ops")
		for _, do := range ds.Ops {
			_, segs, ok := policy.ParseOpKey(do.Op)
			if !ok {
				return invalid("invalid_op", "invalid operation "+do.Op+": METHOD /template")
			}
			params := map[string]bool{}
			for _, sg := range segs {
				if sg.Param != "" {
					params[sg.Param] = true
				}
			}
			op := ensureMap(ops, do.Op)
			for _, r := range do.Rules {
				if err := applyRule(op, params, r); err != nil {
					return err
				}
			}
			for _, part := range []string{"request", "response"} {
				if n := mapGet(op, part); n != nil && n.Kind == yaml.MappingNode && len(n.Content) == 0 {
					mapDel(op, part)
				}
			}
		}
	}
	return nil
}

func applyRule(op *yaml.Node, params map[string]bool, r AssistDraftRule) error {
	where := r.Part + " " + r.Path
	if r.Part != "request" && r.Part != "response" {
		return invalid("invalid_rule", where+": part must be request or response")
	}
	if r.Action != "drop" {
		if _, err := policy.ParseAction(r.Action); err != nil {
			return invalid("invalid_action", where+": "+r.Action+" is not an action (drop, keep, hmac(domain), bucket(...))")
		}
	}
	part := ensureMap(op, r.Part)
	sub, key := "", ""
	switch {
	case strings.HasPrefix(r.Path, "$"):
		if _, ok := policy.ParseTTPath(r.Path); !ok {
			return invalid("invalid_rule", where+": invalid body path")
		}
		// The body rule is either a "$..." shortcut or under body: keep
		// the spelling in use, new rules use the shortcut.
		if b := mapGet(part, "body"); b != nil && b.Kind == yaml.MappingNode && mapGet(b, r.Path) != nil {
			sub = "body"
		}
		key = r.Path
	default:
		kind, name, ok := strings.Cut(r.Path, ".")
		valid := ok
		switch kind {
		case "query", "cookies":
			valid = valid && policy.ValidKeyName(name)
		case "headers":
			valid = valid && policy.ValidHeaderName(name)
		case "path":
			valid = valid && r.Part == "request" && params[name]
		default:
			valid = false
		}
		if !valid {
			return invalid("invalid_rule", where+": not a field of the operation")
		}
		sub, key = kind, name
	}
	target := part
	if sub != "" {
		if r.Action == "drop" {
			target = mapGet(part, sub)
		} else {
			target = ensureMap(part, sub)
		}
	}
	if r.Action == "drop" {
		if target != nil && target.Kind == yaml.MappingNode {
			mapDel(target, key)
			if sub != "" && len(target.Content) == 0 {
				mapDel(part, sub)
			}
		}
		if sub == "" {
			if b := mapGet(part, "body"); b != nil && b.Kind == yaml.MappingNode {
				mapDel(b, key)
				if len(b.Content) == 0 {
					mapDel(part, "body")
				}
			}
		}
		return nil
	}
	setScalar(target, key, r.Action)
	return nil
}

// ---- yaml.Node helpers (mapping nodes) ----

func strNode(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

func mapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, strNode(key), v)
}

func mapDel(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func setScalar(m *yaml.Node, key, val string) { mapSet(m, key, strNode(val)) }

// ensureMap returns the mapping at key, creating it (or replacing a null).
func ensureMap(m *yaml.Node, key string) *yaml.Node {
	if n := mapGet(m, key); n != nil && n.Kind == yaml.MappingNode {
		return n
	}
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapSet(m, key, n)
	return n
}

// addService adds services.<name>: {match: {<k>: <v>}}.
func addService(svcs *yaml.Node, name, k, v string) {
	svcs.Style &^= yaml.FlowStyle
	match := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
	val := strNode(v)
	if k == "inbound" {
		val.Tag = "!!bool"
	}
	match.Content = []*yaml.Node{strNode(k), val}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{strNode("match"), match}}
	mapSet(svcs, name, entry)
}

// applyFamily writes one change of hmac.families (spec v1.18, C15).
func applyFamily(top *yaml.Node, a *policy.Author, fc *FamilyChange) error {
	if !policy.ValidDomain(fc.Family) || policy.ReservedDomains[fc.Family] {
		return invalid("invalid_family", "a family name follows the domain grammar ^[a-z][a-z0-9_-]{0,31}$ and is not reserved")
	}
	hm := ensureMap(top, "hmac")
	if fc.Remove {
		fams := mapGet(hm, "families")
		if fams == nil || fams.Kind != yaml.MappingNode || mapGet(fams, fc.Family) == nil {
			return apiErr(http.StatusNotFound, "unknown_family", "the policy has no family "+fc.Family)
		}
		mapDel(fams, fc.Family)
		if len(fams.Content) == 0 {
			mapDel(hm, "families")
		}
		return nil
	}
	ds := append([]string(nil), fc.Domains...)
	sort.Strings(ds)
	fam := map[string][]string{}
	for k, v := range a.Families {
		fam[k] = v
	}
	fam[fc.Family] = ds
	for other, members := range a.Families {
		if other == fc.Family {
			continue
		}
		for _, d := range members {
			for _, x := range ds {
				if d == x {
					return conflict("domain_in_family", "the domain "+d+" is already in the family "+other)
				}
			}
		}
	}
	if err := policy.ValidateFamilies(fam); err != nil {
		return invalid("invalid_family", policyErrMsg(err))
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, d := range ds {
		seq.Content = append(seq.Content, strNode(d))
	}
	mapSet(ensureMap(hm, "families"), fc.Family, seq)
	return nil
}
