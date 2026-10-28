package fleet

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/hostpat"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// AssistResult is the answer of the policy assistant: the operations seen
// in discovery mode, per service, each with its field proposals. Nothing is
// applied: a person reviews it and proposes a draft (AssistDraft), which
// then follows the normal approval flow.
type AssistResult struct {
	PolicyID string `json:"policy_id"`
	// MinCalls is how many calls an operation needs before its proposals
	// rest on enough evidence.
	MinCalls int `json:"min_calls"`
	// Ready: every operation has at least MinCalls calls.
	Ready bool `json:"ready"`
	// NeedCalls is the largest number of calls still missing for one
	// operation (0 when every operation has enough).
	NeedCalls int64 `json:"need_calls"`
	// Message says, in English, what the assistant still needs.
	Message string `json:"message"`
	// HasIdentity: the policy already declares identity.subject.
	HasIdentity bool `json:"has_identity"`
	// Identity is the proposed identity.subject, when the inbound requests
	// carry an Authorization header.
	Identity *IdentityProposal `json:"identity,omitempty"`
	// IdentityCandidates are the request headers and cookies of the own
	// services ranked as who the user is, best first, with the signals of
	// the automatic detection (identity_detect.go). Only names, counts,
	// shapes and scores.
	IdentityCandidates []IdentityCandidate `json:"identity_candidates"`
	// IdentityBest is the source the detection picks by itself (a bearer
	// JWT claim sub first, else the best header above the threshold); nil
	// when none is convincing.
	IdentityBest *AssistIdentity `json:"identity_best,omitempty"`
	// Sampling says whether the sampling of the policy lets enough distinct users through
	// for rules (k-anonymity) and, if not, which rate to ask for. Nil without a policy.
	Sampling *SamplingAdvice `json:"sampling,omitempty"`
	Services []AssistService `json:"services"`
}

// SamplingAdvice compares the distinct users the policy's sampling lets through with the
// k-anonymity threshold. A value or a rule is published only when at least KMin distinct
// users produced it, and the sampling is per user: with a low rate a service with few
// users shows fewer than KMin of them and no rule can ever be proposed.
type SamplingAdvice struct {
	// CurrentBP is the sampling rate of the policy, in basis points (500 = 5 %).
	CurrentBP int `json:"current_bp"`
	// SampledSubjects: distinct users seen so far, from the subject tokens (Source
	// "subject"); 0 with Source "no_identity" when no subject token was seen and the
	// policy has no identity.subject yet: users cannot be counted then (distinct
	// Authorization headers are tokens, not users).
	SampledSubjects int    `json:"sampled_subjects"`
	Source          string `json:"source"`
	KMin            int    `json:"k_min"`
	// TargetSubjects is what the suggestion aims at: twice KMin, so that rules whose
	// outcomes split the users still have KMin in each branch.
	TargetSubjects int  `json:"target_subjects"`
	Enough         bool `json:"enough"`
	// PopulationEstimate is the number of users in the traffic seen so far
	// (SampledSubjects / rate). It grows while more traffic is observed.
	PopulationEstimate int `json:"population_estimate"`
	// SuggestedBP is the rate to ask for (the current one when Enough), rounded up to
	// a whole percent; 10000 when even sampling everyone would not be enough yet.
	SuggestedBP int    `json:"suggested_bp"`
	Message     string `json:"message"`
}

// sampling builds the advice from the policy rate and the users seen.
func samplingAdvice(currentBP, sampled int, source string, kmin int) *SamplingAdvice {
	if kmin < 1 {
		kmin = DefaultKMin
	}
	sa := &SamplingAdvice{CurrentBP: currentBP, SampledSubjects: sampled, Source: source, KMin: kmin, TargetSubjects: 2 * kmin, SuggestedBP: currentBP}
	switch {
	case currentBP <= 0:
		sa.Message = "the policy samples nothing: no user can be seen"
		sa.SuggestedBP = 10000
	case source == "no_identity":
		sa.Message = "user identity not configured (identity.subject): the users cannot be counted; set who the user is, then the sampling is per user"
	case sampled == 0:
		sa.Message = "no distinct user seen yet: set who the user is (identity.subject) and wait for traffic"
	default:
		sa.PopulationEstimate = int(math.Ceil(float64(sampled) * 10000 / float64(currentBP)))
		sa.Enough = sampled >= sa.TargetSubjects
		if sa.Enough {
			sa.Message = fmt.Sprintf("%d distinct users sampled (k=%d): enough", sampled, kmin)
			break
		}
		need := int(math.Ceil(float64(sa.TargetSubjects) * 10000 / float64(sa.PopulationEstimate)))
		need = (need + 99) / 100 * 100 // whole percent
		sa.SuggestedBP = min(10000, max(need, currentBP))
		// The comparison is with the target (twice k), so the message names
		// it: "34 < k=20" would contradict itself.
		few := fmt.Sprintf("%d < k=%d", sampled, kmin)
		if sampled >= kmin {
			few = fmt.Sprintf("%d, at least %d wanted (twice k=%d, so that every outcome of a rule keeps k users)", sampled, sa.TargetSubjects, kmin)
		}
		if sa.PopulationEstimate < sa.TargetSubjects {
			sa.SuggestedBP = 10000
			sa.Message = fmt.Sprintf("few distinct users sampled: %s; about %d users in the traffic seen so far, so even sampling all of them is not enough yet: wait for more traffic",
				few, sa.PopulationEstimate)
		} else {
			sa.Message = fmt.Sprintf("few distinct users sampled: %s; raise the sampling of the policy to %d%% (about %d users in the traffic seen so far) or wait for more traffic",
				few, sa.SuggestedBP/100, sa.PopulationEstimate)
		}
	}
	return sa
}

// IdentityCandidate is a request header or cookie that may carry the user,
// with the evidence of the automatic detection (identity_detect.go): only
// names, counts, shapes and scores, never a value.
type IdentityCandidate struct {
	From string `json:"from"` // header | cookie
	Name string `json:"name"`
	// JWTClaim is the claim to read when the values are JWTs ("sub").
	JWTClaim string `json:"jwt_claim,omitempty"`
	Calls    int64  `json:"calls"` // inbound calls carrying it
	Distinct int    `json:"distinct_estimate"`
	// JWT: the values are JWTs (a bearer token, or a header of JWTs).
	JWT bool `json:"jwt"`
	// Shape is the dominant drop shape of the values ("drop:str:uuid").
	Shape string `json:"shape,omitempty"`
	// Presence is the share of the inbound calls of its services carrying
	// it (0..1); PerCall the distinct values per call (0..1: near 1 a
	// request id, low a value that repeats per user).
	Presence float64 `json:"presence"`
	PerCall  float64 `json:"distinct_per_call"`
	// Score (0..100) rates it as the user; Signals say why (codes:
	// jwt_bearer, jwt_shape, id_shape, short_shape, personal_shape,
	// long_shape, repeats, most_calls, some_calls, name_hint).
	Score   int      `json:"score"`
	Signals []string `json:"signals"`
	// Excluded says why it is never chosen by itself (credential, cookie,
	// few_values, per_call, not_id_shape, rare); a person may still choose it.
	Excluded string `json:"excluded,omitempty"`
	// ObserveSafe: choosing it applies at once, without approvals
	// (policy.IdentityObserveSafe).
	ObserveSafe bool `json:"observe_safe"`
	// Best: the source the detection picks.
	Best bool `json:"best,omitempty"`
}

// IdentityProposal proposes identity.subject from a request header.
type IdentityProposal struct {
	From     string `json:"from"` // header
	Name     string `json:"name"` // authorization
	JWTClaim string `json:"jwt_claim"`
	Service  string `json:"service"`
	Calls    int64  `json:"calls"`
	With     int64  `json:"with_header"`
	Reason   string `json:"reason"`
}

// AssistService is one service seen under the policy.
type AssistService struct {
	// Service is the name in the events: a service name or host:<pattern>.
	Service string `json:"service"`
	Kind    string `json:"kind"` // inbound | external
	// Declared: the policy already declares the service (Name, Base).
	Declared bool `json:"declared"`
	// Name is the policy service name: the declared one, or a proposal
	// ("" when the person has to choose it).
	Name string `json:"name"`
	// HostPattern is the host of an undeclared external service.
	HostPattern string `json:"host_pattern,omitempty"`
	// Exact: the pattern has no {*} label and is not an IP class, so the
	// base is the pattern with the scheme the person chooses.
	Exact bool       `json:"exact"`
	Base  string     `json:"base,omitempty"`
	Calls int64      `json:"calls"`
	Ops   []AssistOp `json:"ops"`
	// Preselect is the default of "declare in the policy": true only for
	// an external host this group's sources call now that no service of
	// the policy declares yet.
	Preselect bool `json:"preselect"`
	// MergedPatterns are the host patterns folded into this block: the
	// older host:<pattern> calls of a service the policy declares since.
	MergedPatterns []string `json:"merged_patterns,omitempty"`
	// Stale: the host was not called for a while although other hosts
	// were (an old port, a fake that moved): never preselected.
	Stale bool `json:"stale,omitempty"`
}

// assistStaleAfter: a host whose last call is this much older than the
// newest outbound call of the same traffic is stale.
const assistStaleAfter = 30 * time.Minute

// patternDescribes reports whether a host pattern describes host[:port]
// (hostpat.Matches, plus the IP classes: ip:private:9101 describes
// 127.0.0.1:9101).
func patternDescribes(p, hostPort string) bool {
	if hostpat.Matches(p, hostPort) {
		return true
	}
	ph, pp := hostpat.SplitPort(p)
	hh, hp := hostpat.SplitPort(hostPort)
	if pp != hp || !hostpat.IsIP(ph) {
		return false
	}
	if a, ok := hostpat.ParseIPv4(hh); ok {
		return hostpat.ClassIPv4(a) == ph
	}
	if a, ok := hostpat.ParseIPv6(strings.Trim(hh, "[]")); ok {
		return hostpat.ClassIPv6(a) == ph
	}
	return false
}

// ipTwinName proposes a name for an IP-class pattern ("ip:private:9511" ->
// "private-9511"): the person still types the address of the base.
func ipTwinName(pattern string) string {
	host, port := hostpat.SplitPort(pattern)
	if !hostpat.IsIP(host) || port == "" {
		return ""
	}
	cls := host[strings.LastIndexByte(host, ':')+1:]
	name := strings.ToLower(cls + "-" + port)
	if !policy.ValidServiceName(name) {
		return ""
	}
	return name
}

// AssistOp is one operation template with its field proposals.
type AssistOp struct {
	Op       string `json:"op"`
	Declared bool   `json:"declared"`
	Calls    int64  `json:"calls"`
	// NeedCalls is how many more calls the proposals of the operation need.
	NeedCalls int64        `json:"need_calls"`
	RawOps    []string     `json:"raw_ops"`
	Fields    []Suggestion `json:"fields"`
	// GraphQL: the operation is a GraphQL endpoint and its document is in
	// json ($.query), query (the parameter query) or body (application/graphql).
	GraphQL string `json:"graphql,omitempty"`
}

// identityMinShare is the share of inbound calls that must carry an
// Authorization header for the assistant to propose identity.subject.
const identityMinShare = 0.5

// twinName proposes a service name for an exact host pattern: the host,
// plus "-<port>" with a non-default port (as ProposeHostTwin).
func twinName(pattern string) string {
	if !hostpat.Exact(pattern) {
		return ""
	}
	host, port := hostpat.SplitPort(pattern)
	name := strings.ToLower(host)
	if port != "" {
		name += "-" + port
	}
	if !policy.ValidServiceName(name) {
		return ""
	}
	return name
}

// Assist returns the assistant's proposals for a policy: operations per
// service (templated from the traffic), each with its fields.
func (f *Fleet) Assist(ctx context.Context, policyID string) (*AssistResult, error) {
	return f.AssistIn(ctx, policyID, "")
}

// assistSources returns the sources whose traffic the assistant reads: the
// group's (the console's filter), else those of the groups the policy
// serves; nil when none is known (every source of the policy).
func (f *Fleet) assistSources(ctx context.Context, policyID, group string) ([]string, error) {
	groups := []string{}
	if group != "" {
		groups = append(groups, group)
	} else {
		pg, err := f.PolicyGroups(ctx)
		if err != nil {
			return nil, err
		}
		groups = pg[policyID]
	}
	if len(groups) == 0 {
		return nil, nil
	}
	m, err := f.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for id, g := range m {
		if slices.Contains(groups, g) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// AssistIn is Assist over the traffic of one group's sources ("" the groups
// the policy serves): another team's calls to the same host never show.
func (f *Fleet) AssistIn(ctx context.Context, policyID, group string) (*AssistResult, error) {
	if !policy.ValidPolicyID(policyID) {
		return nil, errNotFound
	}
	f.mu.RLock()
	d := f.discovery
	f.mu.RUnlock()
	if d == nil {
		return nil, apiErr(503, "discovery_unavailable", "discovery sketches are not available")
	}
	var a *policy.Author
	if doc, _, err := f.workingAuthor(ctx, policyID); err == nil {
		a, _ = ParseAuthor(doc)
	}
	declared := map[string][]string{}
	if a != nil {
		for name, s := range a.Services {
			for op := range s.Ops {
				declared[name] = append(declared[name], op)
			}
			sort.Strings(declared[name])
		}
	}
	var disc *Discovery
	var err error
	if gd, ok := d.(GroupDiscoverySource); ok {
		srcs, serr := f.assistSources(ctx, policyID, group)
		if serr != nil {
			return nil, serr
		}
		disc, err = gd.DiscoverIn(ctx, policyID, declared, srcs)
	} else {
		disc, err = d.Discover(ctx, policyID, declared)
	}
	if err != nil {
		return nil, err
	}
	// The declared external services by host[:port] of their base: an old
	// host:<pattern> block that describes one of them is folded into it.
	declaredHosts := map[string]string{}
	if a != nil {
		for name, s := range a.Services {
			if s.Base == "" {
				continue
			}
			if b, ok := policy.ParseBase(s.Base); ok {
				declaredHosts[name] = b.HostPort()
			}
		}
	}
	foldInto := func(svc string) string {
		pat, ok := strings.CutPrefix(svc, "host:")
		if !ok {
			return ""
		}
		names := make([]string, 0, len(declaredHosts))
		for n := range declaredHosts {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if patternDescribes(pat, declaredHosts[n]) {
				return n
			}
		}
		return ""
	}
	var newest time.Time
	for svc, t := range disc.LastSeen {
		if strings.HasPrefix(svc, "host:") || declaredHosts[svc] != "" {
			if t.After(newest) {
				newest = t
			}
		}
	}
	res := &AssistResult{PolicyID: policyID, MinCalls: assistMinObserved, Ready: true, Services: []AssistService{}}
	res.HasIdentity = a != nil && a.Subject != nil

	fields := map[[2]string][]Suggestion{}
	for _, df := range disc.Fields {
		if _, _, ok := splitDiscPath(df.Path); !ok {
			continue
		}
		k := [2]string{df.Service, df.Op}
		fields[k] = append(fields[k], suggest(df))
	}
	bySvc := map[string]*AssistService{}
	var order []string
	for _, op := range disc.Ops {
		if op.Service == "host:unlisted" || op.Service == "host:invalid" || op.Service == "" {
			continue // cannot be declared: no host left the source
		}
		key := op.Service
		if into := foldInto(op.Service); into != "" {
			key = into // the old calls of a host the policy declares since
		}
		s := bySvc[key]
		if s == nil {
			s = &AssistService{Service: key, Kind: "external"}
			if op.Inbound {
				s.Kind = "inbound"
			}
			if a != nil {
				if as, ok := a.Services[key]; ok {
					s.Declared, s.Name, s.Base = true, key, as.Base
					if as.Inbound {
						s.Kind = "inbound"
					}
				}
			}
			if !s.Declared {
				if pat, ok := strings.CutPrefix(key, "host:"); ok {
					s.HostPattern, s.Exact, s.Name = pat, hostpat.Exact(pat), twinName(pat)
					if s.Name == "" {
						s.Name = ipTwinName(pat)
					}
					last, seen := disc.LastSeen[key]
					s.Stale = seen && !newest.IsZero() && newest.Sub(last) > assistStaleAfter
					s.Preselect = !s.Stale
				} else {
					s.Name = key
				}
			}
			bySvc[key] = s
			order = append(order, key)
		}
		if key != op.Service {
			pat := strings.TrimPrefix(op.Service, "host:")
			if !slices.Contains(s.MergedPatterns, pat) {
				s.MergedPatterns = append(s.MergedPatterns, pat)
				sort.Strings(s.MergedPatterns)
			}
		}
		ao := AssistOp{Op: op.Op, Calls: op.Calls, RawOps: op.RawOps, Fields: fields[[2]string{op.Service, op.Op}], GraphQL: op.GraphQL}
		if i := slices.IndexFunc(s.Ops, func(o AssistOp) bool { return o.Op == op.Op }); i >= 0 {
			// The same operation under the declared name and under the old
			// host:<pattern> (either may come first: the discovery sorts by
			// service name): one operation, one row per field, the fields of
			// the declared name first.
			ex := &s.Ops[i]
			for j := range ao.Fields {
				ao.Fields[j].Service = key
			}
			if key == op.Service {
				ex.Fields = mergeSuggestions(ao.Fields, ex.Fields)
				ex.RawOps = op.RawOps
			} else {
				ex.Fields = mergeSuggestions(ex.Fields, ao.Fields)
			}
			ex.Calls += op.Calls
			s.Calls += op.Calls
			continue
		}
		if key != op.Service {
			for i := range ao.Fields {
				ao.Fields[i].Service = key
			}
		}
		if ao.Fields == nil {
			ao.Fields = []Suggestion{}
		}
		sort.Slice(ao.Fields, func(i, j int) bool {
			x, y := ao.Fields[i], ao.Fields[j]
			if x.Part != y.Part {
				return x.Part < y.Part
			}
			return x.Path < y.Path
		})
		if a != nil {
			_, ao.Declared = a.Services[key].Ops[op.Op]
		}
		s.Calls += op.Calls
		s.Ops = append(s.Ops, ao)
	}
	for _, s := range bySvc {
		for i := range s.Ops {
			if o := &s.Ops[i]; o.Calls < assistMinObserved {
				o.NeedCalls = assistMinObserved - o.Calls
				res.Ready = false
				res.NeedCalls = max(res.NeedCalls, o.NeedCalls)
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := bySvc[order[i]], bySvc[order[j]]
		if (a.Kind == "inbound") != (b.Kind == "inbound") {
			return a.Kind == "inbound"
		}
		return a.Service < b.Service
	})
	for _, name := range order {
		res.Services = append(res.Services, *bySvc[name])
	}
	if len(res.Services) == 0 {
		res.Ready, res.NeedCalls = false, assistMinObserved
	}
	switch {
	case len(res.Services) == 0:
		res.Message = fmt.Sprintf("no traffic seen yet under this policy: at least %d calls per operation are needed", assistMinObserved)
	case !res.Ready:
		res.Message = fmt.Sprintf("more traffic is needed: up to %d more calls per operation (at least %d each)", res.NeedCalls, assistMinObserved)
	default:
		res.Message = "every operation has enough calls"
	}
	res.IdentityCandidates, res.IdentityBest = detectIdentity(disc)
	if a != nil && a.Sampling != nil {
		if bp, err := policy.RateToBP(a.Sampling.Rate); err == nil {
			// Users are counted only by their subject tokens. Before
			// identity.subject is set there is nothing to count them by:
			// distinct Authorization headers are tokens, not users (a JWT
			// with a fresh iat at every login counts the same member many
			// times), and the sampling is per call, not per user, until the
			// identity is approved. Say so instead of a misleading number.
			sampled, source := disc.Subjects, "subject"
			if sampled == 0 && !res.HasIdentity {
				source = "no_identity"
			}
			res.Sampling = samplingAdvice(bp, sampled, source, f.opts.KMin)
		}
	}
	if !res.HasIdentity {
		var best string
		var bs AuthStat
		for svc, st := range disc.Auth {
			if st.WithAuthorization > bs.WithAuthorization || (st.WithAuthorization == bs.WithAuthorization && svc < best) {
				best, bs = svc, st
			}
		}
		if best != "" && bs.Calls > 0 && float64(bs.WithAuthorization) >= identityMinShare*float64(bs.Calls) {
			res.Identity = &IdentityProposal{From: "header", Name: "authorization", JWTClaim: "sub", Service: best, Calls: bs.Calls, With: bs.WithAuthorization,
				Reason: "most inbound requests carry an Authorization header: the subject (JWT claim sub) becomes a token, for per-user sampling and customer profiles"}
		}
	}
	return res, nil
}

// mergeSuggestions is first plus the fields of second it lacks (same part
// and path), sorted by part and path.
func mergeSuggestions(first, second []Suggestion) []Suggestion {
	out := append([]Suggestion{}, first...)
	have := map[[2]string]bool{}
	for _, f := range first {
		have[[2]string{f.Part, f.Path}] = true
	}
	for _, f := range second {
		if !have[[2]string{f.Part, f.Path}] {
			have[[2]string{f.Part, f.Path}] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Part != out[j].Part {
			return out[i].Part < out[j].Part
		}
		return out[i].Path < out[j].Path
	})
	return out
}
