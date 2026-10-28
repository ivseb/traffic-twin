package core

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/fleet"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/hostpat"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// ---------------------------------------------------------------------------
// Hosts registry (admin-api listHosts, twinHost; spec v1.5,
// docs/spec/sanitizer.md 3.5)
//
// Every outbound host a service calls is visible, grouped by registrable
// domain: the host patterns of the events (host:<pattern>, labels that look
// like values already {*}), the external services the policies declare
// (match.base) and the calls that left as host:unlisted (strict mode) or
// host:invalid. Only patterns, counts and times are shown: no value ever
// reaches this view. twinHost turns a pattern into a policy draft with an
// external service for it; the draft follows the normal approvals.

var rolesHosts = []auth.Role{auth.RoleOperator, auth.RoleAdmin}

type hostCaller struct {
	Service string `json:"service"`
	Calls   int64  `json:"calls"`
}

type hostPattern struct {
	Pattern string `json:"pattern"`
	// Group is the group whose sources made these calls: the same pattern
	// called by two groups is two entries.
	Group string `json:"group"`
	// Service is the service of the events: host:<pattern>, or the name of
	// the declared external service.
	Service string `json:"service"`
	// Declared: an external service of a policy matches this host (its
	// calls appear under the service name).
	Declared     bool         `json:"declared"`
	DeclaredBy   []string     `json:"declared_by,omitempty"` // policy ids
	Exact        bool         `json:"exact"`                 // no {*} label, not an IP class: can be twinned without typing the host
	Quarantined  bool         `json:"quarantined"`           // a label of this domain is collapsed by the intake
	Calls        int64        `json:"calls"`
	ServerErrors int64        `json:"server_errors"`
	ClientErrors int64        `json:"client_errors"`
	ErrorRate    float64      `json:"error_rate"` // server errors (5xx and network errors) / calls
	LatencyP50MS *int64       `json:"latency_p50_ms"`
	FirstSeen    *time.Time   `json:"first_seen"`
	LastSeen     *time.Time   `json:"last_seen"`
	Callers      []hostCaller `json:"callers"`
	Policies     []string     `json:"policies"`
	// NowDeclaredAs is set on a host pattern that a policy has declared
	// since (its older calls stay under host:<pattern>): the name of that
	// external service, so the console shows one entry, not two.
	NowDeclaredAs string `json:"now_declared_as,omitempty"`
	// FoldedFrom lists the older host:<pattern> rows of this group that the
	// declaration replaced: their calls, callers and times are counted in
	// this entry (declared once, "dichiarato come <service>"), which is the
	// only one the registry shows for that host.
	FoldedFrom []string `json:"folded_from,omitempty"`
}

// hostCounts are the figures of the page header, over the entries listed
// (IP-class hosts like ip:private:9732 included: a fake API on 127.0.0.1 is
// a host of the group).
type hostCounts struct {
	// Domains is the number of domains with at least one entry; Hosts the
	// entries; IPHosts those of an IP class (ip:private, ip:public);
	// Declared and Undeclared split the entries by policy declaration
	// (a pattern replaced by a declaration is not listed any more, so it is
	// not "undeclared"); Folded counts the older rows folded into their
	// declaration.
	Domains    int `json:"domains"`
	Hosts      int `json:"hosts"`
	IPHosts    int `json:"ip_hosts"`
	Declared   int `json:"declared"`
	Undeclared int `json:"undeclared"`
	Folded     int `json:"folded"`
}

type hostDomain struct {
	Domain    string        `json:"domain"`
	Calls     int64         `json:"calls"`
	FirstSeen *time.Time    `json:"first_seen"`
	LastSeen  *time.Time    `json:"last_seen"`
	Patterns  []hostPattern `json:"patterns"`
}

type hostsView struct {
	Domains  []hostDomain `json:"domains"`
	Unlisted hostPattern  `json:"unlisted"`
	Invalid  hostPattern  `json:"invalid"`
	Counts   hostCounts   `json:"counts"`
	// Discovery is hosts.discovery of each known policy (latest version).
	Discovery map[string]string `json:"discovery"`
}

type declaredHost struct {
	service string
	host    string // host[:port] of match.base
	pols    []string
}

// declaredServices lists the external services of the latest signed version
// of every policy.
func (c *Core) declaredServices() (map[string]*declaredHost, map[string]string) {
	c.policies.Refresh()
	c.policies.mu.Lock()
	latest := map[string]*policy.Policy{}
	for _, p := range c.policies.known {
		if cur := latest[p.PolicyID]; cur == nil || p.Version > cur.Version {
			latest[p.PolicyID] = p
		}
	}
	c.policies.mu.Unlock()
	out := map[string]*declaredHost{}
	modes := map[string]string{}
	for pid, p := range latest {
		modes[pid] = policy.HostsAuto
		if !p.Hosts.Auto() {
			modes[pid] = policy.HostsOff
		}
		for _, s := range p.Services {
			if s.Match.Base == "" {
				continue
			}
			b, ok := policy.ParseBase(s.Match.Base)
			if !ok {
				continue
			}
			d := out[s.Name]
			if d == nil {
				d = &declaredHost{service: s.Name, host: b.HostPort()}
				out[s.Name] = d
			}
			d.pols = append(d.pols, pid)
		}
	}
	for _, d := range out {
		sort.Strings(d.pols)
	}
	return out, modes
}

func (c *Core) sourceServices(ctx context.Context) map[string]string {
	out := map[string]string{}
	srcs, err := c.fleet.ListSources(ctx, "")
	if err != nil {
		return out
	}
	for _, s := range srcs {
		out[s.SourceID] = s.ServiceName
	}
	return out
}

func (c *Core) hostsRegistry(ctx context.Context) (*hostsView, error) {
	return c.hostsRegistryPeriod(ctx, time.Time{}, time.Time{}, nil)
}

// hostKey is the identity of an outbound host or service: the same pattern
// called by two groups (two teams with a fake API on 127.0.0.1:9301) is two
// entries, and a declared name of one group never relabels another group's
// calls.
type hostKey struct{ group, service string }

// hostsRegistryPeriod is the registry over the event time [from, to): with a
// period it reads the rollups, which outlive the raw events (any age, hour
// resolution or coarser for old data); without, the ingest aggregates.
// groups restricts it to the calls of those groups' sources (nil: every
// group, each entry with its group).
func (c *Core) hostsRegistryPeriod(ctx context.Context, from, to time.Time, groups groupscope.Set) (*hostsView, error) {
	st := c.intake.Store()
	var stats []intake.HostStat
	var p50 map[string]int64
	var err error
	if from.IsZero() && to.IsZero() {
		if stats, err = st.HostStats(ctx); err != nil {
			return nil, err
		}
		p50, err = st.HostLatencyP50(ctx)
	} else {
		if to.IsZero() {
			to = c.now().Add(time.Hour)
		}
		// Count the events of the last minutes too.
		if _, err = st.RollupPending(ctx); err != nil {
			return nil, err
		}
		if stats, err = st.HostStatsRange(ctx, from, to); err != nil {
			return nil, err
		}
		p50, err = st.HostLatencyP50Range(ctx, from, to)
	}
	if err != nil {
		return nil, err
	}
	decl, modes := c.declaredServices()
	byPolicy := c.declaredByPolicy()
	srcGroup, err := c.fleet.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	polGroups, err := c.fleet.PolicyGroups(ctx)
	if err != nil {
		return nil, err
	}
	declOf := groupDeclared(byPolicy, polGroups)
	callerOf := c.sourceServices(ctx)
	quarantined := map[string]bool{}
	for _, q := range c.intake.Quarantines(false) {
		if q.Kind == intake.QuarantineHostLabel {
			quarantined[q.Domain] = true
		}
	}

	byService := map[hostKey]*hostPattern{}
	callers := map[hostKey]map[string]int64{}
	pols := map[hostKey]map[string]bool{}
	get := func(k hostKey) *hostPattern {
		hp := byService[k]
		if hp == nil {
			hp = &hostPattern{Service: k.service, Group: k.group, Callers: []hostCaller{}, Policies: []string{}}
			byService[k] = hp
			callers[k] = map[string]int64{}
			pols[k] = map[string]bool{}
		}
		return hp
	}
	for _, s := range stats {
		g := srcGroup[s.SourceID]
		if !groups.Has(g) {
			continue // another group's calls
		}
		k := hostKey{g, s.Service}
		_, isDeclared := decl[s.Service]
		if !strings.HasPrefix(s.Service, "host:") && !isDeclared {
			continue // an outbound service of an older policy that no longer declares it
		}
		hp := get(k)
		hp.Calls += s.Count
		hp.ServerErrors += s.ServerErrors
		hp.ClientErrors += s.ClientErrors
		if hp.FirstSeen == nil || s.FirstTS.Before(*hp.FirstSeen) {
			t := s.FirstTS
			hp.FirstSeen = &t
		}
		if hp.LastSeen == nil || s.LastTS.After(*hp.LastSeen) {
			t := s.LastTS
			hp.LastSeen = &t
		}
		name := callerOf[s.SourceID]
		if name == "" {
			name = "source:" + s.SourceID
		}
		callers[k][name] += s.Count
		pols[k][s.PolicyID] = true
	}
	// The services the policies of a group declare, even before a call.
	for pid, gs := range polGroups {
		for _, g := range gs {
			if !groups.Has(g) {
				continue
			}
			for name := range byPolicy[pid] {
				get(hostKey{g, name})
			}
		}
	}

	// An old host:<pattern> row that a declaration of the same group replaced
	// is folded into the declared entry: one host, one row.
	folded := map[hostKey][]string{}
	nFolded := 0
	for k, hp := range byService {
		if !strings.HasPrefix(k.service, "host:") || k.service == "host:unlisted" || k.service == "host:invalid" {
			continue
		}
		gd := declOf(k.group)
		if _, declared := gd[k.service]; declared {
			continue
		}
		pat := strings.TrimPrefix(k.service, "host:")
		name := declaredFor(pat, gd)
		if name == "" {
			continue
		}
		tk := hostKey{k.group, name}
		t := byService[tk]
		if t == nil {
			continue
		}
		t.Calls += hp.Calls
		t.ServerErrors += hp.ServerErrors
		t.ClientErrors += hp.ClientErrors
		if hp.FirstSeen != nil && (t.FirstSeen == nil || hp.FirstSeen.Before(*t.FirstSeen)) {
			t.FirstSeen = hp.FirstSeen
		}
		if hp.LastSeen != nil && (t.LastSeen == nil || hp.LastSeen.After(*t.LastSeen)) {
			t.LastSeen = hp.LastSeen
		}
		for n, cnt := range callers[k] {
			callers[tk][n] += cnt
		}
		for pid := range pols[k] {
			pols[tk][pid] = true
		}
		folded[tk] = append(folded[tk], pat)
		delete(byService, k)
		nFolded++
	}

	view := &hostsView{Domains: []hostDomain{}, Discovery: modes}
	domains := map[string]*hostDomain{}
	keys := make([]hostKey, 0, len(byService))
	for k := range byService {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].service != keys[j].service {
			return keys[i].service < keys[j].service
		}
		return keys[i].group < keys[j].group
	})
	merge := func(dst *hostPattern, src *hostPattern) {
		dst.Calls += src.Calls
		dst.ServerErrors += src.ServerErrors
		dst.ClientErrors += src.ClientErrors
		if src.FirstSeen != nil && (dst.FirstSeen == nil || src.FirstSeen.Before(*dst.FirstSeen)) {
			dst.FirstSeen = src.FirstSeen
		}
		if src.LastSeen != nil && (dst.LastSeen == nil || src.LastSeen.After(*dst.LastSeen)) {
			dst.LastSeen = src.LastSeen
		}
		dst.Callers = append(dst.Callers, src.Callers...)
		for _, p := range src.Policies {
			if !slices.Contains(dst.Policies, p) {
				dst.Policies = append(dst.Policies, p)
			}
		}
		if dst.Calls > 0 {
			dst.ErrorRate = float64(dst.ServerErrors) / float64(dst.Calls)
		}
	}
	for _, k := range keys {
		svc := k.service
		hp := byService[k]
		for n, cnt := range callers[k] {
			hp.Callers = append(hp.Callers, hostCaller{Service: n, Calls: cnt})
		}
		sort.Slice(hp.Callers, func(i, j int) bool {
			if hp.Callers[i].Calls != hp.Callers[j].Calls {
				return hp.Callers[i].Calls > hp.Callers[j].Calls
			}
			return hp.Callers[i].Service < hp.Callers[j].Service
		})
		for p := range pols[k] {
			hp.Policies = append(hp.Policies, p)
		}
		sort.Strings(hp.Policies)
		if hp.Calls > 0 {
			hp.ErrorRate = float64(hp.ServerErrors) / float64(hp.Calls)
			if v, ok := p50[svc]; ok {
				hp.LatencyP50MS = &v
			}
		}
		switch svc {
		case "host:unlisted":
			hp.Pattern = "unlisted"
			merge(&view.Unlisted, hp)
			view.Unlisted.Pattern, view.Unlisted.Service = "unlisted", svc
			continue
		case "host:invalid":
			hp.Pattern = "invalid"
			merge(&view.Invalid, hp)
			view.Invalid.Pattern, view.Invalid.Service = "invalid", svc
			continue
		}
		gd := declOf(k.group)
		if d, ok := gd[svc]; ok {
			hp.Pattern, hp.Declared, hp.DeclaredBy = shownPattern(d.host), true, d.pols
		} else if d, ok := decl[svc]; ok {
			// Declared by a policy this group's events ran under (a policy
			// not bound to the group any more).
			hp.Pattern, hp.Declared, hp.DeclaredBy = shownPattern(d.host), true, d.pols
		} else {
			hp.Pattern = strings.TrimPrefix(svc, "host:")
			// Only the group's own policies: another team declaring the
			// same host never relabels this group's calls.
			hp.NowDeclaredAs = declaredFor(hp.Pattern, gd)
		}
		if f := folded[k]; len(f) > 0 {
			sort.Strings(f)
			hp.FoldedFrom = f
		}
		hp.Exact = hostpat.Exact(hp.Pattern)
		dom := hostpat.Domain(hp.Pattern)
		hp.Quarantined = quarantined[dom]
		hd := domains[dom]
		if hd == nil {
			hd = &hostDomain{Domain: dom, Patterns: []hostPattern{}}
			domains[dom] = hd
		}
		hd.Calls += hp.Calls
		if hp.FirstSeen != nil && (hd.FirstSeen == nil || hp.FirstSeen.Before(*hd.FirstSeen)) {
			hd.FirstSeen = hp.FirstSeen
		}
		if hp.LastSeen != nil && (hd.LastSeen == nil || hp.LastSeen.After(*hd.LastSeen)) {
			hd.LastSeen = hp.LastSeen
		}
		hd.Patterns = append(hd.Patterns, *hp)
	}
	for _, hd := range domains {
		sort.Slice(hd.Patterns, func(i, j int) bool {
			if hd.Patterns[i].Pattern != hd.Patterns[j].Pattern {
				return hd.Patterns[i].Pattern < hd.Patterns[j].Pattern
			}
			return hd.Patterns[i].Group < hd.Patterns[j].Group
		})
		view.Domains = append(view.Domains, *hd)
	}
	sort.Slice(view.Domains, func(i, j int) bool {
		if view.Domains[i].Calls != view.Domains[j].Calls {
			return view.Domains[i].Calls > view.Domains[j].Calls
		}
		return view.Domains[i].Domain < view.Domains[j].Domain
	})
	view.Counts.Folded = nFolded
	view.Counts.Domains = len(view.Domains)
	for _, hd := range view.Domains {
		for _, h := range hd.Patterns {
			view.Counts.Hosts++
			if strings.HasPrefix(hd.Domain, "ip:") {
				view.Counts.IPHosts++
			}
			if h.Declared {
				view.Counts.Declared++
			} else if h.NowDeclaredAs == "" {
				view.Counts.Undeclared++
			}
		}
	}
	for _, u := range []*hostPattern{&view.Unlisted, &view.Invalid} {
		if u.Callers == nil {
			u.Callers = []hostCaller{}
		}
		if u.Policies == nil {
			u.Policies = []string{}
		}
		sort.Strings(u.Policies)
		sort.Slice(u.Callers, func(i, j int) bool {
			if u.Callers[i].Calls != u.Callers[j].Calls {
				return u.Callers[i].Calls > u.Callers[j].Calls
			}
			return u.Callers[i].Service < u.Callers[j].Service
		})
	}
	if view.Unlisted.Pattern == "" {
		view.Unlisted.Pattern, view.Unlisted.Service = "unlisted", "host:unlisted"
	}
	if view.Invalid.Pattern == "" {
		view.Invalid.Pattern, view.Invalid.Service = "invalid", "host:invalid"
	}
	return view, nil
}

// groupDeclared returns the declared external services of a group: those
// of the policies serving it (memoized per group).
func groupDeclared(byPolicy map[string]map[string]string, polGroups map[string][]string) func(g string) map[string]*declaredHost {
	groupDecl := map[string]map[string]*declaredHost{}
	return func(g string) map[string]*declaredHost {
		if m, ok := groupDecl[g]; ok {
			return m
		}
		m := map[string]*declaredHost{}
		for pid, gs := range polGroups {
			if !slices.Contains(gs, g) {
				continue
			}
			for name, hp := range byPolicy[pid] {
				d := m[name]
				if d == nil {
					d = &declaredHost{service: name, host: hp}
					m[name] = d
				}
				d.pols = append(d.pols, pid)
			}
		}
		for _, d := range m {
			sort.Strings(d.pols)
		}
		groupDecl[g] = m
		return m
	}
}

// replacedBy returns, for a group and a service of its events, the external
// service its policies declare since for the same host: an undeclared
// host:<pattern> whose host a declared match.base now describes (its older
// calls stay under host:<pattern>). "" when the service is not replaced.
// Only the group's own policies count: another team declaring the same host
// never relabels this group's calls.
func (c *Core) replacedBy(ctx context.Context) (func(group, service string) string, error) {
	polGroups, err := c.fleet.PolicyGroups(ctx)
	if err != nil {
		return nil, err
	}
	return replacedResolver(c.declaredByPolicy(), polGroups), nil
}

// replacedResolver is replacedBy over the declared services of each policy
// and the groups of each policy.
func replacedResolver(byPolicy map[string]map[string]string, polGroups map[string][]string) func(group, service string) string {
	declOf := groupDeclared(byPolicy, polGroups)
	return func(group, service string) string {
		pat, ok := strings.CutPrefix(service, "host:")
		if !ok || pat == "unlisted" || pat == "invalid" {
			return ""
		}
		gd := declOf(group)
		if _, declared := gd[service]; declared {
			return ""
		}
		return declaredFor(pat, gd)
	}
}

// replacedLookup implements contract.ReplacedLookup.
type replacedLookup struct{ c *Core }

func (r replacedLookup) ReplacedBy(ctx context.Context) (func(group, service string) string, error) {
	return r.c.replacedBy(ctx)
}

// declaredByPolicy lists, per policy (latest signed version), the external
// services it declares with the host[:port] of their match.base.
func (c *Core) declaredByPolicy() map[string]map[string]string {
	c.policies.Refresh()
	c.policies.mu.Lock()
	latest := map[string]*policy.Policy{}
	for _, p := range c.policies.known {
		if cur := latest[p.PolicyID]; cur == nil || p.Version > cur.Version {
			latest[p.PolicyID] = p
		}
	}
	c.policies.mu.Unlock()
	out := map[string]map[string]string{}
	for pid, p := range latest {
		for _, s := range p.Services {
			if s.Match.Base == "" {
				continue
			}
			b, ok := policy.ParseBase(s.Match.Base)
			if !ok {
				continue
			}
			if out[pid] == nil {
				out[pid] = map[string]string{}
			}
			out[pid][s.Name] = b.HostPort()
		}
	}
	return out
}

// declaredFor returns the declared external service whose host the pattern
// describes ("" when none; the first by name when several).
func declaredFor(pattern string, decl map[string]*declaredHost) string {
	names := make([]string, 0, len(decl))
	for n := range decl {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if patternDescribes(pattern, decl[n].host) {
			return n
		}
	}
	return ""
}

// shownPattern is the pattern the registry shows for the host of a declared
// match.base: the registry holds patterns only (spec v1.5), so a base on an
// IP literal is shown as its class (127.0.0.1:9101 -> ip:private:9101) and
// a label that is not safe as {*}, exactly as a source would emit it.
func shownPattern(hostPort string) string {
	host, port := hostpat.SplitPort(hostPort)
	if h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"); h != host {
		if a, ok := hostpat.ParseIPv6(h); ok {
			return hostpat.FromIPv6(a, port)
		}
	}
	if p, ok := hostpat.FromHost(host, port); ok {
		return p
	}
	return hostPort
}

// patternDescribes is hostpat.Matches extended to the IP classes: an
// ip:private:9101 pattern describes 127.0.0.1:9101.
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

func (c *Core) apiListHosts(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	from, to, err := period(r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	if err != nil {
		return err
	}
	v, err := c.hostsRegistryPeriod(r.Context(), from, to, groupscope.FromRequest(r))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// apiTwinHost creates a policy draft with an external service for a host
// pattern. The pattern in the path is the event's service with or without
// the "host:" prefix (percent-encoded: {*} is %7B%2A%7D).
func (c *Core) apiTwinHost(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	pattern := strings.TrimPrefix(r.PathValue("pattern"), "host:")
	if !event.ValidServiceRef("host:"+pattern) || pattern == "unlisted" || pattern == "invalid" {
		return apiErr(http.StatusUnprocessableEntity, "invalid_pattern", "not a host pattern")
	}
	var req fleet.HostTwinRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if req.PolicyID == "" {
		// The policy under which the group's sources called the host, when
		// there is only one (without a group: of every group).
		stats, err := c.intake.Store().HostStats(ctx)
		if err != nil {
			return err
		}
		srcGroup, err := c.fleet.SourceGroups(ctx)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, s := range stats {
			if s.Service == "host:"+pattern && (req.Group == "" || srcGroup[s.SourceID] == req.Group) {
				seen[s.PolicyID] = true
			}
		}
		if len(seen) == 1 {
			for pid := range seen {
				req.PolicyID = pid
			}
		} else if len(seen) == 0 && req.Group != "" {
			if g, err := c.fleet.GetGroup(ctx, req.Group); err == nil && g.PolicyID != nil {
				req.PolicyID = *g.PolicyID
			}
		}
	}
	v, err := c.fleet.ProposeHostTwin(ctx, p, pattern, req)
	ev := audit.Event{Actor: p.AuditActor(), Action: "host.twin", Target: audit.Target{Type: "host", ID: auditPattern(pattern)},
		Outcome: audit.Success, RequestID: httpx.RequestID(ctx)}
	if err != nil {
		ev.Outcome = audit.Failure
		var fe *fleet.APIError
		if errors.As(err, &fe) {
			ev.Reason = fe.Code
			c.record(ctx, ev)
			return apiErr(fe.Status, fe.Code, fe.Message)
		}
		ev.Reason = "internal"
		c.record(ctx, ev)
		return err
	}
	ev.Details = map[string]string{"policy_id": v.PolicyID, "version": strconv.FormatInt(v.Version, 10)}
	c.record(ctx, ev)
	httpx.WriteJSON(w, http.StatusCreated, v)
	return nil
}

// auditPattern writes a pattern in the audit alphabet: {*} becomes "_" and
// the result is cut at 128 bytes (a pattern carries no value either way).
func auditPattern(p string) string {
	s := strings.ReplaceAll(p, hostpat.Star, "_")
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
