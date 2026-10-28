package contract

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// APIDeps are the dependencies of the admin API handlers.
type APIDeps struct {
	Engine *Engine
	// Audit records the mutating calls; optional.
	Audit *audit.Log
	// ExtraGaps contribute gaps computed elsewhere (miner); optional.
	ExtraGaps []GapSource
	// Twin stores the per-service "twin yes/no" selection; optional (without
	// it the flag is reported with its default and cannot be changed).
	Twin TwinStore
	// Replaced tells which host:<pattern> services were declared since
	// under another name in their group; optional.
	Replaced ReplacedLookup
	// Wrap, when set, wraps the handler of the three prefixes (tt-core runs
	// the long snapshot requests as jobs through it); optional.
	Wrap func(http.Handler) http.Handler
}

// TwinStore keeps the operators' choice of which discovered services get a
// twin (a contract in the packs). Only explicit choices are stored; the
// default is DefaultTwin.
type TwinStore interface {
	// Selection returns the explicit choices by service name.
	Selection(ctx context.Context) (map[string]bool, error)
	SetTwin(ctx context.Context, service string, twin bool) error
}

// ReplacedLookup names the declared service that replaces an undeclared
// host:<pattern> service of a group: once a policy of the group declares an
// external service whose match.base the pattern describes, the new calls
// carry that name and the old ones stay under host:<pattern> (kept as
// history). The lists mark the old entry (replaced_by) and leave it out of
// the packs by default: its twin would duplicate the declared one under
// another name.
type ReplacedLookup interface {
	// ReplacedBy returns a resolver: (group, service) -> declared name, ""
	// when the service is not replaced.
	ReplacedBy(ctx context.Context) (func(group, service string) string, error)
}

// DefaultTwin: the system under test (inbound) is always in a pack; the
// external services it calls are twinned unless an operator says no.
func DefaultTwin(kind string) bool { return kind != "inbound" }

// Roles allowed by api/admin-api.v1.openapi.yaml (x-tt-roles).
var (
	rolesContracts  = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer, auth.RolePublisher, auth.RoleAuditor}
	rolesSnapshots  = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer, auth.RoleAuditor}
	rolesDiscovery  = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer, auth.RoleAuditor}
	rolesGaps       = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer, auth.RoleAuditor}
	rolesSnapshotDo = []auth.Role{auth.RoleOperator}
	rolesTwinSet    = []auth.Role{auth.RoleOperator}
)

// Mount mounts the contract, discovery and gaps endpoints of the admin API
// on srv, before srv.Run:
//
//	/api/v1/services, /api/v1/services/{service}/ops   (listServices, listServiceOps)
//	/api/v1/contracts[...]                             (listContracts, getContract, listSnapshots, getSnapshot)
//	/api/v1/gaps                                       (listGaps)
//
// Each prefix is mounted with the union of the roles of its operations and
// every route checks its own list again. The alerts and webhooks endpoints
// are mounted by drift.Mount.
func Mount(srv *server.Server, d APIDeps) {
	h := Handler(d)
	if d.Wrap != nil {
		h = d.Wrap(h)
	}
	srv.Mount("/api/v1/services", h, rolesDiscovery...)
	srv.Mount("/api/v1/contracts", h, rolesContracts...)
	srv.Mount("/api/v1/gaps", h, rolesGaps...)
}

type api struct {
	APIDeps
	gaps gapCache
}

// gapCache keeps the gaps of the snapshots already decoded. A snapshot never
// changes once written (its id is new at every save), so GET /api/v1/gaps
// decodes each latest snapshot once instead of every service at every call.
type gapCache struct {
	mu sync.Mutex
	m  map[int64][]Gap
}

// maxCachedGaps bounds the cache (one entry per snapshot id).
const maxCachedGaps = 8192

func (c *gapCache) get(seq int64) ([]Gap, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.m[seq]
	return g, ok
}

func (c *gapCache) put(seq int64, g []Gap) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= maxCachedGaps {
		c.m = map[int64][]Gap{}
	}
	c.m[seq] = g
}

// Handler returns the handler for all the routes of this package. Handlers
// read the caller from auth.PrincipalFrom, so tests can inject one with
// auth.WithPrincipal.
func Handler(d APIDeps) http.Handler {
	a := &api{APIDeps: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/services", guard(rolesDiscovery, a.listServices))
	mux.HandleFunc("GET /api/v1/services/{service}/ops", guard(rolesDiscovery, a.listServiceOps))
	mux.HandleFunc("PUT /api/v1/services/{service}/twin", guard(rolesTwinSet, a.setTwin))
	mux.HandleFunc("GET /api/v1/contracts", guard(rolesContracts, a.listContracts))
	mux.HandleFunc("GET /api/v1/contracts/{service}", guard(rolesContracts, a.getContract))
	mux.HandleFunc("GET /api/v1/contracts/{service}/postman", guard(rolesContracts, a.getPostman))
	mux.HandleFunc("GET /api/v1/contracts/{service}/status", guard(rolesContracts, a.getContractStatus))
	mux.HandleFunc("GET /api/v1/contracts/{service}/snapshots", guard(rolesSnapshots, a.listSnapshots))
	mux.HandleFunc("POST /api/v1/contracts/{service}/snapshots", guard(rolesSnapshotDo, a.createSnapshot))
	mux.HandleFunc("GET /api/v1/contracts/{service}/snapshots/{snapshot_id}", guard(rolesSnapshots, a.getSnapshot))
	mux.HandleFunc("GET /api/v1/gaps", guard(rolesGaps, a.listGaps))
	return mux
}

func guard(roles []auth.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.PrincipalFrom(r.Context())
		if !ok || !p.HasAny(roles...) {
			httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
			return
		}
		next(w, r)
	}
}

func (a *api) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	a.Engine.log.ErrorContext(r.Context(), "contract api", "route", r.Pattern, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

// ---- discovery ----

type serviceEntry struct {
	Service string `json:"service"`
	// Group is the group whose sources produced these calls ("": a source
	// no group claims): the same service name in two groups is two rows.
	Group     string    `json:"group"`
	Kind      string    `json:"kind"`
	Calls     int64     `json:"calls"`
	Ops       int       `json:"ops"`
	InPolicy  bool      `json:"in_policy"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Twin: the service is included in the packs by default (an explicit
	// operator choice, else DefaultTwin of its kind; false for a replaced
	// service).
	Twin bool `json:"twin"`
	// ReplacedBy is set on an old host:<pattern> entry that the group's
	// policy declares since as this external service (ReplacedLookup).
	ReplacedBy string `json:"replaced_by,omitempty"`
}

// TwinKey is the key of a twin choice: the service within its group (the
// plain service name for group "", and as the fallback of every group).
func TwinKey(group, service string) string {
	if group == "" {
		return service
	}
	return group + "/" + service
}

// TwinOf returns the twin choice of (group, service) in a selection.
func TwinOf(sel map[string]bool, group, service string) (bool, bool) {
	if v, ok := sel[TwinKey(group, service)]; ok {
		return v, true
	}
	v, ok := sel[service]
	return v, ok
}

// groupSummary is the op summaries of one group's sources.
type groupSummary struct {
	group string
	sums  []intake.OpSummary
}

// summariesBy returns the summaries of all stored events per selected group
// (sorted by group).
func (a *api) summariesBy(ctx context.Context, sel groupscope.Set) ([]groupSummary, error) {
	gs, err := a.Engine.GroupSources(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(gs))
	for g := range gs {
		if sel.Has(g) {
			names = append(names, g)
		}
	}
	sort.Strings(names)
	out := make([]groupSummary, 0, len(names))
	for _, g := range names {
		sums, err := summaries(ctx, a.Engine.src, time.Time{}, time.Time{}, nil, gs[g])
		if err != nil {
			return nil, err
		}
		out = append(out, groupSummary{group: g, sums: sums})
	}
	return out, nil
}

// oneGroup is the group of a detail endpoint (?group=G): "" without one, or
// with several.
func oneGroup(r *http.Request) string {
	if gs := groupscope.FromRequest(r); len(gs) == 1 {
		return gs[0]
	}
	return ""
}

// groupSources returns the sources of group g for a detail endpoint (nil for
// every group).
func (a *api) groupSources(ctx context.Context, g string) ([]string, error) {
	if g == "" {
		return nil, nil
	}
	return a.Engine.SourcesOf(ctx, groupscope.Set{g})
}

func (a *api) listServices(w http.ResponseWriter, r *http.Request) {
	groups, err := a.summariesBy(r.Context(), groupscope.FromRequest(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type gkey struct{ group, service string }
	by := map[gkey]*serviceEntry{}
	ops := map[gkey]map[string]bool{}
	for _, gsum := range groups {
		for _, s := range gsum.sums {
			k := gkey{gsum.group, s.Service}
			e := by[k]
			if e == nil {
				e = &serviceEntry{Service: s.Service, Group: gsum.group, FirstSeen: s.FirstTS, LastSeen: s.LastTS}
				switch {
				case s.Dir == event.Inbound:
					e.Kind = "inbound"
				case strings.HasPrefix(s.Service, "host:"):
					e.Kind = "outbound-host"
				default:
					e.Kind = "outbound-policy"
				}
				e.InPolicy = e.Kind != "outbound-host"
				by[k] = e
				ops[k] = map[string]bool{}
			}
			e.Calls += s.Count
			ops[k][s.Op] = true
			if s.FirstTS.Before(e.FirstSeen) {
				e.FirstSeen = s.FirstTS
			}
			if s.LastTS.After(e.LastSeen) {
				e.LastSeen = s.LastTS
			}
		}
	}
	var sel map[string]bool
	if a.Twin != nil {
		if sel, err = a.Twin.Selection(r.Context()); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	var replaced func(group, service string) string
	if a.Replaced != nil {
		if replaced, err = a.Replaced.ReplacedBy(r.Context()); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	out := make([]serviceEntry, 0, len(by))
	for k, e := range by {
		e.Ops = len(ops[k])
		e.Twin = DefaultTwin(e.Kind)
		if replaced != nil {
			if e.ReplacedBy = replaced(k.group, k.service); e.ReplacedBy != "" {
				e.Twin = false
			}
		}
		if v, ok := TwinOf(sel, k.group, k.service); ok {
			e.Twin = v
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Group < out[j].Group
	})
	httpx.WriteJSON(w, http.StatusOK, out)
}

// setTwin records whether a discovered service is twinned: {"twin": bool}.
func (a *api) setTwin(w http.ResponseWriter, r *http.Request) {
	svc := r.PathValue("service")
	if a.Twin == nil {
		httpx.WriteError(w, http.StatusNotImplemented, "not_supported", "the twin selection is not stored by this server")
		return
	}
	var in struct {
		Twin  *bool  `json:"twin"`
		Group string `json:"group"`
	}
	if err := httpx.DecodeJSON(w, r, 1<<10, &in); err != nil || in.Twin == nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "twin (boolean) is required")
		return
	}
	if in.Group == "" {
		in.Group = oneGroup(r)
	}
	srcs, err := a.groupSources(r.Context(), in.Group)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sums, err := summaries(r.Context(), a.Engine.src, time.Time{}, time.Time{}, nil, srcs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	inbound, known := false, false
	for _, s := range sums {
		if s.Service == svc {
			known = true
			inbound = inbound || s.Dir == event.Inbound
		}
	}
	if !known {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if inbound && !*in.Twin {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "inbound_always_twinned", "the system under test is always part of a pack")
		return
	}
	err = a.Twin.SetTwin(r.Context(), TwinKey(in.Group, svc), *in.Twin)
	a.record(r, "service.twin", svc, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"service": svc, "group": in.Group, "twin": *in.Twin})
}

type opEntry struct {
	Op          string           `json:"op"`
	Calls       int64            `json:"calls"`
	RouteSource map[string]int64 `json:"route_source"`
	Statuses    map[string]int64 `json:"statuses"`
}

func (a *api) listServiceOps(w http.ResponseWriter, r *http.Request) {
	svc := r.PathValue("service")
	srcs, err := a.groupSources(r.Context(), oneGroup(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sums, err := summaries(r.Context(), a.Engine.src, time.Time{}, time.Time{}, nil, srcs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	by := map[string]*opEntry{}
	for _, s := range sums {
		if s.Service != svc {
			continue
		}
		e := by[s.Op]
		if e == nil {
			e = &opEntry{Op: s.Op, RouteSource: map[string]int64{}, Statuses: map[string]int64{}}
			by[s.Op] = e
		}
		e.Calls += s.Count
		key := "net_error"
		if s.Status != 0 {
			key = strconv.Itoa(s.Status)
		}
		e.Statuses[key] += s.Count
	}
	if len(by) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	out := make([]*opEntry, 0, len(by))
	for _, e := range by {
		// Route sources are counted on a bounded sample of the events, in
		// index order (ORDER BY id would sort every event of the operation).
		n := 0
		_ = a.Engine.src.Scan(r.Context(), intake.Query{Service: svc, Op: e.Op, Limit: 100, AnyOrder: true, SourceIDs: srcs}, func(se *intake.StoredEvent) error {
			e.RouteSource[se.Event.RouteSource]++
			n++
			return nil
		})
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Op < out[j].Op })
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ---- contracts ----

func (a *api) listContracts(w http.ResponseWriter, r *http.Request) {
	infos, err := a.latestInfos(r.Context(), groupscope.FromRequest(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if a.Replaced != nil {
		replaced, err := a.Replaced.ReplacedBy(r.Context())
		if err != nil {
			a.fail(w, r, err)
			return
		}
		for i := range infos {
			infos[i].ReplacedBy = replaced(infos[i].Group, infos[i].Service)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, infos)
}

// latestInfos is the newest snapshot of every (group, service) of the
// selected groups.
func (a *api) latestInfos(ctx context.Context, sel groupscope.Set) ([]SnapshotInfo, error) {
	infos, err := a.Engine.snaps.LatestInfos(ctx)
	if err != nil {
		return nil, err
	}
	out := []SnapshotInfo{}
	for _, i := range infos {
		if sel.Has(i.Group) {
			out = append(out, i)
		}
	}
	return out, nil
}

// latest is the newest snapshot of (group, service). Without a group it is
// the snapshot of every group's traffic, else the only group's snapshot
// when one group has the service.
func (a *api) latest(ctx context.Context, group, svc string) (*Snapshot, error) {
	snap, err := a.Engine.snaps.LatestIn(ctx, group, svc)
	if group != "" || !errors.Is(err, ErrNotFound) {
		return snap, err
	}
	infos, err := a.Engine.snaps.LatestInfos(ctx)
	if err != nil {
		return nil, err
	}
	var only *SnapshotInfo
	for k := range infos {
		if infos[k].Service == svc {
			if only != nil {
				return nil, ErrNotFound
			}
			only = &infos[k]
		}
	}
	if only == nil {
		return nil, ErrNotFound
	}
	return a.Engine.snaps.LatestIn(ctx, only.Group, svc)
}

func wantYAML(r *http.Request) bool {
	switch r.URL.Query().Get("format") {
	case "yaml", "yml":
		return true
	case "json":
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "yaml")
}

func (a *api) writeContract(w http.ResponseWriter, r *http.Request, c *Contract, snap *SnapshotInfo) {
	opts := a.Engine.RenderOptions()
	opts.PackSafe = r.URL.Query().Get("pack_safe") == "true"
	var body []byte
	var err error
	ctype := "application/json; charset=utf-8"
	if wantYAML(r) {
		body, err = c.YAML(opts)
		ctype = "application/yaml; charset=utf-8"
	} else {
		body, err = c.JSON(opts)
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "no-store")
	if snap != nil {
		h.Set("X-TT-Snapshot", snap.SnapshotID)
	}
	_, _ = w.Write(body)
}

// contractOf resolves the contract of the request's service: the latest
// stored snapshot, or one inferred on the fly (not stored). It writes the
// error answer itself and returns ok=false.
func (a *api) contractOf(w http.ResponseWriter, r *http.Request) (c *Contract, snap *SnapshotInfo, ok bool) {
	svc, group := r.PathValue("service"), oneGroup(r)
	s, err := a.latest(r.Context(), group, svc)
	if err == nil {
		return s.Contract, &s.SnapshotInfo, true
	}
	if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, err)
		return nil, nil, false
	}
	// No snapshot yet: infer on the fly (not stored, cached briefly).
	var sel groupscope.Set
	if group != "" {
		sel = groupscope.Set{group}
	}
	c, err = a.Engine.PreviewIn(r.Context(), sel, svc)
	if err != nil {
		a.fail(w, r, err)
		return nil, nil, false
	}
	if c == nil || len(c.Ops) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return nil, nil, false
	}
	return c, nil, true
}

func (a *api) getContract(w http.ResponseWriter, r *http.Request) {
	if c, snap, ok := a.contractOf(w, r); ok {
		a.writeContract(w, r, c, snap)
	}
}

// getPostman answers GET /api/v1/contracts/{service}/postman: the contract
// as a Postman Collection v2.1 file.
func (a *api) getPostman(w http.ResponseWriter, r *http.Request) {
	c, snap, ok := a.contractOf(w, r)
	if !ok {
		return
	}
	opts := a.Engine.RenderOptions()
	opts.PackSafe = r.URL.Query().Get("pack_safe") == "true"
	doc, err := c.JSON(opts)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	base := strings.TrimSpace(r.URL.Query().Get("base_url"))
	if base != "" && !validBaseURL(base) {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_base_url", "base_url must be a short http(s) URL without credentials, query or fragment")
		return
	}
	if base == "" {
		base = DefaultPostmanServiceURL(r.PathValue("service"))
	}
	body, err := PostmanCollection(doc, PostmanOptions{Name: r.PathValue("service"), BaseURL: base})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+safeFileName(r.PathValue("service"))+`.postman_collection.json"`)
	h.Set("Cache-Control", "no-store")
	if snap != nil {
		h.Set("X-TT-Snapshot", snap.SnapshotID)
	}
	_, _ = w.Write(body)
}

// validBaseURL accepts the default {{baseUrl}} of a Postman collection: an
// absolute http or https URL of at most 200 bytes, printable ASCII, with a
// host and no user info, query or fragment (security review r4: a link to
// the export cannot plant a javascript: or credential-carrying URL in a
// collection someone imports).
func validBaseURL(s string) bool {
	if len(s) > 200 || strings.ContainsAny(s, "\"<>\\` ") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") || u.Opaque != "" {
		return false
	}
	return true
}

// safeFileName keeps letters, digits, dot, dash and underscore of a service name.
func safeFileName(s string) string {
	b := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b = append(b, r)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "contract"
	}
	return string(b)
}

// contractStatus answers GET /api/v1/contracts/{service}/status: why a
// contract is (not yet) there and when it will be.
type contractStatus struct {
	Service string `json:"service"`
	Group   string `json:"group"`
	// Calls and Operations are the stored calls and the operations they
	// group into (raw paths templated as in the contract).
	Calls      int64 `json:"calls"`
	Operations int   `json:"operations"`
	// ReadyOperations have at least MinCalls calls: their schema is
	// reliable and they are diffed. BestOpCalls is the busiest operation.
	ReadyOperations int   `json:"ready_operations"`
	BestOpCalls     int64 `json:"best_op_calls"`
	MinCalls        int   `json:"min_calls"`
	KMin            int   `json:"k_min"`
	// InferredOperations have a template inferred from raw paths (the
	// policy declares none).
	InferredOperations int `json:"inferred_operations"`
	// Snapshot is the latest stored snapshot (null before the first).
	Snapshot *SnapshotInfo `json:"snapshot"`
	// NextSnapshotAt is when the scheduled snapshot of the current window
	// runs; WindowHours its length.
	NextSnapshotAt time.Time `json:"next_snapshot_at"`
	WindowHours    float64   `json:"window_hours"`
}

func (a *api) getContractStatus(w http.ResponseWriter, r *http.Request) {
	svc, group := r.PathValue("service"), oneGroup(r)
	srcs, err := a.groupSources(r.Context(), group)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sums, err := summaries(r.Context(), a.Engine.src, time.Time{}, time.Time{}, nil, srcs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cfg := a.Engine.cfg
	st := contractStatus{Service: svc, Group: group, MinCalls: cfg.MinSamples, KMin: cfg.KMin, WindowHours: cfg.Window.Hours()}
	var keys []string
	calls := map[string]int64{}
	for _, s := range sums {
		if s.Service != svc {
			continue
		}
		if _, ok := calls[s.Op]; !ok {
			keys = append(keys, s.Op)
		}
		calls[s.Op] += s.Count
		st.Calls += s.Count
	}
	if len(keys) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	tmpl := inferTemplates(keys)
	byOp := map[string]int64{}
	inferred := map[string]bool{}
	for k, n := range calls {
		op := k
		if t, ok := tmpl[k]; ok {
			op = t
			if t != k || strings.Contains(k, "{") {
				inferred[t] = true
			}
		}
		byOp[op] += n
	}
	st.Operations, st.InferredOperations = len(byOp), len(inferred)
	for _, n := range byOp {
		if n >= int64(cfg.MinSamples) {
			st.ReadyOperations++
		}
		st.BestOpCalls = max(st.BestOpCalls, n)
	}
	if snap, err := a.latest(r.Context(), group, svc); err == nil {
		info := snap.SnapshotInfo
		st.Snapshot = &info
	} else if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	cur := a.Engine.LastCompletedWindow(a.Engine.now())
	st.NextSnapshotAt = cur.To.Add(cfg.Window).Add(cfg.Grace)
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (a *api) listSnapshots(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid limit")
			return
		}
		limit = n
	}
	infos, err := a.Engine.snaps.ListIn(r.Context(), oneGroup(r), r.PathValue("service"), limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if infos == nil {
		infos = []SnapshotInfo{}
	}
	httpx.WriteJSON(w, http.StatusOK, infos)
}

func (a *api) getSnapshot(w http.ResponseWriter, r *http.Request) {
	svc, id, group := r.PathValue("service"), r.PathValue("snapshot_id"), oneGroup(r)
	if other := r.URL.Query().Get("diff_against"); other != "" {
		d, err := a.Engine.DiffSnapshotsIn(r.Context(), group, svc, id, other)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, d)
		return
	}
	snap, err := a.Engine.snaps.GetIn(r.Context(), group, svc, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeContract(w, r, snap.Contract, &snap.SnapshotInfo)
}

type snapshotRequest struct {
	From *time.Time `json:"from"`
	To   *time.Time `json:"to"`
	// Recent covers the last window length up to now ("Aggiorna contratto
	// ora" in the console): a new service gets its contract without
	// waiting for the end of the day.
	Recent bool `json:"recent"`
}

// createSnapshot (additive to the admin API) takes a snapshot of one service
// now; without a body it covers the last completed window.
func (a *api) createSnapshot(w http.ResponseWriter, r *http.Request) {
	svc := r.PathValue("service")
	var req snapshotRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, 4096, &req); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
			return
		}
	}
	win := a.Engine.LastCompletedWindow(a.Engine.now())
	if req.From != nil && req.To != nil {
		if !req.To.After(*req.From) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "to must be after from")
			return
		}
		win = Window{From: req.From.UTC(), To: req.To.UTC()}
	} else if req.Recent {
		now := a.Engine.now().UTC().Truncate(time.Second)
		win = Window{From: now.Add(-a.Engine.cfg.Window), To: now.Add(time.Second)}
	}
	var snaps []*Snapshot
	var err error
	if g := oneGroup(r); g != "" {
		snaps, err = a.Engine.SnapshotWindowIn(r.Context(), win, g, svc)
	} else {
		snaps, err = a.Engine.SnapshotWindow(r.Context(), win, svc)
	}
	a.record(r, "contract.snapshot", svc, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if len(snaps) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no events for this service in the window")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, snaps[0].SnapshotInfo)
}

func (a *api) record(r *http.Request, action, service string, err error) {
	if a.Audit == nil {
		return
	}
	actor, reqID := auth.RequestActor(r)
	oc := audit.Success
	if err != nil {
		oc = audit.Failure
	}
	_, _ = a.Audit.Record(context.WithoutCancel(r.Context()), audit.Event{Actor: actor, Action: action,
		Target: audit.Target{Type: "service", ID: audit.SafeValue(service)}, Outcome: oc, RequestID: reqID})
}

// ---- gaps ----

func (a *api) listGaps(w http.ResponseWriter, r *http.Request) {
	sel := groupscope.FromRequest(r)
	infos, err := a.latestInfos(r.Context(), sel)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := []Gap{}
	add := func(gs []Gap, group string) {
		for _, g := range gs {
			g.Group = group
			out = append(out, g)
		}
	}
	for _, i := range infos {
		if g, ok := a.gaps.get(i.seq); ok {
			add(g, i.Group)
			continue
		}
		snap, err := a.Engine.snaps.GetIn(r.Context(), i.Group, i.Service, i.SnapshotID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		g := snap.Contract.Gaps()
		a.gaps.put(i.seq, g)
		add(g, i.Group)
	}
	var svcGroups map[string][]string
	if !sel.All() {
		if svcGroups, err = a.Engine.ServiceGroups(r.Context()); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	for _, g := range a.ExtraGaps {
		more, err := g.Gaps(r.Context())
		if err != nil {
			a.Engine.log.WarnContext(r.Context(), "contract: extra gaps", "err", err)
			continue
		}
		for _, x := range more {
			// Gaps of the miner (rules, entities) belong to the groups of
			// their service.
			if svcGroups == nil || sel.Any(svcGroups[x.Service]) {
				out = append(out, x)
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
