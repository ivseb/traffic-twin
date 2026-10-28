package world

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Admin API prefixes served by this package.
const (
	PrefixArchetypes = "/api/v1/archetypes"
	PrefixWorlds     = "/api/v1/worlds"
)

// Roles per operation (x-tt-roles of api/admin-api.v1.openapi.yaml).
var (
	rolesRead  = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor}
	rolesWrite = []auth.Role{auth.RoleOperator}
)

// Job is the admin API Job object. Builds run synchronously for now (the
// answer already carries the final status); /api/v1/jobs is not served by
// this package.
type Job struct {
	JobID  string `json:"job_id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Mount serves the archetype and world endpoints of the admin API:
//
//	GET  /api/v1/archetypes                              operator, publisher, auditor
//	POST /api/v1/archetypes/build                        operator
//	GET  /api/v1/worlds                                  operator, publisher, auditor
//	POST /api/v1/worlds                                  operator
//	GET  /api/v1/worlds/{world_id}                       operator, publisher, auditor
//	GET  /api/v1/worlds/{world_id}/customers             operator, publisher, auditor (page of synthetic customers, extension)
//	GET  /api/v1/worlds/{world_id}/customers/{customer}  operator, publisher, auditor (preview, extension)
//
// Wiring in cmd/tt (tt core):
//
//	ws, _ := world.New(world.Options{DB: db, Audit: auditLog, Events: intake.NewStore(db),
//		Contracts: contractSource, Rules: ruleSource, Outcomes: minerOutcomes})
//	world.Mount(srv, ws)
func Mount(srv *server.Server, s *Service) {
	h := s.Handler()
	srv.Mount(PrefixArchetypes, h, rolesRead...)
	srv.Mount(PrefixWorlds, h, rolesRead...)
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error

// Handler returns the HTTP handler (behind auth.Require).
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, roles []auth.Role, h handlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			if !p.HasAny(roles...) {
				s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny", Outcome: audit.Denied, Reason: "missing_role",
					Target: audit.RouteTarget(r)})
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			if err := h(w, r, p); err != nil {
				var ae *APIError
				if errors.As(err, &ae) {
					httpx.WriteErrorDetails(w, ae.Status, ae.Code, ae.Message, ae.Details)
					return
				}
				s.o.Logger.ErrorContext(r.Context(), "world: request failed", "err", err)
				httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
			}
		})
	}
	route("GET "+PrefixArchetypes, rolesRead, s.apiArchetypes)
	route("POST "+PrefixArchetypes+"/build", rolesWrite, s.apiBuild)
	route("GET "+PrefixWorlds, rolesRead, s.apiList)
	route("POST "+PrefixWorlds, rolesWrite, s.apiGenerate)
	route("GET "+PrefixWorlds+"/{world_id}", rolesRead, s.apiGet)
	route("GET "+PrefixWorlds+"/{world_id}/customers", rolesRead, s.apiCustomers)
	route("GET "+PrefixWorlds+"/{world_id}/customers/{customer_id}", rolesRead, s.apiPreview)
	notFound := func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	}
	mux.HandleFunc(PrefixArchetypes+"/", notFound)
	mux.HandleFunc(PrefixWorlds+"/", notFound)
	return mux
}

func (s *Service) record(ctx context.Context, e audit.Event) {
	if e.RequestID == "" {
		e.RequestID = httpx.RequestID(ctx)
	}
	if _, err := s.o.Audit.Record(ctx, e); err != nil {
		s.o.Logger.ErrorContext(ctx, "world: audit write failed", "action", e.Action, "err", err)
	}
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(w, r, 64<<10, dst); err != nil {
		return apiErr(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
	}
	return nil
}

// oneGroup is the group selected by ?group= (one value; "" without).
func oneGroup(r *http.Request) string {
	if gs := groupscope.FromRequest(r); len(gs) == 1 {
		return gs[0]
	}
	return ""
}

var groupRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func (s *Service) apiArchetypes(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	group := oneGroup(r)
	b, _, err := s.LatestBuildIn(r.Context(), group)
	if err != nil {
		return err
	}
	out := ArchetypeList{KMin: s.o.KMin, Archetypes: []Archetype{}, Group: group}
	if b != nil {
		out.KMin, out.Profiles, out.Dropped = b.KMin, b.Profiles, b.Dropped
		out.Built = true
		if b.Archetypes != nil {
			out.Archetypes = b.Archetypes
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

// ArchetypeList is the answer of GET /api/v1/archetypes: the archetypes of
// the latest build with the k they were built with. Without a build,
// archetypes is empty, built is false and k_min is the configured one.
type ArchetypeList struct {
	KMin       int         `json:"k_min"`
	Built      bool        `json:"built"`
	Profiles   int         `json:"profiles"`
	Dropped    int         `json:"dropped_subjects"`
	Archetypes []Archetype `json:"archetypes"`
	// Group is the group the archetypes were built for ("": every group).
	Group string `json:"group"`
}

func (s *Service) apiBuild(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	req := struct {
		KMin  *int   `json:"k_min"`
		Group string `json:"group"`
	}{}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.KMin == nil {
		return apiErr(http.StatusBadRequest, "bad_request", "k_min is required")
	}
	if req.Group == "" {
		req.Group = oneGroup(r)
	}
	if req.Group != "" && !groupRE.MatchString(req.Group) {
		return apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	b, id, err := s.BuildArchetypesIn(r.Context(), *req.KMin, req.Group)
	ev := audit.Event{Actor: p.AuditActor(), Action: "archetypes.build", Target: audit.Target{Type: "archetypes"}, Outcome: audit.Success}
	if err != nil {
		ev.Outcome, ev.Reason = audit.Failure, "build_failed"
		s.record(r.Context(), ev)
		return err
	}
	ev.Target.ID = strconv.FormatInt(id, 10)
	ev.Details = map[string]string{"k_min": strconv.Itoa(b.KMin), "archetypes": strconv.Itoa(len(b.Archetypes)),
		"profiles": strconv.Itoa(b.Profiles), "dropped_subjects": strconv.Itoa(b.Dropped), "group": audit.SafeValue(req.Group)}
	s.record(r.Context(), ev)
	httpx.WriteJSON(w, http.StatusAccepted, Job{JobID: httpx.NewID("job_"), Kind: "archetypes.build", Status: "done",
		Result: map[string]any{"archetypes": len(b.Archetypes), "profiles": b.Profiles, "dropped_subjects": b.Dropped, "k_min": b.KMin, "group": req.Group}})
	return nil
}

func (s *Service) apiList(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	l, err := s.List(r.Context())
	if err != nil {
		return err
	}
	sel := groupscope.FromRequest(r)
	out := []Info{}
	for _, i := range l {
		if sel.Has(i.Group) {
			out = append(out, i)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

var ruleIDRE = regexp.MustCompile(`^r-[0-9]{4,}$`)

// serviceRE: a service of the events (a name, or host:<pattern>).
var serviceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:{}*-]{0,127}$`)

func (s *Service) apiGenerate(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Seed          *int64   `json:"seed"`
		Customers     *int     `json:"customers"`
		UseArchetypes *bool    `json:"use_archetypes"`
		T0            *string  `json:"t0"`
		Rules         []string `json:"rules"`
		Services      []string `json:"services"`
		Group         string   `json:"group"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Seed == nil || req.Customers == nil || *req.Seed < 0 {
		return apiErr(http.StatusBadRequest, "bad_request", "seed and customers are required")
	}
	if req.Group != "" && !groupRE.MatchString(req.Group) {
		return apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	g := GenerateRequest{Seed: uint64(*req.Seed), Customers: *req.Customers, UseArchetypes: req.UseArchetypes, Rules: req.Rules, Services: req.Services, Group: req.Group}
	for _, id := range req.Rules {
		if !ruleIDRE.MatchString(id) {
			return apiErr(http.StatusUnprocessableEntity, "invalid_rules", "malformed rule id")
		}
	}
	if len(req.Services) > 500 {
		return apiErr(http.StatusUnprocessableEntity, "invalid_services", "too many services")
	}
	for _, sv := range req.Services {
		if !serviceRE.MatchString(sv) {
			return apiErr(http.StatusUnprocessableEntity, "invalid_services", "malformed service name")
		}
	}
	if req.T0 != nil {
		t, err := parseTime(*req.T0)
		if err != nil {
			return apiErr(http.StatusUnprocessableEntity, "invalid_t0", "t0 must be a date-time")
		}
		g.T0 = &t
	}
	info, err := s.Generate(r.Context(), g, p.AuditActor())
	ev := audit.Event{Actor: p.AuditActor(), Action: "world.generate", Target: audit.Target{Type: "world"}, Outcome: audit.Success}
	if err != nil {
		ev.Outcome, ev.Reason = audit.Failure, "generate_failed"
		var ae *APIError
		if errors.As(err, &ae) {
			ev.Reason = ae.Code
		}
		s.record(r.Context(), ev)
		return err
	}
	ev.Target.ID = info.WorldID
	ev.Details = map[string]string{"seed": strconv.FormatUint(info.Seed, 10), "customers": strconv.Itoa(info.Customers),
		"entities": strconv.Itoa(info.Entities), "sha256": info.SHA256}
	s.record(r.Context(), ev)
	httpx.WriteJSON(w, http.StatusAccepted, Job{JobID: httpx.NewID("job_"), Kind: "world.generate", Status: "done", Result: info})
	return nil
}

func (s *Service) apiGet(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	rec, err := s.Record(r.Context(), r.PathValue("world_id"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, rec.Info)
	return nil
}

var customerIDRE = regexp.MustCompile(`^[A-Z]{2,5}-SYN-[0-9]{4,}$`)

func (s *Service) apiPreview(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	cid := r.PathValue("customer_id")
	if !customerIDRE.MatchString(cid) {
		return ErrNotFound
	}
	lines, err := s.Preview(r.Context(), r.PathValue("world_id"), cid)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"world_id": r.PathValue("world_id"), "customer": cid, "lines": lines})
	return nil
}

// apiCustomers answers GET /api/v1/worlds/{world_id}/customers?q=&offset=&limit=.
func (s *Service) apiCustomers(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	q := r.URL.Query()
	num := func(name string, def int) (int, error) {
		v := q.Get(name)
		if v == "" {
			return def, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, apiErr(http.StatusBadRequest, "bad_request", name+" must be a non-negative integer")
		}
		return n, nil
	}
	offset, err := num("offset", 0)
	if err != nil {
		return err
	}
	limit, err := num("limit", DefaultCustomerPage)
	if err != nil {
		return err
	}
	search := q.Get("q")
	if len(search) > 100 {
		return apiErr(http.StatusBadRequest, "bad_request", "q is limited to 100 characters")
	}
	page, err := s.Customers(r.Context(), r.PathValue("world_id"), search, offset, limit)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, page)
	return nil
}
