package mockreg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Prefixes of the APIs.
const (
	PrefixMocks = "/api/v1/mocks"
	PrefixAgent = "/api/v1/mock-agent"
)

// Roles of the admin API (admin implies all of them).
var (
	RolesRead  = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor}
	RolesWrite = []auth.Role{auth.RoleOperator}
	// MountRoles is the union, for srv.Mount.
	MountRoles = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor}
)

// maxCommandsPerReport bounds what one report answer carries (the results
// come back in the next report, within the admin body limit).
const maxCommandsPerReport = 10

// HandlerFunc is an admin API handler with the authenticated principal.
type HandlerFunc func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error

func (g *Registry) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		httpx.WriteError(w, ae.status, ae.code, ae.message)
		return
	}
	g.log.ErrorContext(r.Context(), "mockreg: request failed", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

// AdminHandler serves /api/v1/mocks (behind auth.Require).
//
//	GET    /api/v1/mocks                                 mocks, managed mocks, how to start one
//	GET    /api/v1/mocks/tokens                          mock tokens (no secrets)
//	POST   /api/v1/mocks/tokens                          new token (secret shown once) + setup snippets
//	DELETE /api/v1/mocks/tokens/{token_id}               revoke
//	POST   /api/v1/mocks/managed                         start or refresh the mock of a group in Kubernetes
//	POST   /api/v1/mocks/managed/{group}/restart         new pods
//	DELETE /api/v1/mocks/managed/{group}                 stop
//	GET    /api/v1/mocks/identity?group=                 session per user of a group (identity.go)
//	PUT    /api/v1/mocks/identity                        set header and claim
//	POST   /api/v1/mocks/identity/map                    map a test user (hashed) to a synthetic customer
//	DELETE /api/v1/mocks/identity/map/{hash}?group=      remove a mapped user
//	GET    /api/v1/mocks/pages?group=                    third-party pages of a group (pages.go)
//	PUT    /api/v1/mocks/pages                           replace them
//	GET    /api/v1/mocks/{mock_id}/calls?since=          last calls
//	POST   /api/v1/mocks/{mock_id}/commands              queue a control call (scenario, faults, clock, sessions)
//	GET    /api/v1/mocks/{mock_id}/commands/{command_id} its answer
//
// extra mounts more routes on the same mux (POST /api/v1/mocks/prepare, in core).
func (g *Registry) AdminHandler(audited *audit.Log, extra func(route func(pattern string, roles []auth.Role, h HandlerFunc))) http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, roles []auth.Role, h HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			if !p.HasAny(roles...) {
				g.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny", Target: audit.RouteTarget(r), Outcome: audit.Denied,
					Reason: "missing_role", RequestID: httpx.RequestID(r.Context())})
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			if err := h(w, r, p); err != nil {
				g.writeErr(w, r, err)
			}
		})
	}
	route("GET "+PrefixMocks, RolesRead, g.apiList)
	route("GET "+PrefixMocks+"/tokens", RolesRead, g.apiTokens)
	route("POST "+PrefixMocks+"/tokens", RolesWrite, g.apiCreateToken)
	route("DELETE "+PrefixMocks+"/tokens/{token_id}", RolesWrite, g.apiRevokeToken)
	route("POST "+PrefixMocks+"/managed", RolesWrite, g.apiStartManaged)
	route("POST "+PrefixMocks+"/managed/{group}/restart", RolesWrite, g.apiRestartManaged)
	route("DELETE "+PrefixMocks+"/managed/{group}", RolesWrite, g.apiStopManaged)
	route("GET "+PrefixMocks+"/identity", RolesRead, g.apiIdentity)
	route("PUT "+PrefixMocks+"/identity", RolesWrite, g.apiSetIdentity)
	route("POST "+PrefixMocks+"/identity/map", RolesWrite, g.apiAddIdentityUser)
	route("DELETE "+PrefixMocks+"/identity/map/{hash}", RolesWrite, g.apiRemoveIdentityUser)
	route("GET "+PrefixMocks+"/pages", RolesRead, g.apiPages)
	route("PUT "+PrefixMocks+"/pages", RolesWrite, g.apiSetPages)
	route("GET "+PrefixMocks+"/{mock_id}/calls", RolesRead, g.apiCalls)
	route("POST "+PrefixMocks+"/{mock_id}/commands", RolesWrite, g.apiEnqueue)
	route("GET "+PrefixMocks+"/{mock_id}/commands/{command_id}", RolesRead, g.apiCommand)
	if extra != nil {
		extra(route)
	}
	mux.HandleFunc(PrefixMocks+"/", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	})
	return mux
}

// ConsoleURL is mock.console_url, or the origin of the request.
func (g *Registry) ConsoleURL(r *http.Request) string {
	if g.o.ConsoleURL != "" {
		return strings.TrimSuffix(g.o.ConsoleURL, "/")
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// ListView is the answer of GET /api/v1/mocks.
type ListView struct {
	Mocks       []MockView    `json:"mocks"`
	Managed     []ManagedView `json:"managed"`
	Environment Environment   `json:"environment"`
	// Latest maps each group with mocks to its newest published pack.
	Latest map[string]string `json:"latest_packs"`
}

func (g *Registry) apiList(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ctx := r.Context()
	sel := groupscope.FromRequest(r)
	managed, err := g.managedList(ctx)
	if err != nil {
		return err
	}
	mtok := map[string]bool{}
	groups := map[string]bool{}
	for _, m := range managed {
		mtok[m.TokenID] = true
		groups[m.Group] = true
	}
	for _, gname := range g.groupsOfInstances() {
		groups[gname] = true
	}
	for _, gname := range sel {
		groups[gname] = true
	}
	latest := map[string]string{}
	for gname := range groups {
		if !sel.Has(gname) {
			continue
		}
		id, err := g.latestPack(ctx, gname)
		if err != nil {
			return err
		}
		latest[gname] = id
	}
	out := ListView{Mocks: []MockView{}, Managed: []ManagedView{}, Environment: g.environment(g.ConsoleURL(r)), Latest: latest}
	for _, m := range g.mocks(g.o.Wall(), mtok, latest) {
		if sel.Has(m.Group) {
			out.Mocks = append(out.Mocks, m)
		}
	}
	for _, m := range managed {
		if sel.Has(m.Group) {
			out.Managed = append(out.Managed, m)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (g *Registry) apiTokens(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	l, err := g.ListTokens(r.Context())
	if err != nil {
		return err
	}
	sel := groupscope.FromRequest(r)
	out := []TokenInfo{}
	for _, t := range l {
		if sel.Has(t.Group) {
			out = append(out, t)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(w, r, 64<<10, dst); err != nil {
		return apiErr(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
	}
	return nil
}

func (g *Registry) apiCreateToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Group         string `json:"group"`
		Label         string `json:"label"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	t, err := g.CreateToken(r.Context(), p, req.Group, req.Label, req.ExpiresInDays, false)
	if err != nil {
		return err
	}
	keys := ""
	if g.o.GatePubKeys != nil {
		keys, _ = g.o.GatePubKeys(r.Context())
	}
	t.Setup = setup(g.ConsoleURL(r), t.Group, g.o.Image, keys, t.Token)
	httpx.WriteJSON(w, http.StatusCreated, t)
	return nil
}

func (g *Registry) apiRevokeToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := g.RevokeToken(r.Context(), p, r.PathValue("token_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (g *Registry) apiStartManaged(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Group string `json:"group"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	v, err := g.StartManaged(r.Context(), p, req.Group)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (g *Registry) apiRestartManaged(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	v, err := g.RestartManaged(r.Context(), p, r.PathValue("group"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (g *Registry) apiStopManaged(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	group := r.PathValue("group")
	if !GroupRE.MatchString(group) {
		return errNotFound
	}
	if err := g.StopManaged(r.Context(), p, group); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func mockID(r *http.Request) (string, error) {
	id := r.PathValue("mock_id")
	if !reMockID.MatchString(id) {
		return "", errNotFound
	}
	return id, nil
}

func (g *Registry) apiCalls(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	id, err := mockID(r)
	if err != nil {
		return err
	}
	since := 0
	if s := r.URL.Query().Get("since"); s != "" {
		if since, err = strconv.Atoi(s); err != nil || since < 0 {
			return apiErr(http.StatusBadRequest, "bad_request", "since must be a non-negative integer")
		}
	}
	calls, last, _, err := g.calls(id, since)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"calls": calls, "last_seq": last})
	return nil
}

var commandPathRE = regexp.MustCompile(`^/__tt/(pack|scenarios|customers|pages|sessions(/[A-Za-z0-9_-]{1,64}(/(reset|customer|clock|clock/advance|faults|scenario|entities|pages/[a-z0-9][a-z0-9-]{0,62}/(complete|auto)))?)?)$`)

func (g *Registry) apiEnqueue(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id, err := mockID(r)
	if err != nil {
		return err
	}
	var req struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		return apiErr(http.StatusUnprocessableEntity, "invalid_command", "method must be GET, POST, PUT or DELETE")
	}
	if !commandPathRE.MatchString(req.Path) {
		return apiErr(http.StatusUnprocessableEntity, "invalid_command", "path must be a control path of sessions, scenarios, customers or the pack")
	}
	if len(req.Body) > 0 && string(req.Body) == "null" {
		req.Body = nil
	}
	cid, group, err := g.enqueue(id, mock.Command{Method: req.Method, Path: req.Path, Body: req.Body}, g.o.Wall())
	if err != nil {
		return err
	}
	if req.Method != http.MethodGet {
		g.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "mock.command", Target: audit.Target{Type: "mock", ID: audit.SafeValue(id)}, Outcome: audit.Success,
			Details: map[string]string{"group": group, "method": req.Method, "path": audit.SafeValue(req.Path)}})
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"command_id": cid, "status": "pending"})
	return nil
}

func (g *Registry) apiCommand(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	id, err := mockID(r)
	if err != nil {
		return err
	}
	v, _, err := g.command(id, r.PathValue("command_id"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// AgentHandler serves /api/v1/mock-agent for the mocks in console mode
// (public mount: the mock token is the only credential, checked here).
//
//	GET  /api/v1/mock-agent/pack     the latest published pack of the token's group (.ttpack)
//	POST /api/v1/mock-agent/report   status, URLs, sessions, calls, command results -> latest pack id, commands
func (g *Registry) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h func(w http.ResponseWriter, r *http.Request, t *TokenInfo) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			// Refused tokens are counted per client and token id: guessing
			// the secret of one token is slowed down, while a client behind
			// the same ingress cannot lock out the other tokens.
			client := httpx.ClientIP(r) + "|" + presentedTokenID(r)
			if wait := g.fails.blocked(client, g.o.Wall()); wait > 0 {
				// No lookup at all until the budget refills (a mock retries on 429).
				w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
				httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many refused mock tokens from this client")
				return
			}
			t, err := g.authenticate(r.Context(), r)
			if err == nil {
				err = h(w, r, t)
			}
			if errors.Is(err, errUnauthorized) {
				g.fails.fail(client, g.o.Wall())
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			if err != nil {
				g.writeErr(w, r, err)
			}
		}
	}
	mux.HandleFunc("GET "+PrefixAgent+"/pack", auth(g.agentPack))
	mux.HandleFunc("POST "+PrefixAgent+"/report", auth(g.agentReport))
	mux.HandleFunc(PrefixAgent+"/", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	})
	return mux
}

// agentActor is how a mock appears in the audit log.
func agentActor(t *TokenInfo) audit.Actor {
	return audit.Actor{Kind: audit.ActorSystem, ID: "tt-mock/" + t.TokenID}
}

func (g *Registry) agentPack(w http.ResponseWriter, r *http.Request, t *TokenInfo) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	id, err := g.latestPack(ctx, t.Group)
	if err != nil {
		return err
	}
	if id == "" {
		return apiErr(http.StatusNotFound, "no_pack", "the group has no published pack yet: prepare the mock in the console")
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Trim(inm, `"`) == id {
		w.Header().Set("ETag", `"`+id+`"`)
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	b, err := g.o.Packs.Archive(ctx, id, t.Group, agentActor(t))
	if err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "application/gzip")
	h.Set(mock.HeaderPackID, id)
	h.Set("ETag", `"`+id+`"`)
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return nil
}

func (g *Registry) agentReport(w http.ResponseWriter, r *http.Request, t *TokenInfo) error {
	var rep mock.Report
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	if err := dec.Decode(&rep); err != nil {
		return apiErr(http.StatusBadRequest, "bad_request", "invalid report")
	}
	now := g.o.Wall()
	cmds, err := g.report(t, &rep, now)
	if err != nil {
		return err
	}
	held := false
	before, err := g.latestPack(r.Context(), t.Group)
	if err != nil {
		return err
	}
	// A mock without the latest pack gets the answer at once: it has a
	// pack to download (or one it refused, whose error is shown already).
	upToDate := before == "" || rep.PackID == before || strings.HasPrefix(rep.PackError, before+":")
	if len(cmds) == 0 && upToDate {
		// Long poll: hold the answer until a command is queued, a pack is
		// published or the token revoked, at most one report interval. The
		// mock then reports again at once, so commands reach it in
		// milliseconds and the journal is at most one interval late.
		held = true
		if wake := g.waker(t.TokenID + "." + rep.Instance); wake != nil {
			tm := time.NewTimer(g.o.ReportInterval)
			select {
			case <-wake:
			case <-tm.C:
			case <-r.Context().Done():
			}
			tm.Stop()
		}
		g.mu.Lock()
		if in := g.instances[t.TokenID+"."+rep.Instance]; in != nil {
			if in.revoked {
				g.mu.Unlock()
				return errUnauthorized
			}
			cmds, in.queued = in.queued, nil
		}
		g.mu.Unlock()
	}
	if len(cmds) > maxCommandsPerReport {
		// put the rest back: they go with the next answers
		g.mu.Lock()
		if in := g.instances[t.TokenID+"."+rep.Instance]; in != nil {
			in.queued = append(cmds[maxCommandsPerReport:], in.queued...)
		}
		g.mu.Unlock()
		cmds = cmds[:maxCommandsPerReport]
	}
	latest, err := g.latestPack(r.Context(), t.Group)
	if err != nil {
		return err
	}
	if cmds == nil {
		cmds = []mock.Command{}
	}
	ident, err := g.identityWire(r.Context(), t.Group)
	if err != nil {
		return err
	}
	pages, err := g.pagesWire(r.Context(), t.Group)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, mock.ReportAnswer{PackID: latest, Commands: cmds, IntervalS: int(g.o.ReportInterval / time.Second), Held: held, Identity: ident, Pages: pages})
	return nil
}
