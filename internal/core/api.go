package core

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// SpecVersion is the admin API version implemented (info.version of
// api/admin-api.v1.openapi.yaml).
const SpecVersion = "1.23.0"

const maxAPIJSON = 64 << 10

// apiError is an error with an HTTP status and a stable code.
type apiError struct {
	status        int
	code, message string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

func apiErr(status int, code, msg string) error { return &apiError{status, code, msg} }

type handler func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error

// router builds a handler that checks the per-operation roles (an empty
// list means any authenticated user), audits denials and maps errors.
type router struct {
	c   *Core
	mux *http.ServeMux
}

func (c *Core) newRouter() *router { return &router{c: c, mux: http.NewServeMux()} }

func (rt *router) handle(pattern string, roles []auth.Role, h handler) {
	rt.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		if len(roles) > 0 && !p.HasAny(roles...) {
			rt.c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny",
				Target: audit.RouteTarget(r), Outcome: audit.Denied, Reason: "missing_role"})
			httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
			return
		}
		if err := h(w, r, p); err != nil {
			rt.c.writeErr(w, err)
		}
	})
}

func (c *Core) writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		httpx.WriteError(w, ae.status, ae.code, ae.message)
	case errors.Is(err, auth.ErrUserNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "user not found")
	case errors.Is(err, auth.ErrUserExists):
		httpx.WriteError(w, http.StatusConflict, "user_exists", "user already exists")
	case errors.Is(err, auth.ErrInvalidUsername):
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", auth.ErrInvalidUsername.Error())
	default:
		c.log.Error("admin api error", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (c *Core) record(ctx context.Context, e audit.Event) {
	if c.audit == nil { // unit tests of the wrappers
		return
	}
	if _, err := c.audit.Record(ctx, e); err != nil {
		c.log.Error("audit write failed", "action", e.Action)
	}
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(w, r, maxAPIJSON, dst); err != nil {
		return apiErr(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
	}
	return nil
}

var rolesAny = []auth.Role(nil)

// mountAPI mounts the admin API endpoints composed here.
func (c *Core) mountAPI() {
	// Users (admin-api users).
	users := c.newRouter()
	users.handle("GET /api/v1/users", []auth.Role{auth.RoleAdmin, auth.RoleAuditor}, c.apiListUsers)
	users.handle("POST /api/v1/users", []auth.Role{auth.RoleAdmin}, c.apiCreateUser)
	users.handle("PATCH /api/v1/users/{user_id}", []auth.Role{auth.RoleAdmin}, c.apiUpdateUser)
	users.handle("DELETE /api/v1/users/{user_id}", []auth.Role{auth.RoleAdmin}, c.apiDeleteUser)
	c.srv.Mount("/api/v1/users", users.mux, auth.RoleAdmin, auth.RoleAuditor)

	// Exports of packs to other mock tools.
	exp := c.newRouter()
	exp.handle("POST /api/v1/exports", []auth.Role{auth.RolePublisher}, c.apiRunExport)
	exp.handle("GET /api/v1/exports/{export_id}", []auth.Role{auth.RolePublisher, auth.RoleAuditor}, c.apiGetExport)
	exp.handle("GET /api/v1/exports/{export_id}/download", []auth.Role{auth.RolePublisher}, c.apiDownloadExport)
	c.srv.Mount("/api/v1/exports", c.longJobs(map[string]string{"POST /api/v1/exports": "export"}, exp.mux), auth.RolePublisher, auth.RoleAuditor)

	// Event-level export (zone B only).
	ev := c.newRouter()
	ev.handle("POST /api/v1/events/export", []auth.Role{auth.RoleEventExporter}, c.apiExportEvents)
	ev.handle("GET /api/v1/events/export/{job_id}/download", []auth.Role{auth.RoleEventExporter}, c.apiDownloadEvents)
	c.srv.Mount("/api/v1/events", c.longJobs(map[string]string{"POST /api/v1/events/export": "events.export"}, ev.mux), auth.RoleEventExporter)

	// Settings: labels are editable by an admin, everything else is shown read-only.
	set := c.newRouter()
	set.handle("GET /api/v1/settings", []auth.Role{auth.RoleAdmin, auth.RoleOperator}, c.apiGetSettings)
	set.handle("PATCH /api/v1/settings", []auth.Role{auth.RoleAdmin}, c.apiUpdateSettings)
	c.srv.Mount("/api/v1/settings", set.mux, auth.RoleAdmin, auth.RoleOperator)

	// Jobs and version: any authenticated user.
	sys := c.newRouter()
	sys.handle("GET /api/v1/jobs", rolesAny, c.apiListJobs)
	sys.handle("GET /api/v1/jobs/{job_id}", rolesAny, c.apiGetJob)
	c.srv.MountAuthenticated("/api/v1/jobs", sys.mux)
	ver := c.newRouter()
	ver.handle("GET /api/v1/version", rolesAny, c.apiVersion)
	c.srv.MountAuthenticated("/api/v1/version", ver.mux)

	// keyguard status and audit (proxied, identifiers and counts only).
	kg := c.newRouter()
	kg.handle("GET /api/v1/keyguard/status", []auth.Role{auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor}, c.apiKeyguardStatus)
	kg.handle("GET /api/v1/keyguard/audit", []auth.Role{auth.RoleAuditor}, c.apiKeyguardAudit)
	c.srv.Mount("/api/v1/keyguard", kg.mux, auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor)

	// Store retention and purge.
	st := c.newRouter()
	st.handle("GET /api/v1/store/retention", []auth.Role{auth.RoleAdmin, auth.RoleAuditor}, c.apiGetRetention)
	st.handle("PUT /api/v1/store/retention", []auth.Role{auth.RoleAdmin}, c.apiSetRetention)
	st.handle("POST /api/v1/store/purge", []auth.Role{auth.RoleAdmin}, c.apiPurge)
	st.handle("GET /api/v1/store/usage", []auth.Role{auth.RoleAdmin, auth.RoleAuditor}, c.apiStoreUsage)
	st.handle("POST /api/v1/store/maintenance", []auth.Role{auth.RoleAdmin}, c.apiStoreMaintenance)
	st.handle("GET /api/v1/store/traffic", []auth.Role{auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor}, c.apiStoreTraffic)
	c.srv.Mount("/api/v1/store", st.mux, auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor)

	// Quarantine queue.
	q := c.newRouter()
	q.handle("GET /api/v1/quarantine", []auth.Role{auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor}, c.apiListQuarantine)
	q.handle("POST /api/v1/quarantine/{item_id}/resolve", []auth.Role{auth.RolePolicyApprover}, c.apiResolveQuarantine)
	c.srv.Mount("/api/v1/quarantine", q.mux, auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor)

	// Hosts registry (spec v1.5): every outbound host, grouped by
	// registrable domain; twin creates a policy draft.
	hs := c.newRouter()
	hs.handle("GET /api/v1/hosts", rolesHosts, c.apiListHosts)
	hs.handle("POST /api/v1/hosts/{pattern}/twin", rolesHosts, c.apiTwinHost)
	c.srv.Mount("/api/v1/hosts", hs.mux, rolesHosts...)

	// Scenario presets (stored here, used by pack builds).
	sp := c.newRouter()
	rolesPresetRead := []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor}
	sp.handle("GET /api/v1/scenario-presets", rolesPresetRead, c.apiListPresets)
	sp.handle("POST /api/v1/scenario-presets", []auth.Role{auth.RoleOperator}, c.apiCreatePreset)
	sp.handle("PUT /api/v1/scenario-presets/{preset_id}", []auth.Role{auth.RoleOperator}, c.apiUpdatePreset)
	sp.handle("DELETE /api/v1/scenario-presets/{preset_id}", []auth.Role{auth.RoleOperator}, c.apiDeletePreset)
	c.srv.Mount("/api/v1/scenario-presets", sp.mux, rolesPresetRead...)

	c.mountUserAPI()
}

// rulesHandler serves the miner's /api/v1/rules plus POST
// /api/v1/rules/mine (operator): one mining run now, as a synchronous job.
func (c *Core) rulesHandler() http.Handler {
	rt := c.newRouter()
	rt.handle("POST /api/v1/rules/mine", []auth.Role{auth.RoleOperator}, c.apiMine)
	rt.mux.Handle("/", c.miner.Handler())
	return rt.mux
}

func (c *Core) apiMine(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	c.policies.Refresh()
	j := c.startJob(r.Context(), "rules.mine", p.UserID)
	rep, err := c.miner.RunOnce(r.Context())
	// The miner audits the run itself (as the system); this entry says who asked.
	ev := audit.Event{Actor: p.AuditActor(), Action: "rule.mine_request", Target: audit.Target{Type: "rules"}, Outcome: audit.Success,
		RequestID: httpx.RequestID(r.Context()), Details: map[string]string{"job": j.ID}}
	if err != nil {
		// The miner's errors are internal (store, shapes): no payload values.
		c.log.Error("mining run failed", "err", err)
		ev.Outcome, ev.Reason = audit.Failure, "mining_failed"
		c.record(r.Context(), ev)
		c.jobs.fail(j, "mining_failed")
		return apiErr(http.StatusInternalServerError, "mining_failed", "the mining run failed")
	}
	ev.Details["new"] = strconv.Itoa(len(rep.New))
	c.record(r.Context(), ev)
	var st *miner.Status
	if s, serr := c.miner.Repo().Status(r.Context()); serr == nil {
		st = s
	}
	c.jobs.done(j, mineResult(rep, st))
	httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	return nil
}

// maxJobDiagnostics bounds the entity and rule diagnostics a mining job
// keeps (one entry per candidate: thousands with many services); the
// complete ones are at GET /api/v1/rules/status.
const maxJobDiagnostics = 200

// mineResult is the result of a mining job: the counts, the diagnostics
// (at most maxJobDiagnostics of each, with the totals when cut) and the
// coverage status (st, optional; its own diagnostics are left out: they
// repeat the run's).
func mineResult(rep miner.RunReport, st *miner.Status) map[string]any {
	ents, rules := rep.Diagnostics.Entities, rep.Diagnostics.Rules
	res := map[string]any{"run_id": rep.RunID, "events": rep.Events, "new": nonNil(rep.New),
		"updated": nonNil(rep.Updated), "stale": nonNil(rep.Stale), "unchanged": rep.Unchange}
	if len(ents) > maxJobDiagnostics {
		res["entities_total"] = len(ents)
		ents = ents[:maxJobDiagnostics:maxJobDiagnostics]
	}
	if len(rules) > maxJobDiagnostics {
		res["rule_diagnostics_total"] = len(rules)
		rules = rules[:maxJobDiagnostics:maxJobDiagnostics]
	}
	res["entities"], res["rule_diagnostics"] = slices.Clone(ents), slices.Clone(rules)
	// The coverage (P3) and the warnings next to the counts: "0 new" is never silent.
	if st != nil {
		cp := *st
		cp.Entities, cp.RuleDiagnostics, cp.Candidates, cp.Families = nil, nil, nil, nil
		res["status"] = cp
	}
	return res
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---------------------------------------------------------------------------
// Users

type userView struct {
	ID          string      `json:"id"`
	Username    string      `json:"username,omitempty"`
	DisplayName string      `json:"display_name"`
	Method      string      `json:"auth_method"`
	Roles       []auth.Role `json:"roles"`
	Disabled    bool        `json:"disabled"`
}

func viewUser(u auth.User) userView {
	roles := u.Roles
	if roles == nil {
		roles = []auth.Role{}
	}
	return userView{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Method: u.Method, Roles: roles, Disabled: u.Disabled}
}

func (c *Core) apiListUsers(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	us, err := c.auth.ListUsers(r.Context())
	if err != nil {
		return err
	}
	out := make([]userView, 0, len(us))
	for _, u := range us {
		out = append(out, viewUser(u))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func parseRoles(in []string) ([]auth.Role, error) {
	out := make([]auth.Role, 0, len(in))
	for _, s := range in {
		r, err := auth.ParseRole(s)
		if err != nil {
			return nil, apiErr(http.StatusBadRequest, "invalid_role", "unknown role")
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

func rolesDetail(rs []auth.Role) string {
	s := make([]string, len(rs))
	for i, r := range rs {
		s[i] = string(r)
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

// sensitiveOf returns the sensitive roles among rs (admin, policy-approver,
// event-exporter): granting them is audited (user.sensitive_role) and
// notified to the webhooks (keyguard.alert with alert user.sensitive_role;
// admin-api updateUser, threat model M17).
func sensitiveOf(rs []auth.Role) []auth.Role {
	var out []auth.Role
	for _, r := range rs {
		if slices.Contains(auth.SensitiveRoles, r) {
			out = append(out, r)
		}
	}
	return out
}

// notifySensitiveGrant records user.sensitive_role and alerts the webhooks
// when roles in added are sensitive. Identifiers only. A grant to oneself
// (an admin may do it: admin implies every role anyway) is marked
// self_grant in both.
func (c *Core) notifySensitiveGrant(ctx context.Context, p *auth.Principal, userID string, added []auth.Role) {
	s := sensitiveOf(added)
	if len(s) == 0 {
		return
	}
	roles := rolesDetail(s)
	det := map[string]string{"roles_granted": roles}
	payload := map[string]any{"alert": "user.sensitive_role", "user": userID, "by": p.UserID, "roles_granted": roles}
	if userID == p.UserID {
		det["self_grant"], payload["self_grant"] = "true", true
	}
	c.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "user.sensitive_role", Target: audit.Target{Type: "user", ID: userID}, Outcome: audit.Success,
		Details: det})
	c.alerts.emit(ctx, "keyguard.alert", payload)
}

func (c *Core) apiCreateUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name"`
		Password    string   `json:"password"`
		Roles       []string `json:"roles"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	roles, err := parseRoles(req.Roles)
	if err != nil {
		return err
	}
	if !c.cfg.Auth.Local.Enabled {
		return apiErr(http.StatusUnprocessableEntity, "local_disabled", "local accounts are disabled; OIDC users are created at first login")
	}
	if len(req.Password) < 12 || len(req.Password) > 256 {
		return apiErr(http.StatusBadRequest, "invalid_input", "password must be 12 to 256 characters")
	}
	u, err := c.auth.CreateLocalUser(r.Context(), req.Username, req.Password, roles)
	ev := audit.Event{Actor: p.AuditActor(), Action: "user.create", Target: audit.Target{Type: "user"}, Outcome: audit.Success}
	if err != nil {
		ev.Outcome, ev.Reason = audit.Failure, "invalid_or_exists"
		c.record(r.Context(), ev)
		return err
	}
	ev.Target.ID = u.ID
	ev.Details = map[string]string{"roles": rolesDetail(roles)}
	if len(sensitiveOf(roles)) > 0 {
		ev.Details["sensitive_role"] = "true"
	}
	c.record(r.Context(), ev)
	c.notifySensitiveGrant(r.Context(), p, u.ID, roles)
	httpx.WriteJSON(w, http.StatusCreated, viewUser(u))
	return nil
}

func (c *Core) apiUpdateUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id := r.PathValue("user_id")
	var req struct {
		Roles          *[]string `json:"roles"`
		Disabled       *bool     `json:"disabled"`
		Password       *string   `json:"password"`
		RevokeSessions bool      `json:"revoke_sessions"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	u, err := c.auth.GetUser(ctx, id)
	if err != nil {
		return err
	}
	// Validate everything before changing anything.
	if req.Password != nil {
		if u.Method != "local" {
			return apiErr(http.StatusConflict, "not_local", "only local users have a password")
		}
		if len(*req.Password) < 12 || len(*req.Password) > 256 {
			return apiErr(http.StatusBadRequest, "invalid_input", "password must be 12 to 256 characters")
		}
	}
	if req.Disabled != nil && id == p.UserID && *req.Disabled {
		return apiErr(http.StatusConflict, "self_lockout", "you cannot disable yourself")
	}
	details := map[string]string{}
	var added []auth.Role
	if req.Roles != nil {
		roles, err := parseRoles(*req.Roles)
		if err != nil {
			return err
		}
		if u.Method == "oidc" && c.cfg.Auth.OIDC.RolesClaim != "" {
			return apiErr(http.StatusConflict, "roles_from_idp", "roles of OIDC users are synchronised from the identity provider")
		}
		if id == p.UserID && slices.Contains(u.Roles, auth.RoleAdmin) && !slices.Contains(roles, auth.RoleAdmin) {
			return apiErr(http.StatusConflict, "self_lockout", "you cannot remove your own admin role")
		}
		for _, r := range roles {
			if !slices.Contains(u.Roles, r) {
				added = append(added, r)
			}
		}
		// Only admins reach this operation (a non-admin never grants
		// roles, to itself or to others). An admin may grant roles to
		// itself and combine admin with any role: admin implies every role,
		// so the grant is traced (audit, user.sensitive_role alert), not
		// refused.
		if err := c.auth.SetRoles(ctx, id, roles); err != nil {
			return err
		}
		details["roles"] = rolesDetail(roles)
		if len(sensitiveOf(added)) > 0 {
			details["sensitive_role"] = "true"
		}
		if id == p.UserID && len(added) > 0 {
			details["self_grant"] = "true"
		}
	}
	if req.Disabled != nil {
		if err := c.auth.SetDisabled(ctx, id, *req.Disabled); err != nil {
			return err
		}
		details["disabled"] = strconv.FormatBool(*req.Disabled)
	}
	if req.Password != nil {
		if err := c.auth.SetPassword(ctx, id, *req.Password); err != nil {
			return err
		}
		details["password"] = "reset"
	}
	if req.RevokeSessions {
		if err := c.auth.RevokeSessions(ctx, id); err != nil {
			return err
		}
		details["sessions"] = "revoked"
	}
	c.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "user.update", Target: audit.Target{Type: "user", ID: id}, Outcome: audit.Success, Details: details})
	c.notifySensitiveGrant(ctx, p, id, added)
	if u, err = c.auth.GetUser(ctx, id); err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, viewUser(u))
	return nil
}

func (c *Core) apiDeleteUser(_ http.ResponseWriter, _ *http.Request, _ *auth.Principal) error {
	// Users are referenced by the audit chain and by approvals: they are
	// disabled, never deleted (PATCH {"disabled": true}).
	return apiErr(http.StatusConflict, "use_disable", "users are kept for the audit trail: disable the user instead")
}

// ---------------------------------------------------------------------------
// System

func (c *Core) apiVersion(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) error {
	inst, env := c.labels.get()
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"version": c.opts.Version, "commit": c.opts.Commit, "spec": SpecVersion,
		"installation_name": inst, "environment": env})
	return nil
}

func (c *Core) apiGetJob(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	j := c.jobs.get(r.PathValue("job_id"))
	if j == nil || !jobVisible(j, p) {
		return apiErr(http.StatusNotFound, "not_found", "job not found (archetype, world and pack builds are synchronous: their answer is final)")
	}
	httpx.WriteJSON(w, http.StatusOK, j)
	return nil
}

// jobVisible: a job is readable by its owner and the users who joined it,
// by an auditor and by an admin (scheduled runs belong to the system).
func jobVisible(j *Job, p *auth.Principal) bool {
	return j.visibleTo(p.UserID) || p.HasAny(auth.RoleAuditor)
}

// apiListJobs lists the jobs the caller may read (as GET
// /api/v1/jobs/{job_id}), newest first, without results; ?status= keeps
// one status (queued, running, done, failed). The heavy gate tells how many
// heavy jobs run and wait.
func (c *Core) apiListJobs(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	status := r.URL.Query().Get("status")
	if status != "" && !slices.Contains([]string{"queued", "running", "done", "failed"}, status) {
		return apiErr(http.StatusBadRequest, "bad_request", "status must be queued, running, done or failed")
	}
	js := c.jobs.list(func(j *Job) bool { return jobVisible(j, p) && (status == "" || j.Status == status) })
	running, waiting := c.heavy.stats()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"jobs": js,
		"heavy": map[string]int{"slots": c.heavy.capacity(), "running": running, "queued": waiting}})
	return nil
}

func (c *Core) apiKeyguardStatus(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st, err := c.kg.Status(ctx)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"reachable": false})
		return nil
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"reachable": true, "hmac_kids": nonNil(st.HMACKids), "epochs": nonNil(st.Epochs), "approvals_unverified": st.ApprovalsUnverified,
		"match_budget_left": st.MatchBudgetLeft, "policy_kid": st.PolicyKid, "pack_kid": st.PackKid,
		"revoked_kids": nonNil(st.RevokedKids), "opening_approvals": st.OpeningApprovals, "admin_override": st.AdminOverride,
		"transport": st.Transport,
	})
	return nil
}

func (c *Core) apiKeyguardAudit(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var since int64
	if s := r.URL.Query().Get("since_seq"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return apiErr(http.StatusBadRequest, "bad_request", "since_seq must be a non-negative integer")
		}
		since = n
	}
	entries, err := c.kg.Audit(r.Context(), since)
	if err != nil {
		return apiErr(http.StatusBadGateway, "keyguard_unreachable", "keyguard did not answer")
	}
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "keyguard.audit_read", Target: audit.Target{Type: "keyguard"}, Outcome: audit.Success,
		Details: map[string]string{"entries": strconv.Itoa(len(entries))}})
	if entries == nil {
		httpx.WriteJSON(w, http.StatusOK, []any{})
		return nil
	}
	httpx.WriteJSON(w, http.StatusOK, entries)
	return nil
}

// ---------------------------------------------------------------------------
// Retention and purge

func (c *Core) aggregatesDays() int {
	d := time.Duration(c.cfg.Contract.KeepSnapshots) * c.cfg.Contract.SnapshotWindow
	return max(1, int(d/(24*time.Hour)))
}

func (c *Core) apiGetRetention(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) error {
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"events_days": int(c.intake.Retention() / (24 * time.Hour)), "aggregates_days": c.aggregatesDays()})
	return nil
}

func (c *Core) apiSetRetention(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		EventsDays     int  `json:"events_days"`
		AggregatesDays *int `json:"aggregates_days"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.EventsDays < 1 || req.EventsDays > 365 {
		return apiErr(http.StatusBadRequest, "invalid_input", "events_days must be between 1 and 365")
	}
	if req.AggregatesDays != nil && *req.AggregatesDays != c.aggregatesDays() {
		return apiErr(http.StatusUnprocessableEntity, "not_supported", "aggregates_days follows contract.keep_snapshots in the configuration")
	}
	d := time.Duration(req.EventsDays) * 24 * time.Hour
	if err := c.saveSetting(r.Context(), settingRetention, strconv.Itoa(req.EventsDays)); err != nil {
		return err
	}
	c.intake.SetRetention(d)
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "store.retention", Target: audit.Target{Type: "store"}, Outcome: audit.Success,
		Details: map[string]string{"events_days": strconv.Itoa(req.EventsDays)}})
	return c.apiGetRetention(w, r, p)
}

func (c *Core) apiPurge(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Before  time.Time `json:"before"`
		Service string    `json:"service"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Before.IsZero() {
		return apiErr(http.StatusBadRequest, "invalid_input", "before is required")
	}
	if req.Service != "" {
		return apiErr(http.StatusUnprocessableEntity, "not_supported", "purge by service is not supported yet: purge by time only")
	}
	if running := c.jobs.running("store.purge"); running != nil {
		return apiErr(http.StatusConflict, "purge_running", "a purge is already running: follow it at /api/v1/jobs/"+running.ID)
	}
	j := c.jobs.start("store.purge", p.UserID)
	actor := p.AuditActor()
	c.record(r.Context(), audit.Event{Actor: actor, Action: "store.purge.start", Target: audit.Target{Type: "store"}, Outcome: audit.Success,
		Details: map[string]string{"job_id": j.ID, "before": req.Before.UTC().Format(time.RFC3339)}})
	// The purge of millions of events takes minutes: it runs in the
	// background, in small transactions, and is followed through the job.
	go c.runPurge(j, actor, req.Before)
	httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	return nil
}

// runPurge deletes the events received before the cutoff, reporting progress
// in the job, and audits the end (the start was audited by the caller).
func (c *Core) runPurge(j *Job, actor audit.Actor, before time.Time) {
	ctx := c.jobs.context()
	res, err := c.intake.Store().PurgeBeforeProgress(ctx, before, func(pr intake.PurgeProgress) {
		c.jobs.setProgress(j, map[string]any{"phase": pr.Phase, "events": pr.Events, "tokens": pr.Tokens, "events_estimated": pr.EventsEstimated})
	})
	// The context of the core may be done (shutdown): the closing audit
	// entry must still be written.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	ev := audit.Event{Actor: actor, Action: "store.purge", Target: audit.Target{Type: "store"}, Outcome: audit.Success,
		Details: map[string]string{"job_id": j.ID, "events": strconv.FormatInt(res.Events, 10), "tokens": strconv.FormatInt(res.Tokens, 10),
			"reclaimed_bytes": strconv.FormatInt(res.Reclaimed, 10)}}
	if err != nil {
		c.log.Error("store purge failed", "job_id", j.ID, "err", err)
		c.jobs.fail(j, "purge_failed")
		ev.Outcome, ev.Reason = audit.Failure, "purge_failed"
		c.record(actx, ev)
		return
	}
	c.record(actx, ev)
	out := map[string]any{"events": res.Events, "tokens": res.Tokens, "reclaimed_bytes": res.Reclaimed}
	if res.ReclaimNote != "" {
		out["reclaim_note"] = res.ReclaimNote
	}
	c.jobs.done(j, out)
}
