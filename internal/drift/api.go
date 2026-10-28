package drift

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Roles of api/admin-api.v1.openapi.yaml (x-tt-roles).
var (
	rolesDriftRead = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer, auth.RoleAuditor}
	rolesDriftAck  = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer}
	// Resolving closes an alert for good: operators only.
	rolesDriftResolve = []auth.Role{auth.RoleOperator}
	rolesHookRead     = []auth.Role{auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor}
	rolesHookWrite    = []auth.Role{auth.RoleAdmin}
)

// Mount mounts /api/v1/drift and /api/v1/webhooks on srv, before srv.Run.
// Each prefix gets the union of the roles of its operations and every route
// checks its own list again.
func Mount(srv *server.Server, m *Manager) {
	h := Handler(m)
	srv.Mount("/api/v1/drift", h, auth.RoleOperator, auth.RoleRuleReviewer, auth.RoleAuditor)
	srv.Mount("/api/v1/webhooks", h, auth.RoleAdmin, auth.RoleOperator, auth.RoleAuditor)
}

type api struct{ m *Manager }

// Handler returns the handler for the drift and webhooks routes.
func Handler(m *Manager) http.Handler {
	a := &api{m}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/drift", guard(rolesDriftRead, a.list))
	mux.HandleFunc("POST /api/v1/drift/{drift_id}/ack", guard(rolesDriftAck, a.ack))
	mux.HandleFunc("PATCH /api/v1/drift/{drift_id}", guard(rolesDriftResolve, a.patch))
	mux.HandleFunc("GET /api/v1/webhooks", guard(rolesHookRead, a.listHooks))
	mux.HandleFunc("POST /api/v1/webhooks", guard(rolesHookWrite, a.createHook))
	mux.HandleFunc("PUT /api/v1/webhooks/{webhook_id}", guard(rolesHookWrite, a.updateHook))
	mux.HandleFunc("PATCH /api/v1/webhooks/{webhook_id}", guard(rolesHookWrite, a.patchHook))
	mux.HandleFunc("DELETE /api/v1/webhooks/{webhook_id}", guard(rolesHookWrite, a.deleteHook))
	mux.HandleFunc("POST /api/v1/webhooks/{webhook_id}/test", guard(rolesHookWrite, a.testHook))
	mux.HandleFunc("GET /api/v1/webhooks/{webhook_id}/deliveries", guard(rolesHookRead, a.deliveries))
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
	var inv ErrInvalid
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrTransition):
		httpx.WriteError(w, http.StatusConflict, "invalid_transition", "an alert cannot go back to an earlier state")
	case errors.As(err, &inv):
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", string(inv))
	default:
		a.m.log.ErrorContext(r.Context(), "drift api", "route", r.Pattern, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (a *api) record(r *http.Request, action, typ, id string, err error) {
	if a.m.audit == nil {
		return
	}
	actor, reqID := auth.RequestActor(r)
	oc := audit.Success
	if err != nil {
		oc = audit.Failure
	}
	_, _ = a.m.audit.Record(context.WithoutCancel(r.Context()), audit.Event{Actor: actor, Action: action,
		Target: audit.Target{Type: typ, ID: audit.SafeValue(id)}, Outcome: oc, RequestID: reqID})
}

func (a *api) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{Severity: q.Get("severity"), State: q.Get("state"), Kind: q.Get("kind"), Groups: groupscope.FromRequest(r)}
	if f.Severity != "" && f.Severity != "breaking" && f.Severity != "non-breaking" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid severity")
		return
	}
	if f.State != "" && f.State != StateOpen && f.State != StateAcknowledged && f.State != StateResolved {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid state")
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid limit")
			return
		}
		f.Limit = n
	}
	out, err := a.m.List(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (a *api) ack(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("drift_id")
	p, _ := auth.PrincipalFrom(r.Context())
	by := ""
	if p != nil {
		by = audit.SafeValue(p.UserID)
	}
	err := a.m.Ack(r.Context(), id, by)
	a.record(r, "drift.ack", "drift", id, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// patch changes the state of an alert: {"state": "acknowledged" | "resolved"}.
func (a *api) patch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("drift_id")
	var in struct {
		State string `json:"state"`
	}
	if err := httpx.DecodeJSON(w, r, 1<<10, &in); err != nil || (in.State != StateAcknowledged && in.State != StateResolved) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", `state must be "acknowledged" or "resolved"`)
		return
	}
	p, _ := auth.PrincipalFrom(r.Context())
	by := ""
	if p != nil {
		by = audit.SafeValue(p.UserID)
	}
	err := a.m.SetState(r.Context(), id, in.State, by)
	action := "drift.ack"
	if in.State == StateResolved {
		action = "drift.resolve"
	}
	a.record(r, action, "drift", id, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	al, err := a.m.Get(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, al)
}

func (a *api) listHooks(w http.ResponseWriter, r *http.Request) {
	out, err := a.m.ListWebhooks(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (a *api) createHook(w http.ResponseWriter, r *http.Request) {
	var in Webhook
	if err := httpx.DecodeJSON(w, r, 16<<10, &in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
		return
	}
	out, err := a.m.CreateWebhook(r.Context(), in)
	a.record(r, "webhook.create", "webhook", out.ID, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (a *api) updateHook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("webhook_id")
	var in Webhook
	if err := httpx.DecodeJSON(w, r, 16<<10, &in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
		return
	}
	out, err := a.m.UpdateWebhook(r.Context(), id, in)
	a.record(r, "webhook.update", "webhook", id, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// patchHook switches a webhook on or off: {"enabled": bool}.
func (a *api) patchHook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("webhook_id")
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := httpx.DecodeJSON(w, r, 1<<10, &in); err != nil || in.Enabled == nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "enabled (boolean) is required")
		return
	}
	out, err := a.m.SetWebhookEnabled(r.Context(), id, *in.Enabled)
	action := "webhook.disable"
	if *in.Enabled {
		action = "webhook.enable"
	}
	a.record(r, action, "webhook", id, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (a *api) deleteHook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("webhook_id")
	err := a.m.DeleteWebhook(r.Context(), id)
	a.record(r, "webhook.delete", "webhook", id, err)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) testHook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("webhook_id")
	err := a.m.SendTest(r.Context(), id)
	a.record(r, "webhook.test", "webhook", id, err)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrNotFound):
		a.fail(w, r, err)
	default:
		httpx.WriteError(w, http.StatusBadGateway, "delivery_failed", "the destination did not accept the test notification")
	}
}

func (a *api) deliveries(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	out, err := a.m.Deliveries(r.Context(), r.PathValue("webhook_id"), limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
