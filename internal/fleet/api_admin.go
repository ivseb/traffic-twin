package fleet

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

const maxAdminJSON = 64 << 10

// Roles per operation, exactly as x-tt-roles in api/admin-api.v1.openapi.yaml
// (plus admin on approvePolicy, policy.md 5 v1.2.1). admin implies every
// role (auth.Principal.HasAny): an admin passes every check below, and
// auth.Require audits each such override (authz.admin_override).
var (
	rolesFleetRead   = []auth.Role{auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyApprover}
	rolesOperator    = []auth.Role{auth.RoleOperator}
	rolesOpAuditor   = []auth.Role{auth.RoleOperator, auth.RoleAuditor}
	rolesPolicyRead  = []auth.Role{auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor}
	rolesPolicyWrite = []auth.Role{auth.RoleOperator, auth.RolePolicyApprover}
	rolesApprove     = []auth.Role{auth.RolePolicyApprover, auth.RoleAdmin}
	rolesReject      = []auth.Role{auth.RolePolicyApprover}
	rolesSettings    = []auth.Role{auth.RoleOperator, auth.RolePolicyApprover, auth.RoleAuditor, auth.RoleAdmin}
	rolesKeysRead    = []auth.Role{auth.RoleOperator, auth.RoleAuditor, auth.RoleAdmin}
	rolesAdmin       = []auth.Role{auth.RoleAdmin}
)

type adminHandler func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error

// AdminHandler serves /api/v1/fleet/... It expects to run behind
// auth.Require (server.Mount), and checks the per-operation roles itself.
func (f *Fleet) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, roles []auth.Role, h adminHandler) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			if !p.HasAny(roles...) {
				f.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny",
					Target: audit.RouteTarget(r), Outcome: audit.Denied, Reason: "missing_role"})
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			if err := h(w, r, p); err != nil {
				f.writeErr(w, r, err)
			}
		})
	}
	const pre = AdminPrefix
	route("GET "+pre+"/groups", rolesFleetRead, f.apiListGroups)
	route("POST "+pre+"/groups", rolesOperator, f.apiCreateGroup)
	route("GET "+pre+"/groups/{group}", rolesFleetRead, f.apiGetGroup)
	route("PUT "+pre+"/groups/{group}", rolesOperator, f.apiUpdateGroup)
	route("GET "+pre+"/enrollment-tokens", rolesOpAuditor, f.apiListTokens)
	route("POST "+pre+"/enrollment-tokens", rolesOperator, f.apiCreateToken)
	route("DELETE "+pre+"/enrollment-tokens/{token_id}", rolesOperator, f.apiRevokeToken)
	route("GET "+pre+"/onboarding/{token_id}/status", rolesOperator, f.apiOnboarding)
	route("GET "+pre+"/sources", rolesOpAuditor, f.apiListSources)
	route("GET "+pre+"/sources/{source_id}", rolesOpAuditor, f.apiGetSource)
	route("POST "+pre+"/sources/{source_id}/revoke", rolesOperator, f.apiRevokeSource)
	route("PUT "+pre+"/sources/{source_id}/sampling", rolesOperator, f.apiSourceSampling)
	route("POST "+pre+"/kill", rolesOperator, f.apiKill)
	route("GET "+pre+"/policies", rolesPolicyRead, f.apiListPolicies)
	route("POST "+pre+"/policies", rolesPolicyWrite, f.apiProposePolicy)
	route("GET "+pre+"/policies/{policy_id}/versions/{version}", rolesPolicyRead, f.apiGetVersion)
	route("POST "+pre+"/policies/{policy_id}/versions/{version}/approve", rolesApprove, f.apiApprove)
	route("POST "+pre+"/policies/{policy_id}/versions/{version}/reject", rolesReject, f.apiReject)
	route("POST "+pre+"/policies/{policy_id}/versions/{version}/withdraw", rolesPolicyWrite, f.apiWithdraw)
	route("POST "+pre+"/policies/{policy_id}/rollback", rolesPolicyWrite, f.apiRollback)
	route("GET "+pre+"/policies/{policy_id}/assist", rolesPolicyWrite, f.apiAssist)
	route("POST "+pre+"/policies/{policy_id}/assist/draft", rolesPolicyWrite, f.apiAssistDraft)
	route("POST "+pre+"/groups/{group}/starter-policy", rolesPolicyWrite, f.apiStarter)
	route("GET "+pre+"/groups/{group}/observe", rolesPolicyRead, f.apiObserve)
	route("PUT "+pre+"/groups/{group}/observe", rolesPolicyWrite, f.apiSetObserve)
	route("PUT "+pre+"/groups/{group}/identity", rolesPolicyWrite, f.apiSetIdentity)
	route("PUT "+pre+"/groups/{group}/families", rolesPolicyWrite, f.apiSetFamily)
	route("DELETE "+pre+"/groups/{group}/families/{family}", rolesPolicyWrite, f.apiRemoveFamily)
	route("PUT "+pre+"/groups/{group}/test-k", rolesAdmin, f.apiSetTestK)
	route("POST "+pre+"/policies/classify", rolesPolicyWrite, f.apiClassify)
	route("GET "+pre+"/signing-keys", rolesKeysRead, f.apiListKeys)
	route("POST "+pre+"/signing-keys/{kid}/revoke", rolesAdmin, f.apiRevokeKey)
	route("GET "+pre+"/approval-settings", rolesSettings, f.apiApprovalSettings)
	mux.HandleFunc(pre+"/", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	})
	return mux
}

func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(w, r, maxAdminJSON, dst); err != nil {
		return apiErr(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
	}
	return nil
}

func (f *Fleet) apiListGroups(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	gs, err := f.ListGroups(r.Context())
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, gs)
	return nil
}

func (f *Fleet) apiCreateGroup(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var g Group
	if err := decodeStrict(w, r, &g); err != nil {
		return err
	}
	out, err := f.CreateGroup(r.Context(), p, g)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (f *Fleet) apiGetGroup(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	g, err := f.GetGroup(r.Context(), r.PathValue("group"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, g)
	return nil
}

func (f *Fleet) apiUpdateGroup(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var g Group
	if err := decodeStrict(w, r, &g); err != nil {
		return err
	}
	out, err := f.UpdateGroup(r.Context(), p, r.PathValue("group"), g)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (f *Fleet) apiListTokens(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ts, err := f.ListTokens(r.Context())
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, ts)
	return nil
}

func (f *Fleet) apiCreateToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req TokenRequest
	if err := decodeStrict(w, r, &req); err != nil {
		return err
	}
	t, err := f.CreateToken(r.Context(), p, req)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
	return nil
}

func (f *Fleet) apiRevokeToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := f.RevokeToken(r.Context(), p, r.PathValue("token_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Onboarding status streaming (Accept: text/event-stream).
const (
	sseInterval = 2 * time.Second
	sseMaxLife  = 10 * time.Minute
)

func (f *Fleet) apiOnboarding(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	id := r.PathValue("token_id")
	st, err := f.Onboarding(r.Context(), id)
	if err != nil {
		return err
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		httpx.WriteJSON(w, http.StatusOK, st)
		return nil
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	deadline := time.Now().Add(sseMaxLife)
	t := time.NewTicker(sseInterval)
	defer t.Stop()
	for {
		_ = rc.SetWriteDeadline(time.Now().Add(sseInterval + 10*time.Second))
		b, _ := json.Marshal(st)
		if _, err := fmt.Fprintf(w, "event: status\ndata: %s\n\n", b); err != nil {
			return nil
		}
		if err := rc.Flush(); err != nil {
			return nil
		}
		select {
		case <-r.Context().Done():
			return nil
		case <-t.C:
		}
		if time.Now().After(deadline) {
			return nil
		}
		if st, err = f.Onboarding(r.Context(), id); err != nil {
			return nil
		}
	}
}

func (f *Fleet) apiListSources(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ss, err := f.ListSources(r.Context(), r.URL.Query().Get("group"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, ss)
	return nil
}

func (f *Fleet) apiGetSource(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	s, err := f.GetSource(r.Context(), r.PathValue("source_id"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (f *Fleet) apiRevokeSource(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := f.RevokeSource(r.Context(), p, r.PathValue("source_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (f *Fleet) apiSourceSampling(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		SamplingOverrideBP *int `json:"sampling_override_bp"`
	}
	raw := map[string]json.RawMessage{}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdminJSON))
	if err != nil || json.Unmarshal(body, &raw) != nil {
		return apiErr(http.StatusBadRequest, "bad_request", "invalid JSON body")
	}
	if _, ok := raw["sampling_override_bp"]; !ok || len(raw) != 1 {
		return invalid("invalid_sampling", "sampling_override_bp (integer or null) is required")
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return invalid("invalid_sampling", "sampling_override_bp must be an integer or null")
	}
	if err := f.SetSourceSampling(r.Context(), p, r.PathValue("source_id"), req.SamplingOverrideBP); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (f *Fleet) apiKill(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Active *bool      `json:"active"`
		Scope  *KillScope `json:"scope"`
	}
	if err := decodeStrict(w, r, &req); err != nil {
		return err
	}
	if req.Active == nil || req.Scope == nil {
		return invalid("invalid_kill", "active and scope are required")
	}
	if err := f.SetKill(r.Context(), p, *req.Active, *req.Scope); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (f *Fleet) apiListPolicies(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	vs, err := f.ListPolicies(r.Context())
	if err != nil {
		return err
	}
	pg, err := f.PolicyGroups(r.Context())
	if err != nil {
		return err
	}
	sel := groupscope.FromRequest(r)
	out := make([]*PolicyVersion, 0, len(vs))
	for _, v := range vs {
		gs := slices.Clone(pg[v.PolicyID])
		for _, g := range v.Targets.Groups {
			if !slices.Contains(gs, g) {
				gs = append(gs, g)
			}
		}
		slices.Sort(gs)
		if gs == nil {
			gs = []string{}
		}
		v.Groups = gs
		// With a filter, only the policies of the selected groups: no
		// approve button next to another team's draft.
		if sel.Any(gs) {
			out = append(out, v)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (f *Fleet) apiProposePolicy(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "application/yaml", "application/x-yaml", "text/yaml", "application/json":
	default:
		return apiErr(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/yaml or application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxAuthorBytes))
	if err != nil {
		return apiErr(http.StatusRequestEntityTooLarge, "too_large", "the policy document is too large")
	}
	v, err := f.ProposePolicy(r.Context(), p, body)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
	return nil
}

func pathVersion(r *http.Request) (string, int64, error) {
	pid := r.PathValue("policy_id")
	v, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil || v < 1 {
		return "", 0, errNotFound
	}
	return pid, v, nil
}

func (f *Fleet) apiGetVersion(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	pid, ver, err := pathVersion(r)
	if err != nil {
		return err
	}
	v, err := f.GetPolicyVersion(r.Context(), pid, ver)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// decodeOptional decodes an optional strict JSON body (empty body allowed).
func decodeOptional(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.ContentLength == 0 {
		return nil
	}
	return decodeStrict(w, r, dst)
}

func (f *Fleet) apiApprove(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	pid, ver, err := pathVersion(r)
	if err != nil {
		return err
	}
	var req ApproveRequest
	if err := decodeOptional(w, r, &req); err != nil {
		return err
	}
	v, err := f.ApprovePolicy(r.Context(), p, pid, ver, req)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (f *Fleet) apiReject(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	pid, ver, err := pathVersion(r)
	if err != nil {
		return err
	}
	var req struct {
		Note string `json:"note,omitempty"`
	}
	if err := decodeOptional(w, r, &req); err != nil {
		return err
	}
	if len(req.Note) > 1000 {
		return invalid("too_long", "note is limited to 1000 characters")
	}
	v, err := f.RejectPolicy(r.Context(), p, pid, ver, req.Note)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (f *Fleet) apiWithdraw(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	pid, ver, err := pathVersion(r)
	if err != nil {
		return err
	}
	var req struct {
		Note string `json:"note,omitempty"`
	}
	if err := decodeOptional(w, r, &req); err != nil {
		return err
	}
	v, err := f.WithdrawPolicy(r.Context(), p, pid, ver, req.Note)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (f *Fleet) apiRollback(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		ToVersion *int64 `json:"to_version"`
	}
	if err := decodeStrict(w, r, &req); err != nil {
		return err
	}
	if req.ToVersion == nil || *req.ToVersion < 1 {
		return invalid("invalid_version", "to_version (>= 1) is required")
	}
	v, err := f.Rollback(r.Context(), p, r.PathValue("policy_id"), *req.ToVersion)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
	return nil
}

func (f *Fleet) apiAssist(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	group := ""
	if gs := groupscope.FromRequest(r); len(gs) == 1 {
		group = gs[0]
	}
	out, err := f.AssistIn(r.Context(), r.PathValue("policy_id"), group)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (f *Fleet) apiAssistDraft(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req AssistDraftRequest
	if err := httpx.DecodeJSON(w, r, MaxAuthorBytes, &req); err != nil {
		return apiErr(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
	}
	res, v, err := f.AssistDraft(r.Context(), p, r.PathValue("policy_id"), req)
	if err != nil {
		return err
	}
	if v == nil {
		httpx.WriteJSON(w, http.StatusOK, res)
		return nil
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
	return nil
}

func (f *Fleet) apiStarter(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req StarterRequest
	if err := decodeStrict(w, r, &req); err != nil {
		return err
	}
	v, err := f.CreateStarterPolicy(r.Context(), p, r.PathValue("group"), req)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
	return nil
}

func (f *Fleet) apiObserve(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	out, err := f.ObserveStatusOf(r.Context(), r.PathValue("group"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

// apiSetObserve turns the automatic observe versions of a group on or off:
// {"auto": bool}. The answer is the observe state.
func (f *Fleet) apiSetObserve(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var in struct {
		Auto *bool `json:"auto"`
	}
	if err := decodeStrict(w, r, &in); err != nil {
		return err
	}
	if in.Auto == nil {
		return invalid("invalid_input", "auto (boolean) is required")
	}
	g := r.PathValue("group")
	if err := f.SetObserveAuto(r.Context(), p, g, *in.Auto); err != nil {
		return err
	}
	out, err := f.ObserveStatusOf(r.Context(), g)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

// apiSetIdentity sets who the user is for the group's policy:
// {"from": "header"|"cookie", "name": "...", "jwt_claim": "..."}. The answer
// is the version: active when it applied at once (observe-safe), a draft
// waiting for approvals otherwise.
func (f *Fleet) apiSetIdentity(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var in AssistIdentity
	if err := decodeStrict(w, r, &in); err != nil {
		return err
	}
	v, err := f.SetIdentity(r.Context(), p, r.PathValue("group"), in)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

// apiClassify classifies an author policy (same body as proposePolicy)
// against the active version, without storing it (policy.md 7).
func (f *Fleet) apiClassify(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "application/yaml", "application/x-yaml", "text/yaml", "application/json":
	default:
		return apiErr(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/yaml or application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxAuthorBytes))
	if err != nil {
		return apiErr(http.StatusRequestEntityTooLarge, "too_large", "the policy document is too large")
	}
	out, err := f.ClassifyAuthor(r.Context(), body)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (f *Fleet) apiListKeys(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	ks, err := f.ListSigningKeys(r.Context())
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, ks)
	return nil
}

func (f *Fleet) apiRevokeKey(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := f.RevokeSigningKey(r.Context(), r.PathValue("kid"), p.AuditActor()); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (f *Fleet) apiApprovalSettings(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) error {
	httpx.WriteJSON(w, http.StatusOK, f.GetApprovalSettings())
	return nil
}
