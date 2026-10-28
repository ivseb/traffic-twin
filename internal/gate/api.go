package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// PrefixPacks is the admin API prefix of packs ("Pacchetti twin").
const PrefixPacks = "/api/v1/packs"

// Pack statuses (PackInfo.status).
const (
	StatusBuilding   = "building"
	StatusGateFailed = "gate-failed"
	StatusSigned     = "signed"
	StatusPublished  = "published"
)

// PackInfo is the admin API PackInfo (plus residual_risk and
// approval_mode, extensions to sync in the spec).
type PackInfo struct {
	PackID       string          `json:"pack_id"`
	Status       string          `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	WorldID      string          `json:"world_id,omitempty"`
	Manifest     json.RawMessage `json:"manifest,omitempty"`
	GateReport   json.RawMessage `json:"gate_report,omitempty"`
	PublishedAt  *time.Time      `json:"published_at"`
	ResidualRisk *ResidualRisk   `json:"residual_risk,omitempty"`
	ApprovalMode string          `json:"approval_mode,omitempty"`
	// Group is the group the pack was built for ("" for a pack of every
	// group, older packs and multi-group packs); Groups lists the groups
	// of its services; Services the services it holds.
	Group    string   `json:"group"`
	Groups   []string `json:"groups"`
	Services []string `json:"services"`
	// Warnings are the things the console should say about the pack that do
	// not stop it (built on little traffic: few_observations, with the
	// counts per pack, rule, outcome and endpoint). They are not part of the
	// signed pack. At most 200 are listed; WarningsTotal is the count.
	Warnings      []PackWarning `json:"warnings"`
	WarningsTotal int           `json:"warnings_total"`
}

// WarnFewObservations: the pack rests on little traffic ("poche osservazioni").
const WarnFewObservations = "few_observations"

// WarnTestK (spec v1.18): the pack is of a group marked as test and was
// built with its lower k (Observed: the k used; Needed: the installation
// k). It must never reach users outside that test environment.
const WarnTestK = "test_k"

// PackWarning is one warning about a pack (counts only, never values).
type PackWarning struct {
	Code string `json:"code"`
	// Scope is pack (the whole window), rule, outcome (of a rule) or
	// endpoint.
	Scope   string `json:"scope"`
	Rule    string `json:"rule,omitempty"`
	Service string `json:"service,omitempty"`
	Op      string `json:"op,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	// Unit is what Observed and Needed count: minutes, causes, outcomes,
	// runs or calls. Observed is absent with BelowK: the operation was seen
	// fewer times than k, so its count is not published.
	Unit     string `json:"unit"`
	Observed *int64 `json:"observed,omitempty"`
	BelowK   bool   `json:"below_k,omitempty"`
	Needed   int64  `json:"needed"`
}

// InGroups reports whether the pack belongs to one of the selected groups
// (always true without a filter).
func (i *PackInfo) InGroups(sel groupscope.Set) bool {
	if sel.All() {
		return true
	}
	if i.Group != "" {
		return sel.Has(i.Group)
	}
	return sel.Any(i.Groups)
}

// BuildRequest is the body of POST /api/v1/packs.
type BuildRequest struct {
	WorldID string `json:"world_id"`
	// Services is the explicit include list (empty: every service of the
	// world); ExcludeServices are left out.
	Services        []string `json:"services,omitempty"`
	ExcludeServices []string `json:"exclude_services,omitempty"`
	// Group is the group of the pack (default: the group of the world).
	Group string `json:"group,omitempty"`
	// MultiGroup lets an administrator build a pack whose services belong
	// to several groups (refused otherwise: mixed_groups).
	MultiGroup      bool     `json:"multi_group,omitempty"`
	AnonymizeHosts  *bool    `json:"anonymize_hosts,omitempty"`
	ScenarioPresets []string `json:"scenario_presets,omitempty"`
	ValidDays       *int     `json:"valid_days,omitempty"`
}

// PackService builds, signs, publishes and serves packs
// (internal/packwriter implements it). Errors of type *APIError are
// returned as they are; others become 500.
type PackService interface {
	BuildPack(ctx context.Context, p *auth.Principal, req BuildRequest) (*PackInfo, error)
	ListPacks(ctx context.Context) ([]PackInfo, error)
	GetPack(ctx context.Context, id string) (*PackInfo, error)
	// PublishPack releases a signed pack to the tests ("Rilascia ai test"):
	// a publisher, or an admin with a reason (policy.md 5, v1.2.1).
	// idToken, optional, is an approval ID token the caller obtained itself
	// (bound to the pack, keyguard.md 3.4); without it the pending step-up
	// of the caller is used when keyguard verifies approvals with OIDC.
	PublishPack(ctx context.Context, p *auth.Principal, id, reason, idToken string) (*PackInfo, error)
	// PackArchive returns the published .ttpack.
	PackArchive(ctx context.Context, p *auth.Principal, id string) ([]byte, error)
}

// APIError is an error with an HTTP status and a stable code.
type APIError struct {
	Status        int
	Code, Message string
	// Details name what the error is about (services, rule ids), see httpx.Error.
	Details []map[string]any
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// Errorf builds an APIError (fixed messages only, never values).
func Errorf(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg}
}

// ErrorDetails is Errorf with structured details.
func ErrorDetails(status int, code, msg string, details []map[string]any) *APIError {
	return &APIError{Status: status, Code: code, Message: msg, Details: details}
}

var packIDRE = regexp.MustCompile(`^pk-[0-9A-Za-z-]{1,60}$`)

// Roles per operation (x-tt-roles; publish also admin, policy.md 5 v1.2.1).
// admin implies every role (auth.Principal.HasAny): it also downloads, as an
// audited admin override (authz.admin_override, pack.download with
// admin_override=true).
var (
	rolesRead     = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor}
	rolesBuild    = []auth.Role{auth.RoleOperator}
	rolesPublish  = []auth.Role{auth.RolePublisher, auth.RoleAdmin}
	rolesDownload = []auth.Role{auth.RolePublisher}
)

// Mount serves the pack endpoints:
//
//	GET  /api/v1/packs                     operator, publisher, auditor
//	POST /api/v1/packs                     operator (assemble, gate, keyguard signature)
//	GET  /api/v1/packs/{pack_id}           operator, publisher, auditor (manifest, gate report, residual risk)
//	POST /api/v1/packs/{pack_id}/publish   publisher, or admin with {"reason": "..."}
//	GET  /api/v1/packs/{pack_id}/download  publisher (published packs only)
//
// admin implies every role above (overrides audited).
func Mount(srv *server.Server, ps PackService, log *slog.Logger, opts ...Option) {
	srv.Mount(PrefixPacks, Handler(ps, log, opts...), MountRoles...)
}

// MountRoles are the roles PrefixPacks is mounted with (the union of the
// roles of its operations), for callers that wrap Handler themselves.
var MountRoles = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor, auth.RoleAdmin}

// Option tunes Handler.
type Option func(*handlerOpts)

type handlerOpts struct{ audit *audit.Log }

// WithAudit records role denials (authz.deny, target = route pattern) in a.
func WithAudit(a *audit.Log) Option { return func(o *handlerOpts) { o.audit = a } }

// Handler is the HTTP handler of Mount (behind auth.Require).
func Handler(ps PackService, log *slog.Logger, opts ...Option) http.Handler {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var o handlerOpts
	for _, f := range opts {
		f(&o)
	}
	mux := http.NewServeMux()
	route := func(pattern string, roles []auth.Role, h func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			if !p.HasAny(roles...) {
				if o.audit != nil {
					if _, err := o.audit.Record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny", Target: audit.RouteTarget(r),
						Outcome: audit.Denied, Reason: "missing_role", RequestID: httpx.RequestID(r.Context())}); err != nil {
						log.ErrorContext(r.Context(), "packs: audit write failed", "action", "authz.deny")
					}
				}
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			if id := r.PathValue("pack_id"); id != "" && !packIDRE.MatchString(id) {
				httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
				return
			}
			if err := h(w, r, p); err != nil {
				var ae *APIError
				if errors.As(err, &ae) {
					httpx.WriteErrorDetails(w, ae.Status, ae.Code, ae.Message, ae.Details)
					return
				}
				log.ErrorContext(r.Context(), "packs: request failed", "err", err)
				httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
			}
		})
	}
	route("GET "+PrefixPacks, rolesRead, func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
		l, err := ps.ListPacks(r.Context())
		if err != nil {
			return err
		}
		sel := groupscope.FromRequest(r)
		out := []PackInfo{}
		for k := range l {
			if l[k].InGroups(sel) {
				out = append(out, l[k])
			}
		}
		httpx.WriteJSON(w, http.StatusOK, out)
		return nil
	})
	route("POST "+PrefixPacks, rolesBuild, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		var req BuildRequest
		if err := httpx.DecodeJSON(w, r, 64<<10, &req); err != nil {
			return Errorf(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
		}
		if req.WorldID == "" {
			return Errorf(http.StatusBadRequest, "bad_request", "world_id is required")
		}
		if req.ValidDays != nil && (*req.ValidDays < 1 || *req.ValidDays > 3660) {
			return Errorf(http.StatusUnprocessableEntity, "invalid_valid_days", "valid_days must be 1..3660")
		}
		info, err := ps.BuildPack(r.Context(), p, req)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": httpx.NewID("job_"), "kind": "pack.build", "status": "done", "result": info})
		return nil
	})
	route("GET "+PrefixPacks+"/{pack_id}", rolesRead, func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
		info, err := ps.GetPack(r.Context(), r.PathValue("pack_id"))
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, info)
		return nil
	})
	route("POST "+PrefixPacks+"/{pack_id}/publish", rolesPublish, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		var req struct {
			Reason  string `json:"reason"`
			IDToken string `json:"id_token"`
		}
		if r.ContentLength != 0 {
			if err := httpx.DecodeJSON(w, r, 32<<10, &req); err != nil {
				return Errorf(http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "bad request: "))
			}
		}
		if !p.Has(auth.RolePublisher) && strings.TrimSpace(req.Reason) == "" {
			return Errorf(http.StatusForbidden, "admin_reason_required", "an admin publishing without the publisher role must give a reason")
		}
		info, err := ps.PublishPack(r.Context(), p, r.PathValue("pack_id"), req.Reason, req.IDToken)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, info)
		return nil
	})
	route("GET "+PrefixPacks+"/{pack_id}/download", rolesDownload, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		b, err := ps.PackArchive(r.Context(), p, r.PathValue("pack_id"))
		if err != nil {
			return err
		}
		h := w.Header()
		h.Set("Content-Type", "application/gzip")
		h.Set("Content-Disposition", `attachment; filename="`+r.PathValue("pack_id")+`.ttpack"`)
		h.Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
		return nil
	})
	mux.HandleFunc(PrefixPacks+"/", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	})
	return mux
}
