// Package idformats stores the id formats chosen in the console (one per
// group and id domain, docs/spec/pack.md 4.3) and serves them on the admin
// API:
//
//	GET    /api/v1/id-formats?group=g          operator, publisher, auditor, rule-reviewer
//	POST   /api/v1/id-formats/preview          operator, publisher, auditor, rule-reviewer
//	PUT    /api/v1/id-formats/{domain}         operator, rule-reviewer
//	DELETE /api/v1/id-formats/{domain}?group=g operator, rule-reviewer
//
// The world service reads them (IDFormatsIn) and writes them into the
// contracts of a world's inputs, so the world, the pack and the mock agree.
package idformats

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Prefix of the admin API.
const Prefix = "/api/v1/id-formats"

func init() {
	store.Register(store.Namespace{Name: "idformats", Migrations: []store.Migration{
		{Version: 1, Name: "formats", SQL: `CREATE TABLE idformats (
			grp        TEXT NOT NULL,
			domain     TEXT NOT NULL,
			format     TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (grp, domain)
		) STRICT;`},
	}})
}

// Roles of the API (admin implies all of them).
var (
	RolesRead  = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor, auth.RoleRuleReviewer}
	RolesWrite = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer}
)

var (
	domainRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	groupRE  = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62})?$`)
)

// Store keeps the formats.
type Store struct {
	DB     *store.DB
	Audit  *audit.Log
	Now    func() time.Time
	Logger *slog.Logger
}

// Format is one stored format (the API object).
type Format struct {
	Group         string   `json:"group"`
	Domain        string   `json:"domain"`
	Format        string   `json:"format"`
	CapacityLabel string   `json:"capacity_label"`
	Preview       []string `json:"preview"`
	UpdatedBy     string   `json:"updated_by"`
	UpdatedAt     string   `json:"updated_at"`
}

func view(group, domain, format, by string, at int64) Format {
	f := Format{Group: group, Domain: domain, Format: format, UpdatedBy: by, Preview: []string{},
		UpdatedAt: time.Unix(at, 0).UTC().Format(time.RFC3339)}
	if t, err := idfmt.Parse(format); err == nil {
		f.CapacityLabel = idfmt.CapacityLabel(t.Capacity())
		f.Preview = t.Preview(domain, 3)
	}
	return f
}

// List returns the formats of a group.
func (s *Store) List(ctx context.Context, group string) ([]Format, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT domain, format, updated_by, updated_at FROM idformats WHERE grp = ? ORDER BY domain`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Format{}
	for rows.Next() {
		var d, f, by string
		var at int64
		if err := rows.Scan(&d, &f, &by, &at); err != nil {
			return nil, err
		}
		out = append(out, view(group, d, f, by, at))
	}
	return out, rows.Err()
}

// IDFormatsIn returns the formats by id domain for the worlds of a group.
// The group "" (a world of every group) takes every group's formats, the
// first group in name order winning on a domain set by two.
func (s *Store) IDFormatsIn(ctx context.Context, group string) (map[string]string, error) {
	q, args := `SELECT grp, domain, format FROM idformats WHERE grp = ? ORDER BY grp, domain`, []any{group}
	if group == "" {
		q, args = `SELECT grp, domain, format FROM idformats ORDER BY grp, domain`, nil
	}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var g, d, f string
		if err := rows.Scan(&g, &d, &f); err != nil {
			return nil, err
		}
		if _, ok := out[d]; !ok {
			if _, err := idfmt.Parse(f); err == nil {
				out[d] = f
			}
		}
	}
	return out, rows.Err()
}

// apiError is an error with status and code; details carry the template
// error (code and position) for the console.
type apiError struct {
	status        int
	code, message string
	details       []map[string]any
}

func (e *apiError) Error() string { return e.code }

func (s *Store) record(ctx context.Context, e audit.Event) {
	if s.Audit == nil {
		return
	}
	if _, err := s.Audit.Record(ctx, e); err != nil && s.Logger != nil {
		s.Logger.ErrorContext(ctx, "idformats: audit failed", "err", err)
	}
}

func principalName(p *auth.Principal) string {
	for _, v := range []string{p.Username, p.DisplayName, p.UserID} {
		if v != "" {
			return v
		}
	}
	return ""
}

// Set stores the format of a domain in a group.
func (s *Store) Set(ctx context.Context, p *auth.Principal, group, domain, format string) (*Format, error) {
	if !groupRE.MatchString(group) {
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "invalid_group", message: "malformed group name"}
	}
	if !domainRE.MatchString(domain) {
		return nil, &apiError{status: http.StatusUnprocessableEntity, code: "invalid_domain", message: "malformed id domain"}
	}
	if _, err := idfmt.Parse(format); err != nil {
		var te *idfmt.Error
		errors.As(err, &te)
		ae := &apiError{status: http.StatusUnprocessableEntity, code: "invalid_format", message: err.Error()}
		if te != nil {
			ae.details = []map[string]any{{"code": te.Code, "at": te.At}}
		}
		return nil, ae
	}
	now := s.now()
	by := principalName(p)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO idformats (grp, domain, format, updated_by, updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(grp, domain) DO UPDATE SET format = excluded.format, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		group, domain, format, by, now.Unix()); err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "idformat.set", Target: audit.Target{Type: "id_format", ID: domain}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "domain": domain, "format": format}})
	f := view(group, domain, format, by, now.Unix())
	return &f, nil
}

// Delete removes the format of a domain (the domain goes back to the
// <PREFIX>-SYN-NNNN ids).
func (s *Store) Delete(ctx context.Context, p *auth.Principal, group, domain string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM idformats WHERE grp = ? AND domain = ?`, group, domain)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return &apiError{status: http.StatusNotFound, code: "not_found", message: "no id format for this domain"}
	}
	s.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "idformat.delete", Target: audit.Target{Type: "id_format", ID: domain}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "domain": domain}})
	return nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Preview is the answer of POST /api/v1/id-formats/preview.
type Preview struct {
	Valid         bool         `json:"valid"`
	Preview       []string     `json:"preview,omitempty"`
	CapacityLabel string       `json:"capacity_label,omitempty"`
	Error         *idfmt.Error `json:"error,omitempty"`
}

// PreviewOf checks a format and gives its first three ids.
func PreviewOf(format, domain string) Preview {
	t, err := idfmt.Parse(format)
	if err != nil {
		var te *idfmt.Error
		if !errors.As(err, &te) {
			te = &idfmt.Error{Code: "bad_char"}
		}
		return Preview{Error: te}
	}
	if domain == "" {
		domain = "id"
	}
	return Preview{Valid: true, Preview: t.Preview(domain, 3), CapacityLabel: idfmt.CapacityLabel(t.Capacity())}
}

// Handler serves the API (behind auth.Require with RolesRead).
func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, roles []auth.Role, h func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			if !p.HasAny(roles...) {
				s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny", Target: audit.RouteTarget(r), Outcome: audit.Denied,
					Reason: "missing_role", RequestID: httpx.RequestID(r.Context())})
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			if err := h(w, r, p); err != nil {
				var ae *apiError
				switch {
				case errors.As(err, &ae):
					httpx.WriteErrorDetails(w, ae.status, ae.code, ae.message, ae.details)
				case errors.Is(err, httpx.ErrBadRequest):
					httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
				default:
					if s.Logger != nil {
						s.Logger.ErrorContext(r.Context(), "idformats: request failed", "err", err)
					}
					httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
				}
			}
		})
	}
	route("GET "+Prefix, RolesRead, func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
		g := r.URL.Query().Get("group")
		if !groupRE.MatchString(g) {
			return &apiError{status: http.StatusBadRequest, code: "bad_request", message: "malformed group"}
		}
		l, err := s.List(r.Context(), g)
		if err != nil {
			return err
		}
		sort.Slice(l, func(i, j int) bool { return l[i].Domain < l[j].Domain })
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"formats": l})
		return nil
	})
	route("POST "+Prefix+"/preview", RolesRead, func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
		var req struct {
			Format string `json:"format"`
			Domain string `json:"domain"`
		}
		if err := httpx.DecodeJSON(w, r, 16<<10, &req); err != nil {
			return httpx.ErrBadRequest
		}
		if req.Domain != "" && !domainRE.MatchString(req.Domain) {
			return &apiError{status: http.StatusUnprocessableEntity, code: "invalid_domain", message: "malformed id domain"}
		}
		httpx.WriteJSON(w, http.StatusOK, PreviewOf(req.Format, req.Domain))
		return nil
	})
	route("PUT "+Prefix+"/{domain}", RolesWrite, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		var req struct {
			Group  string `json:"group"`
			Format string `json:"format"`
		}
		if err := httpx.DecodeJSON(w, r, 16<<10, &req); err != nil {
			return httpx.ErrBadRequest
		}
		f, err := s.Set(r.Context(), p, req.Group, r.PathValue("domain"), req.Format)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, f)
		return nil
	})
	route("DELETE "+Prefix+"/{domain}", RolesWrite, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		g := r.URL.Query().Get("group")
		if !groupRE.MatchString(g) || !domainRE.MatchString(r.PathValue("domain")) {
			return &apiError{status: http.StatusBadRequest, code: "bad_request", message: "malformed group or domain"}
		}
		if err := s.Delete(r.Context(), p, g, r.PathValue("domain")); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	mux.HandleFunc(Prefix+"/", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	})
	return mux
}
