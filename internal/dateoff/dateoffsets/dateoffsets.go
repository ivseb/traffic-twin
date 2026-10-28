// Package dateoffsets stores the relative dates chosen in the console (one
// range per group and date field name, docs/spec/pack.md 4.4) and serves
// them on the admin API:
//
//	GET    /api/v1/date-offsets?group=g          operator, publisher, auditor, rule-reviewer
//	PUT    /api/v1/date-offsets/{field}          operator, rule-reviewer
//	DELETE /api/v1/date-offsets/{field}?group=g  operator, rule-reviewer
//
// The world service reads them (DateOffsetsIn) and writes them into the
// contracts of a world's inputs (dateoff.Annotate): a person's range wins
// over the one learned from the traffic.
package dateoffsets

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Prefix of the admin API.
const Prefix = "/api/v1/date-offsets"

func init() {
	store.Register(store.Namespace{Name: "dateoffsets", Migrations: []store.Migration{
		{Version: 1, Name: "offsets", SQL: `CREATE TABLE dateoffsets (
			grp        TEXT NOT NULL,
			field      TEXT NOT NULL,
			min        TEXT NOT NULL,
			max        TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (grp, field)
		) STRICT;`},
	}})
}

// Roles of the API (admin implies all of them).
var (
	RolesRead  = []auth.Role{auth.RoleOperator, auth.RolePublisher, auth.RoleAuditor, auth.RoleRuleReviewer}
	RolesWrite = []auth.Role{auth.RoleOperator, auth.RoleRuleReviewer}
)

var (
	fieldRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	groupRE = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62})?$`)
)

// Store keeps the ranges.
type Store struct {
	DB     *store.DB
	Audit  *audit.Log
	Now    func() time.Time
	Logger *slog.Logger
}

// Offset is one stored range (the API object).
type Offset struct {
	Group     string `json:"group"`
	Field     string `json:"field"`
	Min       string `json:"min"`
	Max       string `json:"max"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
}

// List returns the ranges of a group.
func (s *Store) List(ctx context.Context, group string) ([]Offset, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT field, min, max, updated_by, updated_at FROM dateoffsets WHERE grp = ? ORDER BY field`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Offset{}
	for rows.Next() {
		var o Offset
		var at int64
		if err := rows.Scan(&o.Field, &o.Min, &o.Max, &o.UpdatedBy, &at); err != nil {
			return nil, err
		}
		o.Group, o.UpdatedAt = group, time.Unix(at, 0).UTC().Format(time.RFC3339)
		out = append(out, o)
	}
	return out, rows.Err()
}

// DateOffsetsIn returns the ranges by field name for the worlds of a group.
// The group "" (a world of every group) takes every group's ranges, the
// first group in name order winning on a field set by two.
func (s *Store) DateOffsetsIn(ctx context.Context, group string) (map[string]dateoff.Range, error) {
	q, args := `SELECT grp, field, min, max FROM dateoffsets WHERE grp = ? ORDER BY grp, field`, []any{group}
	if group == "" {
		q, args = `SELECT grp, field, min, max FROM dateoffsets ORDER BY grp, field`, nil
	}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]dateoff.Range{}
	for rows.Next() {
		var g, f string
		var r dateoff.Range
		if err := rows.Scan(&g, &f, &r.Min, &r.Max); err != nil {
			return nil, err
		}
		if _, ok := out[f]; !ok {
			if _, _, err := r.Parse(); err == nil {
				out[f] = r
			}
		}
	}
	return out, rows.Err()
}

type apiError struct {
	status        int
	code, message string
}

func (e *apiError) Error() string { return e.code }

func (s *Store) record(ctx context.Context, e audit.Event) {
	if s.Audit == nil {
		return
	}
	if _, err := s.Audit.Record(ctx, e); err != nil && s.Logger != nil {
		s.Logger.ErrorContext(ctx, "dateoffsets: audit failed", "err", err)
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

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Set stores the range of a date field in a group.
func (s *Store) Set(ctx context.Context, p *auth.Principal, group, field string, r dateoff.Range) (*Offset, error) {
	if !groupRE.MatchString(group) {
		return nil, &apiError{http.StatusUnprocessableEntity, "invalid_group", "malformed group name"}
	}
	if !fieldRE.MatchString(field) {
		return nil, &apiError{http.StatusUnprocessableEntity, "invalid_field", "malformed field name"}
	}
	if _, _, err := r.Parse(); err != nil {
		return nil, &apiError{http.StatusUnprocessableEntity, "invalid_offset", err.Error()}
	}
	now := s.now()
	by := principalName(p)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO dateoffsets (grp, field, min, max, updated_by, updated_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(grp, field) DO UPDATE SET min = excluded.min, max = excluded.max, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		group, field, r.Min, r.Max, by, now.Unix()); err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "dateoffset.set", Target: audit.Target{Type: "date_offset", ID: field}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "field": field, "min": r.Min, "max": r.Max}})
	return &Offset{Group: group, Field: field, Min: r.Min, Max: r.Max, UpdatedBy: by, UpdatedAt: now.Format(time.RFC3339)}, nil
}

// Delete removes the range of a field (the learned one applies again).
func (s *Store) Delete(ctx context.Context, p *auth.Principal, group, field string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM dateoffsets WHERE grp = ? AND field = ?`, group, field)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return &apiError{http.StatusNotFound, "not_found", "no relative date for this field"}
	}
	s.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "dateoffset.delete", Target: audit.Target{Type: "date_offset", ID: field}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "field": field}})
	return nil
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
					httpx.WriteError(w, ae.status, ae.code, ae.message)
				case errors.Is(err, httpx.ErrBadRequest):
					httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
				default:
					if s.Logger != nil {
						s.Logger.ErrorContext(r.Context(), "dateoffsets: request failed", "err", err)
					}
					httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
				}
			}
		})
	}
	route("GET "+Prefix, RolesRead, func(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
		g := r.URL.Query().Get("group")
		if !groupRE.MatchString(g) {
			return &apiError{http.StatusBadRequest, "bad_request", "malformed group"}
		}
		l, err := s.List(r.Context(), g)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"offsets": l})
		return nil
	})
	route("PUT "+Prefix+"/{field}", RolesWrite, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		var req struct {
			Group string `json:"group"`
			Min   string `json:"min"`
			Max   string `json:"max"`
		}
		if err := httpx.DecodeJSON(w, r, 4<<10, &req); err != nil {
			return httpx.ErrBadRequest
		}
		o, err := s.Set(r.Context(), p, req.Group, r.PathValue("field"), dateoff.Range{Min: req.Min, Max: req.Max})
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, o)
		return nil
	})
	route("DELETE "+Prefix+"/{field}", RolesWrite, func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
		g := r.URL.Query().Get("group")
		if !groupRE.MatchString(g) || !fieldRE.MatchString(r.PathValue("field")) {
			return &apiError{http.StatusBadRequest, "bad_request", "malformed group or field"}
		}
		if err := s.Delete(r.Context(), p, g, r.PathValue("field")); err != nil {
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
