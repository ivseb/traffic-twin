package mockreg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Third-party pages of a group's mocks (docs/spec/mock.md 9): payment or
// e-signature pages with their buttons, return URLs and callbacks. The
// configuration reaches every console-mode mock of the group in the answer
// to its report; the HMAC keys (test secrets) never leave the console in the
// API answers.
//
//	GET /api/v1/mocks/pages?group=g    operator, publisher, auditor
//	PUT /api/v1/mocks/pages            operator   {group, pages: [...]}

// PagesView is the API object.
type PagesView struct {
	Group     string      `json:"group"`
	Pages     []mock.Page `json:"pages"`
	UpdatedBy string      `json:"updated_by,omitempty"`
	UpdatedAt string      `json:"updated_at,omitempty"`
}

func (g *Registry) pagesRow(ctx context.Context, group string) (*mock.PagesConfig, string, int64, error) {
	var raw, by string
	var at int64
	err := g.o.DB.QueryRowContext(ctx, `SELECT config, updated_by, updated_at FROM mockreg_pages WHERE grp = ?`, group).Scan(&raw, &by, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", 0, nil
	}
	if err != nil {
		return nil, "", 0, err
	}
	var c mock.PagesConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, "", 0, err
	}
	return &c, by, at, nil
}

// Pages returns the view of a group's pages (keys hidden).
func (g *Registry) Pages(ctx context.Context, group string) (*PagesView, error) {
	c, by, at, err := g.pagesRow(ctx, group)
	if err != nil {
		return nil, err
	}
	v := &PagesView{Group: group, Pages: c.Masked().Pages}
	if c != nil {
		v.UpdatedBy, v.UpdatedAt = by, time.Unix(at, 0).UTC().Format(time.RFC3339)
	}
	return v, nil
}

// pagesWire is the configuration sent to the group's mocks (nil when the
// group has none).
func (g *Registry) pagesWire(ctx context.Context, group string) (*mock.PagesConfig, error) {
	c, _, _, err := g.pagesRow(ctx, group)
	return c, err
}

// SetPages replaces the pages of a group. An HMAC key left empty keeps the
// stored key of the same page.
func (g *Registry) SetPages(ctx context.Context, p *auth.Principal, group string, pages []mock.Page) (*PagesView, error) {
	if !identityGroupRE.MatchString(group) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	c := &mock.PagesConfig{Pages: pages}
	if c.Pages == nil {
		c.Pages = []mock.Page{}
	}
	cur, _, _, err := g.pagesRow(ctx, group)
	if err != nil {
		return nil, err
	}
	if cur != nil {
		for i := range c.Pages {
			cb := c.Pages[i].Callback
			if cb == nil || cb.HMAC == nil || cb.HMAC.Key != "" {
				continue
			}
			for _, old := range cur.Pages {
				if old.ID == c.Pages[i].ID && old.Callback != nil && old.Callback.HMAC != nil {
					cb.HMAC.Key = old.Callback.HMAC.Key
				}
			}
		}
	}
	if err := c.Validate(); err != nil {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_pages", err.Error())
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(raw) > 256<<10 {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_pages", "the configuration is larger than 256 KiB")
	}
	by := principalName(p)
	if _, err := g.o.DB.ExecContext(ctx, `INSERT INTO mockreg_pages (grp, config, updated_by, updated_at) VALUES (?,?,?,?)
		ON CONFLICT(grp) DO UPDATE SET config = excluded.config, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		group, string(raw), by, g.o.Now().UTC().Unix()); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(c.Pages))
	for _, pg := range c.Pages {
		ids = append(ids, pg.ID)
	}
	g.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "mock.pages_set", Target: audit.Target{Type: "mock_pages", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "pages": strconv.Itoa(len(c.Pages)), "ids": strings.Join(ids, ",")}})
	g.wakeGroup(group)
	return g.Pages(ctx, group)
}

func (g *Registry) apiPages(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	group := r.URL.Query().Get("group")
	if !identityGroupRE.MatchString(group) {
		return apiErr(http.StatusBadRequest, "bad_request", "malformed group")
	}
	v, err := g.Pages(r.Context(), group)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (g *Registry) apiSetPages(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Group string      `json:"group"`
		Pages []mock.Page `json:"pages"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	v, err := g.SetPages(r.Context(), p, req.Group, req.Pages)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}
