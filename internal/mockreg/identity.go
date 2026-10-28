package mockreg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// "Session per user" of a group's mocks (docs/spec/mock.md 2.6): the
// header (and JWT claim) whose value chooses a mock session and synthetic
// customer, the group's hashing key (kept here so the mapping survives
// restarts and pack changes) and the explicit user -> customer map, whose
// users are stored only as keyed hashes. The setting reaches every
// console-mode mock of the group in the answer to its report.
//
//	GET    /api/v1/mocks/identity?group=g          operator, publisher, auditor
//	PUT    /api/v1/mocks/identity                  operator   {group, header, claim}
//	POST   /api/v1/mocks/identity/map              operator   {group, user, customer}
//	DELETE /api/v1/mocks/identity/map/{hash}?group=g  operator

var (
	identityHeaderRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)
	identityClaimRE  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	identityHashRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	customerIDRE     = regexp.MustCompile(`^[A-Z]{2,5}-SYN-[0-9]{4,}$`)
	identityGroupRE  = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62})?$`)
)

const maxIdentityUsers = 1000

// IdentityView is the API object.
type IdentityView struct {
	Group     string             `json:"group"`
	Enabled   bool               `json:"enabled"`
	Header    string             `json:"header"`
	Claim     string             `json:"claim"`
	Map       []IdentityMapEntry `json:"map"`
	UpdatedBy string             `json:"updated_by,omitempty"`
	UpdatedAt string             `json:"updated_at,omitempty"`
}

// IdentityMapEntry is one mapped user: the keyed hash, never the user.
type IdentityMapEntry struct {
	Hash     string `json:"hash"`
	Customer string `json:"customer"`
}

type identityRow struct {
	header, claim string
	key           []byte
	by            string
	at            int64
}

func (g *Registry) identityRow(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, group string) (*identityRow, error) {
	var r identityRow
	err := q.QueryRowContext(ctx, `SELECT header, claim, hash_key, updated_by, updated_at FROM mockreg_identity WHERE grp = ?`, group).
		Scan(&r.header, &r.claim, &r.key, &r.by, &r.at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (g *Registry) identityMap(ctx context.Context, group string) ([]IdentityMapEntry, error) {
	rows, err := g.o.DB.QueryContext(ctx, `SELECT user_hash, customer FROM mockreg_identity_map WHERE grp = ? ORDER BY customer, user_hash`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityMapEntry{}
	for rows.Next() {
		var e IdentityMapEntry
		if err := rows.Scan(&e.Hash, &e.Customer); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Identity returns the view of a group's setting.
func (g *Registry) Identity(ctx context.Context, group string) (*IdentityView, error) {
	v := &IdentityView{Group: group, Map: []IdentityMapEntry{}}
	row, err := g.identityRow(ctx, g.o.DB, group)
	if err != nil || row == nil {
		return v, err
	}
	v.Header, v.Claim, v.Enabled = row.header, row.claim, row.header != ""
	v.UpdatedBy, v.UpdatedAt = row.by, time.Unix(row.at, 0).UTC().Format(time.RFC3339)
	if v.Map, err = g.identityMap(ctx, group); err != nil {
		return nil, err
	}
	return v, nil
}

// identityWire is the setting sent to the group's mocks (nil when the
// group has none).
func (g *Registry) identityWire(ctx context.Context, group string) (*mock.IdentityWire, error) {
	row, err := g.identityRow(ctx, g.o.DB, group)
	if err != nil || row == nil {
		return nil, err
	}
	w := &mock.IdentityWire{Header: row.header, Claim: row.claim}
	if row.header == "" {
		return w, nil
	}
	w.Key = base64.RawURLEncoding.EncodeToString(row.key)
	m, err := g.identityMap(ctx, group)
	if err != nil {
		return nil, err
	}
	if len(m) > 0 {
		w.Map = map[string]string{}
		for _, e := range m {
			w.Map["h:"+e.Hash] = e.Customer
		}
	}
	return w, nil
}

// ensureIdentity returns the group's row, creating it (off, with a new key)
// when missing.
func (g *Registry) ensureIdentity(ctx context.Context, group, by string) (*identityRow, error) {
	row, err := g.identityRow(ctx, g.o.DB, group)
	if err != nil || row != nil {
		return row, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	now := g.o.Now().UTC().Unix()
	if _, err := g.o.DB.ExecContext(ctx, `INSERT INTO mockreg_identity (grp, header, claim, hash_key, updated_by, updated_at) VALUES (?, '', '', ?, ?, ?)
		ON CONFLICT(grp) DO NOTHING`, group, key, by, now); err != nil {
		return nil, err
	}
	return g.identityRow(ctx, g.o.DB, group)
}

// SetIdentity sets header and claim of a group ("" header: off).
func (g *Registry) SetIdentity(ctx context.Context, p *auth.Principal, group, header, claim string) (*IdentityView, error) {
	if !identityGroupRE.MatchString(group) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	header, claim = strings.TrimSpace(header), strings.TrimSpace(claim)
	if header != "" && !identityHeaderRE.MatchString(header) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_header", "the header name may contain letters, digits and - _ . (at most 64)")
	}
	if claim != "" && (header == "" || !identityClaimRE.MatchString(claim)) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_claim", "the claim name may contain letters, digits and _ . : - (at most 64), and needs a header")
	}
	by := principalName(p)
	if _, err := g.ensureIdentity(ctx, group, by); err != nil {
		return nil, err
	}
	if _, err := g.o.DB.ExecContext(ctx, `UPDATE mockreg_identity SET header = ?, claim = ?, updated_by = ?, updated_at = ? WHERE grp = ?`,
		header, claim, by, g.o.Now().UTC().Unix(), group); err != nil {
		return nil, err
	}
	g.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "mock.identity_set", Target: audit.Target{Type: "mock_identity", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "header": header, "claim": claim}})
	g.wakeGroup(group)
	return g.Identity(ctx, group)
}

// AddIdentityUser maps a test user (hashed at once, never stored) to a
// synthetic customer.
func (g *Registry) AddIdentityUser(ctx context.Context, p *auth.Principal, group, user, customer string) (*IdentityView, error) {
	if !identityGroupRE.MatchString(group) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	if user == "" || len(user) > 1024 {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_user", "the user is empty or longer than 1024 bytes")
	}
	if !customerIDRE.MatchString(customer) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_customer", "a synthetic customer id looks like CUS-SYN-0007")
	}
	row, err := g.ensureIdentity(ctx, group, principalName(p))
	if err != nil {
		return nil, err
	}
	var n int
	if err := g.o.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM mockreg_identity_map WHERE grp = ?`, group).Scan(&n); err != nil {
		return nil, err
	}
	if n >= maxIdentityUsers {
		return nil, apiErr(http.StatusUnprocessableEntity, "too_many_users", "at most 1000 mapped users per group")
	}
	h := mock.IdentityHash(row.key, user)
	if _, err := g.o.DB.ExecContext(ctx, `INSERT INTO mockreg_identity_map (grp, user_hash, customer) VALUES (?,?,?)
		ON CONFLICT(grp, user_hash) DO UPDATE SET customer = excluded.customer`, group, h, customer); err != nil {
		return nil, err
	}
	g.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "mock.identity_map_set", Target: audit.Target{Type: "mock_identity", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "user_hash": h[:8], "customer": customer}})
	g.wakeGroup(group)
	return g.Identity(ctx, group)
}

// RemoveIdentityUser removes a mapped user by hash.
func (g *Registry) RemoveIdentityUser(ctx context.Context, p *auth.Principal, group, hash string) (*IdentityView, error) {
	if !identityGroupRE.MatchString(group) || !identityHashRE.MatchString(hash) {
		return nil, apiErr(http.StatusBadRequest, "bad_request", "malformed group or hash")
	}
	res, err := g.o.DB.ExecContext(ctx, `DELETE FROM mockreg_identity_map WHERE grp = ? AND user_hash = ?`, group, hash)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, apiErr(http.StatusNotFound, "not_found", "no mapped user with this hash")
	}
	g.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "mock.identity_map_delete", Target: audit.Target{Type: "mock_identity", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "user_hash": hash[:8]}})
	g.wakeGroup(group)
	return g.Identity(ctx, group)
}

// wakeGroup ends the held reports of the group's mocks, so the setting
// reaches them at once.
func (g *Registry) wakeGroup(group string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, in := range g.instances {
		if in.Group == group {
			in.wake()
		}
	}
}

func (g *Registry) apiIdentity(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	group := r.URL.Query().Get("group")
	if !identityGroupRE.MatchString(group) {
		return apiErr(http.StatusBadRequest, "bad_request", "malformed group")
	}
	v, err := g.Identity(r.Context(), group)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (g *Registry) apiSetIdentity(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Group  string `json:"group"`
		Header string `json:"header"`
		Claim  string `json:"claim"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	v, err := g.SetIdentity(r.Context(), p, req.Group, req.Header, req.Claim)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (g *Registry) apiAddIdentityUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Group    string `json:"group"`
		User     string `json:"user"`
		Customer string `json:"customer"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	v, err := g.AddIdentityUser(r.Context(), p, req.Group, req.User, req.Customer)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

func (g *Registry) apiRemoveIdentityUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	v, err := g.RemoveIdentityUser(r.Context(), p, r.URL.Query().Get("group"), r.PathValue("hash"))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}
