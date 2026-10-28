// Package mockreg is the mock registry of tt-core ("Mock" page of the
// console): mock tokens, the mocks that report to the console (managed by
// tt-core in Kubernetes, or installed by the user with the container image
// or the Helm chart), their last calls and the control commands queued for
// them, and the managed mocks that tt-core creates in its Kubernetes
// namespace.
//
// A mock token (ttm_...) is scoped to one group, stored as a SHA-256 hash,
// expires and can be revoked. With it a mock can only download the latest
// published pack of that group and post its report (internal/mock console
// mode): it is not a console session and opens no other endpoint.
//
// What the mocks report is zone C data: synthetic packs, test calls. The
// registry keeps only call summaries (method, path, status, scenario,
// fault), never headers, bodies or query strings.
package mockreg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "mockreg", Migrations: []store.Migration{
		{Version: 1, Name: "tokens_managed", SQL: `CREATE TABLE mockreg_tokens (
			id          TEXT PRIMARY KEY,
			secret_hash TEXT NOT NULL,
			grp         TEXT NOT NULL,
			label       TEXT NOT NULL DEFAULT '',
			managed     INTEGER NOT NULL DEFAULT 0 CHECK (managed IN (0, 1)),
			created_by  TEXT NOT NULL,
			created_at  INTEGER NOT NULL,
			expires_at  INTEGER NOT NULL,
			revoked     INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
			last_used   INTEGER NOT NULL DEFAULT 0
		) STRICT;
		CREATE INDEX mockreg_tokens_grp ON mockreg_tokens(grp);
		CREATE TABLE mockreg_managed (
			grp        TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			token_id   TEXT NOT NULL,
			url        TEXT NOT NULL,
			created_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		) STRICT;`},
		{Version: 2, Name: "identity_sessions", SQL: `CREATE TABLE mockreg_identity (
			grp        TEXT PRIMARY KEY,
			header     TEXT NOT NULL,
			claim      TEXT NOT NULL DEFAULT '',
			hash_key   BLOB NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		) STRICT;
		CREATE TABLE mockreg_identity_map (
			grp        TEXT NOT NULL,
			user_hash  TEXT NOT NULL,
			customer   TEXT NOT NULL,
			PRIMARY KEY (grp, user_hash)
		) STRICT;`},
		{Version: 3, Name: "third_party_pages", SQL: `CREATE TABLE mockreg_pages (
			grp        TEXT PRIMARY KEY,
			config     TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		) STRICT;`},
	}})
}

// GroupRE is the shape of a group name (as fleet groups).
var GroupRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

var (
	reToken   = regexp.MustCompile(`^ttm_([0-9a-f]{24})\.([A-Za-z0-9_-]{43})$`)
	reTokenID = regexp.MustCompile(`^mtk-[0-9a-f]{24}$`)
)

// Token lifetimes.
const (
	DefaultTokenDays = 180
	MaxTokenDays     = 365
)

// PackSource gives the registry the published packs (internal/packwriter
// through a core adapter).
type PackSource interface {
	// LatestPublished is the id of the newest published pack built for
	// group ("" when there is none).
	LatestPublished(ctx context.Context, group string) (string, error)
	// Archive is the signed .ttpack of a published pack of group, the
	// download audited as actor.
	Archive(ctx context.Context, id, group string, actor audit.Actor) ([]byte, error)
}

// Options configure a Registry.
type Options struct {
	DB     *store.DB
	Audit  *audit.Log
	Logger *slog.Logger
	// Now is the clock of token creation and expiry (tt-core's clock).
	Now func() time.Time
	// Wall is the clock of the reports (last seen, caches); default time.Now.
	Wall  func() time.Time
	Packs PackSource
	// GroupExists checks that a token's group exists (nil: any well-formed name).
	GroupExists func(ctx context.Context, group string) (bool, error)
	// GatePubKeys returns the TT_GATE_PUBKEYS value (keyguard's pack keys).
	GatePubKeys func(ctx context.Context) (string, error)
	// RealBases maps the services of a group to the base URL of the real
	// endpoint (declared by its signed policy), for "replace X with Y".
	RealBases func(group string) map[string]string
	// ConsoleURL is how mocks reach tt-core (mock.console_url); when empty
	// the snippets use the URL of the request.
	ConsoleURL string
	// Image is the container image of the mock (snippets, managed mocks).
	Image string
	// Kube manages mocks in Kubernetes (nil: not available).
	Kube *Kube
	// ReportInterval is the report period asked of the mocks (default 5s).
	ReportInterval time.Duration
}

// Registry is the mock registry.
type Registry struct {
	o   Options
	log *slog.Logger

	mu        sync.Mutex
	instances map[string]*instance
	latest    map[string]latestPack

	fails failLimiter
}

// Refused tokens per client and token id on the agent API: a burst of failBurst, then
// failBurst per failWindow. Valid mocks never fail (a refused mock stops).
const (
	failBurst     = 20
	failWindow    = time.Minute
	maxFailClient = 10000
)

// failLimiter counts refused mock tokens per client (agent API).
type failLimiter struct {
	mu sync.Mutex
	m  map[string]*failBucket
}

type failBucket struct {
	n     float64
	since time.Time
}

func (l *failLimiter) refill(b *failBucket, now time.Time) {
	if d := now.Sub(b.since); d > 0 {
		b.n = max(0, b.n-d.Seconds()*failBurst/failWindow.Seconds())
	}
	b.since = now
}

// blocked returns how long the client must wait (0: it may try).
func (l *failLimiter) blocked(client string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[client]
	if b == nil {
		return 0
	}
	l.refill(b, now)
	if b.n <= failBurst-1 {
		return 0
	}
	return time.Duration((b.n - (failBurst - 1)) / failBurst * float64(failWindow))
}

func (l *failLimiter) fail(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*failBucket{}
	}
	b := l.m[client]
	if b == nil {
		if len(l.m) >= maxFailClient {
			for k, o := range l.m {
				if l.refill(o, now); o.n == 0 {
					delete(l.m, k)
				}
			}
			if len(l.m) >= maxFailClient {
				return
			}
		}
		b = &failBucket{since: now}
		l.m[client] = b
	}
	l.refill(b, now)
	b.n++
}

type latestPack struct {
	id string
	at time.Time
}

// New builds a Registry.
func New(o Options) (*Registry, error) {
	if o.DB == nil || o.Audit == nil || o.Packs == nil {
		return nil, errors.New("mockreg: db, audit and packs are required")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Wall == nil {
		o.Wall = time.Now
	}
	if o.ReportInterval <= 0 {
		o.ReportInterval = 3 * time.Second
	}
	if o.Image == "" {
		o.Image = "ghcr.io/ivseb/traffic-twin:latest"
	}
	return &Registry{o: o, log: o.Logger, instances: map[string]*instance{}, latest: map[string]latestPack{}}, nil
}

func (g *Registry) record(ctx context.Context, e audit.Event) {
	if _, err := g.o.Audit.Record(ctx, e); err != nil {
		g.log.Error("mockreg: audit write failed", "action", e.Action)
	}
}

// apiError is an error with a status and a stable code.
type apiError struct {
	status        int
	code, message string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

func apiErr(status int, code, msg string) error { return &apiError{status, code, msg} }

var errNotFound = apiErr(http.StatusNotFound, "not_found", "not found")

// ErrorCode is the stable code of an error of the registry ("" for others).
func ErrorCode(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.code
	}
	return ""
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TokenInfo describes a mock token without its secret.
type TokenInfo struct {
	TokenID   string     `json:"token_id"`
	Group     string     `json:"group"`
	Label     string     `json:"label"`
	Managed   bool       `json:"managed"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Revoked   bool       `json:"revoked"`
	LastUsed  *time.Time `json:"last_used"`
}

// NewToken is a created token: the secret is shown once.
type NewToken struct {
	TokenInfo
	Token string `json:"token"`
	Setup *Setup `json:"setup,omitempty"`
}

var reLabel = regexp.MustCompile(`^[\pL\pN _.:/@+()-]{0,64}$`)

func principalName(p *auth.Principal) string {
	for _, s := range []string{p.Username, p.DisplayName, p.UserID} {
		if s != "" {
			return s
		}
	}
	return ""
}

// CreateToken creates a mock token for group, valid days days.
func (g *Registry) CreateToken(ctx context.Context, p *auth.Principal, group, label string, days int, managed bool) (*NewToken, error) {
	if !GroupRE.MatchString(group) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	if g.o.GroupExists != nil {
		ok, err := g.o.GroupExists(ctx, group)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, apiErr(http.StatusUnprocessableEntity, "unknown_group", "group not found")
		}
	}
	label = strings.TrimSpace(label)
	if !reLabel.MatchString(label) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_label", "the label is at most 64 letters, digits, spaces and . _ - : / @ + ( )")
	}
	if days == 0 {
		days = DefaultTokenDays
	}
	if days < 1 || days > MaxTokenDays {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_expiry", "expires_in_days must be between 1 and 365")
	}
	var idb [12]byte
	var sec [32]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(sec[:]); err != nil {
		return nil, err
	}
	idHex := hex.EncodeToString(idb[:])
	secret := base64.RawURLEncoding.EncodeToString(sec[:])
	id := "mtk-" + idHex
	now := g.o.Now().UTC().Truncate(time.Second)
	exp := now.Add(time.Duration(days) * 24 * time.Hour)
	by := principalName(p)
	if _, err := g.o.DB.ExecContext(ctx, `INSERT INTO mockreg_tokens (id, secret_hash, grp, label, managed, created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)`,
		id, hashSecret(secret), group, label, boolInt(managed), by, now.Unix(), exp.Unix()); err != nil {
		return nil, err
	}
	g.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "mock.token_create", Target: audit.Target{Type: "mock_token", ID: id}, Outcome: audit.Success,
		Details: map[string]string{"group": group, "expires_at": exp.Format(time.RFC3339), "managed": boolStr(managed)}})
	return &NewToken{TokenInfo: TokenInfo{TokenID: id, Group: group, Label: label, Managed: managed, CreatedBy: by, CreatedAt: now, ExpiresAt: exp},
		Token: "ttm_" + idHex + "." + secret}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

const tokenCols = `id, grp, label, managed, created_by, created_at, expires_at, revoked, last_used`

func scanToken(sc interface{ Scan(...any) error }) (*TokenInfo, error) {
	var t TokenInfo
	var managed, revoked int
	var created, exp, used int64
	if err := sc.Scan(&t.TokenID, &t.Group, &t.Label, &managed, &t.CreatedBy, &created, &exp, &revoked, &used); err != nil {
		return nil, err
	}
	t.Managed, t.Revoked = managed == 1, revoked == 1
	t.CreatedAt, t.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(exp, 0).UTC()
	if used > 0 {
		u := time.Unix(used, 0).UTC()
		t.LastUsed = &u
	}
	return &t, nil
}

// ListTokens returns the tokens (never their secrets), newest first.
func (g *Registry) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	rows, err := g.o.DB.QueryContext(ctx, `SELECT `+tokenCols+` FROM mockreg_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenInfo{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (g *Registry) token(ctx context.Context, id string) (*TokenInfo, error) {
	if !reTokenID.MatchString(id) {
		return nil, errNotFound
	}
	t, err := scanToken(g.o.DB.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM mockreg_tokens WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return t, err
}

// RevokeToken revokes a token: its mocks are refused from the next report
// on (a mock in console mode then stops).
func (g *Registry) RevokeToken(ctx context.Context, p *auth.Principal, id string) error {
	t, err := g.token(ctx, id)
	if err != nil {
		return err
	}
	if _, err := g.o.DB.ExecContext(ctx, `UPDATE mockreg_tokens SET revoked = 1 WHERE id = ?`, id); err != nil {
		return err
	}
	g.mu.Lock()
	for _, in := range g.instances {
		if in.TokenID == id {
			in.revoked = true
			in.wake()
		}
	}
	g.mu.Unlock()
	g.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "mock.token_revoke", Target: audit.Target{Type: "mock_token", ID: id}, Outcome: audit.Success,
		Details: map[string]string{"group": t.Group}})
	return nil
}

// presentedTokenID is the token id part of the bearer mock token of r ("" when malformed).
func presentedTokenID(r *http.Request) string {
	raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if m := reToken.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	return ""
}

// authenticate checks a bearer mock token and returns it.
func (g *Registry) authenticate(ctx context.Context, r *http.Request) (*TokenInfo, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, errUnauthorized
	}
	m := reToken.FindStringSubmatch(raw)
	if m == nil {
		return nil, errUnauthorized
	}
	id := "mtk-" + m[1]
	var hash string
	var grp string
	var exp, used int64
	var revoked int
	err := g.o.DB.QueryRowContext(ctx, `SELECT secret_hash, grp, expires_at, revoked, last_used FROM mockreg_tokens WHERE id = ?`, id).Scan(&hash, &grp, &exp, &revoked, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, err
	}
	want, _ := hex.DecodeString(hash)
	got := sha256.Sum256([]byte(m[2]))
	if subtle.ConstantTimeCompare(want, got[:]) != 1 || revoked == 1 {
		return nil, errUnauthorized
	}
	now := g.o.Now().UTC()
	if !now.Before(time.Unix(exp, 0)) {
		return nil, errUnauthorized
	}
	if now.Unix()-used >= 60 {
		_, _ = g.o.DB.ExecContext(ctx, `UPDATE mockreg_tokens SET last_used = ? WHERE id = ?`, now.Unix(), id)
	}
	return &TokenInfo{TokenID: id, Group: grp}, nil
}

var errUnauthorized = apiErr(http.StatusUnauthorized, "unauthenticated", "a valid mock token is required")

// latestPack is the newest published pack of a group, cached briefly (every
// mock asks at every report).
func (g *Registry) latestPack(ctx context.Context, group string) (string, error) {
	now := g.o.Wall()
	g.mu.Lock()
	lp, ok := g.latest[group]
	g.mu.Unlock()
	if ok && now.Sub(lp.at) < 2*time.Second && now.Sub(lp.at) >= 0 {
		return lp.id, nil
	}
	id, err := g.o.Packs.LatestPublished(ctx, group)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	g.latest[group] = latestPack{id: id, at: now}
	g.mu.Unlock()
	return id, nil
}

// PackPublished drops the cached latest pack of the groups (call it after a
// publication so the mocks see it at their next report).
func (g *Registry) PackPublished(group string) {
	g.mu.Lock()
	delete(g.latest, group)
	for _, in := range g.instances {
		if in.Group == group {
			in.wake()
		}
	}
	g.mu.Unlock()
}
