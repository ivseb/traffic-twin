package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Token types (admin-api createEnrollmentToken).
const (
	TokenOneTime = "one_time"
	TokenGroup   = "group"
)

// SourceKinds are the source kinds of the Fleet API.
var SourceKinds = []string{"sdk-node", "sdk-python", "sdk-java", "sdk-dotnet", "sdk-go", "sdk-php", "egress", "obi", "import-har", "import-otlp"}

// TokenKinds are the kinds an enrollment token can have: the source kinds
// plus k8s-inject, which any sdk-* source can enroll with.
var TokenKinds = append(append([]string(nil), SourceKinds...), KindK8sInject)

func validKind(k string) bool { return slices.Contains(SourceKinds, k) }

func validTokenKind(k string) bool { return slices.Contains(TokenKinds, k) }

// tokenAdmits reports whether a token of kind tok can enroll a source of kind src.
func tokenAdmits(tok, src string) bool {
	return tok == src || (tok == KindK8sInject && strings.HasPrefix(src, "sdk-") && validKind(src))
}

var (
	reToken   = regexp.MustCompile(`^tte_([A-Za-z0-9_-]{32,128})\.([A-Za-z0-9_-]{43})$`)
	reTokenID = regexp.MustCompile(`^tok-[0-9A-Za-z]{1,32}$`)
)

// TokenRequest is the body of createEnrollmentToken.
type TokenRequest struct {
	Kind       string `json:"kind"`
	Group      string `json:"group"`
	TokenType  string `json:"token_type"`
	ExpiresInS *int64 `json:"expires_in_s,omitempty"`
}

// NewToken is the result of CreateToken: the secret is shown once.
type NewToken struct {
	TokenID   string    `json:"token_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Snippets  []Snippet `json:"snippets"`
}

// TokenInfo describes a token without its secret (EnrollmentTokenInfo).
type TokenInfo struct {
	TokenID   string    `json:"token_id"`
	Kind      string    `json:"kind"`
	Group     string    `json:"group"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
	Uses      int64     `json:"uses"`
	Revoked   bool      `json:"revoked"`
	CreatedBy string    `json:"created_by"`
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateToken creates an enrollment token. Only the SHA-256 of the secret
// is stored; the token embeds the CA pin.
func (f *Fleet) CreateToken(ctx context.Context, p *auth.Principal, req TokenRequest) (*NewToken, error) {
	if !validTokenKind(req.Kind) {
		return nil, invalid("invalid_kind", "unknown source kind")
	}
	if req.Kind == KindK8sInject && req.TokenType != TokenGroup {
		return nil, invalid("invalid_token_type", "k8s-inject tokens are group tokens: every pod of the workload enrolls with the same one")
	}
	ttl := time.Hour
	if req.ExpiresInS != nil {
		if *req.ExpiresInS < 60 || *req.ExpiresInS > 31536000 {
			return nil, invalid("invalid_expiry", "expires_in_s must be between 60 and 31536000")
		}
		ttl = time.Duration(*req.ExpiresInS) * time.Second
	}
	maxUses := int64(1)
	switch req.TokenType {
	case TokenOneTime:
		if ttl > MaxOneTimeTokenTTL {
			return nil, invalid("invalid_expiry", "one-time tokens expire within 24 hours")
		}
	case TokenGroup:
		if ttl > MaxGroupTokenTTL {
			return nil, invalid("invalid_expiry", "group tokens expire within 365 days")
		}
		maxUses = 0 // unlimited
	default:
		return nil, invalid("invalid_token_type", "token_type must be one_time or group")
	}
	g, err := f.GetGroup(ctx, req.Group)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, invalid("unknown_group", "group not found")
		}
		return nil, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	secret := b64.EncodeToString(raw[:])
	id := httpx.NewID("tok-")
	now := f.now().UTC().Truncate(time.Second)
	exp := now.Add(ttl)
	if _, err := f.db.ExecContext(ctx, `INSERT INTO fleet_tokens(id, secret_hash, kind, grp, token_type, expires_at, max_uses, created_by, created_by_name, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, id, hashSecret(secret), req.Kind, req.Group, req.TokenType, exp.Unix(), maxUses,
		p.UserID, displayName(p), now.Unix()); err != nil {
		return nil, err
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.token_create", Target: audit.Target{Type: "enrollment_token", ID: id}, Outcome: audit.Success,
		Details: map[string]string{"group": req.Group, "kind": req.Kind, "token_type": req.TokenType, "expires_at": exp.Format(time.RFC3339)}})
	token := "tte_" + secret + "." + f.ca.pin
	service := ""
	if len(g.AllowedServiceNames) > 0 {
		service = g.AllowedServiceNames[0]
	}
	return &NewToken{TokenID: id, Token: token, ExpiresAt: exp, Snippets: Snippets(req.Kind, f.publicURL, token, service)}, nil
}

func displayName(p *auth.Principal) string {
	if p.Username != "" {
		return p.Username
	}
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.UserID
}

// ListTokens returns every token (never the secrets).
func (f *Fleet) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT id, kind, grp, token_type, expires_at, uses, revoked, created_by_name FROM fleet_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenInfo{}
	for rows.Next() {
		var t TokenInfo
		var exp int64
		var rev int
		if err := rows.Scan(&t.TokenID, &t.Kind, &t.Group, &t.TokenType, &exp, &t.Uses, &rev, &t.CreatedBy); err != nil {
			return nil, err
		}
		t.ExpiresAt, t.Revoked = time.Unix(exp, 0).UTC(), rev == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

func (f *Fleet) getToken(ctx context.Context, id string) (*TokenInfo, error) {
	var t TokenInfo
	var exp int64
	var rev int
	err := f.db.QueryRowContext(ctx, `SELECT id, kind, grp, token_type, expires_at, uses, revoked, created_by_name FROM fleet_tokens WHERE id = ?`, id).
		Scan(&t.TokenID, &t.Kind, &t.Group, &t.TokenType, &exp, &t.Uses, &rev, &t.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	t.ExpiresAt, t.Revoked = time.Unix(exp, 0).UTC(), rev == 1
	return &t, nil
}

// RevokeToken revokes a token; sources already enrolled keep their
// certificate.
func (f *Fleet) RevokeToken(ctx context.Context, p *auth.Principal, id string) error {
	if !reTokenID.MatchString(id) {
		return errNotFound
	}
	res, err := f.db.ExecContext(ctx, `UPDATE fleet_tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.token_revoke", Target: audit.Target{Type: "enrollment_token", ID: id}, Outcome: audit.Success})
	return nil
}

// tokenProblem is a 401 enrollment failure.
func tokenProblem(code string) *APIError {
	return apiErr(401, code, map[string]string{
		"token_unknown":   "enrollment token unknown",
		"token_expired":   "enrollment token expired",
		"token_revoked":   "enrollment token revoked",
		"token_exhausted": "enrollment token already used",
	}[code])
}

// consumeToken checks a token and counts one use inside tx. It returns the
// token row. The check-and-increment is a single conditional UPDATE, so a
// one-time token cannot be used twice even by concurrent requests.
func (f *Fleet) consumeToken(ctx context.Context, tx *sql.Tx, secret string, now time.Time) (*TokenInfo, error) {
	var t TokenInfo
	var exp, maxUses int64
	var rev int
	err := tx.QueryRowContext(ctx, `SELECT id, kind, grp, token_type, expires_at, uses, max_uses, revoked FROM fleet_tokens WHERE secret_hash = ?`, hashSecret(secret)).
		Scan(&t.TokenID, &t.Kind, &t.Group, &t.TokenType, &exp, &t.Uses, &maxUses, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tokenProblem("token_unknown")
	}
	if err != nil {
		return nil, err
	}
	t.ExpiresAt, t.Revoked = time.Unix(exp, 0).UTC(), rev == 1
	switch {
	case t.Revoked:
		return &t, tokenProblem("token_revoked")
	case !now.Before(t.ExpiresAt):
		return &t, tokenProblem("token_expired")
	case maxUses > 0 && t.Uses >= maxUses:
		return &t, tokenProblem("token_exhausted")
	}
	res, err := tx.ExecContext(ctx, `UPDATE fleet_tokens SET uses = uses + 1 WHERE id = ? AND revoked = 0 AND expires_at > ? AND (max_uses = 0 OR uses < max_uses)`,
		t.TokenID, now.Unix())
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return &t, tokenProblem("token_exhausted")
	}
	t.Uses++
	return &t, nil
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
