package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ivseb/traffic-twin/internal/audit"
)

// OIDCOptions configure OIDC login.
type OIDCOptions struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // empty for public clients (PKCE only)
	RedirectURL  string
	Scopes       []string
	// RolesClaim, when set, names the claim (string or list of strings)
	// whose values are mapped to roles through RoleMapping at every login.
	// When empty, roles of OIDC users are managed locally.
	RolesClaim  string
	RoleMapping map[string][]Role
	// ApprovalClientID, when set, enables the approval step-up
	// (GET /api/v1/auth/oidc/stepup): a second client registered at the
	// same provider, whose client id is keyguard's dedicated approval
	// audience (TT_KEYGUARD_OIDC_AUDIENCE). It MUST differ from ClientID,
	// so login ID tokens never verify at keyguard. ApprovalRedirectURL
	// defaults to RedirectURL with the path /api/v1/auth/oidc/stepup/callback.
	ApprovalClientID     string
	ApprovalClientSecret string
	ApprovalRedirectURL  string
	// HTTPClient is used for discovery, JWKS and token requests (custom CA
	// bundles, tests). Defaults to a client with a 10 s timeout.
	HTTPClient *http.Client
}

// oidcClient lazily discovers the provider, so tt-core starts even when the
// identity provider is unreachable; discovery is retried at most every
// discoveryBackoff.
type oidcClient struct {
	opts OIDCOptions
	hc   *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	// approval verifies step-up ID tokens (audience ApprovalClientID).
	approval *oidc.IDTokenVerifier
	lastTry  time.Time
}

const (
	discoveryBackoff = 10 * time.Second
	oidcStateTTL     = 10 * time.Minute
	oidcCookieTLS    = "__Host-tt_oidc"
	oidcCookiePlain  = "tt_oidc"
	maxReturnTo      = 512
)

func newOIDCClient(o OIDCOptions) (*oidcClient, error) {
	if o.IssuerURL == "" || o.ClientID == "" || o.RedirectURL == "" {
		return nil, errors.New("auth: oidc needs issuer, client id and redirect url")
	}
	if !slices.Contains(o.Scopes, oidc.ScopeOpenID) {
		o.Scopes = append([]string{oidc.ScopeOpenID}, o.Scopes...)
	}
	if o.ApprovalClientID != "" {
		if o.ApprovalClientID == o.ClientID {
			return nil, errors.New("auth: oidc approval client id must differ from the login client id")
		}
		if o.ApprovalRedirectURL == "" {
			u, err := url.Parse(o.RedirectURL)
			if err != nil {
				return nil, errors.New("auth: oidc redirect url is not a URL")
			}
			u.Path, u.RawQuery = stepUpCallbackPath, ""
			o.ApprovalRedirectURL = u.String()
		}
	}
	for _, roles := range o.RoleMapping {
		if _, err := normalizeRoles(roles); err != nil {
			return nil, fmt.Errorf("auth: oidc role mapping: %w", err)
		}
	}
	hc := o.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &oidcClient{opts: o, hc: hc}, nil
}

func (c *oidcClient) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.hc)
}

func (c *oidcClient) ensure(ctx context.Context, now time.Time) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, c.verifier, nil
	}
	if !c.lastTry.IsZero() && now.Sub(c.lastTry) < discoveryBackoff {
		return nil, nil, errors.New("oidc provider unavailable")
	}
	c.lastTry = now
	// Discovery uses a detached context so the provider's key set is not
	// bound to this request; NewProvider itself is bounded by hc.Timeout.
	p, err := oidc.NewProvider(c.ctx(context.WithoutCancel(ctx)), c.opts.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	c.provider = p
	c.verifier = p.VerifierContext(c.ctx(context.Background()), &oidc.Config{ClientID: c.opts.ClientID})
	if c.opts.ApprovalClientID != "" {
		c.approval = p.VerifierContext(c.ctx(context.Background()), &oidc.Config{ClientID: c.opts.ApprovalClientID})
	}
	return c.provider, c.verifier, nil
}

func (c *oidcClient) oauth2Config(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.opts.ClientID,
		ClientSecret: c.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  c.opts.RedirectURL,
		Scopes:       c.opts.Scopes,
	}
}

func (s *Service) oidcCookieName() string {
	if s.opts.TLS {
		return oidcCookieTLS
	}
	return oidcCookiePlain
}

// safeReturnTo accepts only same-origin absolute paths (no scheme, no
// host, no "//" or "/\" prefixes) to prevent open redirects.
func safeReturnTo(s string) string {
	if s == "" || len(s) > maxReturnTo || s[0] != '/' || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return "/"
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return "/"
		}
	}
	return s
}

// OIDCStartHandler handles GET /api/v1/auth/oidc/start?return_to=/path:
// it stores state, nonce and PKCE verifier server-side, binds the state to
// the browser with a short-lived cookie and redirects to the provider.
func (s *Service) OIDCStartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.oidc == nil {
			writeErr(w, http.StatusNotFound, "oidc_disabled", "OIDC login is not enabled")
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		p, _, err := s.oidc.ensure(r.Context(), s.now())
		if err != nil {
			s.log.WarnContext(r.Context(), "oidc provider unavailable", "err", err)
			writeErr(w, http.StatusServiceUnavailable, "oidc_unavailable", "identity provider unavailable")
			return
		}
		state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
		_, err = s.db.ExecContext(r.Context(), `INSERT INTO auth_oidc_states (state_hash, nonce, verifier, return_to, expires_at) VALUES (?, ?, ?, ?, ?)`,
			hashToken(state), nonce, verifier, safeReturnTo(r.URL.Query().Get("return_to")), s.now().Add(oidcStateTTL).Unix())
		if err != nil {
			s.log.ErrorContext(r.Context(), "oidc state store failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: s.oidcCookieName(), Value: state, Path: "/", MaxAge: int(oidcStateTTL.Seconds()),
			HttpOnly: true, Secure: true,
			// Lax: the callback is a top-level cross-site navigation from the
			// provider, which Strict cookies would not accompany.
			SameSite: http.SameSiteLaxMode,
		})
		url := s.oidc.oauth2Config(p).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, url, http.StatusFound)
	})
}

// OIDCCallbackHandler handles GET /api/v1/auth/oidc/callback. On success it
// creates a session and redirects to the stored return_to path; on failure
// it redirects to /?auth_error=<code>.
func (s *Service) OIDCCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.oidc == nil {
			writeErr(w, http.StatusNotFound, "oidc_disabled", "OIDC login is not enabled")
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		ctx := r.Context()
		// The state cookie is single use whatever happens next.
		http.SetCookie(w, &http.Cookie{Name: s.oidcCookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})

		fail := func(code string) {
			s.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorAnonymous}, Action: "auth.oidc_login", Target: audit.Target{Type: "session"}, Outcome: audit.Failure, Reason: code})
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/?auth_error="+code, http.StatusFound)
		}

		q := r.URL.Query()
		if q.Get("error") != "" {
			fail("idp_error") // the provider's error text is not reflected
			return
		}
		state, code := q.Get("state"), q.Get("code")
		c, err := r.Cookie(s.oidcCookieName())
		if state == "" || code == "" || err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
			fail("state_mismatch")
			return
		}
		nonce, verifier, returnTo, err := s.consumeOIDCState(ctx, state)
		if err != nil {
			fail("state_invalid")
			return
		}
		p, v, err := s.oidc.ensure(ctx, s.now())
		if err != nil {
			fail("idp_unavailable")
			return
		}
		tok, err := s.oidc.oauth2Config(p).Exchange(s.oidc.ctx(ctx), code, oauth2.VerifierOption(verifier))
		if err != nil {
			s.log.WarnContext(ctx, "oidc code exchange failed")
			fail("exchange_failed")
			return
		}
		raw, ok := tok.Extra("id_token").(string)
		if !ok || raw == "" {
			fail("no_id_token")
			return
		}
		idt, err := v.Verify(s.oidc.ctx(ctx), raw)
		if err != nil {
			s.log.WarnContext(ctx, "oidc id_token rejected")
			fail("id_token_invalid")
			return
		}
		if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
			fail("nonce_mismatch")
			return
		}
		if idt.AccessTokenHash != "" {
			if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
				fail("at_hash_mismatch")
				return
			}
		}
		var claims map[string]any
		if err := idt.Claims(&claims); err != nil {
			fail("claims_invalid")
			return
		}
		userID, name, err := s.upsertOIDCUser(ctx, idt.Issuer, idt.Subject, claims)
		if err != nil {
			if errors.Is(err, errUserDisabled) {
				fail("user_disabled")
				return
			}
			s.log.ErrorContext(ctx, "oidc user upsert failed", "err", err)
			fail("internal")
			return
		}
		if _, err := s.createSession(ctx, w, r, userID, "oidc"); err != nil {
			s.log.ErrorContext(ctx, "session create failed", "err", err)
			fail("internal")
			return
		}
		s.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorUser, ID: userID, Name: audit.SafeName(name)}, Action: "auth.oidc_login", Target: audit.Target{Type: "session"}, Outcome: audit.Success})
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, returnTo, http.StatusFound)
	})
}

func (s *Service) consumeOIDCState(ctx context.Context, state string) (nonce, verifier, returnTo string, err error) {
	err = s.db.InTx(ctx, func(tx *sql.Tx) error {
		var exp int64
		h := hashToken(state)
		if err := tx.QueryRowContext(ctx, `SELECT nonce, verifier, return_to, expires_at FROM auth_oidc_states WHERE state_hash = ?`, h).
			Scan(&nonce, &verifier, &returnTo, &exp); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_oidc_states WHERE state_hash = ?`, h); err != nil {
			return err
		}
		if !s.now().Before(time.Unix(exp, 0)) {
			return errors.New("state expired")
		}
		return nil
	})
	return
}

var errUserDisabled = errors.New("user disabled")

func claimString(claims map[string]any, key string) string {
	v, _ := claims[key].(string)
	return v
}

// claimStrings reads a string or list-of-strings claim.
func claimStrings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (s *Service) mapRoles(claims map[string]any) []Role {
	var roles []Role
	for _, g := range claimStrings(claims, s.oidc.opts.RolesClaim) {
		roles = append(roles, s.oidc.opts.RoleMapping[g]...)
	}
	out, _ := normalizeRoles(roles) // validated in newOIDCClient
	return out
}

func (s *Service) upsertOIDCUser(ctx context.Context, issuer, subject string, claims map[string]any) (string, string, error) {
	name := claimString(claims, "name")
	if name == "" {
		name = claimString(claims, "preferred_username")
	}
	if name == "" {
		name = claimString(claims, "email")
	}
	if name == "" {
		name = subject
	}
	if len(name) > 128 {
		name = name[:128]
	}
	var userID string
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		var disabled bool
		err := tx.QueryRowContext(ctx, `SELECT id, disabled FROM auth_users WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, subject).Scan(&userID, &disabled)
		now := s.ts()
		switch {
		case errors.Is(err, sql.ErrNoRows):
			userID = newUserID()
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth_users (id, oidc_issuer, oidc_subject, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
				userID, issuer, subject, name, now, now); err != nil {
				return err
			}
		case err != nil:
			return err
		case disabled:
			return errUserDisabled
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET display_name = ?, updated_at = ? WHERE id = ?`, name, now, userID); err != nil {
				return err
			}
		}
		if s.oidc.opts.RolesClaim != "" {
			return setRolesTx(ctx, tx, userID, s.mapRoles(claims))
		}
		return nil
	})
	return userID, name, err
}
