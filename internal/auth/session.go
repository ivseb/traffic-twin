package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// CSRFHeader carries the synchronizer token on unsafe requests.
const CSRFHeader = "X-CSRF-Token"

// Cookie names. The __Host- prefix (TLS only) pins the cookie to the exact
// host, path "/" and Secure.
const (
	cookieTLS   = "__Host-tt_session"
	cookiePlain = "tt_session"
)

// Principal is the authenticated caller of a request.
type Principal struct {
	UserID        string    `json:"id"`
	Username      string    `json:"username,omitempty"`
	DisplayName   string    `json:"display_name"`
	Method        string    `json:"auth_method"`
	Roles         []Role    `json:"roles"`
	CSRFToken     string    `json:"-"`
	ExpiresAt     time.Time `json:"-"`
	IdleExpiresAt time.Time `json:"-"`
	// OIDCIssuer and OIDCSubject identify an OIDC account at its identity
	// provider (empty for local accounts). Approval step-up tokens must
	// carry the same iss and sub.
	OIDCIssuer  string `json:"-"`
	OIDCSubject string `json:"-"`
	sessionHash string
	// ovr collects the admin overrides of the current request (set by
	// Require, shared by the copies of the principal).
	ovr *overrideNote
}

// overrideNote records that a request was admitted only because its caller
// is admin, and for which roles.
type overrideNote struct {
	mu    sync.Mutex
	roles []Role
}

// Has reports whether p itself holds role r (no implication: use it to tell
// an admin override from the role's own path, e.g. the admin approval).
func (p *Principal) Has(r Role) bool { return p != nil && slices.Contains(p.Roles, r) }

// IsAdmin reports whether p holds admin, which implies every role.
func (p *Principal) IsAdmin() bool { return p.Has(RoleAdmin) }

// HasAny reports whether p may act as one of roles: it holds one of them,
// or it is admin (admin implies every role). It is the authorization check
// of Require and of every per-operation guard. When only admin grants it,
// the request is an admin override: Require records it in the audit
// (authz.admin_override) once the handler has answered. The last check of
// a request decides (a route guard runs after the check of its mount):
// when p holds one of roles itself, an override noted by an earlier, wider
// check is cleared.
func (p *Principal) HasAny(roles ...Role) bool {
	if p == nil || len(roles) == 0 {
		return false
	}
	for _, r := range roles {
		if p.Has(r) {
			p.noteOverride(nil)
			return true
		}
	}
	if !p.IsAdmin() {
		return false
	}
	p.noteOverride(roles)
	return true
}

// AdminOverride reports whether p acts as one of roles only because it is
// admin (it holds none of them itself).
func (p *Principal) AdminOverride(roles ...Role) bool {
	if !p.IsAdmin() {
		return false
	}
	for _, r := range roles {
		if p.Has(r) {
			return false
		}
	}
	return true
}

func (p *Principal) noteOverride(roles []Role) {
	if p.ovr == nil {
		return
	}
	p.ovr.mu.Lock()
	p.ovr.roles = slices.Clone(roles) // the innermost (most specific) check wins; nil clears
	p.ovr.mu.Unlock()
}

func (p *Principal) overrideRoles() []Role {
	if p == nil || p.ovr == nil {
		return nil
	}
	p.ovr.mu.Lock()
	defer p.ovr.mu.Unlock()
	return p.ovr.roles
}

// AuditActor returns p as an audit actor.
func (p *Principal) AuditActor() audit.Actor {
	if p == nil {
		return audit.Actor{Kind: audit.ActorAnonymous}
	}
	return audit.Actor{Kind: audit.ActorUser, ID: p.UserID, Name: audit.SafeName(p.DisplayName)}
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p (for tests of downstream handlers).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal set by Require.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}

// RequestActor returns the audit actor and request id of r; it matches
// audit.ActorFunc.
func RequestActor(r *http.Request) (audit.Actor, string) {
	p, _ := PrincipalFrom(r.Context())
	return p.AuditActor(), httpx.RequestID(r.Context())
}

func (s *Service) cookieName() string {
	if s.opts.TLS {
		return cookieTLS
	}
	return cookiePlain
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// MaxSessionsPerUser bounds the concurrent sessions of one user: a login
// beyond it ends the oldest session of the user.
const MaxSessionsPerUser = 5

// createSession stores a new session for userID, deleting the session the
// request may already carry (fixation defence), and sets the cookie. The
// other sessions of the user stay valid, up to MaxSessionsPerUser.
func (s *Service) createSession(ctx context.Context, w http.ResponseWriter, r *http.Request, userID, method string) (*Principal, error) {
	id := randomToken()
	csrf := randomToken()
	now := s.now()
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
			if _, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id_hash = ?`, hashToken(c.Value)); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions (id_hash, user_id, csrf_token, method, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			hashToken(id), userID, csrf, method, now.Unix(), now.Unix(), now.Add(s.opts.AbsoluteTimeout).Unix()); err != nil {
			return err
		}
		// A user keeps several sessions at once (browsers, a CLI with
		// curl): a new login never ends the others, up to
		// MaxSessionsPerUser; beyond that the oldest ones end.
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ? AND id_hash NOT IN (
			SELECT id_hash FROM auth_sessions WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?)`, userID, userID, MaxSessionsPerUser)
		return err
	})
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		// No Max-Age: a browser-session cookie; the server enforces expiry.
	})
	return s.loadSession(ctx, id)
}

func (s *Service) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

var errNoSession = errors.New("no valid session")

// maxTouchInterval limits last_seen writes to one per interval per session.
const maxTouchInterval = time.Minute

// touchInterval is the write interval: at most a minute, and at most a
// quarter of the idle timeout, so that a short idle timeout is not
// stretched by up to one interval of unrecorded activity.
func (s *Service) touchInterval() time.Duration {
	if q := s.opts.IdleTimeout / 4; q > 0 && q < maxTouchInterval {
		return q
	}
	return maxTouchInterval
}

// loadSession resolves a raw session id, enforcing idle and absolute
// timeouts and the user's disabled flag. Roles are read live.
func (s *Service) loadSession(ctx context.Context, id string) (*Principal, error) {
	if id == "" || len(id) > 128 {
		return nil, errNoSession
	}
	h := hashToken(id)
	var p Principal
	var lastSeen, expires int64
	var disabled bool
	var username, oidcIss, oidcSub sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT s.user_id, s.csrf_token, s.method, s.last_seen, s.expires_at, u.username, u.display_name, u.disabled, u.oidc_issuer, u.oidc_subject
		FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id WHERE s.id_hash = ?`, h).
		Scan(&p.UserID, &p.CSRFToken, &p.Method, &lastSeen, &expires, &username, &p.DisplayName, &disabled, &oidcIss, &oidcSub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoSession
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	idleDeadline := time.Unix(lastSeen, 0).Add(s.opts.IdleTimeout)
	if disabled || !now.Before(time.Unix(expires, 0)) || !now.Before(idleDeadline) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id_hash = ?`, h)
		return nil, errNoSession
	}
	if now.Sub(time.Unix(lastSeen, 0)) >= s.touchInterval() {
		if _, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET last_seen = ? WHERE id_hash = ?`, now.Unix(), h); err != nil {
			return nil, err
		}
		lastSeen = now.Unix()
	}
	p.Username = username.String
	p.OIDCIssuer, p.OIDCSubject = oidcIss.String, oidcSub.String
	p.sessionHash = h
	p.ExpiresAt = time.Unix(expires, 0).UTC()
	p.IdleExpiresAt = time.Unix(lastSeen, 0).Add(s.opts.IdleTimeout).UTC()
	if p.IdleExpiresAt.After(p.ExpiresAt) {
		p.IdleExpiresAt = p.ExpiresAt
	}
	rows, err := s.db.QueryContext(ctx, `SELECT role FROM auth_user_roles WHERE user_id = ? ORDER BY role`, p.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	p.Roles = []Role{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		p.Roles = append(p.Roles, Role(r))
	}
	return &p, rows.Err()
}

func (s *Service) deleteSession(ctx context.Context, p *Principal) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id_hash = ?`, p.sessionHash)
	return err
}

// Authenticate resolves the session of r, if any.
func (s *Service) Authenticate(r *http.Request) (*Principal, error) {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil, errNoSession
	}
	return s.loadSession(r.Context(), c.Value)
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Require returns middleware that admits a request only with a valid
// session, a matching CSRF token on unsafe methods and (if roles are given)
// at least one of roles. With no roles any authenticated user passes. An
// admin satisfies every role ([Principal.HasAny]).
//
// Responses: 401 unauthenticated, 403 csrf / forbidden. Denials are audited.
// So are admin overrides: when a request of an admin was admitted (here or
// by a guard of the handler) only because admin implies the role, and it
// changes something (unsafe method) or downloads a file (an attachment),
// Require records authz.admin_override with the route pattern, the roles
// the operation needs and the answer's status: an admin can act alone, but
// never invisibly.
func (s *Service) Require(roles ...Role) func(http.Handler) http.Handler {
	for _, r := range roles {
		if _, err := ParseRole(string(r)); err != nil {
			panic("auth.Require: " + err.Error())
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := s.Authenticate(r)
			if err != nil {
				if !errors.Is(err, errNoSession) {
					s.log.ErrorContext(r.Context(), "session lookup failed", "err", err)
					httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
					return
				}
				if _, cerr := r.Cookie(s.cookieName()); cerr == nil {
					s.clearCookie(w)
				}
				httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			if !isSafeMethod(r.Method) {
				got := r.Header.Get(CSRFHeader)
				if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(p.CSRFToken)) != 1 {
					s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.csrf", Target: routeTarget(r), Outcome: audit.Denied, Reason: "csrf_token_mismatch"})
					httpx.WriteError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
					return
				}
			}
			if p.IsAdmin() {
				p.ovr = &overrideNote{}
			}
			if len(roles) > 0 && !p.HasAny(roles...) {
				s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.deny", Target: routeTarget(r), Outcome: audit.Denied, Reason: "missing_role"})
				httpx.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			r2 := r.WithContext(WithPrincipal(r.Context(), p))
			if p.ovr == nil {
				next.ServeHTTP(w, r2)
				return
			}
			ow := &overrideWriter{ResponseWriter: w}
			next.ServeHTTP(ow, r2)
			s.recordOverride(r2, p, ow)
		})
	}
}

// recordOverride writes authz.admin_override for a request admitted by
// admin implication that changed something or downloaded a file.
func (s *Service) recordOverride(r *http.Request, p *Principal, ow *overrideWriter) {
	roles := p.overrideRoles()
	if len(roles) == 0 || (isSafeMethod(r.Method) && !ow.attachment) {
		return
	}
	status := ow.status
	if status == 0 {
		status = http.StatusOK
	}
	outcome := audit.Success
	if status >= 400 {
		outcome = audit.Failure
	}
	names := make([]string, len(roles))
	for i, x := range roles {
		names[i] = string(x)
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "authz.admin_override", Target: routeTarget(r), Outcome: outcome,
		Reason: "admin_implies_role", Details: map[string]string{"roles_required": strings.Join(names, ","), "status": strconv.Itoa(status)}})
}

// overrideWriter records the status of an admin request and whether it is a
// file download; it keeps Flush and Unwrap working for streaming handlers.
type overrideWriter struct {
	http.ResponseWriter
	status     int
	attachment bool
}

func (o *overrideWriter) WriteHeader(code int) {
	if o.status == 0 {
		o.status = code
		o.attachment = strings.HasPrefix(o.Header().Get("Content-Disposition"), "attachment")
	}
	o.ResponseWriter.WriteHeader(code)
}

func (o *overrideWriter) Write(b []byte) (int, error) {
	if o.status == 0 {
		o.WriteHeader(http.StatusOK)
	}
	return o.ResponseWriter.Write(b)
}

func (o *overrideWriter) Flush() {
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (o *overrideWriter) Unwrap() http.ResponseWriter { return o.ResponseWriter }

// routeTarget identifies the route by its matched pattern, never the raw
// request path (client-chosen strings must not reach the audit log).
func routeTarget(r *http.Request) audit.Target {
	return audit.RouteTarget(r)
}
