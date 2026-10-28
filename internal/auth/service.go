// Package auth implements authentication, sessions, CSRF protection and
// role-based access control for the tt-core admin listener (threat model
// M7, M17).
//
//   - Local accounts: argon2id password hashes; the first admin is created
//     through a one-time setup token printed at start-up.
//   - OIDC: authorization code flow with PKCE, state and nonce, ID token
//     verification against the issuer's JWKS (cached by go-oidc).
//   - Sessions: opaque random ids stored server-side (SQLite, only their
//     SHA-256), HttpOnly + Secure + SameSite=Strict cookie, idle and absolute
//     timeouts, a fresh id at every login.
//   - CSRF: synchronizer token bound to the session, required in the
//     X-CSRF-Token header for every unsafe method.
//   - RBAC: roles (see Role) checked by [Service.Require]; admin implies
//     every role, and every admin override is audited (authz.admin_override).
//   - Separation of duties between non-admin approvers: [CheckApproval].
package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "auth", Migrations: migrations})
}

var migrations = []store.Migration{
	{Version: 1, Name: "users sessions setup oidc", SQL: `
CREATE TABLE auth_users (
	id            TEXT PRIMARY KEY,
	username      TEXT UNIQUE,
	oidc_issuer   TEXT,
	oidc_subject  TEXT,
	display_name  TEXT NOT NULL,
	password_hash TEXT NOT NULL DEFAULT '',
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL,
	UNIQUE (oidc_issuer, oidc_subject),
	CHECK ((username IS NOT NULL) OR (oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL))
) STRICT;
CREATE TABLE auth_user_roles (
	user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
	role    TEXT NOT NULL,
	PRIMARY KEY (user_id, role)
) STRICT;
CREATE TABLE auth_sessions (
	id_hash     TEXT PRIMARY KEY,
	user_id     TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
	csrf_token  TEXT NOT NULL,
	method      TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX auth_sessions_expires ON auth_sessions(expires_at);
CREATE TABLE auth_setup (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	token_hash TEXT NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE TABLE auth_oidc_states (
	state_hash TEXT PRIMARY KEY,
	nonce      TEXT NOT NULL,
	verifier   TEXT NOT NULL,
	return_to  TEXT NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
`},
}

// Options configure a Service.
type Options struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	// TLS reports whether the admin listener serves HTTPS; the session
	// cookie then uses the __Host- prefix. Cookies are always Secure.
	TLS          bool
	LocalEnabled bool
	// OIDC is nil when OIDC login is disabled.
	OIDC *OIDCOptions
	// PasswordParams defaults to DefaultPasswordParams.
	PasswordParams *PasswordParams
	// HashConcurrency bounds parallel argon2id computations (default 4).
	HashConcurrency int
	// AccountLimit bounds failed local logins per username (default
	// DefaultAccountLimit), on top of the server's per-client limit.
	AccountLimit AccountLimit
	Logger       *slog.Logger
	Now          func() time.Time
}

// Service is the authentication service.
type Service struct {
	db     *store.DB
	audit  *audit.Log
	opts   Options
	log    *slog.Logger
	now    func() time.Time
	hasher *hasher
	oidc   *oidcClient
	setup  sync.Mutex
	logins *accountLimiter
	stepup *stepUps
}

// New builds a Service. db must have been opened with store.Open (which
// applies this package's migrations).
func New(db *store.DB, auditLog *audit.Log, opts Options) (*Service, error) {
	if opts.IdleTimeout <= 0 || opts.AbsoluteTimeout < opts.IdleTimeout {
		return nil, errors.New("auth: invalid session timeouts")
	}
	if !opts.LocalEnabled && opts.OIDC == nil {
		return nil, errors.New("auth: no login method enabled")
	}
	params := DefaultPasswordParams
	if opts.PasswordParams != nil {
		params = *opts.PasswordParams
	}
	if opts.HashConcurrency <= 0 {
		opts.HashConcurrency = 4
	}
	h, err := newHasher(params, opts.HashConcurrency)
	if err != nil {
		return nil, err
	}
	s := &Service{db: db, audit: auditLog, opts: opts, log: opts.Logger, now: opts.Now, hasher: h, logins: newAccountLimiter(opts.AccountLimit), stepup: newStepUps()}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if opts.OIDC != nil {
		c, err := newOIDCClient(*opts.OIDC)
		if err != nil {
			return nil, err
		}
		s.oidc = c
	}
	return s, nil
}

// User is an account.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username,omitempty"` // local accounts only
	DisplayName string    `json:"display_name"`
	Method      string    `json:"auth_method"` // "local" or "oidc"
	Roles       []Role    `json:"roles"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
}

var reUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// Errors returned by user management.
var (
	ErrInvalidUsername = errors.New("username must be 3-64 characters of [a-z0-9._-], starting with a letter or digit")
	ErrUserExists      = errors.New("user already exists")
	ErrUserNotFound    = errors.New("user not found")
)

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func (s *Service) ts() string { return s.now().UTC().Format(time.RFC3339Nano) }

// CreateLocalUser creates a local account. Callers (the admin API) are
// responsible for authorization and for recording an audit event.
func (s *Service) CreateLocalUser(ctx context.Context, username, password string, roles []Role) (User, error) {
	var u User
	err := s.db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		u, err = s.createLocalUserTx(ctx, tx, username, password, roles)
		return err
	})
	return u, err
}

func (s *Service) createLocalUserTx(ctx context.Context, tx *sql.Tx, username, password string, roles []Role) (User, error) {
	if !reUsername.MatchString(username) {
		return User{}, ErrInvalidUsername
	}
	if err := checkPasswordPolicy(password); err != nil {
		return User{}, err
	}
	roles, err := normalizeRoles(roles)
	if err != nil {
		return User{}, err
	}
	hash, err := s.hasher.hash(ctx, password)
	if err != nil {
		return User{}, err
	}
	u := User{ID: newUserID(), Username: username, DisplayName: username, Method: "local", Roles: roles, CreatedAt: s.now().UTC()}
	now := s.ts()
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_users (id, username, display_name, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, username, username, hash, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrUserExists
		}
		return User{}, err
	}
	if err := setRolesTx(ctx, tx, u.ID, roles); err != nil {
		return User{}, err
	}
	return u, nil
}

func setRolesTx(ctx context.Context, tx *sql.Tx, userID string, roles []Role) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_user_roles WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, r := range roles {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_user_roles (user_id, role) VALUES (?, ?)`, userID, string(r)); err != nil {
			return err
		}
	}
	return nil
}

// SetRoles replaces the roles of a user. Roles are read at every request,
// so the change applies to live sessions immediately.
func (s *Service) SetRoles(ctx context.Context, userID string, roles []Role) error {
	roles, err := normalizeRoles(roles)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(tx *sql.Tx) error {
		if err := userExistsTx(ctx, tx, userID); err != nil {
			return err
		}
		if err := setRolesTx(ctx, tx, userID, roles); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE auth_users SET updated_at = ? WHERE id = ?`, s.ts(), userID)
		return err
	})
}

// SetDisabled enables or disables a user; disabling revokes all sessions.
func (s *Service) SetDisabled(ctx context.Context, userID string, disabled bool) error {
	return s.db.InTx(ctx, func(tx *sql.Tx) error {
		if err := userExistsTx(ctx, tx, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET disabled = ?, updated_at = ? WHERE id = ?`, boolInt(disabled), s.ts(), userID); err != nil {
			return err
		}
		if disabled {
			_, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ?`, userID)
			return err
		}
		return nil
	})
}

// SetPassword changes a local user's password and revokes their sessions.
func (s *Service) SetPassword(ctx context.Context, userID, password string) error {
	if err := checkPasswordPolicy(password); err != nil {
		return err
	}
	hash, err := s.hasher.hash(ctx, password)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE auth_users SET password_hash = ?, updated_at = ? WHERE id = ? AND username IS NOT NULL`, hash, s.ts(), userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrUserNotFound
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ?`, userID)
		return err
	})
}

// RevokeSessions deletes every session of a user.
func (s *Service) RevokeSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ?`, userID)
	return err
}

func userExistsTx(ctx context.Context, tx *sql.Tx, userID string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM auth_users WHERE id = ?`, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetUser loads one user with roles.
func (s *Service) GetUser(ctx context.Context, userID string) (User, error) {
	users, err := s.queryUsers(ctx, `WHERE u.id = ?`, userID)
	if err != nil {
		return User{}, err
	}
	if len(users) == 0 {
		return User{}, ErrUserNotFound
	}
	return users[0], nil
}

// ListUsers returns all users ordered by creation time.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	return s.queryUsers(ctx, ``)
}

func (s *Service) queryUsers(ctx context.Context, where string, args ...any) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, COALESCE(u.username, ''), u.display_name, u.oidc_issuer IS NOT NULL, u.disabled, u.created_at,
		COALESCE((SELECT group_concat(role, ',') FROM (SELECT role FROM auth_user_roles r WHERE r.user_id = u.id ORDER BY role)), '')
		FROM auth_users u `+where+` ORDER BY u.created_at, u.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var oidcUser, disabled bool
		var created, roles string
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &oidcUser, &disabled, &created, &roles); err != nil {
			return nil, err
		}
		u.Method = "local"
		if oidcUser {
			u.Method = "oidc"
		}
		u.Disabled = disabled
		u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		u.Roles = splitRoles(roles)
		out = append(out, u)
	}
	return out, rows.Err()
}

func splitRoles(s string) []Role {
	out := []Role{}
	for _, r := range strings.Split(s, ",") {
		if r != "" {
			out = append(out, Role(r))
		}
	}
	return out
}

// CountUsers returns the number of accounts.
func (s *Service) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM auth_users`).Scan(&n)
	return n, err
}

// record writes an audit event; failures are logged (never with values).
func (s *Service) record(ctx context.Context, e audit.Event) {
	if s.audit == nil {
		return
	}
	if e.RequestID == "" {
		e.RequestID = httpx.RequestID(ctx)
	}
	if _, err := s.audit.Record(ctx, e); err != nil {
		s.log.ErrorContext(ctx, "audit record failed", "action", e.Action, "err", err)
	}
}

// Cleanup removes expired sessions, OIDC states and setup tokens.
func (s *Service) Cleanup(ctx context.Context) error {
	now := s.now().Unix()
	idleCut := s.now().Add(-s.opts.IdleTimeout).Unix()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM auth_sessions WHERE expires_at <= ? OR last_seen <= ?`, []any{now, idleCut}},
		{`DELETE FROM auth_oidc_states WHERE expires_at <= ?`, []any{now}},
		{`DELETE FROM auth_setup WHERE expires_at <= ?`, []any{now}},
	} {
		if _, err := s.db.ExecContext(ctx, q.sql, q.args...); err != nil {
			return fmt.Errorf("auth: cleanup: %w", err)
		}
	}
	return nil
}

func newUserID() string { return httpx.NewID("usr_") }

// RunJanitor calls Cleanup every interval until ctx is done.
func (s *Service) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Cleanup(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("auth cleanup failed", "err", err)
			}
		}
	}
}
