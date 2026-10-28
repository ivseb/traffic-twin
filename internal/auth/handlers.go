package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// maxAuthBody bounds login and setup request bodies.
const maxAuthBody = 8 << 10

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	httpx.WriteError(w, status, code, msg)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

// MeResponse is returned by login and GET /api/v1/auth/me.
type MeResponse struct {
	User             *Principal `json:"user"`
	Roles            []Role     `json:"roles"`
	CSRFToken        string     `json:"csrf_token"`
	ExpiresAt        time.Time  `json:"expires_at"`
	IdleExpiresAt    time.Time  `json:"idle_expires_at"`
	CSRFHeaderName   string     `json:"csrf_header"`
	SessionIdleTTLMs int64      `json:"session_idle_timeout_ms"`
}

func (s *Service) me(p *Principal) MeResponse {
	return MeResponse{
		User: p, Roles: p.Roles, CSRFToken: p.CSRFToken,
		ExpiresAt: p.ExpiresAt, IdleExpiresAt: p.IdleExpiresAt,
		CSRFHeaderName: CSRFHeader, SessionIdleTTLMs: s.opts.IdleTimeout.Milliseconds(),
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginHandler handles POST /api/v1/auth/login {username, password}.
// It always answers 401 invalid_credentials for unknown users, wrong
// passwords, disabled or OIDC-only accounts, with uniform timing.
func (s *Service) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.opts.LocalEnabled {
			writeErr(w, http.StatusNotFound, "local_disabled", "local login is not enabled")
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		var req loginRequest
		if err := httpx.DecodeJSON(w, r, maxAuthBody, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		ctx := r.Context()
		if ok, wait := s.logins.allow(req.Username, s.now()); !ok {
			// Per-account limit (the per-client one is the server's): the
			// attempt is not even checked, so the right password does not
			// help either while the account is limited.
			s.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorAnonymous}, Action: "auth.login", Target: audit.Target{Type: "session"},
				Outcome: audit.Denied, Reason: "account_rate_limited"})
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(wait.Seconds()+0.999))))
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many failed logins for this account; try again later")
			return
		}
		var userID, hash string
		var disabled bool
		err := s.db.QueryRowContext(ctx, `SELECT id, password_hash, disabled FROM auth_users WHERE username = ?`, req.Username).Scan(&userID, &hash, &disabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.log.ErrorContext(ctx, "login lookup failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		known := err == nil
		if len(req.Password) > 4*MaxPasswordLen {
			req.Password = req.Password[:4*MaxPasswordLen] // bound hashing input; cannot match anyway
		}
		ok, verr := s.hasher.verify(ctx, req.Password, hash)
		if verr != nil && !errors.Is(verr, errBadHash) {
			writeErr(w, http.StatusServiceUnavailable, "busy", "try again later")
			return
		}
		if !known || !ok || disabled {
			// The attempted username is recorded only when it exists, so a
			// password typed into the username field never reaches the log.
			actor := audit.Actor{Kind: audit.ActorAnonymous}
			if known {
				actor = audit.Actor{Kind: audit.ActorUser, ID: userID, Name: audit.SafeName(req.Username)}
			}
			reason := "invalid_credentials"
			if known && disabled {
				reason = "user_disabled"
			}
			s.logins.fail(req.Username, s.now())
			s.record(ctx, audit.Event{Actor: actor, Action: "auth.login", Target: audit.Target{Type: "session"}, Outcome: audit.Failure, Reason: reason})
			writeErr(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		p, err := s.createSession(ctx, w, r, userID, "local")
		if err != nil {
			s.log.ErrorContext(ctx, "session create failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.logins.success(req.Username)
		s.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "auth.login", Target: audit.Target{Type: "session"}, Outcome: audit.Success})
		httpx.WriteJSON(w, http.StatusOK, s.me(p))
	})
}

// LogoutHandler handles POST /api/v1/auth/logout. Mount it behind
// Require() (session + CSRF).
func (s *Service) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		if err := s.deleteSession(r.Context(), p); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.clearCookie(w)
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "auth.logout", Target: audit.Target{Type: "session"}, Outcome: audit.Success})
		w.WriteHeader(http.StatusNoContent)
	})
}

// MeHandler handles GET /api/v1/auth/me. Mount it behind Require().
func (s *Service) MeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, s.me(p))
	})
}

// ConfigResponse tells the login page which methods are available.
type ConfigResponse struct {
	Local         bool `json:"local"`
	OIDC          bool `json:"oidc"`
	SetupRequired bool `json:"setup_required"`
}

// ConfigHandler handles GET /api/v1/auth/config (public).
func (s *Service) ConfigHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		pending, err := s.setupPending(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, ConfigResponse{Local: s.opts.LocalEnabled, OIDC: s.oidc != nil, SetupRequired: pending})
	})
}

// SetupTokenTTL bounds the validity of a printed setup token.
const SetupTokenTTL = 24 * time.Hour

func (s *Service) setupPending(ctx context.Context) (bool, error) {
	if !s.opts.LocalEnabled {
		return false, nil
	}
	n, err := s.CountUsers(ctx)
	return n == 0, err
}

// EnsureSetupToken returns a fresh one-time setup token when no user exists
// yet (local login enabled), replacing any earlier token, or "" otherwise.
// The caller prints it once to the operator console; it is never logged.
func (s *Service) EnsureSetupToken(ctx context.Context) (string, error) {
	s.setup.Lock()
	defer s.setup.Unlock()
	pending, err := s.setupPending(ctx)
	if err != nil || !pending {
		return "", err
	}
	tok := "tts_" + randomToken()
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_setup (id, token_hash, expires_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash, expires_at = excluded.expires_at`,
		hashToken(tok), s.now().Add(SetupTokenTTL).Unix())
	if err != nil {
		return "", err
	}
	s.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"}, Action: "auth.setup_token_issued", Target: audit.Target{Type: "setup"}, Outcome: audit.Success})
	return tok, nil
}

type setupRequest struct {
	SetupToken string `json:"setup_token"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

// SetupHandler handles POST /api/v1/setup {setup_token, username, password}:
// it creates the first admin, consumes the token and logs the admin in.
func (s *Service) SetupHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		var req setupRequest
		if err := httpx.DecodeJSON(w, r, maxAuthBody, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		ctx := r.Context()
		s.setup.Lock()
		var u User
		err := s.db.InTx(ctx, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM auth_users`).Scan(&n); err != nil {
				return err
			}
			var hash string
			var exp int64
			err := tx.QueryRowContext(ctx, `SELECT token_hash, expires_at FROM auth_setup WHERE id = 1`).Scan(&hash, &exp)
			if n > 0 || errors.Is(err, sql.ErrNoRows) || !s.opts.LocalEnabled {
				return errSetupDone
			}
			if err != nil {
				return err
			}
			if subtle.ConstantTimeCompare([]byte(hash), []byte(hashToken(req.SetupToken))) != 1 || !s.now().Before(time.Unix(exp, 0)) {
				return errSetupToken
			}
			u, err = s.createLocalUserTx(ctx, tx, req.Username, req.Password, []Role{RoleAdmin})
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `DELETE FROM auth_setup WHERE id = 1`)
			return err
		})
		s.setup.Unlock()
		switch {
		case errors.Is(err, errSetupDone):
			writeErr(w, http.StatusConflict, "setup_done", "setup already completed")
			return
		case errors.Is(err, errSetupToken):
			s.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorAnonymous}, Action: "auth.setup", Target: audit.Target{Type: "setup"}, Outcome: audit.Failure, Reason: "invalid_token"})
			writeErr(w, http.StatusUnauthorized, "invalid_setup_token", "invalid or expired setup token")
			return
		case errors.Is(err, ErrInvalidUsername), errors.Is(err, ErrWeakPassword):
			writeErr(w, http.StatusBadRequest, "invalid_input", err.Error())
			return
		case err != nil:
			s.log.ErrorContext(ctx, "setup failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorUser, ID: u.ID, Name: audit.SafeName(u.Username)}, Action: "auth.setup", Target: audit.Target{Type: "user", ID: u.ID}, Outcome: audit.Success, Details: map[string]string{"role": string(RoleAdmin)}})
		p, err := s.createSession(ctx, w, r, u.ID, "local")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, s.me(p))
	})
}

var (
	errSetupDone  = errors.New("setup done")
	errSetupToken = errors.New("bad setup token")
)
