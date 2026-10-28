package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/audit"
)

// Approval step-up (keyguard.md 3.2 step 4, admin-api "Approval step-up",
// red team round 3 RT3-KG-3, RT3-OIDC-1/2).
//
// When keyguard verifies approvals with OIDC, each approval (policy
// version, pack publish, quarantine dismiss) needs an ID token minted for
// that one change: the approver authenticates again at the identity
// provider through a dedicated client (the approval audience), with
// nonce = approvebind.Nonce(purpose, ...) computed by tt-core from the
// change. The callback verifies the token (iss, aud, nonce, and sub equal
// to the approver's own OIDC subject) and keeps it in memory, for at most
// StepUpTTL, for the next approval request of the same user, purpose and
// reference. It is never written to the database.

// StepUpTTL is how long a step-up token waits for its approval request
// (keyguard accepts tokens up to 10 minutes old).
const StepUpTTL = 10 * time.Minute

const (
	stepUpStartPath    = "/api/v1/auth/oidc/stepup"
	stepUpCallbackPath = "/api/v1/auth/oidc/stepup/callback"
	stepUpCookieTLS    = "__Host-tt_stepup"
	stepUpCookiePlain  = "tt_stepup"
	maxStepUps         = 10000
	maxStepUpRef       = 200
)

// Errors of ApprovalToken.
var (
	// ErrStepUpRequired: no step-up token for this change; the approver
	// must go through GET /api/v1/auth/oidc/stepup first.
	ErrStepUpRequired = errors.New("auth: approval step-up required")
	// ErrStepUpDisabled: approvals need OIDC tokens but tt-core has no
	// approval client configured (auth.oidc.approval_client_id).
	ErrStepUpDisabled = errors.New("auth: approval step-up not configured")
	// ErrLocalApprover: local accounts have no identity at the provider,
	// so they cannot present (or obtain) approval ID tokens.
	ErrLocalApprover = errors.New("auth: local accounts cannot present OIDC approval tokens")
	// ErrApprovalToken: the presented ID token does not verify, is not
	// bound to this change or belongs to someone else.
	ErrApprovalToken = errors.New("auth: approval ID token invalid")
)

// StepUpBinder returns the approval nonce of (purpose, ref) for p, or an
// error when the referenced change does not exist or p may not approve it.
// tt-core wires one that dispatches on purpose (policies, packs,
// quarantine items).
type StepUpBinder func(ctx context.Context, p *Principal, purpose, ref string) (nonce string, err error)

// ErrStepUpNotFound may be returned by a StepUpBinder for an unknown ref.
var ErrStepUpNotFound = errors.New("auth: step-up reference not found")

type stepUpState struct {
	nonce, verifier, userID, purpose, ref, returnTo string
	exp                                             time.Time
}

type stepUpToken struct {
	raw, nonce string
	exp        time.Time
}

type stepUps struct {
	mu     sync.Mutex
	binder StepUpBinder
	states map[string]stepUpState // hashToken(state)
	tokens map[string]stepUpToken // user \0 purpose \0 ref
}

func newStepUps() *stepUps {
	return &stepUps{states: map[string]stepUpState{}, tokens: map[string]stepUpToken{}}
}

func stepUpKey(user, purpose, ref string) string { return user + "\x00" + purpose + "\x00" + ref }

// prune drops expired entries; caller holds mu.
func (u *stepUps) prune(now time.Time) {
	for k, v := range u.states {
		if !now.Before(v.exp) {
			delete(u.states, k)
		}
	}
	for k, v := range u.tokens {
		if !now.Before(v.exp) {
			delete(u.tokens, k)
		}
	}
}

// SetStepUpBinder installs the function that computes approval nonces.
func (s *Service) SetStepUpBinder(b StepUpBinder) {
	s.stepup.mu.Lock()
	s.stepup.binder = b
	s.stepup.mu.Unlock()
}

// StepUpEnabled reports whether tt-core can run approval step-ups (OIDC
// login with an approval client).
func (s *Service) StepUpEnabled() bool {
	return s.oidc != nil && s.oidc.opts.ApprovalClientID != ""
}

// CheckApprovalAudience checks that keyguard's OIDC settings (as reported
// by its status) match tt-core's approval client: same issuer, audience
// equal to the approval client id and different from the login client id.
func (s *Service) CheckApprovalAudience(issuer, audience string) error {
	if !s.StepUpEnabled() {
		return ErrStepUpDisabled
	}
	o := s.oidc.opts
	switch {
	case strings.TrimSuffix(issuer, "/") != strings.TrimSuffix(o.IssuerURL, "/"):
		return errors.New("auth: keyguard verifies approvals for another OIDC issuer")
	case audience == o.ClientID:
		return errors.New("auth: keyguard's approval audience is the login client id: login tokens would approve changes")
	case audience != o.ApprovalClientID:
		return errors.New("auth: keyguard's approval audience differs from auth.oidc.approval_client_id")
	}
	return nil
}

func (s *Service) stepUpCookieName() string {
	if s.opts.TLS {
		return stepUpCookieTLS
	}
	return stepUpCookiePlain
}

func (c *oidcClient) approvalConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.opts.ApprovalClientID,
		ClientSecret: c.opts.ApprovalClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  c.opts.ApprovalRedirectURL,
		Scopes:       c.opts.Scopes,
	}
}

// stepUpReturn redirects to returnTo with stepup=ok or stepup_error=code
// (the UI resumes the pending approval from there).
func stepUpReturn(w http.ResponseWriter, r *http.Request, returnTo, code string) {
	q := "stepup=ok"
	if code != "" {
		q = "stepup_error=" + code
	}
	sep := "?"
	if strings.Contains(returnTo, "?") {
		sep = "&"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, returnTo+sep+q, http.StatusFound)
}

// StepUpStartHandler handles GET /api/v1/auth/oidc/stepup?purpose=&ref=&return_to=
// for a signed-in OIDC user: it computes the approval nonce of the change,
// stores state, nonce and PKCE verifier in memory, binds the state to the
// browser with a short-lived cookie and redirects to the provider with the
// approval client, prompt=login and max_age=600. Errors redirect to
// return_to?stepup_error=<code>.
func (s *Service) StepUpStartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		ctx := r.Context()
		q := r.URL.Query()
		returnTo := safeReturnTo(q.Get("return_to"))
		p, ok := PrincipalFrom(ctx)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		purpose, ref := q.Get("purpose"), q.Get("ref")
		ev := audit.Event{Actor: p.AuditActor(), Action: "auth.oidc_stepup", Target: audit.Target{Type: "approval", ID: audit.SafeValue(purpose)}, Outcome: audit.Failure}
		fail := func(code string) {
			ev.Reason = code
			s.record(ctx, ev)
			stepUpReturn(w, r, returnTo, code)
		}
		if !s.StepUpEnabled() {
			fail("stepup_disabled")
			return
		}
		if p.OIDCSubject == "" {
			fail("oidc_required")
			return
		}
		if !approvebind.ValidPurpose(purpose) || ref == "" || len(ref) > maxStepUpRef {
			fail("invalid_request")
			return
		}
		s.stepup.mu.Lock()
		binder := s.stepup.binder
		s.stepup.mu.Unlock()
		if binder == nil {
			fail("stepup_disabled")
			return
		}
		nonce, err := binder(ctx, p, purpose, ref)
		if err != nil {
			if errors.Is(err, ErrStepUpNotFound) {
				fail("not_found")
				return
			}
			s.log.WarnContext(ctx, "oidc step-up binding failed", "err", err)
			fail("not_approvable")
			return
		}
		prov, _, err := s.oidc.ensure(ctx, s.now())
		if err != nil {
			s.log.WarnContext(ctx, "oidc provider unavailable", "err", err)
			fail("oidc_unavailable")
			return
		}
		state, verifier := randomToken(), oauth2.GenerateVerifier()
		now := s.now()
		s.stepup.mu.Lock()
		s.stepup.prune(now)
		full := len(s.stepup.states) >= maxStepUps
		if !full {
			s.stepup.states[hashToken(state)] = stepUpState{nonce: nonce, verifier: verifier, userID: p.UserID, purpose: purpose, ref: ref,
				returnTo: returnTo, exp: now.Add(oidcStateTTL)}
		}
		s.stepup.mu.Unlock()
		if full {
			fail("busy")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: s.stepUpCookieName(), Value: state, Path: "/", MaxAge: int(oidcStateTTL.Seconds()),
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		url := s.oidc.approvalConfig(prov).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier),
			oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "600"))
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, url, http.StatusFound)
	})
}

// StepUpCallbackHandler handles GET /api/v1/auth/oidc/stepup/callback: it
// exchanges the code with the approval client, verifies the ID token (iss,
// aud = approval client, nonce, auth_time, and iss/sub equal to the
// approver's OIDC identity) and keeps it in memory for the approval
// request. It never creates a session.
func (s *Service) StepUpCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		ctx := r.Context()
		http.SetCookie(w, &http.Cookie{Name: s.stepUpCookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		ev := audit.Event{Actor: audit.Actor{Kind: audit.ActorAnonymous}, Action: "auth.oidc_stepup", Target: audit.Target{Type: "approval"}, Outcome: audit.Failure}
		returnTo := "/"
		fail := func(code string) {
			ev.Reason = code
			s.record(ctx, ev)
			stepUpReturn(w, r, returnTo, code)
		}
		if !s.StepUpEnabled() {
			fail("stepup_disabled")
			return
		}
		q := r.URL.Query()
		if q.Get("error") != "" {
			fail("idp_error")
			return
		}
		state, code := q.Get("state"), q.Get("code")
		c, err := r.Cookie(s.stepUpCookieName())
		if state == "" || code == "" || err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
			fail("state_mismatch")
			return
		}
		now := s.now()
		s.stepup.mu.Lock()
		st, ok := s.stepup.states[hashToken(state)]
		delete(s.stepup.states, hashToken(state))
		s.stepup.mu.Unlock()
		if !ok || !now.Before(st.exp) {
			fail("state_invalid")
			return
		}
		returnTo = st.returnTo
		ev.Target.ID = audit.SafeValue(st.purpose)
		var iss, sub sql.NullString
		var disabled bool
		var name string
		if err := s.db.QueryRowContext(ctx, `SELECT oidc_issuer, oidc_subject, disabled, display_name FROM auth_users WHERE id = ?`, st.userID).
			Scan(&iss, &sub, &disabled, &name); err != nil || disabled || !sub.Valid {
			fail("user_invalid")
			return
		}
		ev.Actor = audit.Actor{Kind: audit.ActorUser, ID: st.userID, Name: audit.SafeName(name)}
		prov, _, err := s.oidc.ensure(ctx, now)
		if err != nil {
			fail("idp_unavailable")
			return
		}
		tok, err := s.oidc.approvalConfig(prov).Exchange(s.oidc.ctx(ctx), code, oauth2.VerifierOption(st.verifier))
		if err != nil {
			s.log.WarnContext(ctx, "oidc step-up code exchange failed")
			fail("exchange_failed")
			return
		}
		raw, ok := tok.Extra("id_token").(string)
		if !ok || raw == "" {
			fail("no_id_token")
			return
		}
		if code := s.checkApprovalToken(ctx, raw, st.nonce, iss.String, sub.String); code != "" {
			fail(code)
			return
		}
		s.stepup.mu.Lock()
		s.stepup.prune(now)
		if len(s.stepup.tokens) < maxStepUps {
			s.stepup.tokens[stepUpKey(st.userID, st.purpose, st.ref)] = stepUpToken{raw: raw, nonce: st.nonce, exp: now.Add(StepUpTTL)}
		}
		s.stepup.mu.Unlock()
		ev.Outcome = audit.Success
		ev.Details = map[string]string{"ref": audit.SafeValue(st.ref)}
		s.record(ctx, ev)
		stepUpReturn(w, r, returnTo, "")
	})
}

// checkApprovalToken verifies a step-up ID token and returns "" or an
// error code (never token content).
func (s *Service) checkApprovalToken(ctx context.Context, raw, nonce, issuer, subject string) string {
	_, _, err := s.oidc.ensure(ctx, s.now())
	if err != nil {
		return "idp_unavailable"
	}
	s.oidc.mu.Lock()
	v := s.oidc.approval
	s.oidc.mu.Unlock()
	if v == nil {
		return "stepup_disabled"
	}
	idt, err := v.Verify(s.oidc.ctx(ctx), raw)
	if err != nil {
		return "id_token_invalid"
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return "nonce_mismatch"
	}
	if idt.Issuer != issuer || idt.Subject != subject {
		return "subject_mismatch"
	}
	var claims struct {
		AuthTime *float64 `json:"auth_time"`
	}
	if err := idt.Claims(&claims); err != nil || claims.AuthTime == nil {
		return "stale_authentication"
	}
	at := time.Unix(int64(*claims.AuthTime), 0)
	if now := s.now(); now.Sub(at) > StepUpTTL || at.After(now.Add(time.Minute)) {
		return "stale_authentication"
	}
	return ""
}

// ApprovalTokenError maps an ApprovalToken error to an HTTP status, a
// stable code and a fixed message (admin-api "Approval step-up").
// explicit reports whether the caller supplied the token itself.
func ApprovalTokenError(err error, explicit bool) (int, string, string) {
	switch {
	case errors.Is(err, ErrStepUpRequired):
		return http.StatusForbidden, "stepup_required", "re-authenticate at the identity provider for this approval (step-up)"
	case errors.Is(err, ErrLocalApprover) && explicit:
		return http.StatusForbidden, "id_token_not_allowed", "local accounts cannot attach OIDC ID tokens"
	case errors.Is(err, ErrLocalApprover):
		return http.StatusForbidden, "oidc_required", "keyguard verifies approvals with OIDC: sign in with the identity provider to approve"
	case errors.Is(err, ErrApprovalToken):
		return http.StatusForbidden, "id_token_invalid", "the ID token does not verify, is not bound to this change or is not yours"
	case errors.Is(err, ErrStepUpDisabled):
		return http.StatusServiceUnavailable, "stepup_disabled", "keyguard verifies approvals with OIDC but tt-core has no approval client (auth.oidc.approval_client_id)"
	}
	return http.StatusServiceUnavailable, "oidc_unavailable", "the identity provider cannot be reached"
}

// ApprovalToken returns a verified approval ID token of p for the change
// (purpose, ref) whose binding is nonce: explicit, when the caller supplied
// one in the request (verified here), else the token of p's last step-up
// for that change (consumed). Local accounts get ErrLocalApprover, also
// when they supply a token.
func (s *Service) ApprovalToken(ctx context.Context, p *Principal, purpose, ref, nonce, explicit string) (string, error) {
	if p == nil || p.OIDCSubject == "" {
		return "", ErrLocalApprover
	}
	if !s.StepUpEnabled() {
		return "", ErrStepUpDisabled
	}
	if explicit != "" {
		if code := s.checkApprovalToken(ctx, explicit, nonce, p.OIDCIssuer, p.OIDCSubject); code != "" {
			if code == "idp_unavailable" {
				return "", errors.New("auth: identity provider unavailable")
			}
			return "", ErrApprovalToken
		}
		return explicit, nil
	}
	key := stepUpKey(p.UserID, purpose, ref)
	now := s.now()
	s.stepup.mu.Lock()
	t, ok := s.stepup.tokens[key]
	delete(s.stepup.tokens, key)
	s.stepup.mu.Unlock()
	if !ok || !now.Before(t.exp) || subtle.ConstantTimeCompare([]byte(t.nonce), []byte(nonce)) != 1 {
		// No step-up, or one for an earlier state of the change (the
		// draft was recompiled with other groups meanwhile).
		return "", ErrStepUpRequired
	}
	return t.raw, nil
}
