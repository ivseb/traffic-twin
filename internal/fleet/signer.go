package fleet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// Signer is the part of tt keyguard that Fleet needs (docs/spec/keyguard.md
// 3.2, 3.3, 6; api/keyguard-api.v1.openapi.yaml). tt-core never holds a
// policy signing key: every signature comes from keyguard, which re-checks
// the opening/closing classification and the approvals on its own.
//
// The keyguard client (internal/keyguard) satisfies this interface through
// a thin adapter wired in cmd/tt.
type Signer interface {
	// SignPolicy asks keyguard to sign a compiled body
	// (POST /keyguard/v1/policy/sign). A refusal is returned as
	// *SignRefusedError.
	SignPolicy(ctx context.Context, req SignRequest) (Signature, error)
	// RenewPolicy re-signs a body that differs from the last signed body of
	// the same policy_id only in version, issued_seq, created_at and
	// not_after (POST /keyguard/v1/policy/renew).
	RenewPolicy(ctx context.Context, body []byte) (Signature, error)
	// PolicySigningKeys returns the policy signing public keys
	// (GET /keyguard/v1/public-keys, "policy" list). A key may carry an
	// endorsement by an older key, used to announce a rotation to sources
	// (add_signing_keys in the heartbeat response).
	PolicySigningKeys(ctx context.Context) ([]SigningKey, error)
	// Status returns keyguard's approval settings (GET /keyguard/v1/status):
	// they are read from keyguard, never configured in tt-core, so a
	// compromised tt-core cannot lower them (policy.md 5, v1.2.1).
	Status(ctx context.Context) (SignerStatus, error)
}

// SignerStatus is the approval configuration enforced by keyguard.
type SignerStatus struct {
	// OpeningApprovals is the number of distinct approvals an opening
	// change needs (TT_KEYGUARD_OPENING_APPROVALS: 1 or 2, default 2).
	OpeningApprovals int
	// AdminOverride reports whether a single approval by an admin with a
	// reason is accepted (TT_KEYGUARD_ADMIN_OVERRIDE, default true).
	AdminOverride bool
	// ApprovalsUnverified is true when keyguard has no OIDC issuer and
	// trusts the identities declared by tt-core.
	ApprovalsUnverified bool
	// OIDCIssuer and OIDCAudience are keyguard's approval issuer and
	// dedicated approval audience (set when approvals are verified):
	// tt-core's step-up must obtain tokens for exactly these.
	OIDCIssuer, OIDCAudience string
	// PolicyKid is the kid keyguard currently signs policies with: tt-core
	// refuses to revoke it (RT3-KEY-2).
	PolicyKid string
	// ObserveAuto: keyguard signs observe-safe changes without approvals
	// (TT_KEYGUARD_OBSERVE_AUTO, default true; policy.md 7).
	ObserveAuto bool
	// HMACKids are the HMAC key ids keyguard holds (the starter policy
	// takes the first one when none is given).
	HMACKids []string
}

// ApprovalTokens obtains approval ID tokens bound to a change (the OIDC
// step-up of internal/auth). Wired by tt-core when OIDC login is enabled.
type ApprovalTokens interface {
	// ApprovalToken returns a verified ID token of p for (purpose, ref)
	// bound to nonce: explicit when given, else p's pending step-up.
	ApprovalToken(ctx context.Context, p *auth.Principal, purpose, ref, nonce, explicit string) (string, error)
	// CheckApprovalAudience checks keyguard's issuer and audience against
	// tt-core's approval client.
	CheckApprovalAudience(issuer, audience string) error
}

// Approval modes returned by keyguard (keyguard.md 3.2).
const (
	ApprovalStandard = "standard"
	ApprovalSingle   = "single"
	ApprovalAdmin    = "admin"
	// ApprovalObserve: an observe-safe change signed without approvals
	// (policy.md 7, spec v1.6).
	ApprovalObserve = "observe"
)

// SignRequest is the input of Signer.SignPolicy.
type SignRequest struct {
	Body      []byte // exact compiled body bytes (tt.policy.body/v1)
	Proposer  string // user id of the author of the change
	Approvals []SignApproval
}

// SignApproval is one recorded approval forwarded to keyguard.
type SignApproval struct {
	User    string   // user id
	Roles   []string // roles held when approving
	At      time.Time
	IDToken string // fresh OIDC ID token, when the approver supplied one
	// Reason is the mandatory justification of an admin single approval
	// (policy.md 5, v1.2.1); empty otherwise.
	Reason string
}

// Signature is keyguard's answer: an Ed25519 signature over
// policy.SignedMessage(body).
type Signature struct {
	Alg string // always "Ed25519"
	Kid string
	Sig []byte
	// Classification is keyguard's own verdict (closing | opening); empty
	// for renewals.
	Classification string
	// ApprovalsVerified is true when keyguard verified the approvers' OIDC
	// ID tokens (keyguard.md 3.2 point 4).
	ApprovalsVerified bool
	// ApprovalMode is standard | single | admin (keyguard.md 3.2 point 3);
	// empty for renewals.
	ApprovalMode string
	// OpensValues is keyguard's observe-safe verdict (nil when keyguard does
	// not report it).
	OpensValues *bool
}

// Alerter delivers alert events to the configured webhooks. Optional.
// Details are identifiers and counts only.
type Alerter interface {
	Alert(ctx context.Context, kind string, details map[string]string)
}

// SigningKey is a policy signing public key.
type SigningKey struct {
	Kid       string
	PublicKey ed25519.PublicKey
	// EndorsedBy and Endorsement, when set, are the kid of an older key and
	// its signature over "tt-fleet-key/v1" || 0x00 || kid || 0x00 || key
	// (policy.Endorse).
	EndorsedBy  string
	Endorsement string
}

// SignRefusedError is returned by a Signer when keyguard refused to sign
// (HTTP 403 or 422 from keyguard). Code is keyguard's error code; it is
// shown to approvers, never a payload value.
type SignRefusedError struct {
	Code    string
	Message string
}

func (e *SignRefusedError) Error() string {
	return fmt.Sprintf("keyguard refused to sign: %s", e.Code)
}

// ErrSignerUnavailable may be wrapped by Signer implementations when
// keyguard cannot be reached.
var ErrSignerUnavailable = errors.New("fleet: keyguard unavailable")
