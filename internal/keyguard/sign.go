package keyguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Roles keyguard knows (the names of tt-core's roles).
const (
	RolePolicyApprover = "policy-approver"
	RoleAdmin          = "admin"
	RolePublisher      = "publisher"
)

// Approval modes (policy.md 5, keyguard.md 3.2).
const (
	ModeStandard = "standard"
	ModeSingle   = "single"
	ModeAdmin    = "admin"
	// ModeObserve: an observe-safe change signed without approvals
	// (policy.md 7, spec v1.6).
	ModeObserve = "observe"
)

// MaxReasonBytes bounds an approval reason.
const MaxReasonBytes = 1000

// Approval is one approval forwarded by tt-core.
type Approval struct {
	User    string    `json:"user"`
	Roles   []string  `json:"roles"`
	At      time.Time `json:"at"`
	IDToken string    `json:"id_token,omitempty"`
	// Reason is mandatory for an admin approval (policy.md 5). It is free
	// text without real values, kept in keyguard's database.
	Reason string `json:"reason,omitempty"`
}

// SignResult is the answer of SignPolicy and RenewPolicy.
type SignResult struct {
	Alg            string `json:"alg"`
	Kid            string `json:"kid"`
	Sig            string `json:"sig"`
	Classification string `json:"classification,omitempty"`
	ApprovalMode   string `json:"approval_mode,omitempty"`
	// OpensValues is keyguard's own observe-safe verdict (policy.md 7):
	// false when the change lets no value out beyond the bodies signed.
	OpensValues *bool `json:"opens_values,omitempty"`
}

var reUser = regexp.MustCompile(`^[A-Za-z0-9_.:/@+=,-]{1,128}$`)

// decodeSigned decodes a body keyguard already accepted.
func decodeSigned(body []byte) (*policy.Policy, error) {
	return policy.DecodeBody(body)
}

// acceptBody validates a body submitted for signing: schema, every rule of
// policy.md 1.4, canonical bytes (keyguard signs exactly what it parsed),
// times and HMAC kids.
func (s *Service) acceptBody(body []byte) (*policy.Policy, *Error) {
	p, err := policy.DecodeBody(body)
	if err != nil {
		return nil, apiErr(422, "invalid_body", "the body is not a valid tt.policy.body/v1")
	}
	if err := policy.Validate(p); err != nil {
		return nil, apiErr(422, "invalid_body", "the body breaks a policy rule")
	}
	if enc, err := policy.EncodeBody(p); err != nil || !bytes.Equal(enc, body) {
		return nil, apiErr(422, "not_canonical", "the body is not in canonical form")
	}
	now := s.now()
	if p.CreatedAt.After(now.Add(5 * time.Minute)) {
		return nil, apiErr(422, "invalid_times", "created_at is in the future")
	}
	if !p.NotAfter.After(now) {
		return nil, apiErr(422, "invalid_times", "not_after has passed")
	}
	if p.NotAfter.Sub(p.CreatedAt) > s.cfg.PolicyValidity {
		return nil, apiErr(422, "invalid_times", "not_after is beyond the maximum validity")
	}
	for _, k := range append([]string{p.HMAC.Kid}, p.HMAC.AcceptKids...) {
		if s.cfg.RevokedKids[k] {
			return nil, apiErr(422, "kid_revoked", "the policy uses a revoked HMAC kid")
		}
		if !s.hmac.Has(k) {
			return nil, apiErr(422, "kid_not_held", "the policy uses an HMAC kid this keyguard does not hold")
		}
	}
	return p, nil
}

// classifyChange computes the classification of p against what keyguard
// signed (policy.md 5): the last body of the same policy_id (targets
// included) and, for each target group, the group's current policy (the
// newest signed body targeting it, if not expired). Any opening comparison
// makes the change opening.
func (s *Service) classifyChange(ctx context.Context, p *policy.Policy) (closing bool, reason string, lastVersion int64, err error) {
	closing = true
	set := func(ok bool, r string) {
		if !ok && closing {
			closing, reason = false, r
		}
	}
	last, err := lastBodyOf(ctx, s.db, p.PolicyID)
	if err != nil {
		return false, "", 0, err
	}
	if last == nil {
		set(false, "first_policy")
	} else {
		lp, err := decodeSigned(last)
		if err != nil {
			return false, "", 0, err
		}
		lastVersion = lp.Version
		ok, r := classify(lp, p, true)
		set(ok, r)
	}
	current, err := s.groupCurrent(ctx, p.Groups)
	if err != nil {
		return false, "", 0, err
	}
	for _, g := range p.Groups {
		cp := current[g]
		if cp == nil {
			set(false, "group_without_policy")
			continue
		}
		ok, r := classify(cp, p, false)
		set(ok, r)
	}
	return closing, reason, lastVersion, nil
}

// groupCurrent returns, for each group, the newest signed body targeting it,
// or nil when there is none or it has expired.
func (s *Service) groupCurrent(ctx context.Context, groups []string) (map[string]*policy.Policy, error) {
	out := map[string]*policy.Policy{}
	pending := len(groups)
	now := s.now()
	var derr error
	err := signedBodies(ctx, s.db, func(_ int64, _ string, body []byte) bool {
		bp, err := decodeSigned(body)
		if err != nil {
			derr = err
			return false
		}
		for _, g := range groups {
			if _, done := out[g]; done || !bp.HasGroup(g) {
				continue
			}
			if now.Before(bp.NotAfter) {
				out[g] = bp
			} else {
				out[g] = nil
			}
			pending--
		}
		return pending > 0
	})
	if err == nil {
		err = derr
	}
	return out, err
}

// observeVerdict computes, from the bodies keyguard signed, whether p opens
// values (policy.ClassifyValues, policy.md 7): against the last body of the
// same policy_id (targets included) and, for each target group, against the
// group's current policy (targets ignored: only what the sources of the
// group receive). A group without a current policy compares with nothing.
// reason is the first opening reason code (never a value).
func (s *Service) observeVerdict(ctx context.Context, p *policy.Policy) (opens bool, reason string, err error) {
	set := func(c policy.ValueClass) {
		if c.OpensValues && !opens {
			opens, reason = true, c.Reasons[0].Code
		}
	}
	last, err := lastBodyOf(ctx, s.db, p.PolicyID)
	if err != nil {
		return true, "", err
	}
	var lp *policy.Policy
	if last != nil {
		if lp, err = decodeSigned(last); err != nil {
			return true, "", err
		}
	}
	set(policy.ClassifyValues(lp, p))
	current, err := s.groupCurrent(ctx, p.Groups)
	if err != nil {
		return true, "", err
	}
	noGroups := *p
	noGroups.Groups = nil
	for _, g := range p.Groups {
		var cp *policy.Policy
		if c := current[g]; c != nil {
			cc := *c
			cc.Groups = nil
			cp = &cc
		}
		set(policy.ClassifyValues(cp, &noGroups))
	}
	return opens, reason, nil
}

// checkApprovals verifies the approvals for a change (keyguard.md 3.2 steps
// 3-4, policy.md 5) and returns the approval mode, the rows to store and the
// fingerprints of every ID token presented (all of them are stored, also
// in admin mode, so none can be presented again: RT3-KG-4). nonce is the
// binding of the change (approvebind).
func (s *Service) checkApprovals(ctx context.Context, closing bool, proposer, nonce string, approvals []Approval) (string, []approvalRow, []string, *Error) {
	if len(approvals) == 0 {
		return "", nil, nil, apiErr(403, "insufficient_approvals", "no approval")
	}
	if len(approvals) > 8 {
		return "", nil, nil, apiErr(403, "insufficient_approvals", "too many approvals")
	}
	rows := make([]approvalRow, 0, len(approvals))
	var fps []string
	seenUser, seenID := map[string]bool{}, map[string]bool{}
	for _, a := range approvals {
		row, ident, fp, e := s.checkApproval(ctx, a, nonce)
		if e != nil {
			return "", nil, nil, e
		}
		if seenUser[a.User] || seenID[ident] {
			return "", nil, nil, apiErr(403, "duplicate_approver", "the same person approved twice")
		}
		seenUser[a.User], seenID[ident] = true, true
		if !slices.Contains(a.Roles, RolePolicyApprover) && !slices.Contains(a.Roles, RoleAdmin) {
			return "", nil, nil, apiErr(403, "missing_role", "an approver has neither policy-approver nor admin role")
		}
		rows = append(rows, row)
		fps = append(fps, fp...)
	}
	required := 1
	if !closing {
		required = s.cfg.OpeningApprove
	}
	var approvers, notProposer int
	for i, a := range approvals {
		if !slices.Contains(a.Roles, RolePolicyApprover) {
			continue
		}
		approvers++
		if a.User != proposer && rows[i].Subject != proposer {
			notProposer++
		}
	}
	if approvers >= required && (required < 2 || notProposer >= 1) {
		if !closing && required == 1 {
			return ModeSingle, rows, fps, nil
		}
		return ModeStandard, rows, fps, nil
	}
	// Admin approval: a single admin approval with a reason is always
	// enough, unless disabled.
	for i, a := range approvals {
		if !slices.Contains(a.Roles, RoleAdmin) {
			continue
		}
		if !s.cfg.AdminOverride {
			return "", nil, nil, apiErr(403, "admin_override_disabled", "admin approval is disabled on this keyguard")
		}
		if strings.TrimSpace(a.Reason) == "" {
			return "", nil, nil, apiErr(403, "admin_reason_required", "an admin approval needs a reason")
		}
		return ModeAdmin, []approvalRow{rows[i]}, fps, nil
	}
	return "", nil, nil, apiErr(403, "insufficient_approvals", "not enough distinct approvals for this change")
}

// verifiedRoles are the roles keyguard never takes from tt-core when it
// verifies approvals with OIDC: each must be in the approver's token.
var verifiedRoles = []string{RoleAdmin, RolePolicyApprover, RolePublisher}

// checkApproval validates one approval and returns its row, the identity
// used for distinctness (the OIDC subject when verified, else the user) and
// the fingerprints of its ID token. With OIDC the token must be bound to
// the change (nonce) and carry, in the configured roles claim, every
// sensitive role tt-core declares (RT3-KG-2, RT3-KG-3).
func (s *Service) checkApproval(ctx context.Context, a Approval, nonce string) (approvalRow, string, []string, *Error) {
	if !reUser.MatchString(a.User) || len(a.Roles) == 0 || len(a.Roles) > 16 || a.At.IsZero() {
		return approvalRow{}, "", nil, apiErr(403, "invalid_approval", "an approval is malformed")
	}
	for _, r := range a.Roles {
		if !reUser.MatchString(r) {
			return approvalRow{}, "", nil, apiErr(403, "invalid_approval", "an approval role is malformed")
		}
	}
	if len(a.Reason) > MaxReasonBytes || !utf8.ValidString(a.Reason) || strings.ContainsFunc(a.Reason, func(r rune) bool { return r < 0x20 && r != '\n' }) {
		return approvalRow{}, "", nil, apiErr(403, "invalid_approval", "an approval reason is malformed")
	}
	if a.At.After(s.now().Add(time.Minute)) {
		return approvalRow{}, "", nil, apiErr(403, "invalid_approval", "an approval is dated in the future")
	}
	row := approvalRow{User: a.User, Roles: strings.Join(a.Roles, ","), At: a.At, Reason: a.Reason}
	if s.verifier == nil {
		return row, "user:" + a.User, nil, nil
	}
	if a.IDToken == "" || len(a.IDToken) > maxIDTokenBytes {
		return approvalRow{}, "", nil, apiErr(403, "approval_unverifiable", "an approval has no usable OIDC ID token")
	}
	tok, err := s.verifier.verify(ctx, a.IDToken, nonce)
	switch {
	case errors.Is(err, errNonceMismatch):
		return approvalRow{}, "", nil, apiErr(403, "approval_unverifiable", "an approval ID token is not bound to this change")
	case err != nil:
		return approvalRow{}, "", nil, apiErr(403, "approval_unverifiable", "an approval ID token does not verify")
	}
	for _, r := range verifiedRoles {
		if slices.Contains(a.Roles, r) && !slices.Contains(tok.Roles, r) {
			return approvalRow{}, "", nil, apiErr(403, "role_unverified", "an approver role is not in the approver's ID token")
		}
	}
	row.Subject, row.Verified, row.TokenSHA256 = tok.Subject, true, tok.Fingerprints[0]
	return row, "sub:" + tok.Subject, tok.Fingerprints, nil
}

// maxIDTokenBytes bounds an approval ID token.
const maxIDTokenBytes = 16 << 10

// SignPolicy signs a compiled policy body after re-checking it,
// recomputing the classification and verifying the approvals
// (keyguard.md 3.2).
func (s *Service) SignPolicy(ctx context.Context, body []byte, proposer string, approvals []Approval) (*SignResult, error) {
	s.signMu.Lock()
	defer s.signMu.Unlock()
	target := audit.Target{Type: "policy"}
	refuse := func(e *Error, details map[string]string) (*SignResult, error) {
		if details == nil {
			details = map[string]string{}
		}
		details["approvers"] = joinIDs(approverIDs(approvals))
		if _, err := s.record(ctx, "keyguard.policy_sign", audit.Denied, e.Code, target, details); err != nil {
			return nil, err
		}
		typ := AlertSignRefused
		if e.Status == 403 && e.Code != "issued_seq_not_increasing" {
			typ = AlertApprovalRefuse
		}
		s.alerts.raise(Alert{Type: typ, At: s.now().UTC(), Counts: map[string]int64{"approvals": int64(len(approvals))}})
		return nil, e
	}
	if !reUser.MatchString(proposer) {
		return refuse(apiErr(422, "invalid_request", "proposer is malformed"), nil)
	}
	p, e := s.acceptBody(body)
	if e != nil {
		return refuse(e, nil)
	}
	target.ID = p.PolicyID
	details := map[string]string{"version": itoa(p.Version), "issued_seq": itoa(p.IssuedSeq), "hash": policy.Hash(body)}
	closing, classReason, lastVersion, err := s.classifyChange(ctx, p)
	if err != nil {
		return nil, err
	}
	class := ClassOpening
	if closing {
		class = ClassClosing
	} else {
		details["opening_reason"] = classReason
	}
	details["classification"] = class
	if lastVersion > 0 && p.Version <= lastVersion {
		return refuse(apiErr(422, "version_not_increasing", "version must be greater than the last signed version"), details)
	}
	if seq, err := lastIssuedSeq(ctx, s.db); err != nil {
		return nil, err
	} else if p.IssuedSeq <= seq {
		return refuse(apiErr(403, "issued_seq_not_increasing", "issued_seq must be greater than any signed before"), details)
	}
	opens, valueReason, err := s.observeVerdict(ctx, p)
	if err != nil {
		return nil, err
	}
	details["opens_values"] = strconv.FormatBool(opens)
	if opens {
		details["value_reason"] = valueReason
	}
	nonce, err := approvebind.PolicyBodyNonce(p.PolicyID, p.Version, body)
	if err != nil {
		return nil, err
	}
	var (
		mode string
		rows []approvalRow
		fps  []string
	)
	if len(approvals) == 0 && !opens && s.cfg.ObserveAuto {
		// Observe-safe (policy.md 7): keyguard's own verdict, never tt-core's.
		mode = ModeObserve
	} else if mode, rows, fps, e = s.checkApprovals(ctx, closing, proposer, nonce, approvals); e != nil {
		return refuse(e, details)
	}
	kid, sig := s.policyKeys.Sign(policy.SignedMessage(body))
	row := signedRow{IssuedSeq: p.IssuedSeq, PolicyID: p.PolicyID, Version: p.Version, Op: "sign", Classification: class, Body: body}
	if err := insertSigned(ctx, s.db, row, mode, policy.Hash(body), kid, s.verifier == nil, rows, fps, s.now()); err != nil {
		switch {
		case errors.Is(err, errSeqNotIncreasing):
			return refuse(apiErr(403, "issued_seq_not_increasing", "issued_seq must be greater than any signed before"), details)
		case errors.Is(err, errTokenReused):
			return refuse(apiErr(403, "approval_unverifiable", "an approval ID token was already used"), details)
		}
		return nil, err
	}
	details["approval_mode"] = mode
	details["approvers"] = joinIDs(approverIDs(approvals))
	details["approvals_unverified"] = strconv.FormatBool(s.verifier == nil)
	details["approvals_bound"] = strconv.FormatBool(s.verifier != nil)
	details["kid"] = kid
	if mode == ModeAdmin {
		details["admin_reason"] = audit.SafeValue(rows[0].Reason)
	}
	if _, err := s.record(ctx, "keyguard.policy_sign", audit.Success, "", target, details); err != nil {
		return nil, err
	}
	if mode == ModeAdmin {
		s.alerts.raise(Alert{Type: AlertAdminApproval, At: s.now().UTC(), Counts: map[string]int64{"issued_seq": p.IssuedSeq, "version": p.Version}})
	}
	return &SignResult{Alg: "Ed25519", Kid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig), Classification: class, ApprovalMode: mode, OpensValues: &opens}, nil
}

func approverIDs(apps []Approval) []string {
	out := make([]string, 0, len(apps))
	for _, a := range apps {
		out = append(out, a.User)
	}
	return out
}

// renewableFields are the only fields a renewal may change (keyguard.md 3.3).
var renewableFields = []string{"version", "issued_seq", "created_at", "not_after"}

func stripRenewable(body []byte) ([]byte, error) {
	v, err := ttjson.Parse(body, ttjson.ParseOptions{MaxDepth: 16, RejectDuplicates: true})
	if err != nil || v.Kind != ttjson.Object {
		return nil, errors.New("invalid body")
	}
	kept := v.Obj[:0:0]
	for _, m := range v.Obj {
		if !slices.Contains(renewableFields, m.Key) {
			kept = append(kept, m)
		}
	}
	v.Obj = kept
	return ttjson.Encode(v)
}

// RenewPolicy re-signs a body that differs from the last one signed for the
// same policy_id only in version, issued_seq, created_at and not_after
// (keyguard.md 3.3). No approval is needed. The renewed policy must still
// be the current one of every group it targets and must not have expired:
// otherwise a renewal could bring back a superseded or lapsed policy.
func (s *Service) RenewPolicy(ctx context.Context, body []byte) (*SignResult, error) {
	s.signMu.Lock()
	defer s.signMu.Unlock()
	target := audit.Target{Type: "policy"}
	refuse := func(e *Error, details map[string]string) (*SignResult, error) {
		if _, err := s.record(ctx, "keyguard.policy_renew", audit.Denied, e.Code, target, details); err != nil {
			return nil, err
		}
		s.alerts.raise(Alert{Type: AlertSignRefused, At: s.now().UTC()})
		return nil, e
	}
	p, e := s.acceptBody(body)
	if e != nil {
		return refuse(e, nil)
	}
	target.ID = p.PolicyID
	details := map[string]string{"version": itoa(p.Version), "issued_seq": itoa(p.IssuedSeq), "hash": policy.Hash(body)}
	last, err := lastBodyOf(ctx, s.db, p.PolicyID)
	if err != nil {
		return nil, err
	}
	if last == nil {
		return refuse(apiErr(403, "no_signed_policy", "no earlier body was signed for this policy_id"), details)
	}
	lp, err := decodeSigned(last)
	if err != nil {
		return nil, err
	}
	a, err1 := stripRenewable(last)
	b, err2 := stripRenewable(body)
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
		return refuse(apiErr(403, "fields_differ", "fields other than version, issued_seq, created_at and not_after differ"), details)
	}
	if !s.now().Before(lp.NotAfter) {
		return refuse(apiErr(403, "expired", "the last signed body has expired: sign it again with approvals"), details)
	}
	if p.Version < lp.Version {
		return refuse(apiErr(422, "version_not_increasing", "version must not decrease"), details)
	}
	current, err := s.groupCurrent(ctx, p.Groups)
	if err != nil {
		return nil, err
	}
	for _, g := range p.Groups {
		if cp := current[g]; cp == nil || cp.PolicyID != p.PolicyID || cp.IssuedSeq != lp.IssuedSeq {
			return refuse(apiErr(403, "superseded", "the policy is no longer the current one of a target group"), details)
		}
	}
	kid, sig := s.policyKeys.Sign(policy.SignedMessage(body))
	row := signedRow{IssuedSeq: p.IssuedSeq, PolicyID: p.PolicyID, Version: p.Version, Op: "renew", Classification: "renewal", Body: body}
	if err := insertSigned(ctx, s.db, row, "none", policy.Hash(body), kid, s.verifier == nil, nil, nil, s.now()); err != nil {
		if errors.Is(err, errSeqNotIncreasing) {
			return refuse(apiErr(403, "issued_seq_not_increasing", "issued_seq must be greater than any signed before"), details)
		}
		return nil, err
	}
	details["kid"] = kid
	details["not_after"] = p.NotAfter.UTC().Format(time.RFC3339)
	if _, err := s.record(ctx, "keyguard.policy_renew", audit.Success, "", target, details); err != nil {
		return nil, err
	}
	return &SignResult{Alg: "Ed25519", Kid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}, nil
}
