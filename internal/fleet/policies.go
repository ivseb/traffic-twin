package fleet

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// Policy version statuses (admin-api PolicyVersion.status).
const (
	StatusDraft      = "draft"
	StatusActive     = "active"
	StatusSuperseded = "superseded"
	StatusRejected   = "rejected"
)

// Origins of a version.
const (
	OriginPropose  = "propose"
	OriginRollback = "rollback"
	OriginRetarget = "retarget"
	OriginRenew    = "renew"
	OriginStarter  = "starter"
	// OriginObserveAuto: the version tt-core derives by itself in the
	// observe phase (policy.md 7): hmac on identifiers and the automatic
	// identity, applied without approval.
	OriginObserveAuto = "observe-auto"
)

// MaxAuthorBytes bounds an author policy document.
const MaxAuthorBytes = 512 << 10

// idTokenMaxAge is how long an approver's OIDC ID token is kept in memory
// for forwarding to keyguard (keyguard.md 3.2: issued less than 10 minutes
// before signing). ID tokens are never stored on disk.
const idTokenMaxAge = 10 * time.Minute

// systemUser is the proposer of automatic renewals.
const systemUser = "system"

// ParseAuthor parses an author policy (tt.policy/v1) in YAML or JSON (a
// YAML subset). Duplicate keys, multiple documents and unknown fields are
// rejected.
func ParseAuthor(doc []byte) (*policy.Author, error) {
	if len(doc) == 0 || len(doc) > MaxAuthorBytes {
		return nil, invalid("invalid_policy", "the policy document is empty or too large")
	}
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		return nil, invalid("invalid_policy", "the policy is not valid YAML or JSON")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalid("invalid_policy", "the policy must be a single YAML document")
	}
	// RT4-YAML: the document a person reads must mean what keyguard signs.
	// Anchors, aliases, merge keys and explicit tags (!!binary turns
	// "a2VlcA==" into "keep") are refused.
	if !plainYAML(&node) {
		return nil, invalid("invalid_policy", "the policy must not use YAML anchors, aliases, merge keys or tags")
	}
	var tree any
	if err := node.Decode(&tree); err != nil {
		return nil, invalid("invalid_policy", "the policy is not valid YAML or JSON")
	}
	a, err := policy.AuthorFromGeneric(tree)
	if err != nil {
		return nil, invalid("invalid_policy", policyErrMsg(err))
	}
	return a, nil
}

// plainYAML reports whether a YAML tree uses none of the features that make
// a document mean something else than it shows: anchors, aliases, merge
// keys and explicit tags. The walk is iterative (no recursion on input).
func plainYAML(root *yaml.Node) bool {
	stack := []*yaml.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 || n.Tag == "!!merge" {
			return false
		}
		stack = append(stack, n.Content...)
	}
	return true
}

// policyErrMsg returns the validation message of the policy package. Its
// messages name fields and rules of the policy, which is configuration
// (zone B), not payload data.
func policyErrMsg(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// Approval is one recorded approval.
type Approval struct {
	UserID   string    `json:"-"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
	Verified bool      `json:"verified"`
	Admin    bool      `json:"admin_override,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Note     string    `json:"note,omitempty"`
	// TokenFresh is set on drafts when keyguard verifies approvals with
	// OIDC: whether tt-core still holds this approver's step-up ID token
	// (at most 10 minutes). When false the approver renews the approval
	// (approve again, with a new step-up) before the quorum can be signed.
	TokenFresh *bool `json:"token_fresh,omitempty"`
	roles      []string
}

// PolicyVersion is the admin view of a policy version
// (admin-api PolicyVersion).
type PolicyVersion struct {
	PolicyID       string    `json:"policy_id"`
	Version        int64     `json:"version"`
	IssuedSeq      *int64    `json:"issued_seq"`
	Status         string    `json:"status"`
	Origin         string    `json:"origin"`
	ProposedBy     string    `json:"proposed_by"`
	ProposedAt     time.Time `json:"proposed_at"`
	Classification string    `json:"classification"`
	// OpensValues: the change lets values out beyond observe-safe
	// (policy.md 7) and needs approvals; false: it applies at once.
	OpensValues bool `json:"opens_values"`
	// ValueReasons says why it opens values (codes and locations, never
	// values); empty when it does not.
	ValueReasons      []policy.ValueReason `json:"value_reasons"`
	ApprovalsRequired int                  `json:"approvals_required"`
	ApprovalMode      string               `json:"approval_mode,omitempty"`
	Approvals         []Approval           `json:"approvals"`
	Targets           Targets              `json:"targets"`
	NotAfter          *time.Time           `json:"not_after,omitempty"`
	Diff              []DiffEntry          `json:"diff"`
	Hash              string               `json:"hash,omitempty"`
	Note              string               `json:"note,omitempty"`
	// Withdrawn: the draft was withdrawn by its proposer (or an admin) before
	// anyone decided on it (status rejected, note starting with "withdrawn").
	Withdrawn  bool   `json:"withdrawn,omitempty"`
	AuthorYAML string `json:"author_yaml,omitempty"`
	// Supersedes lists the pending drafts this one folded in (only in the answer that creates it):
	// a second "Gemella" adds to the draft of the first instead of creating a sibling.
	Supersedes []int64 `json:"supersedes,omitempty"`
	// Groups are the groups the policy serves (bound to it or targeted by
	// its versions): the console's Group filter and Group column.
	Groups []string `json:"groups"`

	proposedByID string
	draftBody    []byte
}

// Targets lists the groups a version is assigned to.
type Targets struct {
	Groups []string `json:"groups"`
}

const versionCols = `policy_id, version, status, origin, author, proposed_by, proposed_by_name, proposed_at, classification,
	approvals_required, diff, targets, draft_body, issued_seq, not_after, hash, approval_mode, note, value_reasons`

func scanVersion(sc interface{ Scan(...any) error }) (*PolicyVersion, error) {
	v := &PolicyVersion{}
	var proposedAt int64
	var diff, targets, reasons string
	var seq, notAfter sql.NullInt64
	var hash sql.NullString
	if err := sc.Scan(&v.PolicyID, &v.Version, &v.Status, &v.Origin, &v.AuthorYAML, &v.proposedByID, &v.ProposedBy, &proposedAt,
		&v.Classification, &v.ApprovalsRequired, &diff, &targets, &v.draftBody, &seq, &notAfter, &hash, &v.ApprovalMode, &v.Note, &reasons); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(reasons), &v.ValueReasons); err != nil {
		return nil, err
	}
	if v.ValueReasons == nil && reasons == "null" {
		// Stored before spec v1.6: an opening change counts as opening values.
		v.OpensValues = v.Classification == Opening && v.Origin != OriginRenew
	}
	if v.ValueReasons == nil {
		v.ValueReasons = []policy.ValueReason{}
	}
	v.OpensValues = v.OpensValues || len(v.ValueReasons) > 0
	v.ProposedAt = time.Unix(proposedAt, 0).UTC()
	if err := json.Unmarshal([]byte(diff), &v.Diff); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(targets), &v.Targets.Groups); err != nil {
		return nil, err
	}
	if seq.Valid {
		v.IssuedSeq = &seq.Int64
	}
	if notAfter.Valid {
		t := time.Unix(notAfter.Int64, 0).UTC()
		v.NotAfter = &t
	}
	v.Hash = hash.String
	v.Withdrawn = v.Status == StatusRejected && strings.HasPrefix(v.Note, WithdrawnNote)
	return v, nil
}

func (f *Fleet) loadApprovals(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, pid string, ver int64) ([]Approval, error) {
	rows, err := q.QueryContext(ctx, `SELECT user_id, user_name, roles, at, verified, admin, reason, note FROM fleet_policy_approvals WHERE policy_id = ? AND version = ? ORDER BY at, user_id`, pid, ver)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		var roles string
		var at int64
		var verified, admin int
		if err := rows.Scan(&a.UserID, &a.By, &roles, &at, &verified, &admin, &a.Reason, &a.Note); err != nil {
			return nil, err
		}
		a.At, a.Verified, a.Admin = time.Unix(at, 0).UTC(), verified == 1, admin == 1
		_ = json.Unmarshal([]byte(roles), &a.roles)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListPolicies returns every version of every policy, newest first within
// a policy, with the author document (the UI wizard edits the active one).
// Drafts show their classification against the current active version.
func (f *Fleet) ListPolicies(ctx context.Context) ([]*PolicyVersion, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT `+versionCols+` FROM fleet_policy_versions ORDER BY policy_id, version DESC`)
	if err != nil {
		return nil, err
	}
	var out []*PolicyVersion
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []*PolicyVersion{}
	}
	for _, v := range out {
		if v.Approvals, err = f.loadApprovals(ctx, f.db, v.PolicyID, v.Version); err != nil {
			return nil, err
		}
		f.refreshDraftView(v)
	}
	return out, nil
}

// GetPolicyVersion returns one version with its author document.
func (f *Fleet) GetPolicyVersion(ctx context.Context, pid string, ver int64) (*PolicyVersion, error) {
	v, err := scanVersion(f.db.QueryRowContext(ctx, `SELECT `+versionCols+` FROM fleet_policy_versions WHERE policy_id = ? AND version = ?`, pid, ver))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if v.Approvals, err = f.loadApprovals(ctx, f.db, pid, ver); err != nil {
		return nil, err
	}
	f.refreshDraftView(v)
	if st, _ := f.approvalSettings(); v.Status == StatusDraft && !st.ApprovalsUnverified {
		now := f.now()
		f.mu.RLock()
		for i := range v.Approvals {
			t, ok := f.idTokens[idTokenKey(pid, ver, v.Approvals[i].UserID)]
			fresh := ok && now.Sub(t.at) <= idTokenMaxAge
			v.Approvals[i].TokenFresh = &fresh
		}
		f.mu.RUnlock()
	}
	return v, nil
}

// SetApprovalTokens wires the approval step-up (internal/auth). Without it,
// approvals cannot be verified by keyguard with OIDC.
func (f *Fleet) SetApprovalTokens(t ApprovalTokens) {
	f.mu.Lock()
	f.tokens = t
	f.mu.Unlock()
}

// ApprovalsVerified reports whether keyguard verifies approvals with OIDC,
// and its issuer and approval audience.
func (f *Fleet) ApprovalsVerified() (issuer, audience string, ok bool) {
	st, _ := f.approvalSettings()
	return st.OIDCIssuer, st.OIDCAudience, !st.ApprovalsUnverified
}

// StepUpRef is the step-up reference of a policy version
// ("<policy_id>/<version>").
func StepUpRef(pid string, ver int64) string { return pid + "/" + itoa(ver) }

// ApprovalNonce returns the approval binding (approvebind.PolicyNonce) of a
// draft as it would be signed now: compiled with the groups bound now.
// The step-up of an approver carries it as nonce.
func (f *Fleet) ApprovalNonce(ctx context.Context, pid string, ver int64) (string, error) {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	v, err := f.GetPolicyVersion(ctx, pid, ver)
	if err != nil {
		return "", err
	}
	if v.Status != StatusDraft || v.Origin == OriginRenew {
		return "", conflict("not_draft", "only drafts can be approved")
	}
	a, err := ParseAuthor([]byte(v.AuthorYAML))
	if err != nil {
		return "", err
	}
	body, _, err := f.compileFor(a, ver, peekSeq(ctx, f.db), f.boundGroups(pid), f.now())
	if err != nil {
		return "", err
	}
	return approvebind.PolicyBodyNonce(pid, ver, body)
}

// approvalToken obtains p's approval token for (pid, ver) bound to nonce
// and maps failures to API errors.
func (f *Fleet) approvalToken(ctx context.Context, p *auth.Principal, pid string, ver int64, nonce, explicit string, st SignerStatus) (string, error) {
	f.mu.RLock()
	t := f.tokens
	f.mu.RUnlock()
	if t == nil {
		if p.OIDCSubject == "" {
			status, code, msg := auth.ApprovalTokenError(auth.ErrLocalApprover, explicit != "")
			return "", apiErr(status, code, msg)
		}
		status, code, msg := auth.ApprovalTokenError(auth.ErrStepUpDisabled, false)
		return "", apiErr(status, code, msg)
	}
	if p.OIDCSubject != "" {
		if err := t.CheckApprovalAudience(st.OIDCIssuer, st.OIDCAudience); err != nil && !errors.Is(err, auth.ErrStepUpDisabled) {
			f.log.ErrorContext(ctx, "fleet: approval step-up misconfigured", "err", err)
			return "", apiErr(503, "stepup_misconfigured", "tt-core's approval client does not match keyguard's OIDC issuer or audience")
		}
	}
	tok, err := t.ApprovalToken(ctx, p, approvebind.PurposePolicy, StepUpRef(pid, ver), nonce, explicit)
	if err != nil {
		status, code, msg := auth.ApprovalTokenError(err, explicit != "")
		return "", apiErr(status, code, msg)
	}
	return tok, nil
}

// refreshDraftView recomputes, for a pending draft, the classification and
// diff against the version active now and the groups bound now (both may
// have changed since the proposal).
func (f *Fleet) refreshDraftView(v *PolicyVersion) {
	if v.Status != StatusDraft {
		return
	}
	cand, err := policy.DecodeBody(v.draftBody)
	if err != nil {
		return
	}
	if g := f.boundGroups(v.PolicyID); len(g) > 0 {
		cand.Groups = g
	}
	v.Targets.Groups = cand.Groups
	act := f.activeBody(v.PolicyID)
	v.Classification, v.Diff = Classify(act, cand)
	vc := f.valueClass(v.PolicyID, cand)
	if hasKeyguardVerdict(v.ValueReasons) {
		vc.Reasons = append(vc.Reasons, keyguardVerdict)
		vc.OpensValues = true
	}
	v.OpensValues, v.ValueReasons = vc.OpensValues, nonNilReasons(vc.Reasons)
	v.ApprovalsRequired = f.required(v.Classification, v.Origin, vc.OpensValues)
}

// keyguardVerdict is stored on a draft keyguard refused to sign without
// approvals: its own classification says the change opens values, whatever
// tt-core computes.
var keyguardVerdict = policy.ValueReason{Code: "keyguard_verdict", Where: "keyguard"}

func hasKeyguardVerdict(rs []policy.ValueReason) bool {
	for _, r := range rs {
		if r == keyguardVerdict {
			return true
		}
	}
	return false
}

func nonNilReasons(r []policy.ValueReason) []policy.ValueReason {
	if r == nil {
		return []policy.ValueReason{}
	}
	return r
}

// valueClass classifies cand like keyguard does (policy.md 7): against the
// active version of pid and against the policy each target group runs now
// (targets ignored there). tt-core's verdict is advisory: keyguard
// recomputes it from the bodies it signed.
func (f *Fleet) valueClass(pid string, cand *policy.Policy) policy.ValueClass {
	out := policy.ClassifyValues(f.activeBody(pid), cand)
	seen := map[policy.ValueReason]bool{}
	for _, r := range out.Reasons {
		seen[r] = true
	}
	noGroups := *cand
	noGroups.Groups = nil
	for _, g := range cand.Groups {
		f.mu.RLock()
		ap := f.currentFor(g)
		var body []byte
		if ap != nil {
			body = f.signed[ap.hash]
		}
		f.mu.RUnlock()
		if ap != nil && ap.policyID == pid {
			continue // compared above
		}
		var cur *policy.Policy
		if body != nil {
			if p, err := policy.DecodeBody(body); err == nil {
				p.Groups = nil
				cur = p
			}
		}
		for _, r := range policy.ClassifyValues(cur, &noGroups).Reasons {
			if !seen[r] {
				seen[r] = true
				out.Reasons = append(out.Reasons, r)
			}
		}
	}
	out.OpensValues = len(out.Reasons) > 0
	return out
}

// activeBody decodes the active version of pid (nil when none).
func (f *Fleet) activeBody(pid string) *policy.Policy {
	f.mu.RLock()
	ap := f.active[pid]
	var body []byte
	if ap != nil {
		body = f.signed[ap.hash]
	}
	f.mu.RUnlock()
	if body == nil {
		return nil
	}
	p, err := policy.DecodeBody(body)
	if err != nil {
		return nil
	}
	return p
}

// required returns the number of approvals a draft needs (policy.md 5,
// v1.2.1, and 7): 0 for an observe-safe change when keyguard signs those
// without approvals (observe_auto), 1 for closing changes, keyguard's
// opening_approvals (default 2) otherwise; a rollback always counts as
// opening.
func (f *Fleet) required(class, origin string, opensValues bool) int {
	st, _ := f.approvalSettings()
	if origin == OriginRollback {
		return st.OpeningApprovals
	}
	if !opensValues && st.ObserveAuto {
		return 0
	}
	if class == Closing {
		return 1
	}
	return st.OpeningApprovals
}

// nextVersion returns max(version)+1 for pid.
func nextVersion(ctx context.Context, tx *sql.Tx, pid string) (int64, error) {
	var v sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM fleet_policy_versions WHERE policy_id = ?`, pid).Scan(&v); err != nil {
		return 0, err
	}
	return v.Int64 + 1, nil
}

func peekSeq(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) int64 {
	s, _ := getMeta(ctx, q, metaIssuedSeq)
	n, _ := strconv.ParseInt(s, 10, 64)
	return n + 1
}

// compileFor compiles an author policy with tt-core's metadata.
func (f *Fleet) compileFor(a *policy.Author, ver, seq int64, groups []string, now time.Time) ([]byte, *policy.Policy, error) {
	if len(groups) == 0 {
		return nil, nil, conflict("no_target_groups", "no group is bound to this policy: set policy_id on a group first")
	}
	body, p, err := policy.Compile(a, policy.CompileMeta{
		Version: ver, IssuedSeq: seq, CreatedAt: now, NotAfter: now.Add(f.opts.PolicyValidity), Groups: groups,
		Bodies: f.opts.Bodies,
	})
	if err != nil {
		return nil, nil, invalid("invalid_policy", policyErrMsg(err))
	}
	return body, p, nil
}

// createDraft stores a new draft. Caller holds policyMu.
func (f *Fleet) createDraft(ctx context.Context, p *auth.Principal, author []byte, origin, note string) (*PolicyVersion, error) {
	return f.createDraftFolding(ctx, p, author, origin, note, nil)
}

// createDraftFolding is createDraft for a proposal that builds on a pending draft (workingAuthor):
// in the same transaction the folded drafts become superseded, so the policy keeps a single
// pending draft that has all the changes instead of siblings that undo each other.
func (f *Fleet) createDraftFolding(ctx context.Context, p *auth.Principal, author []byte, origin, note string, folded []int64) (*PolicyVersion, error) {
	a, err := ParseAuthor(author)
	if err != nil {
		return nil, err
	}
	groups := f.boundGroups(a.PolicyID)
	now := f.now()
	var ver int64
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		if ver, err = nextVersion(ctx, tx, a.PolicyID); err != nil {
			return err
		}
		body, cand, err := f.compileFor(a, ver, peekSeq(ctx, tx), groups, now)
		if err != nil {
			return err
		}
		class, diff := Classify(f.activeBody(a.PolicyID), cand)
		vc := f.valueClass(a.PolicyID, cand)
		_, err = tx.ExecContext(ctx, `INSERT INTO fleet_policy_versions(policy_id, version, status, origin, author, proposed_by, proposed_by_name, proposed_at,
			classification, approvals_required, diff, targets, draft_body, note, value_reasons) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			a.PolicyID, ver, StatusDraft, origin, string(author), p.UserID, displayName(p), now.Unix(),
			class, f.required(class, origin, vc.OpensValues), mustJSON(diff), mustJSON(groups), body, note, mustJSON(nonNilReasons(vc.Reasons)))
		if err != nil {
			return err
		}
		for _, old := range folded {
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_policy_versions SET status = ?, decided_by = ?, decided_at = ?, note = ?
				WHERE policy_id = ? AND version = ? AND status = ?`,
				StatusSuperseded, p.UserID, now.Unix(), "folded into v"+itoa(ver), a.PolicyID, old, StatusDraft); err != nil {
				return err
			}
			// Approvals given to the old draft do not carry over: they were for different content.
			if _, err := tx.ExecContext(ctx, `DELETE FROM fleet_policy_approvals WHERE policy_id = ? AND version = ?`, a.PolicyID, old); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	v, err := f.GetPolicyVersion(ctx, a.PolicyID, ver)
	if err != nil {
		return nil, err
	}
	v.Supersedes = folded
	f.record(ctx, audit.Event{Actor: actorOf(p), Action: "policy." + origin, Target: audit.Target{Type: "policy", ID: a.PolicyID},
		Outcome: audit.Success, Details: map[string]string{
			"version": itoa(ver), "classification": v.Classification, "approvals_required": strconv.Itoa(v.ApprovalsRequired),
			"changes": strconv.Itoa(len(v.Diff)), "opens_values": strconv.FormatBool(v.OpensValues),
		}})
	if v.ApprovalsRequired == 0 {
		// Observe-safe (policy.md 7): it applies at once, signed by keyguard
		// without approvals. On failure it stays a draft (retried later).
		if av, err := f.applyObserveSafe(ctx, p, v); err == nil {
			av.Supersedes = folded
			return av, nil
		}
		if v, err = f.GetPolicyVersion(ctx, a.PolicyID, ver); err != nil {
			return nil, err
		}
		v.Supersedes = folded
	}
	return v, nil
}

// ProposePolicy validates, compiles and classifies an author policy and
// stores it as a draft.
func (f *Fleet) ProposePolicy(ctx context.Context, p *auth.Principal, author []byte) (*PolicyVersion, error) {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	return f.createDraft(ctx, p, author, OriginPropose, "")
}

// Rollback creates a draft with the content of an earlier signed version.
// It needs the opening number of approvals (policy.md 5).
func (f *Fleet) Rollback(ctx context.Context, p *auth.Principal, pid string, to int64) (*PolicyVersion, error) {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	var author string
	var seq sql.NullInt64
	err := f.db.QueryRowContext(ctx, `SELECT author, issued_seq FROM fleet_policy_versions WHERE policy_id = ? AND version = ?`, pid, to).Scan(&author, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if !seq.Valid {
		return nil, invalid("not_signed", "only a version that was signed and active can be restored")
	}
	return f.createDraft(ctx, p, []byte(author), OriginRollback, "rollback to v"+itoa(to))
}

// retarget creates a draft re-targeting the active version of pid to the
// groups bound now (adding a group opens data). It returns nil when pid
// has no active version (the binding then applies to the first version).
func (f *Fleet) retarget(ctx context.Context, p *auth.Principal, pid string) (*DraftRef, error) {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	f.mu.RLock()
	ap := f.active[pid]
	f.mu.RUnlock()
	if ap == nil {
		return nil, nil
	}
	var author string
	if err := f.db.QueryRowContext(ctx, `SELECT author FROM fleet_policy_versions WHERE policy_id = ? AND version = ?`, pid, ap.version).Scan(&author); err != nil {
		return nil, err
	}
	v, err := f.createDraft(ctx, p, []byte(author), OriginRetarget, "")
	if err != nil {
		return nil, err
	}
	return &DraftRef{PolicyID: v.PolicyID, Version: v.Version}, nil
}

// RejectPolicy rejects a draft.
func (f *Fleet) RejectPolicy(ctx context.Context, p *auth.Principal, pid string, ver int64, note string) (*PolicyVersion, error) {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	res, err := f.db.ExecContext(ctx, `UPDATE fleet_policy_versions SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE policy_id = ? AND version = ? AND status = ?`,
		StatusRejected, p.UserID, f.now().Unix(), note, pid, ver, StatusDraft)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := f.GetPolicyVersion(ctx, pid, ver); err != nil {
			return nil, err
		}
		return nil, conflict("not_draft", "only drafts can be rejected")
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.reject", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success,
		Details: map[string]string{"version": itoa(ver)}})
	return f.GetPolicyVersion(ctx, pid, ver)
}

// WithdrawnNote opens the note of a withdrawn draft.
const WithdrawnNote = "withdrawn"

// WithdrawPolicy withdraws a pending draft: its proposer (or an admin) takes
// it back, without needing a policy-approver, so a draft nobody can approve
// (two approvals needed, the proposer cannot approve their own) does not
// block the policy for ever. The draft becomes rejected with the note
// "withdrawn"; the history keeps it. Audited as policy.withdraw.
func (f *Fleet) WithdrawPolicy(ctx context.Context, p *auth.Principal, pid string, ver int64, note string) (*PolicyVersion, error) {
	if len(note) > 1000 {
		return nil, invalid("too_long", "note is limited to 1000 characters")
	}
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	cur, err := f.GetPolicyVersion(ctx, pid, ver)
	if err != nil {
		return nil, err
	}
	if cur.Status != StatusDraft {
		return nil, conflict("not_draft", "only drafts can be withdrawn")
	}
	admin := p.Has(auth.RoleAdmin)
	if cur.proposedByID != p.UserID && !admin {
		f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.withdraw", Target: audit.Target{Type: "policy", ID: pid},
			Outcome: audit.Denied, Reason: "not_proposer", Details: map[string]string{"version": itoa(ver)}})
		return nil, apiErr(http.StatusForbidden, "not_proposer", "only the person who proposed the draft, or an admin, can withdraw it")
	}
	stored := WithdrawnNote
	if note != "" {
		stored += ": " + note
	}
	res, err := f.db.ExecContext(ctx, `UPDATE fleet_policy_versions SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE policy_id = ? AND version = ? AND status = ?`,
		StatusRejected, p.UserID, f.now().Unix(), stored, pid, ver, StatusDraft)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, conflict("not_draft", "only drafts can be withdrawn")
	}
	det := map[string]string{"version": itoa(ver), "own": strconv.FormatBool(cur.proposedByID == p.UserID), "note": strconv.FormatBool(note != "")}
	if admin && cur.proposedByID != p.UserID {
		det["admin_override"] = "true"
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.withdraw", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success, Details: det})
	return f.GetPolicyVersion(ctx, pid, ver)
}

// ApproveRequest is the body of approvePolicy.
type ApproveRequest struct {
	IDToken string `json:"id_token,omitempty"`
	Note    string `json:"note,omitempty"`
	// Reason makes the approval an admin single approval (policy.md 5,
	// v1.2.1): only for callers with the admin role, mandatory for them
	// when they do not also approve as policy-approver.
	Reason string `json:"reason,omitempty"`
}

func idTokenKey(pid string, ver int64, user string) string {
	return pid + "\x00" + itoa(ver) + "\x00" + user
}

// ApprovePolicy records an approval. When the draft reaches its quorum (or
// an admin approves alone with a reason) tt-core asks keyguard to sign the
// recompiled body and activates it. The approval is persisted only if the
// signature succeeds, so a refused or failed signing can be retried.
func (f *Fleet) ApprovePolicy(ctx context.Context, p *auth.Principal, pid string, ver int64, req ApproveRequest) (*PolicyVersion, error) {
	if len(req.Note) > 1000 || len(req.Reason) > 1000 {
		return nil, invalid("too_long", "note and reason are limited to 1000 characters")
	}
	reason := strings.TrimSpace(req.Reason)
	adminMode := false
	switch {
	case p.Has(auth.RoleAdmin) && reason == "":
		// An approval by an admin is always the admin override (reason,
		// audit policy.admin_approval, alert), also when the admin holds
		// policy-approver from before separation of duties was enforced:
		// an admin creates accounts, so its "second person" may be a
		// puppet.
		return nil, invalid("reason_required", "an approval by an admin is an admin override: give a reason")
	case p.Has(auth.RoleAdmin):
		adminMode = true
	case reason != "":
		return nil, apiErr(403, "forbidden", "only an admin can approve alone with a reason")
	case !p.Has(auth.RolePolicyApprover):
		return nil, apiErr(403, "forbidden", "insufficient role")
	}
	settings, _ := f.approvalSettings()
	if adminMode && !settings.AdminOverride {
		return nil, apiErr(403, "admin_override_disabled", "admin single approval is disabled in keyguard")
	}

	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	v, err := f.GetPolicyVersion(ctx, pid, ver)
	if err != nil {
		return nil, err
	}
	if v.Status != StatusDraft {
		return nil, conflict("not_draft", "only drafts can be approved")
	}
	if v.ApprovalsRequired == 0 && v.Origin != OriginRenew {
		// Observe-safe: nothing to approve, it applies (a pending one was
		// not signed yet, for instance keyguard was unreachable).
		return f.applyObserveSafe(ctx, p, v)
	}
	// A draft older than a version signed from another draft would roll
	// the policy back silently: refuse it (renewals do not count).
	var newer int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_policy_versions WHERE policy_id = ? AND version > ? AND issued_seq IS NOT NULL AND origin != ?`,
		pid, ver, OriginRenew).Scan(&newer); err != nil {
		return nil, err
	}
	if newer > 0 {
		return nil, conflict("stale_draft", "a newer version was signed: propose this change again")
	}
	prior := make([]string, 0, len(v.Approvals))
	for _, a := range v.Approvals {
		prior = append(prior, a.UserID)
	}
	// verify: keyguard verifies approvals with OIDC, so every approval
	// needs a step-up ID token bound to this change (keyguard.md 3.2).
	verify := !settings.ApprovalsUnverified
	if req.IDToken != "" && p.OIDCSubject == "" {
		return nil, apiErr(403, "id_token_not_allowed", "local accounts cannot attach OIDC ID tokens")
	}
	if adminMode {
		// The admin override approves alone (policy.md 5, v1.2.1), also a
		// change the admin proposed; approving twice is still refused.
		err = auth.CheckApproval(p, auth.RoleAdmin, "", prior)
	} else {
		err = auth.CheckApproval(p, auth.RolePolicyApprover, v.proposedByID, prior)
	}
	// refresh: with OIDC an approver who already approved approves again
	// to renew an expired step-up token (the approval itself is kept).
	refresh := false
	switch {
	case errors.Is(err, auth.ErrSelfApproval):
		return nil, conflict("self_approval", "the author of a change cannot approve it")
	case errors.Is(err, auth.ErrDuplicateApproval) && verify && !adminMode:
		refresh = true
	case errors.Is(err, auth.ErrDuplicateApproval):
		return nil, conflict("duplicate_approval", "you already approved this version")
	case err != nil:
		return nil, apiErr(403, "forbidden", "insufficient role")
	}

	// Stale approvals: the stored approvals count only if their authors are
	// still enabled and still entitled now (policy-approver, not admin);
	// keyguard receives the roles they hold now, not those captured at
	// approval time. The others are dropped from the draft.
	current, stale, err := f.currentApprovals(ctx, v.Approvals)
	if err != nil {
		return nil, err
	}

	now := f.now()
	roles := make([]string, len(p.Roles))
	for i, r := range p.Roles {
		roles[i] = string(r)
	}
	if adminMode {
		// keyguard sees the admin approval as such (reason, approval_mode
		// admin, policy.admin_approval), also for an admin that holds
		// policy-approver too: never as a standard approver.
		roles = []string{string(auth.RoleAdmin)}
	}
	mine := Approval{UserID: p.UserID, By: displayName(p), At: now.UTC().Truncate(time.Second), Admin: adminMode, Reason: reason, Note: req.Note, roles: roles}
	all := append(append([]Approval{}, current...), mine)
	if refresh {
		all = current
		found := false
		for _, a := range current {
			if a.UserID == p.UserID {
				mine, found = a, true
			}
		}
		if !found {
			return nil, apiErr(403, "forbidden", "insufficient role")
		}
	}
	ids := make([]string, 0, len(all))
	for _, a := range all {
		ids = append(ids, a.UserID)
	}

	// Recompile with the groups bound now to classify what would be signed.
	a, err := ParseAuthor([]byte(v.AuthorYAML))
	if err != nil {
		return nil, err
	}
	groups := f.boundGroups(pid)
	if v.Origin == OriginRenew {
		return nil, conflict("not_draft", "renewals are not approved")
	}
	candBody, cand, err := f.compileFor(a, ver, peekSeq(ctx, f.db), groups, now)
	if err != nil {
		return nil, err
	}
	var nonce string
	if verify {
		if nonce, err = approvebind.PolicyBodyNonce(pid, ver, candBody); err != nil {
			return nil, err
		}
		tok, err := f.approvalToken(ctx, p, pid, ver, nonce, req.IDToken, settings)
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.idTokens[idTokenKey(pid, ver, p.UserID)] = idToken{token: tok, at: now, nonce: nonce}
		f.mu.Unlock()
	}
	class, diff := Classify(f.activeBody(pid), cand)
	need := f.required(class, v.Origin, f.valueClass(pid, cand).OpensValues)
	quorum := adminMode || auth.DistinctApprovals(v.proposedByID, ids) >= need
	// With OIDC every counted approval needs a fresh token bound to this
	// body: an approver whose token expired (or was bound to an earlier
	// state of the draft) renews the approval first.
	waiting := verify && quorum && !adminMode && f.missingTokens(pid, ver, all, nonce, now)
	if !quorum || waiting {
		err := f.db.InTx(ctx, func(tx *sql.Tx) error {
			if err := dropApprovals(ctx, tx, pid, ver, stale); err != nil {
				return err
			}
			if !refresh {
				if err := insertApproval(ctx, tx, pid, ver, mine, false); err != nil {
					return err
				}
			}
			_, err := tx.ExecContext(ctx, `UPDATE fleet_policy_versions SET classification = ?, approvals_required = ?, diff = ?, targets = ? WHERE policy_id = ? AND version = ?`,
				class, need, mustJSON(diff), mustJSON(groups), pid, ver)
			return err
		})
		if err != nil {
			return nil, err
		}
		f.auditDropped(ctx, p, pid, ver, stale)
		action := "policy.approve"
		if refresh {
			action = "policy.approval_renewed"
		}
		det := map[string]string{"version": itoa(ver), "classification": class, "approvals": strconv.Itoa(len(all)), "approvals_required": strconv.Itoa(need)}
		if waiting {
			det["waiting"] = "approval_tokens"
		}
		f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: action, Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success, Details: det})
		return f.GetPolicyVersion(ctx, pid, ver)
	}

	// Quorum reached (or admin override): allocate issued_seq, recompile and sign.
	var seq int64
	if err := f.db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		seq, err = nextIssuedSeq(ctx, tx)
		return err
	}); err != nil {
		return nil, err
	}
	body, cand, err := f.compileFor(a, ver, seq, groups, now)
	if err != nil {
		return nil, err
	}
	signApprovals := f.signApprovals(pid, ver, all, nonce, now)
	if adminMode {
		// Only the admin's approval: earlier approvals may lack a fresh
		// ID token and are not needed.
		signApprovals = f.signApprovals(pid, ver, []Approval{mine}, nonce, now)
	}
	sig, err := f.signer.SignPolicy(ctx, SignRequest{Body: body, Proposer: v.proposedByID, Approvals: signApprovals})
	if err != nil {
		var refused *SignRefusedError
		code := "keyguard_unavailable"
		if errors.As(err, &refused) {
			code = "keyguard_refused"
		}
		f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.sign", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Failure,
			Reason: code, Details: map[string]string{"version": itoa(ver), "issued_seq": itoa(seq), "keyguard_code": refusalCode(refused)}})
		if refused != nil {
			return nil, keyguardRefusal(refused, "keyguard refused to sign: ")
		}
		f.log.ErrorContext(ctx, "fleet: keyguard signing failed", "err", err)
		return nil, apiErr(502, "keyguard_unavailable", "keyguard could not be reached")
	}
	env, err := f.envelope(ctx, body, cand, sig)
	if err != nil {
		f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.sign", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Failure,
			Reason: "signature_invalid", Details: map[string]string{"version": itoa(ver), "kid": audit.SafeValue(sig.Kid)}})
		return nil, apiErr(502, "signature_invalid", "keyguard returned a signature that does not verify")
	}
	mode := sig.ApprovalMode
	if mode == "" {
		mode = ApprovalStandard
		if adminMode {
			mode = ApprovalAdmin
		} else if need == 1 && class == Opening {
			mode = ApprovalSingle
		}
	}
	if sig.Classification == Opening || sig.Classification == Closing {
		class = sig.Classification
	}
	hash := policy.Hash(body)
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		if err := dropApprovals(ctx, tx, pid, ver, stale); err != nil {
			return err
		}
		if !refresh {
			if err := insertApproval(ctx, tx, pid, ver, mine, sig.ApprovalsVerified); err != nil {
				return err
			}
		}
		if sig.ApprovalsVerified {
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_policy_approvals SET verified = 1 WHERE policy_id = ? AND version = ?`, pid, ver); err != nil {
				return err
			}
		}
		return activate(ctx, tx, pid, ver, class, need, diff, groups, seq, cand.NotAfter, hash, body, env, sig.Kid, mode, p.UserID, now)
	})
	if err != nil {
		return nil, err
	}
	f.installActive(body, env, hash)
	f.auditDropped(ctx, p, pid, ver, stale)
	det := map[string]string{"version": itoa(ver), "issued_seq": itoa(seq), "hash": hash, "kid": audit.SafeValue(sig.Kid),
		"classification": class, "approval_mode": mode, "approvals": strconv.Itoa(len(all)), "groups": audit.SafeValue(strings.Join(groups, ","))}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.approve", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success, Details: det})
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.activate", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success, Details: det})
	if mode == ApprovalAdmin {
		// The reason text stays in the policy record (shown by the admin
		// API); the audit log only accepts identifiers, so it carries a
		// digest that binds the entry to the stored text.
		ad := map[string]string{"version": itoa(ver), "issued_seq": itoa(seq), "classification": class,
			"reason_sha256": hashSecret(reason)[:32], "reason_len": strconv.Itoa(len(reason))}
		f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.admin_approval", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success, Details: ad})
		if f.alerts != nil {
			f.alerts.Alert(ctx, "policy.admin_approval", map[string]string{"policy_id": pid, "version": itoa(ver), "by": p.UserID, "classification": class})
		}
	}
	return f.GetPolicyVersion(ctx, pid, ver)
}

// currentApprovals splits stored approvals into those that still count
// (author enabled and, for a standard approval, holding policy-approver and
// not admin; for an admin override, still admin) with the roles held now,
// and the user ids of the stale ones.
func (f *Fleet) currentApprovals(ctx context.Context, as []Approval) ([]Approval, []string, error) {
	ids := make([]string, 0, len(as))
	for _, a := range as {
		ids = append(ids, a.UserID)
	}
	cur, err := auth.CurrentRoles(ctx, f.db, ids)
	if err != nil {
		return nil, nil, err
	}
	var keep []Approval
	var stale []string
	for _, a := range as {
		rs, ok := cur[a.UserID]
		need := auth.RolePolicyApprover
		if a.Admin {
			need = auth.RoleAdmin
		}
		if !ok || !auth.EntitledApprover(rs, need) {
			stale = append(stale, a.UserID)
			continue
		}
		a.roles = make([]string, len(rs))
		for i, r := range rs {
			a.roles[i] = string(r)
		}
		keep = append(keep, a)
	}
	return keep, stale, nil
}

func (f *Fleet) auditDropped(ctx context.Context, p *auth.Principal, pid string, ver int64, users []string) {
	for _, u := range users {
		f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "policy.approval_dropped", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success,
			Reason: "approver_disabled_or_role_removed", Details: map[string]string{"version": itoa(ver), "user": audit.SafeValue(u)}})
	}
}

// dropApprovals deletes stale approvals of a draft (see currentApprovals)
// and audits each (policy.approval_dropped).
func dropApprovals(ctx context.Context, tx *sql.Tx, pid string, ver int64, users []string) error {
	for _, u := range users {
		if _, err := tx.ExecContext(ctx, `DELETE FROM fleet_policy_approvals WHERE policy_id = ? AND version = ? AND user_id = ?`, pid, ver, u); err != nil {
			return err
		}
	}
	return nil
}

// keyguardRefusal is the API error for a refused signature. Rollback
// protection refusals (version_not_increasing, issued_seq_not_increasing)
// are not an upstream failure: keyguard already signed a later version or
// sequence, which is what a second tt-core on the same keyguard looks like.
// v1 supports a single tt-core per keyguard, so the error says so (409).
func keyguardRefusal(r *SignRefusedError, prefix string) *APIError {
	code := refusalCode(r)
	if code == "version_not_increasing" || code == "issued_seq_not_increasing" {
		return apiErr(409, "keyguard_state_conflict",
			"keyguard has already signed a later policy version or sequence ("+code+"): another tt-core is probably using the same keyguard. "+
				"v1 supports one tt-core per keyguard (rollback protection); give each core its own keyguard")
	}
	return apiErr(502, "keyguard_refused", prefix+code)
}

func refusalCode(r *SignRefusedError) string {
	if r == nil {
		return "unavailable"
	}
	return audit.SafeValue(r.Code)
}

func insertApproval(ctx context.Context, tx *sql.Tx, pid string, ver int64, a Approval, verified bool) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO fleet_policy_approvals(policy_id, version, user_id, user_name, roles, at, verified, admin, reason, note) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		pid, ver, a.UserID, a.By, mustJSON(a.roles), a.At.Unix(), boolInt(verified), boolInt(a.Admin), a.Reason, a.Note)
	return err
}

// signApprovals builds the approvals forwarded to keyguard, each with its
// approver's step-up token when one is held, fresh and bound to nonce
// (empty nonce: keyguard does not verify, no token is forwarded).
func (f *Fleet) signApprovals(pid string, ver int64, all []Approval, nonce string, now time.Time) []SignApproval {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]SignApproval, 0, len(all))
	for _, a := range all {
		sa := SignApproval{User: a.UserID, Roles: a.roles, At: a.At, Reason: a.Reason}
		if t, ok := f.idTokens[idTokenKey(pid, ver, a.UserID)]; ok && nonce != "" && t.nonce == nonce && now.Sub(t.at) <= idTokenMaxAge {
			sa.IDToken = t.token
		}
		out = append(out, sa)
	}
	return out
}

// missingTokens reports whether an approval of all lacks a fresh step-up
// token bound to nonce.
func (f *Fleet) missingTokens(pid string, ver int64, all []Approval, nonce string, now time.Time) bool {
	for _, sa := range f.signApprovals(pid, ver, all, nonce, now) {
		if sa.IDToken == "" {
			return true
		}
	}
	return false
}

// envelope assembles the signed envelope and verifies it against the
// known signing keys (refreshing them once if the kid is new).
func (f *Fleet) envelope(ctx context.Context, body []byte, p *policy.Policy, sig Signature) ([]byte, error) {
	if sig.Alg != "" && sig.Alg != "Ed25519" {
		return nil, errors.New("fleet: unexpected signature algorithm")
	}
	env, err := policy.Envelope(body, p, sig.Kid, sig.Sig)
	if err != nil {
		return nil, err
	}
	if _, err := policy.Verify(env, f.keyRing()); err == nil {
		return env, nil
	} else if !errors.Is(err, policy.ErrUnknownKid) {
		return nil, err
	}
	if err := f.refreshSigningKeys(ctx); err != nil {
		return nil, err
	}
	if _, err := policy.Verify(env, f.keyRing()); err != nil {
		return nil, err
	}
	return env, nil
}

// activate stores a signed version as active and supersedes the previous
// active one, inside tx.
func activate(ctx context.Context, tx *sql.Tx, pid string, ver int64, class string, need int, diff []DiffEntry, groups []string,
	seq int64, notAfter time.Time, hash string, body, env []byte, kid, mode, decidedBy string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE fleet_policy_versions SET status = ? WHERE policy_id = ? AND status = ?`, StatusSuperseded, pid, StatusActive); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE fleet_policy_versions SET status = ?, classification = ?, approvals_required = ?, diff = ?, targets = ?,
		issued_seq = ?, not_after = ?, hash = ?, body = ?, envelope = ?, signer_kid = ?, approval_mode = ?, decided_by = ?, decided_at = ?
		WHERE policy_id = ? AND version = ?`,
		StatusActive, class, need, mustJSON(diff), mustJSON(groups), seq, notAfter.Unix(), hash, body, env, kid, mode, decidedBy, now.Unix(), pid, ver)
	return err
}

func (f *Fleet) installActive(body, env []byte, hash string) {
	ap, err := newActive(body, env, hash)
	if err != nil {
		return // cannot happen: the body was just compiled and verified
	}
	f.mu.Lock()
	f.signed[hash] = body
	f.active[ap.policyID] = ap
	f.mu.Unlock()
}

// RenewExpiringPolicies re-signs, through keyguard's renew operation
// (keyguard.md 3.3), every active version whose not_after is within
// PolicyRenewBefore. The renewed body differs only in version, issued_seq,
// created_at and not_after. A policy whose discovery or auto_words window
// has passed cannot be recompiled and is left to expire (humans must
// propose a new version); this is logged and audited.
//
// After a key rotation it also re-signs every active version signed by a
// kid other than keyguard's active one, so that no source still runs a
// policy signed by the old key when it is revoked (policy.md 3.1).
func (f *Fleet) RenewExpiringPolicies(ctx context.Context) {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	now := f.now()
	f.mu.RLock()
	rotated := ""
	if f.kgKnown && hasKid(f.keys, f.kgStatus.PolicyKid) {
		rotated = f.kgStatus.PolicyKid
	}
	var due []*activePolicy
	for _, ap := range f.active {
		if ap.notAfter.Sub(now) < f.opts.PolicyRenewBefore || (rotated != "" && ap.signerKid != "" && ap.signerKid != rotated) {
			due = append(due, ap)
		}
	}
	f.mu.RUnlock()
	sort.Slice(due, func(i, j int) bool { return due[i].policyID < due[j].policyID })
	for _, ap := range due {
		if !f.stillBound(ap) {
			// Every group of this version was unbound or moved to another
			// policy: nothing runs it, so it is not renewed and lapses.
			key := ap.policyID + "\x00" + itoa(ap.version)
			f.mu.Lock()
			seen := f.renewSkipped[key]
			f.renewSkipped[key] = true
			f.mu.Unlock()
			if !seen {
				f.log.InfoContext(ctx, "fleet: policy not renewed, no group is bound to it", "policy_id", ap.policyID, "version", ap.version)
				f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"}, Action: "policy.renew", Target: audit.Target{Type: "policy", ID: ap.policyID},
					Outcome: audit.Denied, Reason: "no_bound_group", Details: map[string]string{"version": itoa(ap.version)}})
			}
			continue
		}
		// Expired discovery or automatic path words windows: the body cannot
		// be recompiled as is; a closing version without them replaces it.
		if done, err := f.closeExpiredWindows(ctx, ap, now); done || err != nil {
			if err != nil {
				f.log.WarnContext(ctx, "fleet: closing expired windows failed", "policy_id", ap.policyID, "err", err)
			}
			continue
		}
		if err := f.renewOne(ctx, ap, now); err != nil {
			code := "renew_failed"
			var ae *APIError
			if errors.As(err, &ae) {
				code = ae.Code
			}
			f.log.WarnContext(ctx, "fleet: policy renewal failed", "policy_id", ap.policyID, "version", ap.version, "code", code)
			f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"}, Action: "policy.renew", Target: audit.Target{Type: "policy", ID: ap.policyID},
				Outcome: audit.Failure, Reason: audit.SafeValue(code), Details: map[string]string{"version": itoa(ap.version)}})
		}
	}
}

// stillBound reports whether at least one group named by the signed targets
// of ap is still bound to its policy (policy_id of the group).
func (f *Fleet) stillBound(ap *activePolicy) bool {
	bound := f.boundGroups(ap.policyID)
	for _, g := range ap.groups {
		if slices.Contains(bound, g) {
			return true
		}
	}
	return false
}

func (f *Fleet) renewOne(ctx context.Context, ap *activePolicy, now time.Time) error {
	var author string
	if err := f.db.QueryRowContext(ctx, `SELECT author FROM fleet_policy_versions WHERE policy_id = ? AND version = ?`, ap.policyID, ap.version).Scan(&author); err != nil {
		return err
	}
	a, err := ParseAuthor([]byte(author))
	if err != nil {
		return err
	}
	var ver, seq int64
	if err := f.db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		if ver, err = nextVersion(ctx, tx, ap.policyID); err != nil {
			return err
		}
		seq, err = nextIssuedSeq(ctx, tx)
		return err
	}); err != nil {
		return err
	}
	body, cand, err := f.compileFor(a, ver, seq, ap.groups, now)
	if err != nil {
		return err
	}
	sig, err := f.signer.RenewPolicy(ctx, body)
	if err != nil {
		var refused *SignRefusedError
		if errors.As(err, &refused) {
			return keyguardRefusal(refused, "")
		}
		return err
	}
	env, err := f.envelope(ctx, body, cand, sig)
	if err != nil {
		return err
	}
	hash := policy.Hash(body)
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_policy_versions(policy_id, version, status, origin, author, proposed_by, proposed_by_name, proposed_at,
			classification, approvals_required, diff, targets, draft_body) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			ap.policyID, ver, StatusDraft, OriginRenew, author, systemUser, systemUser, now.Unix(), Closing, 1, "[]", mustJSON(ap.groups), body); err != nil {
			return err
		}
		return activate(ctx, tx, ap.policyID, ver, Closing, 1, []DiffEntry{}, ap.groups, seq, cand.NotAfter, hash, body, env, sig.Kid, "", systemUser, now)
	})
	if err != nil {
		return err
	}
	f.installActive(body, env, hash)
	f.record(ctx, audit.Event{Actor: audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"}, Action: "policy.renew", Target: audit.Target{Type: "policy", ID: ap.policyID},
		Outcome: audit.Success, Details: map[string]string{"version": itoa(ver), "issued_seq": itoa(seq), "hash": hash,
			"not_after": cand.NotAfter.Format(time.RFC3339)}})
	return nil
}

// CurrentEnvelope returns the signed envelope a group must run, or nil.
func (f *Fleet) CurrentEnvelope(group string) (env []byte, hash string) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if ap := f.currentFor(group); ap != nil {
		return ap.envelope, ap.hash
	}
	return nil, ""
}

// ApprovalSettings is the approval configuration shown to the UI.
type ApprovalSettings struct {
	// OpeningRequired is approvals.opening_required as enforced by keyguard.
	OpeningRequired int `json:"opening_required"`
	// AdminOverride reports whether an admin may approve alone with a reason.
	AdminOverride bool `json:"admin_override"`
	// ApprovalsUnverified is true when keyguard trusts identities declared
	// by tt-core (no OIDC).
	ApprovalsUnverified bool `json:"approvals_unverified"`
	// Known is false while keyguard has not been reached yet (the values
	// are then the strict defaults).
	Known bool `json:"known"`
}

// GetApprovalSettings returns the approval settings read from keyguard.
func (f *Fleet) GetApprovalSettings() ApprovalSettings {
	st, known := f.approvalSettings()
	return ApprovalSettings{OpeningRequired: st.OpeningApprovals, AdminOverride: st.AdminOverride, ApprovalsUnverified: st.ApprovalsUnverified, Known: known}
}
