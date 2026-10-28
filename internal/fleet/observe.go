package fleet

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// Observe phase (policy.md 7, spec v1.6).
//
// Connecting a source is plug & play: the group gets the starter policy at
// once (structure only: every value dropped, discovery and automatic path
// words for a few days), signed by keyguard without approvals because it
// opens no value. Once tt-core has seen enough shapes (ObserveOptions.After
// or MinEvents), it derives by itself the observe version: hmac on the
// fields the policy assistant classifies as identifiers and, when the
// requests carry it, identity.subject from the source the automatic
// detection picks from the data (the bearer JWT claim sub, or the request
// header that behaves like a user id, identity_detect.go). That version is observe-safe
// too: it is applied without approval, signed as usual, audited with the
// system as actor and origin observe-auto. Only a change that opens values
// (keep, bucket, another identity source...) waits for approvals.

// ObserveOptions configure the observe phase.
type ObserveOptions struct {
	// Enabled turns on the automatic observe version (fleet.observe.enabled).
	Enabled bool
	// After: the observe version is derived at the latest this long after
	// the starter policy was activated, if any call was seen (default 15m).
	After time.Duration
	// MinEvents: it is derived as soon as this many calls were seen under
	// the policy (default 200).
	MinEvents int
	// Interval of the observe pass (default 1m).
	Interval time.Duration
	// NoCodes: the observe version never proposes `code` (fleet.observe.codes
	// false: sources older than v1.11 would refuse the policy).
	NoCodes bool
	// NoCodeDigits: the observe version never proposes code(alnum)
	// (fleet.observe.code_digits false: sources older than v1.19).
	NoCodeDigits bool
	// Quarantined reports whether the intake quarantined the kept values of
	// a field (more distinct values than the cardinality threshold,
	// event.md 5.2): the observe version never proposes code on it again.
	// part is request or response, path as in the assistant. Optional.
	Quarantined func(policyID, service, op, part, path string) bool
	// NoGraphQL: the observe version never proposes `graphql` on the
	// GraphQL endpoints it recognizes (fleet.observe.graphql false: sources
	// older than v1.14 would refuse the policy).
	NoGraphQL bool
}

// Defaults of ObserveOptions.
const (
	DefaultObserveAfter     = 15 * time.Minute
	DefaultObserveMinEvents = 200
	DefaultObserveInterval  = time.Minute
	// DefaultObserveSampling is the sampling of the starter policy when the
	// person does not choose one: with the default k (20) and the target of
	// twice k users, about 400 users in the traffic are enough.
	DefaultObserveSampling = "0.1"
)

// noteObserve is the note of the observe versions.
const noteObserve = "observe phase: identifiers masked automatically"

// systemPrincipal is the actor of the automatic versions.
func systemPrincipal() *auth.Principal {
	return &auth.Principal{UserID: systemUser, Username: systemUser, DisplayName: systemUser}
}

// actorOf is the audit actor of p: the system for the automatic versions.
func actorOf(p *auth.Principal) audit.Actor {
	if p != nil && p.UserID == systemUser {
		return audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"}
	}
	return p.AuditActor()
}

// Classification is the answer of ClassifyAuthor (classifyPolicy).
type Classification struct {
	PolicyID       string `json:"policy_id"`
	Classification string `json:"classification"`
	// OpensValues false: the change applies at once, without approval.
	OpensValues       bool                 `json:"opens_values"`
	ValueReasons      []policy.ValueReason `json:"value_reasons"`
	ApprovalsRequired int                  `json:"approvals_required"`
	Diff              []DiffEntry          `json:"diff"`
}

// ClassifyAuthor classifies an author policy against the version active now
// and the groups bound now, without storing anything.
func (f *Fleet) ClassifyAuthor(ctx context.Context, author []byte) (*Classification, error) {
	a, err := ParseAuthor(author)
	if err != nil {
		return nil, err
	}
	groups := f.boundGroups(a.PolicyID)
	if len(groups) == 0 {
		groups = []string{"classify-check"}
	}
	_, cand, err := f.compileFor(a, 1, peekSeq(ctx, f.db), groups, f.now())
	if err != nil {
		return nil, err
	}
	class, diff := Classify(f.activeBody(a.PolicyID), cand)
	vc := f.valueClass(a.PolicyID, cand)
	return &Classification{PolicyID: a.PolicyID, Classification: class, OpensValues: vc.OpensValues, ValueReasons: nonNilReasons(vc.Reasons),
		ApprovalsRequired: f.required(class, OriginPropose, vc.OpensValues), Diff: diff}, nil
}

// applyObserveSafe signs a draft that needs no approval (policy.md 7) and
// activates it. keyguard recomputes the verdict itself: when it says the
// change opens values the draft stays pending with the opening number of
// approvals. Caller holds policyMu.
func (f *Fleet) applyObserveSafe(ctx context.Context, p *auth.Principal, v *PolicyVersion) (*PolicyVersion, error) {
	pid, ver := v.PolicyID, v.Version
	var newer int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_policy_versions WHERE policy_id = ? AND version > ? AND issued_seq IS NOT NULL AND origin != ?`,
		pid, ver, OriginRenew).Scan(&newer); err != nil {
		return nil, err
	}
	if newer > 0 {
		return nil, conflict("stale_draft", "a newer version was signed: propose this change again")
	}
	a, err := ParseAuthor([]byte(v.AuthorYAML))
	if err != nil {
		return nil, err
	}
	groups := f.boundGroups(pid)
	now := f.now()
	_, cand, err := f.compileFor(a, ver, peekSeq(ctx, f.db), groups, now)
	if err != nil {
		return nil, err
	}
	class, diff := Classify(f.activeBody(pid), cand)
	vc := f.valueClass(pid, cand)
	if hasKeyguardVerdict(v.ValueReasons) {
		vc.Reasons, vc.OpensValues = append(vc.Reasons, keyguardVerdict), true
	}
	if need := f.required(class, v.Origin, vc.OpensValues); need != 0 {
		// The bound groups or the active version changed: it opens values now.
		if _, err := f.db.ExecContext(ctx, `UPDATE fleet_policy_versions SET classification = ?, approvals_required = ?, diff = ?, targets = ?, value_reasons = ?
			WHERE policy_id = ? AND version = ? AND status = ?`, class, need, mustJSON(diff), mustJSON(groups), mustJSON(nonNilReasons(vc.Reasons)), pid, ver, StatusDraft); err != nil {
			return nil, err
		}
		return f.GetPolicyVersion(ctx, pid, ver)
	}
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
	proposer := v.proposedByID
	if proposer == "" {
		proposer = systemUser
	}
	sig, err := f.signer.SignPolicy(ctx, SignRequest{Body: body, Proposer: proposer})
	if err != nil {
		var refused *SignRefusedError
		code := "keyguard_unavailable"
		if errors.As(err, &refused) {
			code = "keyguard_refused"
		}
		f.record(ctx, audit.Event{Actor: actorOf(p), Action: "policy.sign", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Failure,
			Reason: code, Details: map[string]string{"version": itoa(ver), "issued_seq": itoa(seq), "keyguard_code": refusalCode(refused), "approval_mode": ApprovalObserve}})
		if refused != nil {
			if refused.Code == "insufficient_approvals" || refused.Code == "approvals_insufficient" {
				// keyguard's own verdict: the change opens values.
				st, _ := f.approvalSettings()
				_, _ = f.db.ExecContext(ctx, `UPDATE fleet_policy_versions SET approvals_required = ?, value_reasons = ? WHERE policy_id = ? AND version = ? AND status = ?`,
					st.OpeningApprovals, mustJSON(append(nonNilReasons(vc.Reasons), keyguardVerdict)), pid, ver, StatusDraft)
			}
			return nil, keyguardRefusal(refused, "keyguard refused to sign: ")
		}
		f.log.ErrorContext(ctx, "fleet: keyguard signing failed", "err", err)
		return nil, apiErr(502, "keyguard_unavailable", "keyguard could not be reached")
	}
	env, err := f.envelope(ctx, body, cand, sig)
	if err != nil {
		f.record(ctx, audit.Event{Actor: actorOf(p), Action: "policy.sign", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Failure,
			Reason: "signature_invalid", Details: map[string]string{"version": itoa(ver), "kid": audit.SafeValue(sig.Kid)}})
		return nil, apiErr(502, "signature_invalid", "keyguard returned a signature that does not verify")
	}
	mode := sig.ApprovalMode
	if mode == "" {
		mode = ApprovalObserve
	}
	if sig.Classification == Opening || sig.Classification == Closing {
		class = sig.Classification
	}
	hash := policy.Hash(body)
	decidedBy := p.UserID
	err = f.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE fleet_policy_versions SET value_reasons = ? WHERE policy_id = ? AND version = ?`, "[]", pid, ver); err != nil {
			return err
		}
		return activate(ctx, tx, pid, ver, class, 0, diff, groups, seq, cand.NotAfter, hash, body, env, sig.Kid, mode, decidedBy, now)
	})
	if err != nil {
		return nil, err
	}
	f.installActive(body, env, hash)
	det := map[string]string{"version": itoa(ver), "issued_seq": itoa(seq), "hash": hash, "kid": audit.SafeValue(sig.Kid),
		"classification": class, "approval_mode": mode, "origin": audit.SafeValue(v.Origin), "opens_values": "false",
		"groups": audit.SafeValue(strings.Join(groups, ","))}
	f.record(ctx, audit.Event{Actor: actorOf(p), Action: "policy.activate", Target: audit.Target{Type: "policy", ID: pid}, Outcome: audit.Success, Details: det})
	return f.GetPolicyVersion(ctx, pid, ver)
}

// observeOrigins are the origins of the versions of the observe phase: a
// version with another origin was signed by a person (proposed, approved,
// a rollback...). Since spec v1.6.1 tt-core keeps deriving after such a
// version, but only for the identifier fields nobody chose for: a field
// with a rule stays as written, and a field whose rule a person removed
// (set back to drop) is never masked again by itself (humanChoices).
var observeOrigins = map[string]bool{OriginStarter: true, OriginObserveAuto: true, OriginRenew: true, OriginRetarget: true}

// observeState reads the observe phase of pid from its versions.
type observeState struct {
	started       time.Time // decided_at of the first signed starter version
	managed       bool      // a version with another origin was signed
	observeVer    int64     // last signed observe-auto version (0: none)
	observeAt     time.Time
	pendingDrafts []int64 // drafts not decided yet
	zeroDrafts    []int64 // drafts that need no approval (not signed yet)
}

func (f *Fleet) readObserveState(ctx context.Context, pid string) (*observeState, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT version, status, origin, issued_seq IS NOT NULL, COALESCE(decided_at, 0), approvals_required
		FROM fleet_policy_versions WHERE policy_id = ? ORDER BY version`, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	st := &observeState{}
	for rows.Next() {
		var ver, decided int64
		var status, origin string
		var signed bool
		var need int
		if err := rows.Scan(&ver, &status, &origin, &signed, &decided, &need); err != nil {
			return nil, err
		}
		switch {
		case status == StatusDraft:
			st.pendingDrafts = append(st.pendingDrafts, ver)
			if need == 0 {
				st.zeroDrafts = append(st.zeroDrafts, ver)
			}
		case signed && !observeOrigins[origin]:
			st.managed = true
		case signed && origin == OriginStarter && st.started.IsZero():
			st.started = time.Unix(decided, 0).UTC()
		case signed && origin == OriginObserveAuto:
			st.observeVer, st.observeAt = ver, time.Unix(decided, 0).UTC()
		}
	}
	return st, rows.Err()
}

// humanChoice is what the people who signed versions of a policy decided
// against automatic masking: the fields whose rule a person removed (back to
// the default drop) and whether a person removed identity.subject.
type humanChoice struct {
	removed         map[string]bool // ruleKey
	identityRemoved bool
}

// ruleKey names a field rule of an author policy: service, operation ("" for
// the service scope), part and path as in the assistant ("$.id",
// "query.x", "headers.x", "cookies.x", "path.x").
func ruleKey(svc, op, part, path string) string {
	return svc + "\x00" + op + "\x00" + part + "\x00" + path
}

// authorRules lists the field rules of an author policy (ruleKey).
func authorRules(a *policy.Author) map[string]bool {
	out := map[string]bool{}
	addPart := func(svc, op, part string, ap *policy.AuthorPart) {
		if ap == nil {
			return
		}
		for k := range ap.Body {
			out[ruleKey(svc, op, part, k)] = true
		}
		for kind, m := range map[string]map[string]string{"query": ap.Query, "headers": ap.Headers, "cookies": ap.Cookies, "path": ap.Path} {
			for k := range m {
				out[ruleKey(svc, op, part, kind+"."+k)] = true
			}
		}
	}
	for name, s := range a.Services {
		addPart(name, "", "request", s.Request)
		addPart(name, "", "response", s.Response)
		for op, o := range s.Ops {
			addPart(name, op, "request", o.Request)
			addPart(name, op, "response", o.Response)
		}
	}
	return out
}

// humanChoices walks the signed versions of pid in signing order: every
// field rule (and identity.subject) present before a version signed by a
// person and absent from it was removed by that person.
func (f *Fleet) humanChoices(ctx context.Context, pid string) (*humanChoice, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT origin, author FROM fleet_policy_versions WHERE policy_id = ? AND issued_seq IS NOT NULL ORDER BY issued_seq`, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hc := &humanChoice{removed: map[string]bool{}}
	var prev map[string]bool
	prevSubject := false
	for rows.Next() {
		var origin, doc string
		if err := rows.Scan(&origin, &doc); err != nil {
			return nil, err
		}
		a, err := ParseAuthor([]byte(doc))
		if err != nil {
			continue // stored before a grammar change: nothing to learn from it
		}
		cur := authorRules(a)
		if prev != nil && !observeOrigins[origin] {
			for k := range prev {
				if !cur[k] {
					hc.removed[k] = true
				}
			}
			if prevSubject && a.Subject == nil {
				hc.identityRemoved = true
			}
		}
		for k := range cur {
			delete(hc.removed, k) // a person (or tt-core) wrote a rule again
		}
		if a.Subject != nil {
			hc.identityRemoved = false
		}
		prev, prevSubject = cur, a.Subject != nil
	}
	return hc, rows.Err()
}

// removedByPerson reports whether a person removed the rule of the field,
// in the operation or in the service scope.
func (hc *humanChoice) removedByPerson(svc, op, part, path string) bool {
	if hc == nil {
		return false
	}
	return hc.removed[ruleKey(svc, op, part, path)] || hc.removed[ruleKey(svc, "", part, path)]
}

// ObserveAutoOf reports the per-group switch of the automatic observe
// versions (true unless someone turned it off).
func (f *Fleet) ObserveAutoOf(ctx context.Context, group string) (bool, error) {
	var on int
	err := f.db.QueryRowContext(ctx, `SELECT observe_auto FROM fleet_groups WHERE name = ?`, group).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errNotFound
	}
	return on == 1, err
}

// SetObserveAuto turns the automatic observe versions of a group on or off
// (admin-api setObserveAuto). Off: tt-core derives nothing by itself for a
// policy bound to the group; the versions already signed stay.
func (f *Fleet) SetObserveAuto(ctx context.Context, p *auth.Principal, group string, on bool) error {
	res, err := f.db.ExecContext(ctx, `UPDATE fleet_groups SET observe_auto = ?, updated_at = ? WHERE name = ?`, boolInt(on), f.now().Unix(), group)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	f.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "fleet.group_observe_auto", Target: audit.Target{Type: "group", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"auto": strconv.FormatBool(on)}})
	return nil
}

// autoOff reports whether a group bound to pid turned the automation off.
func (f *Fleet) autoOff(ctx context.Context, pid string) (bool, error) {
	var n int
	err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_groups WHERE policy_id = ? AND observe_auto = 0`, pid).Scan(&n)
	return n > 0, err
}

// observedPolicies lists the policies bound to a group.
func (f *Fleet) observedPolicies() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	set := map[string]bool{}
	for _, g := range f.groups {
		if g.policyID != "" {
			set[g.policyID] = true
		}
	}
	out := make([]string, 0, len(set))
	for pid := range set {
		out = append(out, pid)
	}
	sort.Strings(out)
	return out
}

// ObserveTick runs one pass of the observe phase over every bound policy:
// it signs the observe-safe drafts still pending (keyguard was unreachable)
// and derives the observe version where it is due.
func (f *Fleet) ObserveTick(ctx context.Context) {
	if !f.opts.Observe.Enabled {
		return
	}
	if st, known := f.approvalSettings(); !known || !st.ObserveAuto {
		return
	}
	for _, pid := range f.observedPolicies() {
		if err := f.observeOne(ctx, pid); err != nil {
			code := "observe_failed"
			var ae *APIError
			if errors.As(err, &ae) {
				code = ae.Code
			}
			f.log.WarnContext(ctx, "fleet: observe pass failed", "policy_id", pid, "code", code)
		}
	}
}

func (f *Fleet) observeOne(ctx context.Context, pid string) error {
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	st, err := f.readObserveState(ctx, pid)
	if err != nil {
		return err
	}
	sys := systemPrincipal()
	for _, ver := range st.zeroDrafts {
		v, err := f.GetPolicyVersion(ctx, pid, ver)
		if err != nil {
			return err
		}
		if v.ApprovalsRequired == 0 {
			if _, err := f.applyObserveSafe(ctx, sys, v); err != nil {
				return err
			}
		}
	}
	if len(st.zeroDrafts) > 0 {
		if st, err = f.readObserveState(ctx, pid); err != nil {
			return err
		}
	}
	// A pending draft would become stale once another version is signed
	// (stale_draft): tt-core waits until the people decided on it.
	if st.started.IsZero() || len(st.pendingDrafts) > 0 || f.activeBody(pid) == nil {
		return nil
	}
	if off, err := f.autoOff(ctx, pid); err != nil || off {
		return err
	}
	f.mu.RLock()
	d := f.discovery
	f.mu.RUnlock()
	if d == nil {
		return nil
	}
	res, err := f.AssistIn(ctx, pid, "")
	if err != nil {
		return err
	}
	calls := observedCalls(res)
	minEvents := f.opts.Observe.MinEvents
	if calls == 0 || (calls < int64(minEvents) && f.now().Sub(st.started) < f.opts.Observe.After) {
		return nil
	}
	cur, err := f.latestAuthor(ctx, pid)
	if err != nil {
		return err
	}
	a, err := ParseAuthor(cur)
	if err != nil {
		return err
	}
	var hc *humanChoice
	if st.managed {
		if hc, err = f.humanChoices(ctx, pid); err != nil {
			return err
		}
	}
	codes := codeOptions{on: !f.opts.Observe.NoCodes, alnum: !f.opts.Observe.NoCodes && !f.opts.Observe.NoCodeDigits}
	if q := f.opts.Observe.Quarantined; q != nil {
		codes.quarantined = func(svc, op, part, path string) bool { return q(pid, svc, op, part, path) }
	}
	req := observeDecisions(res, a, hc, codes)
	if !f.opts.Observe.NoGraphQL {
		addGraphQLDecisions(&req, res, a, hc)
	}
	if len(req.Services) == 0 && req.Identity == nil {
		return nil
	}
	built, err := f.observeSafeDraft(ctx, pid, req)
	if err != nil || built == nil {
		return err
	}
	_, err = f.createDraftFolding(ctx, sys, []byte(built.After), OriginObserveAuto, noteObserve, nil)
	return err
}

// observeSafeDraft builds the observe version of the decisions. When the
// whole of it would open values (with values in the policy an hmac can, for
// instance, reach the descendant of a dropped container: policy.md 7.2) it
// keeps the services whose decisions alone do not, and audits the refusal
// once per refused content. nil: nothing to apply. Caller holds policyMu.
func (f *Fleet) observeSafeDraft(ctx context.Context, pid string, req AssistDraftRequest) (*AssistDraftResult, error) {
	built, folded, err := f.buildAssistDraft(ctx, pid, req)
	if err != nil || len(folded) > 0 || built.After == built.Before {
		return nil, err
	}
	if !built.OpensValues {
		return built, nil
	}
	refused := built
	safe := AssistDraftRequest{}
	if req.Identity != nil {
		one := AssistDraftRequest{Identity: req.Identity}
		if b, _, err := f.buildAssistDraft(ctx, pid, one); err == nil && !b.OpensValues {
			safe.Identity = req.Identity
		}
	}
	for _, s := range req.Services {
		one := AssistDraftRequest{Services: []AssistDraftService{s}}
		if b, _, err := f.buildAssistDraft(ctx, pid, one); err == nil && !b.OpensValues {
			safe.Services = append(safe.Services, s)
		}
	}
	if len(safe.Services) > 0 || safe.Identity != nil {
		if b, _, err := f.buildAssistDraft(ctx, pid, safe); err == nil && !b.OpensValues && b.After != b.Before {
			built = b
		} else {
			built = nil
		}
	} else {
		built = nil
	}
	// Never applied: the decisions are hmac and automatic identities only.
	// A derivation that would open values is refused and audited (once for
	// the same content: the pass runs every minute).
	hash := hashText(refused.After)
	f.mu.Lock()
	if f.observeRefused == nil {
		f.observeRefused = map[string]string{}
	}
	seen := f.observeRefused[pid] == hash
	f.observeRefused[pid] = hash
	f.mu.Unlock()
	if !seen {
		code := "opens_values"
		if len(refused.ValueReasons) > 0 {
			code = refused.ValueReasons[0].Code
		}
		f.record(ctx, audit.Event{Actor: actorOf(systemPrincipal()), Action: "policy." + OriginObserveAuto, Target: audit.Target{Type: "policy", ID: pid},
			Outcome: audit.Denied, Reason: audit.SafeValue(code)})
	}
	return built, nil
}

func observedCalls(res *AssistResult) int64 {
	var n int64
	for _, s := range res.Services {
		n += s.Calls
	}
	return n
}

// observeDecisions picks, from the assistant's proposals, what the observe
// version applies: hmac on the identifiers (reason id or path_id) of the
// services the policy can declare without a person (own services and
// declared external ones), only on fields without a rule, and the
// automatic identity when the policy has none.
func observeDecisions(res *AssistResult, a *policy.Author, hc *humanChoice, codes codeOptions) AssistDraftRequest {
	req := AssistDraftRequest{}
	for _, s := range res.Services {
		if s.Kind == "external" && !s.Declared {
			continue // its base (scheme) cannot be guessed
		}
		ds := AssistDraftService{Service: s.Service, Name: s.Name}
		for _, o := range s.Ops {
			var rules []AssistDraftRule
			for _, fl := range o.Fields {
				if action, ok := codes.candidate(fl); ok {
					if codes.quarantined != nil && codes.quarantined(s.Name, o.Op, fl.Part, fl.Path) {
						continue // too many distinct values: an identifier, never a code again
					}
					if !authorHasRule(a, s.Name, o.Op, fl.Part, fl.Path) && !hc.removedByPerson(s.Name, o.Op, fl.Part, fl.Path) {
						rules = append(rules, AssistDraftRule{Part: fl.Part, Path: fl.Path, Action: action})
					}
					continue
				}
				if !strings.HasPrefix(fl.Suggestion, "hmac(") || (fl.ReasonCode != "id" && fl.ReasonCode != "path_id") {
					continue
				}
				if h, ok := strings.CutPrefix(fl.Path, "headers."); ok && (policy.CredentialHeaders[h] || policy.ForbiddenKeepHeaders[h]) {
					continue
				}
				if authorHasRule(a, s.Name, o.Op, fl.Part, fl.Path) || hc.removedByPerson(s.Name, o.Op, fl.Part, fl.Path) {
					continue // a person (or an earlier pass) chose for this field
				}
				rules = append(rules, AssistDraftRule{Part: fl.Part, Path: fl.Path, Action: fl.Suggestion})
			}
			if len(rules) > 0 {
				ds.Ops = append(ds.Ops, AssistDraftOp{Op: o.Op, Rules: rules})
			}
		}
		if len(ds.Ops) > 0 && policy.ValidServiceName(ds.Name) {
			req.Services = append(req.Services, ds)
		}
	}
	// Who the user is: the automatic detection (identity_detect.go) picks it
	// from the data, never a person's choice (a.Subject set, or removed).
	if a.Subject == nil && (hc == nil || !hc.identityRemoved) && res.IdentityBest != nil {
		id := *res.IdentityBest
		req.Identity = &id
	}
	return req
}

// codeOptions are the code proposals of the observe version: on
// (fleet.observe.codes), alnum (fleet.observe.code_digits, spec v1.19) and
// the fields the intake quarantined.
type codeOptions struct {
	on, alnum   bool
	quarantined func(service, op, part, path string) bool
}

// candidate returns the code action the observe version puts on a field
// (policy.md 1.5, sanitizer.md 5.6): "code" or "code(alnum)" on a status-
// or code-like name allowed by policy.CodeRuleAllowed, with a short string
// or digits shape (policy.CodeProposalShape), seen often enough and with
// few distinct values. The source still lets out only values with the
// shape of a code; the others stay shapes. The intake quarantines a field
// whose kept values exceed the cardinality threshold.
func (o codeOptions) candidate(fl Suggestion) (string, bool) {
	if !o.on || !codeCandidate(fl) {
		return "", false
	}
	kind, name := codeKindName(fl.Path)
	shape, ok := policy.CodeProposalShape(kind, name, fl.Shape, o.alnum)
	if !ok {
		return "", false
	}
	if shape == policy.CodeShapeAlnum {
		return "code(alnum)", true
	}
	return "code", true
}

// codeKindName splits an assistant path into the code rule kind and name.
func codeKindName(path string) (string, string) {
	if strings.HasPrefix(path, "$") {
		return policy.CodePartBody, path
	}
	k, n, _ := strings.Cut(path, ".")
	return k, n
}

// codeCandidate reports whether a field may receive a code rule from the
// observe version: a status- or code-like name allowed by
// policy.CodeRuleAllowed, a short string or digits shape, seen often enough
// and with few distinct values.
func codeCandidate(fl Suggestion) bool {
	if fl.Shape != "drop:str:l8" && fl.Shape != "drop:str:l32" && fl.Shape != "drop:str:digits" {
		return false
	}
	if fl.Observed < assistMinObserved || fl.DistinctEstimate < 1 || fl.DistinctEstimate > assistEnumMax {
		return false
	}
	switch fl.ReasonCode {
	case "credential", "personal_format", "personal_name", "dynamic_name", "trace":
		return false
	}
	var kind, name string
	switch {
	case strings.HasPrefix(fl.Path, "$"):
		kind, name = policy.CodePartBody, fl.Path
	default:
		k, n, ok := strings.Cut(fl.Path, ".")
		if !ok || k != "query" {
			// path segments are words or identifiers; header values (content-type,
			// accept…) are never codes; cookies never.
			return false
		}
		kind, name = k, n
	}
	return policy.CodeRuleAllowed(kind, name)
}

// authorHasRule reports whether the author policy has a rule for the field
// (path as in the assistant: "$.id", "query.x", "headers.x", "cookies.x",
// "path.x") in the operation or the service scope.
func authorHasRule(a *policy.Author, svc, op, part, path string) bool {
	s, ok := a.Services[svc]
	if !ok {
		return false
	}
	has := func(ap *policy.AuthorPart) bool {
		if ap == nil {
			return false
		}
		if strings.HasPrefix(path, "$") {
			_, ok := ap.Body[path]
			return ok
		}
		kind, name, _ := strings.Cut(path, ".")
		m := map[string]map[string]string{"query": ap.Query, "headers": ap.Headers, "cookies": ap.Cookies, "path": ap.Path}[kind]
		_, ok := m[name]
		return ok
	}
	if o, ok := s.Ops[op]; ok {
		if (part == "request" && has(o.Request)) || (part == "response" && has(o.Response)) {
			return true
		}
	}
	if part == "request" {
		return has(s.Request)
	}
	return has(s.Response)
}

// ObserveStatus is the live state of the observe phase of a group
// (admin-api getObserveStatus): what the wizard shows while it listens.
type ObserveStatus struct {
	Group    string `json:"group"`
	PolicyID string `json:"policy_id,omitempty"`
	// Enabled: tt-core derives the observe version and keyguard signs
	// observe-safe changes without approvals.
	Enabled bool `json:"enabled"`
	// Auto is the group's switch of the automatic observe versions
	// (setObserveAuto, default true). With Enabled and Auto tt-core keeps
	// masking the identifiers it sees for the first time, also after a
	// person's change (phase managed), never a field a person chose for.
	Auto bool `json:"auto"`
	// Phase: no_policy | waiting_approval | listening | masked | managed.
	Phase         string `json:"phase"`
	ActiveVersion int64  `json:"active_version,omitempty"`
	// StartedAt: the starter policy was activated (capture started).
	StartedAt *time.Time `json:"started_at,omitempty"`
	// DueAt: the observe version is derived at the latest then (if calls
	// were seen); MinEvents calls bring it forward.
	DueAt              *time.Time `json:"due_at,omitempty"`
	MinEvents          int        `json:"min_events"`
	Events             int64      `json:"events"`
	ObserveVersion     int64      `json:"observe_version,omitempty"`
	ObserveActivatedAt *time.Time `json:"observe_activated_at,omitempty"`
	// DiscoveryUntil: discovery and automatic path words stay on until then.
	DiscoveryUntil *time.Time        `json:"discovery_until,omitempty"`
	SamplingBP     int               `json:"sampling_bp"`
	Services       []ObservedService `json:"services"`
	Masked         []MaskedField     `json:"masked"`
	Identity       *AssistIdentity   `json:"identity,omitempty"`
	// IdentityCandidates ranks who the user may be, with the signals of the
	// automatic detection (names, counts, shapes, scores: never a value);
	// IdentityBest is the source the detection picks.
	IdentityCandidates []IdentityCandidate `json:"identity_candidates"`
	IdentityBest       *AssistIdentity     `json:"identity_best,omitempty"`
	Sampling           *SamplingAdvice     `json:"sampling,omitempty"`
	// Families are the HMAC domain families of the policy (spec v1.18,
	// hmac.families): family → joined domains.
	Families map[string][]string `json:"families"`
	// TestKMin is the lower k of a group marked as test (0: not a test
	// group; spec v1.18) and KMin the installation k.
	TestKMin int `json:"test_k_min"`
	KMin     int `json:"k_min"`
}

// ObservedService is one service seen under the policy.
type ObservedService struct {
	Service string `json:"service"`
	Kind    string `json:"kind"` // inbound | external
	Calls   int64  `json:"calls"`
	Ops     int    `json:"ops"`
}

// MaskedField is one rule of the active version that turns a field into a
// token (hmac): never a value.
type MaskedField struct {
	Service string `json:"service"`
	Op      string `json:"op,omitempty"`
	Part    string `json:"part"` // request | response | errors
	Kind    string `json:"kind"` // path | query | headers | cookies | body
	Field   string `json:"field"`
	Domain  string `json:"domain"`
}

// ObserveStatusOf returns the observe state of a group.
func (f *Fleet) ObserveStatusOf(ctx context.Context, group string) (*ObserveStatus, error) {
	g, err := f.GetGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	st, _ := f.approvalSettings()
	auto, err := f.ObserveAutoOf(ctx, group)
	if err != nil {
		return nil, err
	}
	out := &ObserveStatus{Group: group, Enabled: f.opts.Observe.Enabled && st.ObserveAuto, Auto: auto, MinEvents: f.opts.Observe.MinEvents,
		Phase: "no_policy", Services: []ObservedService{}, Masked: []MaskedField{}, IdentityCandidates: []IdentityCandidate{},
		Families: map[string][]string{}, KMin: f.kMin()}
	if out.TestKMin, err = f.TestKOf(ctx, group); err != nil {
		return nil, err
	}
	if g.PolicyID == nil {
		return out, nil
	}
	pid := *g.PolicyID
	out.PolicyID = pid
	if fams := f.familiesOf(ctx, pid); fams != nil {
		out.Families = fams
	}
	os, err := f.readObserveState(ctx, pid)
	if err != nil {
		return nil, err
	}
	f.mu.RLock()
	ap := f.active[pid]
	f.mu.RUnlock()
	act := f.activeBody(pid)
	switch {
	case act == nil && len(os.pendingDrafts) > 0:
		out.Phase = "waiting_approval"
	case act == nil:
		out.Phase = "no_policy"
	case os.managed:
		out.Phase = "managed"
	case os.observeVer > 0:
		out.Phase = "masked"
	default:
		out.Phase = "listening"
	}
	if ap != nil {
		out.ActiveVersion = ap.version
	}
	if !os.started.IsZero() {
		t := os.started
		out.StartedAt = &t
		due := t.Add(f.opts.Observe.After)
		out.DueAt = &due
	}
	if os.observeVer > 0 {
		t := os.observeAt
		out.ObserveVersion, out.ObserveActivatedAt = os.observeVer, &t
	}
	if act != nil {
		out.SamplingBP = act.Sampling.RateBP
		if act.Discovery != nil && act.Discovery.Enabled {
			t := act.Discovery.ExpiresAt
			out.DiscoveryUntil = &t
		}
		if s := act.Subject; s != nil {
			out.Identity = &AssistIdentity{From: s.From, Name: s.Name, JWTClaim: s.JWTClaim, JSONPath: s.JSONPath}
		}
		out.Masked = maskedFields(act)
	}
	f.mu.RLock()
	d := f.discovery
	f.mu.RUnlock()
	if d != nil && act != nil {
		if res, err := f.AssistIn(ctx, pid, group); err == nil {
			out.Events = observedCalls(res)
			out.Sampling = res.Sampling
			out.IdentityCandidates, out.IdentityBest = res.IdentityCandidates, res.IdentityBest
			for _, s := range res.Services {
				out.Services = append(out.Services, ObservedService{Service: s.Service, Kind: s.Kind, Calls: s.Calls, Ops: len(s.Ops)})
			}
		}
	}
	return out, nil
}

// noteIdentity is the note of the versions made by SetIdentity.
const noteIdentity = "user identity chosen in the console"

// SetIdentity sets identity.subject of the group's policy, replacing the
// one it has (admin-api setIdentity): a request header (any name that is
// not a credential applies at once: the value leaves only as a token,
// policy.md 7.1) or a cookie / credential-like header, which waits for the
// opening approvals. The version is proposed like any draft (audited) and,
// when observe-safe, signed and activated at once; the choice is audited
// as policy.identity_set. tt-core never replaces a person's choice
// afterwards.
func (f *Fleet) SetIdentity(ctx context.Context, p *auth.Principal, group string, id AssistIdentity) (*PolicyVersion, error) {
	g, err := f.GetGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	if g.PolicyID == nil {
		return nil, conflict("no_policy", "the group has no policy yet: connect a source first")
	}
	if id.From == "" {
		id.From = "header"
	}
	if id.From == "header" {
		id.Name = strings.ToLower(strings.TrimSpace(id.Name))
	}
	id.JWTClaim = strings.TrimSpace(id.JWTClaim)
	id.JSONPath = strings.TrimSpace(id.JSONPath)
	_, v, err := f.AssistDraftWith(ctx, p, *g.PolicyID, AssistDraftRequest{Identity: &id, ReplaceIdentity: true}, noteIdentity)
	if err != nil {
		return nil, err
	}
	f.record(ctx, audit.Event{Actor: actorOf(p), Action: "policy.identity_set", Target: audit.Target{Type: "group", ID: group}, Outcome: audit.Success,
		Details: map[string]string{"policy": v.PolicyID, "version": itoa(v.Version), "from": audit.SafeValue(id.From), "name": audit.SafeValue(id.Name),
			"jwt_claim": audit.SafeValue(id.JWTClaim), "json_path": audit.SafeValue(id.JSONPath), "status": v.Status, "opens_values": strconv.FormatBool(v.OpensValues)}})
	return v, nil
}

// maskedFields lists the hmac rules of a compiled policy, sorted.
func maskedFields(p *policy.Policy) []MaskedField {
	out := []MaskedField{}
	addPart := func(svc, op, part string, pt *policy.Part) {
		for kind, m := range map[string]map[string]policy.Action{"path": pt.Path, "query": pt.Query, "headers": pt.Headers, "cookies": pt.Cookies} {
			for name, a := range m {
				if a.Kind == policy.ActHMAC {
					out = append(out, MaskedField{Service: svc, Op: op, Part: part, Kind: kind, Field: name, Domain: a.Domain})
				}
			}
		}
		for _, r := range pt.Body {
			if r.Action.Kind == policy.ActHMAC {
				out = append(out, MaskedField{Service: svc, Op: op, Part: part, Kind: "body", Field: r.Path, Domain: r.Action.Domain})
			}
		}
	}
	addScope := func(svc string, s *policy.Scope) {
		addPart(svc, "", "request", &s.Request)
		addPart(svc, "", "response", &s.Response)
		addPart(svc, "", "errors", &s.Errors)
	}
	addScope("", &p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		addScope(s.Name, &s.Scope)
		for j := range s.Ops {
			addPart(s.Name, s.Ops[j].Op, "request", &s.Ops[j].Request)
			addPart(s.Name, s.Ops[j].Op, "response", &s.Ops[j].Response)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return strings.Join([]string{a.Service, a.Op, a.Part, a.Kind, a.Field}, "\x00") < strings.Join([]string{b.Service, b.Op, b.Part, b.Kind, b.Field}, "\x00")
	})
	return out
}

func observeDefaults(o *ObserveOptions) {
	if o.After <= 0 {
		o.After = DefaultObserveAfter
	}
	if o.MinEvents <= 0 {
		o.MinEvents = DefaultObserveMinEvents
	}
	if o.Interval <= 0 {
		o.Interval = DefaultObserveInterval
	}
}

func hashText(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
