package keyguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Error is an API error: an HTTP status, a machine code and a fixed
// message. Messages never contain request data, keys or tokens.
type Error struct {
	Status  int
	Code    string
	Message string
	// Extra is merged into the error body (pack reverse-HMAC findings).
	Extra map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func apiErr(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// Options are runtime hooks of a Service.
type Options struct {
	Logger *slog.Logger
	// Now is the clock (tests). Defaults to time.Now.
	Now func() time.Time
	// OnAlert receives every alert synchronously (tests).
	OnAlert func(Alert)
	// Transport is reported in the status ("unix" or "mtls").
	Transport string
}

// Service is a running keyguard: keys, database, filters and limits.
type Service struct {
	cfg        Config
	db         *store.DB
	audit      *audit.Log
	hmac       *HMACKeys
	policyKeys *SigningKeys
	packKeys   *SigningKeys
	filters    *filterSet
	verifier   *approvalVerifier
	alerts     *alerter
	log        *slog.Logger
	now        func() time.Time
	transport  string

	rateMu    sync.Mutex
	lastMatch time.Time
	lastPack  time.Time

	signMu sync.Mutex // serializes policy signing and renewal

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New loads the keys, opens the database, loads the filters and starts the
// snapshot loop. Any key problem (missing, malformed, permissive file mode,
// revoked active signer) is fatal.
func New(ctx context.Context, cfg Config, opts Options) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, log: opts.Logger, now: opts.Now, transport: opts.Transport, stop: make(chan struct{})}
	if s.log == nil {
		s.log = NewLogger(io.Discard, "error", "json")
	}
	if s.now == nil {
		s.now = time.Now
	}
	fail := func(err error) (*Service, error) {
		s.zeroKeys()
		if s.db != nil {
			_ = s.db.Close()
		}
		return nil, err
	}
	var err error
	if s.hmac, err = LoadHMACKeys(cfg.HMACKeys); err != nil {
		return fail(fmt.Errorf("hmac keys: %w", err))
	}
	if s.policyKeys, err = LoadSigningKeys(cfg.PolicyKey, cfg.RevokedKids); err != nil {
		return fail(fmt.Errorf("policy signing key: %w", err))
	}
	if s.packKeys, err = LoadSigningKeys(cfg.PackKey, cfg.RevokedKids); err != nil {
		return fail(fmt.Errorf("pack signing key: %w", err))
	}
	if cfg.OIDCIssuer != "" {
		if s.verifier, err = newApprovalVerifier(&cfg, s.now); err != nil {
			return fail(err)
		}
	}
	if s.db, err = OpenDB(ctx, cfg.DBPath); err != nil {
		return fail(err)
	}
	s.audit = audit.New(s.db)
	s.filters = newFilterSet(s.db, cfg.BloomCapacity)
	if err := s.filters.load(ctx); err != nil {
		return fail(fmt.Errorf("load filters: %w", err))
	}
	s.alerts = newAlerter(cfg.AlertWebhook, s.log)
	s.alerts.sent = opts.OnAlert
	if _, err := s.record(ctx, "keyguard.start", audit.Success, "", audit.Target{Type: "process"}, map[string]string{
		"hmac_kids":            joinIDs(s.hmac.Kids()),
		"policy_kid":           s.policyKeys.Kid(),
		"pack_kid":             s.packKeys.Kid(),
		"approvals_unverified": strconv.FormatBool(s.verifier == nil),
		"opening_approvals":    strconv.Itoa(cfg.OpeningApprove),
		"admin_override":       strconv.FormatBool(cfg.AdminOverride),
		"observe_auto":         strconv.FormatBool(cfg.ObserveAuto),
	}); err != nil {
		s.alerts.close()
		return fail(err)
	}
	s.wg.Add(1)
	go s.snapshotLoop()
	return s, nil
}

func (s *Service) zeroKeys() {
	if s.hmac != nil {
		s.hmac.Zero()
	}
	if s.policyKeys != nil {
		s.policyKeys.Zero()
	}
	if s.packKeys != nil {
		s.packKeys.Zero()
	}
}

// Close snapshots the filters, closes the database and zeroes the keys.
func (s *Service) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
		err = s.filters.snapshot(context.Background(), s.retentionCutoff())
		s.alerts.close()
		if cerr := s.db.Close(); err == nil {
			err = cerr
		}
		s.zeroKeys()
	})
	return err
}

func (s *Service) retentionCutoff() time.Time {
	if s.cfg.Retention <= 0 {
		return time.Time{}
	}
	return s.now().Add(-s.cfg.Retention)
}

func (s *Service) snapshotLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.Snapshot)
	defer t.Stop()
	lastMaintain := time.Now()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if err := s.filters.snapshot(context.Background(), s.retentionCutoff()); err != nil {
				s.log.Error("keyguard filter snapshot failed", "error", err.Error())
			}
			// The data lifecycle (retention.go), about once an hour.
			if time.Since(lastMaintain) >= maintainEvery {
				lastMaintain = time.Now()
				if res, err := s.Maintain(context.Background()); err != nil {
					s.log.Error("keyguard maintenance failed", "error", err.Error())
				} else if res.Fingerprints+res.AuditEntries > 0 {
					s.log.Info("keyguard maintenance", "fingerprints", res.Fingerprints, "audit_entries", res.AuditEntries,
						"segments", res.Segments, "reclaimed_bytes", res.Reclaimed)
				}
			}
		}
	}
}

// Snapshot forces a filter snapshot (tests, shutdown).
func (s *Service) Snapshot(ctx context.Context) error {
	return s.filters.snapshot(ctx, s.retentionCutoff())
}

// record appends an audit entry. Callers performing a sensitive action
// fail closed when it errors.
func (s *Service) record(ctx context.Context, action string, outcome audit.Outcome, reason string, target audit.Target, details map[string]string) (audit.Entry, error) {
	return s.audit.Record(ctx, audit.Event{
		Actor:   audit.Actor{Kind: audit.ActorSystem, ID: "tt-core"},
		Action:  action,
		Target:  target,
		Outcome: outcome,
		Reason:  reason,
		Details: details,
	})
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += audit.SafeValue(id)
	}
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// allow applies a minimum interval between calls (keyguard.md 3.1: 1 call
// per second by default).
func (s *Service) allow(last *time.Time, interval time.Duration) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := s.now()
	if !last.IsZero() && now.Sub(*last) < interval {
		return false
	}
	*last = now
	return true
}

// ---- token feed ----

// AddTokens inserts real tokens accepted by the intake into the filters of
// epoch (keyguard.md 2). The kid of each filter is the one in the token.
func (s *Service) AddTokens(ctx context.Context, epoch string, tokens []string) error {
	if !validEpoch(epoch) {
		return apiErr(400, "invalid_request", "epoch is malformed")
	}
	if len(tokens) > 100000 {
		return apiErr(400, "batch_too_large", "at most 100000 tokens per call")
	}
	byKid := map[string][]digest{}
	for _, t := range tokens {
		kid, mac, ok := parseToken(t)
		if !ok {
			return apiErr(400, "invalid_request", "a token is malformed")
		}
		byKid[kid] = append(byKid[kid], tokenDigest(kid, mac))
	}
	kids := make([]string, 0, len(byKid))
	for k := range byKid {
		kids = append(kids, k)
	}
	sort.Strings(kids)
	now := s.now()
	for _, kid := range kids {
		if err := s.filters.add(ctx, filterKey{epoch: epoch, kid: kid}, byKid[kid], now); err != nil {
			return err
		}
	}
	_, err := s.record(ctx, "keyguard.tokens", audit.Success, "", audit.Target{Type: "filter", ID: audit.SafeValue(epoch)},
		map[string]string{"tokens": strconv.Itoa(len(tokens)), "kids": joinIDs(kids)})
	return err
}

func validEpoch(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ---- reverse-HMAC ----

// PolicyRef names a signed policy version.
type PolicyRef struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

type matchCtx struct {
	kids, epochs, domains []string
}

// resolve builds the HMAC context of a set of policies from the bodies
// keyguard signed itself (it does not trust tt-core's description of them).
func (s *Service) resolve(ctx context.Context, refs []PolicyRef) (*matchCtx, error) {
	if len(refs) == 0 || len(refs) > 64 {
		return nil, apiErr(400, "invalid_request", "between 1 and 64 policies are required")
	}
	kids, epochs, domains := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range refs {
		body, err := bodyOfVersion(ctx, s.db, r.ID, r.Version)
		if err != nil {
			return nil, err
		}
		if body == nil {
			return nil, apiErr(422, "unknown_policy", "a policy version was never signed by this keyguard")
		}
		p, err := decodeSigned(body)
		if err != nil {
			return nil, err
		}
		kids[p.HMAC.Kid] = true
		for _, k := range p.HMAC.AcceptKids {
			kids[k] = true
		}
		epochs[p.HMAC.Epoch] = true
		for _, d := range hmacDomains(p) {
			domains[d] = true
		}
	}
	mc := &matchCtx{kids: sortedKeys(kids), epochs: sortedKeys(epochs), domains: sortedKeys(domains)}
	for _, k := range mc.kids {
		if !s.hmac.Has(k) {
			// Fail closed: without the key the check cannot be done.
			return nil, apiErr(422, "kid_not_held", "a policy uses an HMAC kid this keyguard does not hold")
		}
	}
	return mc, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// check returns, for each candidate, whether one of its tokens (any kid,
// epoch and domain of mc) is in a real-token filter.
func (s *Service) check(mc *matchCtx, cands []Candidate) []bool {
	out := make([]bool, len(cands))
	s.filters.view(func(fm map[filterKey]*filter) {
		type pair struct {
			kid, epoch string
			f          *filter
		}
		var pairs []pair
		for _, kid := range mc.kids {
			for _, ep := range mc.epochs {
				if f := fm[filterKey{epoch: ep, kid: kid}]; f != nil && len(f.segs) > 0 {
					pairs = append(pairs, pair{kid, ep, f})
				}
			}
		}
		if len(pairs) == 0 {
			return
		}
		workers := min(runtime.GOMAXPROCS(0), max(1, len(cands)/256))
		var wg sync.WaitGroup
		chunk := (len(cands) + workers - 1) / workers
		for w := 0; w < workers; w++ {
			lo, hi := w*chunk, min((w+1)*chunk, len(cands))
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				macers := map[string]*macer{}
				for _, kid := range mc.kids {
					sec, _ := s.hmac.secret(kid)
					macers[kid] = newMacer(sec)
				}
				for i := lo; i < hi; i++ {
				cand:
					for _, rep := range cands[i].representations() {
						v := []byte(rep)
						for _, p := range pairs {
							m := macers[p.kid]
							for _, d := range mc.domains {
								if p.f.has(tokenDigest(p.kid, m.mac16(p.epoch, d, v))) {
									out[i] = true
									break cand
								}
							}
						}
					}
				}
			}(lo, hi)
		}
		wg.Wait()
	})
	return out
}

// MatchResult is the answer of Match: one boolean per candidate.
type MatchResult struct {
	Matches   []bool `json:"matches"`
	Positives int    `json:"positives"`
}

// Match runs the reverse-HMAC check (keyguard.md 3.1). It is rate-limited
// and budgeted; every call is audited and every positive raises an alert.
func (s *Service) Match(ctx context.Context, refs []PolicyRef, cands []Candidate) (*MatchResult, error) {
	target := audit.Target{Type: "match"}
	refuse := func(e *Error, alertType string) (*MatchResult, error) {
		if _, err := s.record(ctx, "keyguard.match", audit.Denied, e.Code, target, map[string]string{"candidates": strconv.Itoa(len(cands))}); err != nil {
			return nil, err
		}
		if alertType != "" {
			s.alerts.raise(Alert{Type: alertType, At: s.now().UTC(), Counts: map[string]int64{"candidates": int64(len(cands))}})
		}
		return nil, e
	}
	if len(cands) > s.cfg.MatchMaxBatch {
		return refuse(apiErr(400, "batch_too_large", "too many candidates in one call"), "")
	}
	if !s.allow(&s.lastMatch, s.cfg.MatchInterval) {
		return refuse(apiErr(429, "rate_limited", "match is limited to one call per interval"), AlertRateLimited)
	}
	mc, err := s.resolve(ctx, refs)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return refuse(e, "")
		}
		return nil, err
	}
	if _, ok, err := consumeBudget(ctx, s.db, s.now(), int64(len(cands)), s.cfg.MatchBudget); err != nil {
		return nil, err
	} else if !ok {
		return refuse(apiErr(429, "budget_exceeded", "daily match budget exhausted"), AlertBudgetExceeded)
	}
	res := &MatchResult{Matches: s.check(mc, cands)}
	for _, m := range res.Matches {
		if m {
			res.Positives++
		}
	}
	reason := ""
	if res.Positives > 0 {
		reason = "alert"
	}
	details := map[string]string{"candidates": strconv.Itoa(len(cands)), "positives": strconv.Itoa(res.Positives), "policies": refsDetail(refs)}
	if _, err := s.record(ctx, "keyguard.match", audit.Success, reason, target, details); err != nil {
		return nil, err
	}
	if res.Positives > 0 {
		s.alerts.raise(Alert{Type: AlertMatchPositive, At: s.now().UTC(), Counts: map[string]int64{"candidates": int64(len(cands)), "positives": int64(res.Positives)}})
	}
	return res, nil
}

func refsDetail(refs []PolicyRef) string {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.ID+"@"+itoa(r.Version))
	}
	return joinIDs(ids)
}

// ---- info ----

// PublicKeys returns the public signing keys (never private parts).
func (s *Service) PublicKeys() map[string][]PublicKey {
	return map[string][]PublicKey{"policy": s.policyKeys.Public(), "pack": s.packKeys.Public()}
}

// Status is the status document: key ids, filter sizes, budget, OIDC state.
type Status struct {
	HMACKids            []string     `json:"hmac_kids"`
	Epochs              []string     `json:"epochs"`
	ApprovalsUnverified bool         `json:"approvals_unverified"`
	MatchBudgetLeft     int64        `json:"match_budget_left"`
	PolicyKid           string       `json:"policy_kid"`
	PackKid             string       `json:"pack_kid"`
	RevokedKids         []string     `json:"revoked_kids"`
	Filters             []FilterInfo `json:"filters"`
	LastIssuedSeq       int64        `json:"last_issued_seq"`
	OpeningApprovals    int          `json:"opening_approvals"`
	AdminOverride       bool         `json:"admin_override"`
	// ObserveAuto: observe-safe changes are signed without approvals
	// (TT_KEYGUARD_OBSERVE_AUTO, default true; policy.md 7).
	ObserveAuto bool   `json:"observe_auto"`
	Transport   string `json:"transport,omitempty"`
	// OIDC is set when approvals are verified (keyguard.md 3.2 step 4): the
	// issuer and the dedicated approval audience tt-core's step-up must
	// obtain tokens for, and the claim roles are read from.
	OIDC *OIDCStatus `json:"oidc,omitempty"`
}

// OIDCStatus describes approval verification (no secret).
type OIDCStatus struct {
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	RolesClaim string `json:"roles_claim"`
}

// Status returns the current status.
func (s *Service) Status(ctx context.Context) (*Status, error) {
	left, err := budgetLeft(ctx, s.db, s.now(), s.cfg.MatchBudget)
	if err != nil {
		return nil, err
	}
	seq, err := lastIssuedSeq(ctx, s.db)
	if err != nil {
		return nil, err
	}
	st := &Status{
		HMACKids: s.hmac.Kids(), ApprovalsUnverified: s.verifier == nil, MatchBudgetLeft: left,
		PolicyKid: s.policyKeys.Kid(), PackKid: s.packKeys.Kid(), RevokedKids: sortedKeys(s.cfg.RevokedKids),
		Filters: s.filters.info(), LastIssuedSeq: seq, OpeningApprovals: s.cfg.OpeningApprove,
		AdminOverride: s.cfg.AdminOverride, ObserveAuto: s.cfg.ObserveAuto, Transport: s.transport,
	}
	if s.verifier != nil {
		st.OIDC = &OIDCStatus{Issuer: s.cfg.OIDCIssuer, Audience: s.cfg.OIDCAudience, RolesClaim: s.cfg.OIDCRolesClaim}
	}
	epochs := map[string]bool{}
	for _, f := range st.Filters {
		epochs[f.Epoch] = true
	}
	st.Epochs = sortedKeys(epochs)
	if st.Filters == nil {
		st.Filters = []FilterInfo{}
	}
	return st, nil
}

// AuditEntry is one entry of GET /keyguard/v1/audit.
type AuditEntry struct {
	Seq      int64             `json:"seq"`
	At       time.Time         `json:"at"`
	Op       string            `json:"op"`
	Outcome  string            `json:"outcome"`
	Detail   map[string]string `json:"detail,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Audit returns up to limit entries after sinceSeq.
func (s *Service) Audit(ctx context.Context, sinceSeq int64, limit int) ([]AuditEntry, error) {
	out := []AuditEntry{}
	err := s.audit.Iterate(ctx, sinceSeq, limit, func(e audit.Entry) error {
		outcome := "ok"
		switch {
		case e.Reason == "alert":
			outcome = "alert"
		case e.Outcome != audit.Success:
			outcome = "refused"
		}
		d := map[string]string{}
		for k, v := range e.Details {
			d[k] = v
		}
		if e.Reason != "" && e.Reason != "alert" {
			d["code"] = e.Reason
		}
		if e.Target.ID != "" {
			d["target"] = e.Target.ID
		}
		out = append(out, AuditEntry{Seq: e.Seq, At: e.Time, Op: e.Action, Outcome: outcome, Detail: d, PrevHash: e.PrevHash, Hash: e.Hash})
		return nil
	})
	return out, err
}

// VerifyAudit walks the audit hash chain.
func (s *Service) VerifyAudit(ctx context.Context) (audit.VerifyResult, error) {
	return s.audit.Verify(ctx)
}
