package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/drift"
	"github.com/ivseb/traffic-twin/internal/fleet"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/world"
)

// authOptions maps the validated configuration to auth.Options.
func authOptions(cfg *config.Config, logger *slog.Logger, pp *auth.PasswordParams, now func() time.Time) auth.Options {
	o := auth.Options{
		IdleTimeout:     cfg.Auth.Session.IdleTimeout,
		AbsoluteTimeout: cfg.Auth.Session.AbsoluteTimeout,
		TLS:             cfg.Admin.TLS.Enabled(),
		LocalEnabled:    cfg.Auth.Local.Enabled,
		PasswordParams:  pp,
		Logger:          logger,
		Now:             now,
	}
	if c := cfg.Auth.OIDC; c.Enabled {
		mapping := map[string][]auth.Role{}
		for group, roles := range c.RoleMapping {
			for _, r := range roles {
				mapping[group] = append(mapping[group], auth.Role(r)) // validated by config
			}
		}
		o.OIDC = &auth.OIDCOptions{
			IssuerURL: c.IssuerURL, ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL,
			Scopes: c.Scopes, RolesClaim: c.RolesClaim, RoleMapping: mapping,
			ApprovalClientID: c.ApprovalClientID, ApprovalClientSecret: c.ApprovalClientSecret,
		}
	}
	return o
}

// ---------------------------------------------------------------------------
// keyguard client -> fleet.Signer

type signer struct{ kg *client.Client }

var _ fleet.Signer = (*signer)(nil)

func refusal(err error) error {
	var ke *client.Error
	if errors.As(err, &ke) && (ke.Status == http.StatusForbidden || ke.Status == http.StatusUnprocessableEntity) {
		return &fleet.SignRefusedError{Code: ke.Code, Message: ke.Message}
	}
	return err
}

func toSignature(s *client.Signature, verified bool) (fleet.Signature, error) {
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fleet.Signature{}, errors.New("keyguard: malformed signature")
	}
	return fleet.Signature{Alg: s.Alg, Kid: s.Kid, Sig: sig, Classification: s.Classification,
		ApprovalMode: s.ApprovalMode, ApprovalsVerified: verified, OpensValues: s.OpensValues}, nil
}

func (s *signer) SignPolicy(ctx context.Context, req fleet.SignRequest) (fleet.Signature, error) {
	approvals := make([]client.Approval, 0, len(req.Approvals))
	tokens := len(req.Approvals) > 0
	for _, a := range req.Approvals {
		approvals = append(approvals, client.Approval{User: a.User, Roles: a.Roles, At: a.At, IDToken: a.IDToken, Reason: a.Reason})
		tokens = tokens && a.IDToken != ""
	}
	out, err := s.kg.SignPolicy(ctx, req.Body, req.Proposer, approvals)
	if err != nil {
		return fleet.Signature{}, refusal(err)
	}
	// keyguard verifies ID tokens whenever it has an OIDC issuer; it then
	// refuses unverifiable approvals, so a signature over approvals that
	// all carry a token is a verified one.
	verified := false
	if tokens {
		if st, err := s.kg.Status(ctx); err == nil {
			verified = !st.ApprovalsUnverified
		}
	}
	return toSignature(out, verified)
}

func (s *signer) RenewPolicy(ctx context.Context, body []byte) (fleet.Signature, error) {
	out, err := s.kg.RenewPolicy(ctx, body)
	if err != nil {
		return fleet.Signature{}, refusal(err)
	}
	return toSignature(out, false)
}

func (s *signer) PolicySigningKeys(ctx context.Context) ([]fleet.SigningKey, error) {
	pk, err := s.kg.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]fleet.SigningKey, 0, len(pk.Policy))
	for _, k := range pk.Policy {
		b, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("keyguard: malformed policy public key")
		}
		sk := fleet.SigningKey{Kid: k.Kid, PublicKey: ed25519.PublicKey(b)}
		if k.EndorsedBy != "" && k.Endorsement != "" {
			sk.EndorsedBy, sk.Endorsement = k.EndorsedBy, k.Endorsement
		}
		out = append(out, sk)
	}
	return out, nil
}

func (s *signer) Status(ctx context.Context) (fleet.SignerStatus, error) {
	st, err := s.kg.Status(ctx)
	if err != nil {
		return fleet.SignerStatus{}, err
	}
	out := fleet.SignerStatus{OpeningApprovals: st.OpeningApprovals, AdminOverride: st.AdminOverride, ApprovalsUnverified: st.ApprovalsUnverified,
		PolicyKid: st.PolicyKid, ObserveAuto: st.ObserveAuto, HMACKids: st.HMACKids}
	if st.OIDC != nil {
		out.OIDCIssuer, out.OIDCAudience = st.OIDC.Issuer, st.OIDC.Audience
	} else if !st.ApprovalsUnverified {
		// A keyguard that verifies approvals but does not report its OIDC
		// settings: the step-up cannot be checked against it.
		out.OIDCIssuer, out.OIDCAudience = "", ""
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Approval step-up (keyguard.md 3.2 step 4): auth obtains and verifies the
// tokens, fleet / the pack writer / the quarantine ask for them.

// approvalTokens implements packwriter.ApprovalTokens and the quarantine
// check on top of auth's step-up and keyguard's status (via fleet).
type approvalTokens struct {
	auth  *auth.Service
	fleet *fleet.Fleet
	log   *slog.Logger
}

func (a approvalTokens) Verified() bool {
	_, _, ok := a.fleet.ApprovalsVerified()
	return ok
}

func (a approvalTokens) ApprovalToken(ctx context.Context, p *auth.Principal, purpose, ref, nonce, explicit string) (string, error) {
	if p.OIDCSubject != "" {
		iss, aud, _ := a.fleet.ApprovalsVerified()
		if err := a.auth.CheckApprovalAudience(iss, aud); err != nil && !errors.Is(err, auth.ErrStepUpDisabled) {
			a.log.ErrorContext(ctx, "approval step-up misconfigured", "err", err)
			return "", auth.ErrStepUpDisabled
		}
	}
	return a.auth.ApprovalToken(ctx, p, purpose, ref, nonce, explicit)
}

// stepUpBinder computes the nonce of a step-up from the change it is for.
func (c *Core) stepUpBinder(ctx context.Context, p *auth.Principal, purpose, ref string) (string, error) {
	notFound := func(err error) error {
		var fe *fleet.APIError
		if errors.As(err, &fe) && fe.Status == http.StatusNotFound {
			return auth.ErrStepUpNotFound
		}
		var ge *gate.APIError
		if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
			return auth.ErrStepUpNotFound
		}
		return err
	}
	switch purpose {
	case approvebind.PurposePolicy:
		i := strings.LastIndexByte(ref, '/')
		if i <= 0 {
			return "", auth.ErrStepUpNotFound
		}
		ver, err := strconv.ParseInt(ref[i+1:], 10, 64)
		if err != nil || ver < 1 {
			return "", auth.ErrStepUpNotFound
		}
		n, err := c.fleet.ApprovalNonce(ctx, ref[:i], ver)
		return n, notFound(err)
	case approvebind.PurposePack:
		n, err := c.packs.PublishNonce(ctx, ref)
		return n, notFound(err)
	case approvebind.PurposeQuarantine:
		id, ok := parseItemID(ref)
		if !ok {
			return "", auth.ErrStepUpNotFound
		}
		if _, ok := c.findQuarantine(id); !ok {
			return "", auth.ErrStepUpNotFound
		}
		return approvebind.QuarantineNonce(ref), nil
	}
	return "", auth.ErrStepUpNotFound
}

// ---------------------------------------------------------------------------
// Alerts: fleet alerts and intake quarantines -> drift webhooks

// alertBridge implements fleet.Alerter and intake.AlarmSink on top of the
// drift manager (built after Fleet and the intake, hence the late binding).
type alertBridge struct {
	log *slog.Logger
	mu  sync.RWMutex
	m   *drift.Manager
}

var (
	_ fleet.Alerter    = (*alertBridge)(nil)
	_ intake.AlarmSink = (*alertBridge)(nil)
)

func (b *alertBridge) setManager(m *drift.Manager) {
	b.mu.Lock()
	b.m = m
	b.mu.Unlock()
}

func (b *alertBridge) emit(ctx context.Context, typ string, payload map[string]any) {
	b.mu.RLock()
	m := b.m
	b.mu.RUnlock()
	if m == nil {
		return
	}
	if err := m.Emit(ctx, typ, payload); err != nil {
		b.log.Warn("alert not queued", "type", typ, "err", err)
	}
}

// fleetAlertTypes maps Fleet alert kinds to webhook event types
// (admin-api Webhook.events).
var fleetAlertTypes = map[string]string{
	"fleet.kill":            "kill.changed",
	"policy.admin_approval": "keyguard.alert",
}

// Alert implements fleet.Alerter. Details are identifiers and counts.
func (b *alertBridge) Alert(ctx context.Context, kind string, details map[string]string) {
	typ, ok := fleetAlertTypes[kind]
	if !ok {
		typ = "source.problem"
	}
	p := map[string]any{"alert": kind}
	for k, v := range details {
		p[k] = v
	}
	b.emit(ctx, typ, p)
}

// QuarantineRaised implements intake.AlarmSink: quarantine.opened, with the
// location of the element (names and paths, never values).
func (b *alertBridge) QuarantineRaised(ctx context.Context, q intake.Quarantine) {
	p := map[string]any{"item_id": "q-" + strconv.FormatInt(q.ID, 10), "kind": string(q.Kind), "service": q.Service,
		"distinct_estimate": q.Estimate, "threshold": q.Threshold}
	if q.Op != "" {
		p["op"] = q.Op
	}
	if q.Part != "" || q.Path != "" {
		p["where"] = q.Part + " " + q.Path
	}
	if q.Kind == intake.QuarantineHost || q.Kind == intake.QuarantineHostLabel {
		p["alert"] = intake.AlarmHostCardinality
		if q.Domain != "" {
			p["where"] = "hosts under " + q.Domain + " position " + strconv.Itoa(q.Position)
		}
	}
	// Called from the intake's goroutines: never block it on the database.
	go b.emit(context.WithoutCancel(ctx), "quarantine.opened", p)
}

// staleness adapts the drift manager to miner.StalenessSink.
type staleness struct{ m *drift.Manager }

func (s staleness) RuleStale(ctx context.Context, n miner.StaleNotice) {
	reason := n.Reason
	if n.Detail != "" {
		reason = n.Detail
	}
	_ = s.m.RuleStale(ctx, drift.RuleStaleReport{RuleID: n.RuleID, Confidence: n.Current, Previous: n.Previous, Reason: reason})
}

// ruleLookup implements drift.RuleLookup and drift.RuleMarker over the
// miner's repository (bound once the miner exists).
type ruleLookup struct {
	repo *miner.Repo
	now  func() time.Time
}

func (l *ruleLookup) RulesTouching(service, op string) []string {
	if l.repo == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rs, err := l.repo.List(ctx, miner.StatusApproved)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rs {
		if c := r.Rule.Causal; c != nil && c.Cause.Service == service && c.Cause.Op == op {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

func (l *ruleLookup) MarkStale(ctx context.Context, ruleID, reason string) error {
	if l.repo == nil {
		return nil
	}
	return l.repo.MarkStale(ctx, ruleID, reason, l.now())
}

// minerGaps contributes the miner's gaps to GET /api/v1/gaps.
type minerGaps struct {
	repo *miner.Repo
	kMin int
}

func (g minerGaps) Gaps(ctx context.Context) ([]contract.Gap, error) {
	var out []contract.Gap
	ents, err := g.repo.Entities(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		// Pre-existing objects (seed) are made by the world generator and
		// keyed records by their writes (rules v1.6): no gap.
		if e.CreatedBy == nil && e.Seed == nil && e.Key == nil {
			out = append(out, contract.NewGap("entity-without-creator", e.Service, "", contract.ScopeOp, "entity "+e.Name,
				"entity "+e.Name+" has no creating operation: the mock cannot create it", 0, 0))
		}
	}
	rs, err := g.repo.List(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		c := r.Rule.Causal
		if c == nil || c.Status == miner.StatusRejected {
			continue
		}
		if n := c.Evidence.Counts.DistinctSubjects; n < 2*g.kMin {
			out = append(out, contract.NewGap("rule-low-support", c.Cause.Service, c.Cause.Op, contract.ScopeOp, "rule "+c.ID,
				"rule "+c.ID+" is supported by few distinct subjects", int64(n), int64(2*g.kMin)))
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Inputs of worlds and packs

// approvedRules implements world.RulesSource over the miner's repository.
type approvedRules struct {
	repo *miner.Repo
	now  func() time.Time
}

func (a approvedRules) ApprovedRules(ctx context.Context) (*world.RuleSet, error) {
	doc, err := a.repo.Document(ctx, miner.StatusApproved, a.now())
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return &world.RuleSet{Doc: b}, nil
}

// contractsSource implements world.ContractsSource: the contracts inferred
// over the mining window ending now (the same events the rules come from),
// rendered pack-safe, with their observed keep values (Declared, with the
// distinct subjects behind each) and the generated example values
// (Synthetic) tagged for the gate.
type contractsSource struct {
	eng    *contract.Engine
	now    func() time.Time
	window time.Duration
	cache  *liveContracts
}

// liveContracts keeps the contracts inferred for worlds and packs for a few
// minutes. Inferring them reads every event of the window (minutes with
// millions of events, test/perf), and a world and the pack built from it
// usually follow each other: the second one reuses the first inference.
type liveContracts struct {
	mu  sync.Mutex
	at  time.Time
	out []world.Contract
	// groups caches the contracts of each group's traffic (ContractsIn).
	groups map[string]liveEntry
}

type liveEntry struct {
	at  time.Time
	out []world.Contract
}

// liveContractsTTL is how long an inference is reused.
const liveContractsTTL = 10 * time.Minute

func (s contractsSource) Contracts(ctx context.Context) ([]world.Contract, error) {
	if s.cache == nil {
		return s.infer(ctx)
	}
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	if now := s.now(); s.cache.out != nil && now.Sub(s.cache.at) < liveContractsTTL && !now.Before(s.cache.at) {
		return s.cache.out, nil
	}
	out, err := s.infer(ctx)
	if err != nil {
		return nil, err
	}
	s.cache.at, s.cache.out = s.now(), out
	return out, nil
}

func (s contractsSource) infer(ctx context.Context) ([]world.Contract, error) {
	now := s.now()
	win := contract.Window{From: now.Add(-s.window), To: now.Add(time.Minute)}
	cs, err := s.eng.Live(ctx, win)
	if err != nil {
		return nil, err
	}
	return s.render(cs)
}

// render renders the contracts pack-safe for the world and the gate.
func (s contractsSource) render(cs []*contract.Contract) ([]world.Contract, error) {
	ro := s.eng.RenderOptions()
	ro.PackSafe = true
	out := make([]world.Contract, 0, len(cs))
	for _, c := range cs {
		doc, err := c.JSON(ro)
		if err != nil {
			return nil, err
		}
		wc := world.Contract{Service: c.Service, Doc: doc, External: external(c), Declared: declared(c), Combos: c.Combos()}
		wc.Synthetic = synthetic(doc, wc.Declared)
		out = append(out, wc)
	}
	return out, nil
}

// external: every operation of the service was observed outbound (a
// service called by the system under test, never by customers).
func external(c *contract.Contract) bool {
	if len(c.Ops) == 0 {
		return false
	}
	for _, op := range c.Ops {
		if op.Dir != "outbound" {
			return false
		}
	}
	return true
}

// declared collects the published keep values of a contract model with
// their distinct subjects (capped at k by the inference).
func declared(c *contract.Contract) map[string]int64 {
	out := map[string]int64{}
	var walk func(s *contract.Schema)
	walk = func(s *contract.Schema) {
		if s == nil {
			return
		}
		for _, e := range s.Enum {
			if e.Published && int64(e.Subjects) > out[e.Value] {
				out[e.Value] = int64(e.Subjects)
			}
		}
		for _, p := range s.Props {
			walk(p.Schema)
		}
		walk(s.Additional)
		walk(s.Items)
	}
	params := func(ps []*contract.Param) {
		for _, p := range ps {
			walk(p.Schema)
		}
	}
	for _, op := range c.Ops {
		params(op.PathParams)
		params(op.Query)
		params(op.Headers)
		params(op.Cookies)
		for _, m := range op.Body {
			walk(m.Schema)
		}
		for _, r := range op.Responses {
			params(r.Headers)
			params(r.Cookies)
			for _, m := range r.Body {
				walk(m.Schema)
			}
		}
	}
	return out
}

// synthetic lists the strings of the rendered examples that are not
// observed keep values: the inference generates them from annotations only
// (placeholders such as ORD-SYN-0042 or user@example.com).
func synthetic(doc []byte, decl map[string]int64) []string {
	var d any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if dec.Decode(&d) != nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(v any, inExample bool)
	walk = func(v any, inExample bool) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(e, inExample || k == "example" || k == "examples")
			}
		case []any:
			for _, e := range x {
				walk(e, inExample)
			}
		case string:
			if _, ok := decl[x]; inExample && !ok {
				seen[x] = true
			}
		}
	}
	walk(d, false)
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// packDefaults applies gate.valid_days to build requests that give none.
type packDefaults struct {
	gate.PackService
	validDays int
}

func (p packDefaults) BuildPack(ctx context.Context, pr *auth.Principal, req gate.BuildRequest) (*gate.PackInfo, error) {
	if req.ValidDays == nil {
		d := p.validDays
		req.ValidDays = &d
	}
	return p.PackService.BuildPack(ctx, pr, req)
}

// kMinGuard enforces world.k_min on POST /api/v1/archetypes/build: a
// smaller k is refused, a missing one takes the configured value.
func kMinGuard(next http.Handler, kMin int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != world.PrefixArchetypes+"/build" {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		if err != nil {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return
		}
		var req map[string]any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if len(bytes.TrimSpace(body)) > 0 {
			if err := dec.Decode(&req); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
				return
			}
		}
		if req == nil {
			req = map[string]any{}
		}
		if v, ok := req["k_min"]; !ok {
			req["k_min"] = kMin
		} else if n, ok := v.(json.Number); ok {
			if k, err := n.Int64(); err == nil && k < int64(kMin) {
				httpx.WriteError(w, http.StatusUnprocessableEntity, "k_min_too_small", "k_min is below the configured world.k_min ("+strconv.Itoa(kMin)+")")
				return
			}
		}
		b, _ := json.Marshal(req)
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(bytes.NewReader(b))
		r2.ContentLength = int64(len(b))
		r2.Header.Set("Content-Type", "application/json")
		next.ServeHTTP(w, r2)
	})
}
