package miner

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Deps are the collaborators of the miner service.
type Deps struct {
	// DB holds the rules (opened with store.Open).
	DB *store.DB
	// Events is the event storage (intake.Store).
	Events EventSource
	// Domains resolves HMAC domains from the signed policies; optional.
	Domains DomainResolver
	// Audit records reviews and mining runs. Required.
	Audit *audit.Log
	// Staleness is told when an approved rule becomes stale; optional.
	Staleness StalenessSink
	// Contracts gives the contracts that rules written by hand are checked
	// against (catalog); optional: without it only the structure and the
	// entities are checked.
	Contracts ContractSource
	// Groups attributes event sources to groups (fleet); optional. With it
	// each group's traffic is mined apart: no entity, reference or rule
	// mixes two teams' services.
	Groups groupscope.Resolver
	// TestK, optional, gives the lower k of the groups marked as test in the
	// console (rules v1.9, C0): group → k (2 ≤ k < Config.KMin).
	TestK func(ctx context.Context) (map[string]int, error)
	// Config defaults to DefaultConfig.
	Config *Config
	Logger *slog.Logger
	Now    func() time.Time
}

// Service runs the mining job and serves the rules API.
type Service struct {
	d    Deps
	cfg  Config
	repo *Repo
	log  *slog.Logger
	now  func() time.Time
	run  sync.Mutex
}

// New builds the service.
func New(d Deps) (*Service, error) {
	if d.DB == nil || d.Events == nil || d.Audit == nil {
		return nil, errors.New("miner: DB, Events and Audit are required")
	}
	cfg := DefaultConfig()
	if d.Config != nil {
		cfg = *d.Config
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Service{d: d, cfg: cfg, log: d.Logger, now: d.Now}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.repo = NewRepo(d.DB, cfg, d.Staleness)
	// A replacement approved before the supersession rule existed leaves the
	// old rule approved: move it out of the active set now.
	if moved, err := s.repo.SupersedeApproved(context.Background(), s.now()); err != nil {
		s.log.Warn("miner: superseded rules not settled", "reason", "store")
	} else if len(moved) > 0 {
		s.log.Info("miner: superseded rules left the active set", "rules", len(moved))
	}
	return s, nil
}

// Mount builds the service and mounts /api/v1/rules on the admin listener
// (rule-reviewer, operator and auditor may read; only rule-reviewer may
// change a rule).
func Mount(srv *server.Server, d Deps) (*Service, error) {
	s, err := New(d)
	if err != nil {
		return nil, err
	}
	srv.Mount("/api/v1/rules", s.Handler(), auth.RoleRuleReviewer, auth.RoleOperator, auth.RoleAuditor)
	return s, nil
}

// Repo returns the rule repository (for the pack builder and the drift
// detector: Document, MarkStale).
func (s *Service) Repo() *Repo { return s.repo }

var systemActor = audit.Actor{Kind: audit.ActorSystem, ID: "miner", Name: "miner"}

// RunOnce mines the configured window ending now and stores the drafts.
// Concurrent calls are serialized.
func (s *Service) RunOnce(ctx context.Context) (RunReport, error) {
	s.run.Lock()
	defer s.run.Unlock()
	started := s.now()
	opt := MineOptions{Now: started}
	var err error
	if s.d.Groups != nil {
		if opt.SourceGroups, err = s.d.Groups.SourceGroups(ctx); err != nil {
			return RunReport{}, err
		}
		if opt.SourceGroups == nil {
			opt.SourceGroups = map[string]string{}
		}
	}
	if opt.Names, err = s.repo.EntityNames(ctx); err != nil {
		return RunReport{}, err
	}
	if opt.OpReads, err = s.repo.OpReads(ctx); err != nil {
		return RunReport{}, err
	}
	if s.d.TestK != nil {
		if opt.GroupKMin, err = s.d.TestK(ctx); err != nil {
			return RunReport{}, err
		}
	}
	res, err := MineIn(ctx, s.d.Events, started.Add(-s.cfg.Window), started, s.d.Domains, s.cfg, opt)
	if err != nil {
		s.record(ctx, audit.Event{Actor: systemActor, Action: "rule.mine", Target: audit.Target{Type: "rules"},
			Outcome: audit.Failure, Reason: reasonOf(err)})
		return RunReport{}, err
	}
	if res.Clamped {
		s.log.Warn("miner: window narrowed to the newest events", "max_events", s.cfg.MaxEvents, "from", res.Window.From)
	}
	rep, err := s.repo.Apply(ctx, res, started, s.now())
	if err != nil {
		s.record(ctx, audit.Event{Actor: systemActor, Action: "rule.mine", Target: audit.Target{Type: "rules"},
			Outcome: audit.Failure, Reason: "store"})
		return RunReport{}, err
	}
	s.record(ctx, audit.Event{Actor: systemActor, Action: "rule.mine", Target: audit.Target{Type: "rules", ID: strconv.FormatInt(rep.RunID, 10)},
		Outcome: audit.Success, Details: map[string]string{
			"events": strconv.Itoa(rep.Events), "new": strconv.Itoa(len(rep.New)),
			"updated": strconv.Itoa(len(rep.Updated)), "stale": strconv.Itoa(len(rep.Stale)),
			"observed_s": strconv.FormatInt(int64(rep.Observed/time.Second), 10),
			"state":      classify(rep.Events, rep.Observed, s.cfg.MinCoverage()),
		}})
	for _, id := range rep.Stale {
		s.record(ctx, audit.Event{Actor: systemActor, Action: "rule.stale", Target: audit.Target{Type: "rule", ID: id}, Outcome: audit.Success,
			Details: staleAuditDetails(id, rep.Diagnostics.Rules)})
	}
	for _, e := range rep.Diagnostics.Entities {
		if !e.Accepted {
			s.log.Warn("miner: entity dropped", "entity", e.Name, "reason", e.Reason)
		}
	}
	if rep.Insufficient {
		s.log.Warn("miner: insufficient traffic", "events", rep.Events, "observed_hours", hours(rep.Observed), "min_hours", hours(s.cfg.MinCoverage()))
	}
	s.log.Info("miner run", "events", rep.Events, "new", len(rep.New), "updated", len(rep.Updated), "stale", len(rep.Stale))
	return rep, nil
}

// staleAuditDetails are the details of the rule.stale audit event of rule
// id. The audit takes identifier-like values only and the reason is a
// sentence ("rule no longer mined for 3 runs"), so it is folded.
func staleAuditDetails(id string, diags []RuleDiag) map[string]string {
	det := map[string]string{}
	for _, d := range diags {
		if d.RuleID == id && d.Decision == DecisionStale {
			det["reason"] = audit.SafeValue(d.Reason)
			if d.Code != "" {
				det["code"] = audit.SafeValue(d.Code)
			}
		}
	}
	return det
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, ErrTooManyEvents):
		return "too_many_events"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	}
	return "error"
}

// Start runs the mining job every interval until ctx ends (first run after
// one interval). It returns at once.
func (s *Service) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
					s.log.Error("miner run failed", "reason", reasonOf(err))
				}
			}
		}
	}()
}

func (s *Service) record(ctx context.Context, e audit.Event) {
	if _, err := s.d.Audit.Record(ctx, e); err != nil {
		s.log.Error("miner audit failed", "action", e.Action)
	}
}

// ---------------------------------------------------------------------------
// HTTP API (api/admin-api.v1.openapi.yaml, tag rules)

var reRuleIDParam = regexp.MustCompile(`^r-[0-9]{4,}$`)

const maxBody = 8 << 10

// Handler serves /api/v1/rules. It expects the server's authentication
// middleware (Mount) and checks the reviewer role itself on changes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/rules", s.listRules)
	mux.HandleFunc("GET /api/v1/rules/status", s.getStatus)
	mux.HandleFunc("GET /api/v1/rules/catalog", s.getCatalog)
	mux.HandleFunc("POST /api/v1/rules/check", s.checkRule)
	mux.HandleFunc("GET /api/v1/rules/op-kinds", s.getOpKinds)
	mux.HandleFunc("PUT /api/v1/rules/op-kinds", s.putOpKind)
	mux.HandleFunc("POST /api/v1/rules", s.createRule)
	mux.HandleFunc("PUT /api/v1/rules/{rule_id}", s.replaceRule)
	mux.HandleFunc("GET /api/v1/rules/{rule_id}", s.getRule)
	mux.HandleFunc("PATCH /api/v1/rules/{rule_id}", s.editRule)
	mux.HandleFunc("POST /api/v1/rules/{rule_id}/approve", s.approveRule)
	mux.HandleFunc("POST /api/v1/rules/{rule_id}/reject", s.rejectRule)
	mux.HandleFunc("POST /api/v1/rules/{rule_id}/retire", s.retireRule)
	mux.HandleFunc("/api/v1/rules", methodNotAllowed)
	mux.HandleFunc("/api/v1/rules/", notFound)
	return mux
}

func methodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
}

func (s *Service) principal(w http.ResponseWriter, r *http.Request, write bool, action, target string) (*auth.Principal, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return nil, false
	}
	allowed := p.HasAny(auth.RoleRuleReviewer, auth.RoleOperator, auth.RoleAuditor)
	if write {
		allowed = p.HasAny(auth.RoleRuleReviewer) // admin too: an audited override
	}
	if !allowed {
		if write {
			s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: action, Target: audit.Target{Type: "rule", ID: target},
				Outcome: audit.Denied, Reason: "missing_role", RequestID: httpx.RequestID(r.Context())})
		}
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "missing role")
		return nil, false
	}
	return p, true
}

// wellFormedID is the rule id of the path when it is well formed, else "".
func wellFormedID(r *http.Request) string {
	if id := r.PathValue("rule_id"); reRuleIDParam.MatchString(id) {
		return id
	}
	return ""
}

func ruleID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("rule_id")
	if !reRuleIDParam.MatchString(id) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid rule id")
		return "", false
	}
	return id, true
}

func (s *Service) writeRepoError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "rule not found")
	case errors.Is(err, ErrConflict):
		httpx.WriteError(w, http.StatusConflict, "rule_state", "the rule status does not allow this change")
	case errors.Is(err, ErrBadEdit):
		// The reason names rules, effects and entities only (shapes, no
		// values): e.g. an entity no longer seen in the mining window.
		msg := "invalid rule change"
		if d := strings.TrimPrefix(strings.TrimPrefix(err.Error(), ErrBadEdit.Error()), ": "); d != "" && d != err.Error() {
			msg += ": " + d
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", msg)
	default:
		s.log.Error("miner api", "kind", "storage")
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// ruleView is a rule as the admin API shows it: the rules.v1 object plus
// proposed_at, the time the miner first proposed it. The extra field never
// enters a pack (Document writes plain rules).
type ruleView struct{ *StoredRule }

func (v ruleView) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(v.Rule)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	at, _ := json.Marshal(v.CreatedAt.UTC().Format(time.RFC3339))
	m["proposed_at"] = at
	if v.StaleReason != "" {
		// Why the rule is stale, or what is going wrong while it is on watch.
		sr, _ := json.Marshal(v.StaleReason)
		m["stale_reason"] = sr
	}
	if by, ok := strings.CutPrefix(v.StaleReason, ReasonSupersededPrefix); ok && v.Rule.Status() == StatusSuperseded {
		// The approved rule that replaced this one.
		sb, _ := json.Marshal(by)
		m["superseded_by"] = sb
	}
	if v.Rule.Status() == StatusRejected && v.StaleReason == ReasonRetired {
		rt, _ := json.Marshal(true)
		m["retired"] = rt
	}
	if v.Strikes > 0 {
		sk, _ := json.Marshal(v.Strikes)
		m["failed_runs"] = sk
	}
	return json.Marshal(m)
}

func (s *Service) listRules(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principal(w, r, false, "", ""); !ok {
		return
	}
	st := r.URL.Query().Get("status")
	if st != "" && !validStatus(st) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid status")
		return
	}
	rs, err := s.repo.List(r.Context(), st)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	out := make([]ruleView, 0, len(rs))
	for _, x := range rs {
		out = append(out, ruleView{x})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) getRule(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principal(w, r, false, "", ""); !ok {
		return
	}
	id, ok := ruleID(w, r)
	if !ok {
		return
	}
	x, err := s.repo.Get(r.Context(), id)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ruleView{x})
}

func (s *Service) editRule(w http.ResponseWriter, r *http.Request) {
	// Role first, then the identifier: a caller without the role gets
	// 403 whatever the path holds (and the denial audits only a
	// well-formed id, never a client-chosen string).
	p, ok := s.principal(w, r, true, "rule.edit", wellFormedID(r))
	if !ok {
		return
	}
	id, ok := ruleID(w, r)
	if !ok {
		return
	}
	var body struct {
		Title *string          `json:"title"`
		After map[string]Delay `json:"after"`
	}
	if err := httpx.DecodeJSON(w, r, maxBody, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
		return
	}
	if body.Title == nil && len(body.After) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "nothing to change")
		return
	}
	x, err := s.repo.Edit(r.Context(), id, body.Title, body.After, s.now())
	if err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.edit", Target: audit.Target{Type: "rule", ID: id},
			Outcome: audit.Failure, Reason: editReason(err), RequestID: httpx.RequestID(r.Context())})
		s.writeRepoError(w, err)
		return
	}
	det := map[string]string{"after": strconv.Itoa(len(body.After)), "title": strconv.FormatBool(body.Title != nil)}
	if nid := x.Rule.ID(); nid != id {
		det["new_rule"] = nid
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.edit", Target: audit.Target{Type: "rule", ID: id},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, det)})
	httpx.WriteJSON(w, http.StatusOK, ruleView{x})
}

func editReason(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrConflict):
		return "rule_state"
	case errors.Is(err, ErrBadEdit):
		return "invalid_input"
	}
	return "internal"
}

func (s *Service) approveRule(w http.ResponseWriter, r *http.Request) {
	// Role first, then the identifier: a caller without the role gets
	// 403 whatever the path holds (and the denial audits only a
	// well-formed id, never a client-chosen string).
	p, ok := s.principal(w, r, true, "rule.approve", wellFormedID(r))
	if !ok {
		return
	}
	id, ok := ruleID(w, r)
	if !ok {
		return
	}
	x, err := s.repo.Approve(r.Context(), id, p.UserID, s.now())
	if err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.approve", Target: audit.Target{Type: "rule", ID: id},
			Outcome: audit.Failure, Reason: editReason(err), RequestID: httpx.RequestID(r.Context())})
		s.writeRepoError(w, err)
		return
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.approve", Target: audit.Target{Type: "rule", ID: id},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, map[string]string{"kind": x.Rule.Kind()})})
	for _, old := range x.Superseded {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.supersede", Target: audit.Target{Type: "rule", ID: old},
			Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: map[string]string{"by": id}})
	}
	httpx.WriteJSON(w, http.StatusOK, ruleView{x})
}

func (s *Service) rejectRule(w http.ResponseWriter, r *http.Request) {
	// Role first, then the identifier: a caller without the role gets
	// 403 whatever the path holds (and the denial audits only a
	// well-formed id, never a client-chosen string).
	p, ok := s.principal(w, r, true, "rule.reject", wellFormedID(r))
	if !ok {
		return
	}
	id, ok := ruleID(w, r)
	if !ok {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, maxBody, &body); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
			return
		}
	}
	x, err := s.repo.Reject(r.Context(), id, p.UserID, body.Note, s.now())
	if err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.reject", Target: audit.Target{Type: "rule", ID: id},
			Outcome: audit.Failure, Reason: editReason(err), RequestID: httpx.RequestID(r.Context())})
		s.writeRepoError(w, err)
		return
	}
	// The note is free text: it stays in the rule, never in the audit log.
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.reject", Target: audit.Target{Type: "rule", ID: id},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, map[string]string{"note": strconv.FormatBool(body.Note != "")})})
	httpx.WriteJSON(w, http.StatusOK, ruleView{x})
}

// retireRule takes an approved (or stale) rule out of the active set: it
// stays in history as rejected/retired and leaves the next packs.
func (s *Service) retireRule(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(w, r, true, "rule.retire", wellFormedID(r))
	if !ok {
		return
	}
	id, ok := ruleID(w, r)
	if !ok {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, maxBody, &body); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_input", "invalid request body")
			return
		}
	}
	x, err := s.repo.Retire(r.Context(), id, p.UserID, body.Note, s.now())
	if err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.retire", Target: audit.Target{Type: "rule", ID: id},
			Outcome: audit.Failure, Reason: editReason(err), RequestID: httpx.RequestID(r.Context())})
		s.writeRepoError(w, err)
		return
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.retire", Target: audit.Target{Type: "rule", ID: id},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, map[string]string{"note": strconv.FormatBool(body.Note != "")})})
	httpx.WriteJSON(w, http.StatusOK, ruleView{x})
}

// overrideDetail marks det admin_override=true when p reviews rules only
// because it is admin (admin implies rule-reviewer: traced, not refused).
func overrideDetail(p *auth.Principal, det map[string]string) map[string]string {
	if p.AdminOverride(auth.RoleRuleReviewer) {
		det["admin_override"] = "true"
	}
	return det
}
