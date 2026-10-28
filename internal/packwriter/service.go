package packwriter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
	"github.com/ivseb/traffic-twin/internal/store"
	"github.com/ivseb/traffic-twin/internal/world"
)

func init() {
	store.Register(store.Namespace{Name: "packwriter", Migrations: migrations})
}

// DefaultValidDays is the validity of a pack built without valid_days.
const DefaultValidDays = 30

// Packs hold synthetic data only (they passed the gate, or failed it and
// are never served). manifest and gate_report are kept for the UI.
var migrations = []store.Migration{
	{Version: 1, Name: "packs", SQL: `
CREATE TABLE packwriter_packs (
	id            TEXT PRIMARY KEY,
	status        TEXT NOT NULL CHECK (status IN ('building', 'gate-failed', 'signed', 'published')),
	world_id      TEXT NOT NULL,
	created_at    INTEGER NOT NULL,
	created_by    TEXT NOT NULL,
	published_at  INTEGER,
	published_by  TEXT,
	approval_mode TEXT NOT NULL DEFAULT '',
	manifest      BLOB NOT NULL,
	gate_report   BLOB NOT NULL,
	risk          TEXT NOT NULL DEFAULT '',
	archive       BLOB,
	sig           BLOB
) STRICT;`},
	// Multi-team isolation: the group of a pack ('' before, or for a
	// multi-group pack: groups lists them) and its services.
	{Version: 2, Name: "pack group", SQL: `
ALTER TABLE packwriter_packs ADD COLUMN grp TEXT NOT NULL DEFAULT '';
ALTER TABLE packwriter_packs ADD COLUMN groups TEXT NOT NULL DEFAULT '[]';
ALTER TABLE packwriter_packs ADD COLUMN services TEXT NOT NULL DEFAULT '[]';`},
	// Warnings of a pack built on little traffic (JSON list; not part of
	// the signed pack) and their total.
	{Version: 3, Name: "pack warnings", SQL: `
ALTER TABLE packwriter_packs ADD COLUMN warnings TEXT NOT NULL DEFAULT '[]';
ALTER TABLE packwriter_packs ADD COLUMN warnings_total INTEGER NOT NULL DEFAULT 0;`},
}

// Keyguard is what the pack writer needs from tt keyguard (*client.Client).
type Keyguard interface {
	gate.Matcher
	SignPack(ctx context.Context, archive []byte, requester *client.Approval) (*client.PackResult, error)
	PublicKeys(ctx context.Context) (*client.PublicKeys, error)
}

// PoliciesSource returns the signed policies the pack's data were captured
// under (manifest source.policies; keyguard derives domains, epochs and
// kids from them).
type PoliciesSource interface {
	SourcePolicies(ctx context.Context) ([]client.PolicyRef, error)
}

// GroupPoliciesSource is implemented by policy sources that know the groups
// of the policies (tt-core): a group's pack carries only its policies.
type GroupPoliciesSource interface {
	SourcePoliciesIn(ctx context.Context, groups []string) ([]client.PolicyRef, error)
}

// PresetsSource returns stored scenario presets by id.
type PresetsSource interface {
	Presets(ctx context.Context, ids []string) ([]world.Preset, error)
}

// WorldSource regenerates stored worlds (*world.Service).
type WorldSource interface {
	Regenerate(ctx context.Context, id string) (*world.Record, *world.Input, *world.Output, error)
	BuildByID(ctx context.Context, id int64) (*world.Build, error)
}

// Options configures a Service.
type Options struct {
	DB       *store.DB
	Audit    *audit.Log
	Worlds   WorldSource
	Keyguard Keyguard
	Policies PoliciesSource
	// Rules, optional, gives outcome subject counts (RuleSet.OutcomeSubjects).
	Rules   world.RulesSource
	Faults  FaultsSource
	Presets PresetsSource
	// KMin of packs (default 20).
	KMin      int
	TTVersion string
	Locale    string
	Now       func() time.Time
	TempDir   string
	Logger    *slog.Logger
	// Approvals, optional, obtains approval ID tokens bound to a pack when
	// keyguard verifies approvals with OIDC (keyguard.md 3.4).
	Approvals ApprovalTokens
	// ServiceGroups, optional, maps each observed service to the groups
	// whose sources produced it: a pack of a world of every group must not
	// mix groups unless an administrator asks for it (multi_group).
	ServiceGroups func(ctx context.Context) (map[string][]string, error)
	// TestK, optional, gives the lower k of the groups marked as test (spec
	// v1.18): a pack of exactly one such group is built and gated with that
	// k and carries the warning test_k. Packs of several groups keep KMin.
	TestK func(ctx context.Context) (map[string]int, error)
}

// ApprovalTokens is the approval step-up seen by the pack writer.
type ApprovalTokens interface {
	// Verified reports whether keyguard verifies approvals with OIDC.
	Verified() bool
	// ApprovalToken returns p's ID token for (purpose, ref) bound to
	// nonce: explicit when given, else p's pending step-up.
	ApprovalToken(ctx context.Context, p *auth.Principal, purpose, ref, nonce, explicit string) (string, error)
}

// PublishNonce returns the approval binding of publishing pack id
// (approvebind.PackNonce over its manifest), for the step-up.
func (s *Service) PublishNonce(ctx context.Context, id string) (string, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return "", err
	}
	if r.info.Status != gate.StatusSigned {
		return "", apiErr(http.StatusConflict, "not_signed", "the pack is not signed (gate failed)")
	}
	return packNonce(r)
}

func packNonce(r *row) (string, error) {
	files, err := ReadArchive(r.archive)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(files[ManifestPath])
	return approvebind.PackNonce(r.info.PackID, hex.EncodeToString(sum[:])), nil
}

// Service implements gate.PackService.
type Service struct {
	o Options
}

var _ gate.PackService = (*Service)(nil)

// New builds a Service.
func New(o Options) (*Service, error) {
	if o.DB == nil || o.Audit == nil || o.Worlds == nil || o.Keyguard == nil || o.Policies == nil {
		return nil, errors.New("packwriter: db, audit, worlds, keyguard and policies are required")
	}
	if o.KMin == 0 {
		o.KMin = 20
	}
	if o.KMin < 2 {
		return nil, errors.New("packwriter: k_min must be >= 2")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Locale == "" {
		o.Locale = "it"
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{o: o}, nil
}

func apiErr(status int, code, msg string) error { return gate.Errorf(status, code, msg) }

var errNotFound = apiErr(http.StatusNotFound, "not_found", "not found")

func (s *Service) record(ctx context.Context, e audit.Event) {
	if e.RequestID == "" {
		e.RequestID = httpx.RequestID(ctx)
	}
	if _, err := s.o.Audit.Record(ctx, e); err != nil {
		s.o.Logger.ErrorContext(ctx, "packwriter: audit write failed", "action", e.Action, "err", err)
	}
}

// BuildPack assembles a pack from a stored world, runs the gate and, when
// it passes, asks keyguard to sign it and verifies the signed pack.
func (s *Service) BuildPack(ctx context.Context, p *auth.Principal, req gate.BuildRequest) (*gate.PackInfo, error) {
	info, err := s.build(ctx, p, req)
	ev := audit.Event{Actor: p.AuditActor(), Action: "pack.build", Target: audit.Target{Type: "pack"}, Outcome: audit.Success}
	if info != nil {
		ev.Target.ID = info.PackID
		ev.Details = map[string]string{"status": info.Status, "world_id": audit.SafeValue(req.WorldID)}
		if info.Status == gate.StatusGateFailed {
			ev.Outcome, ev.Reason = audit.Failure, "gate_failed"
		}
	}
	if err != nil {
		ev.Outcome, ev.Reason = audit.Failure, "build_failed"
		var ae *gate.APIError
		if errors.As(err, &ae) {
			ev.Reason = ae.Code
		}
	}
	s.record(ctx, ev)
	return info, err
}

func (s *Service) build(ctx context.Context, p *auth.Principal, req gate.BuildRequest) (*gate.PackInfo, error) {
	rec, in, out, err := s.o.Worlds.Regenerate(ctx, req.WorldID)
	if err != nil {
		var we *world.APIError
		if errors.As(err, &we) {
			return nil, apiErr(we.Status, we.Code, we.Message)
		}
		return nil, err
	}
	if probs := world.Verify(out.World, in.Rules); len(probs) > 0 {
		return nil, apiErr(http.StatusUnprocessableEntity, "world_integrity", "the world breaks integrity rules")
	}
	// The world fixes the group: its contracts are that group's traffic.
	group := rec.Group
	if req.Group != "" && rec.Group != "" && rec.Group != req.Group {
		return nil, gate.ErrorDetails(http.StatusUnprocessableEntity, "group_mismatch", "the world belongs to another group",
			[]map[string]any{{"world_group": rec.Group, "group": req.Group}})
	}
	if req.MultiGroup && !p.IsAdmin() {
		return nil, apiErr(http.StatusForbidden, "multi_group_forbidden", "only an administrator can build a pack with the services of several groups")
	}
	contracts, err := selectContracts(in, req.Services, req.ExcludeServices)
	if err != nil {
		return nil, err
	}
	groups, err := s.packGroups(ctx, group, contracts, req.MultiGroup)
	if err != nil {
		return nil, err
	}
	if group == "" && len(groups) == 1 {
		group = groups[0]
	}
	if req.Group != "" && group != req.Group && !req.MultiGroup {
		// A world of every group whose services are not the asked group's.
		return nil, gate.ErrorDetails(http.StatusUnprocessableEntity, "group_mismatch", "the services of the world are not the group's: generate the world for the group",
			[]map[string]any{{"world_group": rec.Group, "group": req.Group}})
	}
	var pols []client.PolicyRef
	if gp, ok := s.o.Policies.(GroupPoliciesSource); ok && len(groups) > 0 {
		pols, err = gp.SourcePoliciesIn(ctx, groups)
	} else {
		pols, err = s.o.Policies.SourcePolicies(ctx)
	}
	if err != nil {
		return nil, err
	}
	if len(pols) == 0 {
		return nil, apiErr(http.StatusConflict, "no_policies", "no signed source policy: the gate cannot run")
	}
	var rs *world.RuleSet
	if s.o.Rules != nil {
		if rs, err = s.o.Rules.ApprovedRules(ctx); err != nil {
			return nil, err
		}
	}
	kmin, testK, err := s.packKMin(ctx, group, groups, req.MultiGroup)
	if err != nil {
		return nil, err
	}
	var faults *Faults
	if s.o.Faults != nil {
		if faults, err = s.o.Faults.Faults(ctx, contracts, kmin); err != nil {
			return nil, err
		}
	}
	presets := world.DerivePresets(in.Rules, out.Customers, faults.Hints(), s.o.Locale)
	var texts []string
	if len(req.ScenarioPresets) > 0 {
		if s.o.Presets == nil {
			return nil, apiErr(http.StatusUnprocessableEntity, "unknown_preset", "no stored scenario presets")
		}
		stored, err := s.o.Presets.Presets(ctx, req.ScenarioPresets)
		if err != nil {
			return nil, err
		}
		if err := checkPresets(stored, in, out, contracts); err != nil {
			return nil, err
		}
		for _, sp := range stored {
			texts = append(texts, sp.Name, sp.Description)
		}
		presets = mergePresets(presets, stored)
	}
	now := s.o.Now().UTC().Truncate(time.Second)
	id, err := s.nextID(ctx, now)
	if err != nil {
		return nil, err
	}
	a := &Assembly{PackID: id, CreatedAt: now, KMin: kmin, TTVersion: s.o.TTVersion, Policies: pols, Contracts: contracts,
		Rules: in.Rules, RuleSet: rs, World: out, Seed: rec.Seed, Presets: presets, PresetTexts: texts, Faults: faults,
		Anonymize: req.AnonymizeHosts == nil || *req.AnonymizeHosts, Archetypes: rec.Archetypes}
	if !req.MultiGroup && len(groups) <= 1 {
		a.Group = group
	}
	a.Window = [2]time.Time{rec.T0.Add(-rec.Window), rec.T0}
	if w, ok := in.Rules.Doc["window"].(map[string]any); ok {
		f, e1 := time.Parse(time.RFC3339, fmt.Sprint(w["from"]))
		t, e2 := time.Parse(time.RFC3339, fmt.Sprint(w["to"]))
		if e1 == nil && e2 == nil {
			a.Window = [2]time.Time{f, t}
		}
	}
	// A pack always expires (pack.md 2.1): without valid_days it is valid
	// DefaultValidDays days, so a leaked old pack is not good forever.
	days := DefaultValidDays
	if req.ValidDays != nil {
		days = *req.ValidDays
	}
	na := now.Add(time.Duration(days) * 24 * time.Hour)
	a.NotAfter = &na
	var risk *gate.RiskInput
	if rec.BuildID > 0 {
		if b, err := s.o.Worlds.BuildByID(ctx, rec.BuildID); err == nil && b != nil {
			risk = RiskInput(b)
		}
	}
	res, files, err := s.Gate(ctx, a, risk)
	if err != nil {
		return nil, err
	}
	info := &gate.PackInfo{PackID: id, Status: gate.StatusGateFailed, CreatedAt: now, WorldID: rec.WorldID, ResidualRisk: res.Risk,
		Group: group, Groups: groups, Services: contractNames(contracts)}
	warns := observationWarnings(contracts, in.Rules, kmin, a.Window)
	if testK {
		used := int64(kmin)
		warns = append([]gate.PackWarning{{Code: gate.WarnTestK, Scope: "pack", Unit: "subjects", Observed: &used, Needed: int64(s.o.KMin)}}, warns...)
	}
	info.Warnings, info.WarningsTotal = capWarnings(warns)
	if !res.Passed() {
		return info, s.store(ctx, info, p, files[ManifestPath], files[GateReportPath], nil, nil)
	}
	unsigned, err := Archive(files)
	if err != nil {
		return nil, err
	}
	pr, err := s.sign(ctx, unsigned, nil)
	if err != nil {
		var ce *client.Error
		if errors.As(err, &ce) && ce.Status == http.StatusForbidden {
			// keyguard refused (its own reverse-HMAC, gate report, hashes):
			// record the failure with keyguard's findings.
			rep := res.Report
			rep.Verdict = "fail"
			for i := range rep.Checks {
				if rep.Checks[i].ID == gate.CheckReverseHMAC && ce.ReverseHMAC != nil {
					rep.Checks[i].Status = "fail"
					for _, f := range ce.ReverseHMAC.Findings {
						rep.Checks[i].Findings = append(rep.Checks[i].Findings, gate.Finding{File: f.File, Pointer: f.Pointer, Reason: f.Reason})
					}
				}
			}
			return info, s.store(ctx, info, p, files[ManifestPath], rep.File(), nil, nil)
		}
		return nil, err
	}
	sig := pr.Signature.SigFile()
	if err := s.Verify(ctx, files, sig); err != nil {
		s.o.Logger.ErrorContext(ctx, "packwriter: signed pack does not verify", "pack_id", id, "err", err)
		return nil, apiErr(http.StatusInternalServerError, "verify_failed", "the signed pack does not verify")
	}
	info.Status = gate.StatusSigned
	return info, s.store(ctx, info, p, files[ManifestPath], files[GateReportPath], unsigned, sig)
}

// Gate assembles the pack, runs the gate and adds report and manifest.
func (s *Service) Gate(ctx context.Context, a *Assembly, risk *gate.RiskInput) (*gate.Result, map[string][]byte, error) {
	as, err := Assemble(a)
	if err != nil {
		return nil, nil, err
	}
	var sizes []gate.ArchetypeSize
	for _, ar := range a.Archetypes {
		sizes = append(sizes, gate.ArchetypeSize{ID: ar.ID, Size: ar.Size})
	}
	res, err := gate.Run(ctx, &gate.Input{PackID: a.PackID, KMin: a.KMin, Files: as.Files, ContractServices: as.ContractServices,
		Prov: as.Prov, Archetypes: sizes, OutcomeSubjects: as.OutcomeSubjects, Combos: as.Combos, Policies: a.Policies, Matcher: s.o.Keyguard, Risk: risk})
	if err != nil {
		return nil, nil, err
	}
	files, err := as.Finish(res.Report)
	if err != nil {
		return nil, nil, err
	}
	return res, files, nil
}

// RiskInput converts an archetype build to the gate's risk input.
func RiskInput(b *world.Build) *gate.RiskInput {
	r := &gate.RiskInput{Dropped: b.Dropped}
	for _, c := range b.Classes {
		r.Classes = append(r.Classes, gate.Class{Vector: c.Vector, Count: c.Count})
	}
	for _, a := range b.Archetypes {
		oc := a.Features.Outcome
		if oc == "" {
			oc = "none"
		}
		ar := gate.ArchetypeRisk{ID: a.ID, Vector: []string{a.Features.OrdersPerMonth, a.Features.ActiveHours, a.Features.ErrorRate, a.Features.PrimaryOp, oc}}
		for _, m := range b.Members[a.ID] {
			ar.Members = append(ar.Members, gate.Class{Vector: m.Vector, Count: m.Count})
		}
		r.Archetypes = append(r.Archetypes, ar)
	}
	return r
}

// packGroups returns the groups of a pack: the given group (its world's
// contracts are that group's traffic only), else the groups of the
// selected services. A world of every group whose services belong to more
// than one group (two teams, or one host:port two teams call: its contract
// mixes their calls) is refused unless multi (an administrator's explicit
// choice); then every group of the services is listed.
func (s *Service) packGroups(ctx context.Context, group string, contracts []world.Contract, multi bool) ([]string, error) {
	if group != "" {
		return []string{group}, nil
	}
	if s.o.ServiceGroups == nil {
		return nil, nil
	}
	sg, err := s.o.ServiceGroups(ctx)
	if err != nil {
		return nil, err
	}
	union := map[string]bool{}
	shared := false
	for _, c := range contracts {
		gs := sg[c.Service]
		shared = shared || len(gs) > 1
		for _, g := range gs {
			union[g] = true
		}
	}
	if !multi && (shared || len(union) > 1) {
		return nil, mixedGroups(contracts, sg)
	}
	out := make([]string, 0, len(union))
	for g := range union {
		out = append(out, g)
	}
	slices.Sort(out)
	return out, nil
}

func mixedGroups(contracts []world.Contract, sg map[string][]string) error {
	var details []map[string]any
	for _, c := range contracts {
		details = append(details, map[string]any{"service": c.Service, "groups": nonNilStrings(sg[c.Service])})
	}
	return gate.ErrorDetails(http.StatusUnprocessableEntity, "mixed_groups",
		"the selected services belong to several groups: generate the world for one group, exclude the other groups' services, or (administrator) set multi_group", details)
}

func contractNames(cs []world.Contract) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Service)
	}
	slices.Sort(out)
	return out
}

func selectContracts(in *world.Input, services, exclude []string) ([]world.Contract, error) {
	var out []world.Contract
	have := map[string]bool{}
	for _, c := range in.Contracts {
		if len(services) > 0 && !slices.Contains(services, c.Service) {
			continue
		}
		if slices.Contains(exclude, c.Service) {
			continue
		}
		out = append(out, c)
		have[c.Service] = true
	}
	var unknown []map[string]any
	for _, sname := range services {
		if !have[sname] {
			unknown = append(unknown, map[string]any{"service": sname})
		}
	}
	if len(unknown) > 0 {
		return nil, gate.ErrorDetails(http.StatusUnprocessableEntity, "unknown_service", "a requested service has no contract: "+listServices(unknown), unknown)
	}
	if err := checkRulesServices(in.Rules, have); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, apiErr(http.StatusUnprocessableEntity, "no_services", "no contract to publish")
	}
	return out, nil
}

// checkRulesServices refuses a pack whose rules use a service that is not in it, and says which
// services are missing, which rules need them and what to do: include the service, or leave the
// rule out (generate the world again for the services of the team).
func checkRulesServices(r *world.Rules, have map[string]bool) error {
	byService := map[string][]string{} // missing service -> rule ids
	needs := r.Needs()
	for _, id := range r.IDs {
		for _, sv := range needs[id] {
			if !have[sv] {
				byService[sv] = append(byService[sv], id)
			}
		}
	}
	entities := map[string][]string{} // missing service -> entities no rule explains
	for name, ss := range r.EntityNeeds() {
		for _, sv := range ss {
			if !have[sv] && len(byService[sv]) == 0 {
				entities[sv] = append(entities[sv], name)
			}
		}
	}
	if len(byService) == 0 && len(entities) == 0 {
		return nil
	}
	names := map[string]bool{}
	for sv := range byService {
		names[sv] = true
	}
	for sv := range entities {
		names[sv] = true
	}
	var details []map[string]any
	for _, sv := range slices.Sorted(maps.Keys(names)) {
		d := map[string]any{"service": sv, "rules": nonNilStrings(byService[sv])}
		if es := entities[sv]; len(es) > 0 {
			slices.Sort(es)
			d["entities"] = es
		}
		details = append(details, d)
	}
	return gate.ErrorDetails(http.StatusUnprocessableEntity, "missing_service",
		"the rules use a service that is not in the pack: "+listMissing(details)+"; include the service or leave the rules out (generate the world again for the services of the pack)", details)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	slices.Sort(s)
	return s
}

func listServices(details []map[string]any) string {
	var parts []string
	for _, d := range details {
		parts = append(parts, fmt.Sprint(d["service"]))
	}
	return strings.Join(parts, ", ")
}

// listMissing renders "r-0007, r-0008 need shipping-ext; r-0009 needs payments-ext" (bounded).
func listMissing(details []map[string]any) string {
	var parts []string
	for _, d := range details {
		rules, _ := d["rules"].([]string)
		what := "rules " + strings.Join(rules, ", ")
		if len(rules) == 1 {
			what = "rule " + rules[0]
		}
		if len(rules) == 0 {
			what = "entities"
			if es, ok := d["entities"].([]string); ok {
				what += " " + strings.Join(es, ", ")
			}
		}
		parts = append(parts, what+" need "+fmt.Sprint(d["service"]))
	}
	s := strings.Join(parts, "; ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func checkPresets(ps []world.Preset, in *world.Input, out *world.Output, contracts []world.Contract) error {
	custs := map[string]bool{}
	for _, c := range out.Customers {
		custs[c.ID] = true
	}
	arch := map[string]bool{}
	for _, a := range in.Archetypes {
		arch[a.ID] = true
	}
	svcs := map[string]bool{}
	for _, c := range contracts {
		svcs[c.Service] = true
	}
	bad := apiErr(http.StatusUnprocessableEntity, "invalid_preset", "a scenario preset cites customers, archetypes, rules or services not in the pack")
	for _, p := range ps {
		if (p.Customer != "" && !custs[p.Customer]) || (p.Archetype != "" && !arch[p.Archetype]) || (p.Customer != "" && p.Archetype != "") {
			return bad
		}
		for _, o := range p.Outcomes {
			ok := false
			for _, c := range in.Rules.Causal {
				if c.ID == o.Rule {
					for _, oc := range c.Outcomes {
						ok = ok || oc.Name == o.Outcome
					}
				}
			}
			if !ok {
				return bad
			}
		}
		if rules, ok := p.Faults["rules"].([]any); ok {
			for _, x := range rules {
				m, _ := x.(map[string]any)
				if sv, _ := m["service"].(string); !svcs[sv] {
					return bad
				}
			}
		}
	}
	return nil
}

func mergePresets(derived, stored []world.Preset) []world.Preset {
	ids := map[string]bool{}
	for _, p := range stored {
		ids[p.ID] = true
	}
	out := append([]world.Preset(nil), stored...)
	for _, p := range derived {
		if !ids[p.ID] {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) nextID(ctx context.Context, now time.Time) (string, error) {
	day := now.Format("20060102")
	var n int
	if err := s.o.DB.QueryRowContext(ctx, `SELECT count(*) FROM packwriter_packs WHERE id LIKE ?`, "pk-"+day+"-%").Scan(&n); err != nil {
		return "", err
	}
	return fmt.Sprintf("pk-%s-%04d", day, n+1), nil
}

// sign calls keyguard, waiting on its rate limit.
func (s *Service) sign(ctx context.Context, archive []byte, req *client.Approval) (*client.PackResult, error) {
	for attempt := 0; ; attempt++ {
		pr, err := s.o.Keyguard.SignPack(ctx, archive, req)
		if err == nil {
			return pr, nil
		}
		if !client.IsRateLimited(err) || attempt >= 30 {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1100 * time.Millisecond):
		}
	}
}

// Verify loads the signed pack with internal/pack (signature with
// keyguard's public keys, manifest, hashes, content and world integrity,
// not_after) before it is declared good.
func (s *Service) Verify(ctx context.Context, files map[string][]byte, sig []byte) error {
	pks, err := s.o.Keyguard.PublicKeys(ctx)
	if err != nil {
		return err
	}
	keys, err := pack.ParseKeySet(pks.GatePubKeys())
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(s.o.TempDir, "ttpack-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	all := map[string][]byte{SignaturePath: sig}
	for p, b := range files {
		all[p] = b
	}
	if err := WriteDir(dir, all); err != nil {
		return err
	}
	_, err = pack.Load(dir, pack.Options{Keys: keys, Now: s.o.Now})
	return err
}

func (s *Service) store(ctx context.Context, info *gate.PackInfo, p *auth.Principal, manifest, report, archive, sig []byte) error {
	var risk string
	if info.ResidualRisk != nil {
		b, _ := json.Marshal(info.ResidualRisk)
		risk = string(b)
	}
	groupsJ, _ := json.Marshal(nonNilStrings(info.Groups))
	servicesJ, _ := json.Marshal(nonNilStrings(info.Services))
	if info.Warnings == nil {
		info.Warnings = []gate.PackWarning{}
	}
	warnJ, _ := json.Marshal(info.Warnings)
	_, err := s.o.DB.ExecContext(ctx, `INSERT INTO packwriter_packs (id, status, world_id, created_at, created_by, manifest, gate_report, risk, archive, sig, grp, groups, services, warnings, warnings_total) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		info.PackID, info.Status, info.WorldID, info.CreatedAt.Unix(), p.UserID, manifest, report, risk, archive, sig, info.Group, string(groupsJ), string(servicesJ), string(warnJ), info.WarningsTotal)
	if err != nil {
		return err
	}
	info.Manifest, info.GateReport = manifest, report
	return nil
}

type row struct {
	info     gate.PackInfo
	archive  []byte
	sig      []byte
	approval string
}

func (s *Service) load(ctx context.Context, id string) (*row, error) {
	var r row
	var created int64
	var pub sql.NullInt64
	var risk string
	var man, rep []byte
	var groupsJ, servicesJ, warnJ string
	err := s.o.DB.QueryRowContext(ctx, `SELECT id, status, world_id, created_at, published_at, approval_mode, manifest, gate_report, risk, archive, sig, grp, groups, services, warnings, warnings_total FROM packwriter_packs WHERE id = ?`, id).
		Scan(&r.info.PackID, &r.info.Status, &r.info.WorldID, &created, &pub, &r.info.ApprovalMode, &man, &rep, &risk, &r.archive, &r.sig, &r.info.Group, &groupsJ, &servicesJ, &warnJ, &r.info.WarningsTotal)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groupsJ), &r.info.Groups)
	_ = json.Unmarshal([]byte(servicesJ), &r.info.Services)
	_ = json.Unmarshal([]byte(warnJ), &r.info.Warnings)
	if r.info.Warnings == nil {
		r.info.Warnings = []gate.PackWarning{}
	}
	r.info.CreatedAt = time.Unix(created, 0).UTC()
	if pub.Valid {
		t := time.Unix(pub.Int64, 0).UTC()
		r.info.PublishedAt = &t
	}
	r.info.Manifest, r.info.GateReport = man, rep
	if risk != "" {
		var rr gate.ResidualRisk
		if json.Unmarshal([]byte(risk), &rr) == nil {
			r.info.ResidualRisk = &rr
		}
	}
	return &r, nil
}

// GetPack implements gate.PackService.
func (s *Service) GetPack(ctx context.Context, id string) (*gate.PackInfo, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	return &r.info, nil
}

// ListPacks implements gate.PackService (without manifests).
func (s *Service) ListPacks(ctx context.Context) ([]gate.PackInfo, error) {
	rows, err := s.o.DB.QueryContext(ctx, `SELECT id, status, world_id, created_at, published_at, approval_mode, gate_report, risk, grp, groups, services, warnings, warnings_total FROM packwriter_packs ORDER BY created_at DESC, id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gate.PackInfo{}
	for rows.Next() {
		var i gate.PackInfo
		var created int64
		var pub sql.NullInt64
		var rep []byte
		var risk, groupsJ, servicesJ, warnJ string
		if err := rows.Scan(&i.PackID, &i.Status, &i.WorldID, &created, &pub, &i.ApprovalMode, &rep, &risk, &i.Group, &groupsJ, &servicesJ, &warnJ, &i.WarningsTotal); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(groupsJ), &i.Groups)
		_ = json.Unmarshal([]byte(servicesJ), &i.Services)
		_ = json.Unmarshal([]byte(warnJ), &i.Warnings)
		if i.Warnings == nil {
			i.Warnings = []gate.PackWarning{}
		}
		if risk != "" {
			var rr gate.ResidualRisk
			if json.Unmarshal([]byte(risk), &rr) == nil {
				i.ResidualRisk = &rr
			}
		}
		i.CreatedAt = time.Unix(created, 0).UTC()
		if pub.Valid {
			t := time.Unix(pub.Int64, 0).UTC()
			i.PublishedAt = &t
		}
		i.GateReport = rep
		out = append(out, i)
	}
	return out, rows.Err()
}

// PublishPack implements gate.PackService: keyguard signs the pack again
// with the requester's approval (X-TT-Approval: a publisher, or an admin
// with a reason), the signature must be the same (Ed25519 is
// deterministic), the pack is verified again and marked published.
func (s *Service) PublishPack(ctx context.Context, p *auth.Principal, id, reason, idToken string) (*gate.PackInfo, error) {
	ev := audit.Event{Actor: p.AuditActor(), Action: "pack.publish", Target: audit.Target{Type: "pack", ID: audit.SafeValue(id)}, Outcome: audit.Failure}
	fail := func(err error, reason string) (*gate.PackInfo, error) {
		ev.Reason = reason
		s.record(ctx, ev)
		return nil, err
	}
	r, err := s.load(ctx, id)
	if err != nil {
		return fail(err, "not_found")
	}
	switch r.info.Status {
	case gate.StatusPublished:
		return &r.info, nil
	case gate.StatusSigned:
	default:
		return fail(apiErr(http.StatusConflict, "not_signed", "the pack is not signed (gate failed)"), "not_signed")
	}
	if len(r.archive) == 0 {
		// Expired or superseded unpublished pack whose archive the
		// maintenance removed (retention.go): build it again.
		return fail(apiErr(http.StatusGone, "pack_pruned", "the archive of this unpublished pack was removed by the retention; build the pack again"), "pack_pruned")
	}
	// The approval keyguard sees carries the roles the requester holds now
	// (read at this request). A requester holding admin always approves as
	// an admin override, also with publisher: reason required, keyguard
	// signs in approval_mode admin and raises pack.admin_approval.
	var roles []string
	switch {
	case p.Has(auth.RoleAdmin):
		if reasonEmpty(reason) {
			return fail(apiErr(http.StatusForbidden, "admin_reason_required", "an admin approval needs a reason"), "admin_reason_required")
		}
		roles = []string{string(auth.RoleAdmin)}
	case p.Has(auth.RolePublisher):
		roles = []string{string(auth.RolePublisher)}
	default:
		return fail(apiErr(http.StatusForbidden, "forbidden", "insufficient role"), "missing_role")
	}
	now := s.o.Now().UTC()
	appr := &client.Approval{User: p.UserID, Roles: roles, At: now, Reason: reason}
	if idToken != "" && p.OIDCSubject == "" {
		return fail(apiErr(http.StatusForbidden, "id_token_not_allowed", "local accounts cannot attach OIDC ID tokens"), "id_token_not_allowed")
	}
	if s.o.Approvals != nil && s.o.Approvals.Verified() {
		// keyguard verifies the requester with OIDC: a step-up token bound
		// to this pack and manifest (RT3-KG-3).
		nonce, err := packNonce(r)
		if err != nil {
			return fail(err, "corrupt")
		}
		tok, err := s.o.Approvals.ApprovalToken(ctx, p, approvebind.PurposePack, id, nonce, idToken)
		if err != nil {
			status, code, msg := auth.ApprovalTokenError(err, idToken != "")
			return fail(apiErr(status, code, msg), code)
		}
		appr.IDToken = tok
	}
	pr, err := s.sign(ctx, r.archive, appr)
	if err != nil {
		var ce *client.Error
		if errors.As(err, &ce) && ce.Status == http.StatusForbidden {
			return fail(apiErr(http.StatusForbidden, "keyguard_refused", "keyguard refused to sign the pack"), "keyguard_"+audit.SafeValue(ce.Code))
		}
		return fail(err, "keyguard_unreachable")
	}
	sig := pr.Signature.SigFile()
	if !bytes.Equal(sig, r.sig) {
		return fail(apiErr(http.StatusConflict, "signature_changed", "keyguard returned a different signature"), "signature_changed")
	}
	files, err := ReadArchive(r.archive)
	if err != nil {
		return fail(err, "corrupt")
	}
	if err := s.Verify(ctx, files, sig); err != nil {
		if errors.Is(err, pack.ErrExpired) {
			return fail(apiErr(http.StatusConflict, "pack_expired", "the pack is past its not_after"), "pack_expired")
		}
		return fail(apiErr(http.StatusInternalServerError, "verify_failed", "the signed pack does not verify"), "verify_failed")
	}
	res, err := s.o.DB.ExecContext(ctx, `UPDATE packwriter_packs SET status = 'published', published_at = ?, published_by = ?, approval_mode = ? WHERE id = ? AND status = 'signed'`,
		now.Unix(), p.UserID, pr.ApprovalMode, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fail(apiErr(http.StatusConflict, "conflict", "the pack changed meanwhile"), "conflict")
	}
	ev.Outcome = audit.Success
	ev.Details = map[string]string{"approval_mode": audit.SafeValue(pr.ApprovalMode), "kid": audit.SafeValue(pr.Signature.Kid),
		"strings_checked": strconv.FormatInt(pr.ReverseHMAC.StringsChecked, 10)}
	s.record(ctx, ev)
	return s.GetPack(ctx, id)
}

func reasonEmpty(s string) bool { return len(bytes.TrimSpace([]byte(s))) == 0 }

// PackArchive implements gate.PackService: the .ttpack of a published pack
// (with manifest.sig.json). Downloads are audited.
func (s *Service) PackArchive(ctx context.Context, p *auth.Principal, id string) ([]byte, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.info.Status != gate.StatusPublished {
		return nil, apiErr(http.StatusConflict, "not_published", "only published packs can be downloaded")
	}
	files, err := ReadArchive(r.archive)
	if err != nil {
		return nil, err
	}
	files[SignaturePath] = r.sig
	b, err := Archive(files)
	if err != nil {
		return nil, err
	}
	det := map[string]string{"bytes": strconv.Itoa(len(b))}
	if p.AdminOverride(auth.RolePublisher) {
		det["admin_override"] = "true" // admin implies publisher: traced, not refused
	}
	s.record(ctx, audit.Event{Actor: p.AuditActor(), Action: "pack.download", Target: audit.Target{Type: "pack", ID: id}, Outcome: audit.Success,
		Details: det})
	return b, nil
}

// LatestPublished is the id of the newest published pack built for group
// ("" when there is none). A mock in console mode serves it.
func (s *Service) LatestPublished(ctx context.Context, group string) (string, error) {
	var id string
	err := s.o.DB.QueryRowContext(ctx, `SELECT id FROM packwriter_packs WHERE status = 'published' AND grp = ? ORDER BY published_at DESC, id DESC LIMIT 1`, group).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// MockArchive is the .ttpack of a published pack of group for a mock in
// console mode (internal/mockreg), the download audited as actor (the
// mock token).
func (s *Service) MockArchive(ctx context.Context, id, group string, actor audit.Actor) ([]byte, error) {
	r, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.info.Status != gate.StatusPublished || r.info.Group != group {
		return nil, apiErr(http.StatusNotFound, "not_found", "no published pack of this group")
	}
	files, err := ReadArchive(r.archive)
	if err != nil {
		return nil, err
	}
	files[SignaturePath] = r.sig
	b, err := Archive(files)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{Actor: actor, Action: "pack.download", Target: audit.Target{Type: "pack", ID: id}, Outcome: audit.Success,
		Details: map[string]string{"bytes": strconv.Itoa(len(b)), "group": audit.SafeValue(group), "via": "mock_token"}})
	return b, nil
}

// packKMin is the k of a pack: the lower k of its group when the pack is of
// exactly one group marked as test (spec v1.18, C0), else Options.KMin. A
// pack of several groups never takes a test k: the low-k rules of a test
// group then fail the gate, which is the safe outcome.
func (s *Service) packKMin(ctx context.Context, group string, groups []string, multi bool) (int, bool, error) {
	if s.o.TestK == nil || multi || len(groups) > 1 || group == "" {
		return s.o.KMin, false, nil
	}
	m, err := s.o.TestK(ctx)
	if err != nil {
		return 0, false, err
	}
	if k := m[group]; k >= 2 && k < s.o.KMin {
		return k, true, nil
	}
	return s.o.KMin, false, nil
}
