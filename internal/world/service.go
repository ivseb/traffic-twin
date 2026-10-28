package world

import (
	"bufio"
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
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/idfmt"
	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "world", Migrations: migrations})
}

// Archetype builds and generated worlds. World bytes are synthetic; the
// archetype class histograms hold no token but are zone-B data that no API
// returns.
var migrations = []store.Migration{
	{Version: 1, Name: "archetype builds and worlds", SQL: `
CREATE TABLE world_builds (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	k_min       INTEGER NOT NULL,
	window_from INTEGER NOT NULL,
	window_to   INTEGER NOT NULL,
	profiles    INTEGER NOT NULL,
	dropped     INTEGER NOT NULL,
	archetypes  TEXT NOT NULL,
	classes     TEXT NOT NULL,
	members     TEXT NOT NULL,
	created_at  INTEGER NOT NULL
) STRICT;
CREATE TABLE world_worlds (
	id          TEXT PRIMARY KEY,
	seed        INTEGER NOT NULL,
	customers   INTEGER NOT NULL,
	build_id    INTEGER REFERENCES world_builds(id),
	archetypes  TEXT NOT NULL,
	t0          INTEGER NOT NULL,
	window_s    INTEGER NOT NULL,
	locale      TEXT NOT NULL,
	rules       TEXT NOT NULL,
	inputs_sha  TEXT NOT NULL,
	world_sha   TEXT NOT NULL,
	world       BLOB NOT NULL,
	synthetic   BLOB NOT NULL,
	customers_json TEXT NOT NULL,
	entities    INTEGER NOT NULL,
	history     INTEGER NOT NULL,
	pending     INTEGER NOT NULL,
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL
) STRICT;`},
	{Version: 2, Name: "world scope", SQL: `ALTER TABLE world_worlds ADD COLUMN services TEXT NOT NULL DEFAULT '[]';`},
	// Multi-team isolation: archetypes are built from one group's traffic
	// and a world belongs to one group ('' before: every group).
	{Version: 3, Name: "world group", SQL: `
ALTER TABLE world_builds ADD COLUMN grp TEXT NOT NULL DEFAULT '';
ALTER TABLE world_worlds ADD COLUMN grp TEXT NOT NULL DEFAULT '';`},
}

// Options configures a Service.
type Options struct {
	DB        *store.DB
	Audit     *audit.Log
	Events    EventSource
	Outcomes  OutcomeSource
	Contracts ContractsSource
	Rules     RulesSource
	Now       func() time.Time
	// ProfileWindow is the event window of archetype builds (default 30 days
	// before now).
	ProfileWindow time.Duration
	// Locale of invented names ("it" default, "en").
	Locale string
	// KMin is the configured minimum archetype size (world.k_min); the
	// archetype list reports it while there is no build yet.
	KMin   int
	Logger *slog.Logger
	// Groups attributes event sources to groups (fleet); optional. With it
	// archetypes and worlds can be built from one group's traffic.
	Groups groupscope.Resolver
	// IDFormats gives the id formats chosen in the console (optional,
	// docs/spec/pack.md 4.3); they are written into the contracts of the
	// inputs, so the world, the pack and the mock use them.
	IDFormats IDFormatSource
	// DateOffsets gives the relative dates chosen in the console
	// (optional, docs/spec/pack.md 4.4), written into the contracts of the
	// inputs over the ranges learned from the traffic.
	DateOffsets DateOffsetSource
}

// DateOffsetSource returns the relative dates of a group by field name.
type DateOffsetSource interface {
	DateOffsetsIn(ctx context.Context, group string) (map[string]dateoff.Range, error)
}

// WithDateOffsets returns copies of the contracts with the ranges written
// in (dateoff.Annotate).
func WithDateOffsets(cs []Contract, ranges map[string]dateoff.Range) ([]Contract, error) {
	if len(ranges) == 0 {
		return cs, nil
	}
	out := make([]Contract, len(cs))
	for i, c := range cs {
		doc, err := dateoff.Annotate(c.Doc, ranges)
		if err != nil {
			return nil, fmt.Errorf("world: relative dates of %s: %w", c.Service, err)
		}
		c.Doc = doc
		out[i] = c
	}
	return out, nil
}

// IDFormatSource returns the id formats of a group by id domain.
type IDFormatSource interface {
	IDFormatsIn(ctx context.Context, group string) (map[string]string, error)
}

// WithIDFormats returns copies of the contracts with the id formats written
// in (idfmt.Annotate): x-tt-value.id_format on the id fields of those
// domains, example ids in the format. The ids it writes are synthetic.
func WithIDFormats(cs []Contract, formats map[string]string) ([]Contract, error) {
	if len(formats) == 0 {
		return cs, nil
	}
	out := make([]Contract, len(cs))
	for i, c := range cs {
		doc, synth, err := idfmt.Annotate(c.Doc, formats)
		if err != nil {
			return nil, fmt.Errorf("world: id formats of %s: %w", c.Service, err)
		}
		c.Doc = doc
		c.Synthetic = append(append([]string(nil), c.Synthetic...), synth...)
		out[i] = c
	}
	return out, nil
}

// Service stores archetypes and worlds and serves the admin API.
type Service struct {
	o Options
}

// New builds a Service.
func New(o Options) (*Service, error) {
	if o.DB == nil || o.Audit == nil || o.Contracts == nil || o.Rules == nil {
		return nil, errors.New("world: db, audit, contracts and rules are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ProfileWindow <= 0 {
		o.ProfileWindow = 30 * 24 * time.Hour
	}
	if o.Locale == "" {
		o.Locale = "it"
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{o: o}, nil
}

// APIError is an error with an HTTP status and a stable code; messages are
// fixed strings.
type APIError struct {
	Status        int
	Code, Message string
	// Details name what the error is about (services, rule ids), see httpx.Error.
	Details []map[string]any
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func apiErr(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg}
}

// ErrNotFound is returned for unknown worlds or customers.
var ErrNotFound = apiErr(http.StatusNotFound, "not_found", "not found")

// BuildArchetypes rebuilds the archetypes from the events of the profile
// window and stores them.
func (s *Service) BuildArchetypes(ctx context.Context, kMin int) (*Build, int64, error) {
	return s.BuildArchetypesIn(ctx, kMin, "")
}

// groupSources returns the sources of a group (nil: every group).
func (s *Service) groupSources(ctx context.Context, group string) ([]string, error) {
	if group == "" || s.o.Groups == nil {
		return nil, nil
	}
	m, err := s.o.Groups.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	return groupscope.Set{group}.Sources(m), nil
}

// BuildArchetypesIn rebuilds the archetypes of one group ("" every group)
// from the inbound events of its sources: the customers of another team
// never shape this team's archetypes nor its residual risk.
func (s *Service) BuildArchetypesIn(ctx context.Context, kMin int, group string) (*Build, int64, error) {
	if kMin < 2 {
		return nil, 0, apiErr(http.StatusUnprocessableEntity, "invalid_k", "k_min must be at least 2")
	}
	if s.o.Events == nil {
		return nil, 0, apiErr(http.StatusServiceUnavailable, "no_events", "no event store configured")
	}
	now := s.o.Now().UTC().Truncate(time.Second)
	var creates []string
	if rs, err := s.o.Rules.ApprovedRules(ctx); err == nil && rs != nil {
		if r, err := ParseRules(rs.Doc, nil); err == nil {
			for _, e := range r.Entities {
				if e.CreatedBy != nil {
					creates = append(creates, e.Service+" "+e.CreatedBy.Op)
				}
			}
		}
	}
	srcs, err := s.groupSources(ctx, group)
	if err != nil {
		return nil, 0, err
	}
	b, err := BuildArchetypes(ctx, s.o.Events, ProfileOptions{KMin: kMin, From: now.Add(-s.o.ProfileWindow), To: now, CreateOps: creates, Outcomes: s.o.Outcomes, Sources: srcs})
	if err != nil {
		return nil, 0, err
	}
	b.Group = group
	arch, _ := json.Marshal(b.Archetypes)
	cls, _ := json.Marshal(b.Classes)
	mem, _ := json.Marshal(b.Members)
	res, err := s.o.DB.ExecContext(ctx, `INSERT INTO world_builds (k_min, window_from, window_to, profiles, dropped, archetypes, classes, members, created_at, grp) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		kMin, b.From.Unix(), b.To.Unix(), b.Profiles, b.Dropped, string(arch), string(cls), string(mem), now.Unix(), group)
	if err != nil {
		return nil, 0, err
	}
	id, _ := res.LastInsertId()
	return b, id, nil
}

const buildCols = `id, k_min, window_from, window_to, profiles, dropped, archetypes, classes, members, grp`

// LatestBuild returns the newest archetype build of every group's traffic
// (group ""), or nil.
func (s *Service) LatestBuild(ctx context.Context) (*Build, int64, error) {
	return s.LatestBuildIn(ctx, "")
}

// LatestBuildIn returns the newest archetype build of one group, or nil.
func (s *Service) LatestBuildIn(ctx context.Context, group string) (*Build, int64, error) {
	return s.build(ctx, `SELECT `+buildCols+` FROM world_builds WHERE grp = ? ORDER BY id DESC LIMIT 1`, group)
}

// BuildByID returns an archetype build by id.
func (s *Service) BuildByID(ctx context.Context, id int64) (*Build, error) {
	b, _, err := s.build(ctx, `SELECT `+buildCols+` FROM world_builds WHERE id = ?`, id)
	return b, err
}

func (s *Service) build(ctx context.Context, q string, args ...any) (*Build, int64, error) {
	var id, from, to int64
	var a, c, m string
	b := &Build{}
	err := s.o.DB.QueryRowContext(ctx, q, args...).Scan(&id, &b.KMin, &from, &to, &b.Profiles, &b.Dropped, &a, &c, &m, &b.Group)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	b.From, b.To = time.Unix(from, 0).UTC(), time.Unix(to, 0).UTC()
	if json.Unmarshal([]byte(a), &b.Archetypes) != nil || json.Unmarshal([]byte(c), &b.Classes) != nil || json.Unmarshal([]byte(m), &b.Members) != nil {
		return nil, 0, errors.New("world: stored build is corrupt")
	}
	return b, id, nil
}

// GenerateRequest is the body of POST /api/v1/worlds.
type GenerateRequest struct {
	Seed          uint64     `json:"seed"`
	Customers     int        `json:"customers"`
	UseArchetypes *bool      `json:"use_archetypes,omitempty"`
	T0            *time.Time `json:"t0,omitempty"`
	Rules         []string   `json:"rules,omitempty"`
	// Services restricts the world to the services of one team: the approved rules and the
	// contracts that involve only these services. Without it the world applies every approved rule.
	Services []string `json:"services,omitempty"`
	// Group restricts the world to one group: its contracts (inferred from
	// its sources' traffic only), its archetypes and the rules whose
	// services are all its own. Services, when given, must be its services.
	Group string `json:"group,omitempty"`
}

// Info is WorldInfo of the admin API (plus counts).
type Info struct {
	WorldID        string   `json:"world_id"`
	Seed           uint64   `json:"seed"`
	Customers      int      `json:"customers"`
	ArchetypesUsed bool     `json:"archetypes_used"`
	Rules          []string `json:"rules"`
	// Services is the scope the world was generated for (empty: every service).
	Services []string `json:"services"`
	// Group is the group the world was generated for ("": every group).
	Group     string    `json:"group"`
	CreatedAt time.Time `json:"created_at"`
	T0        time.Time `json:"t0"`
	Locale    string    `json:"locale"`
	Entities  int       `json:"entities"`
	History   int       `json:"history"`
	Pending   int       `json:"pending"`
	SHA256    string    `json:"sha256"`
	// SkippedRules are the approved rules left out because they cannot be
	// used (answer of the generation only, not stored). For one group only
	// their number is given: the ids may belong to other teams.
	SkippedRules      []SkippedRule `json:"skipped_rules,omitempty"`
	SkippedRulesCount int           `json:"skipped_rules_count,omitempty"`
	// ExcludedRules are the group's own approved rules (their cause is a
	// service of the scope) left out because they also need services
	// outside the scope (answer of the generation only).
	ExcludedRules []ExcludedRule `json:"excluded_rules,omitempty"`
}

// ExcludedRule is an approved rule left out of a world's scope.
type ExcludedRule struct {
	ID       string   `json:"id"`
	Services []string `json:"services"`
}

// Record is a stored world with what is needed to regenerate it.
type Record struct {
	Info
	BuildID    int64
	Archetypes []Archetype
	Window     time.Duration
	InputsSHA  string
	World      []byte
	Synthetic  []string
	CustList   []CustomerInfo
}

var worldIDRE = regexp.MustCompile(`^w-[0-9]{8}-[0-9]{4,}$`)

// Inputs gathers the generator inputs for a rule selection and archetypes.
func (s *Service) Inputs(ctx context.Context, p Params, rules []string, arch []Archetype, services []string) (*Input, []Contract, error) {
	return s.InputsIn(ctx, p, rules, arch, services, "")
}

// InputsIn is Inputs for one group ("" every group): the contracts of that
// group's traffic, scoped to its services (the given ones, else all of the
// group's), so the rules of other teams are left out.
func (s *Service) InputsIn(ctx context.Context, p Params, rules []string, arch []Archetype, services []string, group string) (*Input, []Contract, error) {
	rs, err := s.o.Rules.ApprovedRules(ctx)
	if err != nil {
		return nil, nil, err
	}
	if rs == nil {
		return nil, nil, apiErr(http.StatusConflict, "no_rules", "no approved rules")
	}
	r, err := ParseRules(rs.Doc, rules)
	if err != nil {
		// The reason names rule ids and entities only (shapes, no values):
		// without it the console cannot say which rule to fix.
		return nil, nil, apiErr(http.StatusUnprocessableEntity, "invalid_rules", "the approved rules cannot be used: "+err.Error())
	}
	all := r
	var cs []Contract
	if gc, ok := s.o.Contracts.(GroupContractsSource); ok && group != "" {
		cs, err = gc.ContractsIn(ctx, group)
		if err != nil {
			return nil, nil, err
		}
		if len(services) == 0 {
			for _, c := range cs {
				services = append(services, c.Service)
			}
			if len(services) == 0 {
				return nil, nil, apiErr(http.StatusUnprocessableEntity, "no_services", "the group has no traffic in the mining window")
			}
		}
	} else if cs, err = s.o.Contracts.Contracts(ctx); err != nil {
		return nil, nil, err
	}
	report := &ScopeReport{}
	if len(services) > 0 {
		var info *ScopeInfo
		r, info = r.Scope(services)
		for _, id := range rules {
			if m := info.Excluded[id]; len(m) > 0 {
				return nil, nil, scopeError(info, rules)
			}
		}
		report = ownReport(all, info, services)
		in := map[string]bool{}
		for _, sv := range services {
			in[sv] = true
		}
		var scoped []Contract
		for _, c := range cs {
			if in[c.Service] {
				scoped = append(scoped, c)
			}
		}
		cs = scoped
	} else {
		report.Skipped = all.Skipped
	}
	if len(rules) == 0 && len(r.IDs) == 0 && (len(report.Excluded) > 0 || len(report.Skipped) > 0) {
		return nil, nil, noUsableRules(report)
	}
	if s.o.IDFormats != nil {
		fm, err := s.o.IDFormats.IDFormatsIn(ctx, group)
		if err != nil {
			return nil, nil, err
		}
		if cs, err = WithIDFormats(cs, fm); err != nil {
			return nil, nil, err
		}
	}
	if s.o.DateOffsets != nil {
		dm, err := s.o.DateOffsets.DateOffsetsIn(ctx, group)
		if err != nil {
			return nil, nil, err
		}
		if cs, err = WithDateOffsets(cs, dm); err != nil {
			return nil, nil, err
		}
	}
	return &Input{Params: p, Rules: r, Contracts: cs, Archetypes: arch, Report: report}, cs, nil
}

// ScopeReport tells the approved rules of the scope's own services that a
// world leaves out: those that also need a service outside the scope, and
// those that cannot be used (Skipped). Rules whose cause is outside the
// scope belong to other teams and are never named.
type ScopeReport struct {
	Excluded []ExcludedRule
	Skipped  []SkippedRule
}

// ownReport keeps, of what Scope and ParseRules left out, the rules of the
// scope: a causal rule whose cause is a service of the scope, a batch rule
// whose entity is.
func ownReport(all *Rules, info *ScopeInfo, services []string) *ScopeReport {
	in := map[string]bool{}
	for _, sv := range services {
		in[sv] = true
	}
	own := map[string]bool{}
	for _, c := range all.Causal {
		own[c.ID] = in[c.Cause.Service]
	}
	for _, b := range all.Batch {
		e := all.Entity(b.Entity)
		own[b.ID] = e != nil && in[e.Service]
	}
	rep := &ScopeReport{}
	for _, id := range all.IDs {
		if m := info.Excluded[id]; len(m) > 0 && own[id] {
			rep.Excluded = append(rep.Excluded, ExcludedRule{ID: id, Services: m})
		}
	}
	for _, sk := range all.Skipped {
		if sk.Service != "" && in[sk.Service] {
			rep.Skipped = append(rep.Skipped, sk)
		}
	}
	return rep
}

// noUsableRules is the answer when the scope has approved rules and none
// can be used: a world without them would be empty (no entity, no rule)
// and the pack built from it would mock nothing of what was approved.
func noUsableRules(rep *ScopeReport) *APIError {
	e := apiErr(http.StatusUnprocessableEntity, "no_usable_rules", "none of the approved rules of these services can be used")
	for _, x := range rep.Excluded {
		e.Details = append(e.Details, map[string]any{"rule": x.ID, "services": x.Services, "reason": "out_of_scope"})
	}
	for _, x := range rep.Skipped {
		e.Details = append(e.Details, map[string]any{"rule": x.ID, "reason": "unusable", "detail": x.Reason})
	}
	return e
}

// scopeError says which requested rules need services outside the scope.
func scopeError(info *ScopeInfo, requested []string) *APIError {
	e := apiErr(http.StatusUnprocessableEntity, "rule_out_of_scope", "a requested rule uses a service that is not in the selected services")
	for _, id := range requested {
		if m := info.Excluded[id]; len(m) > 0 {
			e.Details = append(e.Details, map[string]any{"rule": id, "services": m})
		}
	}
	return e
}

// InputsHash fingerprints the generator inputs.
func InputsHash(in *Input) string {
	h := sha256.New()
	write := func(b []byte) {
		fmt.Fprintf(h, "%d:", len(b))
		h.Write(b)
	}
	rd, _ := canonicalJSON(in.Rules.Doc)
	write(rd)
	for _, c := range in.Contracts {
		write([]byte(c.Service))
		if b, err := Canonicalize(c.Doc); err == nil {
			write(b)
		}
		write([]byte(strconv.FormatBool(c.External)))
	}
	ab, _ := json.Marshal(in.Archetypes)
	write(ab)
	fmt.Fprintf(h, "%d|%d|%d|%d|%s", in.Seed, in.Customers, in.T0.Unix(), in.Window, in.Locale)
	return hex.EncodeToString(h.Sum(nil))
}

// Generate generates and stores a world.
func (s *Service) Generate(ctx context.Context, req GenerateRequest, actor audit.Actor) (*Info, error) {
	if req.Customers < 1 || req.Customers > MaxCustomers {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_customers", "customers must be 1..100000")
	}
	now := s.o.Now().UTC()
	t0 := now.Truncate(24 * time.Hour)
	if req.T0 != nil {
		t0 = req.T0.UTC().Truncate(time.Second)
	}
	use := req.UseArchetypes == nil || *req.UseArchetypes
	var arch []Archetype
	var buildID int64
	if use {
		b, id, err := s.LatestBuildIn(ctx, req.Group)
		if err != nil {
			return nil, err
		}
		if b == nil || len(b.Archetypes) == 0 {
			return nil, apiErr(http.StatusConflict, "no_archetypes", "no archetypes: build them first or set use_archetypes false")
		}
		arch, buildID = b.Archetypes, id
	}
	services := normServices(req.Services)
	in, _, err := s.InputsIn(ctx, Params{Seed: req.Seed, Customers: req.Customers, T0: t0, Window: DefaultWindow, Locale: s.o.Locale}, req.Rules, arch, services, req.Group)
	if err != nil {
		return nil, err
	}
	out, err := Generate(in)
	if err != nil {
		return nil, apiErr(http.StatusUnprocessableEntity, "generation_failed", "the world cannot be generated from these rules and contracts")
	}
	if probs := Verify(out.World, in.Rules); len(probs) > 0 {
		s.o.Logger.ErrorContext(ctx, "world: generated world fails integrity", "problems", len(probs), "first", probs[0])
		return nil, apiErr(http.StatusInternalServerError, "integrity", "the generated world breaks integrity rules")
	}
	sum := sha256.Sum256(out.World)
	var seq int
	day := now.Format("20060102")
	if err := s.o.DB.QueryRowContext(ctx, `SELECT count(*) FROM world_worlds WHERE id LIKE ?`, "w-"+day+"-%").Scan(&seq); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("w-%s-%04d", day, seq+1)
	rules, _ := json.Marshal(in.Rules.IDs)
	servicesJ, _ := json.Marshal(services)
	archJ, _ := json.Marshal(arch)
	syn, _ := json.Marshal(out.Synthetic)
	custJ, _ := json.Marshal(out.Customers)
	var bid any
	if buildID > 0 {
		bid = buildID
	}
	_, err = s.o.DB.ExecContext(ctx, `INSERT INTO world_worlds (id, seed, customers, build_id, archetypes, t0, window_s, locale, rules, inputs_sha, world_sha, world, synthetic, customers_json, entities, history, pending, created_at, created_by, services, grp)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, int64(req.Seed), req.Customers, bid, string(archJ), t0.Unix(), int64(DefaultWindow/time.Second), s.o.Locale, string(rules), InputsHash(in), hex.EncodeToString(sum[:]),
		out.World, syn, string(custJ), out.Entities, out.History, out.Pending, now.Unix(), actor.ID, string(servicesJ), req.Group)
	if err != nil {
		return nil, err
	}
	rec, err := s.Record(ctx, id)
	if err != nil {
		return nil, err
	}
	rec.Info.SkippedRulesCount = len(in.Rules.Skipped)
	if req.Group == "" && len(services) == 0 {
		rec.Info.SkippedRules = in.Rules.Skipped
	} else if in.Report != nil {
		// The scope's own rules only: the others may belong to other teams.
		rec.Info.SkippedRules = in.Report.Skipped
	}
	if in.Report != nil {
		rec.Info.ExcludedRules = in.Report.Excluded
	}
	return &rec.Info, nil
}

const recordCols = `id, seed, customers, coalesce(build_id, 0), archetypes, t0, window_s, locale, rules, inputs_sha, world_sha, entities, history, pending, created_at, services, grp`

func scanRecord(sc interface{ Scan(...any) error }, extra ...any) (*Record, error) {
	r := &Record{}
	var seed int64
	var arch, rules, services string
	var t0, win, created int64
	dst := []any{&r.WorldID, &seed, &r.Customers, &r.BuildID, &arch, &t0, &win, &r.Locale, &rules, &r.InputsSHA, &r.SHA256, &r.Entities, &r.History, &r.Pending, &created, &services, &r.Group}
	if err := sc.Scan(append(dst, extra...)...); err != nil {
		return nil, err
	}
	r.Seed = uint64(seed)
	r.T0, r.CreatedAt, r.Window = time.Unix(t0, 0).UTC(), time.Unix(created, 0).UTC(), time.Duration(win)*time.Second
	if json.Unmarshal([]byte(arch), &r.Archetypes) != nil || json.Unmarshal([]byte(rules), &r.Rules) != nil || json.Unmarshal([]byte(services), &r.Services) != nil {
		return nil, errors.New("world: stored world is corrupt")
	}
	if r.Services == nil {
		r.Services = []string{}
	}
	r.ArchetypesUsed = len(r.Archetypes) > 0
	return r, nil
}

// List returns the stored worlds, newest first.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	rows, err := s.o.DB.QueryContext(ctx, `SELECT `+recordCols+` FROM world_worlds ORDER BY created_at DESC, id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Info{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r.Info)
	}
	return out, rows.Err()
}

// Record returns a stored world with its bytes and provenance tags.
func (s *Service) Record(ctx context.Context, id string) (*Record, error) {
	if !worldIDRE.MatchString(id) {
		return nil, ErrNotFound
	}
	var world, syn []byte
	var cust string
	r, err := scanRecord(s.o.DB.QueryRowContext(ctx, `SELECT `+recordCols+`, world, synthetic, customers_json FROM world_worlds WHERE id = ?`, id), &world, &syn, &cust)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.World = world
	if json.Unmarshal(syn, &r.Synthetic) != nil || json.Unmarshal([]byte(cust), &r.CustList) != nil {
		return nil, errors.New("world: stored world is corrupt")
	}
	return r, nil
}

// ErrStale reports a world whose inputs changed since it was generated.
var ErrStale = apiErr(http.StatusConflict, "world_stale", "rules, contracts or archetypes changed since the world was generated: generate it again")

// Regenerate runs the generator again with the stored parameters and the
// current inputs and checks that it produces the stored bytes. This is the
// provenance proof of world.jsonl used by the pack writer: every string
// comes from the generator (Output.Synthetic) or from the inputs.
func (s *Service) Regenerate(ctx context.Context, id string) (*Record, *Input, *Output, error) {
	rec, err := s.Record(ctx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	in, _, err := s.InputsIn(ctx, Params{Seed: rec.Seed, Customers: rec.Customers, T0: rec.T0, Window: rec.Window, Locale: rec.Locale}, rec.Rules, rec.Archetypes, rec.Services, rec.Group)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return nil, nil, nil, ErrStale
		}
		return nil, nil, nil, err
	}
	out, err := Generate(in)
	if err != nil {
		return nil, nil, nil, ErrStale
	}
	sum := sha256.Sum256(out.World)
	if hex.EncodeToString(sum[:]) != rec.SHA256 || !bytes.Equal(out.World, rec.World) {
		return nil, nil, nil, ErrStale
	}
	return rec, in, out, nil
}

// Preview returns the lines of a world about one synthetic customer: the
// customer, its entities, their history and its pending effects.
func (s *Service) Preview(ctx context.Context, id, customerID string) ([]json.RawMessage, error) {
	rec, err := s.Record(ctx, id)
	if err != nil {
		return nil, err
	}
	var out []json.RawMessage
	owned := map[string]bool{}
	found := false
	sc := bufio.NewScanner(bytes.NewReader(rec.World))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var h struct {
			Type, ID, Entity string
			CustomerID       *string `json:"customer_id"`
		}
		line := sc.Bytes()
		if json.Unmarshal(line, &h) != nil {
			continue
		}
		keep := false
		switch h.Type {
		case "customer":
			keep = h.ID == customerID
			found = found || keep
		case "entity", "pending":
			keep = h.CustomerID != nil && *h.CustomerID == customerID
			if keep && h.Type == "entity" {
				owned[h.Entity+"\x00"+h.ID] = true
			}
		case "history":
			keep = owned[h.Entity+"\x00"+h.ID]
		}
		if keep {
			out = append(out, append(json.RawMessage(nil), line...))
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	return out, nil
}

// normServices sorts and de-duplicates a service scope (nil for none).
func normServices(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
