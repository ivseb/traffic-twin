package miner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

func init() {
	store.Register(store.Namespace{Name: "miner", Migrations: []store.Migration{
		{Version: 1, Name: "rules", SQL: `
CREATE TABLE miner_rules (
	id TEXT PRIMARY KEY,
	seq INTEGER NOT NULL UNIQUE,
	signature TEXT NOT NULL,
	kind TEXT NOT NULL,
	status TEXT NOT NULL,
	structure TEXT NOT NULL,
	confidence REAL NOT NULL,
	approved_confidence REAL,
	body TEXT NOT NULL,
	latest TEXT,
	edits TEXT,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	last_run INTEGER
) STRICT;
CREATE INDEX miner_rules_signature ON miner_rules (signature, seq);
CREATE INDEX miner_rules_status ON miner_rules (status, seq);
CREATE TABLE miner_runs (
	id INTEGER PRIMARY KEY,
	started_at INTEGER NOT NULL,
	finished_at INTEGER NOT NULL,
	window_from TEXT NOT NULL,
	window_to TEXT NOT NULL,
	events INTEGER NOT NULL,
	new_rules INTEGER NOT NULL,
	updated_rules INTEGER NOT NULL,
	stale_rules INTEGER NOT NULL,
	entities TEXT NOT NULL,
	keys TEXT NOT NULL
) STRICT;
`},
		{Version: 2, Name: "run_coverage", SQL: `
ALTER TABLE miner_runs ADD COLUMN observed_seconds INTEGER NOT NULL DEFAULT 0;
`},
		{Version: 3, Name: "stale_strikes_and_diagnostics", SQL: `
ALTER TABLE miner_rules ADD COLUMN strikes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE miner_rules ADD COLUMN stale_reason TEXT;
ALTER TABLE miner_runs ADD COLUMN diagnostics TEXT;
`},
		// Entity names (names.go): an entity is the one a service creates in
		// a domain within a group; the names given are kept across runs.
		// Filled from the stored rules on first use (EntityNames).
		{Version: 4, Name: "entity_names", SQL: `
CREATE TABLE miner_entity_names (
	name TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	service TEXT NOT NULL,
	grp TEXT NOT NULL DEFAULT '',
	id_prefix TEXT NOT NULL,
	created_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX miner_entity_names_key ON miner_entity_names (grp, domain, service);
`},
		// Rules v1.9: customer attributes, aggregates and list operations of
		// the run (they describe the reads, like the entities).
		{Version: 5, Name: "run_extras", SQL: `
ALTER TABLE miner_runs ADD COLUMN extras TEXT;
`},
	}})
}

// StaleNotice tells that an approved rule became stale.
type StaleNotice struct {
	RuleID string
	Kind   string
	// Reason is a short code: confidence_drop, not_observed, or the code
	// given to MarkStale (e.g. contract_changed by the drift detector).
	Reason string
	// Detail is the explanation stored with the rule ("entity order: birth
	// share 0.52 < 0.60 for 3 runs"); empty for externally given reasons.
	Detail   string
	Previous float64 // confidence when approved
	Current  float64
}

// StalenessSink is the drift hook: it is told, after the change is stored,
// whenever an approved rule becomes stale (alerts, UI notifications). It is
// called synchronously and must not block for long.
type StalenessSink interface {
	RuleStale(ctx context.Context, n StaleNotice)
}

// Repository errors.
var (
	ErrNotFound = errors.New("miner: rule not found")
	ErrConflict = errors.New("miner: rule state does not allow this change")
	ErrBadEdit  = errors.New("miner: invalid edit")
)

// Repo stores mined rules and their review state (SQLite).
type Repo struct {
	db   *store.DB
	cfg  Config
	sink StalenessSink
}

// NewRepo returns a repository on a database opened with store.Open (this
// package registers its migrations in init).
func NewRepo(db *store.DB, cfg Config, sink StalenessSink) *Repo {
	return &Repo{db: db, cfg: cfg, sink: sink}
}

// StoredRule is a rule with its bookkeeping.
type StoredRule struct {
	Rule       Rule
	Signature  string
	Confidence float64
	// ApprovedConfidence is the confidence when the rule was approved.
	ApprovedConfidence float64
	CreatedAt          time.Time
	UpdatedAt          time.Time
	// Strikes counts the consecutive failed runs of an approved rule (it
	// becomes stale at Config.StaleRuns); StaleReason says why the rule is
	// stale, or what is going wrong while it is on watch.
	Strikes     int
	StaleReason string
	// Superseded lists the rules an approval moved out of the active set
	// (set only by Approve; not stored).
	Superseded []string
}

// RunReport summarizes one Apply.
type RunReport struct {
	RunID  int64
	Events int
	// Observed is the span of the traffic the run saw; Insufficient is true
	// when it is shorter than the minimum coverage (no rule can be decided).
	Observed     time.Duration
	Insufficient bool
	New          []string
	Updated      []string
	Stale        []string
	Unchange     int
	// Diagnostics explains the run: entities and rules.
	Diagnostics Diagnostics
}

type edits struct {
	Title *string          `json:"title,omitempty"`
	After map[string]Delay `json:"after,omitempty"`
	// Body is the definition written by a person (Replace): it wins over
	// what the miner proposes when it refreshes the draft.
	Body *Rule `json:"body,omitempty"`
}

type row struct {
	id, signature, kind, status, structure string
	seq                                    int64
	strikes                                int
	staleReason                            sql.NullString
	confidence                             float64
	approvedConf                           sql.NullFloat64
	body                                   string
	edits                                  sql.NullString
	createdAt, updatedAt                   int64
}

const rowCols = `id, seq, signature, kind, status, structure, confidence, approved_confidence, body, edits, created_at, updated_at, strikes, stale_reason`

type scanner interface{ Scan(...any) error }

func scanRow(s scanner) (*row, error) {
	r := &row{}
	err := s.Scan(&r.id, &r.seq, &r.signature, &r.kind, &r.status, &r.structure, &r.confidence, &r.approvedConf,
		&r.body, &r.edits, &r.createdAt, &r.updatedAt, &r.strikes, &r.staleReason)
	return r, err
}

func (r *row) rule() (Rule, error) {
	var out Rule
	err := json.Unmarshal([]byte(r.body), &out)
	return out, err
}

func (r *row) stored() (*StoredRule, error) {
	ru, err := r.rule()
	if err != nil {
		return nil, err
	}
	return &StoredRule{Rule: ru, Signature: r.signature, Confidence: r.confidence, ApprovedConfidence: r.approvedConf.Float64,
		CreatedAt: time.UnixMilli(r.createdAt).UTC(), UpdatedAt: time.UnixMilli(r.updatedAt).UTC(),
		Strikes: r.strikes, StaleReason: r.staleReason.String}, nil
}

func cloneRule(r Rule) (Rule, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return Rule{}, err
	}
	var out Rule
	err = json.Unmarshal(b, &out)
	return out, err
}

func ruleJSON(r Rule) (string, error) {
	b, err := json.Marshal(r)
	return string(b), err
}

// setHeader sets id, status, supersedes and review of a rule.
func setHeader(r *Rule, id, status, supersedes string, review *Review) {
	pid, pst, _, psup, prev := r.common()
	*pid, *pst, *psup, *prev = id, status, supersedes, review
}

// applyEdits applies reviewer edits; effect ids that no longer exist are
// ignored.
func applyEdits(r *Rule, e edits) {
	applyBody(r, e.Body)
	_, _, title, _, _ := r.common()
	if e.Title != nil {
		*title = *e.Title
	}
	if r.Causal != nil {
		for i := range r.Causal.Effects {
			if d, ok := e.After[r.Causal.Effects[i].ID]; ok {
				r.Causal.Effects[i].After = d
			}
		}
	}
}

func (rp *Repo) latestBySignature(ctx context.Context, tx *sql.Tx, sig string) (*row, error) {
	r, err := scanRow(tx.QueryRowContext(ctx, `SELECT `+rowCols+` FROM miner_rules WHERE signature = ? ORDER BY seq DESC LIMIT 1`, sig))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func nextSeq(ctx context.Context, tx *sql.Tx) (int64, error) {
	var n sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(seq) FROM miner_rules`).Scan(&n); err != nil {
		return 0, err
	}
	return n.Int64 + 1, nil
}

func (rp *Repo) insert(ctx context.Context, tx *sql.Tx, r Rule, sig, structure string, conf float64, ed *edits, now time.Time) (string, error) {
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return "", err
	}
	id := fmt.Sprintf("r-%04d", seq)
	_, _, _, sup, _ := r.common()
	setHeader(&r, id, StatusDraft, *sup, nil)
	if ed != nil {
		applyEdits(&r, *ed)
	}
	body, err := ruleJSON(r)
	if err != nil {
		return "", err
	}
	var edJSON any
	if ed != nil {
		b, _ := json.Marshal(ed)
		edJSON = string(b)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO miner_rules (id, seq, signature, kind, status, structure, confidence, body, edits, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, seq, sig, r.Kind(), StatusDraft, structure, conf, body, edJSON, now.UnixMilli(), now.UnixMilli())
	return id, err
}

// Apply stores the rules of a mining run: new rules become drafts with a
// new id; a draft with the same signature is refreshed in place (keeping
// the reviewer's edits); an approved or rejected rule is never modified: a
// changed structure becomes a new draft that supersedes it. An approved rule
// whose confidence dropped (or whose cause is seen but no longer mined)
// collects a strike; it becomes stale only after Config.StaleRuns
// consecutive strikes, with the reason stored; a good run clears the
// strikes, a run with too little traffic judges nothing. Nothing is ever
// approved here.
func (rp *Repo) Apply(ctx context.Context, res *Result, started, now time.Time) (RunReport, error) {
	insufficient := res.Observed < rp.cfg.MinCoverage()
	var rep RunReport
	var notices []StaleNotice
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		notices = notices[:0]
		rep = RunReport{Events: res.Events, Observed: res.Observed, Insufficient: insufficient}
		var rdiag []RuleDiag
		seen := map[string]bool{}

		// judge records the outcome of a run for an approved rule.
		judge := func(r *row, mm *Mined, bad bool, code, why string) error {
			d := RuleDiag{RuleID: r.id, Signature: r.signature, Kind: r.kind, StaleRuns: rp.cfg.StaleRuns}
			if mm != nil {
				d.Confidence = mm.Confidence
			}
			switch {
			case insufficient:
				d.Decision, d.Reason, d.Strikes = DecisionSkipped, "not judged: too little traffic observed", r.strikes
			case !bad:
				d.Decision, d.Reason = DecisionKept, "confirmed by the run"
				if r.strikes > 0 {
					if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET strikes = 0, stale_reason = NULL WHERE id = ?`, r.id); err != nil {
						return err
					}
				}
			default:
				strikes := r.strikes + 1
				d.Strikes = strikes
				if strikes < rp.cfg.StaleRuns {
					d.Decision, d.Reason = DecisionWatch, why
					if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET strikes = ?, stale_reason = ? WHERE id = ?`, strikes, why, r.id); err != nil {
						return err
					}
					break
				}
				detail := fmt.Sprintf("%s for %d runs", why, strikes)
				if err := rp.setStatus(ctx, tx, r, StatusStale, now); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET strikes = ?, stale_reason = ? WHERE id = ?`, strikes, detail, r.id); err != nil {
					return err
				}
				d.Decision, d.Reason = DecisionStale, detail
				n := StaleNotice{RuleID: r.id, Kind: r.kind, Reason: code, Detail: detail, Previous: r.approvedConf.Float64}
				if mm != nil {
					n.Current = mm.Confidence
				}
				notices = append(notices, n)
				rep.Stale = append(rep.Stale, r.id)
			}
			rdiag = append(rdiag, d)
			return nil
		}

		for _, mm := range res.Rules {
			seen[mm.Signature] = true
			latest, err := rp.latestBySignature(ctx, tx, mm.Signature)
			if err != nil {
				return err
			}
			r, err := cloneRule(mm.Rule)
			if err != nil {
				return err
			}
			d := RuleDiag{Signature: mm.Signature, Kind: r.Kind(), Confidence: mm.Confidence, Code: WhyMined}
			for _, md := range res.Diag.Rules {
				if md.Signature == mm.Signature {
					d.Service, d.Op, d.Entity = md.Service, md.Op, md.Entity
					break
				}
			}
			if latest == nil {
				setHeader(&r, "", StatusDraft, "", nil)
				id, err := rp.insert(ctx, tx, r, mm.Signature, mm.Structure, mm.Confidence, nil, now)
				if err != nil {
					return err
				}
				rep.New = append(rep.New, id)
				d.RuleID, d.Decision, d.Reason = id, DecisionProposed, "new draft"
				rdiag = append(rdiag, d)
				continue
			}
			d.RuleID = latest.id
			switch latest.status {
			case StatusDraft:
				old, err := latest.rule()
				if err != nil {
					return err
				}
				_, _, _, sup, _ := old.common()
				setHeader(&r, latest.id, StatusDraft, *sup, nil)
				var ed edits
				if latest.edits.Valid {
					_ = json.Unmarshal([]byte(latest.edits.String), &ed)
					applyEdits(&r, ed)
				}
				body, err := ruleJSON(r)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET body = ?, structure = ?, confidence = ?, updated_at = ? WHERE id = ?`,
					body, mm.Structure, mm.Confidence, now.UnixMilli(), latest.id); err != nil {
					return err
				}
				rep.Updated = append(rep.Updated, latest.id)
				d.Decision, d.Reason = DecisionProposed, "draft refreshed"
				rdiag = append(rdiag, d)
			case StatusApproved, StatusStale, StatusRejected:
				if latest.structure != mm.Structure {
					setHeader(&r, "", StatusDraft, latest.id, nil)
					id, err := rp.insert(ctx, tx, r, mm.Signature, mm.Structure, mm.Confidence, nil, now)
					if err != nil {
						return err
					}
					rep.New = append(rep.New, id)
					d.RuleID, d.Decision, d.Reason = id, DecisionProposed, "structure changed: new draft supersedes "+latest.id
					rdiag = append(rdiag, d)
					continue
				}
				latestEv, _ := ruleJSON(r)
				if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET confidence = ?, latest = ?, updated_at = ? WHERE id = ?`,
					mm.Confidence, latestEv, now.UnixMilli(), latest.id); err != nil {
					return err
				}
				if latest.status == StatusApproved {
					bad := rp.dropped(latest.approvedConf.Float64, mm.Confidence)
					why := ""
					if bad {
						why = fmt.Sprintf("confidence %.2f (approved at %.2f) below the floor", mm.Confidence, latest.approvedConf.Float64)
					}
					if err := judge(latest, mm, bad, "confidence_drop", why); err != nil {
						return err
					}
					if !bad {
						rep.Unchange++
					}
				} else {
					d.Decision, d.Reason = DecisionKept, "rule is "+latest.status+": not proposed again"
					rdiag = append(rdiag, d)
					rep.Unchange++
				}
			}
		}

		// Approved rules not mined: judged only when the run saw what they
		// are about; otherwise nothing is decided.
		rows, err := tx.QueryContext(ctx, `SELECT `+rowCols+` FROM miner_rules WHERE status = ? ORDER BY seq`, StatusApproved)
		if err != nil {
			return err
		}
		var missing []*row
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				rows.Close()
				return err
			}
			if !seen[r.signature] && !isManualSig(r.signature) {
				missing = append(missing, r)
			}
		}
		rows.Close()
		for _, r := range missing {
			if !rp.observed(res, r.signature) {
				rdiag = append(rdiag, RuleDiag{RuleID: r.id, Signature: r.signature, Kind: r.kind, Decision: DecisionNotSeen,
					Reason: "its cause was not seen in the window: nothing to judge", Strikes: r.strikes, StaleRuns: rp.cfg.StaleRuns})
				continue
			}
			if !insufficient {
				if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET confidence = 0 WHERE id = ?`, r.id); err != nil {
					return err
				}
			}
			if err := judge(r, nil, true, "not_observed", rp.whyNotMined(res, r.signature)); err != nil {
				return err
			}
		}
		// Mining-level reasons for candidates that produced nothing (and
		// have no approved rule of their own to carry them).
		have := map[string]bool{}
		for _, d := range rdiag {
			have[d.Signature] = true
		}
		for _, d := range res.Diag.Rules {
			if d.Decision == DecisionNotMined && !have[d.Signature] {
				rdiag = append(rdiag, d)
			}
		}
		if err := saveNames(ctx, tx, res.Names); err != nil {
			return err
		}
		subjects := res.Subjects
		rep.Diagnostics = Diagnostics{Entities: nonNilEntities(res.Diag.Entities), Rules: nonNilRules(rdiag), Subjects: &subjects, Merges: res.Diag.Merges, Groups: res.Diag.Groups, Reads: res.Diag.Reads,
			Candidates: res.Diag.Candidates, Families: res.Diag.Families, TestK: res.Diag.TestK}
		diag, _ := json.Marshal(rep.Diagnostics)

		ents, _ := json.Marshal(res.Entities)
		if res.Entities == nil {
			ents = []byte("[]")
		}
		keys := make([]KeyRef, 0, len(res.Keys))
		for _, k := range res.Keys {
			keys = append(keys, k.KeyRef())
		}
		kb, _ := json.Marshal(keys)
		xb, _ := json.Marshal(runExtras{Attributes: res.Attributes, Aggregates: res.Aggregates, Lists: res.Lists})
		r, err := tx.ExecContext(ctx, `INSERT INTO miner_runs (started_at, finished_at, window_from, window_to, events, new_rules, updated_rules, stale_rules, entities, keys, observed_seconds, diagnostics, extras)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, started.UnixMilli(), now.UnixMilli(), res.Window.From, res.Window.To, res.Events,
			len(rep.New), len(rep.Updated), len(rep.Stale), string(ents), string(kb), int64(res.Observed/time.Second), string(diag), string(xb))
		if err != nil {
			return err
		}
		rep.RunID, _ = r.LastInsertId()
		if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET last_run = ? WHERE signature IN (SELECT value FROM json_each(?))`,
			rep.RunID, sigJSON(seen)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return RunReport{}, err
	}
	rp.notify(ctx, notices)
	return rep, nil
}

// saveNames stores the entity names of a run (a name stored before groups
// were known takes the group that adopted it).
func saveNames(ctx context.Context, tx *sql.Tx, names []EntityName) error {
	for _, n := range names {
		created := n.Created
		if created.IsZero() {
			created = time.Unix(0, 0)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO miner_entity_names (name, domain, service, grp, id_prefix, created_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET grp = excluded.grp WHERE miner_entity_names.grp = '' AND miner_entity_names.domain = excluded.domain AND miner_entity_names.service = excluded.service`,
			n.Name, n.Domain, n.Service, n.Group, n.IDPrefix, created.UnixMilli()); err != nil {
			// A key taken by another name (UNIQUE grp, domain, service) is
			// left as stored: the stored name wins at the next run.
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			}
			return err
		}
	}
	return nil
}

// EntityNames returns the stored entity names. The first time (none stored
// yet, rules already there: a console that mined before entity names were
// stored) they are recovered from the rules, so that an approved rule keeps
// the entity it was approved with: the creator in the signature of the
// approved rules first, then stale, rejected and draft ones, oldest first,
// then the entities of the latest run; each bare name goes to the first
// creator that claims it.
func (rp *Repo) EntityNames(ctx context.Context) ([]EntityName, error) {
	var out []EntityName
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		if out, err = loadNames(ctx, tx); err != nil || len(out) > 0 {
			return err
		}
		seed, err := rp.seedNames(ctx, tx)
		if err != nil || len(seed) == 0 {
			return err
		}
		if err := saveNames(ctx, tx, seed); err != nil {
			return err
		}
		out, err = loadNames(ctx, tx)
		return err
	})
	return out, err
}

func loadNames(ctx context.Context, tx *sql.Tx) ([]EntityName, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name, domain, service, grp, id_prefix, created_at FROM miner_entity_names ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EntityName
	for rows.Next() {
		var n EntityName
		var at int64
		if err := rows.Scan(&n.Name, &n.Domain, &n.Service, &n.Group, &n.IDPrefix, &at); err != nil {
			return nil, err
		}
		n.Created = time.UnixMilli(at).UTC()
		out = append(out, n)
	}
	return out, rows.Err()
}

func (rp *Repo) seedNames(ctx context.Context, tx *sql.Tx) ([]EntityName, error) {
	rows, err := tx.QueryContext(ctx, `SELECT signature, created_at FROM miner_rules
		ORDER BY CASE status WHEN 'approved' THEN 0 WHEN 'stale' THEN 1 WHEN 'rejected' THEN 2 ELSE 3 END, seq`)
	if err != nil {
		return nil, err
	}
	type claim struct {
		domain, service string
		at              int64
	}
	var claims []claim
	for rows.Next() {
		var sig string
		var at int64
		if err := rows.Scan(&sig, &at); err != nil {
			rows.Close()
			return nil, err
		}
		if parts := strings.Split(sig, "|"); len(parts) >= 4 && parts[0] == "causal" {
			claims = append(claims, claim{parts[3], parts[1], at})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var latest []Entity
	var ej string
	if err := tx.QueryRowContext(ctx, `SELECT entities FROM miner_runs ORDER BY id DESC LIMIT 1`).Scan(&ej); err == nil {
		_ = json.Unmarshal([]byte(ej), &latest)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	prefix := map[string]string{}
	for _, e := range latest {
		if e.Name == e.IDDomain && e.IDPrefix != "" {
			prefix[e.Name] = e.IDPrefix
		}
	}
	var out []EntityName
	byName, byKey := map[string]bool{}, map[[2]string]bool{}
	add := func(name, domain, service string, at int64, p string) {
		if name == "" || domain == "" || service == "" || byName[name] || byKey[[2]string{domain, service}] || !reIdent.MatchString(name) {
			return
		}
		if p == "" {
			if p = prefix[name]; p == "" {
				p = idPrefix(domain)
			}
		}
		byName[name], byKey[[2]string{domain, service}] = true, true
		out = append(out, EntityName{Name: name, Domain: domain, Service: service, IDPrefix: p, Created: time.UnixMilli(at).UTC()})
	}
	for _, c := range claims {
		add(c.domain, c.domain, c.service, c.at, "")
	}
	for _, e := range latest {
		add(e.Name, e.IDDomain, e.Service, 0, e.IDPrefix)
	}
	return out, nil
}

func nonNilEntities(e []EntityDiag) []EntityDiag {
	if e == nil {
		return []EntityDiag{}
	}
	return e
}

func nonNilRules(r []RuleDiag) []RuleDiag {
	if r == nil {
		return []RuleDiag{}
	}
	return r
}

// whyNotMined explains why an approved rule was not mined although its cause
// was seen: the rejected entity (with the numbers), the candidate's own
// reason, or a generic one.
func (rp *Repo) whyNotMined(res *Result, sig string) string {
	dom := signatureDomain(sig)
	for _, e := range res.Diag.Entities {
		if e.Name == dom && !e.Accepted {
			return "entity " + dom + ": " + e.Reason
		}
	}
	for _, d := range res.Diag.Rules {
		if d.Signature == sig && d.Decision == DecisionNotMined {
			return "rule not mined: " + d.Reason
		}
	}
	if strings.HasPrefix(sig, "batch|") {
		return "entity " + dom + ": batch run pattern no longer found"
	}
	return "rule no longer mined"
}

// signatureDomain is the entity domain of a rule signature.
func signatureDomain(sig string) string {
	parts := strings.Split(sig, "|")
	switch {
	case len(parts) >= 4 && parts[0] == "causal":
		return parts[3]
	case len(parts) >= 2 && parts[0] == "batch":
		return parts[1]
	}
	return ""
}

func sigJSON(m map[string]bool) string {
	b, _ := json.Marshal(sortedKeys(m))
	return string(b)
}

func (rp *Repo) notify(ctx context.Context, ns []StaleNotice) {
	if rp.sink == nil {
		return
	}
	for _, n := range ns {
		rp.sink.RuleStale(ctx, n)
	}
}

// dropped reports a confidence drop that makes an approved rule stale.
func (rp *Repo) dropped(approved, now float64) bool {
	return now < rp.cfg.MinConfidence || now < approved*(1-rp.cfg.StaleDrop)
}

// observed reports whether the run saw what the rule is about.
func (rp *Repo) observed(res *Result, sig string) bool {
	parts := strings.Split(sig, "|")
	switch {
	case len(parts) >= 3 && parts[0] == "causal":
		return res.Ops[parts[1]+" "+parts[2]] > 0
	case len(parts) >= 2 && parts[0] == "batch":
		for _, e := range res.Entities {
			if e.Name == parts[1] || e.IDDomain == parts[1] {
				return true
			}
		}
		for _, e := range res.Diag.Entities {
			if e.Name == parts[1] {
				return true // a rejected candidate: that is a failure to explain
			}
		}
	}
	return false
}

func (rp *Repo) setStatus(ctx context.Context, tx *sql.Tx, r *row, status string, now time.Time) error {
	ru, err := r.rule()
	if err != nil {
		return err
	}
	id, _, _, sup, rev := ru.common()
	setHeader(&ru, *id, status, *sup, *rev)
	body, err := ruleJSON(ru)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE miner_rules SET status = ?, body = ?, updated_at = ? WHERE id = ?`, status, body, now.UnixMilli(), r.id)
	if err == nil {
		r.status, r.body = status, body
	}
	return err
}

// List returns the rules, optionally with one status, by id.
func (rp *Repo) List(ctx context.Context, status string) ([]*StoredRule, error) {
	q, args := `SELECT `+rowCols+` FROM miner_rules ORDER BY seq`, []any{}
	if status != "" {
		q, args = `SELECT `+rowCols+` FROM miner_rules WHERE status = ? ORDER BY seq`, []any{status}
	}
	rows, err := rp.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*StoredRule
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		s, err := r.stored()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Get returns one rule.
func (rp *Repo) Get(ctx context.Context, id string) (*StoredRule, error) {
	r, err := scanRow(rp.db.QueryRowContext(ctx, `SELECT `+rowCols+` FROM miner_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.stored()
}

func getTx(ctx context.Context, tx *sql.Tx, id string) (*row, error) {
	r, err := scanRow(tx.QueryRowContext(ctx, `SELECT `+rowCols+` FROM miner_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// Entities returns the entities of the latest run.
func (rp *Repo) Entities(ctx context.Context) ([]Entity, error) {
	var s string
	err := rp.db.QueryRowContext(ctx, `SELECT entities FROM miner_runs ORDER BY id DESC LIMIT 1`).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return []Entity{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entity
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Keys returns the link keys of the latest run.
func (rp *Repo) Keys(ctx context.Context) ([]KeyRef, error) {
	var s string
	err := rp.db.QueryRowContext(ctx, `SELECT keys FROM miner_runs ORDER BY id DESC LIMIT 1`).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return []KeyRef{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []KeyRef
	err = json.Unmarshal([]byte(s), &out)
	return out, err
}

// Document assembles tt-rules with the latest entities and the rules with
// the given status ("" = all). For a pack, use StatusApproved.
func (rp *Repo) Document(ctx context.Context, status string, now time.Time) (*Document, error) {
	ents, err := rp.Entities(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := rp.List(ctx, status)
	if err != nil {
		return nil, err
	}
	d := &Document{Format: Format, GeneratedAt: now.UTC().Format(time.RFC3339), Entities: ents, Rules: []Rule{}}
	var from, to string
	var extras sql.NullString
	if err := rp.db.QueryRowContext(ctx, `SELECT window_from, window_to, extras FROM miner_runs ORDER BY id DESC LIMIT 1`).Scan(&from, &to, &extras); err == nil {
		d.Window = &Window{From: from, To: to}
		var x runExtras
		if extras.Valid && json.Unmarshal([]byte(extras.String), &x) == nil {
			d.Attributes, d.Aggregates, d.Lists = x.Attributes, x.Aggregates, x.Lists
		}
	}
	for _, r := range rs {
		d.Rules = append(d.Rules, r.Rule)
	}
	return d, nil
}

// Approve moves a draft or stale rule to approved. by identifies the
// reviewer (user id).
func (rp *Repo) Approve(ctx context.Context, id, by string, now time.Time) (*StoredRule, error) {
	return rp.review(ctx, id, by, "", StatusApproved, now)
}

// Reject moves a draft or stale rule to rejected, with an optional note.
func (rp *Repo) Reject(ctx context.Context, id, by, note string, now time.Time) (*StoredRule, error) {
	if len(note) > 1000 {
		return nil, ErrBadEdit
	}
	return rp.review(ctx, id, by, note, StatusRejected, now)
}

func (rp *Repo) review(ctx context.Context, id, by, note, status string, now time.Time) (*StoredRule, error) {
	var out *StoredRule
	var moved []string
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		moved = nil
		r, err := getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.status != StatusDraft && r.status != StatusStale {
			return ErrConflict
		}
		ru, err := r.rule()
		if err != nil {
			return err
		}
		if status == StatusApproved {
			ents, err := rp.entitiesTx(ctx, tx)
			if err != nil {
				return err
			}
			if err := ru.Validate(ents); err != nil {
				return fmt.Errorf("%w: %v", ErrBadEdit, err)
			}
		}
		at := now.UTC().Format(time.RFC3339)
		pid, _, _, sup, _ := ru.common()
		setHeader(&ru, *pid, status, *sup, &Review{By: []string{by}, At: &at, Note: note})
		body, err := ruleJSON(ru)
		if err != nil {
			return err
		}
		q := `UPDATE miner_rules SET status = ?, body = ?, updated_at = ? WHERE id = ?`
		args := []any{status, body, now.UnixMilli(), id}
		if status == StatusApproved {
			q = `UPDATE miner_rules SET status = ?, body = ?, updated_at = ?, approved_confidence = confidence, strikes = 0, stale_reason = NULL WHERE id = ?`
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
		if status == StatusApproved {
			if moved, err = rp.supersedeTx(ctx, tx, now); err != nil {
				return err
			}
		}
		r, err = getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		out, err = r.stored()
		return err
	})
	if out != nil {
		out.Superseded = moved
	}
	return out, err
}

func (rp *Repo) entitiesTx(ctx context.Context, tx *sql.Tx) (map[string]*Entity, error) {
	var s string
	err := tx.QueryRowContext(ctx, `SELECT entities FROM miner_runs ORDER BY id DESC LIMIT 1`).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]*Entity{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Entity
	if err := json.Unmarshal([]byte(s), &list); err != nil {
		return nil, err
	}
	m := map[string]*Entity{}
	for i := range list {
		m[list[i].Name] = &list[i]
	}
	return m, nil
}

// Edit changes the title and the figurative delays (a duration or a
// {min, max} range) of a draft in place; on
// an approved or stale rule it creates a new draft that supersedes it.
// Rejected rules cannot be edited.
func (rp *Repo) Edit(ctx context.Context, id string, title *string, after map[string]Delay, now time.Time) (*StoredRule, error) {
	if title != nil && (len([]rune(*title)) > 200 || strings.ContainsAny(*title, "\x00")) {
		return nil, ErrBadEdit
	}
	// A delay is one duration or a {min, max} range with min <= max (rules spec 3.3).
	for _, d := range after {
		if validDelay(d) != nil {
			return nil, ErrBadEdit
		}
	}
	var out *StoredRule
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		r, err := getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		ru, err := r.rule()
		if err != nil {
			return err
		}
		if len(after) > 0 {
			if ru.Causal == nil {
				return ErrBadEdit
			}
			ids := map[string]bool{}
			for _, e := range ru.Causal.Effects {
				ids[e.ID] = true
			}
			for k := range after {
				if !ids[k] {
					return ErrBadEdit
				}
			}
		}
		var ed edits
		if r.edits.Valid {
			_ = json.Unmarshal([]byte(r.edits.String), &ed)
		}
		if title != nil {
			ed.Title = title
		}
		if len(after) > 0 && ed.After == nil {
			ed.After = map[string]Delay{}
		}
		for k, v := range after {
			ed.After[k] = v
		}
		target := id
		switch r.status {
		case StatusDraft:
			applyEdits(&ru, ed)
			body, err := ruleJSON(ru)
			if err != nil {
				return err
			}
			eb, _ := json.Marshal(ed)
			if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET body = ?, edits = ?, updated_at = ? WHERE id = ?`,
				body, string(eb), now.UnixMilli(), id); err != nil {
				return err
			}
		case StatusApproved, StatusStale:
			setHeader(&ru, "", StatusDraft, id, nil)
			target, err = rp.insert(ctx, tx, ru, r.signature, r.structure, r.confidence, &ed, now)
			if err != nil {
				return err
			}
		default:
			return ErrConflict
		}
		nr, err := getTx(ctx, tx, target)
		if err != nil {
			return err
		}
		out, err = nr.stored()
		return err
	})
	return out, err
}

// MarkStale marks an approved rule stale for an external reason (the drift
// detector when a contract it depends on changed). reason is a short code.
func (rp *Repo) MarkStale(ctx context.Context, id, reason string, now time.Time) error {
	var n StaleNotice
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		r, err := getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.status != StatusApproved {
			return ErrConflict
		}
		n = StaleNotice{RuleID: id, Kind: r.kind, Reason: reason, Previous: r.approvedConf.Float64, Current: r.confidence}
		if err := rp.setStatus(ctx, tx, r, StatusStale, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE miner_rules SET stale_reason = ? WHERE id = ?`, reason, id)
		return err
	})
	if err != nil {
		return err
	}
	rp.notify(ctx, []StaleNotice{n})
	return nil
}

// supersedeTx moves to superseded every approved or stale rule that a newer
// approved rule replaces: the newer one names it in `supersedes`, or both
// share the (mined) signature and the other has a higher sequence. The old
// rule keeps its body and review (history) but leaves the active set, so it
// is no longer packed and cannot distort outcomes. It returns the ids moved.
func (rp *Repo) supersedeTx(ctx context.Context, tx *sql.Tx, now time.Time) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+rowCols+` FROM miner_rules WHERE status IN (?, ?) ORDER BY seq`, StatusApproved, StatusStale)
	if err != nil {
		return nil, err
	}
	var all []*row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	type approved struct {
		id, sup, sig string
		seq          int64
	}
	var newer []approved
	for _, r := range all {
		if r.status != StatusApproved {
			continue
		}
		ru, err := r.rule()
		if err != nil {
			return nil, err
		}
		_, _, _, sup, _ := ru.common()
		newer = append(newer, approved{id: r.id, sup: *sup, sig: r.signature, seq: r.seq})
	}
	var moved []string
	for _, x := range all {
		by := ""
		var bySeq int64
		for _, n := range newer {
			if n.id == x.id || n.seq <= bySeq {
				continue
			}
			if n.sup == x.id || (n.sig == x.signature && n.seq > x.seq && !isManualSig(n.sig)) {
				by, bySeq = n.id, n.seq
			}
		}
		if by == "" {
			continue
		}
		if err := rp.setStatus(ctx, tx, x, StatusSuperseded, now); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET stale_reason = ?, strikes = 0 WHERE id = ?`, ReasonSupersededPrefix+by, x.id); err != nil {
			return nil, err
		}
		moved = append(moved, x.id)
	}
	return moved, nil
}

// SupersedeApproved applies the supersession rule to the whole repository
// (a console that approved a replacement before the rule existed keeps both
// approved until this runs: the miner service runs it at start-up).
func (rp *Repo) SupersedeApproved(ctx context.Context, now time.Time) ([]string, error) {
	var moved []string
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		moved, err = rp.supersedeTx(ctx, tx, now)
		return err
	})
	return moved, err
}

// Retire takes an approved (or stale) rule out of the active set on a
// reviewer's decision: it becomes rejected with reason "retired", keeping
// the body, the evidence and the earlier review in history; a note is
// stored with the rule. It is the "withdraw" of an approved rule: a draft
// is rejected, an approved rule is retired.
func (rp *Repo) Retire(ctx context.Context, id, by, note string, now time.Time) (*StoredRule, error) {
	if len(note) > 1000 {
		return nil, ErrBadEdit
	}
	var out *StoredRule
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		r, err := getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.status != StatusApproved && r.status != StatusStale {
			return ErrConflict
		}
		ru, err := r.rule()
		if err != nil {
			return err
		}
		at := now.UTC().Format(time.RFC3339)
		pid, _, _, sup, rev := ru.common()
		who := []string{by}
		if *rev != nil {
			who = append(slices.Clone((*rev).By), by)
		}
		setHeader(&ru, *pid, StatusRejected, *sup, &Review{By: who, At: &at, Note: note})
		body, err := ruleJSON(ru)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET status = ?, body = ?, updated_at = ?, stale_reason = ?, strikes = 0 WHERE id = ?`,
			StatusRejected, body, now.UnixMilli(), ReasonRetired, id); err != nil {
			return err
		}
		r, err = getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		out, err = r.stored()
		return err
	})
	return out, err
}
