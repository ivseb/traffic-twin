package miner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ivseb/traffic-twin/internal/derive"
	"strconv"
	"strings"
	"time"
)

// Rules written by hand (rules v1.4, origin "manual") and structural edits
// of drafts. The miner finds what traffic shows (cause -> effect through
// shared ids, state changes, outcome frequencies, batches); a person writes
// what it cannot see (computations, logic on masked values, rare branches,
// aggregate rules). Both follow the same review: a draft, approved or
// rejected by a rule reviewer (an admin alone, audited), exported into packs
// and served by the mock exactly like a mined rule.

// Problem is one reason a rule is refused (or, as a warning, looks odd):
// where (a path into the rule), a code and an English message. It never
// contains values from traffic.
type Problem struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrInvalidRule is returned with the problems of a refused rule.
type ErrInvalidRule struct{ Problems []Problem }

func (e *ErrInvalidRule) Error() string {
	if len(e.Problems) == 0 {
		return "miner: invalid rule"
	}
	return "miner: invalid rule: " + e.Problems[0].Message
}

const manualSigPrefix = "manual|"

func isManualSig(sig string) bool { return strings.HasPrefix(sig, manualSigPrefix) }

func fieldKnown(fs []CatalogField, from, name, path string) bool {
	for _, f := range fs {
		if f.From == from && ((path != "" && f.Path == path) || (path == "" && f.Name == name)) {
			return true
		}
	}
	return false
}

// CheckAgainst validates a rule against the contracts and the entities:
// operations, fields, statuses, examples must exist. Problems refuse the
// rule; warnings (a status never observed) are shown but accepted.
func CheckAgainst(r Rule, cat *Catalog, ents map[string]*Entity) (problems, warnings []Problem) {
	add := func(path, code, msg string, a ...any) {
		problems = append(problems, Problem{Path: path, Code: code, Message: fmt.Sprintf(msg, a...)})
	}
	warn := func(path, code, msg string, a ...any) {
		warnings = append(warnings, Problem{Path: path, Code: code, Message: fmt.Sprintf(msg, a...)})
	}
	entFields := func(path, entity string, vals map[string]any) {
		ce := cat.Entity(entity)
		if ce == nil || len(ce.Fields) == 0 {
			return // fields unknown: nothing to check against
		}
		for _, k := range sortedKeys(vals) {
			known := false
			for _, f := range ce.Fields {
				if f.Name == k || strings.HasPrefix(k, f.Name+".") {
					known = true
					break
				}
			}
			if !known {
				add(path+"."+k, "unknown_field", "entity %s has no field %s", entity, k)
			}
		}
		checkDerived(path, entity, vals, ce, add)
	}
	checkStatus := func(path string, op *CatalogOp, st int) {
		for _, s := range op.Statuses {
			if s == st {
				return
			}
		}
		warn(path, "status_not_observed", "status %d was never observed for %s", st, op.Op)
	}
	switch {
	case r.Causal != nil:
		c := r.Causal
		svc := cat.Service(c.Cause.Service)
		op := svc.Op(c.Cause.Op)
		switch {
		case svc == nil:
			add("cause.service", "unknown_service", "service %s is not in the contracts", c.Cause.Service)
		case op == nil:
			add("cause.op", "unknown_op", "operation %s is not in the contract of %s", c.Cause.Op, c.Cause.Service)
		}
		if op != nil {
			for i, st := range c.Cause.When.Status {
				checkStatus("cause.when.status["+strconv.Itoa(i)+"]", op, st)
			}
			for _, name := range sortedKeys(c.Cause.Bind) {
				ref := c.Cause.Bind[name]
				p := "cause.bind." + name
				switch ref.From {
				case "resp.body":
					if ref.Path != "$" && !fieldKnown(op.Response, "resp.body", "", ref.Path) {
						add(p, "unknown_field", "the response of %s has no field %s", op.Op, ref.Path)
					}
				case "req.body":
					if ref.Path != "$" && !fieldKnown(op.Request, "req.body", "", ref.Path) {
						add(p, "unknown_field", "the request of %s has no field %s", op.Op, ref.Path)
					}
				case "req.path", "req.query", "req.headers", "req.cookies":
					if !fieldKnown(op.Params, ref.From, ref.Name, "") {
						add(p, "unknown_field", "%s has no parameter %s in %s", op.Op, ref.Name, ref.From)
					}
				}
			}
		}
		for i, e := range c.Effects {
			p := "effects[" + strconv.Itoa(i) + "]"
			if rs := e.Respond; rs != nil {
				rsvc := cat.Service(rs.Service)
				rop := rsvc.Op(rs.Op)
				switch {
				case rsvc == nil:
					add(p+".respond.service", "unknown_service", "service %s is not in the contracts", rs.Service)
				case rop == nil:
					add(p+".respond.op", "unknown_op", "operation %s is not in the contract of %s", rs.Op, rs.Service)
				default:
					checkStatus(p+".respond.status", rop, rs.Status)
					if rs.Example != "" {
						found := false
						for _, n := range rop.Examples[strconv.Itoa(rs.Status)] {
							found = found || n == rs.Example
						}
						if !found {
							add(p+".respond.example", "unknown_example", "%s has no example %s for status %d", rs.Op, rs.Example, rs.Status)
						}
					}
				}
				continue
			}
			if ents[e.Entity] == nil {
				add(p+".entity", "unknown_entity", "entity %s is not known (mine first, or pick an entity of the list)", e.Entity)
				continue
			}
			entFields(p+".create", e.Entity, e.Create)
			entFields(p+".set", e.Entity, e.Set)
			entFields(p+".where", e.Entity, e.Where)
		}
	case r.Batch != nil:
		b := r.Batch
		if ents[b.Entity] == nil {
			add("entity", "unknown_entity", "entity %s is not known", b.Entity)
		} else {
			entFields("where", b.Entity, b.Where)
			entFields("set", b.Entity, b.Set)
		}
	}
	return problems, warnings
}

// prepareManual normalizes a rule written by hand before validation: the
// header the server owns (id placeholder, status, origin, evidence, review).
func prepareManual(r *Rule, id string, origin string) error {
	switch {
	case r.Causal != nil && r.Batch == nil:
		c := r.Causal
		c.ID, c.Kind, c.Status, c.Origin, c.Review = id, KindCausal, StatusDraft, origin, nil
		c.Evidence = CausalEvidence{Counts: CausalCounts{Outcomes: map[string]int{}}}
		for _, o := range c.Outcomes {
			c.Evidence.Counts.Outcomes[o.Name] = 0
		}
	case r.Batch != nil && r.Causal == nil:
		b := r.Batch
		b.ID, b.Kind, b.Status, b.Origin, b.Review = id, KindBatch, StatusDraft, origin, nil
		b.Evidence = BatchEvidence{}
	default:
		return &ErrInvalidRule{Problems: []Problem{{Code: "invalid", Message: "a rule is causal or batch"}}}
	}
	_, _, title, _, _ := r.common()
	*title = strings.TrimSpace(*title)
	if *title == "" || len([]rune(*title)) > 200 || strings.ContainsAny(*title, "\x00") {
		return &ErrInvalidRule{Problems: []Problem{{Path: "title", Code: "invalid", Message: "the title is required (at most 200 characters)"}}}
	}
	return nil
}

// Check validates a rule written by hand (structure, then contracts and
// entities) without storing it.
func (rp *Repo) Check(ctx context.Context, r Rule, cat *Catalog) (problems, warnings []Problem, err error) {
	if err := prepareManual(&r, "r-0000", OriginManual); err != nil {
		var ie *ErrInvalidRule
		if errors.As(err, &ie) {
			return ie.Problems, nil, nil
		}
		return nil, nil, err
	}
	var ents map[string]*Entity
	err = rp.db.InTx(ctx, func(tx *sql.Tx) error {
		var e error
		ents, e = rp.entitiesTx(ctx, tx)
		return e
	})
	if err != nil {
		return nil, nil, err
	}
	p, w := checkRule(r, cat, ents)
	return p, w, nil
}

func checkRule(r Rule, cat *Catalog, ents map[string]*Entity) (problems, warnings []Problem) {
	if err := r.Validate(ents); err != nil {
		msg := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
		return []Problem{{Code: "invalid", Message: msg}}, nil
	}
	if cat == nil {
		return nil, nil
	}
	return CheckAgainst(r, cat, ents)
}

// CreateManual stores a rule written by hand as a draft with origin manual.
func (rp *Repo) CreateManual(ctx context.Context, r Rule, cat *Catalog, now time.Time) (*StoredRule, []Problem, error) {
	var out *StoredRule
	var warnings []Problem
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		seq, err := nextSeq(ctx, tx)
		if err != nil {
			return err
		}
		id := fmt.Sprintf("r-%04d", seq)
		if err := prepareManual(&r, id, OriginManual); err != nil {
			return err
		}
		ents, err := rp.entitiesTx(ctx, tx)
		if err != nil {
			return err
		}
		probs, warns := checkRule(r, cat, ents)
		if len(probs) > 0 {
			return &ErrInvalidRule{Problems: probs}
		}
		warnings = warns
		body, err := ruleJSON(r)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO miner_rules (id, seq, signature, kind, status, structure, confidence, body, edits, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, ?)`, id, seq, manualSigPrefix+id, r.Kind(), StatusDraft, "manual", body, now.UnixMilli(), now.UnixMilli()); err != nil {
			return err
		}
		row, err := getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		out, err = row.stored()
		return err
	})
	return out, warnings, err
}

// Replace changes the definition of a rule (cause, effects, outcomes, or
// schedule, where, set, fraction; and the title): in place for a draft, as
// a new draft that supersedes it for an approved or stale rule. A mined
// draft keeps the person's definition when the miner refreshes it (only
// its evidence follows the traffic). Rejected rules cannot change.
func (rp *Repo) Replace(ctx context.Context, id string, r Rule, cat *Catalog, now time.Time) (*StoredRule, []Problem, error) {
	var out *StoredRule
	var warnings []Problem
	err := rp.db.InTx(ctx, func(tx *sql.Tx) error {
		row, err := getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if row.status == StatusRejected {
			return ErrConflict
		}
		old, err := row.rule()
		if err != nil {
			return err
		}
		if old.Kind() != r.Kind() {
			return &ErrInvalidRule{Problems: []Problem{{Path: "kind", Code: "invalid", Message: "the kind of a rule cannot change"}}}
		}
		origin := old.Origin()
		if err := prepareManual(&r, id, origin); err != nil {
			return err
		}
		if origin == OriginMined {
			// A mined rule keeps the stored origin form (absent) and its evidence.
			setOrigin(&r, "")
			keepEvidence(&r, old)
		}
		ents, err := rp.entitiesTx(ctx, tx)
		if err != nil {
			return err
		}
		probs, warns := checkRule(r, cat, ents)
		if len(probs) > 0 {
			return &ErrInvalidRule{Problems: probs}
		}
		warnings = warns
		var ed edits
		if row.edits.Valid {
			_ = json.Unmarshal([]byte(row.edits.String), &ed)
		}
		def, err := cloneRule(r)
		if err != nil {
			return err
		}
		ed.Body, ed.Title, ed.After = &def, nil, nil
		target := id
		switch row.status {
		case StatusDraft:
			_, _, _, sup, _ := old.common()
			setHeader(&r, id, StatusDraft, *sup, nil)
			body, err := ruleJSON(r)
			if err != nil {
				return err
			}
			eb, _ := json.Marshal(ed)
			if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET body = ?, edits = ?, updated_at = ? WHERE id = ?`, body, string(eb), now.UnixMilli(), id); err != nil {
				return err
			}
		case StatusApproved, StatusStale:
			setHeader(&r, "", StatusDraft, id, nil)
			target, err = rp.insert(ctx, tx, r, row.signature, row.structure, row.confidence, &ed, now)
			if err != nil {
				return err
			}
			if isManualSig(row.signature) {
				// Each manual draft carries its own signature: the miner never
				// refreshes it.
				if _, err := tx.ExecContext(ctx, `UPDATE miner_rules SET signature = ? WHERE id = ?`, manualSigPrefix+target, target); err != nil {
					return err
				}
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
	return out, warnings, err
}

func setOrigin(r *Rule, o string) {
	if r.Causal != nil {
		r.Causal.Origin = o
	}
	if r.Batch != nil {
		r.Batch.Origin = o
	}
}

func keepEvidence(r *Rule, old Rule) {
	switch {
	case r.Causal != nil && old.Causal != nil:
		r.Causal.Evidence = old.Causal.Evidence
		if r.Causal.Evidence.Counts.Outcomes == nil {
			r.Causal.Evidence.Counts.Outcomes = map[string]int{}
		}
		// New outcome names have no observations yet.
		for _, o := range r.Causal.Outcomes {
			if _, ok := r.Causal.Evidence.Counts.Outcomes[o.Name]; !ok {
				r.Causal.Evidence.Counts.Outcomes[o.Name] = 0
			}
		}
		if h := r.Causal.Evidence.Hints; h != nil {
			ids := map[string]bool{}
			for _, e := range r.Causal.Effects {
				ids[e.ID] = true
			}
			for k := range h.Magnitude {
				if !ids[k] {
					delete(h.Magnitude, k)
				}
			}
		}
	case r.Batch != nil && old.Batch != nil:
		r.Batch.Evidence = old.Batch.Evidence
	}
}

// applyBody replaces the definition of a mined rule by the person's
// (edits.Body), keeping the header and the evidence of the mined one.
func applyBody(r *Rule, def *Rule) {
	if def == nil {
		return
	}
	switch {
	case r.Causal != nil && def.Causal != nil:
		c, d := r.Causal, def.Causal
		c.Title, c.Cause, c.Effects, c.Outcomes = d.Title, d.Cause, d.Effects, d.Outcomes
		fresh := Rule{Causal: c}
		keepEvidence(&fresh, Rule{Causal: &CausalRule{Evidence: c.Evidence}})
	case r.Batch != nil && def.Batch != nil:
		b, d := r.Batch, def.Batch
		b.Title, b.Schedule, b.Entity, b.Where, b.Set, b.Fraction = d.Title, d.Schedule, d.Entity, d.Where, d.Set, d.Fraction
	}
}

// checkDerived checks the derived values of create/set against the fields
// of the entity (docs/spec/rules.md 3.15): every field they read is a field
// of the entity (or a value of the same map), and the type of the result
// fits the contract type of the field it writes.
func checkDerived(path, entity string, vals map[string]any, ce *CatalogEntity, add func(path, code, msg string, a ...any)) {
	dv, err := derive.ParseValues(vals)
	if err != nil {
		add(path, "bad_derived", "%v", err)
		return
	}
	fieldOf := func(name string) (CatalogField, bool) {
		for _, f := range ce.Fields {
			if f.Name == name {
				return f, true
			}
		}
		return CatalogField{}, false
	}
	top := func(p string) string { return strings.SplitN(p, ".", 2)[0] }
	known := func(p string) bool {
		if _, ok := vals[p]; ok {
			return true
		}
		if _, ok := vals[top(p)]; ok {
			return true
		}
		for _, f := range ce.Fields {
			if f.Name == p || top(f.Name) == top(p) {
				return true
			}
		}
		return false
	}
	for _, k := range sortedKeys(vals) {
		e := dv[k]
		if e == nil {
			continue
		}
		for _, f := range e.References().Fields {
			if !known(f) {
				add(path+"."+k, "unknown_field", "derived value of %s reads %s, which entity %s does not have", k, f, entity)
			}
		}
		f, ok := fieldOf(k)
		if !ok || f.Type == "" {
			continue
		}
		switch rt := e.ResultType(); {
		case rt == "number" && f.Type != "number" && f.Type != "integer":
			add(path+"."+k, "derived_type", "%s computes a number, but field %s is a %s", e.Fn, k, f.Type)
		case rt == "string" && f.Type != "string":
			add(path+"."+k, "derived_type", "%s computes a text, but field %s is a %s", e.Fn, k, f.Type)
		}
	}
}
