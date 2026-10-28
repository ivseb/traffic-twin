package miner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// HTTP API of the rules written by hand (admin-api, tag rules):
//
//	GET  /api/v1/rules/catalog       what a rule may name (contracts, entities)
//	POST /api/v1/rules/check         validate a rule without storing it
//	POST /api/v1/rules               store a rule written by hand (draft, origin manual)
//	PUT  /api/v1/rules/{rule_id}     replace the definition of a rule (draft in place,
//	                                 approved/stale: new superseding draft)

const maxRuleBody = 64 << 10

// catalog builds the catalog of the request's groups.
func (s *Service) catalog(r *http.Request) (*Catalog, error) {
	ents, err := s.repo.Entities(r.Context())
	if err != nil {
		return nil, err
	}
	var docs []ContractDoc
	if s.d.Contracts != nil {
		docs, err = s.d.Contracts.ContractDocs(r.Context(), []string(groupscope.FromRequest(r)))
		if err != nil {
			return nil, err
		}
	}
	sel := groupscope.FromRequest(r)
	if !sel.All() {
		if ents, err = s.entitiesOf(r.Context(), ents, sel, docs); err != nil {
			return nil, err
		}
	}
	return BuildCatalog(docs, ents), nil
}

// entitiesOf keeps the entities of the selected groups: those whose name
// was given to a selected group (names.go), and, for names without a group
// (stored before groups), those of a service in the catalog.
func (s *Service) entitiesOf(ctx context.Context, ents []Entity, sel groupscope.Set, docs []ContractDoc) ([]Entity, error) {
	names, err := s.repo.EntityNames(ctx)
	if err != nil {
		return nil, err
	}
	groupOf := map[string]string{}
	for _, n := range names {
		groupOf[n.Name] = n.Group
	}
	services := map[string]bool{}
	for _, d := range docs {
		services[d.Service] = true
	}
	out := make([]Entity, 0, len(ents))
	for _, e := range ents {
		if g := groupOf[e.Name]; g != "" {
			if !sel.Has(g) {
				continue
			}
		} else if !services[e.Service] {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Service) getCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principal(w, r, false, "", ""); !ok {
		return
	}
	cat, err := s.catalog(r)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cat)
}

func problemDetails(ps []Problem) []map[string]any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{"path": p.Path, "code": p.Code, "message": p.Message})
	}
	return out
}

func nonNilProblems(ps []Problem) []Problem {
	if ps == nil {
		return []Problem{}
	}
	return ps
}

// decodeRule reads a rule definition (the rules.v1 object without the
// header the server owns).
func decodeRule(w http.ResponseWriter, r *http.Request) (Rule, bool) {
	var ru Rule
	if err := httpx.DecodeJSON(w, r, maxRuleBody, &ru); err != nil {
		httpx.WriteErrorDetails(w, http.StatusBadRequest, "invalid_rule", "the rule is not a valid rules.v1 object",
			[]map[string]any{{"path": "", "code": "invalid", "message": "a causal or batch rule (kind) with known fields only"}})
		return Rule{}, false
	}
	return ru, true
}

func (s *Service) checkRule(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.principal(w, r, false, "", ""); !ok {
		return
	}
	ru, ok := decodeRule(w, r)
	if !ok {
		return
	}
	cat, err := s.catalog(r)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	probs, warns, err := s.repo.Check(r.Context(), ru, cat)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"valid": len(probs) == 0, "problems": nonNilProblems(probs), "warnings": nonNilProblems(warns)})
}

func (s *Service) writeRuleError(w http.ResponseWriter, err error) {
	var ie *ErrInvalidRule
	if errors.As(err, &ie) {
		httpx.WriteErrorDetails(w, http.StatusUnprocessableEntity, "invalid_rule", ie.Error(), problemDetails(ie.Problems))
		return
	}
	s.writeRepoError(w, err)
}

func ruleReason(err error) string {
	var ie *ErrInvalidRule
	if errors.As(err, &ie) {
		return "invalid_rule"
	}
	return editReason(err)
}

// createdView is a rule with the warnings of its validation.
type createdView struct {
	ruleView
	warnings []Problem
}

func (v createdView) MarshalJSON() ([]byte, error) {
	b, err := v.ruleView.MarshalJSON()
	if err != nil || len(v.warnings) == 0 {
		return b, err
	}
	// Append "warnings" to the object.
	wb, err := json.Marshal(v.warnings)
	if err != nil {
		return nil, err
	}
	return append(append(b[:len(b)-1], []byte(`,"warnings":`)...), append(wb, '}')...), nil
}

func (s *Service) createRule(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(w, r, true, "rule.create", "")
	if !ok {
		return
	}
	ru, ok := decodeRule(w, r)
	if !ok {
		return
	}
	cat, err := s.catalog(r)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	x, warns, err := s.repo.CreateManual(r.Context(), ru, cat, s.now())
	if err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.create", Target: audit.Target{Type: "rule"},
			Outcome: audit.Failure, Reason: ruleReason(err), RequestID: httpx.RequestID(r.Context())})
		s.writeRuleError(w, err)
		return
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.create", Target: audit.Target{Type: "rule", ID: x.Rule.ID()},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, map[string]string{
			"kind": x.Rule.Kind(), "origin": OriginManual, "effects": strconv.Itoa(effectCount(x.Rule))})})
	httpx.WriteJSON(w, http.StatusCreated, createdView{ruleView{x}, warns})
}

func effectCount(r Rule) int {
	if r.Causal != nil {
		return len(r.Causal.Effects)
	}
	return 1
}

func (s *Service) replaceRule(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(w, r, true, "rule.edit", wellFormedID(r))
	if !ok {
		return
	}
	id, ok := ruleID(w, r)
	if !ok {
		return
	}
	ru, ok := decodeRule(w, r)
	if !ok {
		return
	}
	cat, err := s.catalog(r)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	x, warns, err := s.repo.Replace(r.Context(), id, ru, cat, s.now())
	if err != nil {
		s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.edit", Target: audit.Target{Type: "rule", ID: id},
			Outcome: audit.Failure, Reason: ruleReason(err), RequestID: httpx.RequestID(r.Context())})
		s.writeRuleError(w, err)
		return
	}
	det := map[string]string{"definition": "true", "origin": x.Rule.Origin()}
	if nid := x.Rule.ID(); nid != id {
		det["new_rule"] = nid
	}
	s.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.edit", Target: audit.Target{Type: "rule", ID: id},
		Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: overrideDetail(p, det)})
	httpx.WriteJSON(w, http.StatusOK, createdView{ruleView{x}, warns})
}
