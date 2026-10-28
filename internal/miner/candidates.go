package miner

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Candidates below the threshold (rules v1.9, C0). With k = 20 a test
// environment with a handful of testers produces no rule at all. The miner
// runs a second, relaxed pass on each group's log (k = 2, MinDistinct scaled
// the same way) and lists, as candidates, the rules of that pass that the
// normal pass did not produce, seen by fewer subjects than the group's k.
// A candidate carries structure only: the operations, the entity, the field
// names, the clear states (codes and booleans the policy already lets out),
// a status, the number of subjects as a bucket, and the rule skeleton the
// editor starts from (origin manual, status draft, counts zeroed, no link
// keys nor hints). Never an example, a token or an exact count. Nothing of
// the relaxed pass is stored (names are given on a throwaway copy of the
// name book) and its diagnostics are dropped. A group with more than
// Config.CandidateMaxEvents events is not passed again (memory and time).
//
// Groups marked as test in the console (MineOptions.GroupKMin) are mined
// with their own k (at least 2, below Config.KMin) and MinDistinct scaled
// by the same ratio; Diagnostics.TestK records it.

// maxCandidates bounds the candidates of a run.
const maxCandidates = 200

// scaledConfig returns cfg with KMin k and MinDistinct scaled by k/KMin.
func scaledConfig(cfg Config, k int) *Config {
	c := cfg
	c.MinDistinct = max(2, cfg.MinDistinct*k/cfg.KMin)
	c.KMin = k
	return &c
}

// groupConfig is the configuration of group g: cfg, or (rules v1.9) cfg
// with the group's test k when it is in [2, KMin); recorded in res.
func groupConfig(cfg Config, k int, g string, res *Result) *Config {
	if k < 2 || k >= cfg.KMin {
		return &cfg
	}
	if res != nil {
		if res.Diag.TestK == nil {
			res.Diag.TestK = map[string]int{}
		}
		res.Diag.TestK[g] = k
	}
	return scaledConfig(cfg, k)
}

// candidatesOf runs the relaxed pass on every group and returns the
// candidates (see above).
func candidatesOf(logs map[string]*Log, cfg Config, opt MineOptions, res *Result, now time.Time) []Candidate {
	if cfg.CandidateMaxEvents <= 0 {
		return nil
	}
	have := map[string]bool{}
	for _, r := range res.Rules {
		have[r.Signature] = true
	}
	known := map[string]bool{}
	for _, e := range res.Entities {
		known[e.Name] = true
	}
	var out []Candidate
	for _, g := range sortedKeys(logs) {
		l := logs[g]
		gcfg := groupConfig(cfg, opt.GroupKMin[g], g, nil)
		if gcfg.KMin <= 2 || l.Events() == 0 || l.Events() > cfg.CandidateMaxEvents {
			continue
		}
		for _, mm := range relaxedRules(l, scaledConfig(*gcfg, 2), g, res.Names, now) {
			c := mm.Rule.Causal
			if c == nil || have[mm.Signature] || c.Evidence.Counts.DistinctSubjects >= gcfg.KMin {
				continue
			}
			have[mm.Signature] = true
			cand := candidateOf(g, mm)
			miss := map[string]bool{}
			for _, e := range c.Effects {
				if e.Entity != "" && !known[e.Entity] {
					miss[e.Entity] = true
				}
			}
			cand.MissingEntities = sortedKeys(miss)
			out = append(out, cand)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Group != out[b].Group {
			return out[a].Group < out[b].Group
		}
		return out[a].Signature < out[b].Signature
	})
	if len(out) > maxCandidates {
		out = out[:maxCandidates]
	}
	return out
}

// relaxedRules mines the causal rules of a log with cfg, storing nothing.
func relaxedRules(l *Log, cfg *Config, g string, stored []EntityName, now time.Time) []*Mined {
	m := newMiner(cfg, l)
	m.selectAll()
	book := newNameBook(stored, now)
	names := book.assign(m.candidates(g))
	m.buildEntities(g, names, book)
	var rs []*Mined
	rs = append(rs, m.mineUpdates()...)
	for i := range m.ents {
		if m.ents[i].creatorOp < 0 {
			continue
		}
		if mm := m.mineCausal(i); mm != nil {
			rs = append(rs, mm)
		}
	}
	rs = append(rs, m.mineRemovals()...)
	lims := m.mineLimits()
	rs = append(rs, lims...)
	rs = append(rs, m.minePreconds(lims)...)
	rs = append(rs, m.mineUpdatesAll()...)
	return rs
}

// candidateOf describes a relaxed rule as a candidate: structure only.
func candidateOf(g string, mm *Mined) Candidate {
	c := mm.Rule.Causal
	parts := strings.Split(mm.Signature, "|")
	cand := Candidate{Group: g, Signature: mm.Signature, Service: c.Cause.Service, Op: c.Cause.Op,
		Subjects: subjectBucket(c.Evidence.Counts.DistinctSubjects)}
	last := parts[len(parts)-1]
	switch {
	case len(parts) >= 5 && parts[3] == "until":
		cand.Kind, cand.Template = CandPrecondition, TplUntil
	case len(parts) >= 5 && parts[3] == "limit":
		cand.Kind, cand.Template = CandLimit, TplAtMostN
	case last == "update_all":
		cand.Kind, cand.Template = CandUpdateAll, TplWriteChangesField
	case last == "remove":
		cand.Kind, cand.Template = CandRemove, TplCustom
	case last == "update":
		cand.Kind, cand.Template = CandUpdate, TplWriteChangesField
	default:
		cand.Kind, cand.Template = CandCreate, TplCustom
	}
	fields, states := map[string]bool{}, map[string]bool{}
	addStates := func(vals map[string]any) {
		for _, v := range vals {
			switch x := v.(type) {
			case string:
				if !strings.HasPrefix(x, "${") {
					states[x] = true
				}
			case bool:
				if x {
					states["true"] = true
				} else {
					states["false"] = true
				}
			}
		}
	}
	for _, e := range c.Effects {
		if e.Respond != nil {
			cand.Status = e.Respond.Status
			cand.Target = e.Respond.Service + " " + e.Respond.Op
			continue
		}
		if cand.Entity == "" {
			cand.Entity = e.Entity
		}
		if e.TargetKey != nil && cand.Kind == CandUpdate {
			cand.Kind = CandKeyedUpdate
		}
		if e.Where != nil && e.AfterEffect != "" && strings.HasSuffix(e.ID, "-reverted") {
			cand.Kind, cand.Template = CandRevert, TplExpiresAfter
		}
		for _, vals := range []map[string]any{e.Create, e.Set} {
			for k := range vals {
				fields[k] = true
			}
			addStates(vals)
		}
		addStates(e.Where)
	}
	cand.Fields, cand.States = sortedKeys(fields), sortedKeys(states)
	cand.Draft = draftOf(c)
	return cand
}

// draftOf is the skeleton of a rule for the editor: a manual draft with
// zero counts, no link keys, no hints, no review.
func draftOf(c *CausalRule) *Rule {
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var d CausalRule
	if err := decodeStrict(b, &d); err != nil {
		return nil
	}
	d.ID, d.Status, d.Origin, d.Supersedes, d.Review = "r-0000", StatusDraft, OriginManual, "", nil
	outs := map[string]int{}
	for _, o := range d.Outcomes {
		outs[o.Name] = 0
	}
	d.Evidence = CausalEvidence{Counts: CausalCounts{Outcomes: outs}}
	return &Rule{Causal: &d}
}
