package pack

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/idfmt"
)

const maxWorldLine = 8 << 20

// Row types of world.jsonl in file order.
const (
	rankMeta = iota
	rankCustomer
	rankEntity
	rankHistory
	rankPending
)

var rankOf = map[string]int{"meta": rankMeta, "customer": rankCustomer, "entity": rankEntity, "history": rankHistory, "pending": rankPending}

// parseWorld reads world.jsonl: row order, per-type sort order and field
// shapes. Referential integrity is checked by checkWorld once the rules are
// known.
func parseWorld(data []byte, wantCustomers int) (*World, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("file must end with a newline")
	}
	w := &World{}
	br := bufio.NewReaderSize(bytes.NewReader(data), 64*1024)
	lineNo := 0
	lastRank := -1
	var prevKey string
	var prevHist *WorldHistory
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
		lineNo++
		if len(line) > maxWorldLine {
			return nil, fmt.Errorf("line %d is too long", lineNo)
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		if len(line) == 0 {
			return nil, fmt.Errorf("line %d is empty", lineNo)
		}
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &head); err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo, err)
		}
		rank, known := rankOf[head.Type]
		if !known {
			return nil, fmt.Errorf("line %d: unknown type %q", lineNo, head.Type)
		}
		if lineNo == 1 && rank != rankMeta {
			return nil, errors.New("first line must be the meta line")
		}
		if rank < lastRank || (rank == rankMeta && lineNo != 1) {
			return nil, fmt.Errorf("line %d: %s rows are out of order", lineNo, head.Type)
		}
		if rank != lastRank {
			prevKey = ""
			prevHist = nil
		}
		lastRank = rank
		switch rank {
		case rankMeta:
			var m struct {
				Type   string `json:"type"`
				Format string `json:"format"`
				Seed   uint64 `json:"seed"`
				T0     string `json:"t0"`
			}
			if err := decodeStrict(line, &m); err != nil || m.Format != "tt.world/v1" || !worldTimeRE.MatchString(m.T0) {
				return nil, fmt.Errorf("line %d: malformed meta", lineNo)
			}
			t0, err := time.Parse(time.RFC3339, m.T0)
			if err != nil {
				return nil, fmt.Errorf("line %d: malformed t0", lineNo)
			}
			w.Seed, w.T0 = m.Seed, t0.UTC()
		case rankCustomer:
			var c struct {
				Type string `json:"type"`
				Customer
			}
			if err := decodeStrict(line, &c); err != nil || !worldIDRE.MatchString(c.ID) || c.Profile == nil {
				return nil, fmt.Errorf("line %d: malformed customer", lineNo)
			}
			if c.Archetype != nil && !archetypeRE.MatchString(*c.Archetype) {
				return nil, fmt.Errorf("line %d: malformed archetype", lineNo)
			}
			if prevKey != "" && c.ID <= prevKey {
				return nil, fmt.Errorf("line %d: customers must be sorted by id", lineNo)
			}
			prevKey = c.ID
			w.Customers = append(w.Customers, c.Customer)
		case rankEntity:
			var e struct {
				Type string `json:"type"`
				WorldEntity
			}
			if err := decodeStrict(line, &e); err != nil || !entityIDRE.MatchString(e.ID) || !identRE.MatchString(e.Entity) || e.State == nil {
				return nil, fmt.Errorf("line %d: malformed entity", lineNo)
			}
			if e.CustomerID != nil && !worldIDRE.MatchString(*e.CustomerID) {
				return nil, fmt.Errorf("line %d: malformed customer_id", lineNo)
			}
			if k := e.Entity + "\x00" + e.ID; prevKey != "" && k <= prevKey {
				return nil, fmt.Errorf("line %d: entities must be sorted by (entity, id)", lineNo)
			} else {
				prevKey = k
			}
			w.Entities = append(w.Entities, e.WorldEntity)
		case rankHistory:
			var h struct {
				Type string `json:"type"`
				WorldHistory
			}
			if err := decodeStrict(line, &h); err != nil || !entityIDRE.MatchString(h.ID) || !identRE.MatchString(h.Entity) ||
				!worldTimeRE.MatchString(h.At) || h.Seq < 1 || h.State == nil {
				return nil, fmt.Errorf("line %d: malformed history", lineNo)
			}
			if h.RuleID != "" && !ruleIDRE.MatchString(h.RuleID) {
				return nil, fmt.Errorf("line %d: malformed rule_id", lineNo)
			}
			if (h.Outcome != "" && !identRE.MatchString(h.Outcome)) || (h.EffectID != "" && !identRE.MatchString(h.EffectID)) {
				return nil, fmt.Errorf("line %d: malformed outcome or effect_id", lineNo)
			}
			at, _ := time.Parse(time.RFC3339, h.At)
			if !at.Before(w.T0) {
				return nil, fmt.Errorf("line %d: history must precede t0", lineNo)
			}
			if p := prevHist; p != nil {
				k0, k1 := p.Entity+"\x00"+p.ID, h.Entity+"\x00"+h.ID
				if k0 > k1 || (k0 == k1 && (p.At > h.At || (p.At == h.At && p.Seq >= h.Seq))) {
					return nil, fmt.Errorf("line %d: history must be sorted by (entity, id, at, seq)", lineNo)
				}
				if k0 == k1 && p.Seq >= h.Seq {
					return nil, fmt.Errorf("line %d: history seq must grow per entity", lineNo)
				}
			}
			cp := h.WorldHistory
			prevHist = &cp
			w.History = append(w.History, h.WorldHistory)
		case rankPending:
			var p struct {
				Type string `json:"type"`
				WorldPending
			}
			if err := decodeStrict(line, &p); err != nil || !entityIDRE.MatchString(p.ID) || !identRE.MatchString(p.Entity) ||
				!ruleIDRE.MatchString(p.RuleID) || !identRE.MatchString(p.Outcome) || !identRE.MatchString(p.EffectID) ||
				p.DueOffsetS < 1 || p.DueOffsetS > 316224000 || p.Seq < 1 {
				return nil, fmt.Errorf("line %d: malformed pending", lineNo)
			}
			if p.CustomerID != nil && !worldIDRE.MatchString(*p.CustomerID) {
				return nil, fmt.Errorf("line %d: malformed customer_id", lineNo)
			}
			for k, v := range p.Vars {
				if !bindNameRE.MatchString(k) {
					return nil, fmt.Errorf("line %d: malformed vars key", lineNo)
				}
				switch v.(type) {
				case string, json.Number, bool, nil:
				default:
					return nil, fmt.Errorf("line %d: vars values must be scalars", lineNo)
				}
			}
			for k, v := range p.EffectIDs {
				if !identRE.MatchString(k) || !entityIDRE.MatchString(v) {
					return nil, fmt.Errorf("line %d: malformed effect_ids", lineNo)
				}
			}
			if n := len(w.Pending); n > 0 {
				prev := w.Pending[n-1]
				if p.DueOffsetS < prev.DueOffsetS || (p.DueOffsetS == prev.DueOffsetS && p.Seq <= prev.Seq) || p.Seq <= prev.Seq {
					return nil, fmt.Errorf("line %d: pending rows must be sorted by (due_offset_s, seq) with seq growing", lineNo)
				}
			}
			w.Pending = append(w.Pending, p.WorldPending)
		}
	}
	if w.T0.IsZero() {
		return nil, errors.New("meta line is missing")
	}
	if len(w.Customers) != wantCustomers {
		return nil, fmt.Errorf("manifest says %d customers, file has %d", wantCustomers, len(w.Customers))
	}
	return w, nil
}

// checkWorld verifies the referential integrity of the world (docs/spec/pack.md
// section 5): customers, relation fields, pending rows.
//
// An entity id is either <PREFIX>-SYN-NNNN or, when the id domain of the
// entity has an id format (pack.md 4.3, fmts by domain), an id of that
// format.
func checkWorld(w *World, r *Rules, fmts map[string]*idfmt.Template) error {
	custs := map[string]bool{}
	for _, c := range w.Customers {
		custs[c.ID] = true
	}
	entRows := map[string]bool{} // entity\x00id
	for _, e := range w.Entities {
		k := e.Entity + "\x00" + e.ID
		if entRows[k] {
			return fmt.Errorf("duplicate entity %s %s", e.Entity, e.ID)
		}
		entRows[k] = true
		if e.CustomerID != nil && !custs[*e.CustomerID] {
			return fmt.Errorf("entity %s refers to an unknown customer", e.ID)
		}
	}
	rules := map[string]*CausalRule{}
	for i := range r.Causal {
		rules[r.Causal[i].ID] = &r.Causal[i]
	}
	ents := map[string]*Entity{}
	for i := range r.Entities {
		ents[r.Entities[i].Name] = &r.Entities[i]
	}
	idOK := func(entity, id string) bool {
		if worldIDRE.MatchString(id) {
			return true
		}
		e := ents[entity]
		if e == nil {
			return false
		}
		t := fmts[e.IDDomain]
		return t != nil && t.Match(id)
	}
	for _, e := range w.Entities {
		if !idOK(e.Entity, e.ID) {
			return fmt.Errorf("entity %s: an id is neither synthetic (-SYN-) nor in the id format of its domain", e.Entity)
		}
	}
	for _, h := range w.History {
		if !idOK(h.Entity, h.ID) {
			return fmt.Errorf("history of %s: an id is neither synthetic (-SYN-) nor in the id format of its domain", h.Entity)
		}
	}
	for _, p := range w.Pending {
		if !idOK(p.Entity, p.ID) {
			return fmt.Errorf("pending seq %d: the id is neither synthetic (-SYN-) nor in the id format of its domain", p.Seq)
		}
	}

	// pending: rule, branch, effect; creators first (seq order decides ties)
	created := map[string]int{} // entity\x00id -> index in Pending of the creating row
	for i, p := range w.Pending {
		rule := rules[p.RuleID]
		if rule == nil {
			return fmt.Errorf("pending seq %d: unknown rule %s", p.Seq, p.RuleID)
		}
		var branch map[string]bool
		for _, o := range rule.Outcomes {
			if o.Name == p.Outcome {
				branch = map[string]bool{}
				for _, id := range o.Effects {
					branch[id] = true
				}
			}
		}
		if branch == nil {
			return fmt.Errorf("pending seq %d: rule %s has no outcome %s", p.Seq, p.RuleID, p.Outcome)
		}
		if !branch[p.EffectID] {
			return fmt.Errorf("pending seq %d: effect %s is not part of outcome %s", p.Seq, p.EffectID, p.Outcome)
		}
		var eff *Effect
		for j := range rule.Effects {
			if rule.Effects[j].ID == p.EffectID {
				eff = &rule.Effects[j]
			}
		}
		if eff.Entity != p.Entity {
			return fmt.Errorf("pending seq %d: effect %s changes entity %s, not %s", p.Seq, p.EffectID, eff.Entity, p.Entity)
		}
		if p.CustomerID != nil && !custs[*p.CustomerID] {
			return fmt.Errorf("pending seq %d refers to an unknown customer", p.Seq)
		}
		k := p.Entity + "\x00" + p.ID
		if eff.Create != nil {
			if entRows[k] {
				return fmt.Errorf("pending seq %d creates %s, which already exists", p.Seq, p.ID)
			}
			if _, dup := created[k]; dup {
				return fmt.Errorf("pending seq %d creates %s twice", p.Seq, p.ID)
			}
			created[k] = i
		}
		for name := range p.Vars {
			if _, ok := rule.Cause.Bind[name]; !ok {
				return fmt.Errorf("pending seq %d: vars cites ${%s}, which the rule does not bind", p.Seq, name)
			}
		}
	}
	for _, p := range w.Pending {
		rule := rules[p.RuleID]
		var eff *Effect
		for j := range rule.Effects {
			if rule.Effects[j].ID == p.EffectID {
				eff = &rule.Effects[j]
			}
		}
		if eff.Create != nil {
			continue
		}
		k := p.Entity + "\x00" + p.ID
		if entRows[k] {
			continue
		}
		ci, ok := created[k]
		if !ok {
			return fmt.Errorf("pending seq %d: entity %s does not exist", p.Seq, p.ID)
		}
		c := w.Pending[ci]
		if c.DueOffsetS > p.DueOffsetS || (c.DueOffsetS == p.DueOffsetS && c.Seq >= p.Seq) {
			return fmt.Errorf("pending seq %d: entity %s is created later", p.Seq, p.ID)
		}
	}

	// relations
	for _, e := range w.Entities {
		def := ents[e.Entity]
		if def == nil {
			continue
		}
		for _, rel := range def.Relations {
			v, ok := dottedGet(e.State, rel.Field)
			if !ok || v == nil {
				continue
			}
			var ids []any
			if rel.Many {
				arr, isArr := v.([]any)
				if !isArr {
					return fmt.Errorf("%s %s: %s must be an array of ids", e.Entity, e.ID, rel.Field)
				}
				ids = arr
			} else {
				ids = []any{v}
			}
			for _, raw := range ids {
				id, isStr := raw.(string)
				if !isStr {
					return fmt.Errorf("%s %s: %s must hold ids", e.Entity, e.ID, rel.Field)
				}
				k := rel.Entity + "\x00" + id
				if _, pend := created[k]; !entRows[k] && !pend {
					return fmt.Errorf("%s %s: %s points to %s %s, which does not exist", e.Entity, e.ID, rel.Field, rel.Entity, id)
				}
			}
		}
	}
	return nil
}

func dottedGet(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
