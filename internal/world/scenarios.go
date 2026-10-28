package world

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Preset is one scenario preset (tt.scenarios/v1, docs/spec/pack.md 6.1).
type Preset struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Customer    string          `json:"customer,omitempty"`
	Archetype   string          `json:"archetype,omitempty"`
	Seed        *uint64         `json:"seed,omitempty"`
	Faults      map[string]any  `json:"faults,omitempty"`
	Outcomes    []PresetOutcome `json:"outcomes,omitempty"`
}

// PresetOutcome forces an outcome of a causal rule.
type PresetOutcome struct {
	Rule    string `json:"rule"`
	Outcome string `json:"outcome"`
	Times   int    `json:"times,omitempty"`
}

// FaultHint is an observed fault of an operation, for fault presets.
type FaultHint struct {
	Service, Op string
	Status      int
	NetError    string
}

var presetIDRE = regexp.MustCompile(`[^a-z0-9-]+`)

func presetID(parts ...string) string {
	s := presetIDRE.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		s = "preset"
	}
	return s
}

var presetText = map[string][3]string{
	"it": {"%s: esito %s", "Forza l'esito %s della regola %s alla prossima causa.", "Guasto %s su %s"},
	"en": {"%s: outcome %s", "Forces outcome %s of rule %s on the next cause.", "Fault %s on %s"},
}

// DerivePresets builds presets from the rules (one per non-dominant outcome
// of each causal rule, on the first customer) and from observed faults (one
// per status or network error, always failing once). All texts are
// generated here; the caller tags them as synthetic.
func DerivePresets(r *Rules, customers []CustomerInfo, faults []FaultHint, locale string) []Preset {
	txt, ok := presetText[locale]
	if !ok {
		txt = presetText["it"]
	}
	cust := ""
	if len(customers) > 0 {
		ids := make([]string, len(customers))
		for i, c := range customers {
			ids[i] = c.ID
		}
		sort.Strings(ids)
		cust = ids[0]
	}
	var out []Preset
	seen := map[string]bool{}
	add := func(p Preset) {
		base := p.ID
		for i := 2; seen[p.ID]; i++ {
			p.ID = presetID(base, fmt.Sprint(i))
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	for _, c := range r.Causal {
		top := 0
		for i, o := range c.Outcomes {
			if o.P > c.Outcomes[top].P {
				top = i
			}
		}
		for i, o := range c.Outcomes {
			if i == top || o.P <= 0 {
				continue
			}
			add(Preset{ID: presetID(c.ID, o.Name), Name: fmt.Sprintf(txt[0], c.ID, o.Name),
				Description: fmt.Sprintf(txt[1], o.Name, c.ID), Customer: cust,
				Outcomes: []PresetOutcome{{Rule: c.ID, Outcome: o.Name, Times: 1}}})
		}
	}
	for _, f := range faults {
		rule := map[string]any{"service": f.Service, "op": f.Op, "p": 1, "times": 1}
		what := f.NetError
		if f.Status != 0 {
			rule["status"] = f.Status
			what = fmt.Sprint(f.Status)
		} else {
			rule["net_error"] = f.NetError
		}
		add(Preset{ID: presetID("fault", f.Service, f.Op, what), Name: fmt.Sprintf(txt[2], what, f.Service+" "+f.Op),
			Faults: map[string]any{"mode": "custom", "rules": []any{rule}}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Strings returns every string of a preset (provenance tags).
func (p Preset) Strings() []string {
	s := []string{p.ID, p.Name, p.Description, p.Customer, p.Archetype}
	for _, o := range p.Outcomes {
		s = append(s, o.Rule, o.Outcome)
	}
	return s
}

// ScenariosFile renders scenarios.json (canonical, presets sorted by id).
func ScenariosFile(presets []Preset) ([]byte, error) {
	ps := append([]Preset(nil), presets...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	list := []any{}
	for _, p := range ps {
		m := map[string]any{"id": p.ID, "name": p.Name}
		if p.Description != "" {
			m["description"] = p.Description
		}
		if p.Customer != "" {
			m["customer"] = p.Customer
		} else if p.Archetype != "" {
			m["archetype"] = p.Archetype
		}
		if p.Seed != nil {
			m["seed"] = *p.Seed
		}
		if p.Faults != nil {
			m["faults"] = p.Faults
		}
		if len(p.Outcomes) > 0 {
			var oc []any
			for _, o := range p.Outcomes {
				om := map[string]any{"outcome": o.Outcome, "rule": o.Rule}
				if o.Times > 0 {
					om["times"] = o.Times
				}
				oc = append(oc, om)
			}
			m["outcomes"] = oc
		}
		list = append(list, m)
	}
	return CanonicalFile(map[string]any{"format": "tt.scenarios/v1", "scenarios": list})
}
