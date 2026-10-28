package pack

import (
	"errors"
	"fmt"
	"math"
	"regexp"
)

var (
	scenarioIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	faultOpRE    = regexp.MustCompile(`^(\*|[A-Z]{1,16} /[!-~]*)$`)
)

// parseScenarios reads scenarios.json (tt.scenarios/v1) and checks it against
// the rest of the pack: customers, archetypes, rules and outcomes, services.
func parseScenarios(data []byte, w *World, r *Rules, services map[string]bool) (*Scenarios, error) {
	var s Scenarios
	if err := decodeStrict(data, &s); err != nil {
		return nil, err
	}
	if s.Format != "tt.scenarios/v1" {
		return nil, errors.New("format must be tt.scenarios/v1")
	}
	if len(s.Scenarios) > 1000 {
		return nil, errors.New("too many presets")
	}
	custs := map[string]bool{}
	archs := map[string]bool{}
	for _, c := range w.Customers {
		custs[c.ID] = true
		if c.Archetype != nil {
			archs[*c.Archetype] = true
		}
	}
	outcomes := map[string]map[string]bool{}
	for _, c := range r.Causal {
		set := map[string]bool{}
		for _, o := range c.Outcomes {
			set[o.Name] = true
		}
		outcomes[c.ID] = set
	}
	prev := ""
	for i, sc := range s.Scenarios {
		at := fmt.Sprintf("preset %q", sc.ID)
		if !scenarioIDRE.MatchString(sc.ID) {
			return nil, fmt.Errorf("preset %d: malformed id", i)
		}
		if i > 0 && sc.ID <= prev {
			return nil, fmt.Errorf("%s: presets must be sorted by unique id", at)
		}
		prev = sc.ID
		if sc.Name == "" || len(sc.Name) > 120 || len(sc.Description) > 1000 {
			return nil, fmt.Errorf("%s: malformed name or description", at)
		}
		if sc.Customer != "" && sc.Archetype != "" {
			return nil, fmt.Errorf("%s: customer and archetype are exclusive", at)
		}
		if sc.Customer != "" {
			if !worldIDRE.MatchString(sc.Customer) || !custs[sc.Customer] {
				return nil, fmt.Errorf("%s: unknown customer", at)
			}
		}
		if sc.Archetype != "" {
			if !archetypeRE.MatchString(sc.Archetype) || !archs[sc.Archetype] {
				return nil, fmt.Errorf("%s: unknown archetype", at)
			}
		}
		if len(sc.Outcomes) > 256 {
			return nil, fmt.Errorf("%s: too many outcomes", at)
		}
		for _, o := range sc.Outcomes {
			set, ok := outcomes[o.Rule]
			if !ok {
				return nil, fmt.Errorf("%s: %s is not an approved causal rule", at, o.Rule)
			}
			if !set[o.Outcome] || !identRE.MatchString(o.Outcome) {
				return nil, fmt.Errorf("%s: rule %s has no outcome %s", at, o.Rule, o.Outcome)
			}
			if o.Times != nil && *o.Times < 1 {
				return nil, fmt.Errorf("%s: times must be >= 1", at)
			}
		}
		if f := sc.Faults; f != nil {
			switch f.Mode {
			case "observed", "off", "custom":
			default:
				return nil, fmt.Errorf("%s: faults mode", at)
			}
			if len(f.Rules) > 256 {
				return nil, fmt.Errorf("%s: too many fault rules", at)
			}
			for _, fr := range f.Rules {
				if fr.Service != "*" && !services[fr.Service] {
					return nil, fmt.Errorf("%s: faults cite unknown service %q", at, fr.Service)
				}
				if !faultOpRE.MatchString(fr.Op) || math.IsNaN(fr.P) || fr.P < 0 || fr.P > 1 {
					return nil, fmt.Errorf("%s: malformed fault rule", at)
				}
				if fr.Status != 0 && (fr.Status < 100 || fr.Status > 599) {
					return nil, fmt.Errorf("%s: fault status out of range", at)
				}
				if fr.Status != 0 && fr.NetError != "" {
					return nil, fmt.Errorf("%s: status and net_error are exclusive", at)
				}
				switch fr.NetError {
				case "", "timeout", "reset", "refused", "dns", "tls", "other":
				default:
					return nil, fmt.Errorf("%s: unknown net_error", at)
				}
				if fr.LatencyMs != nil && *fr.LatencyMs < 0 {
					return nil, fmt.Errorf("%s: negative latency", at)
				}
				if fr.Times != nil && *fr.Times < 1 {
					return nil, fmt.Errorf("%s: times must be >= 1", at)
				}
				if (fr.Example != "" || fr.Body != nil) && fr.Status == 0 {
					return nil, fmt.Errorf("%s: example and body need a status", at)
				}
				if fr.Example != "" && !exampleKeyRE.MatchString(fr.Example) {
					return nil, fmt.Errorf("%s: malformed example name", at)
				}
				if fr.Body != nil {
					if err := ValidateErrorBody(fr.Body); err != nil {
						return nil, fmt.Errorf("%s: %v", at, err)
					}
				}
			}
		}
	}
	return &s, nil
}
