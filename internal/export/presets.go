package export

import (
	"fmt"
	"sort"
	"strings"
)

// PresetReport says how a scenarios.json preset maps to a target.
type PresetReport struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"` // mapped | partial | lost
	How    []string `json:"how"`
	Lost   []string `json:"lost"`
}

type presetOpts struct {
	faultHeader    string
	customerHeader string
	scoped         map[string]bool // customers with owner-scoped stubs (WireMock)
}

func (m *model) buildPresets() {
	custs := append([]WorldCustomer(nil), m.in.World.Customers...)
	sort.Slice(custs, func(i, j int) bool { return custs[i].ID < custs[j].ID })
	ps := append([]Preset(nil), m.in.Scenarios...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	for _, p := range ps {
		plan := presetPlan{P: p, Customer: p.Customer}
		if plan.Customer == "" && p.Archetype != "" {
			for _, c := range custs {
				if c.Archetype == p.Archetype {
					plan.Customer = c.ID
					break
				}
			}
		}
		for _, po := range p.Outcomes {
			n := po.Times
			if n <= 0 {
				n = 1
			}
			var cands []*chain
			for _, c := range m.chains {
				if c.Rule.ID == po.Rule && c.Outcome == po.Outcome {
					cands = append(cands, c)
				}
			}
			sort.SliceStable(cands, func(i, j int) bool {
				ai, aj := cands[i].Owner == plan.Customer, cands[j].Owner == plan.Customer
				if ai != aj && plan.Customer != "" {
					return ai
				}
				return cands[i].Subject < cands[j].Subject
			})
			if len(cands) > n {
				cands = cands[:n]
			}
			plan.Chains = append(plan.Chains, cands...)
			if len(cands) < n {
				plan.Missing = append(plan.Missing, fmt.Sprintf("outcome %s of %s: %d subjects wanted, %d in the world", po.Outcome, po.Rule, n, len(cands)))
			}
		}
		m.presets = append(m.presets, plan)
	}
}

// presetReports maps every preset to what the target can do about it.
func (m *model) presetReports(target string, o presetOpts) []PresetReport {
	adv := map[string]*lookup{}
	for _, svc := range sortedKeys(m.lookups) {
		for _, l := range m.lookups[svc] {
			if l.Scenario != "" && l.Advance && adv[l.Scenario] == nil {
				adv[l.Scenario] = l
			}
		}
	}
	var out []PresetReport
	for _, pl := range m.presets {
		r := PresetReport{ID: pl.P.ID, Name: pl.P.Name, How: []string{}, Lost: []string{}}
		for _, c := range pl.Chains {
			l := adv[c.scenario()]
			if l == nil {
				r.Lost = append(r.Lost, fmt.Sprintf("subject %s of %s (%s) is not exposed by any operation", c.Subject, c.Rule.ID, c.Outcome))
				continue
			}
			var states []string
			for _, v := range l.Views {
				states = append(states, v.State)
			}
			switch target {
			case TargetWireMock:
				r.How = append(r.How, fmt.Sprintf("outcome %s of %s: scenario %s, call %s %s=%s (%s); POST /__admin/scenarios/reset restarts it",
					c.Outcome, c.Rule.ID, l.Scenario, l.Op.Key, l.Param, l.Key, strings.Join(states, " > ")))
			case TargetMicrocks:
				r.How = append(r.How, fmt.Sprintf("outcome %s of %s: call %s with %s=%s (%d steps, one per call, kept in the store)",
					c.Outcome, c.Rule.ID, l.Op.Key, l.Param, l.Key, len(l.Views)))
			case TargetPrism:
				last := l.Views[len(l.Views)-1]
				r.How = append(r.How, fmt.Sprintf("outcome %s of %s: %s %s=%s with Prefer: example=%s (one example per step, chosen by hand)",
					c.Outcome, c.Rule.ID, l.Op.Key, l.Param, l.Key, last.Name))
			}
		}
		r.Lost = append(r.Lost, pl.Missing...)
		if pl.Customer != "" {
			if target == TargetWireMock && o.scoped[pl.Customer] {
				r.How = append(r.How, fmt.Sprintf("customer %s: send header %s: %s", pl.Customer, o.customerHeader, pl.Customer))
			} else if len(pl.Chains) > 0 {
				r.How = append(r.How, fmt.Sprintf("customer %s: the subjects above are the ones of that customer when the world has them", pl.Customer))
			} else {
				r.Lost = append(r.Lost, fmt.Sprintf("customer %s: the session customer has no equivalent in %s", pl.Customer, target))
			}
		}
		if f := pl.P.Faults; f != nil {
			if f.Mode == "observed" {
				r.Lost = append(r.Lost, "faults.mode observed: random injection at the observed frequencies is not representable")
			}
			for _, fr := range f.Rules {
				r.addFault(m, target, o, fr)
			}
		}
		if pl.P.Seed != nil {
			r.Lost = append(r.Lost, fmt.Sprintf("seed %d: the exports make no random choices", *pl.P.Seed))
		}
		switch {
		case len(r.Lost) == 0:
			r.Status = "mapped"
			if len(r.How) == 0 {
				r.How = append(r.How, "nothing to force: the default behaviour applies")
			}
		case len(r.How) == 0:
			r.Status = "lost"
		default:
			r.Status = "partial"
		}
		out = append(out, r)
	}
	return out
}

func (r *PresetReport) addFault(m *model, target string, o presetOpts, fr PresetFaultRule) {
	where := fr.Service + " " + fr.Op
	if fr.P <= 0 {
		return
	}
	if fr.Op == "*" {
		r.Lost = append(r.Lost, "fault on every operation ("+fr.Service+" *): send it per operation")
		return
	}
	if fr.LatencyMS > 0 {
		r.Lost = append(r.Lost, fmt.Sprintf("latency_ms %d on %s: not injectable on demand", fr.LatencyMS, where))
	}
	op := m.ops[fr.Service+"|"+fr.Op]
	if op == nil {
		r.Lost = append(r.Lost, "fault on "+where+": operation is not in the export")
		return
	}
	if fr.P < 1 {
		r.Lost = append(r.Lost, fmt.Sprintf("fault on %s with p=%v: no random injection, only forced on request", where, fr.P))
	}
	if fr.Times > 0 {
		r.Lost = append(r.Lost, fmt.Sprintf("fault on %s limited to %d times: no call counter", where, fr.Times))
	}
	f := m.faults[fr.Service+"|"+fr.Op]
	switch {
	case fr.Status > 0:
		hasFault := false
		for _, s := range f.Statuses {
			if s.Status == fr.Status {
				hasFault = true
			}
		}
		resp := op.response(fr.Status)
		switch target {
		case TargetWireMock:
			switch {
			case hasFault:
				r.How = append(r.How, fmt.Sprintf("fault %d on %s: send header %s: %d", fr.Status, where, o.faultHeader, fr.Status))
			case resp != nil && len(resp.Examples) > 0:
				r.How = append(r.How, fmt.Sprintf("fault %d on %s: send header X-TT-Example: %s", fr.Status, where, resp.Examples[0].Name))
			default:
				r.Lost = append(r.Lost, fmt.Sprintf("fault %d on %s: no stub for that status", fr.Status, where))
			}
		case TargetMicrocks:
			if resp != nil && len(resp.Examples) > 0 {
				r.How = append(r.How, fmt.Sprintf("fault %d on %s: use the parameter value %s", fr.Status, where, triggerValue(resp.Examples[0].Name)))
			} else {
				r.Lost = append(r.Lost, fmt.Sprintf("fault %d on %s: no example with that status", fr.Status, where))
			}
		case TargetPrism:
			if resp != nil {
				r.How = append(r.How, fmt.Sprintf("fault %d on %s: send Prefer: code=%d", fr.Status, where, fr.Status))
			} else {
				r.Lost = append(r.Lost, fmt.Sprintf("fault %d on %s: status not declared in the contract", fr.Status, where))
			}
		}
	case fr.NetError != "":
		listed := false
		for _, n := range f.NetErrors {
			if n.Kind == fr.NetError {
				listed = true
			}
		}
		if target == TargetWireMock && listed {
			r.How = append(r.How, fmt.Sprintf("network error %s on %s: send header %s: %s", fr.NetError, where, o.faultHeader, fr.NetError))
		} else {
			r.Lost = append(r.Lost, fmt.Sprintf("network error %s on %s: not representable in %s", fr.NetError, where, target))
		}
	}
}
