package export

import "fmt"

// delayInfo describes the figurative delays of a rule for the loss report.
func (m *model) delayInfo(ruleID string) string {
	for _, r := range m.rules {
		if r.ID != ruleID {
			continue
		}
		fixed, ranges := 0, 0
		for _, e := range r.Effects {
			if e.After.IsRange {
				ranges++
			} else {
				fixed++
			}
		}
		return fmt.Sprintf("%d single values, %d ranges {min,max}", fixed, ranges)
	}
	return ""
}

// reportCommon records what every target shares: relation links kept and
// delay shapes seen.
func (m *model) reportCommon(rep *reportBuilder) {
	total := 0
	for _, el := range sortedKeys(m.links) {
		rep.exported("relation", "relation:"+el, m.links[el])
		total += m.links[el]
	}
	rep.count("relation_values", total)
	rep.count("range_delays", m.stats.RangeDelays)
}
