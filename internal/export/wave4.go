package export

import "fmt"

// Rules v1.9 (docs/spec/rules.md 2.11-2.13, 3.12-3.15) in the exporters:
// the stubs answer every request alike and keep no per-session state, so
// conditions, customer attributes, aggregates, list filters and the paging
// of static lists are reported as losses; target_all and preconditions
// (respond.until) are dropped with the other effects (withoutResponses).

// conditionLosses reports the conditions of a rule: the stubs draw the
// outcomes (or follow the scenarios) whatever the request and the
// customer.
func (m *model) conditionLosses(r *Rule) {
	if r.Kind != "causal" || r.Cause == nil {
		return
	}
	n := 0
	if len(r.Cause.When.Match) > 0 {
		n++
	}
	for _, o := range r.Outcomes {
		if len(o.When) > 0 {
			n++
		}
	}
	if n > 0 {
		m.note("conditional-outcome", "rule:"+r.ID, fmt.Sprintf("%d conditions on the request or the customer (when) are not exported: the outcomes do not depend on the request", n), n)
	}
}

// readLosses reports the read-time members of the rules.
func (m *model) readLosses() {
	rs := &m.in.Rules
	for _, a := range rs.Attributes {
		m.note("customer-attribute", "attribute:"+a.Name, "a customer attribute is not exported: the stubs answer the contract's values, not one value per customer", 1)
	}
	for _, g := range rs.Aggregates {
		m.note("aggregate", "op:"+g.Service+" "+g.Op, "a number computed from the customer's objects (aggregate) is not exported: the stubs answer the observed value", 1)
	}
	for _, l := range rs.Lists {
		m.note("list-paging", "op:"+l.Service+" "+l.Op, "the paging of a static list is not exported: every page answers the same items", 1)
	}
	for _, e := range rs.Entities {
		for _, rb := range e.ReadBy {
			if rb.List != nil && len(rb.List.Filters) > 0 {
				m.note("list-filter", "entity:"+e.Name, fmt.Sprintf("%d list filters of %s are not exported", len(rb.List.Filters), rb.Op), len(rb.List.Filters))
			}
		}
	}
}
