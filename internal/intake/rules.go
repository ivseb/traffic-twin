package intake

import "github.com/ivseb/traffic-twin/internal/event"

// groups is the ordered list of rule groups that apply to one side of an
// exchange (docs/spec/sanitizer.md 5.0): operation (1), service errors (2a),
// global errors (2b), service (3), global (4). Missing groups are skipped.
type groups struct {
	g [5]*partRules
	n int
}

func (gs *groups) add(p *partRules) {
	if p != nil {
		gs.g[gs.n] = p
		gs.n++
	}
}

// groupsFor builds the groups for a side. op may be nil (raw route), svc may
// be nil (no service entry in the policy).
func (p *Policy) groupsFor(svc *serviceRules, op *opRules, resp bool, status int) groups {
	var gs groups
	if !resp {
		if op != nil {
			gs.add(op.req)
		}
		if svc != nil {
			gs.add(svc.scope.req)
		}
		gs.add(p.global.req)
		return gs
	}
	if op != nil {
		gs.add(op.resp)
	}
	if status >= 400 {
		if svc != nil {
			gs.add(svc.scope.errs)
		}
		gs.add(p.global.errs)
	}
	if svc != nil {
		gs.add(svc.scope.resp)
	}
	gs.add(p.global.resp)
	return gs
}

type partID uint8

const (
	partQuery partID = iota
	partHeaders
	partCookies
)

// named returns the action for a name in a query, header or cookie map: the
// first group that has a rule for the name wins. nil means drop.
func (gs *groups) named(part partID, name string) *action {
	for i := 0; i < gs.n; i++ {
		var m map[string]*action
		switch part {
		case partQuery:
			m = gs.g[i].query
		case partHeaders:
			m = gs.g[i].headers
		default:
			m = gs.g[i].cookies
		}
		if a, ok := m[name]; ok {
			return a
		}
	}
	return nil
}

// anyNamed reports whether some rule of the part, in any group, satisfies
// ok. It is used for the collapsed name {*}: the original name is unknown, so
// a value is plausible if any rule could have produced it.
func (gs *groups) anyNamed(part partID, ok func(*action) bool) bool {
	for i := 0; i < gs.n; i++ {
		var m map[string]*action
		switch part {
		case partQuery:
			m = gs.g[i].query
		case partHeaders:
			m = gs.g[i].headers
		default:
			m = gs.g[i].cookies
		}
		for _, a := range m {
			if ok(a) {
				return true
			}
		}
	}
	return false
}

// bodyAction returns the effective action of a body leaf at the concrete
// steps (nil = no rule, i.e. drop by default). The first group with at least
// one matching rule decides; inside the group the rule with more .name steps
// wins, then the smaller path string.
func (gs *groups) bodyAction(steps []step) *action {
	for i := 0; i < gs.n; i++ {
		if gs.g[i].body == nil {
			continue
		}
		var best *bodyRule
		gs.g[i].body.match(steps, 0, &best)
		if best != nil {
			return best.act
		}
	}
	return nil
}

// anyBodyAction reports whether any matching rule of any group satisfies ok;
// used for the plausibility of leaves under collapsed keys (steps may
// contain stepStar for a collapsed key).
func (gs *groups) anyBodyAction(steps []step, ok func(*action) bool) bool {
	for i := 0; i < gs.n; i++ {
		if gs.g[i].body == nil {
			continue
		}
		var all []*bodyRule
		gs.g[i].body.collect(steps, 0, &all)
		for _, r := range all {
			if ok(r.act) {
				return true
			}
		}
	}
	return false
}

func better(r, cur *bodyRule) bool {
	if cur == nil {
		return true
	}
	if r.nameSteps != cur.nameSteps {
		return r.nameSteps > cur.nameSteps
	}
	return r.path < cur.path
}

// match finds the best rule whose tt-path matches the concrete steps.
// Concrete step kinds: stepName (literal key), stepStar (collapsed key {*},
// matched by .* and by .name rules whose name would itself be collapsed),
// stepElem (array element).
func (n *tnode) match(steps []step, i int, best **bodyRule) {
	if i == len(steps) {
		for _, r := range n.rules {
			if better(r, *best) {
				*best = r
			}
		}
		return
	}
	s := steps[i]
	switch s.kind {
	case stepName:
		if c := n.named[s.name]; c != nil {
			c.match(steps, i+1, best)
		}
		if n.star != nil {
			n.star.match(steps, i+1, best)
		}
	case stepStar:
		if n.star != nil {
			n.star.match(steps, i+1, best)
		}
		for name, c := range n.named {
			if event.DynamicName(name) {
				c.match(steps, i+1, best)
			}
		}
	default:
		if n.elem != nil {
			n.elem.match(steps, i+1, best)
		}
	}
}

// collect gathers all rules matching the concrete steps.
func (n *tnode) collect(steps []step, i int, out *[]*bodyRule) {
	if i == len(steps) {
		*out = append(*out, n.rules...)
		return
	}
	s := steps[i]
	switch s.kind {
	case stepName:
		if c := n.named[s.name]; c != nil {
			c.collect(steps, i+1, out)
		}
		if n.star != nil {
			n.star.collect(steps, i+1, out)
		}
	case stepStar:
		if n.star != nil {
			n.star.collect(steps, i+1, out)
		}
		for name, c := range n.named {
			if event.DynamicName(name) {
				c.collect(steps, i+1, out)
			}
		}
	default:
		if n.elem != nil {
			n.elem.collect(steps, i+1, out)
		}
	}
}

// reach reports whether some rule path has more steps than the container
// position and starts with them ("può raggiungere un discendente").
func (n *tnode) reach(steps []step, i int) bool {
	if i == len(steps) {
		return n.deeper
	}
	s := steps[i]
	switch s.kind {
	case stepName:
		if c := n.named[s.name]; c != nil && c.reach(steps, i+1) {
			return true
		}
		return n.star != nil && n.star.reach(steps, i+1)
	case stepStar:
		if n.star != nil && n.star.reach(steps, i+1) {
			return true
		}
		for name, c := range n.named {
			if event.DynamicName(name) && c.reach(steps, i+1) {
				return true
			}
		}
		return false
	default:
		return n.elem != nil && n.elem.reach(steps, i+1)
	}
}

// hasDropAt reports whether an explicit drop rule matches the container
// position exactly.
func (n *tnode) hasDropAt(steps []step) bool {
	var all []*bodyRule
	n.collect(steps, 0, &all)
	for _, r := range all {
		if r.act.kind == actDrop {
			return true
		}
	}
	return false
}

// containerDropped reports whether an ancestor container of the leaf at
// steps should have been collapsed by an explicit drop rule that applies
// (sanitizer.md 5.0, "Contenitori"): the drop applies only if no rule of the
// groups from 1 up to the group where it was found can reach a descendant.
func (gs *groups) containerDropped(steps []step) bool {
	any := false
	for i := 0; i < gs.n; i++ {
		if gs.g[i].body != nil && gs.g[i].hasDrop {
			any = true
			break
		}
	}
	if !any {
		return false
	}
	for k := 0; k < len(steps); k++ {
		prefix := steps[:k]
		found := -1
		for i := 0; i < gs.n; i++ {
			if gs.g[i].body != nil && gs.g[i].body.hasDropAt(prefix) {
				found = i
				break
			}
		}
		if found < 0 {
			continue
		}
		reached := false
		for j := 0; j <= found; j++ {
			if gs.g[j].body != nil && gs.g[j].body.reach(prefix, 0) {
				reached = true
				break
			}
		}
		if !reached {
			return true
		}
	}
	return false
}
