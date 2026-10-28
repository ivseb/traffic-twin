package miner

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// Rules v1.9 (docs/spec/rules.md 3.12–3.15, 2.11–2.13): conditions on the
// request and on the customer (cause.when.match, outcomes[].when), customer
// attributes, aggregates computed from the collections, list filters and
// list operations no entity reads, preconditions (respond.until) and
// effects on all the objects of the customer (target_all).

// Match is one condition: a request value (At) or a customer attribute
// (Customer) is one of In, or a number in [Min, Max).
type Match struct {
	At       *Ref     `json:"at,omitempty"`
	Customer string   `json:"customer,omitempty"`
	In       []any    `json:"in,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
}

// Attribute is a customer attribute carried by some responses (rules.md
// 2.11): each customer has one value, the same in all of them.
type Attribute struct {
	Name     string             `json:"name"`
	Values   map[string]float64 `json:"values"`
	Subjects int                `json:"subjects"`
	Fields   []AttrField        `json:"fields"`
}

// AttrField is a response member that carries an attribute.
type AttrField struct {
	Service string `json:"service"`
	Op      string `json:"op"`
	At      Ref    `json:"at"`
}

// Aggregate is a number of a response computed at read time from the
// customer's collection (rules.md 2.12): a count, a sum or a counter moved
// by writes.
type Aggregate struct {
	Service string     `json:"service"`
	Op      string     `json:"op"`
	At      Ref        `json:"at"`
	Count   *AggCount  `json:"count,omitempty"`
	Sum     *AggSum    `json:"sum,omitempty"`
	Delta   []AggDelta `json:"delta,omitempty"`
	// Subjects is the exact number of subjects whose reads confirmed it.
	Subjects int `json:"subjects,omitempty"`
}

// AggCount counts the customer's entities whose fields equal Where.
type AggCount struct {
	Entity string         `json:"entity"`
	Where  map[string]any `json:"where,omitempty"`
}

// AggSum sums a numeric field of the customer's entities matching Where.
type AggSum struct {
	Entity string         `json:"entity"`
	Field  string         `json:"field"`
	Where  map[string]any `json:"where,omitempty"`
}

// AggDelta moves the number by By at every successful call of Op.
type AggDelta struct {
	Service string `json:"service,omitempty"`
	Op      string `json:"op"`
	By      int    `json:"by"`
}

// ListFilter keeps the list items whose Field equals the value of Param.
type ListFilter struct {
	Param NameRef `json:"param"`
	Field string  `json:"field"`
}

// ListOp is a list operation that no entity reads (rules.md 2.13): the
// mock pages its static answer.
type ListOp struct {
	Service string    `json:"service"`
	Op      string    `json:"op"`
	At      Ref       `json:"at"`
	List    ListShape `json:"list"`
}

// Limits of the v1.9 members.
const (
	maxMatches       = 8
	maxMatchValues   = 64
	maxAttrValues    = 64
	maxAttrFields    = 32
	maxDeltas        = 8
	maxListFilters   = 8
	maxDocAttributes = 64
	maxDocAggregates = 256
	maxDocLists      = 256
)

// validMatches checks conditions; customer names must be attributes of
// the document when attrs is not nil.
func validMatches(ms []Match, attrs map[string]bool) error {
	if len(ms) == 0 || len(ms) > maxMatches {
		return invalidf("between 1 and %d conditions", maxMatches)
	}
	for _, m := range ms {
		if (m.At == nil) == (m.Customer == "") {
			return invalidf("a condition takes at or customer")
		}
		if m.At != nil {
			if !strings.HasPrefix(m.At.From, "req.") || m.At.From == "req.cookies" || m.At.Field != "" || m.At.Owner {
				return invalidf("a condition reads the request body, path, query or headers")
			}
			if err := validRef(*m.At, false); err != nil {
				return err
			}
			if m.At.Path != "" && strings.Contains(m.At.Path, "[*]") {
				return invalidf("a condition reads a body member outside arrays")
			}
		}
		if m.Customer != "" {
			if !reBindName.MatchString(m.Customer) {
				return invalidf("bad customer attribute %q", m.Customer)
			}
			if attrs != nil && !attrs[m.Customer] {
				return invalidf("unknown customer attribute %q", m.Customer)
			}
		}
		rng := m.Min != nil || m.Max != nil
		if (len(m.In) > 0) == rng {
			return invalidf("a condition takes in or min/max")
		}
		if len(m.In) > maxMatchValues {
			return invalidf("too many condition values")
		}
		for _, v := range m.In {
			switch x := v.(type) {
			case string:
				if len(x) > 256 || strings.Contains(x, "${") {
					return invalidf("bad condition value")
				}
			case bool, float64, int, int64, json.Number:
			default:
				return invalidf("condition values are scalars")
			}
		}
		if m.Min != nil && m.Max != nil && !(*m.Min < *m.Max) {
			return invalidf("condition min must be below max")
		}
		for _, f := range []*float64{m.Min, m.Max} {
			if f != nil && (math.IsNaN(*f) || math.IsInf(*f, 0)) {
				return invalidf("bad condition bound")
			}
		}
	}
	return nil
}

// validTargetAll checks an effect on all the customer's objects.
func validTargetAll(e Effect) error {
	if e.Create != nil || e.Target != "" || e.TargetID != "" || e.TargetKey != nil {
		return invalidf("target_all excludes create, target, target_id and target_key")
	}
	if e.Remove == (e.Set != nil) {
		return invalidf("target_all takes set or remove")
	}
	return nil
}

// validateExtras checks the v1.9 members of a document.
func (d *Document) validateExtras(ents map[string]*Entity) error {
	if len(d.Attributes) > maxDocAttributes || len(d.Aggregates) > maxDocAggregates || len(d.Lists) > maxDocLists {
		return invalidf("too many attributes, aggregates or lists")
	}
	names := map[string]bool{}
	for _, a := range d.Attributes {
		if !reBindName.MatchString(a.Name) || names[a.Name] {
			return invalidf("bad or duplicate attribute %q", a.Name)
		}
		names[a.Name] = true
		if len(a.Values) < 2 || len(a.Values) > maxAttrValues || a.Subjects < 0 {
			return invalidf("attribute %q: between 2 and %d values", a.Name, maxAttrValues)
		}
		sum := 0.0
		for v, p := range a.Values {
			if v == "" || len(v) > 64 || p < 0 || p > 1 || math.IsNaN(p) {
				return invalidf("attribute %q: bad value", a.Name)
			}
			sum += p
		}
		if math.Abs(sum-1) > 0.001 {
			return invalidf("attribute %q: shares sum to %.4f", a.Name, sum)
		}
		if len(a.Fields) == 0 || len(a.Fields) > maxAttrFields {
			return invalidf("attribute %q: between 1 and %d fields", a.Name, maxAttrFields)
		}
		for _, f := range a.Fields {
			if err := validRespPoint(f.Service, f.Op, f.At); err != nil {
				return err
			}
		}
	}
	for _, g := range d.Aggregates {
		if err := validRespPoint(g.Service, g.Op, g.At); err != nil {
			return err
		}
		n := 0
		if g.Count != nil {
			n++
			if err := validAggEntity(g.Count.Entity, g.Count.Where, ents); err != nil {
				return err
			}
		}
		if g.Sum != nil {
			n++
			if err := validAggEntity(g.Sum.Entity, g.Sum.Where, ents); err != nil {
				return err
			}
			if !reFieldPath.MatchString(g.Sum.Field) {
				return invalidf("aggregate sum: bad field")
			}
		}
		if g.Delta != nil {
			n++
			if len(g.Delta) == 0 || len(g.Delta) > maxDeltas {
				return invalidf("aggregate delta: between 1 and %d operations", maxDeltas)
			}
			for _, dl := range g.Delta {
				if (dl.Service != "" && !reService.MatchString(dl.Service)) || !reOp.MatchString(dl.Op) || dl.By == 0 || dl.By < -1000 || dl.By > 1000 {
					return invalidf("aggregate delta: bad operation or step")
				}
			}
		}
		if n != 1 || g.Subjects < 0 {
			return invalidf("an aggregate takes one of count, sum and delta")
		}
	}
	for _, lo := range d.Lists {
		if !reService.MatchString(lo.Service) || !reOp.MatchString(lo.Op) || lo.At.From != "resp.body" ||
			!reTTPath.MatchString(lo.At.Path) || !strings.HasSuffix(lo.At.Path, "[*]") {
			return invalidf("list %s %s: bad operation or items path", lo.Service, lo.Op)
		}
		if err := validListFilters(lo.List.Filters); err != nil {
			return err
		}
	}
	return nil
}

// validRespPoint checks a response member outside arrays of an operation.
func validRespPoint(service, op string, at Ref) error {
	if !reService.MatchString(service) || !reOp.MatchString(op) || at.From != "resp.body" ||
		!reTTPath.MatchString(at.Path) || at.Path == "$" || strings.Contains(at.Path, "[*]") || strings.Contains(at.Path, ".*") {
		return invalidf("bad response member %s %s %s", service, op, at)
	}
	return nil
}

func validAggEntity(name string, where map[string]any, ents map[string]*Entity) error {
	if !reIdent.MatchString(name) || (ents != nil && ents[name] == nil) {
		return invalidf("aggregate of unknown entity %q", name)
	}
	if err := validValues(where); err != nil {
		return err
	}
	for _, v := range where {
		if s, ok := v.(string); ok && strings.Contains(s, "${") {
			return invalidf("aggregate where takes literal values only")
		}
	}
	return nil
}

func validListFilters(fs []ListFilter) error {
	if len(fs) > maxListFilters {
		return invalidf("too many list filters")
	}
	for _, f := range fs {
		if f.Param.From != "req.query" || !reName.MatchString(f.Param.Name) || !reFieldPath.MatchString(f.Field) {
			return invalidf("bad list filter")
		}
	}
	return nil
}

// MatchValue reports whether a value (a JSON scalar of the request or of
// the customer) satisfies a condition (rules.md 3.12): equal to one of In
// by canonical form, or a number in [Min, Max).
func MatchValue(m Match, v any, present bool) bool {
	if !present || v == nil {
		return false
	}
	if len(m.In) > 0 {
		cv := canonScalar(v)
		for _, x := range m.In {
			if canonScalar(x) == cv {
				return true
			}
		}
		return false
	}
	f, ok := scalarFloat(v)
	if !ok {
		return false
	}
	return (m.Min == nil || f >= *m.Min) && (m.Max == nil || f < *m.Max)
}

// canonScalar is the canonical string of a scalar: strings as they are
// (a string that is a number compares as that number), booleans true or
// false, numbers in their shortest decimal form.
func canonScalar(v any) string {
	if f, ok := scalarFloat(v); ok {
		if _, isBool := v.(bool); !isBool {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}

// scalarFloat reads a number (also a string that is a number).
func scalarFloat(v any) (float64, bool) {
	var s string
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		s = string(x)
	case string:
		s = strings.TrimSpace(x)
	default:
		return 0, false
	}
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// validCustomerRefs checks that the customer conditions of a rule name
// attributes of the document.
func (r *Rule) validCustomerRefs(attrs map[string]bool) error {
	c := r.Causal
	if c == nil {
		return nil
	}
	lists := [][]Match{c.Cause.When.Match}
	for _, o := range c.Outcomes {
		lists = append(lists, o.When)
	}
	for _, ms := range lists {
		for _, m := range ms {
			if m.Customer != "" && !attrs[m.Customer] {
				return invalidf("rule %q: unknown customer attribute %q", c.ID, m.Customer)
			}
		}
	}
	return nil
}
