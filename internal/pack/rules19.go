package pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Rules v1.9 (docs/spec/rules.md 2.11-2.13, 3.12-3.15): conditions on the
// request and on the customer, customer attributes, aggregates, list
// filters and list operations no entity reads, preconditions and effects
// on all the objects of the customer.

// Match is one condition: a request value (At) or a customer attribute
// (Customer) is one of In, or a number in [Min, Max).
type Match struct {
	At       *Ref     `json:"at,omitempty"`
	Customer string   `json:"customer,omitempty"`
	In       []any    `json:"in,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
}

// Attribute is a customer attribute carried by some responses.
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

// Aggregate is a response number computed at read time.
type Aggregate struct {
	Service  string     `json:"service"`
	Op       string     `json:"op"`
	At       Ref        `json:"at"`
	Count    *AggCount  `json:"count,omitempty"`
	Sum      *AggSum    `json:"sum,omitempty"`
	Delta    []AggDelta `json:"delta,omitempty"`
	Subjects int        `json:"subjects,omitempty"`
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

// AggDelta moves the number by By at every successful call of Op
// (Service: the aggregate's when empty).
type AggDelta struct {
	Service string `json:"service,omitempty"`
	Op      string `json:"op"`
	By      int    `json:"by"`
}

// ListFilter keeps the items whose Field equals the value of Param.
type ListFilter struct {
	Param NameRef `json:"param"`
	Field string  `json:"field"`
}

// ListOp is a list operation no entity reads: the mock pages its static
// answer.
type ListOp struct {
	Service string    `json:"service"`
	Op      string    `json:"op"`
	At      Ref       `json:"at"`
	List    ListShape `json:"list"`
}

func validateMatches(ms []Match, attrs map[string]bool) error {
	if len(ms) == 0 || len(ms) > 8 {
		return errors.New("between 1 and 8 conditions")
	}
	for _, m := range ms {
		if (m.At == nil) == (m.Customer == "") {
			return errors.New("a condition takes at or customer")
		}
		if m.At != nil {
			switch m.At.From {
			case "req.body", "req.query", "req.headers", "req.path":
			default:
				return errors.New("a condition reads the request body, path, query or headers")
			}
			if err := validateRef(*m.At); err != nil {
				return err
			}
			if m.At.Field != "" || m.At.Owner || strings.Contains(m.At.Path, "[*]") {
				return errors.New("a condition reads one value outside arrays")
			}
		}
		if m.Customer != "" && (attrs == nil || !attrs[m.Customer]) {
			return fmt.Errorf("unknown customer attribute %q", m.Customer)
		}
		rng := m.Min != nil || m.Max != nil
		if (len(m.In) > 0) == rng || len(m.In) > 64 {
			return errors.New("a condition takes in (1 to 64 values) or min/max")
		}
		for _, v := range m.In {
			switch x := v.(type) {
			case string:
				if len(x) > 256 || strings.Contains(x, "${") {
					return errors.New("bad condition value")
				}
			case bool, float64, json.Number:
			default:
				return errors.New("condition values are scalars")
			}
		}
		if m.Min != nil && m.Max != nil && !(*m.Min < *m.Max) {
			return errors.New("condition min must be below max")
		}
	}
	return nil
}

// validateConditions checks cause.when.match and outcomes[].when.
func validateConditions(r *CausalRule, attrs map[string]bool) error {
	if r.Cause.When.Match != nil {
		if err := validateMatches(r.Cause.When.Match, attrs); err != nil {
			return fmt.Errorf("cause.when.match: %v", err)
		}
	}
	for _, o := range r.Outcomes {
		if o.When != nil {
			if err := validateMatches(o.When, attrs); err != nil {
				return fmt.Errorf("outcome %s: when: %v", o.Name, err)
			}
		}
	}
	return nil
}

func validateTargetAll(r *CausalRule, e *Effect) error {
	if e.Create != nil || e.Target != "" || e.TargetID != "" || e.TargetKey != nil {
		return errors.New("target_all excludes create, target, target_id and target_key")
	}
	if e.Remove == (e.Set != nil) {
		return errors.New("target_all takes set or remove")
	}
	if err := validateFieldValues(e.Set); err != nil {
		return err
	}
	if err := validateFieldValues(e.Where); err != nil {
		return err
	}
	for _, v := range e.Where {
		if s, ok := v.(string); ok && strings.Contains(s, "${") {
			return errors.New("where takes literal values only")
		}
	}
	for _, v := range e.Set {
		s, ok := v.(string)
		if !ok || !strings.Contains(s, "${") || notRefRE.MatchString(s) {
			continue
		}
		m := bindRefRE.FindStringSubmatch(s)
		if m == nil {
			return errors.New("target_all sets literals, ${var} or ${not:field}")
		}
		if _, ok := r.Cause.Bind[m[1]]; !ok {
			return fmt.Errorf("${%s} is not bound by the cause", m[1])
		}
	}
	return nil
}

func validateListFilters(fs []ListFilter) error {
	if len(fs) > 8 {
		return errors.New("too many filters")
	}
	for _, f := range fs {
		if f.Param.From != "req.query" || f.Param.Name == "" || len(f.Param.Name) > 64 || !fieldPathRE.MatchString(f.Field) {
			return errors.New("malformed filter")
		}
	}
	return nil
}

// respPoint checks a response member outside arrays of a pack operation.
func respPoint(service, op string, at Ref, services map[string]bool) error {
	if !services[service] {
		return fmt.Errorf("unknown service %q", service)
	}
	if !opRE.MatchString(op) || at.From != "resp.body" || at.Path == "$" || strings.Contains(at.Path, "[*]") {
		return errors.New("a response member outside arrays")
	}
	return validateRef(at)
}

func validateExtras(w *rulesWire, ents map[string]*Entity, services map[string]bool) error {
	names := map[string]bool{}
	for _, a := range w.Attributes {
		if !bindNameRE.MatchString(a.Name) || names[a.Name] {
			return fmt.Errorf("attribute %q: malformed or duplicate name", a.Name)
		}
		names[a.Name] = true
		if len(a.Values) < 2 || len(a.Values) > 64 || a.Subjects < 0 || len(a.Fields) == 0 || len(a.Fields) > 32 {
			return fmt.Errorf("attribute %q: 2 to 64 values and 1 to 32 fields", a.Name)
		}
		sum := 0.0
		for v, p := range a.Values {
			if v == "" || len(v) > 64 || p < 0 || p > 1 || math.IsNaN(p) {
				return fmt.Errorf("attribute %q: bad value", a.Name)
			}
			sum += p
		}
		if math.Abs(sum-1) > 0.001 {
			return fmt.Errorf("attribute %q: shares sum to %g", a.Name, sum)
		}
		for _, f := range a.Fields {
			if err := respPoint(f.Service, f.Op, f.At, services); err != nil {
				return fmt.Errorf("attribute %q: %v", a.Name, err)
			}
		}
	}
	for i, g := range w.Aggregates {
		if err := respPoint(g.Service, g.Op, g.At, services); err != nil {
			return fmt.Errorf("aggregate %d: %v", i, err)
		}
		n := 0
		where := map[string]any(nil)
		ent := ""
		if g.Count != nil {
			n++
			ent, where = g.Count.Entity, g.Count.Where
		}
		if g.Sum != nil {
			n++
			ent, where = g.Sum.Entity, g.Sum.Where
			if !fieldPathRE.MatchString(g.Sum.Field) {
				return fmt.Errorf("aggregate %d: malformed sum.field", i)
			}
		}
		if g.Delta != nil {
			n++
			if len(g.Delta) == 0 || len(g.Delta) > 8 {
				return fmt.Errorf("aggregate %d: 1 to 8 delta operations", i)
			}
			for _, d := range g.Delta {
				svc := d.Service
				if svc == "" {
					svc = g.Service
				}
				if !services[svc] || !opRE.MatchString(d.Op) || d.By == 0 || d.By < -1000 || d.By > 1000 {
					return fmt.Errorf("aggregate %d: bad delta", i)
				}
			}
		}
		if n != 1 || g.Subjects < 0 {
			return fmt.Errorf("aggregate %d: one of count, sum and delta", i)
		}
		if ent != "" && ents[ent] == nil {
			return fmt.Errorf("aggregate %d: unknown entity %q", i, ent)
		}
		if err := validateFieldValues(where); err != nil {
			return fmt.Errorf("aggregate %d: where: %v", i, err)
		}
		for _, v := range where {
			if s, ok := v.(string); ok && strings.Contains(s, "${") {
				return fmt.Errorf("aggregate %d: where takes literal values only", i)
			}
		}
	}
	for _, lo := range w.Lists {
		if !services[lo.Service] || !opRE.MatchString(lo.Op) || lo.At.From != "resp.body" || !isListPath(lo.At.Path) {
			return fmt.Errorf("list %s %s: unknown service or not an items path", lo.Service, lo.Op)
		}
		if err := validateRef(lo.At); err != nil {
			return fmt.Errorf("list %s %s: %v", lo.Service, lo.Op, err)
		}
		if err := validateListShape(&lo.List); err != nil {
			return fmt.Errorf("list %s %s: %v", lo.Service, lo.Op, err)
		}
		if err := validateListFilters(lo.List.Filters); err != nil {
			return fmt.Errorf("list %s %s: %v", lo.Service, lo.Op, err)
		}
	}
	return nil
}

// MatchValue reports whether a value (a scalar of the request or of the
// customer) satisfies a condition (docs/spec/rules.md 3.12): equal to one
// of In by canonical form, or a number in [Min, Max). A missing value
// never matches.
func MatchValue(m Match, v any, present bool) bool {
	if !present || v == nil {
		return false
	}
	if len(m.In) > 0 {
		cv := CanonScalar(v)
		for _, x := range m.In {
			if CanonScalar(x) == cv {
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

// CanonScalar is the canonical string of a scalar: a number (also a string
// that is one) in its shortest decimal form, booleans true or false,
// other strings as they are.
func CanonScalar(v any) string {
	if _, isBool := v.(bool); !isBool {
		if f, ok := scalarFloat(v); ok {
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
