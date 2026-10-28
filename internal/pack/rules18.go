package pack

import (
	"errors"
	"fmt"
	"strings"
)

// Rules v1.8 (docs/spec/rules.md 3.8 and 3.9): effects on keyed records
// (target_key) and counters per key on response effects (respond.limit).

// validateTargetKey checks target_key: the entity is keyed and every key
// field gets a bound "${var}" or a literal.
func validateTargetKey(r *CausalRule, e *Effect, ents map[string]*Entity) error {
	if e.Create != nil || e.Target != "" || e.TargetID != "" {
		return errors.New("target_key excludes create, target and target_id")
	}
	ent := ents[e.Entity]
	if ent == nil || ent.Key == nil {
		return errors.New("target_key needs a keyed entity")
	}
	tk := *e.TargetKey
	if len(tk) != len(ent.Key.Fields) {
		return fmt.Errorf("target_key must give every key field of %s", ent.Name)
	}
	for _, f := range ent.Key.Fields {
		v, ok := tk[f]
		if !ok {
			return fmt.Errorf("target_key misses key field %q", f)
		}
		if len(v) > 256 {
			return fmt.Errorf("target_key %q is too long", f)
		}
		if m := bindRefRE.FindStringSubmatch(v); m != nil {
			if _, ok := r.Cause.Bind[m[1]]; !ok {
				return fmt.Errorf("target_key %q: ${%s} is not bound by the cause", f, m[1])
			}
		} else if strings.Contains(v, "${") {
			return fmt.Errorf("target_key %q: a reference must be the whole string ${var}", f)
		}
	}
	return nil
}

// validateLimit checks the counter of a response effect.
func validateLimit(r *CausalRule, rs *Respond) error {
	lm := rs.Limit
	if lm == nil {
		return nil
	}
	if lm.N < 1 || lm.N > 100000 {
		return errors.New("limit.n out of range")
	}
	if lm.Window != "" {
		d, err := ParseDuration(lm.Window)
		if err != nil || d <= 0 {
			return errors.New("limit.window must be a positive duration")
		}
	}
	if rs.Times != 0 {
		return errors.New("limit excludes times")
	}
	if lm.Key == "" {
		return nil
	}
	m := bindRefRE.FindStringSubmatch(lm.Key)
	if m == nil {
		return errors.New("limit.key must be ${variable}")
	}
	ref, ok := r.Cause.Bind[m[1]]
	if !ok {
		return fmt.Errorf("limit.key: ${%s} is not bound by the cause", m[1])
	}
	if !strings.HasPrefix(ref.From, "req.") {
		return errors.New("limit.key must be bound to the request")
	}
	if rs.Service != r.Cause.Service || rs.Op != r.Cause.Op {
		return errors.New("a limit with a key answers the operation of the cause")
	}
	return nil
}
