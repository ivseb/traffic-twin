package miner

import (
	"errors"
	"fmt"
	"strings"
)

// Rules v1.8 (docs/spec/rules.md 3.8 and 3.9): effects on keyed records
// (target_key) and counters per key on response effects (respond.limit).

// validTargetKey checks target_key: every key field of the keyed entity,
// with a bound "${var}" or a literal (nil ents skips the entity checks).
func (c *CausalRule) validTargetKey(e Effect, ents map[string]*Entity) error {
	tk := *e.TargetKey
	if e.Create != nil || e.Target != "" || e.TargetID != "" {
		return errors.New("target_key excludes create, target and target_id")
	}
	if len(tk) > 8 {
		return errors.New("too many target_key fields")
	}
	for f, v := range tk {
		if !reFieldName.MatchString(f) || len(v) > 256 {
			return fmt.Errorf("bad target_key field %q", f)
		}
		if reBindRef.MatchString(v) {
			if _, ok := c.Cause.Bind[v[2:len(v)-1]]; !ok {
				return fmt.Errorf("target_key %q of unbound variable", f)
			}
		} else if strings.Contains(v, "${") {
			return fmt.Errorf("target_key %q: a reference must be the whole string ${var}", f)
		}
	}
	if ents == nil {
		return nil
	}
	ent := ents[e.Entity]
	if ent == nil || ent.Key == nil {
		return errors.New("target_key needs a keyed entity")
	}
	if len(tk) != len(ent.Key.Fields) {
		return fmt.Errorf("target_key must give every key field of %s", ent.Name)
	}
	for _, f := range ent.Key.Fields {
		if _, ok := tk[f]; !ok {
			return fmt.Errorf("target_key misses key field %q", f)
		}
	}
	return nil
}

// validLimit checks the counter of a response effect: n at least 1, a
// duration window, a key bound to the request of the cause, and with a key
// the operation of the cause (the key is read from the calls it counts and
// from the calls it answers).
func (c *CausalRule) validLimit(r *Respond) error {
	lm := r.Limit
	if lm == nil {
		return nil
	}
	if lm.N < 1 || lm.N > 100000 {
		return errors.New("bad limit.n")
	}
	if lm.Window != "" && (!reDuration.MatchString(lm.Window) || parseDuration(lm.Window) == 0) {
		return errors.New("bad limit.window")
	}
	if r.Times != 0 {
		return errors.New("limit excludes times")
	}
	if lm.Key == "" {
		return nil
	}
	if !reBindRef.MatchString(lm.Key) {
		return errors.New("limit.key must be ${variable}")
	}
	ref, ok := c.Cause.Bind[lm.Key[2:len(lm.Key)-1]]
	if !ok {
		return errors.New("limit.key of unbound variable")
	}
	if !strings.HasPrefix(ref.From, "req.") {
		return errors.New("limit.key must be bound to the request")
	}
	if r.Service != c.Cause.Service || r.Op != c.Cause.Op {
		return errors.New("a limit with a key answers the operation of the cause")
	}
	return nil
}
