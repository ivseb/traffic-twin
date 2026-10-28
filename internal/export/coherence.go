package export

import "strings"

// shareHiddenWhen gives a read the hidden_when of a sibling read that
// locates the entity through the same field (see the miner and the mock):
// visibility belongs to the entity state and to how it is selected. The
// input is not modified.
func shareHiddenWhen(in []ReadBy) []ReadBy {
	out := make([]ReadBy, len(in))
	copy(out, in)
	for i := range out {
		by := out[i].By
		if out[i].HiddenWhen != nil || by == nil || by.Owner || by.Field == "" {
			continue
		}
		for j := range in {
			if in[j].HiddenWhen != nil && in[j].By != nil && !in[j].By.Owner && in[j].By.Field == by.Field {
				out[i].HiddenWhen = in[j].HiddenWhen
				break
			}
		}
	}
	return out
}

// schemaAtPath follows a tt path ("$", "$.items[*]") from the schema of the
// success response; nil when the path leaves the declared schema.
func (o *operation) schemaAtPath(at string) map[string]any {
	r := o.successResponse()
	if r == nil {
		return nil
	}
	cur := o.resolve(r.Schema)
	p := strings.TrimPrefix(strings.TrimPrefix(at, "$"), ".")
	if p == "" {
		return cur
	}
	for _, seg := range strings.Split(p, ".") {
		arr := strings.HasSuffix(seg, "[*]")
		seg = strings.TrimSuffix(seg, "[*]")
		if seg != "" {
			cur = o.resolve(asMap(asMap(cur["properties"])[seg]))
		}
		if arr {
			cur = o.resolve(asMap(cur["items"]))
		}
		if cur == nil {
			return nil
		}
	}
	return cur
}

// coherent returns the entity states with their conditional properties
// (x-tt-when) in line with the state: a CANCELLED shipment carries
// cancelReason, a shipment in any other state does not. States are copied,
// never modified.
func (o *operation) coherent(at Ref, items []map[string]any) []map[string]any {
	sch := o.schemaAtPath(at.Path)
	props := asMap(sch["properties"])
	if len(props) == 0 {
		return items
	}
	type cond struct {
		name, disc string
		in         []string
		first      any
	}
	var conds []cond
	for _, name := range sortedKeys(props) {
		ps := o.resolve(asMap(props[name]))
		when := asMap(ps["x-tt-when"])
		if len(when) != 1 {
			continue
		}
		for disc, raw := range when {
			c := cond{name: name, disc: disc}
			for _, v := range asSlice(raw) {
				if sv, ok := v.(string); ok {
					c.in = append(c.in, sv)
				}
			}
			if en := asSlice(ps["enum"]); len(en) > 0 {
				c.first = en[0]
			} else if en := asSlice(asMap(ps["x-tt-value"])["enum"]); len(en) > 0 {
				c.first = en[0]
			}
			if len(c.in) > 0 {
				conds = append(conds, c)
			}
		}
	}
	if len(conds) == 0 {
		return items
	}
	out := make([]map[string]any, len(items))
	for i, it := range items {
		cp := make(map[string]any, len(it)+1)
		for k, v := range it {
			cp[k] = v
		}
		for _, c := range conds {
			dv, _ := cp[c.disc].(string)
			want := false
			for _, v := range c.in {
				want = want || v == dv
			}
			_, has := cp[c.name]
			switch {
			case want && !has && c.first != nil:
				cp[c.name] = c.first
			case !want && has:
				delete(cp, c.name)
			}
		}
		out[i] = cp
	}
	return out
}
