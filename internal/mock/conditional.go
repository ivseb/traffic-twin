package mock

// whenOf reads x-tt-when of a property schema: the sibling it depends on and
// the values that switch it on.
func whenOf(s map[string]any) (string, []string, bool) {
	w, _ := s["x-tt-when"].(map[string]any)
	if len(w) != 1 {
		return "", nil, false
	}
	for disc, raw := range w {
		list, _ := raw.([]any)
		var vals []string
		for _, v := range list {
			if sv, ok := v.(string); ok {
				vals = append(vals, sv)
			}
		}
		return disc, vals, len(vals) > 0
	}
	return "", nil, false
}

func containsString(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// pickEnum chooses a value of the schema's enum (or x-tt-value enum),
// deterministically per request key and property.
func (b *builder) pickEnum(s map[string]any, name string) (any, bool) {
	en, _ := s["enum"].([]any)
	if len(en) == 0 {
		if xv, ok := s["x-tt-value"].(map[string]any); ok {
			en, _ = xv["enum"].([]any)
		}
	}
	if len(en) == 0 {
		return nil, false
	}
	return cloneJSON(en[b.hashN(name, uint64(len(en)))]), true
}
