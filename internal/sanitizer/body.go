package sanitizer

import (
	"bytes"
	"sort"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// errInvalidJSON makes the whole body trunc:invalid-json.
var errInvalidJSON = ttjson.ErrSyntax

// jsonBody sanitizes a JSON body (section 9.2). It returns errInvalidJSON
// for anything that is not RFC 8259 JSON in valid UTF-8.
func (r *run) jsonBody(d []byte, rs *ruleSet, discPrefix string) (ttjson.Value, error) {
	if !utf8.Valid(d) {
		return ttjson.Value{}, errInvalidJSON
	}
	b := bodyRun{r: r, d: d, rules: rs.body}
	cands := r.arena[:0]
	for i := range rs.body {
		cands = append(cands, int32(i))
	}
	r.arena = cands
	v, end, err := b.value(ttjson.SkipWS(d, 0), 1, cands, discPrefix)
	if err != nil {
		return ttjson.Value{}, err
	}
	if ttjson.SkipWS(d, end) != len(d) {
		return ttjson.Value{}, errInvalidJSON
	}
	return v, nil
}

type bodyRun struct {
	r     *run
	d     []byte
	rules []cRule
}

// winner returns the action of the first candidate rule whose length equals
// the current number of steps (depth-1).
func (b *bodyRun) winner(cands []int32, depth int) *policy.Action {
	for _, ci := range cands {
		if len(b.rules[ci].steps) == depth-1 {
			return b.rules[ci].act
		}
	}
	return nil
}

// containerDrop implements the container rule of section 5.0: keep, hmac
// and bucket rules on a container are ignored; the first explicit drop
// matching the container (precedence order), found in group g, collapses it
// only if no rule of groups up to g can reach a descendant.
func (b *bodyRun) containerDrop(cands []int32, depth int) bool {
	level := depth - 1
	g := -1
	for _, ci := range cands {
		r := &b.rules[ci]
		if len(r.steps) == level && r.act.Kind == policy.ActDrop {
			g = r.group
			break
		}
	}
	if g < 0 {
		return false
	}
	for _, ci := range cands {
		r := &b.rules[ci]
		if r.group <= g && len(r.steps) > level {
			return false
		}
	}
	return true
}

// filter returns the candidates whose step at index level matches.
func (b *bodyRun) filter(cands []int32, level int, key []byte, isElem bool) []int32 {
	if len(cands) == 0 {
		return nil
	}
	start := len(b.r.arena)
	for _, ci := range cands {
		st := b.rules[ci].steps
		if len(st) <= level {
			continue
		}
		s := st[level]
		switch {
		case isElem && s.Kind == policy.StepAnyElem,
			!isElem && s.Kind == policy.StepAnyMember,
			!isElem && s.Kind == policy.StepName && s.Name == string(key):
			b.r.arena = append(b.r.arena, ci)
		}
	}
	return b.r.arena[start:len(b.r.arena):len(b.r.arena)]
}

func (b *bodyRun) value(i, depth int, cands []int32, path string) (ttjson.Value, int, error) {
	d := b.d
	if i >= len(d) {
		return ttjson.Value{}, 0, errInvalidJSON
	}
	c := d[i]
	if c == '{' || c == '[' {
		if depth > b.r.lim.MaxDepth {
			end, _, err := ttjson.SkipValue(d, i, nil)
			if err != nil {
				return ttjson.Value{}, 0, err
			}
			return tokTruncDepth, end, nil
		}
		if b.containerDrop(cands, depth) {
			return b.collapse(i)
		}
		if c == '{' {
			return b.object(i, depth, cands, path)
		}
		return b.array(i, depth, cands, path)
	}
	var l leaf
	var end int
	var err error
	switch {
	case c == '"':
		var s []byte
		end, s, l.lone, err = ttjson.ScanString(d, i, nil)
		l.kind, l.s = leafStr, s
	case c == 't' || c == 'f' || c == 'n':
		end, err = ttjson.ScanLiteral(d, i)
		switch c {
		case 't':
			l.kind, l.b = leafBool, true
		case 'f':
			l.kind = leafBool
		default:
			l.kind = leafNull
		}
	default:
		end, l.isInt, err = ttjson.ScanNumber(d, i)
		if err == nil {
			l.kind, l.s = leafNum, d[i:end]
		}
	}
	if err != nil {
		return ttjson.Value{}, 0, err
	}
	out, def := b.r.applyLeaf(&l, b.winner(cands, depth))
	if def {
		b.r.addDisc(path, &l)
	}
	return out, end, nil
}

// collapse validates and skips a container that has an explicit drop and
// returns drop:obj:<class> (distinct keys) or drop:arr:<class> (elements).
func (b *bodyRun) collapse(i int) (ttjson.Value, int, error) {
	if b.d[i] == '[' {
		end, n, err := ttjson.SkipValue(b.d, i, nil)
		if err != nil {
			return ttjson.Value{}, 0, err
		}
		return ttjson.Str("drop:arr:" + LenClass(int64(n))), end, nil
	}
	seen := map[string]struct{}{}
	end, _, err := ttjson.SkipValue(b.d, i, func(k []byte, _ bool) { seen[string(k)] = struct{}{} })
	if err != nil {
		return ttjson.Value{}, 0, err
	}
	return ttjson.Str("drop:obj:" + LenClass(int64(len(seen)))), end, nil
}

type objMember struct {
	key       string // decoded key (generalized UTF-8 when lone)
	literal   bool
	val       ttjson.Value
	pos       int // position of the last occurrence
	discStart int
	discEnd   int
}

func (b *bodyRun) object(i, depth int, cands []int32, path string) (ttjson.Value, int, error) {
	d := b.d
	r := b.r
	var members []objMember
	var index map[string]int
	i = ttjson.SkipWS(d, i+1)
	if i < len(d) && d[i] == '}' {
		return ttjson.Obj(), i + 1, nil
	}
	arenaMark := len(r.arena)
	for pos := 0; ; pos++ {
		end, k, lone, err := ttjson.ScanString(d, i, r.keyBuf)
		if err != nil {
			return ttjson.Value{}, 0, err
		}
		key := string(k)
		literal := !lone && IsLiteralKey(k)
		i = ttjson.SkipWS(d, end)
		if i >= len(d) || d[i] != ':' {
			return ttjson.Value{}, 0, errInvalidJSON
		}
		childPath := ""
		if r.discOn {
			if literal {
				childPath = path + "." + key
			} else {
				childPath = path + ".*"
			}
		}
		childCands := b.filter(cands, depth-1, k, false)
		discStart := len(r.disc)
		v, end2, err := b.value(ttjson.SkipWS(d, i+1), depth+1, childCands, childPath)
		if err != nil {
			return ttjson.Value{}, 0, err
		}
		r.arena = r.arena[:arenaMark]
		m := objMember{key: key, literal: literal, val: v, pos: pos, discStart: discStart, discEnd: len(r.disc)}
		// Duplicate keys: the last occurrence wins, at its own position.
		dup := -1
		if index != nil {
			if j, ok := index[key]; ok {
				dup = j
			}
		} else {
			for j := range members {
				if members[j].key == key {
					dup = j
					break
				}
			}
		}
		if dup >= 0 {
			r.killDisc(members[dup].discStart, members[dup].discEnd)
			members[dup] = m
		} else {
			members = append(members, m)
			if index != nil {
				index[key] = len(members) - 1
			} else if len(members) > 16 {
				index = make(map[string]int, len(members)*2)
				for j := range members {
					index[members[j].key] = j
				}
			}
		}
		i = ttjson.SkipWS(d, end2)
		if i >= len(d) {
			return ttjson.Value{}, 0, errInvalidJSON
		}
		if d[i] == '}' {
			i++
			break
		}
		if d[i] != ',' {
			return ttjson.Value{}, 0, errInvalidJSON
		}
		i = ttjson.SkipWS(d, i+1)
	}
	return b.finishObject(members), i, nil
}

// finishObject applies max_keys truncation and dynamic key collapse
// (sections 6.4, 9.3) and builds the output object.
func (b *bodyRun) finishObject(members []objMember) ttjson.Value {
	r := b.r
	total := len(members)
	truncated := false
	if total > r.lim.MaxKeys {
		// Deduplicated order is the order of last occurrences.
		sort.SliceStable(members, func(x, y int) bool { return members[x].pos < members[y].pos })
		for _, m := range members[r.lim.MaxKeys:] {
			r.killDisc(m.discStart, m.discEnd)
		}
		members = members[:r.lim.MaxKeys]
		truncated = true
	}
	return assembleObject(members, total, truncated)
}

// assembleObject builds an output object from the kept members: literal
// keys as they are, dynamic keys collapsed under {*} (section 9.3 point 4),
// {trunc} when truncated (total is the number of distinct keys).
func assembleObject(members []objMember, total int, truncated bool) ttjson.Value {
	out := ttjson.Value{Kind: ttjson.Object, Obj: make([]ttjson.Member, 0, len(members)+1)}
	var dyn []*objMember
	for idx := range members {
		m := &members[idx]
		if m.literal {
			out.Obj = append(out.Obj, ttjson.Member{Key: m.key, Value: m.val})
		} else {
			dyn = append(dyn, m)
		}
	}
	if len(dyn) > 0 {
		// Collapsed values are ordered by the bytes of their canonical form
		// (section 9.3 point 4), so the order reveals nothing of the keys.
		type enc struct {
			b []byte
			v ttjson.Value
		}
		es := make([]enc, len(dyn))
		for idx, m := range dyn {
			eb, _ := ttjson.Encode(m.val)
			es[idx] = enc{eb, m.val}
		}
		sort.SliceStable(es, func(x, y int) bool { return bytes.Compare(es[x].b, es[y].b) < 0 })
		arr := make([]ttjson.Value, len(es))
		for idx := range es {
			arr[idx] = es[idx].v
		}
		out.Obj = append(out.Obj, ttjson.Member{Key: "{*}", Value: ttjson.Arr(arr...)})
	}
	if truncated {
		out.Obj = append(out.Obj, ttjson.Member{Key: "{trunc}", Value: ttjson.Str("trunc:keys:" + LenClass(int64(total)))})
	}
	return out
}

// arrayCap returns how many elements an array keeps: max_array, or in
// large-body mode (section 22.5) bodies.large_array for an array without
// array ancestors and bodies.large_nested_array for one with.
func (r *run) arrayCap() int {
	switch {
	case !r.large:
		return r.lim.MaxArray
	case r.arrLevel == 0:
		return r.bodies.LargeArray
	}
	return r.bodies.LargeNestedArray
}

func (r *run) killDisc(start, end int) {
	for k := start; k < end && k < len(r.disc); k++ {
		r.disc[k].dead = true
	}
}

func (b *bodyRun) array(i, depth int, cands []int32, path string) (ttjson.Value, int, error) {
	d := b.d
	r := b.r
	i = ttjson.SkipWS(d, i+1)
	out := ttjson.Value{Kind: ttjson.Array, Arr: []ttjson.Value{}}
	if i < len(d) && d[i] == ']' {
		return out, i + 1, nil
	}
	childPath := ""
	if r.discOn {
		childPath = path + "[*]"
	}
	arenaMark := len(r.arena)
	childCands := b.filter(cands, depth-1, nil, true)
	limit := r.arrayCap()
	r.arrLevel++
	defer func() { r.arrLevel-- }()
	n := 0
	for {
		var end int
		var err error
		if n < limit {
			var v ttjson.Value
			v, end, err = b.value(i, depth+1, childCands, childPath)
			if err == nil {
				out.Arr = append(out.Arr, v)
			}
		} else {
			end, _, err = ttjson.SkipValue(d, i, nil)
		}
		if err != nil {
			return ttjson.Value{}, 0, err
		}
		n++
		i = ttjson.SkipWS(d, end)
		if i >= len(d) {
			return ttjson.Value{}, 0, errInvalidJSON
		}
		if d[i] == ']' {
			i++
			break
		}
		if d[i] != ',' {
			return ttjson.Value{}, 0, errInvalidJSON
		}
		i = ttjson.SkipWS(d, i+1)
	}
	r.arena = r.arena[:arenaMark]
	if n > limit {
		out.Arr = append(out.Arr, ttjson.Str("trunc:n:"+LenClass(int64(n))))
	}
	return out, i, nil
}
