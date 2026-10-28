package miner

import (
	"sort"
	"strconv"
	"strings"
)

// List parameters (rules v1.9, rules.md 2.3 and 2.13, C12), learned from
// clear request values and the shape of the answers, never from values of
// the items: a limit (the length never exceeds the value and reaches it on
// full pages), a default limit, a page or an offset (the next page has
// other objects), the order of the items (an item time bucket monotone in
// every list), filters (a clear query code equal to a field of every item).
// They go in read_by.list of the entities, or in the top-level `lists` for
// list operations that no entity reads (the mock pages their static
// answer).

type listEv struct {
	ev    int32
	subj  int32
	n     int
	items []*record
	ids   map[int32]bool
}

// mineListShape learns the parameters of the list at items (a tt-path
// ending with [*]) of op; ent is the entity of the items (-1: none).
func (m *miner) mineListShape(op int32, items string, ent int) (ListShape, bool) {
	l, cfg := m.l, m.cfg
	arr := strings.TrimSuffix(items, "[*]")
	var evs []listEv
	for _, i := range m.opEvents(op) {
		ev := &l.evs[i]
		if !ev.ok() {
			continue
		}
		n := -1
		for _, a := range ev.arrays {
			if a.path == arr {
				n = a.n
			}
		}
		if n < 0 {
			continue
		}
		le := listEv{ev: i, subj: l.subjectOf(i), n: n, ids: map[int32]bool{}}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			if r.side != sideResp || r.path != items {
				continue
			}
			if ent >= 0 {
				e, own, ok := m.recEntity(r)
				if !ok || e != ent {
					continue
				}
				le.ids[own.tok] = true
			} else {
				for _, f := range r.ids {
					le.ids[f.tok] = true
				}
			}
			le.items = append(le.items, r)
		}
		evs = append(evs, le)
	}
	var sh ListShape
	if len(evs) < cfg.KMin {
		return sh, false
	}
	ints := map[string]map[int32]int{} // query name → event → integer value
	codes := map[string]map[int32]string{}
	for _, le := range evs {
		for _, a := range l.reqClear(le.ev) {
			if !strings.HasPrefix(a.name, "?") {
				continue
			}
			name := a.name[1:]
			if a.val.Kind == 's' || a.val.Kind == 'n' {
				if v, err := strconv.Atoi(a.val.S); err == nil && v >= 0 {
					if ints[name] == nil {
						ints[name] = map[int32]int{}
					}
					ints[name][le.ev] = v
					continue
				}
			}
			if a.val.Kind == 's' || a.val.Kind == 'b' {
				if codes[name] == nil {
					codes[name] = map[int32]string{}
				}
				codes[name][le.ev] = a.val.S
			}
		}
	}
	learned := false
	// Limit: the length never exceeds the value, reaches it on full pages.
	limit, bestFull := "", 0
	for _, q := range sortedKeys(ints) {
		vals := ints[q]
		over, full := 0, map[int32]bool{}
		with := map[int32]bool{}
		for _, le := range evs {
			v, ok := vals[le.ev]
			if !ok {
				continue
			}
			with[le.subj] = true
			if le.n > v {
				over++
			}
			if le.n == v && v > 0 && le.subj >= 0 {
				full[le.subj] = true
			}
		}
		if len(with) < cfg.KMin || len(full) < cfg.KMin || float64(over) > 0.01*float64(len(vals)) {
			continue
		}
		if len(full) > bestFull {
			limit, bestFull = q, len(full)
		}
	}
	if limit != "" {
		sh.Limit = &NameRef{From: "req.query", Name: limit}
		learned = true
		// Default limit: without the parameter the lists stop at one of its
		// values, reached for k users.
		seen := map[int]bool{}
		for _, v := range ints[limit] {
			seen[v] = true
		}
		max, full := 0, map[int32]bool{}
		for _, le := range evs {
			if _, ok := ints[limit][le.ev]; !ok && le.n > max {
				max = le.n
			}
		}
		for _, le := range evs {
			if _, ok := ints[limit][le.ev]; !ok && le.n == max && le.subj >= 0 {
				full[le.subj] = true
			}
		}
		if max >= 2 && max <= 1000 && seen[max] && len(full) >= cfg.KMin {
			sh.DefaultLimit = max
		}
	}
	// Page or offset: another integer parameter whose least value is 1 (a
	// page) or 0 (an offset), and whose higher values give other objects
	// than the user's previous first page.
	var pager string
	pagerMin := -1
	for _, q := range sortedKeys(ints) {
		if q == limit {
			continue
		}
		vals := ints[q]
		lo := -1
		for _, v := range vals {
			if lo < 0 || v < lo {
				lo = v
			}
		}
		if lo != 0 && lo != 1 {
			continue
		}
		pairs, disjoint := 0, 0
		users := map[int32]bool{}
		later := map[int32]bool{}
		last := map[int32]*listEv{} // subject → last first page
		for k := range evs {
			le := &evs[k]
			v, ok := vals[le.ev]
			if !ok {
				v = lo
			}
			if le.subj < 0 {
				continue
			}
			if v == lo {
				last[le.subj] = le
				continue
			}
			later[le.subj] = true
			first := last[le.subj]
			if first == nil || len(le.ids) == 0 || len(first.ids) == 0 {
				continue
			}
			pairs++
			dis := true
			for t := range le.ids {
				if first.ids[t] {
					dis = false
					break
				}
			}
			if dis {
				disjoint++
				users[le.subj] = true
			}
		}
		ok := pairs > 0 && float64(disjoint) >= cfg.MinShare*float64(pairs) && len(users) >= cfg.KMin
		if pairs == 0 && limit != "" && len(later) >= cfg.KMin {
			ok = true // items without identifiers: the limit and the later pages say it
		}
		if ok && pager == "" {
			pager, pagerMin = q, lo
		}
	}
	if pager != "" {
		if pagerMin == 1 {
			sh.Page = &NameRef{From: "req.query", Name: pager}
		} else {
			sh.Offset = &NameRef{From: "req.query", Name: pager}
		}
		learned = true
	}
	if f, ord := m.listOrder(evs); f != "" {
		sh.OrderBy, sh.Order = f, ord
		learned = true
	}
	if fs := m.listFilters(evs, codes, limit, pager); len(fs) > 0 {
		sh.Filters = fs
		learned = true
	}
	return sh, learned
}

// listOrder finds an item field whose time buckets are monotone in the
// lists: ascending or descending in at least min_share of the lists that
// show two distinct values, for k users.
func (m *miner) listOrder(evs []listEv) (string, string) {
	cfg := m.cfg
	type tally struct {
		asc, desc, mixed int
		ascU, descU      map[int32]bool
	}
	ts := map[string]*tally{}
	for _, le := range evs {
		if len(le.items) < 2 {
			continue
		}
		var fields []string
		for _, a := range le.items[0].times {
			if a.val.Kind == 's' && reFieldName.MatchString(a.name) {
				fields = append(fields, a.name)
			}
		}
		for _, f := range fields {
			up, down, ok := false, false, true
			prev := ""
			for k, r := range le.items {
				t, has := r.time(f)
				if !has {
					ok = false
					break
				}
				if k > 0 {
					switch {
					case t > prev:
						up = true
					case t < prev:
						down = true
					}
				}
				prev = t
			}
			if !ok || (!up && !down) {
				continue
			}
			t := ts[f]
			if t == nil {
				t = &tally{ascU: map[int32]bool{}, descU: map[int32]bool{}}
				ts[f] = t
			}
			switch {
			case up && down:
				t.mixed++
			case up:
				t.asc++
				if le.subj >= 0 {
					t.ascU[le.subj] = true
				}
			default:
				t.desc++
				if le.subj >= 0 {
					t.descU[le.subj] = true
				}
			}
		}
	}
	bestF, bestO, bestN := "", "", 0
	for _, f := range sortedKeys(ts) {
		t := ts[f]
		all := float64(t.asc + t.desc + t.mixed)
		switch {
		case float64(t.asc) >= cfg.MinShare*all && len(t.ascU) >= cfg.KMin && t.asc > bestN:
			bestF, bestO, bestN = f, "asc", t.asc
		case float64(t.desc) >= cfg.MinShare*all && len(t.descU) >= cfg.KMin && t.desc > bestN:
			bestF, bestO, bestN = f, "desc", t.desc
		}
	}
	return bestF, bestO
}

// listFilters finds the clear query codes equal to a field of every item:
// in min_share of the lists that carry the parameter and have items, for k
// users, with at least two values.
func (m *miner) listFilters(evs []listEv, codes map[string]map[int32]string, skip ...string) []ListFilter {
	cfg := m.cfg
	var out []ListFilter
	for _, q := range sortedKeys(codes) {
		if slicesContains(skip, q) || !reName.MatchString(q) {
			continue
		}
		vals := codes[q]
		comparable, users := 0, map[int32]bool{}
		match := map[string]int{}
		matchU := map[string]map[int32]bool{}
		matchV := map[string]map[string]bool{}
		for _, le := range evs {
			v, ok := vals[le.ev]
			if !ok || len(le.items) == 0 {
				continue
			}
			comparable++
			if le.subj >= 0 {
				users[le.subj] = true
			}
			for _, a := range le.items[0].attrs {
				if (a.val.Kind != 's' && a.val.Kind != 'b') || a.val.S != v || !reFieldName.MatchString(a.name) {
					continue
				}
				all := true
				for _, r := range le.items[1:] {
					if w, ok := r.attr(a.name); !ok || w.S != v {
						all = false
						break
					}
				}
				if !all {
					continue
				}
				match[a.name]++
				if matchU[a.name] == nil {
					matchU[a.name], matchV[a.name] = map[int32]bool{}, map[string]bool{}
				}
				if le.subj >= 0 {
					matchU[a.name][le.subj] = true
				}
				matchV[a.name][v] = true
			}
		}
		if len(users) < cfg.KMin {
			continue
		}
		best, bn := "", 0
		for _, f := range sortedKeys(match) {
			n := match[f]
			if float64(n) < cfg.MinShare*float64(comparable) || len(matchU[f]) < cfg.KMin || len(matchV[f]) < 2 {
				continue
			}
			if n > bn || (n == bn && f == q) {
				best, bn = f, n
			}
		}
		if best != "" && len(out) < maxListFilters {
			out = append(out, ListFilter{Param: NameRef{From: "req.query", Name: q}, Field: best})
		}
	}
	return out
}

// mineLists fills the list parameters of the entities' list reads and
// returns the list operations that no entity reads.
func (m *miner) mineLists() []ListOp {
	l := m.l
	covered := map[[2]string]bool{} // "service op", items path
	for i, e := range m.ents {
		for k := range e.def.ReadBy {
			rb := &e.def.ReadBy[k]
			if !strings.HasSuffix(rb.At.Path, "[*]") {
				continue
			}
			svc := rb.Service
			if svc == "" {
				svc = e.def.Service
			}
			covered[[2]string{svc + " " + rb.Op, rb.At.Path}] = true
			op, ok := l.opIdx[[2]string{svc, rb.Op}]
			if !ok {
				continue
			}
			sh, learned := m.mineListShape(op, rb.At.Path, i)
			if !learned {
				continue
			}
			if rb.List == nil {
				rb.List = &ListShape{}
			}
			rb.List.Limit, rb.List.Page, rb.List.Offset = sh.Limit, sh.Page, sh.Offset
			rb.List.DefaultLimit, rb.List.OrderBy, rb.List.Order, rb.List.Filters = sh.DefaultLimit, sh.OrderBy, sh.Order, sh.Filters
		}
	}
	// List operations no entity reads: top-level arrays of read answers.
	type arrKey struct {
		op   int32
		path string
	}
	users := map[arrKey]map[int32]bool{}
	for i := range l.evs {
		ev := &l.evs[i]
		if !ev.ok() || !l.ops[ev.op].read {
			continue
		}
		s := l.subjectOf(int32(i))
		for _, a := range ev.arrays {
			if strings.Contains(a.path, "[*]") || !reTTPath.MatchString(a.path+"[*]") {
				continue
			}
			k := arrKey{ev.op, a.path}
			if users[k] == nil {
				users[k] = map[int32]bool{}
			}
			if s >= 0 {
				users[k][s] = true
			}
		}
	}
	keys := make([]arrKey, 0, len(users))
	for k, us := range users {
		if len(us) >= m.cfg.KMin {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(a, b int) bool {
		oa, ob := l.ops[keys[a].op], l.ops[keys[b].op]
		if oa.service+" "+oa.op != ob.service+" "+ob.op {
			return oa.service+" "+oa.op < ob.service+" "+ob.op
		}
		return keys[a].path < keys[b].path
	})
	var out []ListOp
	for _, k := range keys {
		o := l.ops[k.op]
		items := k.path + "[*]"
		if covered[[2]string{o.service + " " + o.op, items}] {
			continue
		}
		sh, learned := m.mineListShape(k.op, items, -1)
		if !learned || len(out) >= maxDocLists {
			continue
		}
		out = append(out, ListOp{Service: o.service, Op: o.op, At: Ref{From: "resp.body", Path: items}, List: sh})
	}
	return out
}
