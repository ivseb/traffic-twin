package miner

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Conditional outcomes (rules v1.9, rules.md 3.12, C6): the outcome of a
// creation may depend on a clear value of the request (a code of the body,
// a query parameter, a header, a number bucket) or on an attribute of the
// customer. A source is a condition when the outcome distribution differs
// by its value (chi-square test of independence, p below 0.01 divided by
// the number of sources tried); the values seen for at least k_min users
// get outcomes of their own with `when`, the other values keep the
// unconditional outcomes. Masked values (tokens, shapes) never give a
// condition.

// decidedCause is a cause with a decided outcome group.
type decidedCause struct {
	ev int32
	gk string
}

// condSignificance is the significance level of the test, before the
// correction for the number of sources.
const condSignificance = 0.01

// maxCondValues bounds the distinct values of a source (above, the value
// identifies more than it classifies).
const maxCondValues = 64

type condValue struct {
	key   string // canonical value or number bucket
	match Match
	label string
}

type condSource struct {
	name   string
	ref    *Ref
	cust   string
	values map[string]*condValue
	of     []string // per cause: value key, "" absent
}

// conditionOutcomes splits the outcomes of rule by the most significant
// source, when one is significant; otherwise the rule is left unchanged.
// outName maps the outcome groups to the names of rule.Outcomes.
func (m *miner) conditionOutcomes(rule *CausalRule, causes []decidedCause, outName map[string]string) {
	if len(rule.Outcomes) < 2 {
		return
	}
	l, k := m.l, m.cfg.KMin
	var evs []int32
	var outs []string
	for _, c := range causes {
		if n, ok := outName[c.gk]; ok {
			evs = append(evs, c.ev)
			outs = append(outs, n)
		}
	}
	if len(evs) < 2*k {
		return
	}
	subj := make([]int32, len(evs))
	for i, ev := range evs {
		subj[i] = l.subjectOf(ev)
	}
	srcs := map[string]*condSource{}
	var order []string
	get := func(name string) *condSource {
		s := srcs[name]
		if s == nil {
			s = &condSource{name: name, values: map[string]*condValue{}, of: make([]string, len(evs))}
			srcs[name] = s
			order = append(order, name)
		}
		return s
	}
	for i, ev := range evs {
		for _, a := range l.reqClear(ev) {
			ref, ok := refOfReqVal(a.name)
			if !ok {
				continue
			}
			cv, ok := condValueOf(a.val)
			if !ok {
				continue
			}
			s := get("r" + a.name)
			if s.ref == nil {
				r := ref
				s.ref = &r
			}
			if _, ok := s.values[cv.key]; !ok {
				s.values[cv.key] = cv
			}
			s.of[i] = cv.key
		}
		if m.rx != nil {
			for _, at := range m.rx.attrs {
				v, ok := at.bySubject[subj[i]]
				if !ok {
					continue
				}
				s := get("z" + at.def.Name) // after the request sources: on a tie the request wins
				s.cust = at.def.Name
				key := "v:" + v
				if _, ok := s.values[key]; !ok {
					s.values[key] = &condValue{key: key, match: Match{In: []any{v}}, label: slug(v)}
				}
				s.of[i] = key
			}
		}
	}
	sort.Strings(order)
	type best struct {
		src  *condSource
		kept []string
		p    float64
	}
	var top *best
	tried := 0
	for _, name := range order {
		s := srcs[name]
		if len(s.values) < 2 || len(s.values) > maxCondValues {
			continue
		}
		kept := keptCondValues(s, subj, k)
		if len(kept) == 0 {
			continue
		}
		tried++
		kept, p, ok := chiSquareTest(s, kept, outs)
		if !ok {
			continue
		}
		if top == nil || p < top.p {
			top = &best{s, kept, p}
		}
	}
	if top == nil || tried == 0 || top.p >= condSignificance/float64(tried) {
		return
	}
	m.applyConditions(rule, top.src, top.kept, outs, subj)
}

// condValueOf turns a clear value into a condition value.
func condValueOf(v Value) (*condValue, bool) {
	switch v.Kind {
	case 'q':
		lo, hi, ok := bucketRange(v.S)
		if !ok {
			return nil, false
		}
		mt := Match{Min: lo, Max: hi}
		label := ""
		switch {
		case lo != nil && hi != nil && *lo == *hi:
			mt = Match{In: []any{*lo}}
			label = fnum(*lo)
		case lo != nil && hi != nil:
			label = fnum(*lo) + "-" + fnum(*hi)
		case lo != nil:
			label = "from-" + fnum(*lo)
		default:
			label = "below-" + fnum(*hi)
		}
		return &condValue{key: v.S, match: mt, label: slug(label)}, true
	case 's', 'b', 'n':
		x := valueAny(v)
		return &condValue{key: "v:" + canonScalar(x), match: Match{In: []any{x}}, label: slug(canonScalar(x))}, true
	}
	return nil, false
}

func fnum(f float64) string { return strings.TrimSuffix(fmt.Sprintf("%g", f), ".0") }

// keptCondValues are the values of a source seen for at least k users,
// most frequent first.
func keptCondValues(s *condSource, subj []int32, k int) []string {
	users := map[string]map[int32]bool{}
	count := map[string]int{}
	for i, v := range s.of {
		if v == "" {
			continue
		}
		count[v]++
		if users[v] == nil {
			users[v] = map[int32]bool{}
		}
		if subj[i] >= 0 {
			users[v][subj[i]] = true
		}
	}
	var out []string
	for v, us := range users {
		if len(us) >= k {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if count[out[a]] != count[out[b]] {
			return count[out[a]] > count[out[b]]
		}
		return out[a] < out[b]
	})
	return out
}

// chiSquareTest tests the independence of the source's values (kept
// values, the rest in one row) and the outcomes. Rows whose expected
// counts fall below 5 are merged into the rest, least frequent first. It
// returns the kept values left and the p-value.
func chiSquareTest(s *condSource, kept []string, outs []string) ([]string, float64, bool) {
	cols := map[string]int{}
	for _, o := range outs {
		if _, ok := cols[o]; !ok {
			cols[o] = len(cols)
		}
	}
	if len(cols) < 2 {
		return nil, 1, false
	}
	for len(kept) > 0 {
		row := map[string]int{}
		for i, v := range kept {
			row[v] = i
		}
		rest := len(kept)
		table := make([][]float64, len(kept)+1)
		for i := range table {
			table[i] = make([]float64, len(cols))
		}
		for i, v := range s.of {
			r, ok := row[v]
			if !ok {
				r = rest
			}
			table[r][cols[outs[i]]]++
		}
		if sum(table[rest]) == 0 {
			table = table[:rest]
		}
		if len(table) < 2 {
			return nil, 1, false
		}
		stat, ok := chiSquare(table)
		if !ok {
			kept = kept[:len(kept)-1] // merge the least frequent value into the rest
			continue
		}
		df := float64((len(table) - 1) * (len(cols) - 1))
		return kept, chiSquareSurvival(stat, df), true
	}
	return nil, 1, false
}

func sum(xs []float64) float64 {
	t := 0.0
	for _, x := range xs {
		t += x
	}
	return t
}

// chiSquare is Pearson's statistic of a contingency table; false when an
// expected count is below 5.
func chiSquare(t [][]float64) (float64, bool) {
	rows := make([]float64, len(t))
	cols := make([]float64, len(t[0]))
	n := 0.0
	for i := range t {
		for j := range t[i] {
			rows[i] += t[i][j]
			cols[j] += t[i][j]
			n += t[i][j]
		}
	}
	stat := 0.0
	for i := range t {
		for j := range t[i] {
			e := rows[i] * cols[j] / n
			if e < 5 {
				return 0, false
			}
			d := t[i][j] - e
			stat += d * d / e
		}
	}
	return stat, true
}

// chiSquareSurvival is P(X > x) for a chi-square with df degrees of freedom:
// the regularized upper incomplete gamma Q(df/2, x/2).
func chiSquareSurvival(x, df float64) float64 {
	if x <= 0 {
		return 1
	}
	return gammaQ(df/2, x/2)
}

// gammaQ is the regularized upper incomplete gamma function (series below
// a+1, continued fraction above; Numerical Recipes 6.2).
func gammaQ(a, x float64) float64 {
	lg, _ := math.Lgamma(a)
	if x < a+1 {
		ap, del, s := a, 1/a, 1/a
		for n := 0; n < 500; n++ {
			ap++
			del *= x / ap
			s += del
			if math.Abs(del) < math.Abs(s)*1e-15 {
				break
			}
		}
		return 1 - s*math.Exp(-x+a*math.Log(x)-lg)
	}
	const tiny = 1e-300
	b := x + 1 - a
	c, d := 1/tiny, 1/b
	h := d
	for i := 1; i < 500; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < 1e-15 {
			break
		}
	}
	return math.Exp(-x+a*math.Log(x)-lg) * h
}

// applyConditions rewrites the outcomes of rule: per kept value, the
// outcomes seen for at least k users with `when`; for the other values
// the unconditional outcomes. p are joint shares of the published causes.
// The rule is left unchanged when fewer than two groups remain or when the
// other values have causes but no outcome with k users.
func (m *miner) applyConditions(rule *CausalRule, s *condSource, kept []string, outs []string, subj []int32) {
	k := m.cfg.KMin
	type cell struct {
		n     int
		users map[int32]bool
	}
	groupOf := map[string]int{}
	for i, v := range kept {
		groupOf[v] = i
	}
	rest := len(kept)
	cells := make([]map[string]*cell, len(kept)+1)
	for i := range cells {
		cells[i] = map[string]*cell{}
	}
	restCauses := 0
	for i, v := range s.of {
		g, ok := groupOf[v]
		if !ok {
			g = rest
			restCauses++
		}
		c := cells[g][outs[i]]
		if c == nil {
			c = &cell{users: map[int32]bool{}}
			cells[g][outs[i]] = c
		}
		c.n++
		if subj[i] >= 0 {
			c.users[subj[i]] = true
		}
	}
	byName := map[string]Outcome{}
	var names []string
	for _, o := range rule.Outcomes {
		byName[o.Name] = o
		names = append(names, o.Name)
	}
	type pub struct {
		o Outcome
		n int
	}
	var out []pub
	used := map[string]bool{}
	groups := 0
	for g := 0; g <= rest; g++ {
		var add []pub
		for _, name := range names {
			c := cells[g][name]
			if c == nil || len(c.users) < k {
				continue
			}
			o := byName[name]
			no := Outcome{Name: name, Effects: append([]string{}, o.Effects...)}
			if g < rest {
				cv := s.values[kept[g]]
				mt := cv.match
				if s.ref != nil {
					r := *s.ref
					mt.At = &r
				} else {
					mt.Customer = s.cust
				}
				no.When = []Match{mt}
				no.Name = outcomeName(name, cv.label, used)
			}
			used[no.Name] = true
			add = append(add, pub{no, c.n})
		}
		if len(add) == 0 {
			if g == rest && restCauses > 0 {
				return // other values would have no outcome at all
			}
			continue
		}
		groups++
		out = append(out, add...)
	}
	if groups < 2 {
		return
	}
	total := 0
	for _, p := range out {
		total += p.n
	}
	rule.Outcomes = rule.Outcomes[:0]
	rule.Evidence.Counts.Outcomes = map[string]int{}
	for _, p := range out {
		p.o.P = float64(p.n) / float64(total)
		rule.Outcomes = append(rule.Outcomes, p.o)
		rule.Evidence.Counts.Outcomes[p.o.Name] = p.n
	}
	roundProbabilities(rule.Outcomes)
}

// outcomeName is the miner name of an outcome plus the value label,
// unique and within the identifier grammar.
func outcomeName(base, label string, used map[string]bool) string {
	if label == "" {
		label = "v"
	}
	name := base + "-" + label
	if len(name) > 60 {
		name = strings.TrimRight(name[:60], "-")
	}
	cand := name
	for n := 2; used[cand] || !reIdent.MatchString(cand); n++ {
		cand = name + "-" + itoa(n)
		if n > 99 {
			break
		}
	}
	return cand
}

// whenKey renders conditions for the structure of a rule.
func whenKey(ms []Match) string {
	var b strings.Builder
	for _, mt := range ms {
		if mt.At != nil {
			b.WriteString(mt.At.String())
		} else {
			b.WriteString("customer:" + mt.Customer)
		}
		for _, v := range mt.In {
			fmt.Fprintf(&b, "=%v", v)
		}
		if mt.Min != nil {
			fmt.Fprintf(&b, ">=%g", *mt.Min)
		}
		if mt.Max != nil {
			fmt.Fprintf(&b, "<%g", *mt.Max)
		}
		b.WriteString(";")
	}
	return b.String()
}
