package world

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

// Archetypes (ARCHITECTURE 8.1): every real subject (a token in zone B)
// becomes a vector of generalized features; vectors are grouped in classes
// of at least k distinct subjects; smaller classes are merged into the
// nearest class or dropped. Subject tokens never leave this file: they are
// only map keys while the profiles are built.

// Feature names, in vector order.
var featureNames = []string{"orders_per_month", "active_hours", "error_rate", "primary_op", "outcome"}

// Features are the published (aggregate) features of an archetype.
type Features struct {
	OrdersPerMonth string `json:"orders_per_month"`
	ActiveHours    string `json:"active_hours"`
	ErrorRate      string `json:"error_rate"`
	PrimaryOp      string `json:"primary_op"`
	Outcome        string `json:"outcome,omitempty"`
	// EndpointMix is the share of calls per "service op" among members;
	// only operations used by at least k members are listed (M5).
	EndpointMix map[string]float64 `json:"endpoint_mix,omitempty"`
	// OutcomesMix is the share of rule outcomes ("rule/outcome")
	// experienced by members, with the same k rule.
	OutcomesMix map[string]float64 `json:"outcomes_mix,omitempty"`
}

// Archetype is a k-anonymous group of real subjects.
type Archetype struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Size     int      `json:"size"`
	Features Features `json:"features"`
}

// maxMergeDistance is the largest number of differing features for which a
// class below k is merged into another instead of being dropped.
const maxMergeDistance = 2

// Mixed is the value of a categorical feature whose most common value is
// shared by fewer than k members.
const Mixed = "mixed"

// ClassCount is one generalized vector with the number of subjects that
// have it. It holds no token; it stays in zone B and feeds the residual
// risk measures of the gate.
type ClassCount struct {
	Vector []string `json:"v"`
	Count  int      `json:"n"`
}

// Build is the result of an archetype build.
type Build struct {
	// Group is the group whose traffic the build profiles ("": every group).
	Group      string      `json:"group"`
	KMin       int         `json:"k_min"`
	From       time.Time   `json:"from"`
	To         time.Time   `json:"to"`
	Profiles   int         `json:"profiles"`
	Dropped    int         `json:"dropped_subjects"`
	Archetypes []Archetype `json:"archetypes"`
	// Classes is the histogram of all real vectors; Members the histogram
	// per archetype id. Zone B only (never in an API answer or a pack).
	Classes []ClassCount            `json:"-"`
	Members map[string][]ClassCount `json:"-"`
}

// ProfileOptions controls BuildArchetypes.
type ProfileOptions struct {
	KMin     int
	From, To time.Time
	// CreateOps are the "service op" pairs that count as an order (the
	// created_by operations of the rule entities). Empty: inbound POSTs.
	CreateOps []string
	// Outcomes, optional, gives the rule outcomes per subject.
	Outcomes OutcomeSource
	// MaxEvents bounds the scan (default 5 000 000).
	MaxEvents int
	// Sources restricts the profiles to the events of these sources (one
	// group's; nil: every source).
	Sources []string
}

type profile struct {
	calls, errs, creates int
	hours                [4]int
	ops                  map[string]int
	outcomes             map[string]int64
}

func (p *profile) vector(months float64, outcome string) []string {
	opm := float64(p.creates) / months
	var o string
	switch {
	case p.creates == 0:
		o = "0"
	case opm <= 2.5:
		o = "1-2"
	case opm <= 5.5:
		o = "3-5"
	case opm <= 10.5:
		o = "6-10"
	default:
		o = "11+"
	}
	best := 0
	for i, n := range p.hours {
		if n > p.hours[best] {
			best = i
		}
	}
	hours := []string{"00-06", "06-12", "12-18", "18-24"}[best]
	er := float64(p.errs) / float64(max(1, p.calls))
	var e string
	switch {
	case p.errs == 0:
		e = "0"
	case er < 0.05:
		e = "<5%"
	case er < 0.2:
		e = "5-20%"
	default:
		e = ">20%"
	}
	return []string{o, hours, e, topKey(p.ops), outcome}
}

func topKey[V int | int64](m map[string]V) string {
	best, bestN := "", V(-1)
	for _, k := range sortedKeys(m) {
		if m[k] > bestN {
			best, bestN = k, m[k]
		}
	}
	if best == "" {
		return "none"
	}
	return best
}

// BuildArchetypes reads inbound events with a subject in [From, To) and
// clusters the subjects into archetypes of at least KMin subjects.
func BuildArchetypes(ctx context.Context, src EventSource, opt ProfileOptions) (*Build, error) {
	if opt.KMin < 2 {
		return nil, errors.New("world: k_min must be >= 2")
	}
	if !opt.From.Before(opt.To) {
		return nil, errors.New("world: empty profile window")
	}
	maxEv := opt.MaxEvents
	if maxEv <= 0 {
		maxEv = 5_000_000
	}
	creates := map[string]bool{}
	for _, c := range opt.CreateOps {
		creates[c] = true
	}
	profs := map[string]*profile{}
	n := 0
	visit := func(subject, service, op string, at time.Time, status int, netErr string) error {
		n++
		if n > maxEv {
			return intake.ErrStop
		}
		if subject == "" {
			return nil
		}
		p := profs[subject]
		if p == nil {
			p = &profile{ops: map[string]int{}}
			profs[subject] = p
		}
		key := service + " " + op
		p.calls++
		p.ops[key]++
		p.hours[at.UTC().Hour()/6]++
		ok2xx := status >= 200 && status < 300
		if netErr != "" || status >= 400 {
			p.errs++
		}
		isCreate := creates[key] || (len(creates) == 0 && strings.HasPrefix(op, "POST "))
		if isCreate && ok2xx {
			p.creates++
		}
		return nil
	}
	// Time order straight from the index (no sort of the window), and only
	// the scalar columns when the source has them: the bodies are not needed.
	q := intake.Query{Dir: event.Inbound, From: opt.From, To: opt.To, ByTime: true, SourceIDs: opt.Sources}
	var err error
	if ms, ok := src.(intake.MetaScanner); ok {
		err = ms.ScanMeta(ctx, q, func(m *intake.EventMeta) error {
			return visit(m.Subject, m.Service, m.Op, m.Time, m.Status, m.NetError)
		})
	} else {
		err = src.Scan(ctx, q, func(se *intake.StoredEvent) error {
			ev := se.Event
			return visit(ev.Subject, ev.Service, ev.Op, ev.Time, ev.Status, ev.NetError)
		})
	}
	if err != nil {
		return nil, err
	}
	if opt.Outcomes != nil {
		oc, err := opt.Outcomes.SubjectOutcomes(ctx, opt.From, opt.To)
		if err != nil {
			return nil, err
		}
		for subj, m := range oc {
			if p := profs[subj]; p != nil {
				p.outcomes = m
			}
		}
	}
	months := opt.To.Sub(opt.From).Hours() / (24 * 30)
	if months <= 0 {
		months = 1
	}
	list := make([]*profile, 0, len(profs))
	for _, subj := range sortedKeys(profs) {
		list = append(list, profs[subj])
	}
	profs = nil // tokens are not needed any more
	return cluster(list, months, opt), nil
}

type class struct {
	key     string
	vec     []string
	members []*profile
	hist    map[string]int
}

func vkey(v []string) string { return strings.Join(v, "\x1f") }

func cluster(list []*profile, months float64, opt ProfileOptions) *Build {
	k := opt.KMin
	byKey := map[string]*class{}
	all := map[string]int{}
	vecs := map[string][]string{}
	for _, p := range list {
		oc := "none"
		if opt.Outcomes != nil {
			oc = topKey(p.outcomes)
		}
		v := p.vector(months, oc)
		kk := vkey(v)
		all[kk]++
		vecs[kk] = v
		c := byKey[kk]
		if c == nil {
			c = &class{key: kk, vec: v, hist: map[string]int{}}
			byKey[kk] = c
		}
		c.members = append(c.members, p)
		c.hist[kk]++
	}
	classes := make([]*class, 0, len(byKey))
	for _, kk := range sortedKeys(byKey) {
		classes = append(classes, byKey[kk])
	}
	// Merge the smallest class below k into its nearest class (Hamming
	// distance on the vector; ties: the bigger, then the key) when they
	// differ in at most maxMergeDistance features; drop what cannot be
	// merged (suppression).
	dropped := 0
	for {
		sort.SliceStable(classes, func(i, j int) bool {
			if len(classes[i].members) != len(classes[j].members) {
				return len(classes[i].members) < len(classes[j].members)
			}
			return classes[i].key < classes[j].key
		})
		if len(classes) == 0 || len(classes[0].members) >= k {
			break
		}
		small := classes[0]
		best, bestD := -1, len(featureNames)
		for i := 1; i < len(classes); i++ {
			d := hamming(small.vec, classes[i].vec)
			if d < bestD || (d == bestD && best >= 0 && len(classes[i].members) > len(classes[best].members)) {
				best, bestD = i, d
			}
		}
		if best < 0 || bestD > maxMergeDistance {
			dropped += len(small.members)
			classes = classes[1:]
			continue
		}
		dst := classes[best]
		dst.members = append(dst.members, small.members...)
		for kk, n := range small.hist {
			dst.hist[kk] += n
		}
		dst.vec = modeVector(dst.hist, vecs, 0)
		dst.key = vkey(dst.vec) + "\x1e" + dst.key
		classes = classes[1:]
	}
	sort.SliceStable(classes, func(i, j int) bool {
		if len(classes[i].members) != len(classes[j].members) {
			return len(classes[i].members) > len(classes[j].members)
		}
		return classes[i].key < classes[j].key
	})
	b := &Build{KMin: k, From: opt.From.UTC(), To: opt.To.UTC(), Profiles: len(list), Dropped: dropped, Members: map[string][]ClassCount{}}
	for _, kk := range sortedKeys(all) {
		b.Classes = append(b.Classes, ClassCount{Vector: vecs[kk], Count: all[kk]})
	}
	for i, c := range classes {
		id := fmt.Sprintf("arch-%02d", i+1)
		f := Features{}
		mv := modeVector(c.hist, vecs, k)
		f.OrdersPerMonth, f.ActiveHours, f.ErrorRate, f.PrimaryOp = mv[0], mv[1], mv[2], mv[3]
		if opt.Outcomes != nil {
			f.Outcome = mv[4]
		}
		f.EndpointMix = mix(c.members, k, func(p *profile) map[string]int64 {
			m := map[string]int64{}
			for op, n := range p.ops {
				m[op] = int64(n)
			}
			return m
		})
		if opt.Outcomes != nil {
			f.OutcomesMix = mix(c.members, k, func(p *profile) map[string]int64 { return p.outcomes })
		}
		a := Archetype{ID: id, Size: len(c.members), Features: f}
		a.Label = label(f)
		b.Archetypes = append(b.Archetypes, a)
		for _, kk := range sortedKeys(c.hist) {
			b.Members[id] = append(b.Members[id], ClassCount{Vector: vecs[kk], Count: c.hist[kk]})
		}
	}
	return b
}

func hamming(a, b []string) int {
	d := 0
	for i := range a {
		if a[i] != b[i] {
			d++
		}
	}
	return d
}

// modeVector returns, per feature, the most common value among the class
// members; with k > 0 a value shared by fewer than k members becomes Mixed.
func modeVector(hist map[string]int, vecs map[string][]string, k int) []string {
	out := make([]string, len(featureNames))
	for i := range featureNames {
		cnt := map[string]int{}
		for kk, n := range hist {
			cnt[vecs[kk][i]] += n
		}
		best := topKey(cnt)
		if k > 0 && cnt[best] < k {
			best = Mixed
		}
		out[i] = best
	}
	return out
}

// mix aggregates shares over members, listing only the keys used by at
// least k members, renormalized and rounded to 3 decimals.
func mix(members []*profile, k int, get func(*profile) map[string]int64) map[string]float64 {
	users := map[string]int{}
	tot := map[string]int64{}
	for _, p := range members {
		for key, n := range get(p) {
			if n > 0 {
				users[key]++
				tot[key] += n
			}
		}
	}
	var sum int64
	for key, n := range tot {
		if users[key] >= k {
			sum += n
		}
	}
	if sum == 0 {
		return nil
	}
	out := map[string]float64{}
	for key, n := range tot {
		if users[key] >= k {
			out[key] = math.Round(float64(n)/float64(sum)*1000) / 1000
		}
	}
	return out
}

func label(f Features) string {
	var parts []string
	if f.OrdersPerMonth != Mixed {
		parts = append(parts, f.OrdersPerMonth+" ordini/mese")
	}
	if f.ActiveHours != Mixed {
		parts = append(parts, "attivo "+f.ActiveHours)
	}
	if f.ErrorRate != Mixed {
		parts = append(parts, "errori "+f.ErrorRate)
	}
	if len(parts) == 0 {
		return "profilo misto"
	}
	return strings.Join(parts, ", ")
}
