package miner

import (
	"sort"
)

// Correlation-condition discovery between service messages: two event
// locations are linked when they carry the same tokens. The candidate pairs
// are pruned the way the literature on web-service log correlation does
// (distinctness of each attribute, share of common values): a location with
// few distinct tokens, or tokens repeated in most of its occurrences, would
// match by chance. Evidence is subject to the k threshold.

// Key is a discovered link key between two locations.
type Key struct {
	Domain string
	From   KeyEnd
	To     KeyEnd
	// Matches is the exact number of distinct tokens seen at both ends.
	Matches int
	// FromDistinct and ToDistinct are the distinct tokens at each end.
	FromDistinct, ToDistinct int
	// Confidence is Matches over the smaller distinct count.
	Confidence float64
	// Subjects is the number of distinct subjects behind the matches.
	Subjects int

	from, to int32
}

// KeyRef returns the evidence form of the key.
func (k Key) KeyRef() KeyRef {
	return KeyRef{Domain: k.Domain, From: k.From, To: k.To, Matches: k.Matches}
}

type locStats struct {
	distinct int
	total    int
}

func (l *Log) keyEnd(lc int32) KeyEnd {
	o := l.ops[l.locs[lc].op]
	return KeyEnd{Service: o.service, Op: o.op, At: l.locs[lc].ref}
}

// subjectOf returns the subject of an event, or of the root of its trace.
func (l *Log) subjectOf(i int32) int32 {
	if s := l.evs[i].subject; s >= 0 {
		return s
	}
	return l.evs[l.evs[i].root].subject
}

// lowCard reports whether a location must never be used as a key.
func (l *Log) lowCard(cfg *Config, st locStats) bool {
	if st.distinct < cfg.MinDistinct {
		return true
	}
	return float64(st.distinct) < cfg.MinDistinctRatio*float64(st.total)
}

func (l *Log) locStats() []locStats {
	st := make([]locStats, len(l.locs))
	seen := make([]map[int32]bool, len(l.locs))
	for t, os := range l.occ {
		if len(os) == 0 {
			continue
		}
		for _, o := range os {
			st[o.loc].total++
			if seen[o.loc] == nil {
				seen[o.loc] = map[int32]bool{}
			}
			if !seen[o.loc][int32(t)] {
				seen[o.loc][int32(t)] = true
				st[o.loc].distinct++
			}
		}
	}
	return st
}

// DiscoverKeys finds the link keys of the log.
func (l *Log) DiscoverKeys(cfg *Config) []Key {
	st := l.locStats()
	type pair struct{ a, b int32 }
	shared := map[pair]int{}
	subjects := map[pair]map[int32]bool{}
	firstA := map[pair]int{} // tokens whose first occurrence is at a (vs b)
	for _, os := range l.occ {
		var locs []int32
		seen := map[int32]bool{}
		subj := map[int32]bool{}
		for _, o := range os {
			if !seen[o.loc] {
				seen[o.loc] = true
				locs = append(locs, o.loc)
			}
			if s := l.subjectOf(o.ev); s >= 0 {
				subj[s] = true
			}
		}
		if len(locs) < 2 {
			continue
		}
		sortInt32(locs)
		first := os[0].loc
		for i := 0; i < len(locs); i++ {
			if !l.locs[locs[i]].refOK || l.lowCard(cfg, st[locs[i]]) {
				continue
			}
			for j := i + 1; j < len(locs); j++ {
				if !l.locs[locs[j]].refOK || l.lowCard(cfg, st[locs[j]]) {
					continue
				}
				p := pair{locs[i], locs[j]}
				shared[p]++
				if first == p.a {
					firstA[p]++
				} else if first == p.b {
					firstA[p]--
				}
				m := subjects[p]
				if m == nil {
					m = map[int32]bool{}
					subjects[p] = m
				}
				for s := range subj {
					m[s] = true
				}
			}
		}
	}
	var keys []Key
	for p, n := range shared {
		a, b := p.a, p.b
		if firstA[p] < 0 {
			a, b = b, a
		}
		da, db := st[a].distinct, st[b].distinct
		conf := float64(n) / float64(min(da, db))
		if n < cfg.KMin || conf < cfg.MinKeyConfidence || len(subjects[p]) < cfg.KMin {
			continue
		}
		dom := l.locs[a].domain
		if dom == "" {
			dom = l.locs[b].domain
		}
		if dom == "" || !reDomain.MatchString(dom) {
			continue
		}
		keys = append(keys, Key{
			Domain: dom, From: l.keyEnd(a), To: l.keyEnd(b), Matches: n,
			FromDistinct: da, ToDistinct: db, Confidence: conf, Subjects: len(subjects[p]),
			from: a, to: b,
		})
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Domain != keys[j].Domain {
			return keys[i].Domain < keys[j].Domain
		}
		if keys[i].Matches != keys[j].Matches {
			return keys[i].Matches > keys[j].Matches
		}
		ki, kj := keyString(keys[i]), keyString(keys[j])
		return ki < kj
	})
	return keys
}

func keyString(k Key) string {
	return k.From.Service + " " + k.From.Op + " " + k.From.At.String() + " -> " + k.To.Service + " " + k.To.Op + " " + k.To.At.String()
}
