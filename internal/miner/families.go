package miner

import (
	"math"
	"sort"
	"time"
)

// Joinable HMAC domain families (rules v1.9, C15). The same identifier can
// leave under two HMAC domains (clientId in one service, customerId in
// another): its tokens then differ and nothing links them. The policy can
// join the two domains (hmac.families); the miner proposes the candidates
// from structure only, never comparing tokens of two domains (they cannot
// be equal). For every pair of domains of a group (never subject) seen by
// at least KMin subjects both:
//
//   - same_cardinality: the number of distinct tokens of each domain per
//     subject is the same for at least MinShare of those subjects, and at
//     least two subjects have more than one (one token each proves
//     nothing on its own);
//   - write_read_follow: a token new for the subject in one domain, first
//     seen in a write (its request or its answer), is followed within
//     followWindow by a token new for the subject in the other domain,
//     first seen in the answer of a read, for at least MinShare of those
//     firsts (in either direction, judged on at least KMin firsts);
//   - same_ops (same exchanges): the traces that carry a token of one
//     domain carry a token of the other for at least MinShare of them
//     (judged on at least KMin traces);
//
// and never when the two domains appear in the same record of an answer
// (an object that holds both is two related objects, a relation, not one
// identifier under two names). A pair is proposed with same_cardinality and
// at least one other signal; its score is the mean of the three shares
// (0 for a signal that does not hold). At most maxFamilies per group, by
// score.

const (
	followWindow = time.Minute
	maxFamilies  = 20
)

type famTok struct {
	tok   int32
	first time.Time
	write bool // first seen in a write (request or answer)
	read  bool // first seen in the answer of a read
}

// families proposes the domain families of the group's log.
func (m *miner) families(group string) []FamilyCandidate {
	l, cfg := m.l, m.cfg
	// Per subject and domain, the tokens with their first sight.
	per := map[int32]map[string]map[int32]*famTok{}
	inRecord := map[[2]string]bool{}
	traces := map[string]map[int32]bool{} // domain → roots of the traces carrying it
	for i := range l.evs {
		ev := &l.evs[i]
		s := l.subjectOf(int32(i))
		op := &l.ops[ev.op]
		for _, t := range ev.toks {
			d := l.tokDom[t.tok]
			if d == "" || d == "subject" {
				continue
			}
			if traces[d] == nil {
				traces[d] = map[int32]bool{}
			}
			traces[d][ev.root] = true
			if s < 0 {
				continue
			}
			if per[s] == nil {
				per[s] = map[string]map[int32]*famTok{}
			}
			if per[s][d] == nil {
				per[s][d] = map[int32]*famTok{}
			}
			if per[s][d][t.tok] == nil {
				side := l.locs[t.loc].side
				per[s][d][t.tok] = &famTok{tok: t.tok, first: ev.at(side), write: op.write && !op.read, read: op.read && side == sideResp}
			}
		}
		for ri := range ev.recs {
			r := &ev.recs[ri]
			for a := 0; a < len(r.ids); a++ {
				for b := a + 1; b < len(r.ids); b++ {
					da, db := l.tokDom[r.ids[a].tok], l.tokDom[r.ids[b].tok]
					if da != db {
						inRecord[famPair(da, db)] = true
					}
				}
			}
		}
	}
	both := map[[2]string]map[int32]bool{}
	for s, doms := range per {
		ds := sortedKeys(doms)
		for a := 0; a < len(ds); a++ {
			for b := a + 1; b < len(ds); b++ {
				k := famPair(ds[a], ds[b])
				if inRecord[k] {
					continue
				}
				if both[k] == nil {
					both[k] = map[int32]bool{}
				}
				both[k][s] = true
			}
		}
	}
	var out []FamilyCandidate
	for k, subs := range both {
		if len(subs) < cfg.KMin {
			continue
		}
		// same_cardinality
		same, multi := 0, 0
		for s := range subs {
			na, nb := len(per[s][k[0]]), len(per[s][k[1]])
			if na == nb {
				same++
				if na > 1 {
					multi++
				}
			}
		}
		cardShare := float64(same) / float64(len(subs))
		if cardShare < cfg.MinShare || multi < 2 {
			continue
		}
		// write_read_follow, best direction.
		follow := 0.0
		for _, dir := range [][2]string{{k[0], k[1]}, {k[1], k[0]}} {
			firsts, hit := 0, 0
			for s := range subs {
				var reads []time.Time
				for _, ft := range per[s][dir[1]] {
					if ft.read {
						reads = append(reads, ft.first)
					}
				}
				sort.Slice(reads, func(a, b int) bool { return reads[a].Before(reads[b]) })
				for _, ft := range per[s][dir[0]] {
					if !ft.write {
						continue
					}
					firsts++
					x := sort.Search(len(reads), func(j int) bool { return !reads[j].Before(ft.first) })
					if x < len(reads) && reads[x].Sub(ft.first) <= followWindow {
						hit++
					}
				}
			}
			if firsts >= cfg.KMin {
				follow = math.Max(follow, float64(hit)/float64(firsts))
			}
		}
		// same exchanges (traces), best direction.
		sameTr := 0.0
		for _, dir := range [][2]string{{k[0], k[1]}, {k[1], k[0]}} {
			ta, tb := traces[dir[0]], traces[dir[1]]
			if len(ta) < cfg.KMin {
				continue
			}
			hit := 0
			for r := range ta {
				if tb[r] {
					hit++
				}
			}
			sameTr = math.Max(sameTr, float64(hit)/float64(len(ta)))
		}
		var signals []string
		score := cardShare
		signals = append(signals, SignalSameCardinality)
		if follow >= cfg.MinShare {
			signals = append(signals, SignalWriteReadFollow)
			score += follow
		}
		if sameTr >= cfg.MinShare {
			signals = append(signals, SignalSameOps)
			score += sameTr
		}
		if len(signals) < 2 {
			continue
		}
		out = append(out, FamilyCandidate{Group: group, Domains: []string{k[0], k[1]}, Subjects: len(subs), Signals: signals, Score: round3(score / 3)})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Score != out[b].Score {
			return out[a].Score > out[b].Score
		}
		if out[a].Domains[0] != out[b].Domains[0] {
			return out[a].Domains[0] < out[b].Domains[0]
		}
		return out[a].Domains[1] < out[b].Domains[1]
	})
	if len(out) > maxFamilies {
		out = out[:maxFamilies]
	}
	return out
}

func famPair(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}
