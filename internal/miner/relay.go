package miner

import (
	"sort"
)

// Relayed identifiers. A service often returns, under a field of its own, an
// identifier that an external service minted while the request was being
// served: POST /loans calls the notifications API (POST /v1/messages answers
// {"id": ...}) and returns the id as notificationId. The policy assistant
// names HMAC domains after field names, so the two fields can get different
// domains (notification, message); the domain is part of the HMAC input, so
// the tokens differ and the miner would see two unrelated objects: the loan
// would not refer to the message, and the message's lifecycle (queued, then
// delivered or bounced, seen through later reads of the notifications API)
// would never become an outcome of POST /loans.
//
// The link is recovered from the structure of the traces, never from values:
// in the trace of an exchange p, a foreign-key field of p's response (named
// like xxxId, not the record's own id) holds a token seen there for the
// first time (not in p's request, not in any nested call), while exactly one
// nested call minted a token of another domain that p's response does not
// carry. When that pairing holds for at least KMin exchanges and MinShare of
// those with a new token in the field, the field's domain is an alias of the
// minted one: each pair of tokens becomes one object and the field's domain
// takes the minted domain's name.

// DomainMerge records a recovered link between two HMAC domains.
type DomainMerge struct {
	// From is the domain of the relaying field, Into the minted one.
	From string `json:"from"`
	Into string `json:"into"`
	// Field is where the identifier was relayed ("service op" and location),
	// Source where it was minted.
	Field  string `json:"field"`
	Source string `json:"source"`
	// Pairs is the number of exchanges that relayed a newly minted token.
	Pairs int `json:"pairs"`
}

type relayPair struct{ minted, relay int32 } // locations

// mergeRelayedDomains finds relayed identifiers and merges their tokens (see
// above). It changes the log in place and is idempotent.
func (l *Log) mergeRelayedDomains(cfg *Config) []DomainMerge {
	if len(l.evs) == 0 {
		return nil
	}
	kids := make([][]int32, len(l.evs))
	for i := range l.evs {
		if p := l.evs[i].pev; p >= 0 {
			kids[p] = append(kids[p], int32(i))
		}
	}
	firstAt := func(tok int32) int32 {
		if os := l.occ[tok]; len(os) > 0 {
			return os[0].ev
		}
		return -1
	}
	isFK := func(lc int32) bool {
		lo := &l.locs[lc]
		if lo.side != sideResp || !lo.refOK || lo.ref.Path == "" || lo.domain == "" || lo.domain == "subject" {
			return false
		}
		ps := splitTTPath(lo.ref.Path)
		return len(ps) > 0 && ps[len(ps)-1] != "id" && ps[len(ps)-1] != "[*]"
	}
	count := map[relayPair]int{}
	newAt := map[int32]int{} // relay location → exchanges with a new token there
	maps := map[relayPair][][2]int32{}
	var desc []int32
	for p := range l.evs {
		ev := &l.evs[p]
		if !ev.ok() || len(kids[p]) == 0 {
			continue
		}
		var cands []tokAt
		for _, t := range ev.toks {
			if isFK(t.loc) && firstAt(t.tok) == int32(p) {
				cands = append(cands, t)
			}
		}
		if len(cands) == 0 {
			continue
		}
		desc = desc[:0]
		stack := append([]int32(nil), kids[p]...)
		for len(stack) > 0 && len(desc) < 256 {
			c := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			desc = append(desc, c)
			stack = append(stack, kids[c]...)
		}
		inDesc := map[int32]bool{}
		for _, c := range desc {
			for _, t := range l.evs[c].toks {
				inDesc[t.tok] = true
			}
		}
		inResp := map[int32]bool{}
		for _, t := range ev.toks {
			if l.locs[t.loc].side == sideResp {
				inResp[t.tok] = true
			}
		}
		// Tokens minted by nested calls that the response does not carry.
		var minted []tokAt
		seen := map[int32]bool{}
		for _, c := range desc {
			ce := &l.evs[c]
			if !ce.ok() {
				continue
			}
			for _, t := range ce.toks {
				lo := &l.locs[t.loc]
				if lo.side != sideResp || lo.ref.Path == "" || lo.domain == "" || lo.domain == "subject" ||
					firstAt(t.tok) != c || inResp[t.tok] || seen[t.tok] {
					continue
				}
				if inReq, _ := l.tokIn(c, t.tok); inReq {
					continue
				}
				seen[t.tok] = true
				minted = append(minted, t)
			}
		}
		for _, t := range cands {
			if inDesc[t.tok] {
				continue // known to a nested call: not new here
			}
			newAt[t.loc]++
			var other []tokAt
			for _, u := range minted {
				if l.locs[u.loc].domain != l.locs[t.loc].domain {
					other = append(other, u)
				}
			}
			if len(other) != 1 {
				continue // none, or ambiguous
			}
			k := relayPair{other[0].loc, t.loc}
			count[k]++
			maps[k] = append(maps[k], [2]int32{t.tok, other[0].tok})
		}
	}
	// The best minted location of each relay location.
	best := map[int32]relayPair{}
	for k, n := range count {
		b, ok := best[k.relay]
		if !ok || n > count[b] || (n == count[b] && k.minted < b.minted) {
			best[k.relay] = k
		}
	}
	relays := make([]int32, 0, len(best))
	for r := range best {
		relays = append(relays, r)
	}
	sortInt32(relays)
	var out []DomainMerge
	rename := map[string]string{}
	alias := map[int32]int32{}
	for _, r := range relays {
		k := best[r]
		n := count[k]
		if n < cfg.KMin || float64(n) < cfg.MinShare*float64(newAt[r]) {
			continue
		}
		from, into := l.locs[r].domain, l.locs[k.minted].domain
		if prev, ok := rename[from]; ok && prev != into {
			continue // the same domain relays two kinds of objects: leave it
		}
		rename[from] = into
		for _, m := range maps[k] {
			alias[m[0]] = m[1]
		}
		ro, mo := l.ops[l.locs[r].op], l.ops[l.locs[k.minted].op]
		out = append(out, DomainMerge{From: from, Into: into, Pairs: n,
			Field:  ro.service + " " + ro.op + " " + l.locs[r].field,
			Source: mo.service + " " + mo.op + " " + l.locs[k.minted].field})
	}
	if len(out) == 0 {
		return nil
	}
	// A domain renamed into one that is itself renamed follows the chain.
	for from, into := range rename {
		for i := 0; i < 8; i++ {
			next, ok := rename[into]
			if !ok || next == from {
				break
			}
			into = next
		}
		rename[from] = into
	}
	for i := range l.locs {
		if into, ok := rename[l.locs[i].domain]; ok {
			l.locs[i].domain = into
		}
	}
	l.aliasTokens(alias)
	return out
}

// aliasTokens makes every token of alias the same object as its target:
// occurrences, event tokens and record ids move to the target, and the
// domains of the moved tokens are recomputed.
func (l *Log) aliasTokens(alias map[int32]int32) {
	if len(alias) == 0 {
		return
	}
	// Chains (a token relayed twice) point at their last target.
	for src, dst := range alias {
		for i := 0; i < 8; i++ {
			next, ok := alias[dst]
			if !ok || next == src {
				break
			}
			dst = next
		}
		alias[src] = dst
	}
	to := func(t int32) int32 {
		if a, ok := alias[t]; ok {
			return a
		}
		return t
	}
	for i := range l.evs {
		e := &l.evs[i]
		for k := range e.toks {
			e.toks[k].tok = to(e.toks[k].tok)
		}
		for r := range e.recs {
			for f := range e.recs[r].ids {
				e.recs[r].ids[f].tok = to(e.recs[r].ids[f].tok)
			}
		}
	}
	for src, dst := range alias {
		if src == dst {
			continue
		}
		merged := append(append([]occ(nil), l.occ[dst]...), l.occ[src]...)
		sort.SliceStable(merged, func(a, b int) bool { return merged[a].ev < merged[b].ev })
		l.occ[dst], l.occ[src] = merged, nil
	}
	for t, os := range l.occ {
		cnt := map[string]int{}
		for _, o := range os {
			if d := l.locs[o.loc].domain; d != "" {
				cnt[d]++
			}
		}
		l.tokDom[t] = argmax(cnt)
	}
}
