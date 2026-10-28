package miner

import (
	"sort"
	"strings"
)

// Reads by behaviour (rules v1.6, C5). An operation reads or writes by what
// it does, not by its method: a POST search, a GraphQL mutation used as a
// lookup, a backend that wraps every call in a POST. A POST (or a GraphQL
// mutation) is classified as a read when, over its successful calls seen
// for at least KMin subjects:
//
//   - it returns objects that already exist: most calls return identifiers,
//     and almost none of them (at most 1-MinShare) is minted there (a
//     creation mints a new identifier on every call);
//   - its answers are stable: calls with the same request (subject, request
//     tokens and clear values) return the same identifiers in at least
//     MinShare of the requests seen more than once;
//   - it changes nothing it returns: the clear values of a returned object
//     equal those it had in the last earlier answer that showed it (from
//     any operation) in at least MinShare of the comparable cases (a cancel
//     returns the object with a new status: a write).
//
// A person can decide instead, per operation and group, in the console
// ("this operation is a read"): the decision wins over the traffic both
// ways. PUT, PATCH and DELETE are never classified as reads from the
// traffic.

// ReadDecision is the classification of one operation in a run.
type ReadDecision struct {
	Group   string `json:"group,omitempty"`
	Service string `json:"service"`
	Op      string `json:"op"`
	// Read is the decision; Auto tells it came from the traffic, Override
	// that a person decided it.
	Read     bool `json:"read"`
	Auto     bool `json:"auto,omitempty"`
	Override bool `json:"override,omitempty"`
}

// opReadStats are the counts behind the classification of one operation.
type opReadStats struct {
	calls, withToks        int
	respToks, minted       int
	repeated, stable       int
	compared, changed      int
	subjects               map[int32]bool
	fingerprints           map[string]string // request fingerprint → response tokens
	fpUnstable, fpRepeated map[string]bool
}

// classifyReads decides which POST operations of the log read (see above)
// and applies the console decisions over ("service op" → read). It runs
// before the entities are found: a read never creates.
func (l *Log) classifyReads(cfg *Config, over map[string]bool) []ReadDecision {
	stats := map[int32]*opReadStats{}
	for i := range l.ops {
		o := &l.ops[i]
		if o.method == "POST" && o.write {
			stats[int32(i)] = &opReadStats{subjects: map[int32]bool{}, fingerprints: map[string]string{},
				fpUnstable: map[string]bool{}, fpRepeated: map[string]bool{}}
		}
	}
	if len(stats) > 0 {
		l.readStats(stats)
	}
	var out []ReadDecision
	for i := range l.ops {
		o := &l.ops[i]
		if v, ok := over[o.service+" "+o.op]; ok {
			o.read, o.write, o.readSet = v, !v, true
			out = append(out, ReadDecision{Service: o.service, Op: o.op, Read: v, Override: true})
			continue
		}
		st := stats[int32(i)]
		if st == nil || !st.isRead(cfg) {
			continue
		}
		o.read, o.write, o.readAuto = true, false, true
		out = append(out, ReadDecision{Service: o.service, Op: o.op, Read: true, Auto: true})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Service != out[b].Service {
			return out[a].Service < out[b].Service
		}
		return out[a].Op < out[b].Op
	})
	return out
}

func (st *opReadStats) isRead(cfg *Config) bool {
	if st.calls < cfg.KMin || len(st.subjects) < cfg.KMin {
		return false
	}
	if st.withToks*2 < st.calls || st.respToks == 0 {
		return false // it does not return objects
	}
	if float64(st.minted) > (1-cfg.MinShare)*float64(st.respToks) {
		return false // new identifiers: a creation
	}
	if st.compared > 0 && float64(st.changed) > (1-cfg.MinShare)*float64(st.compared) {
		return false // it changes what it returns: a write
	}
	if st.repeated > 0 && float64(st.stable) < cfg.MinShare*float64(st.repeated) {
		return false // equal requests, different answers
	}
	return true
}

// ownTok is the token a record is about: its "id" member, else its only
// identifier; -1 when it cannot tell.
func ownTok(r *record) int32 {
	for _, f := range r.ids {
		if f.name == "id" {
			return f.tok
		}
	}
	if len(r.ids) == 1 {
		return r.ids[0].tok
	}
	return -1
}

func (l *Log) readStats(stats map[int32]*opReadStats) {
	// Last clear values of each object, from any answer.
	last := map[int32][]attr{}
	for i := range l.evs {
		ev := &l.evs[i]
		st := stats[ev.op]
		if st != nil && ev.ok() {
			st.calls++
			if s := l.subjectOf(int32(i)); s >= 0 {
				st.subjects[s] = true
			}
			var reqToks, respToks []int32
			for _, t := range ev.toks {
				if l.locs[t.loc].side == sideReq {
					reqToks = append(reqToks, t.tok)
				}
			}
			inReq := map[int32]bool{}
			for _, t := range reqToks {
				inReq[t] = true
			}
			seen := map[int32]bool{}
			for _, t := range ev.toks {
				if l.locs[t.loc].side != sideResp || seen[t.tok] {
					continue
				}
				seen[t.tok] = true
				respToks = append(respToks, t.tok)
				st.respToks++
				if !inReq[t.tok] && l.minter(t.tok) == int32(i) {
					st.minted++
				}
			}
			if len(respToks) > 0 {
				st.withToks++
			}
			for ri := range ev.recs {
				r := &ev.recs[ri]
				if r.side != sideResp {
					continue
				}
				own := ownTok(r)
				if own < 0 {
					continue
				}
				prev, ok := last[own]
				if !ok {
					continue
				}
				common, diff := 0, false
				for _, a := range r.attrs {
					for _, p := range prev {
						if p.name == a.name {
							common++
							if p.val != a.val {
								diff = true
							}
						}
					}
				}
				if common > 0 {
					st.compared++
					if diff {
						st.changed++
					}
				}
			}
			fp := fingerprint(l, ev, reqToks)
			sortInt32(respToks)
			var b strings.Builder
			for _, t := range respToks {
				b.WriteString(itoa(int(t)))
				b.WriteByte(',')
			}
			sig := b.String()
			if prev, ok := st.fingerprints[fp]; ok {
				st.fpRepeated[fp] = true
				if prev != sig {
					st.fpUnstable[fp] = true
				}
			} else {
				st.fingerprints[fp] = sig
			}
		}
		if ev.ok() {
			for ri := range ev.recs {
				r := &ev.recs[ri]
				if r.side != sideResp {
					continue
				}
				if own := ownTok(r); own >= 0 && len(r.attrs) > 0 {
					last[own] = r.attrs
				}
			}
		}
	}
	for _, st := range stats {
		st.repeated = len(st.fpRepeated)
		st.stable = st.repeated - len(st.fpUnstable)
	}
}

// fingerprint identifies a request: subject, request tokens and clear
// values of the request state node.
func fingerprint(l *Log, ev *evt, reqToks []int32) string {
	toks := append([]int32(nil), reqToks...)
	sortInt32(toks)
	var b strings.Builder
	b.WriteString(itoa(int(ev.subject)))
	b.WriteByte('|')
	for _, t := range toks {
		b.WriteString(itoa(int(t)))
		b.WriteByte(',')
	}
	b.WriteByte('|')
	attrs := append([]attr(nil), ev.reqState.attrs...)
	sort.Slice(attrs, func(a, c int) bool { return attrs[a].name < attrs[c].name })
	for _, a := range attrs {
		b.WriteString(a.name)
		b.WriteByte('=')
		b.WriteByte(a.val.Kind)
		b.WriteString(a.val.S)
		b.WriteByte(';')
	}
	return b.String()
}

// bodySelector reports whether a request body reference can select the
// entity of a read: a top-level GraphQL variable ($.variables.id, v1.14)
// or, for any read (v1.6), a body member outside arrays at most four
// levels down ($.filters.customerId, $.variables.where.id).
func bodySelector(op *opInfo, r Ref) bool {
	if r.From != "req.body" {
		return false
	}
	if graphqlSelector(op.op, r) {
		return true
	}
	if !op.read || strings.Contains(r.Path, "[*]") {
		return false
	}
	ps := splitTTPath(r.Path)
	return len(ps) >= 1 && len(ps) <= 4
}
