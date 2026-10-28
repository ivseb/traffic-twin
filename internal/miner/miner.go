package miner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Result is the outcome of one mining pass.
type Result struct {
	Window  Window
	Events  int
	Objects int
	// Observed is the span between the first and the last event seen.
	Observed time.Duration
	// Subjects is the number of distinct subject tokens (users) among the events:
	// with fewer than KMin no rule or published value can exist (k-anonymity).
	Subjects int
	// Ops counts the events per "service op" (an approved rule whose cause
	// was seen but not re-mined loses confidence).
	Ops      map[string]int
	Keys     []Key
	Entities []Entity
	// Rules are the mined rules in a stable order (causal by cause, then
	// batch); their ids are provisional until stored.
	Rules []*Mined
	// Diag explains the run: why each entity candidate was accepted or
	// dropped and what became of each rule candidate.
	Diag Diagnostics
	// Clamped is true when the window held more than Config.MaxEvents
	// events and the run mined only the newest ones (Window.From moved).
	Clamped bool
	// Names are the entity names in use (stored by Apply, so that they stay
	// across runs).
	Names []EntityName
	// Attributes, Aggregates and Lists (rules v1.9) describe the reads like
	// the entities: customer attributes carried by responses, numbers
	// computed from the collections, list operations no entity reads.
	Attributes []Attribute
	Aggregates []Aggregate
	Lists      []ListOp
}

// runExtras is the stored form of the v1.9 members of a run.
type runExtras struct {
	Attributes []Attribute `json:"attributes,omitempty"`
	Aggregates []Aggregate `json:"aggregates,omitempty"`
	Lists      []ListOp    `json:"lists,omitempty"`
}

// WindowLimiter is implemented by event sources that can find, without
// loading the events, where the newest n events of a window start
// (*intake.Store does).
type WindowLimiter interface {
	NewestSince(ctx context.Context, from, to time.Time, n int) (time.Time, bool, error)
}

// Document assembles a tt.rules/v1 document with the given rules (all
// mined rules with provisional ids when rules is nil).
func (r *Result) Document(generatedAt time.Time, rules []Rule) *Document {
	d := &Document{Format: Format, Window: &r.Window, Entities: r.Entities, Rules: rules,
		Attributes: r.Attributes, Aggregates: r.Aggregates, Lists: r.Lists}
	if !generatedAt.IsZero() {
		d.GeneratedAt = generatedAt.UTC().Format(time.RFC3339)
	}
	if rules == nil {
		d.Rules = []Rule{}
		for _, m := range r.Rules {
			d.Rules = append(d.Rules, m.Rule)
		}
	}
	if d.Entities == nil {
		d.Entities = []Entity{}
	}
	return d
}

// Mine runs the whole pipeline on the events of [from, to): object-centric
// log, link keys, entities, causal rules, batch rules.
func Mine(ctx context.Context, src EventSource, from, to time.Time, res DomainResolver, cfg Config) (*Result, error) {
	return MineIn(ctx, src, from, to, res, cfg, MineOptions{})
}

// MineOptions are the multi-team inputs of a mining run.
type MineOptions struct {
	// SourceGroups maps each source id to its group: the events of each
	// group are mined apart (nil: all together, as one group "").
	SourceGroups map[string]string
	// Names are the entity names given by earlier runs (Repo.EntityNames).
	Names []EntityName
	// Now dates the names given by this run.
	Now time.Time
	// OpReads are the decisions of a person on the kind of operations
	// (rules v1.6): group → "service op" → read. They win over the
	// classification from the traffic.
	OpReads map[string]map[string]bool
	// GroupKMin lowers k for the groups marked as test in the console
	// (rules v1.9, C0): group → k, at least 2 and below Config.KMin.
	GroupKMin map[string]int
}

// MineIn is Mine with the groups of the sources and the stored entity
// names: nothing mined from one group's traffic mixes with another's, and
// the entities keep their names (see names.go).
func MineIn(ctx context.Context, src EventSource, from, to time.Time, res DomainResolver, cfg Config, opt MineOptions) (*Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// Memory guard: a window with more than MaxEvents events is narrowed to
	// its newest MaxEvents (the log holds every event of the window in
	// memory, about 2 KB each), instead of loading them and failing.
	clamped := false
	if wl, ok := src.(WindowLimiter); ok && cfg.MaxEvents > 0 {
		cut, over, err := wl.NewestSince(ctx, from, to, cfg.MaxEvents)
		if err != nil {
			return nil, err
		}
		if over && cut.After(from) {
			from, clamped = cut, true
		}
	}
	var groupOf func(string) string
	distinct := map[string]bool{}
	if opt.SourceGroups != nil {
		groupOf = func(src string) string { return opt.SourceGroups[src] }
		for _, g := range opt.SourceGroups {
			distinct[g] = true
		}
	}
	// After the narrowing, events still arrive in the window before the scan
	// reaches them: the scan stops at MaxEvents (the newest few are left
	// out) instead of failing the run.
	_, narrowed := src.(WindowLimiter)
	logs, truncated, err := loadGroups(ctx, src, from, to, res, cfg.MaxEvents, groupOf, len(distinct) <= 1, narrowed && cfg.MaxEvents > 0)
	if err != nil {
		return nil, err
	}
	r := mineLogs(logs, cfg, opt)
	r.Clamped = clamped || truncated
	return r, nil
}

// MineLog mines an already loaded log.
func MineLog(l *Log, cfg Config) *Result {
	return MineLogs(map[string]*Log{"": l}, cfg, nil, time.Time{})
}

// MineLogs mines the logs of several groups (LoadGroups), each apart, and
// joins the results: entities are named across the groups (stored names
// first), rule ids are numbered over all of them.
func MineLogs(logs map[string]*Log, cfg Config, stored []EntityName, now time.Time) *Result {
	return mineLogs(logs, cfg, MineOptions{Names: stored, Now: now})
}

func mineLogs(logs map[string]*Log, cfg Config, opt MineOptions) *Result {
	stored, now := opt.Names, opt.Now
	type part struct {
		group  string
		l      *Log
		m      *miner
		merges []DomainMerge
		keys   []Key
	}
	res := &Result{Ops: map[string]int{}}
	var parts []*part
	var cands []candidate
	var first, last, wf, wt time.Time
	subjects := map[string]bool{}
	for _, g := range sortedKeys(logs) {
		l := logs[g]
		res.Events += l.Events()
		res.Objects += l.Objects()
		for t := range l.subj {
			subjects[l.toks[t]] = true
		}
		if l.Events() > 0 {
			if first.IsZero() || l.First.Before(first) {
				first = l.First
			}
			if l.Last.After(last) {
				last = l.Last
			}
		}
		if wf.IsZero() {
			wf, wt = l.From, l.To
		}
		for i := range l.evs {
			o := l.ops[l.evs[i].op]
			res.Ops[o.service+" "+o.op]++
		}
		p := &part{group: g, l: l}
		gcfg := groupConfig(cfg, opt.GroupKMin[g], g, res) // rules v1.9: a test group's lower k
		for _, d := range l.classifyReads(gcfg, opt.OpReads[g]) {
			d.Group = g
			res.Diag.Reads = append(res.Diag.Reads, d)
		}
		p.merges = l.mergeRelayedDomains(gcfg)
		p.keys = l.DiscoverKeys(gcfg)
		p.m = newMiner(gcfg, l)
		p.m.selectAll()
		cands = append(cands, p.m.candidates(g)...)
		parts = append(parts, p)
	}
	res.Subjects = len(subjects)
	if res.Events > 0 && last.After(first) {
		res.Observed = last.Sub(first)
	}
	if wf.IsZero() {
		wf = first
	}
	if wt.IsZero() {
		wt = last
	}
	res.Window = Window{From: wf.UTC().Format(time.RFC3339), To: wt.UTC().Format(time.RFC3339)}
	book := newNameBook(stored, now)
	attrNames := map[string]bool{}
	names := book.assign(cands)
	for _, p := range parts {
		m := p.m
		m.buildEntities(p.group, names, book)
		res.Keys = append(res.Keys, p.keys...)
		// Rules v1.9: customer attributes, list parameters and aggregates
		// describe the reads; the attributes feed the conditions.
		rx := m.mineReadExtras(attrNames)
		res.Attributes = append(res.Attributes, rx.attributes...)
		res.Aggregates = append(res.Aggregates, rx.aggregates...)
		res.Lists = append(res.Lists, rx.lists...)
		// Updates first: the transitions they explain are not spontaneous
		// outcomes of the creations (rules v1.7).
		res.Rules = append(res.Rules, m.mineUpdates()...)
		for i := range m.ents {
			if m.ents[i].creatorOp < 0 {
				continue // no creation to be the cause of
			}
			if mm := m.mineCausal(i); mm != nil {
				res.Rules = append(res.Rules, mm)
			}
		}
		res.Rules = append(res.Rules, m.mineRemovals()...)
		lims := m.mineLimits() // rules v1.8
		res.Rules = append(res.Rules, lims...)
		res.Rules = append(res.Rules, m.minePreconds(lims)...)                // rules v1.9
		res.Rules = append(res.Rules, m.mineUpdatesAll()...)                  // rules v1.9
		res.Diag.Families = append(res.Diag.Families, m.families(p.group)...) // rules v1.9
		for _, e := range m.ents {
			res.Entities = append(res.Entities, e.def) // after the rules: removals set removed_status
		}
		for i := range m.ents {
			res.Rules = append(res.Rules, m.mineBatches(i)...)
		}
		res.Diag.Groups = append(res.Diag.Groups, p.m.groupDiag(p.group))
		res.Diag.Entities = append(res.Diag.Entities, m.ediag...)
		res.Diag.Rules = append(res.Diag.Rules, m.rdiag...)
		res.Diag.Merges = append(res.Diag.Merges, p.merges...)
		for _, d := range m.ediag {
			if !d.Accepted && d.significant() {
				svc, op, _ := strings.Cut(d.Op, " ")
				res.Diag.Rules = append(res.Diag.Rules, RuleDiag{Signature: "causal|" + svc + "|" + op + "|" + d.Name, Kind: KindCausal,
					Decision: DecisionNotMined, Reason: "entity " + d.Name + " not accepted: " + d.Reason,
					Code: WhyEntity, Service: svc, Op: op, Entity: d.Name, Causes: d.Born})
			}
		}
	}
	res.Names = book.names()
	res.Diag.Candidates = candidatesOf(logs, cfg, opt, res, now) // rules v1.9, C0
	sort.SliceStable(res.Rules, func(a, b int) bool {
		ka, kb := res.Rules[a].Rule.Kind(), res.Rules[b].Rule.Kind()
		if ka != kb {
			return ka == KindCausal
		}
		return res.Rules[a].Signature < res.Rules[b].Signature
	})
	for i, r := range res.Rules {
		id := fmt.Sprintf("r-%04d", i+1)
		if r.Rule.Causal != nil {
			r.Rule.Causal.ID = id
		} else {
			r.Rule.Batch.ID = id
		}
	}
	return res
}

// groupDiag summarizes what the run examined of one group's traffic: the
// events, the objects and whether states were observed (a state field in
// clear that changes over time), so that the console does not ask for an
// approval when the states already leave as codes.
func (m *miner) groupDiag(group string) GroupDiag {
	l := m.l
	g := GroupDiag{Group: group, Events: l.Events(), Objects: l.Objects(), Subjects: len(l.subj), Entities: len(m.ents)}
	if l.Events() > 0 && l.Last.After(l.First) {
		g.ObservedSeconds = int64(l.Last.Sub(l.First) / time.Second)
	}
	clear, states := map[string]bool{}, map[string]bool{}
	for i, e := range m.ents {
		for _, f := range e.clearFields {
			clear[f] = true
		}
		if e.stateField != "" {
			states[e.stateField] = true
		}
		if lf := m.lifes[i]; lf != nil && len(lf.succ) > 0 {
			g.Lifecycles++
		}
	}
	g.StatesObserved = len(states) > 0
	g.StateFields = sortedKeys(states)
	g.ClearFields = sortedKeys(clear)
	if len(g.ClearFields) > 4*maxClearFields {
		g.ClearFields = g.ClearFields[:4*maxClearFields]
	}
	return g
}
