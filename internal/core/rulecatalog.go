package core

import (
	"context"
	"sort"
	"sync"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/miner"
)

// ruleContracts gives the miner the pack-safe contracts that rules written
// by hand are checked against, restricted to the traffic of the selected
// groups.
//
// Each (group, service) contributes its newest stored snapshot (the same
// model the contracts page shows: no event is read), rendered once and kept
// while the snapshot stays the newest; a service of the group that has no
// snapshot yet is previewed from that group's sources only (the engine
// caches the preview for a few seconds). The earlier version inferred every
// contract of the console from the raw events of the whole mining window
// (about 100 s with 1.25 M events) and merged services by name, so a team
// saw the operations of another team's service of the same name.
type ruleContracts struct {
	c   *Core
	src contractsSource

	mu   sync.Mutex
	docs map[ruleDocKey]miner.ContractDoc
}

// ruleDocKey identifies a rendered snapshot.
type ruleDocKey struct {
	group, service, snapshot string
}

// maxRuleDocs bounds the rendered documents kept.
const maxRuleDocs = 512

func (r *ruleContracts) ContractDocs(ctx context.Context, groups []string) ([]miner.ContractDoc, error) {
	eng := r.src.eng
	if len(groups) == 0 {
		gs, err := eng.GroupSources(ctx)
		if err != nil {
			return nil, err
		}
		for g := range gs {
			groups = append(groups, g)
		}
		sort.Strings(groups)
	}
	refs, err := eng.Snapshots().LatestRefs(ctx)
	if err != nil {
		return nil, err
	}
	sg, err := r.c.serviceGroups(ctx)
	if err != nil {
		return nil, err
	}
	replaced, err := r.c.replacedBy(ctx)
	if err != nil {
		return nil, err
	}
	var out []miner.ContractDoc
	for _, g := range groups {
		have := map[string]bool{}
		for _, ref := range refs {
			if ref.Group != g || ref.Ops == 0 {
				continue
			}
			have[ref.Service] = true
			if replaced(g, ref.Service) != "" {
				continue // an old host:<pattern> row the group declared since: history
			}
			doc, err := r.snapshotDoc(ctx, ref)
			if err != nil {
				return nil, err
			}
			out = append(out, doc)
		}
		// Services of the group's traffic not snapshotted yet. For group ""
		// (sources no group claims: a console without teams) those whose
		// sources are all unattributed, previewed over every source.
		var missing []string
		for svc, owners := range sg {
			mine := containsStr(owners, g)
			if g == "" {
				mine = len(owners) == 0
			}
			if !have[svc] && mine && replaced(g, svc) == "" {
				missing = append(missing, svc)
			}
		}
		sort.Strings(missing)
		var scope groupscope.Set
		if g != "" {
			scope = groupscope.Set{g}
		}
		for _, svc := range missing {
			c, err := eng.PreviewIn(ctx, scope, svc)
			if err != nil {
				return nil, err
			}
			if c == nil || len(c.Ops) == 0 {
				continue
			}
			ws, err := r.src.render([]*contract.Contract{c})
			if err != nil {
				return nil, err
			}
			for _, w := range ws {
				out = append(out, miner.ContractDoc{Service: w.Service, Doc: w.Doc})
			}
		}
	}
	return out, nil
}

// snapshotDoc renders (or recalls) the pack-safe document of a snapshot.
func (r *ruleContracts) snapshotDoc(ctx context.Context, ref contract.SnapshotInfo) (miner.ContractDoc, error) {
	k := ruleDocKey{ref.Group, ref.Service, ref.SnapshotID}
	r.mu.Lock()
	d, ok := r.docs[k]
	r.mu.Unlock()
	if ok {
		return d, nil
	}
	snap, err := r.src.eng.Snapshots().GetIn(ctx, ref.Group, ref.Service, ref.SnapshotID)
	if err != nil {
		return miner.ContractDoc{}, err
	}
	ws, err := r.src.render([]*contract.Contract{snap.Contract})
	if err != nil {
		return miner.ContractDoc{}, err
	}
	d = miner.ContractDoc{Service: ref.Service}
	if len(ws) > 0 {
		d.Doc = ws[0].Doc
	}
	r.mu.Lock()
	if r.docs == nil || len(r.docs) >= maxRuleDocs {
		r.docs = map[ruleDocKey]miner.ContractDoc{}
	}
	r.docs[k] = d
	r.mu.Unlock()
	return d, nil
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
