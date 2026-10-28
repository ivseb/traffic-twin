package core

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/fleet"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/packwriter"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// policyWatcher follows the signed policy versions known to Fleet and keeps
// the components that read them in step: contract inference hints (HMAC
// domains, bucket bounds), the miner's domain resolver and the list of
// policies a pack's data were captured under (the gate's reverse-HMAC
// check). Signed bodies are immutable, so only new hashes need work.
type policyWatcher struct {
	fleet *fleet.Fleet
	log   *slog.Logger
	eng   *contract.Engine
	doms  *miner.PolicyDomains

	mu       sync.Mutex
	known    map[string]*policy.Policy
	refs     []client.PolicyRef
	interval time.Duration
}

var _ packwriter.PoliciesSource = (*policyWatcher)(nil)

func newPolicyWatcher(f *fleet.Fleet, log *slog.Logger) *policyWatcher {
	return &policyWatcher{fleet: f, log: log, doms: miner.NewPolicyDomains(), known: map[string]*policy.Policy{}, interval: 2 * time.Second}
}

// Hints returns the current contract hints.
func (w *policyWatcher) Hints() contract.Hints {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hintsLocked()
}

func (w *policyWatcher) hintsLocked() contract.Hints {
	hashes := make([]string, 0, len(w.known))
	for h := range w.known {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	ps := make([]*policy.Policy, 0, len(hashes))
	for _, h := range hashes {
		ps = append(ps, w.known[h])
	}
	// Newest versions first: PolicyHints takes the first policy that
	// knows a location.
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].PolicyID != ps[j].PolicyID {
			return ps[i].PolicyID < ps[j].PolicyID
		}
		return ps[i].Version > ps[j].Version
	})
	return contract.PolicyHints(ps...)
}

// Domains is the miner's resolver, filled as policies are signed.
func (w *policyWatcher) Domains() *miner.PolicyDomains { return w.doms }

// Refresh picks up newly signed versions now.
func (w *policyWatcher) Refresh() {
	hashes := w.fleet.KnownPolicyHashes()
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := false
	for _, h := range hashes {
		if _, ok := w.known[h]; ok {
			continue
		}
		body, ok := w.fleet.SignedPolicyBody(h)
		if !ok {
			continue
		}
		p, err := policy.DecodeBody(body)
		if err != nil {
			w.log.Error("signed policy cannot be decoded", "hash", h)
			continue
		}
		w.known[h] = p
		w.doms.Add(h, p)
		w.refs = append(w.refs, client.PolicyRef{ID: p.PolicyID, Version: p.Version})
		changed = true
	}
	if !changed {
		return
	}
	slices.SortFunc(w.refs, func(a, b client.PolicyRef) int {
		if a.ID != b.ID {
			if a.ID < b.ID {
				return -1
			}
			return 1
		}
		return int(a.Version - b.Version)
	})
	w.refs = slices.Compact(w.refs)
	if w.eng != nil {
		w.eng.SetHints(w.hintsLocked())
	}
}

// Run refreshes periodically until ctx is done.
func (w *policyWatcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		w.Refresh()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SourcePolicies implements packwriter.PoliciesSource: every signed policy
// version (events of older versions may be in the pack's window).
func (w *policyWatcher) SourcePolicies(context.Context) ([]client.PolicyRef, error) {
	w.Refresh()
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.refs), nil
}

// watchSources emits source.problem when a source reports a problem it did
// not report at the previous pass (Fleet's problem codes, never values).
func (c *Core) watchSources(ctx context.Context) {
	seen := map[string]bool{}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ss, err := c.fleet.ListSources(ctx, "")
		if err != nil {
			continue
		}
		cur := map[string]bool{}
		for _, s := range ss {
			for _, p := range s.Problems {
				k := s.SourceID + "\x00" + p.Code
				cur[k] = true
				if !seen[k] {
					c.alerts.emit(ctx, "source.problem", map[string]any{"source_id": s.SourceID, "group": s.Group,
						"service": s.ServiceName, "problem": p.Code})
				}
			}
		}
		seen = cur
	}
}
