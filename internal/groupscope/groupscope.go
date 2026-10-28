// Package groupscope is the group (team) dimension of the shared console.
//
// A console is shared by several teams; each source belongs to one group
// (fleet_sources.grp, kept in fleet_source_groups after the source row is
// deleted). The group of an event is the group of its source. Every view of
// the observed traffic (services, hosts, contracts, archetypes, worlds,
// packs, rules, gaps, alerts, quarantine) can be restricted to one or more
// groups with the query parameter group (repeated or comma-separated);
// without it the view covers every group and its rows carry their group.
//
// Two groups that call the same host pattern (two teams with a fake API on
// 127.0.0.1:9301) or that name a service the same way are two different
// services: the identity of an observed service is (group, service).
package groupscope

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// Param is the query parameter that selects the groups.
const Param = "group"

// FromRequest returns the groups selected by the request (sorted, without
// duplicates), or nil for every group.
func FromRequest(r *http.Request) Set {
	if r == nil {
		return nil
	}
	return Parse(r.URL.Query()[Param])
}

// Parse normalizes group values (repeated or comma-separated).
func Parse(vals []string) Set {
	seen := map[string]bool{}
	var out []string
	for _, v := range vals {
		for _, g := range strings.Split(v, ",") {
			if g = strings.TrimSpace(g); g != "" && !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Resolver attributes sources to groups (fleet implements it).
type Resolver interface {
	// SourceGroups maps every source id ever enrolled to its group.
	SourceGroups(ctx context.Context) (map[string]string, error)
}

// Func adapts a function to Resolver.
type Func func(ctx context.Context) (map[string]string, error)

// SourceGroups implements Resolver.
func (f Func) SourceGroups(ctx context.Context) (map[string]string, error) { return f(ctx) }

// Set is a selection of groups (nil or empty: every group).
type Set []string

// All reports whether the set selects every group.
func (s Set) All() bool { return len(s) == 0 }

// Has reports whether group g is selected (always true for every group).
func (s Set) Has(g string) bool {
	if len(s) == 0 {
		return true
	}
	for _, x := range s {
		if x == g {
			return true
		}
	}
	return false
}

// Any reports whether one of the groups is selected (true for every group;
// false for an empty list under a filter).
func (s Set) Any(groups []string) bool {
	if len(s) == 0 {
		return true
	}
	for _, g := range groups {
		if s.Has(g) {
			return true
		}
	}
	return false
}

// Sources returns the ids of the sources of the selected groups, sorted
// (nil for every group, a non-nil empty slice when no source matches).
func (s Set) Sources(m map[string]string) []string {
	if len(s) == 0 {
		return nil
	}
	out := []string{}
	for id, g := range m {
		if s.Has(g) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// BySource groups source ids by group.
func BySource(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for id, g := range m {
		out[g] = append(out[g], id)
	}
	for _, ids := range out {
		sort.Strings(ids)
	}
	return out
}

// ServiceGroups maps each service to the groups whose sources produced it,
// from the (service -> sources) index of the store.
func ServiceGroups(bySvc map[string][]string, src map[string]string) map[string][]string {
	out := map[string][]string{}
	for svc, ids := range bySvc {
		seen := map[string]bool{}
		gs := []string{}
		for _, id := range ids {
			if g := src[id]; g != "" && !seen[g] {
				seen[g] = true
				gs = append(gs, g)
			}
		}
		sort.Strings(gs)
		out[svc] = gs
	}
	return out
}

// Intersect returns the groups present in every list (nil when lists is
// empty): the groups a rule that touches several services belongs to.
func Intersect(lists ...[]string) []string {
	if len(lists) == 0 {
		return nil
	}
	cnt := map[string]int{}
	for _, l := range lists {
		seen := map[string]bool{}
		for _, g := range l {
			if !seen[g] {
				seen[g] = true
				cnt[g]++
			}
		}
	}
	out := []string{}
	for g, n := range cnt {
		if n == len(lists) {
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}
