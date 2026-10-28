package world

import (
	"sort"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Scope of a world: the services of one team.
//
// A console is shared by several teams, each with its own services and rules. A world (and the
// pack built from it) for one team must hold that team's services and rules only: another
// team's rules would drag their services into the pack, and the gate would refuse a pack
// whose rules use a service that is not in it.

// ScopeInfo says what Scope left out.
type ScopeInfo struct {
	// Excluded maps each rule left out to the services it needs that are not in scope.
	Excluded map[string][]string
	// DroppedEntities are the entities left out (a service of theirs, or of an entity they
	// relate to, is not in scope).
	DroppedEntities []string
}

// Needs maps each rule to the services it touches: the service of the cause, and of every
// entity its effects write (the service that owns it, the services that expose it and those of
// the entities it relates to).
func (r *Rules) Needs() map[string][]string {
	out := map[string][]string{}
	for _, c := range r.Causal {
		set := map[string]bool{c.Cause.Service: true}
		for _, e := range c.Effects {
			if e.Respond != nil {
				set[e.Respond.Service] = true
				continue
			}
			r.entityServices(e.Entity, set, map[string]bool{})
		}
		out[c.ID] = sortedKeys(set)
	}
	for _, b := range r.Batch {
		set := map[string]bool{}
		r.entityServices(b.Entity, set, map[string]bool{})
		out[b.ID] = sortedKeys(set)
	}
	return out
}

// EntityNeeds maps each entity to the services it touches.
func (r *Rules) EntityNeeds() map[string][]string {
	out := map[string][]string{}
	for _, e := range r.Entities {
		set := map[string]bool{}
		r.entityServices(e.Name, set, map[string]bool{})
		out[e.Name] = sortedKeys(set)
	}
	return out
}

func (r *Rules) entityServices(name string, set, seen map[string]bool) {
	e := r.ents[name]
	if e == nil || seen[name] {
		return
	}
	seen[name] = true
	if e.Service != "" {
		set[e.Service] = true
	}
	for _, rb := range e.ReadBy {
		if rb.Service != "" {
			set[rb.Service] = true
		}
	}
	for _, u := range e.UpsertedBy {
		if u.Service != "" {
			set[u.Service] = true
		}
	}
	for _, rel := range e.Relations {
		r.entityServices(rel.Entity, set, seen)
	}
}

func missingFrom(need []string, in map[string]bool) []string {
	var out []string
	for _, s := range need {
		if !in[s] {
			out = append(out, s)
		}
	}
	return out
}

// Scope returns the rules restricted to the given services: a rule stays when every service it
// touches is in scope, an entity when every service it touches is. Nothing changes without
// services. The result is a new Rules (the receiver is not modified); its Doc is filtered the
// same way, so the pack's rules.json holds nothing of the services left out.
func (r *Rules) Scope(services []string) (*Rules, *ScopeInfo) {
	info := &ScopeInfo{Excluded: map[string][]string{}}
	if len(services) == 0 {
		return r, info
	}
	in := map[string]bool{}
	for _, s := range services {
		in[s] = true
	}
	out := &Rules{ents: map[string]*pack.Entity{}}
	keepEnt := map[string]bool{}
	for name, need := range r.EntityNeeds() {
		if len(missingFrom(need, in)) == 0 {
			keepEnt[name] = true
		}
	}
	for _, e := range r.Entities {
		if keepEnt[e.Name] {
			out.Entities = append(out.Entities, e)
		} else {
			info.DroppedEntities = append(info.DroppedEntities, e.Name)
		}
	}
	for i := range out.Entities {
		out.ents[out.Entities[i].Name] = &out.Entities[i]
	}
	attrs, attrDocs := scopeAttributes(r, in)
	out.Attributes = attrs
	needs := r.Needs()
	keepRule := map[string]bool{}
	for _, id := range r.IDs {
		if m := missingFrom(needs[id], in); len(m) > 0 {
			info.Excluded[id] = m
			continue
		}
		if m := missingAttributes(r, id, attrs); len(m) > 0 {
			info.Excluded[id] = m // rules v1.9: a customer attribute left out
			continue
		}
		keepRule[id] = true
		out.IDs = append(out.IDs, id)
	}
	for _, c := range r.Causal {
		if keepRule[c.ID] {
			out.Causal = append(out.Causal, c)
		}
	}
	for _, b := range r.Batch {
		if keepRule[b.ID] {
			out.Batch = append(out.Batch, b)
		}
	}
	sort.Strings(info.DroppedEntities)
	// The document: same top-level fields, entities and rules filtered.
	doc := make(map[string]any, len(r.Doc))
	for k, v := range r.Doc {
		doc[k] = v
	}
	ents := []any{}
	if list, ok := r.Doc["entities"].([]any); ok {
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				if n, _ := m["name"].(string); keepEnt[n] {
					ents = append(ents, x)
				}
			}
		}
	}
	rules := []any{}
	if list, ok := r.Doc["rules"].([]any); ok {
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				if id, _ := m["id"].(string); keepRule[id] {
					rules = append(rules, x)
				}
			}
		}
	}
	doc["entities"], doc["rules"] = ents, rules
	scopeExtras(doc, in, keepEnt, attrDocs)
	out.Doc = doc
	return out, info
}
