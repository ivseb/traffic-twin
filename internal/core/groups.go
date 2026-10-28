package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/groupscope"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/world"
)

// Multi-team isolation (usability round 3): the identity of an observed
// service is (group, service), the group of an event is the group of its
// source (fleet.SourceGroups). Every list of the console takes ?group=
// (internal/groupscope); this file holds the pieces of tt-core that join
// the packages: group-scoped contracts for worlds and packs, the policies of
// a group's pack, the rules attributed to groups and the attribution of the
// data stored before groups were tracked.

// serviceGroups maps each observed service to the groups whose sources
// produced it.
func (c *Core) serviceGroups(ctx context.Context) (map[string][]string, error) {
	src, err := c.fleet.SourceGroups(ctx)
	if err != nil {
		return nil, err
	}
	bySvc, err := c.intake.Store().ServiceSources(ctx)
	if err != nil {
		return nil, err
	}
	return groupscope.ServiceGroups(bySvc, src), nil
}

// ContractsIn implements world.GroupContractsSource: the contracts of one
// group's traffic over the mining window.
func (s contractsSource) ContractsIn(ctx context.Context, group string) ([]world.Contract, error) {
	if group == "" {
		return s.Contracts(ctx)
	}
	if s.cache == nil {
		return s.inferIn(ctx, group)
	}
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	now := s.now()
	if e, ok := s.cache.groups[group]; ok && now.Sub(e.at) < liveContractsTTL && !now.Before(e.at) {
		return e.out, nil
	}
	out, err := s.inferIn(ctx, group)
	if err != nil {
		return nil, err
	}
	if s.cache.groups == nil {
		s.cache.groups = map[string]liveEntry{}
	}
	s.cache.groups[group] = liveEntry{at: s.now(), out: out}
	return out, nil
}

func (s contractsSource) inferIn(ctx context.Context, group string) ([]world.Contract, error) {
	now := s.now()
	win := contract.Window{From: now.Add(-s.window), To: now.Add(time.Minute)}
	cs, err := s.eng.LiveIn(ctx, win, group)
	if err != nil {
		return nil, err
	}
	out, err := s.render(cs)
	for i := range out {
		out[i].Group = group
	}
	return out, err
}

// SourcePoliciesIn implements packwriter.GroupPoliciesSource: the signed
// policies serving the groups (a group's pack never names another team's
// policy).
func (w *policyWatcher) SourcePoliciesIn(ctx context.Context, groups []string) ([]client.PolicyRef, error) {
	all, err := w.SourcePolicies(ctx)
	if err != nil {
		return nil, err
	}
	pg, err := w.fleet.PolicyGroups(ctx)
	if err != nil {
		return nil, err
	}
	sel := groupscope.Set(groups)
	var out []client.PolicyRef
	for _, r := range all {
		if sel.Any(pg[r.ID]) {
			out = append(out, r)
		}
	}
	return out, nil
}

// attributeLegacy attributes the data stored before groups were tracked:
// a contract snapshot, an archetype build, a world or a pack of group ""
// whose services were produced by one group only gets that group (the
// attribution goes through the sources, fleet_source_groups). Snapshots of
// a service several groups produced stay of group "" (they mix the groups'
// traffic): the next snapshot run writes one per group. Idempotent.
func (c *Core) attributeLegacy(ctx context.Context) error {
	sg, err := c.serviceGroups(ctx)
	if err != nil {
		return err
	}
	only := func(svc string) string {
		if gs := sg[svc]; len(gs) == 1 {
			return gs[0]
		}
		return ""
	}
	rows, err := c.db.QueryContext(ctx, `SELECT DISTINCT service FROM contract_snapshots WHERE grp = ''`)
	if err != nil {
		return err
	}
	var svcs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		svcs = append(svcs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range svcs {
		g := only(s)
		if g == "" {
			continue
		}
		// A group snapshot of the same window wins (UNIQUE): keep it.
		if _, err := c.db.ExecContext(ctx, `UPDATE OR IGNORE contract_snapshots SET grp = ? WHERE grp = '' AND service = ?`, g, s); err != nil {
			return err
		}
	}
	// Worlds and packs: the group owning every service of their scope.
	wrows, err := c.db.QueryContext(ctx, `SELECT id, services FROM world_worlds WHERE grp = ''`)
	if err != nil {
		return err
	}
	type upd struct{ id, grp string }
	var ws []upd
	for wrows.Next() {
		var id, sj string
		if err := wrows.Scan(&id, &sj); err != nil {
			wrows.Close()
			return err
		}
		var svcs []string
		if json.Unmarshal([]byte(sj), &svcs) == nil && len(svcs) > 0 {
			var lists [][]string
			for _, s := range svcs {
				lists = append(lists, sg[s])
			}
			if common := groupscope.Intersect(lists...); len(common) == 1 {
				ws = append(ws, upd{id, common[0]})
			}
		}
	}
	wrows.Close()
	for _, u := range ws {
		if _, err := c.db.ExecContext(ctx, `UPDATE world_worlds SET grp = ? WHERE id = ? AND grp = ''`, u.grp, u.id); err != nil {
			return err
		}
	}
	// A pack is of the group of its world.
	_, err = c.db.ExecContext(ctx, `UPDATE packwriter_packs SET grp = (SELECT w.grp FROM world_worlds w WHERE w.id = packwriter_packs.world_id),
		groups = json_array((SELECT w.grp FROM world_worlds w WHERE w.id = packwriter_packs.world_id))
		WHERE grp = '' AND EXISTS (SELECT 1 FROM world_worlds w WHERE w.id = packwriter_packs.world_id AND w.grp != '')`)
	return err
}

// ruleHead is the part of a rule the group attribution reads.
type ruleHead struct {
	ID    string `json:"id"`
	Cause *struct {
		Service string `json:"service"`
	} `json:"cause"`
	Entity string `json:"entity"`
}

// ruleNeeds maps each stored rule (any status) to the services it touches:
// its cause and the services of the entities its effects write
// (world.Rules.Needs over the whole rule document).
func (c *Core) ruleNeeds(ctx context.Context) map[string][]string {
	doc, err := c.miner.Repo().Document(ctx, "", c.now())
	if err != nil {
		return nil
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	var top map[string]any
	if json.Unmarshal(b, &top) != nil {
		return nil
	}
	if list, ok := top["rules"].([]any); ok {
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				m["status"] = "approved" // ParseRules keeps approved rules only
			}
		}
	}
	if b, err = json.Marshal(top); err != nil {
		return nil
	}
	r, err := world.ParseRules(b, nil)
	if err != nil {
		return nil
	}
	return r.Needs()
}

// ruleGroups returns the groups a rule belongs to: the groups that produced
// every service it touches. A rule of another team that shares a host
// pattern with this team still touches that team's own service: it stays
// out.
func ruleGroups(raw json.RawMessage, needs map[string][]string, sg map[string][]string) []string {
	var r ruleHead
	if json.Unmarshal(raw, &r) != nil {
		return []string{}
	}
	svcs := needs[r.ID]
	if len(svcs) == 0 && r.Cause != nil && r.Cause.Service != "" {
		svcs = []string{r.Cause.Service}
	}
	var lists [][]string
	for _, s := range svcs {
		lists = append(lists, sg[s])
	}
	out := groupscope.Intersect(lists...)
	if out == nil {
		out = []string{}
	}
	return out
}

// groupRules filters and annotates the miner's rule answers by group:
// GET /api/v1/rules (a list) gets "groups" on each rule and keeps the rules
// of the selected groups; GET /api/v1/rules/{id} gets "groups"; GET
// /api/v1/rules/status keeps the diagnostics of the selected groups'
// services. Rules are attributed through their services (ruleGroups); the
// miner itself knows no group.
func (c *Core) groupRules(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		res := rec.Result()
		body := rec.Body.Bytes()
		copyHeaders := func(n int) {
			for k, v := range res.Header {
				w.Header()[k] = v
			}
			w.Header().Set("Content-Length", strconv.Itoa(n))
			w.WriteHeader(res.StatusCode)
		}
		if res.StatusCode != http.StatusOK {
			copyHeaders(len(body))
			_, _ = w.Write(body)
			return
		}
		sg, err := c.serviceGroups(r.Context())
		if err != nil {
			copyHeaders(len(body))
			_, _ = w.Write(body)
			return
		}
		sel := groupscope.FromRequest(r)
		var out []byte
		var ok bool
		if r.URL.Path == "/api/v1/rules/status" {
			out, ok = filterStatus(body, sg, sel)
		} else {
			out, ok = annotateRules(body, c.ruleNeeds(r.Context()), sg, sel)
		}
		if !ok {
			out = body
		}
		copyHeaders(len(out))
		_, _ = w.Write(out)
	})
}

// annotateRules adds "groups" to a rule or a list of rules (bare array or
// an object with "rules"), keeping the rules of the selected groups.
func annotateRules(body []byte, needs, sg map[string][]string, sel groupscope.Set) ([]byte, bool) {
	trim := bytes.TrimSpace(body)
	one := func(raw json.RawMessage) (map[string]json.RawMessage, []string, bool) {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return nil, nil, false
		}
		gs := ruleGroups(raw, needs, sg)
		b, _ := json.Marshal(gs)
		m["groups"] = b
		return m, gs, true
	}
	filter := func(list []json.RawMessage) []map[string]json.RawMessage {
		out := []map[string]json.RawMessage{}
		for _, raw := range list {
			m, gs, ok := one(raw)
			if ok && sel.Any(gs) {
				out = append(out, m)
			}
		}
		return out
	}
	switch {
	case len(trim) > 0 && trim[0] == '[':
		var list []json.RawMessage
		if json.Unmarshal(trim, &list) != nil {
			return nil, false
		}
		b, err := json.Marshal(filter(list))
		return b, err == nil
	case len(trim) > 0 && trim[0] == '{':
		var obj map[string]json.RawMessage
		if json.Unmarshal(trim, &obj) != nil {
			return nil, false
		}
		if raw, ok := obj["rules"]; ok {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil {
				return nil, false
			}
			b, _ := json.Marshal(filter(list))
			obj["rules"] = b
			out, err := json.Marshal(obj)
			return out, err == nil
		}
		if _, ok := obj["cause"]; ok {
			m, _, ok := one(trim)
			if !ok {
				return nil, false
			}
			out, err := json.Marshal(m)
			return out, err == nil
		}
	}
	return nil, false
}

// inGroupsOf reports whether a service belongs to the selected groups.
func inGroupsOf(sg map[string][]string, sel groupscope.Set, service string) bool {
	return sel.All() || slices.ContainsFunc(sg[service], sel.Has)
}

// filterStatus keeps, in the mining status, the entity and rule
// diagnostics of the selected groups' services.
func filterStatus(body []byte, sg map[string][]string, sel groupscope.Set) ([]byte, bool) {
	if sel.All() {
		return body, true
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return nil, false
	}
	keep := func(key string, svc func(map[string]any) string) {
		raw, ok := obj[key]
		if !ok {
			return
		}
		var list []map[string]any
		if json.Unmarshal(raw, &list) != nil {
			return
		}
		out := []map[string]any{}
		for _, d := range list {
			if s := svc(d); s == "" || inGroupsOf(sg, sel, s) {
				out = append(out, d)
			}
		}
		b, _ := json.Marshal(out)
		obj[key] = b
	}
	keep("entities", func(d map[string]any) string {
		op, _ := d["op"].(string)
		svc, _, _ := strings.Cut(op, " ")
		return svc
	})
	keep("rule_diagnostics", func(d map[string]any) string {
		s, _ := d["service"].(string)
		return s
	})
	keep("candidates", func(d map[string]any) string {
		s, _ := d["service"].(string)
		return s
	})
	// Spec v1.18: candidates, families and test k carry their group.
	keepGroup := func(key string) {
		var list []map[string]any
		if raw, ok := obj[key]; !ok || json.Unmarshal(raw, &list) != nil {
			return
		}
		out := []map[string]any{}
		for _, d := range list {
			if g, _ := d["group"].(string); g == "" || sel.Has(g) {
				out = append(out, d)
			}
		}
		b, _ := json.Marshal(out)
		obj[key] = b
	}
	keepGroup("candidates")
	keepGroup("families")
	if raw, ok := obj["test_k"]; ok {
		var m map[string]int
		if json.Unmarshal(raw, &m) == nil {
			for g := range m {
				if !sel.Has(g) {
					delete(m, g)
				}
			}
			b, _ := json.Marshal(m)
			obj["test_k"] = b
		}
	}
	scopeCoverage(obj, sel)
	out, err := json.Marshal(obj)
	return out, err == nil
}

// scopeCoverage makes the coverage figures of the mining status the
// selected groups' own: "events examined" was the whole console's number
// (identical for every team, and constant while the group's traffic
// grew). The console totals move to events_total / subjects_total.
func scopeCoverage(obj map[string]json.RawMessage, sel groupscope.Set) {
	raw, ok := obj["groups"]
	if !ok {
		return
	}
	var list []map[string]any
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		return // a run stored before the per-group figures existed
	}
	num := func(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }
	kept := []map[string]any{}
	var events, subjects, observed float64
	for _, g := range list {
		name, _ := g["group"].(string)
		if !sel.Has(name) {
			continue
		}
		kept = append(kept, g)
		events += num(g, "events")
		subjects += num(g, "subjects")
		observed = max(observed, num(g, "observed_s"))
	}
	for _, k := range []string{"events", "subjects"} {
		if v, ok := obj[k]; ok {
			obj[k+"_total"] = v
		}
	}
	obj["events"], _ = json.Marshal(int(events))
	obj["subjects"], _ = json.Marshal(int(subjects))
	obj["observed_hours"], _ = json.Marshal(float64(int64(observed/3600*100+0.5)) / 100)
	obj["groups"], _ = json.Marshal(kept)
}
