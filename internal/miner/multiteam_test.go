package miner

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/world"
)

// Two teams on one console (multi-host lab): group demo with shop-api
// (POST /orders creates an order, a shipment through shipping-ext) and a
// tester's group with orders-api (POST /orders creates an order too, a
// shipment through carrier-ext), the tester with more traffic. Before,
// the entities were named by HMAC domain over all the events: both orders
// became one entity created by orders-api, the demo group's approved rule
// needed orders-api and its world came out empty.

var twoTeamGroups = map[string]string{"src-shop1": "demo", "src-orders1": "tester"}

// testerTraffic is a second shop: orders-api with carrier-ext, captured by
// its own source.
func testerTraffic(seed uint64, customers int) (*sim, string) {
	s := runSim(simConfig{Seed: seed, Customers: customers, Days: 8, Start: simStart})
	for i := range s.xs {
		if s.xs[i].ex.ServiceName == "shop-api" {
			s.xs[i].ex.ServiceName = "orders-api"
		}
	}
	pol := strings.NewReplacer(`"shop-api"`, `"orders-api"`, `"shipping-ext"`, `"carrier-ext"`, `"p-demo"`, `"p-tester"`).Replace(simAuthorPolicy)
	return s, pol
}

func twoTeams(t *testing.T, withTester bool) *simFixture {
	t.Helper()
	demo := runSim(simConfig{Seed: 42, Customers: 600, Days: 8, Start: simStart})
	teams := []simTeam{{xs: demo.xs, policyJSON: simAuthorPolicy, service: "shop-api", source: "src-shop1"}}
	if withTester {
		tester, pol := testerTraffic(43, 900)
		teams = append(teams, simTeam{xs: tester.xs, policyJSON: pol, service: "orders-api", source: "src-orders1"})
	}
	f := ingestTeams(t, teams, simStart, demo.end, t.TempDir())
	t.Cleanup(f.close)
	return f
}

var teamServices = map[string][]string{"demo": {"shop-api", "shipping-ext"}, "tester": {"orders-api", "carrier-ext"}}

// teamOf returns the team whose services hold every service of needs.
func teamOf(needs []string) string {
	for team, svcs := range teamServices {
		ok := true
		for _, s := range needs {
			ok = ok && slices.Contains(svcs, s)
		}
		if ok {
			return team
		}
	}
	return ""
}

func parseDoc(t *testing.T, d *Document, approveAll bool) *world.Rules {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	if approveAll {
		for _, x := range top["rules"].([]any) {
			x.(map[string]any)["status"] = StatusApproved
		}
	}
	if b, err = json.Marshal(top); err != nil {
		t.Fatal(err)
	}
	r, err := world.ParseRules(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// worldEntities generates a world of the team's services and counts its
// entity rows.
func worldEntities(t *testing.T, r *world.Rules, team string) (int, *world.ScopeInfo) {
	t.Helper()
	scoped, info := r.Scope(teamServices[team])
	out, err := world.Generate(&world.Input{Params: world.Params{Seed: 1, Customers: 30, T0: simStart.Add(9 * 24 * time.Hour), Locale: "it"}, Rules: scoped})
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped.IDs) == 0 {
		t.Errorf("world of %s: no rule in scope (excluded %v)", team, info.Excluded)
	}
	return out.Entities, info
}

func TestTwoTeamsKeepTheirOwnEntities(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	f := twoTeams(t, true)
	res, err := MineIn(context.Background(), f.store, time.Time{}, time.Time{}, f.doms, DefaultConfig(), MineOptions{SourceGroups: twoTeamGroups, Now: simStart})
	if err != nil {
		t.Fatal(err)
	}
	doc := res.Document(time.Time{}, nil)
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	orders := map[string]Entity{}
	prefixes := map[string]string{}
	for _, e := range res.Entities {
		if p, dup := prefixes[e.IDPrefix]; dup {
			t.Errorf("entities %s and %s share the id prefix %s", p, e.Name, e.IDPrefix)
		}
		prefixes[e.IDPrefix] = e.Name
		if e.IDDomain == "order" {
			orders[e.Service] = e
		}
	}
	if len(orders) != 2 {
		t.Fatalf("order entities by service: %v (entities %+v)", orders, res.Entities)
	}
	if orders["shop-api"].Name == orders["orders-api"].Name {
		t.Fatalf("one name for two teams' orders: %s", orders["shop-api"].Name)
	}
	t.Logf("names: shop-api %s (%s), orders-api %s (%s)", orders["shop-api"].Name, orders["shop-api"].IDPrefix, orders["orders-api"].Name, orders["orders-api"].IDPrefix)
	r := parseDoc(t, doc, true)
	needs := r.Needs()
	byTeam := map[string]int{}
	sigs := map[string]bool{}
	for _, mm := range res.Rules {
		if sigs[mm.Signature] {
			t.Errorf("signature %s twice", mm.Signature)
		}
		sigs[mm.Signature] = true
		id, _, _, _, _ := mm.Rule.common()
		team := teamOf(needs[*id])
		if team == "" {
			t.Errorf("rule %s (%s) mixes the teams' services: %v", *id, mm.Signature, needs[*id])
		}
		byTeam[team]++
	}
	if byTeam["demo"] == 0 || byTeam["tester"] == 0 {
		t.Fatalf("rules per team: %v", byTeam)
	}
	for _, team := range []string{"demo", "tester"} {
		n, info := worldEntities(t, r, team)
		if n == 0 {
			t.Errorf("world of %s has no entity", team)
		}
		// The other team's rules are left out, never this team's.
		for id, miss := range info.Excluded {
			if teamOf(needs[id]) == team {
				t.Errorf("world of %s leaves out its own rule %s (needs %v)", team, id, miss)
			}
		}
	}
}

// The lab database: the demo group approved its POST /orders rule; then the
// tester's team appeared and a run of the old miner renamed "order" to the
// tester's entity. After the fix the approved rule's "order" is shop-api's
// again (names recovered from the approved rules), the tester's order has
// a name of its own, and the demo world is not empty.
func TestApprovedRuleKeepsItsEntityWhenASecondTeamAppears(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	ctx := context.Background()
	f := twoTeams(t, true)
	repo := NewRepo(f.db, DefaultConfig(), nil)
	now := simStart.Add(9 * 24 * time.Hour)

	// 1. Demo only (the demo source's events), approved.
	demoOnly := map[string]string{"src-shop1": "demo", "src-orders1": "ignored"}
	logs, err := LoadGroups(ctx, f.store, time.Time{}, time.Time{}, f.doms, 0, func(s string) string { return demoOnly[s] }, false)
	if err != nil {
		t.Fatal(err)
	}
	first := MineLogs(map[string]*Log{"demo": logs["demo"]}, DefaultConfig(), nil, now)
	if _, err := repo.Apply(ctx, first, now, now); err != nil {
		t.Fatal(err)
	}
	var approved string
	for _, mm := range first.Rules {
		if mm.Rule.Causal != nil && mm.Rule.Causal.Cause.Service == "shop-api" && mm.Rule.Causal.Cause.Op == "POST /orders" {
			sr, err := repo.List(ctx, StatusDraft)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range sr {
				if s.Signature == mm.Signature {
					approved = *mustID(s.Rule)
				}
			}
		}
	}
	if approved == "" {
		t.Fatal("no POST /orders rule for shop-api")
	}
	if _, err := repo.Approve(ctx, approved, "u-demo", now); err != nil {
		t.Fatal(err)
	}

	// 2. The old miner over everything (one log, no groups, no names) and
	// no stored names: the lab database.
	all, err := Load(ctx, f.store, time.Time{}, time.Time{}, "", f.doms, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Apply(ctx, MineLog(all, DefaultConfig()), now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `DELETE FROM miner_entity_names`); err != nil {
		t.Fatal(err)
	}
	ents, err := repo.Entities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e := entityNamed(ents, "order"); e == nil || e.Service != "orders-api" {
		t.Fatalf("the bug is not reproduced: order is %+v", e)
	}

	// 3. The fixed miner.
	names, err := repo.EntityNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := MineIn(ctx, f.store, time.Time{}, time.Time{}, f.doms, DefaultConfig(), MineOptions{SourceGroups: twoTeamGroups, Names: names, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Apply(ctx, res, now, now); err != nil {
		t.Fatal(err)
	}
	doc, err := repo.Document(ctx, StatusApproved, now)
	if err != nil {
		t.Fatal(err)
	}
	if e := entityNamed(doc.Entities, "order"); e == nil || e.Service != "shop-api" {
		t.Fatalf("order after the fix: %+v", e)
	}
	r := parseDoc(t, doc, false)
	if team := teamOf(r.Needs()[approved]); team != "demo" {
		t.Fatalf("approved %s needs %v", approved, r.Needs()[approved])
	}
	if n, _ := worldEntities(t, r, "demo"); n == 0 {
		t.Fatal("demo world without entities")
	}
	var testerOrder *Entity
	for i, e := range doc.Entities {
		if e.IDDomain == "order" && e.Service == "orders-api" {
			testerOrder = &doc.Entities[i]
		}
	}
	if testerOrder == nil || testerOrder.Name == "order" || testerOrder.IDPrefix == entityNamed(doc.Entities, "order").IDPrefix {
		t.Fatalf("tester's order: %+v", testerOrder)
	}

	// 4. Names stay across runs, whichever team has more traffic.
	names2, err := repo.EntityNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := MineIn(ctx, f.store, time.Time{}, time.Time{}, f.doms, DefaultConfig(), MineOptions{SourceGroups: twoTeamGroups, Names: names2, Now: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res2.Entities {
		if e.IDDomain == "order" && e.Service == "orders-api" && e.Name != testerOrder.Name {
			t.Errorf("tester's order renamed %s -> %s", testerOrder.Name, e.Name)
		}
		if e.Name == "order" && e.Service != "shop-api" {
			t.Errorf("order moved to %s", e.Service)
		}
	}
}

func mustID(r Rule) *string {
	id, _, _, _, _ := r.common()
	return id
}

func entityNamed(es []Entity, name string) *Entity {
	for i := range es {
		if es[i].Name == name {
			return &es[i]
		}
	}
	return nil
}

// Names: the first creator keeps the bare name, a later one is qualified,
// the same service in two groups gets the group, prefixes never collide,
// a stored name of group "" goes to the group that creates it first.
func TestEntityNameBook(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	b := newNameBook([]EntityName{{Name: "order", Domain: "order", Service: "shop-api", IDPrefix: "ORD-SYN-", Created: t0}}, t0.Add(time.Hour))
	got := b.assign([]candidate{
		{group: "tester", domain: "order", service: "orders-api", first: t0},
		{group: "demo", domain: "order", service: "shop-api", first: t0.Add(time.Minute)},
		{group: "other", domain: "order", service: "orders-api", first: t0.Add(2 * time.Minute)},
	})
	want := map[nameKey]string{
		{"demo", "order", "shop-api"}:     "order",
		{"tester", "order", "orders-api"}: "order-orders-api",
		{"other", "order", "orders-api"}:  "order-orders-api-other",
	}
	seen := map[string]bool{}
	for k, n := range want {
		e := got[k]
		if e == nil || e.Name != n {
			t.Errorf("%v: %+v, want %s", k, e, n)
			continue
		}
		if seen[e.IDPrefix] || !regexp.MustCompile(`^[A-Z]{2,5}-SYN-$`).MatchString(e.IDPrefix) {
			t.Errorf("%s: prefix %s", n, e.IDPrefix)
		}
		seen[e.IDPrefix] = true
	}
	if g := got[nameKey{"demo", "order", "shop-api"}]; g.Group != "demo" {
		t.Errorf("stored name not adopted: %+v", g)
	}
	if k := b.sigKey(got[nameKey{"tester", "order", "orders-api"}]); k != "order" {
		t.Errorf("tester sig key %s", k)
	}
	if k := b.sigKey(got[nameKey{"other", "order", "orders-api"}]); k != "order-orders-api-other" {
		t.Errorf("other sig key %s", k)
	}
	// A stored name of group "" still used by the sources of no group is
	// not adopted by a group as well: two entities, two names.
	b2 := newNameBook([]EntityName{{Name: "order", Domain: "order", Service: "shop-api", IDPrefix: "ORD-SYN-", Created: t0}}, t0)
	two := b2.assign([]candidate{{group: "demo", domain: "order", service: "shop-api", first: t0}, {group: "", domain: "order", service: "shop-api", first: t0.Add(time.Second)}})
	if a, c := two[nameKey{"demo", "order", "shop-api"}], two[nameKey{"", "order", "shop-api"}]; a == nil || c == nil || a.Name == c.Name || c.Name != "order" {
		t.Errorf("legacy name reused: %+v %+v", a, c)
	}
	// A long service name stays a valid identifier.
	long := b.assign([]candidate{{group: "g", domain: "order", service: strings.Repeat("very-long-service-", 5)}})
	for _, n := range long {
		if !reIdent.MatchString(n.Name) || len(n.Name) > maxEntityName {
			t.Errorf("long name %q", n.Name)
		}
	}
}
