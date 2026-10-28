package miner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/graphql"
)

// ---- C2: effects of the writes that do not create ----

// contract is the state of one pre-existing object of the synthetic
// application (invented data only).
type contract struct {
	id, status, plan, addr, tier string
	favorite                     bool
}

func (c *contract) body() map[string]any {
	return map[string]any{"id": c.id, "status": keep(c.status), "plan": keep(c.plan), "favorite": c.favorite,
		"addressId": c.addr, "tier": c.tier}
}

// contractApp: every user owns two contracts nobody creates in the window;
// the app lists them and reads them by id. act runs the writes of a user
// (u, its contracts, the traffic) between the reads.
type contractApp struct {
	tr    *traffic
	users int
	cs    [][]*contract
}

func newContractApp(users int) *contractApp {
	a := &contractApp{tr: newTraffic(), users: users}
	for u := 0; u < users; u++ {
		var cs []*contract
		for k := 0; k < 2; k++ {
			n := 2*u + k
			cs = append(cs, &contract{id: tok("contract", n), status: "ACTIVE", plan: []string{"BRONZE", "SILVER"}[n%2],
				addr: tok("address", n), tier: "num:0-50", favorite: n%2 == 0})
		}
		a.cs = append(a.cs, cs)
	}
	return a
}

func (a *contractApp) list(u int) {
	var items []any
	for _, c := range a.cs[u] {
		items = append(items, c.body())
	}
	a.tr.add(xcall{op: "GET /contracts", user: user(u), resp: map[string]any{"items": items, "count": len(items)}})
}

func (a *contractApp) read(u, k int) {
	c := a.cs[u][k]
	a.tr.add(xcall{op: "GET /contracts/{id}", path: "/contracts/{" + c.id + "}", user: user(u), resp: c.body()})
}

func (a *contractApp) write(u, k int, op, suffix string, req any) {
	c := a.cs[u][k]
	path := "/contracts/{" + c.id + "}" + suffix
	a.tr.add(xcall{op: op, path: path, user: user(u), req: req, resp: map[string]any{"ok": true}})
}

// run gives every user: a list, then for each round a write on one of its
// contracts followed by a list and a read by id.
func (a *contractApp) run(rounds int, w func(u, k, round int)) *traffic {
	for u := 0; u < a.users; u++ {
		a.list(u)
		a.read(u, 0)
		for r := 0; r < rounds; r++ {
			k := r % 2
			w(u, k, r)
			a.list(u)
			a.read(u, k)
		}
	}
	return a.tr
}

func updateRuleOf(res *Result, op string) *CausalRule {
	for _, r := range res.Rules {
		if c := r.Rule.Causal; c != nil && c.Cause.Op == op && strings.HasSuffix(r.Signature, "|update") {
			return c
		}
	}
	return nil
}

func setOf(t *testing.T, c *CausalRule, id string) map[string]any {
	t.Helper()
	for _, e := range c.Effects {
		if e.ID == id {
			return e.Set
		}
	}
	t.Fatalf("no effect %s in %+v", id, c.Effects)
	return nil
}

func TestUpdateConstantSet(t *testing.T) {
	a := newContractApp(30)
	tr := a.run(1, func(u, k, _ int) {
		a.write(u, k, "POST /contracts/{id}/suspend", "/suspend", nil)
		a.cs[u][k].status = "SUSPENDED"
	})
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "POST /contracts/{id}/suspend")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if b := c.Cause.Bind["contract"]; b.From != "req.path" || b.Name != "id" {
		t.Fatalf("bind: %+v", c.Cause.Bind)
	}
	if len(c.Effects) != 1 || c.Effects[0].TargetID != "${contract}" || c.Effects[0].After.Single != "0s" {
		t.Fatalf("effects: %+v", c.Effects)
	}
	if s := setOf(t, c, "contract-updated"); len(s) != 1 || s["status"] != "SUSPENDED" {
		t.Fatalf("set: %+v", s)
	}
	if len(c.Outcomes) != 1 || c.Outcomes[0].P != 1 || c.Evidence.Counts.DistinctSubjects != 30 {
		t.Fatalf("outcomes/evidence: %+v %+v", c.Outcomes, c.Evidence.Counts)
	}
	if c.Status != StatusDraft || c.Origin != "" {
		t.Fatalf("an update is a mined draft: %+v", c)
	}
}

func TestUpdateCopiesRequestToken(t *testing.T) {
	a := newContractApp(30)
	next := 1000
	tr := a.run(2, func(u, k, _ int) {
		next++
		addr := tok("address", next)
		a.write(u, k, "PUT /contracts/{id}/address", "/address", map[string]any{"addressId": addr, "note": keep("moving")})
		a.cs[u][k].addr = addr
	})
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "PUT /contracts/{id}/address")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	s := setOf(t, c, "contract-updated")
	v, _ := s["addressId"].(string)
	name := strings.TrimSuffix(strings.TrimPrefix(v, "${"), "}")
	if r, ok := c.Cause.Bind[name]; !ok || r.From != "req.body" || r.Path != "$.addressId" {
		t.Fatalf("addressId must copy the request token: set %+v bind %+v", s, c.Cause.Bind)
	}
	if _, ok := s["note"]; ok || len(s) != 1 {
		t.Fatalf("only the changed field: %+v", s)
	}
}

func TestUpdateCopiesRequestCode(t *testing.T) {
	a := newContractApp(30)
	plans := []string{"GOLD", "SILVER", "BRONZE"}
	tr := a.run(2, func(u, k, r int) {
		p := plans[(u+r)%3]
		if p == a.cs[u][k].plan {
			p = plans[(u+r+1)%3]
		}
		a.write(u, k, "PATCH /contracts/{id}", "", map[string]any{"plan": keep(p)})
		a.cs[u][k].plan = p
	})
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "PATCH /contracts/{id}")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	s := setOf(t, c, "contract-updated")
	if s["plan"] != "${plan}" || c.Cause.Bind["plan"] != (Ref{From: "req.body", Path: "$.plan"}) {
		t.Fatalf("plan copies the request: set %+v bind %+v", s, c.Cause.Bind)
	}
}

func TestUpdateToggle(t *testing.T) {
	a := newContractApp(30)
	tr := a.run(3, func(u, k, _ int) {
		a.write(u, k, "POST /contracts/{id}/favorite", "/favorite", nil)
		a.cs[u][k].favorite = !a.cs[u][k].favorite
	})
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "POST /contracts/{id}/favorite")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if s := setOf(t, c, "contract-updated"); s["favorite"] != "${not:favorite}" {
		t.Fatalf("toggle: %+v", s)
	}
}

func TestUpdateNumericBucket(t *testing.T) {
	a := newContractApp(30)
	tr := a.run(1, func(u, k, _ int) {
		a.write(u, k, "POST /contracts/{id}/upgrade", "/upgrade", nil)
		a.cs[u][k].tier = "num:50-100"
	})
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "POST /contracts/{id}/upgrade")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if s := setOf(t, c, "contract-updated"); s["tier"] != json.Number("50") {
		t.Fatalf("a number inside the bucket: %+v (%T)", s, s["tier"])
	}
}

// The change shows only from the second read after the write (a cache):
// a figurative delay of the order of minutes.
func TestUpdateDelayedVisibility(t *testing.T) {
	a := newContractApp(30)
	tr := a.tr
	for u := 0; u < a.users; u++ {
		a.list(u)
		c := a.cs[u][0]
		a.write(u, 0, "POST /contracts/{id}/renew", "/renew", nil)
		a.read(u, 0) // still ACTIVE
		c.status = "RENEWED"
		a.read(u, 0)
		a.list(u)
	}
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "POST /contracts/{id}/renew")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if len(c.Effects) != 1 || c.Effects[0].ID != "contract-updated-later" || c.Effects[0].Set["status"] != "RENEWED" {
		t.Fatalf("effects: %+v", c.Effects)
	}
	if d := c.Effects[0].After; !d.IsRange() || d.Min != "1m" || d.Max != "59m" || c.Evidence.Hints.Magnitude["contract-updated-later"] != MagMinutes {
		t.Fatalf("delay: %+v hints %+v", d, c.Evidence.Hints)
	}
}

func TestNoUpdateFromUnrelatedWrites(t *testing.T) {
	// A write that cites the contract and changes nothing.
	a := newContractApp(30)
	res := a.run(2, func(u, k, _ int) {
		a.write(u, k, "POST /contracts/{id}/ping", "/ping", nil)
	}).mine(t, smallK(), MineOptions{})
	if c := updateRuleOf(res, "POST /contracts/{id}/ping"); c != nil {
		t.Fatalf("a write that changes nothing: %+v", c)
	}
	// A write after which the status takes a value at random.
	a = newContractApp(30)
	sts := []string{"ACTIVE", "SUSPENDED", "CLOSED", "PENDING"}
	res = a.run(3, func(u, k, r int) {
		a.write(u, k, "POST /contracts/{id}/sync", "/sync", nil)
		a.cs[u][k].status = sts[(u*7+r*3+k)%4]
	}).mine(t, smallK(), MineOptions{})
	if c := updateRuleOf(res, "POST /contracts/{id}/sync"); c != nil {
		t.Fatalf("random values are no effect: %+v", c)
	}
	// Below k: 3 users.
	a = newContractApp(3)
	res = a.run(1, func(u, k, _ int) {
		a.write(u, k, "POST /contracts/{id}/suspend", "/suspend", nil)
		a.cs[u][k].status = "SUSPENDED"
	}).mine(t, smallK(), MineOptions{})
	if c := updateRuleOf(res, "POST /contracts/{id}/suspend"); c != nil {
		t.Fatalf("update with 3 users < k: %+v", c)
	}
}

// ---- C11: a read with an effect ----

// notificationsApp: every user has four notifications; it lists them,
// opens one (GET by id), and the list then shows it read. The unopened
// ones stay unread across the lists (the comparison without the read).
func TestReadWithEffect(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		read := make([]bool, 4)
		ids := make([]string, 4)
		for k := range ids {
			ids[k] = tok("notification", 4*u+k)
		}
		list := func() {
			var items []any
			for k, id := range ids {
				items = append(items, map[string]any{"id": id, "read": read[k], "kind": keep("INFO")})
			}
			tr.add(xcall{op: "GET /notifications", user: user(u), resp: map[string]any{"items": items}})
		}
		list()
		list()
		for k := 0; k < 2; k++ {
			tr.add(xcall{op: "GET /notifications/{id}", path: "/notifications/{" + ids[k] + "}", user: user(u),
				resp: map[string]any{"id": ids[k], "read": read[k], "kind": keep("INFO")}})
			read[k] = true
			list()
			list()
		}
	}
	res := tr.mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "GET /notifications/{id}")
	if c == nil {
		t.Fatalf("no rule for the read: %+v", res.Diag.Rules)
	}
	if s := setOf(t, c, "notification-updated"); s["read"] != true || c.Effects[0].TargetID != "${notification}" {
		t.Fatalf("read sets read=true: %+v", c.Effects)
	}
	// The list read is no cause: it does not cite a notification.
	if c := updateRuleOf(res, "GET /notifications"); c != nil {
		t.Fatalf("list: %+v", c)
	}
}

// A read polled at every turn of an object that moves on its own is not
// a cause: without observations free of the read to compare, a read is
// never taken for one.
func TestReadWithoutEffectWhenTheObjectMovesOnItsOwn(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		id := tok("parcel", u)
		tr.add(xcall{op: "POST /parcels", status: 201, user: user(u), req: map[string]any{"size": keep("S")},
			resp: map[string]any{"id": id, "status": keep("QUEUED")}})
		for k := 0; k < 4; k++ {
			st := "QUEUED"
			if k >= 1 {
				st = "SENT"
			}
			tr.add(xcall{op: "GET /parcels/{id}", path: "/parcels/{" + id + "}", user: user(u), resp: map[string]any{"id": id, "status": keep(st)}})
		}
	}
	res := tr.mine(t, smallK(), MineOptions{})
	if c := updateRuleOf(res, "GET /parcels/{id}"); c != nil {
		t.Fatalf("a poll is not the cause of the lifecycle: %+v", c)
	}
}

// ---- lifecycle transitions attributed to the write ----

// Orders are created PENDING and become CONFIRMED on their own; a third of
// them is cancelled by the user. The cancellation is the effect of the
// write, not a spontaneous outcome of the creation, and the spontaneous
// step is guarded so that it never undoes it.
func TestTransitionAttributedToWrite(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 60; u++ {
		id := tok("order", u)
		tr.add(xcall{op: "POST /orders", status: 201, user: user(u), req: map[string]any{"sku": keep("A")},
			resp: map[string]any{"id": id, "status": keep("PENDING")}})
		get := func(st string) {
			tr.add(xcall{op: "GET /orders/{id}", path: "/orders/{" + id + "}", user: user(u), resp: map[string]any{"id": id, "status": keep(st)}})
		}
		list := func(st string) {
			tr.add(xcall{op: "GET /orders", user: user(u), resp: map[string]any{"items": []any{map[string]any{"id": id, "status": keep(st)}}}})
		}
		get("PENDING")
		if u%3 == 0 {
			tr.add(xcall{op: "POST /orders/{id}/cancel", path: "/orders/{" + id + "}/cancel", user: user(u), resp: map[string]any{"ok": true}})
			list("CANCELLED")
			get("CANCELLED")
			continue
		}
		list("PENDING")
		get("CONFIRMED")
		list("CONFIRMED")
	}
	cfg := smallK()
	res := tr.mine(t, cfg, MineOptions{})
	c := updateRuleOf(res, "POST /orders/{id}/cancel")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if s := setOf(t, c, "order-updated"); s["status"] != "CANCELLED" {
		t.Fatalf("cancel: %+v", s)
	}
	var cr *CausalRule
	for _, r := range res.Rules {
		if x := r.Rule.Causal; x != nil && x.Cause.Op == "POST /orders" {
			cr = x
		}
	}
	if cr == nil {
		t.Fatalf("no creation rule: %+v", res.Diag.Rules)
	}
	confirmed := false
	for _, e := range cr.Effects {
		if e.Set["status"] == "CANCELLED" {
			t.Fatalf("the cancellation is not a spontaneous outcome: %+v", cr.Effects)
		}
		if e.Set["status"] == "CONFIRMED" {
			confirmed = true
			if e.Where == nil || e.Where["status"] != "PENDING" {
				t.Fatalf("the spontaneous step must be guarded: %+v", e)
			}
		}
	}
	if !confirmed {
		t.Fatalf("the spontaneous step is gone: %+v", cr.Effects)
	}
	if updateRuleOf(res, "GET /orders/{id}") != nil {
		t.Fatalf("the read is no cause of the confirmation")
	}
	for _, o := range cr.Outcomes {
		if strings.Contains(o.Name, "cancel") {
			t.Fatalf("outcome %s", o.Name)
		}
	}
}

// ---- lifecycle on a boolean ----

func TestBooleanLifecycle(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		id := tok("invoice", u)
		tr.add(xcall{op: "POST /invoices", status: 201, user: user(u), req: map[string]any{"amount": 10},
			resp: map[string]any{"id": id, "paid": false}})
		for k := 0; k < 3; k++ {
			tr.add(xcall{op: "GET /invoices/{id}", path: "/invoices/{" + id + "}", user: user(u), resp: map[string]any{"id": id, "paid": k > 0}})
		}
	}
	cfg := smallK()
	cfg.MinHorizon = 10 * 60 * 1e9
	res := tr.mine(t, cfg, MineOptions{})
	var cr *CausalRule
	for _, r := range res.Rules {
		if x := r.Rule.Causal; x != nil && x.Cause.Op == "POST /invoices" {
			cr = x
		}
	}
	if cr == nil {
		t.Fatalf("no creation rule: %+v", res.Diag.Rules)
	}
	found := false
	for _, e := range cr.Effects {
		found = found || e.Set["paid"] == true
	}
	if !found {
		t.Fatalf("paid false → true is the lifecycle: %+v", cr.Effects)
	}
}

// ---- C16: GraphQL selectors by field and owner, nested lists ----

func gqlDoc(t *testing.T, src string) string {
	t.Helper()
	sh, ok := graphql.Shape(src)
	if !ok {
		t.Fatalf("shape of %q", src)
	}
	return "gql:" + sh.Shape
}

func TestGraphQLSelectorsByFieldAndOwner(t *testing.T) {
	byOwner := gqlDoc(t, "query GetContracts($ownerId: ID!) { contracts(ownerId: $ownerId) { items { id status productId } count } }")
	byProduct := gqlDoc(t, "query ContractsByProduct($productId: ID!) { contracts(productId: $productId) { items { id status productId } count } }")
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		owner := tok("customer", u)
		var items []any
		for k := 0; k < 2; k++ {
			items = append(items, map[string]any{"id": tok("contract", 2*u+k), "status": keep("ACTIVE"), "productId": tok("product", 2*u+k)})
		}
		for r := 0; r < 2; r++ {
			tr.add(xcall{op: "POST /graphql#GetContracts", path: "/graphql", user: user(u),
				req:  map[string]any{"query": byOwner, "operationName": keep("GetContracts"), "variables": map[string]any{"ownerId": owner}},
				resp: map[string]any{"data": map[string]any{"contracts": map[string]any{"items": items, "count": len(items)}}}})
		}
		for k := 0; k < 2; k++ {
			tr.add(xcall{op: "POST /graphql#ContractsByProduct", path: "/graphql", user: user(u),
				req: map[string]any{"query": byProduct, "operationName": keep("ContractsByProduct"),
					"variables": map[string]any{"productId": tok("product", 2*u+k)}},
				resp: map[string]any{"data": map[string]any{"contracts": map[string]any{"items": []any{items[k]}, "count": 1}}}})
		}
	}
	res := tr.mine(t, smallK(), MineOptions{})
	e := entOf(res, "contract")
	if e == nil {
		t.Fatalf("no entity: %+v %+v", res.Entities, res.Diag.Entities)
	}
	own := readOf(e, "POST /graphql#GetContracts")
	if own == nil || own.At.Path != "$.data.contracts.items[*]" || own.By == nil || !own.By.Owner || own.By.Path != "$.variables.ownerId" {
		t.Fatalf("by owner: %+v (by %+v)", own, own)
	}
	if own.List == nil || own.List.Count != "$.data.contracts.count" {
		t.Fatalf("nested list count: %+v", own.List)
	}
	prod := readOf(e, "POST /graphql#ContractsByProduct")
	if prod == nil || prod.By == nil || prod.By.Field != "productId" || prod.By.Path != "$.variables.productId" || prod.At.Path != "$.data.contracts.items[*]" {
		t.Fatalf("by field: %+v (by %+v)", prod, prod)
	}
}
