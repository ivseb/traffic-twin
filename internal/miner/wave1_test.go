package miner

import (
	"strings"
	"testing"
)

// ---- C1: pre-existing entities per user ----

// contractsTraffic: every user owns 0..4 contracts nobody creates in the
// window; the app lists them and reads them by id. A catalog of products is
// read by everybody (not per user).
func contractsTraffic(users int) *traffic {
	tr := newTraffic()
	next := 0
	for u := 0; u < users; u++ {
		n := u % 5
		var items []any
		var ids []string
		for k := 0; k < n; k++ {
			next++
			id := tok("contract", next)
			ids = append(ids, id)
			st := "ACTIVE"
			if k%3 == 2 {
				st = "SUSPENDED"
			}
			items = append(items, map[string]any{"id": id, "status": keep(st), "productId": tok("product", k%3)})
		}
		if items == nil {
			items = []any{}
		}
		tr.add(xcall{op: "GET /contracts", user: user(u), resp: map[string]any{"items": items, "count": len(items)}})
		for k, id := range ids {
			st := "ACTIVE"
			if k%3 == 2 {
				st = "SUSPENDED"
			}
			tr.add(xcall{op: "GET /contracts/{id}", path: "/contracts/{" + id + "}", user: user(u),
				resp: map[string]any{"id": id, "status": keep(st), "productId": tok("product", k%3)}})
			tr.add(xcall{op: "GET /contracts/{id}", path: "/contracts/{" + id + "}", user: user(u),
				resp: map[string]any{"id": id, "status": keep(st), "productId": tok("product", k%3)}})
		}
		for p := 0; p < 3; p++ {
			tr.add(xcall{op: "GET /products/{id}", path: "/products/{" + tok("product", p) + "}", user: user(u),
				resp: map[string]any{"id": tok("product", p), "kind": keep("BASIC")}})
		}
	}
	return tr
}

func TestSeedEntityPerUser(t *testing.T) {
	cfg := smallK()
	res := contractsTraffic(60).mine(t, cfg, MineOptions{})
	e := entOf(res, "contract")
	if e == nil {
		t.Fatalf("no seed entity: %+v", res.Entities)
	}
	if e.CreatedBy != nil || e.Seed == nil || e.IDField != "id" {
		t.Fatalf("seed entity: %+v seed %+v", e, e.Seed)
	}
	list, byID := readOf(e, "GET /contracts"), readOf(e, "GET /contracts/{id}")
	if list == nil || list.At.Path != "$.items[*]" || list.Scope != "owner" || list.List == nil || list.List.Count != "$.count" {
		t.Fatalf("list read: %+v", list)
	}
	if byID == nil || byID.By == nil || byID.By.Name != "id" || byID.Scope != "owner" {
		t.Fatalf("by-id read: %+v", byID)
	}
	// k-anonymous buckets: each holds at least k subjects; 0 objects is a
	// bucket too (users who listed nothing).
	total := 0.0
	for _, b := range e.Seed.PerCustomer {
		total += b.Share
		if n := b.Share * float64(e.Seed.Subjects); n+0.5 < float64(cfg.KMin) {
			t.Errorf("bucket %s holds %.1f subjects < k", b.N, n)
		}
	}
	if e.Seed.Subjects != 60 || e.Seed.PerCustomer[0].N != "0" || total < 0.999 || total > 1.001 {
		t.Fatalf("seed: %+v", e.Seed)
	}
	if v := e.Seed.Values["status"]; v["ACTIVE"] == 0 || v["SUSPENDED"] == 0 {
		t.Fatalf("seed values: %+v", e.Seed.Values)
	}
	// The catalog is read by everybody: not objects of a user.
	if p := entOf(res, "product"); p != nil {
		t.Fatalf("product became an entity: %+v", p)
	}
	ok := false
	for _, d := range res.Diag.Entities {
		ok = ok || (d.Name == "contract" && d.Code == EntitySeed && d.Accepted)
	}
	if !ok {
		t.Fatalf("no seed diagnostic: %+v", res.Diag.Entities)
	}
}

func TestSeedNeedsKSubjectsAndBucketsMerge(t *testing.T) {
	// Fewer users than k: no entity at all.
	if e := entOf(contractsTraffic(4).mine(t, smallK(), MineOptions{}), "contract"); e != nil {
		t.Fatalf("seed with 4 users < k: %+v", e)
	}
	// 12 users with k=5: buckets of fewer than 5 users merge.
	res := contractsTraffic(12).mine(t, smallK(), MineOptions{})
	e := entOf(res, "contract")
	if e == nil || e.Seed == nil {
		t.Fatalf("no seed: %+v", res.Entities)
	}
	for _, b := range e.Seed.PerCustomer {
		if n := b.Share * float64(e.Seed.Subjects); n+0.5 < 5 {
			t.Fatalf("bucket %s: %.1f subjects (buckets %+v)", b.N, n, e.Seed.PerCustomer)
		}
	}
	if len(e.Seed.PerCustomer) < 2 || !strings.Contains(e.Seed.PerCustomer[0].N, "-") {
		t.Fatalf("buckets not merged: %+v", e.Seed.PerCustomer)
	}
}

func TestSeedNotWhenAWriteCreates(t *testing.T) {
	tr := contractsTraffic(30)
	for u := 0; u < 30; u++ {
		tr.add(xcall{op: "POST /contracts", status: 201, user: user(u), req: map[string]any{"kind": keep("BASIC")},
			resp: map[string]any{"id": tok("contract", 9000+u), "status": keep("ACTIVE")}})
	}
	res := tr.mine(t, smallK(), MineOptions{})
	if e := entOf(res, "contract"); e != nil && e.Seed != nil {
		t.Fatalf("a created domain is never a seed: %+v", e)
	}
}

// ---- C3: keyed state without an id ----

func profileTraffic(users int, reflect bool) *traffic {
	tr := newTraffic()
	langs := []string{"it", "en", "de"}
	for u := 0; u < users; u++ {
		before := langs[u%3]
		tr.add(xcall{op: "GET /me/profile", user: user(u), resp: map[string]any{"language": keep(before), "newsletter": u%2 == 0}})
		after := langs[(u+1)%3]
		tr.add(xcall{op: "PUT /me/profile", user: user(u), req: map[string]any{"language": keep(after), "newsletter": u%2 == 1},
			resp: map[string]any{"ok": true}})
		shown := after
		if !reflect {
			shown = before
		}
		tr.add(xcall{op: "GET /me/profile", user: user(u), resp: map[string]any{"language": keep(shown), "newsletter": (u%2 == 1) == reflect}})
	}
	return tr
}

func TestKeyedSingletonPerUser(t *testing.T) {
	res := profileTraffic(30, true).mine(t, smallK(), MineOptions{})
	e := entOf(res, "profile")
	if e == nil {
		t.Fatalf("no keyed entity: %+v", res.Entities)
	}
	if e.Key == nil || !e.Key.Owner || len(e.Key.Fields) != 0 || e.CreatedBy != nil {
		t.Fatalf("key: %+v", e.Key)
	}
	if len(e.UpsertedBy) != 1 || e.UpsertedBy[0].Op != "PUT /me/profile" || e.UpsertedBy[0].State == nil || e.UpsertedBy[0].State.Path != "$" {
		t.Fatalf("upserted_by: %+v", e.UpsertedBy)
	}
	if len(e.ReadBy) != 1 || e.ReadBy[0].Op != "GET /me/profile" || e.ReadBy[0].At.Path != "$" || e.ReadBy[0].By != nil {
		t.Fatalf("read_by: %+v", e.ReadBy)
	}
}

func TestKeyedNotWhenReadIgnoresWrite(t *testing.T) {
	if e := entOf(profileTraffic(30, false).mine(t, smallK(), MineOptions{}), "profile"); e != nil {
		t.Fatalf("keyed entity although reads ignore the writes: %+v", e)
	}
	if e := entOf(profileTraffic(3, true).mine(t, smallK(), MineOptions{}), "profile"); e != nil {
		t.Fatalf("keyed entity with 3 users < k: %+v", e)
	}
}

// consents: one record per (user, document); documents are shared.
func TestKeyedByRequestSelector(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		for d := 0; d < 2; d++ {
			doc := tok("document", d)
			acc := (u+d)%2 == 0
			tr.add(xcall{op: "POST /consents", status: 201, user: user(u), req: map[string]any{"documentId": doc, "accepted": acc},
				resp: map[string]any{"ok": true}})
		}
		for d := 0; d < 2; d++ {
			doc := tok("document", d)
			tr.add(xcall{op: "GET /consents/{documentId}", path: "/consents/{" + doc + "}", user: user(u),
				resp: map[string]any{"accepted": (u+d)%2 == 0, "version": 1}})
		}
	}
	res := tr.mine(t, smallK(), MineOptions{})
	e := entOf(res, "consent")
	if e == nil || e.Key == nil {
		t.Fatalf("no keyed consent: %+v", res.Entities)
	}
	if len(e.Key.Fields) != 1 || e.Key.Fields[0] != "documentId" {
		t.Fatalf("key: %+v", e.Key)
	}
	rb := e.ReadBy[0]
	if r, ok := rb.Key["documentId"]; !ok || r.From != "req.path" || r.Name != "documentId" {
		t.Fatalf("read key: %+v", rb.Key)
	}
	u := e.UpsertedBy[0]
	if r, ok := u.Key["documentId"]; !ok || r.From != "req.body" || r.Path != "$.documentId" {
		t.Fatalf("upsert key: %+v", u.Key)
	}
}

// ---- C4: removal ----

func accountsTraffic(users int, remove bool, gone int) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		a, b := tok("account", 2*u), tok("account", 2*u+1)
		for _, id := range []string{a, b} {
			tr.add(xcall{op: "POST /accounts", status: 201, user: user(u), req: map[string]any{"city": keep("X")},
				resp: map[string]any{"id": id, "kind": keep("HOME")}})
		}
		tr.add(xcall{op: "GET /accounts", user: user(u), resp: map[string]any{"items": []any{
			map[string]any{"id": a, "kind": keep("HOME")}, map[string]any{"id": b, "kind": keep("HOME")}}}})
		tr.add(xcall{op: "GET /accounts/{id}", path: "/accounts/{" + a + "}", user: user(u), resp: map[string]any{"id": a, "kind": keep("HOME")}})
		if remove {
			tr.add(xcall{op: "DELETE /accounts/{id}", path: "/accounts/{" + a + "}", status: 204, user: user(u)})
			if u%2 == 0 {
				tr.add(xcall{op: "GET /accounts", user: user(u), resp: map[string]any{"items": []any{map[string]any{"id": b, "kind": keep("HOME")}}}})
			} else {
				tr.add(xcall{op: "GET /accounts/{id}", path: "/accounts/{" + a + "}", user: user(u), status: gone,
					resp: map[string]any{"error": map[string]any{"code": keep("not_found")}}})
			}
		} else {
			tr.add(xcall{op: "PUT /accounts/{id}/default", path: "/accounts/{" + a + "}/default", user: user(u), resp: map[string]any{"ok": true}})
			tr.add(xcall{op: "GET /accounts", user: user(u), resp: map[string]any{"items": []any{
				map[string]any{"id": a, "kind": keep("HOME")}, map[string]any{"id": b, "kind": keep("HOME")}}}})
		}
	}
	return tr
}

func removalRuleOf(res *Result) *CausalRule {
	for _, r := range res.Rules {
		if c := r.Rule.Causal; c != nil && strings.HasSuffix(r.Signature, "|remove") {
			return c
		}
	}
	return nil
}

func TestRemovalRule(t *testing.T) {
	res := accountsTraffic(30, true, 404).mine(t, smallK(), MineOptions{})
	c := removalRuleOf(res)
	if c == nil {
		t.Fatalf("no removal rule: %+v", res.Diag.Rules)
	}
	if c.Cause.Op != "DELETE /accounts/{id}" || len(c.Effects) != 1 || !c.Effects[0].Remove || c.Effects[0].TargetID != "${account}" {
		t.Fatalf("rule: %+v %+v", c.Cause, c.Effects)
	}
	if b := c.Cause.Bind["account"]; b.From != "req.path" || b.Name != "id" {
		t.Fatalf("bind: %+v", c.Cause.Bind)
	}
	if e := entOf(res, "account"); readOf(e, "GET /accounts/{id}").RemovedStatus != 0 {
		t.Fatalf("404 is the default: %+v", readOf(e, "GET /accounts/{id}"))
	}
	// 410 after removal goes to the read.
	res = accountsTraffic(30, true, 410).mine(t, smallK(), MineOptions{})
	if e := entOf(res, "account"); readOf(e, "GET /accounts/{id}").RemovedStatus != 410 {
		t.Fatalf("removed_status: %+v", readOf(e, "GET /accounts/{id}"))
	}
}

func TestNoRemovalWhenTheObjectStays(t *testing.T) {
	if c := removalRuleOf(accountsTraffic(30, false, 404).mine(t, smallK(), MineOptions{})); c != nil {
		t.Fatalf("a write that leaves the object is no removal: %+v", c)
	}
	if c := removalRuleOf(accountsTraffic(3, true, 404).mine(t, smallK(), MineOptions{})); c != nil {
		t.Fatalf("removal with 3 users < k: %+v", c)
	}
}

// ---- C5: reads by behaviour ----

func lookupTraffic(users int) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		id := tok("order", u)
		tr.add(xcall{op: "POST /orders", status: 201, user: user(u), req: map[string]any{"sku": keep("A")},
			resp: map[string]any{"id": id, "status": keep("CONFIRMED")}})
		for k := 0; k < 2; k++ {
			tr.add(xcall{op: "POST /orders/lookup", user: user(u), req: map[string]any{"filters": map[string]any{"orderId": id}},
				resp: map[string]any{"order": map[string]any{"id": id, "status": keep("CONFIRMED")}}})
		}
		tr.add(xcall{op: "POST /orders/{id}/cancel", path: "/orders/{" + id + "}/cancel", user: user(u),
			resp: map[string]any{"id": id, "status": keep("CANCELLED")}})
	}
	return tr
}

func readDecision(res *Result, op string) *ReadDecision {
	for i := range res.Diag.Reads {
		if res.Diag.Reads[i].Op == op {
			return &res.Diag.Reads[i]
		}
	}
	return nil
}

func TestPostReadByBehaviour(t *testing.T) {
	res := lookupTraffic(30).mine(t, smallK(), MineOptions{})
	if d := readDecision(res, "POST /orders/lookup"); d == nil || !d.Read || !d.Auto {
		t.Fatalf("lookup not classified as a read: %+v", res.Diag.Reads)
	}
	if d := readDecision(res, "POST /orders/{id}/cancel"); d != nil {
		t.Fatalf("cancel changes what it returns, not a read: %+v", d)
	}
	if d := readDecision(res, "POST /orders"); d != nil {
		t.Fatalf("a creation is not a read: %+v", d)
	}
	e := entOf(res, "order")
	if e == nil || e.CreatedBy == nil || e.CreatedBy.Op != "POST /orders" {
		t.Fatalf("order: %+v", e)
	}
	rb := readOf(e, "POST /orders/lookup")
	if rb == nil || rb.By == nil || rb.By.From != "req.body" || rb.By.Path != "$.filters.orderId" || rb.At.Path != "$.order" {
		t.Fatalf("read by body selector: %+v", rb)
	}
}

func TestPostReadOverride(t *testing.T) {
	over := map[string]map[string]bool{"": {"app-api POST /orders/lookup": false, "app-api POST /orders/{id}/cancel": true}}
	res := lookupTraffic(30).mine(t, smallK(), MineOptions{OpReads: over})
	if d := readDecision(res, "POST /orders/lookup"); d == nil || d.Read || !d.Override {
		t.Fatalf("override to write: %+v", d)
	}
	if d := readDecision(res, "POST /orders/{id}/cancel"); d == nil || !d.Read || !d.Override {
		t.Fatalf("override to read: %+v", d)
	}
	e := entOf(res, "order")
	if readOf(e, "POST /orders/lookup") != nil {
		t.Fatalf("a write is not a read_by: %+v", e.ReadBy)
	}
	if readOf(e, "POST /orders/{id}/cancel") == nil {
		t.Fatalf("the operation marked as a read reads the order: %+v", e.ReadBy)
	}
	// Too few users: no automatic classification.
	if d := readDecision(lookupTraffic(3).mine(t, smallK(), MineOptions{}), "POST /orders/lookup"); d != nil {
		t.Fatalf("classified with 3 users < k: %+v", d)
	}
}
