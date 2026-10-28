package miner

import (
	"strings"
	"testing"
	"time"
)

// ---- keyed targets (rules v1.8) ----

// newsletterTraffic: a profile per user (keyed singleton, PUT /me/profile
// is its upserted_by) whose newsletter flag a different write turns on.
func newsletterTraffic(users int, subscribes bool) *traffic {
	tr := newTraffic()
	langs := []string{"it", "en", "de"}
	for u := 0; u < users; u++ {
		l0, l1 := langs[u%3], langs[(u+1)%3]
		tr.add(xcall{op: "GET /me/profile", user: user(u), resp: map[string]any{"language": keep(l0), "newsletter": false}})
		tr.now = tr.now.Add(10 * time.Minute)
		tr.add(xcall{op: "PUT /me/profile", user: user(u), req: map[string]any{"language": keep(l1)}, resp: map[string]any{"ok": true}})
		tr.add(xcall{op: "GET /me/profile", user: user(u), resp: map[string]any{"language": keep(l1), "newsletter": false}})
		tr.add(xcall{op: "POST /newsletter/subscribe", user: user(u), resp: map[string]any{"ok": true}})
		tr.add(xcall{op: "GET /me/profile", user: user(u), resp: map[string]any{"language": keep(l1), "newsletter": subscribes}})
	}
	return tr
}

func ruleByOp(res *Result, op, suffix string) *CausalRule {
	for _, r := range res.Rules {
		if c := r.Rule.Causal; c != nil && c.Cause.Op == op && strings.HasSuffix(r.Signature, suffix) {
			return c
		}
	}
	return nil
}

func TestKeyedTargetSingleton(t *testing.T) {
	res := newsletterTraffic(30, true).mine(t, smallK(), MineOptions{})
	if e := entOf(res, "profile"); e == nil || e.Key == nil {
		t.Fatalf("no keyed profile: %+v", res.Entities)
	}
	c := ruleByOp(res, "POST /newsletter/subscribe", "|profile|update")
	if c == nil {
		t.Fatalf("no update of the profile: %+v", res.Diag.Rules)
	}
	if len(c.Effects) != 1 {
		t.Fatalf("effects: %+v", c.Effects)
	}
	ef := c.Effects[0]
	if ef.Entity != "profile" || ef.TargetID != "" || ef.TargetKey == nil || len(*ef.TargetKey) != 0 {
		t.Fatalf("target: %+v", ef)
	}
	if ef.Set["newsletter"] != true || len(ef.Set) != 1 {
		t.Fatalf("set: %+v", ef.Set)
	}
	if len(c.Cause.Bind) != 0 {
		t.Fatalf("a singleton needs no bind: %+v", c.Cause.Bind)
	}
	// the upsert itself never becomes an update rule of its record
	if ruleByOp(res, "PUT /me/profile", "|update") != nil {
		t.Fatal("upserted_by mined as an update")
	}
}

func TestKeyedTargetNegative(t *testing.T) {
	if c := ruleByOp(newsletterTraffic(30, false).mine(t, smallK(), MineOptions{}), "POST /newsletter/subscribe", "|update"); c != nil {
		t.Fatalf("an update although nothing changes: %+v", c)
	}
	if c := ruleByOp(newsletterTraffic(4, true).mine(t, smallK(), MineOptions{}), "POST /newsletter/subscribe", "|update"); c != nil {
		t.Fatalf("an update with 4 users < k: %+v", c)
	}
}

// consents keyed by documentId, signed by another write that carries the
// document in its path.
func TestKeyedTargetByField(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		for d := 0; d < 2; d++ {
			doc := tok("document", d)
			acc := (u+d)%2 == 0
			tr.add(xcall{op: "POST /consents", status: 201, user: user(u), req: map[string]any{"documentId": doc, "accepted": acc},
				resp: map[string]any{"ok": true}})
			path := "/consents/{" + doc + "}"
			tr.add(xcall{op: "GET /consents/{documentId}", path: path, user: user(u), resp: map[string]any{"accepted": acc, "signed": false}})
			tr.now = tr.now.Add(10 * time.Minute)
			tr.add(xcall{op: "GET /consents/{documentId}", path: path, user: user(u), resp: map[string]any{"accepted": acc, "signed": false}})
			tr.add(xcall{op: "POST /documents/{documentId}/sign", path: "/documents/{" + doc + "}/sign", user: user(u), resp: map[string]any{"ok": true}})
			tr.add(xcall{op: "GET /consents/{documentId}", path: path, user: user(u), resp: map[string]any{"accepted": acc, "signed": true}})
		}
	}
	res := tr.mine(t, smallK(), MineOptions{})
	c := ruleByOp(res, "POST /documents/{documentId}/sign", "|consent|update")
	if c == nil {
		t.Fatalf("no update of the consent: %+v / %+v", res.Entities, res.Diag.Rules)
	}
	ef := c.Effects[0]
	if ef.TargetKey == nil || (*ef.TargetKey)["documentId"] != "${documentid}" || ef.Set["signed"] != true {
		t.Fatalf("effect: %+v %v", ef, ef.TargetKey)
	}
	if b := c.Cause.Bind["documentid"]; b.From != "req.path" || b.Name != "documentId" {
		t.Fatalf("bind: %+v", c.Cause.Bind)
	}
}

// ---- C9: objects that appear later, outside the trace ----

// ticketTraffic: a user opens a request; some minutes later a ticket that
// cites it appears in the user's tickets (minted outside the trace) and,
// with replace, the request leaves the user's requests. got tells which
// users' requests get a ticket.
func ticketTraffic(users int, replace bool, got func(u int) bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		rq, tk := tok("request", u), tok("ticket", u)
		reqItem := map[string]any{"id": rq, "status": keep("OPEN")}
		tr.add(xcall{op: "POST /requests", status: 201, user: user(u), req: map[string]any{"topic": keep("billing")}, resp: reqItem})
		tr.add(xcall{op: "GET /tickets", user: user(u), resp: map[string]any{"items": []any{}}})
		tr.add(xcall{op: "GET /requests", user: user(u), resp: map[string]any{"items": []any{reqItem}}})
		tr.now = tr.now.Add(30 * time.Minute)
		if !got(u) {
			tr.add(xcall{op: "GET /tickets", user: user(u), resp: map[string]any{"items": []any{}}})
			tr.add(xcall{op: "GET /requests", user: user(u), resp: map[string]any{"items": []any{reqItem}}})
			continue
		}
		ticket := map[string]any{"id": tk, "requestId": rq, "status": keep("NEW")}
		tr.add(xcall{op: "GET /tickets", user: user(u), resp: map[string]any{"items": []any{ticket}}})
		left := []any{reqItem}
		if replace {
			left = []any{}
		}
		tr.add(xcall{op: "GET /requests", user: user(u), resp: map[string]any{"items": left}})
		tr.add(xcall{op: "GET /tickets/{id}", path: "/tickets/{" + tk + "}", user: user(u), resp: ticket})
	}
	return tr
}

func creationRuleOf(res *Result, op string) *CausalRule {
	for _, r := range res.Rules {
		if c := r.Rule.Causal; c != nil && c.Cause.Op == op && strings.Count(r.Signature, "|") == 3 {
			return c
		}
	}
	return nil
}

func effectOf(c *CausalRule, id string) *Effect {
	for i := range c.Effects {
		if c.Effects[i].ID == id {
			return &c.Effects[i]
		}
	}
	return nil
}

func TestLaterObjectCreatedByTheCause(t *testing.T) {
	res := ticketTraffic(30, true, func(int) bool { return true }).mine(t, smallK(), MineOptions{})
	tkt := entOf(res, "ticket")
	if tkt == nil || tkt.Seed != nil || tkt.CreatedBy != nil {
		t.Fatalf("ticket: %+v", tkt)
	}
	c := creationRuleOf(res, "POST /requests")
	if c == nil {
		t.Fatalf("no rule for the creation: %+v", res.Diag.Rules)
	}
	ef := effectOf(c, "ticket-created")
	if ef == nil || ef.Entity != "ticket" || ef.Create["requestId"] != "${request}" || ef.Create["status"] != "NEW" {
		t.Fatalf("ticket effect: %+v", c.Effects)
	}
	if ef.After.Min != "1m" || ef.After.Max != "59m" {
		t.Fatalf("figurative delay of minutes: %+v", ef.After)
	}
	rp := effectOf(c, "request-replaced")
	if rp == nil || !rp.Remove || rp.TargetID != "${request}" || rp.AfterEffect != "ticket-created" {
		t.Fatalf("replacement: %+v", c.Effects)
	}
	for _, o := range c.Outcomes {
		if !strings.Contains(strings.Join(o.Effects, ","), "ticket-created") {
			t.Fatalf("outcome without the ticket: %+v", c.Outcomes)
		}
	}
	found := false
	for _, d := range res.Diag.Entities {
		found = found || (d.Name == "ticket" && d.Code == EntityLater)
	}
	if !found {
		t.Fatalf("diagnostic: %+v", res.Diag.Entities)
	}
}

func TestLaterObjectWithoutReplacement(t *testing.T) {
	res := ticketTraffic(30, false, func(int) bool { return true }).mine(t, smallK(), MineOptions{})
	c := creationRuleOf(res, "POST /requests")
	if c == nil || effectOf(c, "ticket-created") == nil {
		t.Fatalf("no ticket effect: %+v", c)
	}
	if effectOf(c, "request-replaced") != nil {
		t.Fatalf("the request stays: no replacement expected: %+v", c.Effects)
	}
}

func TestLaterObjectNegative(t *testing.T) {
	// half of the requests never get a ticket although their users look
	res := ticketTraffic(30, true, func(u int) bool { return u%2 == 0 }).mine(t, smallK(), MineOptions{})
	if c := creationRuleOf(res, "POST /requests"); c != nil && effectOf(c, "ticket-created") != nil {
		t.Fatalf("a ticket for every request although half get none: %+v", c.Effects)
	}
	if e := entOf(res, "ticket"); e == nil || e.Seed == nil {
		t.Fatalf("the tickets stay pre-existing objects: %+v", e)
	}
	// k: 4 users
	res = ticketTraffic(4, true, func(int) bool { return true }).mine(t, smallK(), MineOptions{})
	if c := creationRuleOf(res, "POST /requests"); c != nil && effectOf(c, "ticket-created") != nil {
		t.Fatalf("a later object with 4 users < k: %+v", c.Effects)
	}
}

// ---- C10: a value that comes back on its own ----

func suspendTraffic(users int, back bool) *traffic {
	a := newContractApp(users)
	for u := 0; u < users; u++ {
		a.list(u)
		a.read(u, 0)
		a.tr.now = a.tr.now.Add(10 * time.Minute)
		a.read(u, 0)
		a.write(u, 0, "POST /contracts/{id}/suspend", "/suspend", nil)
		a.cs[u][0].status = "SUSPENDED"
		a.list(u)
		a.read(u, 0)
		a.tr.now = a.tr.now.Add(3 * time.Hour)
		if back {
			a.cs[u][0].status = "ACTIVE"
		}
		a.list(u)
		a.read(u, 0)
	}
	return a.tr
}

func TestUpdateRevertsAfterADelay(t *testing.T) {
	res := suspendTraffic(30, true).mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "POST /contracts/{id}/suspend")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if s := setOf(t, c, "contract-updated"); s["status"] != "SUSPENDED" {
		t.Fatalf("set: %+v", s)
	}
	var rv *Effect
	for i := range c.Effects {
		if c.Effects[i].ID == "contract-status-reverted" {
			rv = &c.Effects[i]
		}
	}
	if rv == nil {
		t.Fatalf("no revert: %+v", c.Effects)
	}
	if rv.Set["status"] != "ACTIVE" || rv.Where["status"] != "SUSPENDED" || rv.AfterEffect != "contract-updated" || rv.TargetID != "${contract}" {
		t.Fatalf("revert: %+v", rv)
	}
	if rv.After.Min != "1h" || rv.After.Max != "23h" {
		t.Fatalf("figurative after of hours: %+v", rv.After)
	}
	if len(c.Outcomes) != 1 || len(c.Outcomes[0].Effects) != 2 {
		t.Fatalf("outcomes: %+v", c.Outcomes)
	}
}

func TestUpdateNoRevertWhenItStays(t *testing.T) {
	res := suspendTraffic(30, false).mine(t, smallK(), MineOptions{})
	c := updateRuleOf(res, "POST /contracts/{id}/suspend")
	if c == nil {
		t.Fatalf("no update rule: %+v", res.Diag.Rules)
	}
	if len(c.Effects) != 1 {
		t.Fatalf("a revert although the value stays: %+v", c.Effects)
	}
	// k: returns seen for 4 users only
	res = suspendTraffic(4, true).mine(t, smallK(), MineOptions{})
	if c := updateRuleOf(res, "POST /contracts/{id}/suspend"); c != nil && len(c.Effects) != 1 {
		t.Fatalf("a revert with 4 users < k: %+v", c.Effects)
	}
}

// ---- C7: uniqueness and counters per key ----

func limitRuleOf(res *Result, op string, status int) *CausalRule {
	for _, r := range res.Rules {
		if c := r.Rule.Causal; c != nil && c.Cause.Op == op && strings.HasSuffix(r.Signature, "|limit|"+itoa(status)) {
			return c
		}
	}
	return nil
}

func limitOf(t *testing.T, c *CausalRule) (*Respond, *Limit) {
	t.Helper()
	if len(c.Effects) != 1 || c.Effects[0].Respond == nil || c.Effects[0].Respond.Limit == nil {
		t.Fatalf("not a limit: %+v", c.Effects)
	}
	return c.Effects[0].Respond, c.Effects[0].Respond.Limit
}

// a second account with the same email answers 409.
func uniqueTraffic(users int, conflict bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		e1, e2 := tok("email", 2*u), tok("email", 2*u+1)
		tr.add(xcall{op: "POST /accounts", status: 201, user: user(u), req: map[string]any{"email": e1}, resp: map[string]any{"id": tok("account", 3*u)}})
		if conflict {
			tr.add(xcall{op: "POST /accounts", status: 409, user: user(u), req: map[string]any{"email": e1}, resp: map[string]any{"error": keep("EMAIL_TAKEN")}})
		} else {
			tr.add(xcall{op: "POST /accounts", status: 201, user: user(u), req: map[string]any{"email": e1}, resp: map[string]any{"id": tok("account", 3*u+1)}})
		}
		tr.add(xcall{op: "POST /accounts", status: 201, user: user(u), req: map[string]any{"email": e2}, resp: map[string]any{"id": tok("account", 3*u+2)}})
	}
	return tr
}

func TestLimitUniqueByRequestToken(t *testing.T) {
	res := uniqueTraffic(30, true).mine(t, smallK(), MineOptions{})
	c := limitRuleOf(res, "POST /accounts", 409)
	if c == nil {
		t.Fatalf("no uniqueness rule: %+v", res.Diag.Rules)
	}
	rs, lm := limitOf(t, c)
	if rs.Status != 409 || rs.Op != "POST /accounts" || lm.N != 1 || lm.Window != "" || lm.Key != "${email}" {
		t.Fatalf("limit: %+v %+v", rs, lm)
	}
	if b := c.Cause.Bind["email"]; b.From != "req.body" || b.Path != "$.email" || len(c.Cause.When.Status) != 1 || c.Cause.When.Status[0] != 201 {
		t.Fatalf("cause: %+v", c.Cause)
	}
}

func TestLimitNegative(t *testing.T) {
	if c := limitRuleOf(uniqueTraffic(30, false).mine(t, smallK(), MineOptions{}), "POST /accounts", 409); c != nil {
		t.Fatalf("a limit without conflicts: %+v", c)
	}
	if c := limitRuleOf(uniqueTraffic(4, true).mine(t, smallK(), MineOptions{}), "POST /accounts", 409); c != nil {
		t.Fatalf("a limit with 4 users < k: %+v", c)
	}
	// a status that comes at random is not a counter
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		for k := 0; k < 6; k++ {
			st := 200
			if (u+k)%10 == 0 {
				st = 429
			}
			tr.add(xcall{op: "GET /quotes", status: st, user: user(u), resp: map[string]any{"price": 3}})
		}
	}
	if c := limitRuleOf(tr.mine(t, smallK(), MineOptions{}), "GET /quotes", 429); c != nil {
		t.Fatalf("a limit for random errors: %+v", c)
	}
}

// three quotes a minute per user: bursts of five calls ten seconds apart.
func TestLimitRatePerUserInAWindow(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		for burst := 0; burst < 2; burst++ {
			for k := 0; k < 5; k++ {
				tr.now = tr.now.Add(-50 * time.Second)
				st := 200
				if k >= 3 {
					st = 429
				}
				tr.add(xcall{op: "GET /quotes", status: st, user: user(u), resp: map[string]any{"price": 3}})
			}
			tr.now = tr.now.Add(2 * time.Hour)
		}
	}
	res := tr.mine(t, smallK(), MineOptions{})
	c := limitRuleOf(res, "GET /quotes", 429)
	if c == nil {
		t.Fatalf("no rate limit: %+v", res.Diag.Rules)
	}
	_, lm := limitOf(t, c)
	if lm.N != 3 || lm.Window != "1m" || lm.Key != "" || len(c.Cause.Bind) != 0 {
		t.Fatalf("limit: %+v bind %+v", lm, c.Cause.Bind)
	}
}

// after three failed logins of a username the next ones answer 423; a day
// later the login works again.
func TestLimitFailedAttempts(t *testing.T) {
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		name := tok("username", u)
		for k := 0; k < 5; k++ {
			st := 401
			if k >= 3 {
				st = 423
			}
			tr.add(xcall{op: "POST /login", status: st, user: user(u), req: map[string]any{"username": name}, resp: map[string]any{"error": keep("NO")}})
		}
		tr.now = tr.now.Add(26 * time.Hour)
		tr.add(xcall{op: "POST /login", status: 200, user: user(u), req: map[string]any{"username": name}, resp: map[string]any{"ok": true}})
	}
	res := tr.mine(t, smallK(), MineOptions{})
	c := limitRuleOf(res, "POST /login", 423)
	if c == nil {
		t.Fatalf("no attempts limit: %+v", res.Diag.Rules)
	}
	_, lm := limitOf(t, c)
	if lm.N != 3 || lm.Window != "15m" || lm.Key != "${username}" || len(c.Cause.When.Status) != 1 || c.Cause.When.Status[0] != 401 {
		t.Fatalf("limit: %+v when %+v", lm, c.Cause.When)
	}
}

// ---- C10: lifecycles with cycles ----

// cardTraffic: a card is created ACTIVE, gets BLOCKED on its own about an
// hour later and, for two users in three, ACTIVE again a couple of hours
// after; with unblock the return is made by a write.
func cardTraffic(users int, unblock bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		id := tok("card", u)
		body := func(st string) map[string]any { return map[string]any{"id": id, "status": keep(st)} }
		read := func(st string) {
			tr.add(xcall{op: "GET /cards/{id}", path: "/cards/{" + id + "}", user: user(u), resp: body(st)})
		}
		tr.add(xcall{op: "POST /cards", status: 201, user: user(u), req: map[string]any{"kind": keep("DEBIT")}, resp: body("ACTIVE")})
		read("ACTIVE")
		tr.now = tr.now.Add(time.Hour)
		read("BLOCKED")
		back := u%3 != 0
		tr.now = tr.now.Add(2 * time.Hour)
		if back && unblock {
			tr.add(xcall{op: "POST /cards/{id}/unblock", path: "/cards/{" + id + "}/unblock", user: user(u), resp: map[string]any{"ok": true}})
		}
		if back {
			read("ACTIVE")
		} else {
			read("BLOCKED")
		}
		read(map[bool]string{true: "ACTIVE", false: "BLOCKED"}[back])
	}
	tr.now = tr.now.Add(72 * time.Hour)
	tr.add(xcall{op: "GET /health", resp: map[string]any{"ok": true}})
	return tr
}

func TestLifecycleCycleOnItsOwn(t *testing.T) {
	res := cardTraffic(30, false).mine(t, smallK(), MineOptions{})
	c := creationRuleOf(res, "POST /cards")
	if c == nil {
		t.Fatalf("no creation rule: %+v", res.Diag.Rules)
	}
	ag := effectOf(c, "card-active-again")
	if ag == nil {
		t.Fatalf("no return: %+v", c.Effects)
	}
	if ag.Set["status"] != "ACTIVE" || ag.Where["status"] != "BLOCKED" || ag.AfterEffect != "card-blocked" || ag.TargetID != "${card}" {
		t.Fatalf("return: %+v", ag)
	}
	if ag.After.Min != "1h" {
		t.Fatalf("figurative after of hours: %+v", ag.After)
	}
	byName := map[string]Outcome{}
	for _, o := range c.Outcomes {
		byName[o.Name] = o
	}
	again, ok := byName["active-again"]
	if !ok || len(again.Effects) != 2 || again.P < 0.6 || again.P > 0.7 {
		t.Fatalf("outcomes: %+v", c.Outcomes)
	}
	if _, ok := byName["never"]; ok {
		t.Fatalf("a card that came back is not a card that never moved: %+v", c.Outcomes)
	}
}

func TestLifecycleCycleByAWrite(t *testing.T) {
	res := cardTraffic(30, true).mine(t, smallK(), MineOptions{})
	if c := creationRuleOf(res, "POST /cards"); c != nil && effectOf(c, "card-active-again") != nil {
		t.Fatalf("a return made by a write is not spontaneous: %+v", c.Effects)
	}
	if c := updateRuleOf(res, "POST /cards/{id}/unblock"); c == nil || setOf(t, c, "card-updated")["status"] != "ACTIVE" {
		t.Fatalf("the write makes the return: %+v %+v", c, res.Diag.Rules)
	}
	// k: 4 users
	if c := creationRuleOf(cardTraffic(4, false).mine(t, smallK(), MineOptions{}), "POST /cards"); c != nil && effectOf(c, "card-active-again") != nil {
		t.Fatalf("a return with 4 users < k: %+v", c.Effects)
	}
}

// ---- rules v1.8 validation ----

func TestValidateRules18(t *testing.T) {
	ents := map[string]*Entity{
		"consent": {Name: "consent", Key: &StateKey{Owner: true, Fields: []string{"documentId"}}},
		"account": {Name: "account"},
	}
	base := func() *CausalRule {
		return &CausalRule{ID: "r-0001", Kind: KindCausal, Status: StatusDraft,
			Cause: Cause{Service: "app-api", Op: "POST /x", When: When{Status: []int{200}},
				Bind: map[string]Ref{"doc": {From: "req.path", Name: "doc"}, "acc": {From: "resp.body", Path: "$.id"}}},
			Outcomes: []Outcome{{Name: "always", P: 1, Effects: []string{"e"}}},
			Evidence: CausalEvidence{Counts: CausalCounts{Outcomes: map[string]int{}}}}
	}
	keyed := func(tk KeyTarget) Effect {
		return Effect{ID: "e", Entity: "consent", TargetKey: &tk, Set: map[string]any{"signed": true}, After: Delay{Single: "0s"}}
	}
	limit := func(lm Limit, op string, times int) Effect {
		return Effect{ID: "e", Respond: &Respond{Service: "app-api", Op: op, Status: 409, Times: times, Limit: &lm}, After: Delay{Single: "0s"}}
	}
	ok := []Effect{
		keyed(KeyTarget{"documentId": "${doc}"}),
		keyed(KeyTarget{"documentId": "DOC-1"}),
		limit(Limit{N: 1, Key: "${doc}"}, "POST /x", 0),
		limit(Limit{N: 3, Window: "15m"}, "GET /other", 0),
	}
	for i, e := range ok {
		r := base()
		r.Effects = []Effect{e}
		if err := r.validate(ents); err != nil {
			t.Fatalf("valid %d: %v", i, err)
		}
	}
	bad := map[string]Effect{
		"target_key on an entity with an id": func() Effect { e := keyed(KeyTarget{}); e.Entity = "account"; return e }(),
		"target_key without the key field":   keyed(KeyTarget{}),
		"target_key of an unbound variable":  keyed(KeyTarget{"documentId": "${nobody}"}),
		"target_key embedding a reference":   keyed(KeyTarget{"documentId": "d-${doc}"}),
		"target_key with target_id":          func() Effect { e := keyed(KeyTarget{"documentId": "${doc}"}); e.TargetID = "${doc}"; return e }(),
		"limit with times":                   limit(Limit{N: 1}, "POST /x", 1),
		"limit n zero":                       limit(Limit{N: 0}, "POST /x", 0),
		"limit bad window":                   limit(Limit{N: 1, Window: "0m"}, "POST /x", 0),
		"limit key from the response":        limit(Limit{N: 1, Key: "${acc}"}, "POST /x", 0),
		"limit key on another operation":     limit(Limit{N: 1, Key: "${doc}"}, "GET /other", 0),
	}
	for name, e := range bad {
		r := base()
		r.Effects = []Effect{e}
		if err := r.validate(ents); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
