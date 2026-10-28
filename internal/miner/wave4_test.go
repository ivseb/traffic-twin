package miner

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---- C17: preconditions ----

// checkoutTraffic: checking out answers 409 until the user added an item
// to the cart, 200 afterwards. lifted=false: the 409 has nothing to do
// with the cart (it comes before and after).
func checkoutTraffic(users int, lifted bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		tr.add(xcall{op: "POST /checkout", status: 409, user: user(u), req: map[string]any{"pay": keep("card")}, resp: map[string]any{"ok": false}})
		tr.add(xcall{op: "POST /checkout", status: 409, user: user(u), req: map[string]any{"pay": keep("card")}, resp: map[string]any{"ok": false}})
		tr.add(xcall{op: "POST /cart/items", status: 201, user: user(u), req: map[string]any{"qty": 1}, resp: map[string]any{"ok": true}})
		after := 200
		if !lifted {
			after = 409
		}
		tr.add(xcall{op: "POST /checkout", status: after, user: user(u), req: map[string]any{"pay": keep("card")}, resp: map[string]any{"ok": true}})
		tr.add(xcall{op: "POST /checkout", status: 200, user: user(u), req: map[string]any{"pay": keep("card")}, resp: map[string]any{"ok": true}})
	}
	return tr
}

const checkoutSig = "causal|app-api|POST /cart/items|until|app-api|POST /checkout|409"

func ruleBySig(res *Result, sig string) *CausalRule {
	for _, r := range res.Rules {
		if r.Signature == sig {
			return r.Rule.Causal
		}
	}
	return nil
}

func candBySig(res *Result, sig string) *Candidate {
	for i := range res.Diag.Candidates {
		if res.Diag.Candidates[i].Signature == sig {
			return &res.Diag.Candidates[i]
		}
	}
	return nil
}

func TestPrecondition(t *testing.T) {
	res := checkoutTraffic(30, true).mine(t, smallK(), MineOptions{})
	c := ruleBySig(res, checkoutSig)
	if c == nil {
		t.Fatalf("no precondition: %+v", res.Diag.Rules)
	}
	if len(c.Effects) != 1 || c.Effects[0].Respond == nil {
		t.Fatalf("effects: %+v", c.Effects)
	}
	rs := c.Effects[0].Respond
	if !rs.Until || rs.Status != 409 || rs.Op != "POST /checkout" || rs.Service != "app-api" || rs.Times != 0 || rs.Limit != nil {
		t.Fatalf("respond: %+v", rs)
	}
	if len(c.Cause.When.Status) != 1 || c.Cause.When.Status[0] != 201 || c.Outcomes[0].Name != "always" {
		t.Fatalf("cause/outcomes: %+v %+v", c.Cause, c.Outcomes)
	}
	if candBySig(res, checkoutSig) != nil {
		t.Fatal("a mined rule is not a candidate")
	}
}

func TestPreconditionNegative(t *testing.T) {
	if c := ruleBySig(checkoutTraffic(30, false).mine(t, smallK(), MineOptions{}), checkoutSig); c != nil {
		t.Fatalf("a precondition although the 409 stays: %+v", c)
	}
	res := checkoutTraffic(4, true).mine(t, smallK(), MineOptions{})
	if c := ruleBySig(res, checkoutSig); c != nil {
		t.Fatalf("a precondition with 4 users < k: %+v", c)
	}
}

// ---- C0: candidates below k, test groups ----

func TestCandidateBelowK(t *testing.T) {
	res := checkoutTraffic(4, true).mine(t, smallK(), MineOptions{})
	cd := candBySig(res, checkoutSig)
	if cd == nil {
		t.Fatalf("no candidate: %+v", res.Diag.Candidates)
	}
	if cd.Kind != CandPrecondition || cd.Template != TplUntil || cd.Subjects != "2-4" || cd.Status != 409 ||
		cd.Target != "app-api POST /checkout" || cd.Service != "app-api" || cd.Op != "POST /cart/items" {
		t.Fatalf("candidate: %+v", cd)
	}
	d := cd.Draft
	if d == nil || d.Causal == nil || d.Causal.ID != "r-0000" || d.Causal.Origin != OriginManual || d.Causal.Status != StatusDraft ||
		d.Causal.Evidence.Counts.Causes != 0 || d.Causal.Evidence.Counts.DistinctSubjects != 0 || d.Causal.Evidence.Hints != nil ||
		d.Causal.Evidence.Keys != nil || d.Causal.Evidence.Counts.Outcomes["always"] != 0 {
		t.Fatalf("draft: %+v", d)
	}
	if err := d.Validate(nil); err != nil {
		t.Fatalf("draft not valid: %v", err)
	}
	b, _ := json.Marshal(res.Diag.Candidates)
	if strings.Contains(string(b), "tk1:") {
		t.Fatalf("a candidate carries a token: %s", b)
	}
	// candidates off
	cfg := smallK()
	cfg.CandidateMaxEvents = 0
	if res := checkoutTraffic(4, true).mine(t, cfg, MineOptions{}); len(res.Diag.Candidates) != 0 {
		t.Fatalf("candidates although off: %+v", res.Diag.Candidates)
	}
	// a single user: nothing (k never below 2)
	if res := checkoutTraffic(1, true).mine(t, smallK(), MineOptions{}); candBySig(res, checkoutSig) != nil {
		t.Fatal("a candidate from one user")
	}
}

func TestTestGroupK(t *testing.T) {
	res := checkoutTraffic(4, true).mine(t, smallK(), MineOptions{GroupKMin: map[string]int{"": 3}})
	if ruleBySig(res, checkoutSig) == nil {
		t.Fatalf("no rule with the test k 3: %+v", res.Diag.Rules)
	}
	if res.Diag.TestK[""] != 3 {
		t.Fatalf("test k not recorded: %+v", res.Diag.TestK)
	}
	if candBySig(res, checkoutSig) != nil {
		t.Fatal("a rule of the test k is not a candidate")
	}
	for _, k := range []int{1, 5, 9} { // below 2 or not below KMin: ignored
		res := checkoutTraffic(4, true).mine(t, smallK(), MineOptions{GroupKMin: map[string]int{"": k}})
		if ruleBySig(res, checkoutSig) != nil || res.Diag.TestK != nil {
			t.Fatalf("k %d: rule or test k: %+v", k, res.Diag.TestK)
		}
	}
}

// ---- target_all: writes on all the user's objects ----

// notificationTraffic: every user has three notifications (pre-existing);
// "read all" marks them read. works=false: they stay unread.
func notificationTraffic(users int, works bool) *traffic {
	tr := newTraffic()
	list := func(u int, read bool) map[string]any {
		var items []any
		for k := 0; k < 3; k++ {
			items = append(items, map[string]any{"id": tok("notification", u*10+k), "read": read, "kind": keep("INFO")})
		}
		return map[string]any{"items": items}
	}
	for u := 0; u < users; u++ {
		tr.add(xcall{op: "GET /notifications", user: user(u), resp: list(u, false)})
		tr.now = tr.now.Add(20 * time.Minute)
		tr.add(xcall{op: "GET /notifications", user: user(u), resp: list(u, false)})
		tr.add(xcall{op: "POST /notifications/read-all", user: user(u), req: map[string]any{"all": true}, resp: map[string]any{"ok": true}})
		tr.add(xcall{op: "GET /notifications", user: user(u), resp: list(u, works)})
	}
	return tr
}

const readAllSig = "causal|app-api|POST /notifications/read-all|notification|update_all"

func TestUpdateAll(t *testing.T) {
	res := notificationTraffic(30, true).mine(t, smallK(), MineOptions{})
	c := ruleBySig(res, readAllSig)
	if c == nil {
		t.Fatalf("no update of all the notifications: %+v / %+v", res.Entities, res.Diag.Rules)
	}
	if len(c.Effects) != 1 {
		t.Fatalf("effects: %+v", c.Effects)
	}
	ef := c.Effects[0]
	if !ef.TargetAll || ef.Entity != "notification" || ef.Set["read"] != true || ef.Where["read"] != false ||
		ef.TargetID != "" || ef.TargetKey != nil || ef.After.Single != "0s" {
		t.Fatalf("effect: %+v", ef)
	}
	if len(c.Cause.Bind) != 0 {
		t.Fatalf("no bind expected: %+v", c.Cause.Bind)
	}
}

func TestUpdateAllNegative(t *testing.T) {
	if c := ruleBySig(notificationTraffic(30, false).mine(t, smallK(), MineOptions{}), readAllSig); c != nil {
		t.Fatalf("an update although nothing changes: %+v", c)
	}
	res := notificationTraffic(4, true).mine(t, smallK(), MineOptions{})
	if c := ruleBySig(res, readAllSig); c != nil {
		t.Fatalf("an update with 4 users < k: %+v", c)
	}
}

func TestCandidateUpdateAll(t *testing.T) {
	cfg := smallK()
	cfg.KMin, cfg.MinDistinct = 8, 8 // six users: below k, enough calls for the Wilson bound of the relaxed pass
	res := notificationTraffic(6, true).mine(t, cfg, MineOptions{})
	cd := candBySig(res, readAllSig)
	if cd == nil {
		t.Fatalf("no candidate: %+v", res.Diag.Candidates)
	}
	if cd.Kind != CandUpdateAll || cd.Template != TplWriteChangesField || cd.Entity != "notification" ||
		strings.Join(cd.Fields, ",") != "read" || strings.Join(cd.States, ",") != "false,true" {
		t.Fatalf("candidate: %+v", cd)
	}
	// The entity is known to the run or listed as missing (the draft can be
	// saved only once it exists).
	known := false
	for _, e := range res.Entities {
		known = known || e.Name == "notification"
	}
	if known == (len(cd.MissingEntities) > 0) {
		t.Fatalf("missing entities %v, entity accepted %v", cd.MissingEntities, known)
	}
	// The precondition candidate touches no entity.
	if pc := candBySig(checkoutTraffic(4, true).mine(t, smallK(), MineOptions{}), checkoutSig); pc == nil || len(pc.MissingEntities) != 0 {
		t.Fatalf("precondition candidate: %+v", pc)
	}
}

// ---- multi-field keyed targets ----

// consentVersionTraffic: consents keyed by document and version, signed
// by a write that carries both (whole=true) or only the document.
func consentVersionTraffic(users int, whole bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		for d := 0; d < 2; d++ {
			doc, ver := tok("document", d), tok("version", u%3+d)
			acc := (u+d)%2 == 0
			tr.add(xcall{op: "POST /consents", status: 201, user: user(u), req: map[string]any{"documentId": doc, "versionId": ver, "accepted": acc},
				resp: map[string]any{"ok": true}})
			path := "/consents/{" + doc + "}/{" + ver + "}"
			read := xcall{op: "GET /consents/{documentId}/{versionId}", path: path, user: user(u)}
			read.resp = map[string]any{"accepted": acc, "signed": false}
			tr.add(read)
			tr.now = tr.now.Add(10 * time.Minute)
			tr.add(read)
			if whole {
				tr.add(xcall{op: "POST /documents/{documentId}/versions/{versionId}/sign", path: "/documents/{" + doc + "}/versions/{" + ver + "}/sign",
					user: user(u), resp: map[string]any{"ok": true}})
			} else {
				tr.add(xcall{op: "POST /documents/{documentId}/sign", path: "/documents/{" + doc + "}/sign", user: user(u), resp: map[string]any{"ok": true}})
			}
			read.resp = map[string]any{"accepted": acc, "signed": true}
			tr.add(read)
		}
	}
	return tr
}

func TestKeyedTargetSeveralFields(t *testing.T) {
	res := consentVersionTraffic(30, true).mine(t, smallK(), MineOptions{})
	var key *StateKey
	for _, e := range res.Entities {
		if e.Key != nil && len(e.Key.Fields) == 2 {
			key = e.Key
		}
	}
	if key == nil {
		t.Fatalf("no keyed entity with two fields: %+v", res.Entities)
	}
	c := ruleByOp(res, "POST /documents/{documentId}/versions/{versionId}/sign", "|update")
	if c == nil {
		t.Fatalf("no update of the consent: %+v", res.Diag.Rules)
	}
	ef := c.Effects[0]
	if ef.TargetKey == nil || len(*ef.TargetKey) != 2 || ef.Set["signed"] != true {
		t.Fatalf("effect: %+v %v", ef, ef.TargetKey)
	}
	for _, f := range key.Fields {
		v := (*ef.TargetKey)[f]
		name := strings.TrimSuffix(strings.TrimPrefix(v, "${"), "}")
		if b, ok := c.Cause.Bind[name]; !ok || b.From != "req.path" || !strings.EqualFold(b.Name, f) {
			t.Fatalf("field %s: %q bound to %+v", f, v, c.Cause.Bind)
		}
	}
}

func TestKeyedTargetSeveralFieldsNegative(t *testing.T) {
	res := consentVersionTraffic(30, false).mine(t, smallK(), MineOptions{})
	if c := ruleByOp(res, "POST /documents/{documentId}/sign", "|update"); c != nil {
		t.Fatalf("a call that misses the version is not a cause: %+v", c)
	}
}

// ---- C15: family candidates ----

// walletTraffic: each user opens 1–3 contracts (the write answers its id
// under the domain contract); a minute later the wallet lists them under
// another name (domain walletcontract). related=true: the wallet record
// holds both ids (a relation, two objects): never a family.
func walletTraffic(users int, related bool) *traffic {
	tr := newTraffic()
	for u := 0; u < users; u++ {
		var items []any
		for k := 0; k <= u%3; k++ {
			n := u*10 + k
			tr.add(xcall{op: "POST /contracts", status: 201, user: user(u), req: map[string]any{"plan": keep("BASE")},
				resp: map[string]any{"contractId": tok("contract", n)}})
			item := map[string]any{"walletContractId": tok("walletc", n), "status": keep("ON")}
			if related {
				item["contractId"] = tok("contract", n)
			}
			items = append(items, item)
			tr.add(xcall{op: "GET /wallet", user: user(u), resp: map[string]any{"items": items}})
		}
		tr.now = tr.now.Add(time.Hour)
	}
	return tr
}

func familyOf(res *Result, a, b string) *FamilyCandidate {
	for i := range res.Diag.Families {
		f := &res.Diag.Families[i]
		if len(f.Domains) == 2 && famPair(a, b) == [2]string{f.Domains[0], f.Domains[1]} {
			return f
		}
	}
	return nil
}

func TestFamilyCandidate(t *testing.T) {
	res := walletTraffic(30, false).mine(t, smallK(), MineOptions{})
	f := familyOf(res, "contract", "walletcontract")
	if f == nil {
		t.Fatalf("no family: %+v", res.Diag.Families)
	}
	if f.Subjects != 30 || f.Score <= 0 || f.Score > 1 || len(f.Signals) < 2 || f.Signals[0] != SignalSameCardinality {
		t.Fatalf("family: %+v", f)
	}
}

func TestFamilyCandidateNegative(t *testing.T) {
	if f := familyOf(walletTraffic(30, true).mine(t, smallK(), MineOptions{}), "contract", "walletcontract"); f != nil {
		t.Fatalf("a relation is not a family: %+v", f)
	}
	if f := familyOf(walletTraffic(4, false).mine(t, smallK(), MineOptions{}), "contract", "walletcontract"); f != nil {
		t.Fatalf("a family with 4 users < k: %+v", f)
	}
	// different cardinalities: the wallet holds one item whatever the contracts
	tr := newTraffic()
	for u := 0; u < 30; u++ {
		for k := 0; k <= u%3; k++ {
			tr.add(xcall{op: "POST /contracts", status: 201, user: user(u), req: map[string]any{"plan": keep("BASE")},
				resp: map[string]any{"contractId": tok("contract", u*10+k)}})
			tr.add(xcall{op: "GET /wallet", user: user(u), resp: map[string]any{"items": []any{map[string]any{"walletContractId": tok("walletc", u)}}}})
		}
	}
	if f := familyOf(tr.mine(t, smallK(), MineOptions{}), "contract", "walletcontract"); f != nil {
		t.Fatalf("different cardinalities: %+v", f)
	}
}
