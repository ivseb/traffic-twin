package miner

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// The key acceptance test of the miner: on demo-like traffic produced from
// demo/GROUND_TRUTH.md (deterministic simulation, Go sanitizer, intake), the
// miner must rediscover R1–R4 and the client-visible part of R5, and must
// not propose anything else.

var (
	demoOnce sync.Once
	demoFix  *simFixture
	demoRes  *Result
	demoDir  string
)

var simStart = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	code := m.Run()
	if demoFix != nil {
		demoFix.close()
	}
	if demoDir != "" {
		os.RemoveAll(demoDir)
	}
	os.Exit(code)
}

func demoFixture(t *testing.T) (*simFixture, *Result) {
	t.Helper()
	demoOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tt-miner-eval-")
		if err != nil {
			t.Fatal(err)
		}
		demoDir = dir
		s := runSim(simConfig{Seed: 42, Customers: 1000, Days: 8, Start: simStart})
		demoFix = ingestSim(t, s, dir)
		demoRes, err = Mine(context.Background(), demoFix.store, time.Time{}, time.Time{}, demoFix.doms, DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
	})
	if demoFix == nil || demoRes == nil {
		t.Fatal("demo fixture unavailable")
	}
	return demoFix, demoRes
}

type keyEndID struct{ service, op, at string }

func endID(e KeyEnd) keyEndID { return keyEndID{e.Service, e.Op, e.At.String()} }

// R1: where each value appears (in the sanitized world).
var r1Groups = map[string][]keyEndID{
	"order": {
		{"shop-api", "POST /orders", "resp.body$.id"},
		{"shipping-ext", "POST /v1/shipments", "req.body$.orderId"},
		{"shipping-ext", "POST /v1/shipments", "resp.body$.orderId"},
		{"shipping-ext", "GET /v1/shipments", "req.query:orderId"},
		{"shipping-ext", "GET /v1/shipments", "resp.body$.items[*].orderId"},
		{"shop-api", "GET /orders/{id}", "req.path:id"},
		{"shop-api", "GET /orders/{id}", "resp.body$.id"},
		{"shop-api", "GET /orders/{id}/shipment", "req.path:id"},
		{"shop-api", "GET /orders/{id}/shipment", "resp.body$.orderId"},
		{"shop-api", "GET /customers/{id}/orders", "resp.body$.items[*].id"},
	},
	"shipment": {
		{"shipping-ext", "POST /v1/shipments", "resp.body$.shipmentId"},
		{"shop-api", "POST /orders", "resp.body$.shipmentId"},
		{"shipping-ext", "GET /v1/shipments", "resp.body$.items[*].shipmentId"},
		{"shop-api", "GET /orders/{id}/shipment", "resp.body$.shipmentId"},
		{"shop-api", "GET /orders/{id}", "resp.body$.shipmentId"},
	},
	"customer": {
		{"shop-api", "GET /customers/{id}/orders", "req.path:id"},
		{"shop-api", "GET /customers/{id}/orders", "resp.body$.customerId"},
		{"shop-api", "POST /orders", "resp.body$.customerId"},
		{"shop-api", "GET /orders/{id}", "resp.body$.customerId"},
	},
}

type evalReport struct {
	lines []string
}

func (r *evalReport) add(format string, a ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, a...))
}

func within(got, want, tol float64) bool { return math.Abs(got-want) <= tol }

func TestEvalGroundTruth(t *testing.T) {
	fix, res := demoFixture(t)
	truth := fix.sim.truth
	rep := &evalReport{}
	rep.add("simulation: %d customers, %d days, %d exchanges, %d orders; truth outcomes %v",
		1000, 8, truth.Events, truth.Orders, truth.Outcomes)

	doc := res.Document(time.Time{}, nil)
	if err := doc.Validate(); err != nil {
		t.Fatalf("mined document is not valid: %v", err)
	}

	// ---- R1: link keys -------------------------------------------------
	groupOf := map[keyEndID]string{}
	for g, ends := range r1Groups {
		for _, e := range ends {
			groupOf[e] = g
		}
	}
	expectedPairs := map[[2]keyEndID]bool{}
	for _, ends := range r1Groups {
		for i := range ends {
			for j := i + 1; j < len(ends); j++ {
				a, b := ends[i], ends[j]
				if b.service+b.op+b.at < a.service+a.op+a.at {
					a, b = b, a
				}
				expectedPairs[[2]keyEndID{a, b}] = true
			}
		}
	}
	keyTP, keyFP := 0, 0
	found := map[[2]keyEndID]bool{}
	for _, k := range res.Keys {
		a, b := endID(k.From), endID(k.To)
		ga, gb := groupOf[a], groupOf[b]
		if ga != "" && ga == gb && ga == k.Domain {
			keyTP++
		} else {
			keyFP++
			t.Errorf("spurious link key: %s", keyString(k))
		}
		if b.service+b.op+b.at < a.service+a.op+a.at {
			a, b = b, a
		}
		found[[2]keyEndID{a, b}] = true
	}
	keyRecallN := 0
	for p := range expectedPairs {
		if found[p] {
			keyRecallN++
		}
	}
	keyP := float64(keyTP) / math.Max(1, float64(keyTP+keyFP))
	keyR := float64(keyRecallN) / float64(len(expectedPairs))
	rep.add("R1 link keys: %d proposed, precision %.3f, recall %.3f (%d/%d location pairs)", len(res.Keys), keyP, keyR, keyRecallN, len(expectedPairs))
	if keyP < 1 {
		t.Errorf("key precision %.3f < 1", keyP)
	}
	if keyR < 0.8 {
		t.Errorf("key recall %.3f < 0.8", keyR)
	}
	mustKey := [2]keyEndID{{"shop-api", "POST /orders", "resp.body$.shipmentId"}, {"shipping-ext", "POST /v1/shipments", "resp.body$.shipmentId"}}
	if !found[mustKey] && !found[[2]keyEndID{mustKey[1], mustKey[0]}] {
		t.Errorf("order↔shipment key (shipmentId in POST /orders and POST /v1/shipments) not found")
	}
	ents := map[string]*Entity{}
	for i := range res.Entities {
		ents[res.Entities[i].Name] = &res.Entities[i]
	}
	hasRel := func(e, field, target string) bool {
		if ents[e] == nil {
			return false
		}
		for _, r := range ents[e].Relations {
			if r.Field == field && r.Entity == target {
				return true
			}
		}
		return false
	}
	if !hasRel("order", "shipmentId", "shipment") || !hasRel("shipment", "orderId", "order") {
		t.Errorf("relations order.shipmentId ↔ shipment.orderId not found")
	}
	if len(res.Entities) != 2 || ents["order"] == nil || ents["shipment"] == nil {
		t.Errorf("entities: want order and shipment, got %d", len(res.Entities))
	}
	rep.add("R1 relations: order.shipmentId→shipment %v, shipment.orderId→order %v", hasRel("order", "shipmentId", "shipment"), hasRel("shipment", "orderId", "order"))

	// ---- rules: precision / recall ---------------------------------------
	var r7, r8 *CausalRule
	var r12 *BatchRule
	tp, fp := 0, 0
	for _, mm := range res.Rules {
		switch {
		case mm.Rule.Causal != nil && mm.Rule.Causal.Cause.Service == "shop-api" && mm.Rule.Causal.Cause.Op == "POST /orders":
			r7 = mm.Rule.Causal
			tp++
		case mm.Rule.Causal != nil && mm.Rule.Causal.Cause.Service == "shipping-ext" && mm.Rule.Causal.Cause.Op == "POST /v1/shipments":
			r8 = mm.Rule.Causal
			tp++
		case mm.Rule.Batch != nil && mm.Rule.Batch.Entity == "shipment" && mm.Rule.Batch.Schedule == "0 2 * * *" &&
			mm.Rule.Batch.Where["status"] == "IN_TRANSIT" && mm.Rule.Batch.Set["status"] == "DELIVERED":
			r12 = mm.Rule.Batch
			tp++
		default:
			fp++
			b, _ := json.Marshal(mm.Rule)
			t.Errorf("spurious rule: %s", b)
		}
	}
	ruleP := float64(tp) / math.Max(1, float64(tp+fp))
	ruleR := float64(tp) / 3
	rep.add("rules: %d proposed, precision %.3f, recall %.3f (expected r-0007 POST /orders, r-0008 POST /v1/shipments, r-0012 batch)", len(res.Rules), ruleP, ruleR)
	if r7 == nil || r8 == nil || r12 == nil {
		t.Fatalf("missing rules: r-0007 %v, r-0008 %v, r-0012 %v", r7 != nil, r8 != nil, r12 != nil)
	}

	// ---- R2: immediate effect ---------------------------------------------
	eff := map[string]Effect{}
	for _, e := range r7.Effects {
		eff[e.ID] = e
	}
	if !equalInts(r7.Cause.When.Status, []int{201}) || r7.Cause.Bind["order"] != (Ref{From: "resp.body", Path: "$.id"}) {
		t.Errorf("r-0007 cause: %+v", r7.Cause)
	}
	req := eff["shipment-requested"]
	if req.Entity != "shipment" || req.Create["orderId"] != "${order}" || req.Create["status"] != "PENDING" || req.After.Single != "0s" {
		t.Errorf("R2 immediate effect: %+v", req)
	}
	link := eff["order-linked"]
	if link.TargetID != "${order}" || link.Set["shipmentId"] != "${effect:shipment-requested}" || link.After.Single != "0s" {
		t.Errorf("R2 link effect: %+v", link)
	}
	rep.add("R2: shipment-requested create {orderId: ${order}, status: PENDING} after 0s = %v; order-linked = %v",
		req.Create["orderId"] == "${order}", link.TargetID == "${order}")

	// ---- R3: lifecycle chain and outcomes -------------------------------
	chain := []struct{ id, after, status string }{
		{"shipment-created", "shipment-requested", "CREATED"},
		{"shipment-in-transit", "shipment-created", "IN_TRANSIT"},
		{"shipment-delivered", "shipment-in-transit", "DELIVERED"},
		{"shipment-cancelled", "shipment-created", "CANCELLED"},
	}
	chainOK := true
	for _, c := range chain {
		e, ok := eff[c.id]
		if !ok || e.AfterEffect != c.after || e.Set["status"] != c.status || e.Target != "shipment-requested" {
			chainOK = false
			t.Errorf("R3 effect %s: %+v", c.id, e)
		}
	}
	effTP := 0
	expectedEff := map[string]bool{"shipment-requested": true, "order-linked": true}
	for _, c := range chain {
		expectedEff[c.id] = true
	}
	for _, e := range r7.Effects {
		if expectedEff[e.ID] {
			effTP++
		} else {
			t.Errorf("spurious effect %s", e.ID)
		}
	}
	rep.add("R3 chain created → in-transit → delivered (cancelled after created) in order: %v; effects precision %.3f recall %.3f",
		chainOK, float64(effTP)/float64(len(r7.Effects)), float64(effTP)/float64(len(expectedEff)))
	mags := r7.Evidence.Hints.Magnitude
	if mags["shipment-created"] != MagMinutes || mags["shipment-in-transit"] != MagHours || mags["shipment-requested"] != MagSeconds {
		t.Errorf("magnitude hints: %v", mags)
	}
	rep.add("R3 magnitude hints: %v", mags)

	outP := map[string]float64{}
	outE := map[string][]string{}
	for _, o := range r7.Outcomes {
		outP[o.Name], outE[o.Name] = o.P, o.Effects
	}
	if len(r7.Outcomes) != 3 {
		t.Errorf("outcomes: %+v", r7.Outcomes)
	}
	// Exact truth over the same decided orders (placed early enough).
	decided := map[string]int{}
	cut := fix.sim.end.Add(-48 * time.Hour)
	for _, sh := range truth.shipments {
		if sh.created.Before(cut) {
			decided[sh.outcome]++
		}
	}
	dn := float64(decided["happy"] + decided["cancelled"] + decided["never"])
	for _, c := range []struct {
		name, truthName string
		p, tol          float64
	}{{"happy", "happy", 0.93, 0.03}, {"cancelled", "cancelled", 0.04, 0.015}, {"never", "never", 0.03, 0.015}} {
		got := outP[c.name]
		if !within(got, c.p, c.tol) {
			t.Errorf("outcome %s: p=%.3f, want %.2f±%.3f", c.name, got, c.p, c.tol)
		}
		rep.add("R3 outcome %-9s p=%.3f (count %d)  ground truth %.2f, exact share in simulation %.3f",
			c.name, got, r7.Evidence.Counts.Outcomes[c.name], c.p, float64(decided[c.truthName])/dn)
	}
	if !equalStrings(outE["happy"], []string{"shipment-requested", "order-linked", "shipment-created", "shipment-in-transit", "shipment-delivered"}) ||
		!equalStrings(outE["cancelled"], []string{"shipment-requested", "order-linked", "shipment-created", "shipment-cancelled"}) ||
		!equalStrings(outE["never"], []string{"shipment-requested", "order-linked"}) {
		t.Errorf("outcome effects: %v", outE)
	}
	if r7.Evidence.Counts.Causes != truth.Orders {
		t.Errorf("causes %d, want %d (every 201 has exactly one 202)", r7.Evidence.Counts.Causes, truth.Orders)
	}
	rep.add("R2 invariant: causes %d = orders %d; key_matches %d", r7.Evidence.Counts.Causes, truth.Orders, *r7.Evidence.Counts.KeyMatches)
	// r-0008: same lifecycle seen from the carrier.
	if r8.Cause.Bind["shipment"] != (Ref{From: "resp.body", Path: "$.shipmentId"}) || len(r8.Outcomes) != 3 {
		t.Errorf("r-0008: %+v", r8.Cause)
	}
	for _, e := range r8.Effects {
		if e.ID == "shipment-created" && e.TargetID != "${shipment}" {
			t.Errorf("r-0008 first effect must target ${shipment}: %+v", e)
		}
	}
	// hidden_when PENDING on both reads.
	hidden := 0
	for _, rb := range ents["shipment"].ReadBy {
		if rb.HiddenWhen["status"] == "PENDING" {
			hidden++
		}
	}
	if hidden != 2 {
		t.Errorf("hidden_when PENDING on %d shipment reads, want 2", hidden)
	}
	rep.add("R3 visibility: hidden_when {status: PENDING} on %d/2 shipment reads", hidden)

	// ---- R4: batch -------------------------------------------------------
	moved := 0
	runs := 0
	for _, r := range truth.Runs {
		moved += r.moved
		if r.moved > 0 {
			runs++
		}
	}
	if !within(r12.Fraction, 0.6, 0.05) {
		t.Errorf("batch fraction %.2f, want 0.6±0.05", r12.Fraction)
	}
	if r12.Evidence.Counts.Runs != runs {
		t.Errorf("batch runs %d, want %d", r12.Evidence.Counts.Runs, runs)
	}
	if !within(float64(r12.Evidence.Counts.EntitiesChanged), float64(moved), 0.1*float64(moved)) {
		t.Errorf("batch entities_changed %d, truth %d", r12.Evidence.Counts.EntitiesChanged, moved)
	}
	rep.add("R4 batch: schedule %q, %v → %v, fraction %.2f (truth 0.6), runs %d (truth %d), entities_changed %d (truth %d), confidence %s",
		r12.Schedule, r12.Where, r12.Set, r12.Fraction, r12.Evidence.Counts.Runs, runs, r12.Evidence.Counts.EntitiesChanged, moved,
		r12.Evidence.Hints.ScheduleConfidence)

	// ---- R5 (client-visible part): reads per customer -----------------------
	var listOK, getOK bool
	for _, rb := range ents["order"].ReadBy {
		if rb.Op == "GET /customers/{id}/orders" && rb.By != nil && rb.By.Owner && rb.Scope == "owner" && rb.Foreign == "forbidden" &&
			rb.List != nil && rb.List.Count == "$.count" && rb.At.Path == "$.items[*]" {
			listOK = true
		}
		if rb.Op == "GET /orders/{id}" && rb.By != nil && rb.By.Name == "id" && rb.Scope == "owner" {
			getOK = true
		}
	}
	if !listOK || !getOK {
		t.Errorf("order read_by: %+v", ents["order"].ReadBy)
	}
	rep.add("R5 (reads seen by clients): GET /customers/{id}/orders owner list with 403 for others = %v; GET /orders/{id} owner scope = %v", listOK, getOK)

	// ---- the mined rules plug into the demo pack ---------------------------
	loadsInPack(t, res)
	rep.add("mined rules (as r-0007/r-0008/r-0012) load in the v1.2 demo pack: ok")

	t.Log("\n" + strings.Join(rep.lines, "\n"))
	if p := os.Getenv("TT_MINER_EVAL_REPORT"); p != "" {
		_ = os.WriteFile(p, []byte(strings.Join(rep.lines, "\n")+"\n"), 0o644)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// loadsInPack swaps the mined document into the demo pack of internal/pack
// (renaming the ids the demo world and scenarios refer to) and loads it with
// the v1.2 pack reader.
func loadsInPack(t *testing.T, res *Result) {
	t.Helper()
	var rules []Rule
	for _, mm := range res.Rules {
		r, err := cloneRule(mm.Rule)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case r.Causal != nil && r.Causal.Cause.Op == "POST /orders":
			r.Causal.ID = "r-0007"
		case r.Causal != nil:
			r.Causal.ID = "r-0008"
		default:
			r.Batch.ID = "r-0012"
		}
		_, pst, _, _, _ := r.common()
		*pst = StatusApproved
		rules = append(rules, r)
	}
	sort.Slice(rules, func(a, b int) bool { return rules[a].ID() < rules[b].ID() })
	doc := res.Document(time.Date(2026, 10, 19, 3, 0, 0, 0, time.UTC), rules)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	spec := packtest.DemoSpec()
	spec.Files["rules.json"] = packtest.CJSON(packtest.JSON(string(b)))
	built, err := packtest.Build(filepath.Join(t.TempDir(), "pack"), spec)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pack.ParseKeySet(built.Keys)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(built.Dir, pack.Options{Keys: keys, MaxAge: -1})
	if err != nil {
		t.Fatalf("pack reader refuses the mined rules: %v", err)
	}
	if len(p.Rules.Causal) != 2 || len(p.Rules.Batch) != 1 {
		t.Fatalf("pack rules: %d causal, %d batch", len(p.Rules.Causal), len(p.Rules.Batch))
	}
}
