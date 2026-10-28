package miner

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

type memSink struct {
	mu sync.Mutex
	ns []StaleNotice
}

func (s *memSink) RuleStale(_ context.Context, n StaleNotice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ns = append(s.ns, n)
}

func (s *memSink) last() StaleNotice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ns) == 0 {
		return StaleNotice{}
	}
	return s.ns[len(s.ns)-1]
}

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// copyResult returns a result whose rules can be changed without touching
// the shared fixture.
func copyResult(t *testing.T, res *Result) *Result {
	t.Helper()
	out := *res
	out.Rules = nil
	for _, mm := range res.Rules {
		r, err := cloneRule(mm.Rule)
		if err != nil {
			t.Fatal(err)
		}
		c := *mm
		c.Rule = r
		out.Rules = append(out.Rules, &c)
	}
	return &out
}

func findSig(res *Result, prefix string) *Mined {
	for _, mm := range res.Rules {
		if len(mm.Signature) >= len(prefix) && mm.Signature[:len(prefix)] == prefix {
			return mm
		}
	}
	return nil
}

func TestRepoLifecycle(t *testing.T) {
	_, res := demoFixture(t)
	ctx := context.Background()
	sink := &memSink{}
	cfg := DefaultConfig()
	cfg.StaleRuns = 1 // the staleness over several runs is in restart_test.go
	rp := NewRepo(openDB(t), cfg, sink)
	now := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)

	rep, err := rp.Apply(ctx, copyResult(t, res), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.New) != 3 || len(rep.Updated) != 0 {
		t.Fatalf("first run: %+v", rep)
	}
	ids := map[string]string{}
	for _, sig := range []string{"causal|shop-api|POST /orders", "causal|shipping-ext", "batch|"} {
		for _, r := range mustList(t, rp, "") {
			if len(r.Signature) >= len(sig) && r.Signature[:len(sig)] == sig {
				ids[sig] = r.Rule.ID()
				if r.Rule.Status() != StatusDraft {
					t.Errorf("new rule %s is %s", r.Rule.ID(), r.Rule.Status())
				}
			}
		}
	}
	orders := ids["causal|shop-api|POST /orders"]

	// Same traffic again: same ids, refreshed in place.
	rep, err = rp.Apply(ctx, copyResult(t, res), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.New) != 0 || len(rep.Updated) != 3 {
		t.Fatalf("second run: %+v", rep)
	}

	// Reviewer edits survive a re-mining.
	title := "Un ordine crea una spedizione"
	if _, err := rp.Edit(ctx, orders, &title, map[string]Delay{"shipment-created": {Single: "5m"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Apply(ctx, copyResult(t, res), now, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, rp, orders)
	if got.Rule.Causal.Title != title || effectAfter(got.Rule.Causal, "shipment-created") != "5m" {
		t.Errorf("edits lost: %q %v", got.Rule.Causal.Title, effectAfter(got.Rule.Causal, "shipment-created"))
	}
	if _, err := rp.Edit(ctx, orders, nil, map[string]Delay{"no-such-effect": {Single: "5m"}}, now); !errors.Is(err, ErrBadEdit) {
		t.Errorf("edit of an unknown effect: %v", err)
	}
	if _, err := rp.Edit(ctx, orders, nil, map[string]Delay{"shipment-created": {Single: "5 minutes"}}, now); !errors.Is(err, ErrBadEdit) {
		t.Errorf("edit with a bad duration: %v", err)
	}

	// Approve: only a person does it; the miner then leaves the body alone.
	ap, err := rp.Approve(ctx, orders, "usr_alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if ap.Rule.Status() != StatusApproved || ap.Rule.Causal.Review == nil || ap.Rule.Causal.Review.By[0] != "usr_alice" {
		t.Fatalf("approve: %+v", ap.Rule.Causal.Review)
	}
	if _, err := rp.Apply(ctx, copyResult(t, res), now, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if mustGet(t, rp, orders).Rule.Status() != StatusApproved {
		t.Errorf("approved rule changed by an unchanged run")
	}

	// Confidence drops: stale, and the drift hook is told.
	low := copyResult(t, res)
	findSig(low, "causal|shop-api|POST /orders").Confidence = 0.3
	rep, err = rp.Apply(ctx, low, now, now.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Stale) != 1 || rep.Stale[0] != orders {
		t.Fatalf("stale: %+v", rep)
	}
	if n := sink.last(); n.RuleID != orders || n.Reason != "confidence_drop" || n.Current != 0.3 {
		t.Errorf("notice: %+v", n)
	}
	st := mustGet(t, rp, orders)
	if st.Rule.Status() != StatusStale || st.Rule.Causal.Title != title {
		t.Errorf("stale rule: %s %q", st.Rule.Status(), st.Rule.Causal.Title)
	}

	// The reviewer confirms; then the cause is seen but the rule not mined.
	if _, err := rp.Approve(ctx, orders, "usr_alice", now); err != nil {
		t.Fatal(err)
	}
	gone := copyResult(t, res)
	var kept []*Mined
	for _, mm := range gone.Rules {
		if mm.Signature != findSig(res, "causal|shop-api|POST /orders").Signature {
			kept = append(kept, mm)
		}
	}
	gone.Rules = kept
	if _, err := rp.Apply(ctx, gone, now, now.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := sink.last(); n.RuleID != orders || n.Reason != "not_observed" {
		t.Errorf("notice: %+v", n)
	}
	if _, err := rp.Approve(ctx, orders, "usr_alice", now); err != nil {
		t.Fatal(err)
	}

	// A changed structure becomes a new draft that supersedes the approved rule.
	changed := copyResult(t, res)
	mm := findSig(changed, "causal|shop-api|POST /orders")
	mm.Structure += "|changed"
	rep, err = rp.Apply(ctx, changed, now, now.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.New) != 1 {
		t.Fatalf("structure change: %+v", rep)
	}
	nd := mustGet(t, rp, rep.New[0])
	if nd.Rule.Status() != StatusDraft || nd.Rule.Causal.Supersedes != orders || mustGet(t, rp, orders).Rule.Status() != StatusApproved {
		t.Errorf("superseding draft: %s supersedes %q", nd.Rule.Status(), nd.Rule.Causal.Supersedes)
	}

	// Editing an approved rule also creates a superseding draft.
	batch := ids["batch|"]
	if _, err := rp.Approve(ctx, batch, "usr_bob", now); err != nil {
		t.Fatal(err)
	}
	t2 := "Consolidamento notturno"
	ed, err := rp.Edit(ctx, batch, &t2, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if ed.Rule.ID() == batch || ed.Rule.Batch.Supersedes != batch || ed.Rule.Batch.Title != t2 || ed.Rule.Status() != StatusDraft {
		t.Errorf("edit of approved: %+v", ed.Rule.Batch)
	}
	if _, err := rp.Edit(ctx, batch, nil, map[string]Delay{"x": {Single: "1m"}}, now); !errors.Is(err, ErrBadEdit) {
		t.Errorf("after on a batch rule: %v", err)
	}

	// Reject, and what a rejected rule refuses.
	carrier := ids["causal|shipping-ext"]
	rj, err := rp.Reject(ctx, carrier, "usr_bob", "duplicate of the shop rule", now)
	if err != nil {
		t.Fatal(err)
	}
	if rj.Rule.Status() != StatusRejected || rj.Rule.Causal.Review.Note == "" {
		t.Errorf("reject: %+v", rj.Rule.Causal.Review)
	}
	if _, err := rp.Approve(ctx, carrier, "usr_bob", now); !errors.Is(err, ErrConflict) {
		t.Errorf("approve rejected: %v", err)
	}
	if _, err := rp.Edit(ctx, carrier, &t2, nil, now); !errors.Is(err, ErrConflict) {
		t.Errorf("edit rejected: %v", err)
	}
	// A rejected rule is not proposed again while nothing changes.
	rep, err = rp.Apply(ctx, copyResult(t, res), now, now.Add(7*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if mustGet(t, rp, carrier).Rule.Status() != StatusRejected {
		t.Errorf("rejected rule touched")
	}
	for _, id := range rep.New {
		if mustGet(t, rp, id).Rule.Causal != nil && mustGet(t, rp, id).Signature == mustGet(t, rp, carrier).Signature {
			t.Errorf("rejected rule re-proposed as %s", id)
		}
	}

	// Drift hook in the other direction: a contract change marks it stale.
	if err := rp.MarkStale(ctx, orders, "contract_changed", now); err != nil {
		t.Fatal(err)
	}
	if n := sink.last(); n.RuleID != orders || n.Reason != "contract_changed" {
		t.Errorf("notice: %+v", n)
	}
	if err := rp.MarkStale(ctx, carrier, "contract_changed", now); !errors.Is(err, ErrConflict) {
		t.Errorf("mark stale of a rejected rule: %v", err)
	}

	// Never auto-approved: every approval above came from Approve.
	for _, r := range mustList(t, rp, StatusApproved) {
		if r.Rule.ID() != batch {
			t.Errorf("unexpected approved rule %s", r.Rule.ID())
		}
	}
	doc, err := rp.Document(ctx, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Errorf("stored document: %v", err)
	}
	if _, err := rp.Get(ctx, "r-9999"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get unknown: %v", err)
	}
}

func effectAfter(c *CausalRule, id string) string {
	for _, e := range c.Effects {
		if e.ID == id {
			return e.After.Single
		}
	}
	return ""
}

func mustList(t *testing.T, rp *Repo, status string) []*StoredRule {
	t.Helper()
	rs, err := rp.List(context.Background(), status)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func mustGet(t *testing.T, rp *Repo, id string) *StoredRule {
	t.Helper()
	r, err := rp.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
