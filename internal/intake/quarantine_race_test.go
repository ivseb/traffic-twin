package intake

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// Many handlers race with the creation of a quarantine and its rewrite of
// stored events: when everything settles, no quarantined value is left.
func TestQuarantineUnderConcurrentIngestion(t *testing.T) {
	h := newHarness(t, withConfig(func(c *Config) { c.BatchSize = 64; c.RewriteChunk = 50 }))
	hash := h.pol.Hash
	const workers, per = 8, 150
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				rej, err := h.in.IngestEvent(context.Background(), testSource, []byte(statusEvent(hash, w*1000+i)))
				if err == ErrOverloaded {
					i--
					continue
				}
				if err != nil || rej.Reason != ReasonNone {
					t.Errorf("worker %d event %d: %v %v", w, i, err, rej)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	qs := h.in.Quarantines(false)
	if len(qs) != 1 {
		t.Fatalf("%+v", qs)
	}
	h.waitRewrite(t, qs[0].ID)
	bodies := h.storedBodies(t)
	if len(bodies) != workers*per {
		t.Fatalf("stored %d, want %d", len(bodies), workers*per)
	}
	if n := countContaining(bodies, `"keep:S`); n != 0 {
		t.Fatalf("%d events kept a quarantined value", n)
	}
	if rawContains(h, "keep:S1") || rawContains(h, "keep:S5") {
		t.Fatal("quarantined values survive in the database files")
	}
}

// A rewrite interrupted by a restart is finished at the next start.
func TestRewriteResumesAfterRestart(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 70; i++ {
		h.ingest(t, statusEvent(hash, i))
	}
	qs := h.in.Quarantines(false)
	if len(qs) != 1 {
		t.Fatal("no quarantine")
	}
	h.waitRewrite(t, qs[0].ID)
	if err := h.in.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Pretend the process died before the rewrite finished and put an old
	// value back, as a half-done rewrite would have left it.
	if _, err := h.db.Exec(`UPDATE intake_quarantine SET rewrite_done = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE intake_events SET body = CAST(replace(CAST(body AS TEXT), '"status":"drop:str:l8"', '"status":"keep:S5"') AS BLOB) WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	in, err := New(context.Background(), h.cfg, Deps{DB: h.db, Sources: h.sources, Policies: h.policies, Now: h.clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close(context.Background())
	h.in = in
	h.waitRewrite(t, qs[0].ID)
	if n := countContaining(h.storedBodies(t), `"keep:S`); n != 0 {
		t.Fatalf("%d events kept a quarantined value after the resumed rewrite", n)
	}
}

func TestPathParameterAndQueryKeepQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	// A kept path parameter: GET /v1/rates/{zone} with a rule keep on zone.
	rate := func(zone string) string {
		return mutate(t, shipmentPost(hash), func(e eventT) {
			e.Op = "GET /v1/rates/{zone}"
			e.Req.Path = "/v1/rates/{keep:" + zone + "}"
			e.Req.Body, e.Req.CT, e.Req.Size, e.Resp.Body = nil, "", "l8", nil
		})
	}
	// A kept query value: promo on POST /orders.
	promo := func(code string) string {
		return strings.Replace(orderPost(hash), `"keep:AUTUMN10"`, `"keep:`+code+`"`, 1)
	}
	for i := 0; i < 70; i++ {
		if rej := h.ingest(t, rate("Z"+twoLetters(i))); rej.Reason != ReasonNone {
			t.Fatalf("rate %d: %s %s", i, rej.Reason, rej.Detail)
		}
		if rej := h.ingest(t, promo("P"+twoLetters(i))); rej.Reason != ReasonNone {
			t.Fatalf("promo %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	qs := h.in.Quarantines(false)
	parts := map[string]string{}
	for _, q := range qs {
		parts[q.Part] = q.Path
		h.waitRewrite(t, q.ID)
	}
	if parts["req.path"] != "p2" || parts["req.query"] != "promo" {
		t.Fatalf("quarantines: %+v", qs)
	}
	bodies := h.storedBodies(t)
	if countContaining(bodies, `{keep:Z`) != 0 || countContaining(bodies, `keep:P`) != 0 {
		t.Fatal("kept path or query values survive")
	}
	if countContaining(bodies, `/v1/rates/{drop:str:l8}`) != 70 || countContaining(bodies, `"promo":["drop:str:l8"]`) != 70 {
		t.Fatal("values were not rewritten to their drop forms")
	}
}
