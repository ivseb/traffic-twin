package intake

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
)

func statusEvent(hash string, i int) string {
	return strings.Replace(orderPost(hash), `"keep:CREATED"`, fmt.Sprintf(`"keep:S%d"`, i), 1)
}

func twoLetters(i int) string { return string(rune('a'+i/26)) + string(rune('a'+i%26)) }

func (h *harness) waitRewrite(t testing.TB, id int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var done int
		if err := h.db.QueryRow(`SELECT rewrite_done FROM intake_quarantine WHERE id = ?`, id).Scan(&done); err == nil && done == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("rewrite of quarantine %d did not complete", id)
}

// storedBodies returns the canonical text of every stored event.
func (h *harness) storedBodies(t testing.TB) []string {
	t.Helper()
	h.idle(t)
	var out []string
	err := h.in.Store().Scan(context.Background(), Query{}, func(se *StoredEvent) error {
		out = append(out, string(se.Event.Canonical()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rawContains looks for text in the database file and its write-ahead log.
func rawContains(h *harness, text string) bool {
	for _, name := range []string{h.db.Path(), h.db.Path() + "-wal"} {
		if raw, err := os.ReadFile(name); err == nil && bytes.Contains(raw, []byte(text)) {
			return true
		}
	}
	return false
}

func countContaining(bodies []string, sub string) int {
	n := 0
	for _, b := range bodies {
		if strings.Contains(b, sub) {
			n++
		}
	}
	return n
}

func TestKeepQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash

	// 45 distinct values: below the threshold, nothing happens.
	for i := 0; i < 45; i++ {
		if rej := h.ingest(t, statusEvent(hash, i)); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	if len(h.in.Quarantines(false)) != 0 {
		t.Fatal("quarantine raised too early")
	}
	// Positive control for the raw-file check further down: the values are
	// in the database files before the quarantine.
	h.idle(t)
	if !rawContains(h, "keep:S1") {
		t.Fatal("test setup: stored values are not visible in the database files")
	}
	// More distinct values cross the threshold of 50.
	for i := 45; i < 70; i++ {
		if rej := h.ingest(t, statusEvent(hash, i)); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	qs := h.in.Quarantines(false)
	if len(qs) != 1 {
		t.Fatalf("quarantines: %+v", qs)
	}
	q := qs[0]
	if q.Kind != QuarantineKeep || q.State != StateOpen || q.PolicyID != "p-shop" || q.Service != "shop-api" ||
		q.Op != "POST /orders" || q.Part != "resp.body" || q.Path != "$.status" || q.Threshold != 50 || q.Estimate <= 50 {
		t.Fatalf("quarantine: %+v", q)
	}
	// The alarm, in the audit log and to the sink.
	if al := h.alarms.Snapshot(); len(al) != 1 || al[0].ID != q.ID {
		t.Fatalf("alarms: %+v", al)
	}
	var entries []audit.Entry
	_ = h.audit.Iterate(context.Background(), 0, 100, func(e audit.Entry) error { entries = append(entries, e); return nil })
	if len(entries) != 1 || entries[0].Action != "intake.quarantine" || entries[0].Details["kind"] != "keep" {
		t.Fatalf("audit: %+v", entries)
	}

	// Stored events are rewritten and the original values are gone.
	h.waitRewrite(t, q.ID)
	bodies := h.storedBodies(t)
	if len(bodies) != 70 {
		t.Fatalf("stored %d events", len(bodies))
	}
	if n := countContaining(bodies, `"keep:S`); n != 0 {
		t.Fatalf("%d stored events still hold a quarantined value", n)
	}
	if n := countContaining(bodies, `"status":"drop:str:l8"`); n != 70 {
		t.Fatalf("%d events carry the drop form, want 70", n)
	}
	// Other kept fields are untouched.
	if n := countContaining(bodies, `keep:AUTUMN10`); n != 70 {
		t.Fatalf("unrelated keep values rewritten: %d", n)
	}
	// And the raw database no longer contains the value anywhere, indexes
	// included (secure_delete overwrites freed pages).
	var cnt int
	_ = h.db.QueryRow(`SELECT count(*) FROM intake_events WHERE instr(body, 'keep:S1') > 0`).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("%d rows still hold the value", cnt)
	}

	// The bytes of the original values are gone from the database file and
	// from its write-ahead log, not just hidden from queries.
	if rawContains(h, "keep:S1") || rawContains(h, "keep:S5") {
		t.Fatal("quarantined values are still in the database files")
	}

	// Future events are rewritten before they are stored.
	if rej := h.ingest(t, statusEvent(hash, 999)); rej.Reason != ReasonNone {
		t.Fatalf("future event: %s", rej.Reason)
	}
	bodies = h.storedBodies(t)
	if countContaining(bodies, `S999`) != 0 || len(bodies) != 71 {
		t.Fatal("a value arrived after the quarantine and was stored in clear")
	}

	// Closing keeps the rewrite; releasing lifts it.
	if cq, err := h.in.CloseQuarantine(context.Background(), q.ID); err != nil || cq.State != StateClosed {
		t.Fatalf("close: %+v %v", cq, err)
	}
	h.ingest(t, statusEvent(hash, 1000))
	if countContaining(h.storedBodies(t), `S1000`) != 0 {
		t.Fatal("rewrite stopped after the quarantine was closed")
	}
	if _, err := h.in.ReleaseQuarantine(context.Background(), q.ID); err != nil {
		t.Fatal(err)
	}
	if len(h.in.Quarantines(false)) != 0 || len(h.in.Quarantines(true)) != 1 {
		t.Fatal("released quarantine still listed as active")
	}
	if rej := h.ingest(t, statusEvent(hash, 1001)); rej.Reason != ReasonNone {
		t.Fatalf("after release: %s", rej.Reason)
	}
	if countContaining(h.storedBodies(t), `"keep:S1001"`) != 1 {
		t.Fatal("rewrite continued after the release")
	}
	if _, err := h.in.ReleaseQuarantine(context.Background(), q.ID); err == nil {
		t.Fatal("a released quarantine was released twice")
	}
}

func TestNameQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	mk := func(i int) string {
		return strings.Replace(orderPost(hash), `"body":{"email"`, fmt.Sprintf(`"body":{"attrs":{"zz%s":"drop:int"},"email"`, twoLetters(i)), 1)
	}
	for i := 0; i < 80; i++ {
		if rej := h.ingest(t, mk(i)); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	var q Quarantine
	for _, c := range h.in.Quarantines(false) {
		if c.Kind == QuarantineName {
			q = c
		}
	}
	if q.ID == 0 || q.Part != "req.body" || q.Path != "$.attrs" {
		t.Fatalf("quarantines: %+v", h.in.Quarantines(false))
	}
	h.waitRewrite(t, q.ID)
	bodies := h.storedBodies(t)
	if n := countContaining(bodies, `"zz`); n != 0 {
		t.Fatalf("%d stored events still carry quarantined names", n)
	}
	if n := countContaining(bodies, `"attrs":{"{*}":["drop:int"]}`); n != 80 {
		t.Fatalf("%d events rewritten to {*}, want 80", n)
	}
	// The names of the other parents are not affected.
	if countContaining(bodies, `"items":[{"qty"`) != 80 {
		t.Fatal("unrelated names were collapsed")
	}
	// A future event is collapsed at the door.
	h.ingest(t, mk(999))
	if countContaining(h.storedBodies(t), `zz`) != 0 {
		t.Fatal("name stored after quarantine")
	}
}

func TestHeaderNameQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 70; i++ {
		ev := strings.Replace(orderPost(hash), `"headers":{"content-type":["keep:application/json"]}`,
			fmt.Sprintf(`"headers":{"content-type":["keep:application/json"],"x-%s":["drop:str:l8"]}`, twoLetters(i)), 1)
		if rej := h.ingest(t, ev); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	qs := h.in.Quarantines(false)
	if len(qs) != 1 || qs[0].Kind != QuarantineName || qs[0].Part != "req.headers" {
		t.Fatalf("%+v", qs)
	}
	h.waitRewrite(t, qs[0].ID)
	bodies := h.storedBodies(t)
	if countContaining(bodies, `"x-`) != 0 || countContaining(bodies, `"headers":{"{*}":["keep:application/json","drop:str:l8"]}`) != 70 {
		t.Fatal("header names were not collapsed")
	}
	// The kept content-type is a literal name: it is collapsed with the rest,
	// its value stays as the sanitizer made it (keep is governed by its own
	// monitor).
	if countContaining(bodies, `"headers":{"content-type":["keep:application/json"]`) != 0 {
		t.Fatal("literal header names left under a quarantined parent")
	}
}

func TestSegmentQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	mk := func(i int) string {
		w := "w" + twoLetters(i)
		return mutate(t, rawPromo(hash), func(e eventT) {
			e.Op = "GET /promo/" + w
			e.Req.Path = "/promo/" + w
		})
	}
	for i := 0; i < 80; i++ {
		if rej := h.ingest(t, mk(i)); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	var q Quarantine
	for _, c := range h.in.Quarantines(false) {
		if c.Kind == QuarantineSegment {
			q = c
		}
	}
	if q.ID == 0 || q.Service != "shop-api" || q.Method != "GET" || q.Position != 1 {
		t.Fatalf("quarantines: %+v", h.in.Quarantines(false))
	}
	h.waitRewrite(t, q.ID)
	bodies := h.storedBodies(t)
	if countContaining(bodies, `/promo/w`) != 0 {
		t.Fatal("quarantined segments remain in op or path")
	}
	if countContaining(bodies, `"op":"GET /promo/{drop:str:l8}"`) != 80 || countContaining(bodies, `"path":"/promo/{drop:str:l8}"`) != 80 {
		t.Fatal("segments were not rewritten to their drop form")
	}
	// The literal at position 0 stays.
	if countContaining(bodies, `/promo/`) != 80 {
		t.Fatal("position 0 was touched")
	}
	h.ingest(t, mk(500))
	if countContaining(h.storedBodies(t), `/promo/w`) != 0 {
		t.Fatal("segment stored after quarantine")
	}
}

func TestHostQuarantine(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	mk := func(i int) string {
		return mutate(t, rawPromo(hash), func(e eventT) {
			e.Dir = "outbound"
			e.Service = fmt.Sprintf("host:h%s.example", twoLetters(i))
			e.Op = "GET /v1/{drop:str:l8}"
			e.Req.Path = "/v1/{drop:str:l8}"
		})
	}
	for i := 0; i < 80; i++ {
		if rej := h.ingest(t, mk(i)); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	var q Quarantine
	for _, c := range h.in.Quarantines(false) {
		if c.Kind == QuarantineHost {
			q = c
		}
	}
	if q.ID == 0 || q.SourceID != testSource {
		t.Fatalf("quarantines: %+v", h.in.Quarantines(false))
	}
	h.waitRewrite(t, q.ID)
	bodies := h.storedBodies(t)
	if countContaining(bodies, `host:h`) != 0 || countContaining(bodies, `"service":"host:{*}.example"`) != 80 {
		t.Fatal("registrable labels were not rewritten to {*}")
	}
	h.ingest(t, mk(700))
	if countContaining(h.storedBodies(t), `host:h`) != 0 {
		t.Fatal("host stored in clear after quarantine")
	}
}

// Quarantines and sketches survive a restart.
func TestQuarantineAndSketchesPersist(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 30; i++ {
		h.ingest(t, statusEvent(hash, i))
	}
	if err := h.in.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopen := func() *Intake {
		in, err := New(context.Background(), h.cfg, Deps{DB: h.db, Sources: h.sources, Policies: h.policies, Tokens: h.tokens, Alarms: h.alarms, Audit: h.audit,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: h.clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	h.in = reopen()
	// 30 values were seen before the restart, 30 different ones after: the
	// union exceeds 50 only if the sketch was persisted.
	for i := 100; i < 130; i++ {
		h.ingest(t, statusEvent(hash, i))
	}
	qs := h.in.Quarantines(false)
	if len(qs) != 1 {
		t.Fatalf("sketch lost across the restart: %+v", qs)
	}
	h.waitRewrite(t, qs[0].ID)
	if err := h.in.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.in = reopen()
	defer h.in.Close(context.Background())
	if got := h.in.Quarantines(false); len(got) != 1 || got[0].ID != qs[0].ID {
		t.Fatalf("quarantine lost across the restart: %+v", got)
	}
	// Still in force after the restart.
	h.ingest(t, statusEvent(hash, 777))
	if countContaining(h.storedBodies(t), `S777`) != 0 {
		t.Fatal("rewrite not applied after the restart")
	}
}

// Discovery tokens are reduced to cardinality sketches and not stored.
func TestDiscoverySketches(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 40; i++ {
		ev := mutate(t, orderPost(hash), func(e eventT) {
			e.Disc = []discT{
				{Path: "req.body.note", Token: fmt.Sprintf("tkd:%s%s%s", twoLetters(i), "AB", "cd")},
				{Path: "req.query.promo", Token: "tkd:SAMEse"},
			}
		})
		if rej := h.ingest(t, ev); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	fields := h.in.Discovery("p-shop")
	got := map[string]int{}
	for _, f := range fields {
		if f.Service != "shop-api" || f.Op != "POST /orders" {
			t.Fatalf("%+v", f)
		}
		got[f.Path] = f.Distinct
	}
	if n := got["req.body.note"]; n < 38 || n > 41 {
		t.Fatalf("distinct estimate for note: %d (%v)", n, got)
	}
	if got["req.query.promo"] != 1 {
		t.Fatalf("distinct estimate for promo: %d", got["req.query.promo"])
	}
	// No tkd: token and no disc field reach the store.
	for _, b := range h.storedBodies(t) {
		if strings.Contains(b, "tkd:") || strings.Contains(b, `"disc"`) {
			t.Fatal("discovery tokens were stored")
		}
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM intake_events WHERE instr(body, 'tkd:') > 0`).Scan(&n)
	if n != 0 {
		t.Fatal("tkd: found in the database")
	}
	// Persisted and restored.
	if err := h.in.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rows int
	_ = h.db.QueryRow(`SELECT count(*) FROM intake_sketch WHERE kind = ?`, int(obsDisc)).Scan(&rows)
	if rows != 2 {
		t.Fatalf("%d discovery sketches persisted", rows)
	}
}

// Raw routes keep their sketches per op as sent (method and sanitized
// path), so the policy assistant can template operations; the union of the
// ops of one template is an estimate of the union, not a sum.
func TestDiscoverySketchesPerRawOp(t *testing.T) {
	h := newHarness(t)
	hash := h.pol.Hash
	for i := 0; i < 60; i++ {
		shape := "l8"
		if i%2 == 1 {
			shape = "l32"
		}
		ev := mutate(t, rawPromo(hash), func(e eventT) {
			e.Op = "GET /promo/{drop:str:" + shape + "}"
			e.Req.Path = "/promo/{drop:str:" + shape + "}"
			// The same 30 values under both ops.
			e.Disc = []discT{{Path: "req.path.1", Token: fmt.Sprintf("tkd:%sAAzz", twoLetters(i/2))}}
		})
		if rej := h.ingest(t, ev); rej.Reason != ReasonNone {
			t.Fatalf("event %d: %s %s", i, rej.Reason, rej.Detail)
		}
	}
	ops := map[string]int{}
	for _, f := range h.in.Discovery("p-shop") {
		ops[f.Op] = f.Distinct
	}
	if len(ops) != 2 || ops["GET /promo/{drop:str:l8}"] < 28 || ops["GET /promo/{drop:str:l32}"] < 28 {
		t.Fatalf("sketches per raw op: %v", ops)
	}
	u := h.in.DiscoveryUnion("p-shop", func(svc, op string) (string, bool) {
		return "GET /promo/{id}", strings.HasPrefix(op, "GET /promo/")
	})
	if len(u) != 1 || u[0].Op != "GET /promo/{id}" || u[0].Service != "shop-api" || u[0].Distinct < 28 || u[0].Distinct > 32 {
		t.Fatalf("union: %+v", u)
	}
	if u := h.in.DiscoveryUnion("p-shop", func(string, string) (string, bool) { return "", false }); len(u) != 0 {
		t.Fatalf("rejected ops: %+v", u)
	}
}

func TestMonitorOverflowFailsClosed(t *testing.T) {
	h := newHarness(t, withConfig(func(c *Config) { c.MaxMonitors = 3 }))
	hash := h.pol.Hash
	// A single order event needs more than 3 monitors (names, keep fields).
	rej := h.ingest(t, orderPost(hash))
	if rej.Reason != ReasonMonitorOverflow {
		t.Fatalf("got %s", rej.Reason)
	}
}
