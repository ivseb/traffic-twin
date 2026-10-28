package world

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/intake"
)

func TestGenerateDeterministic(t *testing.T) {
	a, err := Generate(demoInput(t, 42, 50))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(demoInput(t, 42, 50))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.World, b.World) {
		t.Fatal("same seed, different world bytes")
	}
	if strings.Join(a.Synthetic, "\n") != strings.Join(b.Synthetic, "\n") {
		t.Fatal("same seed, different provenance tags")
	}
	c, err := Generate(demoInput(t, 43, 50))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.World, c.World) {
		t.Fatal("different seeds, same world")
	}
	if !bytes.HasSuffix(a.World, []byte("\n")) || bytes.Contains(a.World, []byte("\n\n")) {
		t.Fatal("world.jsonl must end with one newline and have no empty line")
	}
}

func TestGenerateIntegrityAndPending(t *testing.T) {
	in := demoInput(t, 7, 300)
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if probs := Verify(out.World, in.Rules); len(probs) > 0 {
		t.Fatalf("integrity: %v", probs)
	}
	if out.Pending == 0 || out.History == 0 || out.Entities == 0 {
		t.Fatalf("expected entities, history and pending rows: %+v", out)
	}
	w := string(out.World)
	for _, want := range []string{`"type":"pending"`, `"outcome":"happy"`, `"rule_id":"r-0012"`, `"effect_id":"order-linked"`} {
		if !strings.Contains(w, want) {
			t.Errorf("world lacks %s", want)
		}
	}
	// No real-looking contact: only reserved domains.
	for _, l := range strings.Split(w, "\n") {
		if i := strings.Index(l, "@"); i >= 0 && !strings.Contains(l[i:], "@example.") {
			t.Fatalf("non reserved e-mail domain in %q", l)
		}
	}
	// Breaking a relation is detected.
	broken := strings.Replace(w, `"shipmentId":"SHP-SYN-0001","sku"`, `"shipmentId":"SHP-SYN-9999","sku"`, 1)
	if broken == w {
		broken = strings.Replace(w, `"shipmentId":"SHP-SYN-0001"`, `"shipmentId":"SHP-SYN-9999"`, 1)
	}
	if probs := Verify([]byte(broken), in.Rules); len(probs) == 0 {
		t.Fatal("broken relation not detected")
	}
}

func TestGenerateWithoutArchetypes(t *testing.T) {
	in := demoInput(t, 1, 10)
	in.Archetypes = nil
	out, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.World), `"archetype":null`) {
		t.Fatal("customers without profiles must have archetype null")
	}
	if probs := Verify(out.World, in.Rules); len(probs) > 0 {
		t.Fatal(probs)
	}
}

// fakeEvents is an in-memory EventSource.
type fakeEvents []*intake.StoredEvent

func (f fakeEvents) Scan(_ context.Context, q intake.Query, fn func(*intake.StoredEvent) error) error {
	for _, e := range f {
		if q.Dir != "" && e.Event.Dir != q.Dir {
			continue
		}
		if err := fn(e); err != nil {
			if err == intake.ErrStop {
				return nil
			}
			return err
		}
	}
	return nil
}

// subjects adds n invented subjects calling op `calls` times at hour h.
func subjects(evs *fakeEvents, prefix string, n, creates, h int, errs bool, readOp ...string) {
	read := "GET /orders/{id}"
	if len(readOp) > 0 {
		read = readOp[0]
	}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		subj := fmt.Sprintf("tk1:k1:%s%021d", prefix, i)
		for c := 0; c < creates; c++ {
			st := 201
			if errs && c%2 == 0 {
				st = 503
			}
			*evs = append(*evs, &intake.StoredEvent{Event: &event.Event{Dir: event.Inbound, Service: "shop-api", Op: "POST /orders",
				Status: st, Subject: subj, Time: base.Add(time.Duration(c*24+h) * time.Hour)}})
			*evs = append(*evs, &intake.StoredEvent{Event: &event.Event{Dir: event.Inbound, Service: "shop-api", Op: read,
				Status: 200, Subject: subj, Time: base.Add(time.Duration(c*24+h)*time.Hour + time.Minute)}})
		}
	}
}

func TestArchetypesKAnonymity(t *testing.T) {
	var evs fakeEvents
	subjects(&evs, "A", 30, 4, 19, false)               // 3-5/month, evening
	subjects(&evs, "B", 25, 1, 8, false)                // 1-2/month, morning
	subjects(&evs, "C", 5, 4, 20, true)                 // like A but errors: merged into A
	subjects(&evs, "D", 3, 12, 2, true, "GET /returns") // far from everyone: dropped
	b, err := BuildArchetypes(context.Background(), evs, ProfileOptions{KMin: 20, From: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
		To: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC), CreateOps: []string{"shop-api POST /orders"}})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, a := range b.Archetypes {
		if a.Size < 20 {
			t.Fatalf("archetype %s below k: %d", a.ID, a.Size)
		}
		total += a.Size
		for op := range a.Features.EndpointMix {
			if !strings.HasPrefix(op, "shop-api ") {
				t.Fatalf("unexpected op %q", op)
			}
		}
	}
	if b.Profiles != 63 || b.Dropped != 3 || total != 60 || len(b.Archetypes) != 2 {
		t.Fatalf("profiles %d dropped %d total %d archetypes %d", b.Profiles, b.Dropped, total, len(b.Archetypes))
	}
	if b.Archetypes[0].Size != 35 || b.Archetypes[0].Features.ErrorRate != "0" {
		t.Fatalf("merged archetype: %+v", b.Archetypes[0])
	}
	// k above the population: everything is suppressed.
	b2, err := BuildArchetypes(context.Background(), evs, ProfileOptions{KMin: 100, From: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
		To: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(b2.Archetypes) != 0 {
		t.Fatalf("archetypes below k published: %+v", b2.Archetypes)
	}
}

func TestCron(t *testing.T) {
	c, err := parseCron("0 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	ticks := c.ticks(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC))
	if len(ticks) != 3 || ticks[0].Hour() != 2 {
		t.Fatalf("ticks %v", ticks)
	}
	if _, err := parseCron("61 * * * *"); err == nil {
		t.Fatal("bad minute accepted")
	}
}
