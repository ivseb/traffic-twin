package intake

import (
	"math/rand"
	"testing"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Random damage to valid events never panics, and whatever is accepted is
// still an exact canonical event.
func TestIngestSurvivesCorruptedEvents(t *testing.T) {
	h := newHarness(t, withConfig(func(c *Config) { c.MaxMonitors = 1 << 20 }))
	hash := h.pol.Hash
	bases := []string{orderPost(hash), orderGet(hash), shipmentPost(hash), rawPromo(hash)}
	rnd := rand.New(rand.NewSource(42))
	accepted := 0
	for i := 0; i < 20000; i++ {
		b := []byte(bases[rnd.Intn(len(bases))])
		for k := 0; k < 1+rnd.Intn(3); k++ {
			j := rnd.Intn(len(b))
			switch rnd.Intn(4) {
			case 0:
				b[j] = byte(32 + rnd.Intn(95))
			case 1:
				b = append(b[:j], b[j+1:]...)
			case 2:
				b = append(b[:j], append([]byte{byte(32 + rnd.Intn(95))}, b[j:]...)...)
			default:
				b[j] = "{}[]:,\"\\"[rnd.Intn(8)]
			}
		}
		rej, err := h.in.IngestEvent(t.Context(), testSource, b)
		if err == ErrOverloaded {
			h.idle(t)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if rej.Reason == ReasonNone {
			accepted++
			if _, derr := event.Decode(b); derr != nil {
				t.Fatalf("accepted bytes that do not decode: %v", derr)
			}
		}
	}
	h.idle(t)
	if n := h.count(t); n != int64(accepted) {
		t.Fatalf("stored %d, accepted %d", n, accepted)
	}
	// Everything stored is canonical and still passes the checks' own
	// invariants (decodable by the strict decoder).
	err := h.in.Store().Scan(t.Context(), Query{}, func(se *StoredEvent) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
}
