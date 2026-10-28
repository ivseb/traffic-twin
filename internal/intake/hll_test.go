package intake

import (
	"fmt"
	"math"
	"testing"
)

func TestHLLAccuracy(t *testing.T) {
	for _, p := range []uint8{12, 14} {
		for _, n := range []int{0, 1, 10, 50, 51, 500, 5_000, 100_000} {
			h := NewHLL(p)
			for i := 0; i < n; i++ {
				h.AddString(fmt.Sprintf("value-%d", i))
			}
			est := h.Estimate()
			tol := 3 * 1.04 / math.Sqrt(float64(uint64(1)<<p)) // three standard errors
			if n <= 100 {
				tol = 0.05 // small ranges use linear counting: nearly exact
			}
			if n == 0 {
				if est != 0 {
					t.Fatalf("p=%d empty estimate %f", p, est)
				}
				continue
			}
			if rel := math.Abs(est-float64(n)) / float64(n); rel > tol {
				t.Errorf("p=%d n=%d estimate %.1f (relative error %.4f > %.4f)", p, n, est, rel, tol)
			}
		}
	}
}

func TestHLLDuplicatesDoNotCount(t *testing.T) {
	h := NewHLL(14)
	for r := 0; r < 20; r++ {
		for i := 0; i < 30; i++ {
			h.AddString(fmt.Sprintf("v%d", i))
		}
	}
	// A sketch can merge two values that land on the same register: the
	// count is exact up to that, and never above the true number.
	if c := h.Count(); c < 29 || c > 30 {
		t.Fatalf("count %d, want 30 (or 29 after a register collision)", c)
	}
	if h.AddString("v1") {
		t.Fatal("re-adding a value reported a change")
	}
}

func TestHLLSparseDenseAndMerge(t *testing.T) {
	a, b := NewHLL(12), NewHLL(12)
	for i := 0; i < 3000; i++ { // beyond the sparse limit of p=12 (1024 entries)
		a.AddString(fmt.Sprintf("a%d", i))
	}
	if a.dense == nil {
		t.Fatal("expected the dense representation")
	}
	for i := 0; i < 20; i++ {
		b.AddString(fmt.Sprintf("b%d", i))
	}
	if b.dense != nil {
		t.Fatal("expected the sparse representation")
	}
	u := NewHLL(12)
	if err := u.Merge(a); err != nil {
		t.Fatal(err)
	}
	if err := u.Merge(b); err != nil {
		t.Fatal(err)
	}
	if est := u.Estimate(); math.Abs(est-3020)/3020 > 0.06 {
		t.Fatalf("union estimate %.0f", est)
	}
	if err := u.Merge(NewHLL(14)); err == nil {
		t.Fatal("merge of different precisions accepted")
	}
}

func TestHLLMarshalRoundTrip(t *testing.T) {
	for _, n := range []int{0, 7, 400, 5000} {
		h := NewHLL(12)
		for i := 0; i < n; i++ {
			h.AddString(fmt.Sprint("x", i))
		}
		g, err := UnmarshalHLL(h.MarshalBinary())
		if err != nil {
			t.Fatal(err)
		}
		if g.Estimate() != h.Estimate() {
			t.Fatalf("n=%d: estimate changed after a round trip: %f vs %f", n, g.Estimate(), h.Estimate())
		}
	}
	for _, bad := range [][]byte{nil, {12}, {3, 0}, {12, 2}, {12, 1, 1, 2}, {12, 0, 1, 2, 3}} {
		if _, err := UnmarshalHLL(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestHLLDoesNotStoreValues(t *testing.T) {
	h := NewHLL(14)
	h.AddString("giulia.neri@example.com")
	if b := h.MarshalBinary(); len(b) > 16 {
		t.Fatalf("a single value took %d bytes", len(b))
	}
}
