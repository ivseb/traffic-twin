package keyguard

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func testDigest(i int) digest {
	var mac [16]byte
	s := sha256.Sum256([]byte(fmt.Sprint("tok-", i)))
	copy(mac[:], s[:16])
	return tokenDigest("k1", mac)
}

// Repeated tokens (the intake re-sends the identifiers of every batch) must
// not open new segments: the filter grows with distinct tokens only.
func TestFilterRepeatsDoNotGrow(t *testing.T) {
	const capacity = 1000
	var f filter
	for round := 0; round < 20; round++ {
		for i := 0; i < capacity; i++ {
			f.add(testDigest(i), capacity, int64(round))
		}
	}
	if len(f.segs) != 1 {
		t.Fatalf("20 rounds of the same %d tokens: %d segments, want 1", capacity, len(f.segs))
	}
	for i := 0; i < capacity; i++ {
		if !f.has(testDigest(i)) {
			t.Fatalf("token %d lost", i)
		}
	}
	// New distinct tokens still open a segment when the first is full.
	for i := capacity; i < 2*capacity; i++ {
		f.add(testDigest(i), capacity, 30)
	}
	if len(f.segs) != 2 {
		t.Fatalf("2x capacity distinct tokens: %d segments, want 2", len(f.segs))
	}
	if f.updated != 30 {
		t.Fatalf("updated = %d", f.updated)
	}
}

// A repeat keeps the filter alive: updated moves, and after an hour the
// last segment is marked dirty so that the snapshot persists it.
func TestFilterRepeatRefreshesUpdated(t *testing.T) {
	var f filter
	f.add(testDigest(1), 100, 1000)
	f.dirty = nil
	f.add(testDigest(1), 100, 1500)
	if f.updated != 1500 || len(f.dirty) != 0 {
		t.Fatalf("within the hour: updated %d dirty %v", f.updated, f.dirty)
	}
	f.add(testDigest(1), 100, 1500+3600)
	if f.updated != 5100 || !f.dirty[0] {
		t.Fatalf("after an hour: updated %d dirty %v", f.updated, f.dirty)
	}
}

// BenchmarkFilterAddRepeats measures the add path of a filter fed with
// repeats (5 copies of each token), the steady state of the intake outbox.
func BenchmarkFilterAddRepeats(b *testing.B) {
	ds := make([]digest, 10000)
	for i := range ds {
		ds[i] = testDigest(i)
	}
	var f filter
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.add(ds[(i/5)%len(ds)], 1_000_000, int64(i))
	}
	b.ReportMetric(float64(len(f.segs)), "segments")
}
