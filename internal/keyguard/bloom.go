package keyguard

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

// Bloom filters of real tokens (keyguard.md 2). One filter per (epoch, kid);
// a filter is a list of segments of equal capacity, each sized for a false
// positive rate of at most 1e-6 at its capacity. When the newest segment is
// full a new one is added, so the rate stays bounded (at most segments x
// 1e-6) however many tokens arrive. A false positive is a spurious gate
// failure: the safe direction.
//
// The filter does not hold tokens: each token MAC is first reduced to a
// 16-byte digest SHA-256("tt.keyguard.bloom/v1" || 0 || kid || 0 || mac).

// TargetFPR is the false positive rate per segment at capacity.
const TargetFPR = 1e-6

type digest [16]byte

func tokenDigest(kid string, mac [16]byte) digest {
	h := sha256.New()
	h.Write([]byte("tt.keyguard.bloom/v1"))
	h.Write([]byte{0})
	h.Write([]byte(kid))
	h.Write([]byte{0})
	h.Write(mac[:])
	var s [sha256.Size]byte
	var d digest
	copy(d[:], h.Sum(s[:0]))
	return d
}

type bloomSeg struct {
	capacity uint64
	count    uint64 // distinct insertions (a token already present is not added again)
	m        uint64 // bits
	k        uint32 // hash functions
	bits     []uint64
}

// bloomParams returns the bit count and hash count for capacity n at
// TargetFPR: m = ceil(-n ln p / ln2^2), k = round(m/n ln2).
func bloomParams(n uint64) (m uint64, k uint32) {
	if n < 1 {
		n = 1
	}
	mf := math.Ceil(-float64(n) * math.Log(TargetFPR) / (math.Ln2 * math.Ln2))
	m = uint64(mf)
	m = (m + 63) &^ 63
	k = uint32(math.Round(float64(m) / float64(n) * math.Ln2))
	if k < 1 {
		k = 1
	}
	return m, k
}

func newBloomSeg(capacity uint64) *bloomSeg {
	m, k := bloomParams(capacity)
	return &bloomSeg{capacity: capacity, m: m, k: k, bits: make([]uint64, m/64)}
}

// Kirsch-Mitzenmacher double hashing over the two halves of the digest.
func (s *bloomSeg) index(d digest, i uint32) uint64 {
	h1 := binary.LittleEndian.Uint64(d[0:8])
	h2 := binary.LittleEndian.Uint64(d[8:16]) | 1
	return (h1 + uint64(i)*h2) % s.m
}

func (s *bloomSeg) add(d digest) {
	for i := uint32(0); i < s.k; i++ {
		x := s.index(d, i)
		s.bits[x/64] |= 1 << (x % 64)
	}
	s.count++
}

func (s *bloomSeg) has(d digest) bool {
	for i := uint32(0); i < s.k; i++ {
		x := s.index(d, i)
		if s.bits[x/64]&(1<<(x%64)) == 0 {
			return false
		}
	}
	return true
}

func (s *bloomSeg) marshalBits() []byte {
	b := make([]byte, len(s.bits)*8)
	for i, w := range s.bits {
		binary.LittleEndian.PutUint64(b[i*8:], w)
	}
	return b
}

var errBloomCorrupt = errors.New("keyguard: corrupt bloom filter snapshot")

func unmarshalBloomSeg(capacity, count, m uint64, k uint32, bits []byte) (*bloomSeg, error) {
	if m == 0 || m%64 != 0 || uint64(len(bits)) != m/8 || k == 0 || k > 64 {
		return nil, errBloomCorrupt
	}
	s := &bloomSeg{capacity: capacity, count: count, m: m, k: k, bits: make([]uint64, m/64)}
	for i := range s.bits {
		s.bits[i] = binary.LittleEndian.Uint64(bits[i*8:])
	}
	return s, nil
}

// filter is the scalable filter of one (epoch, kid).
type filter struct {
	segs    []*bloomSeg
	dirty   map[int]bool // segments changed since the last snapshot
	updated int64        // unix seconds of the last insertion
}

func (f *filter) add(d digest, capacity uint64, now int64) {
	// The intake sends every token of every batch, so the same identifier
	// arrives again and again: counting repeats would open a new segment
	// (and grow the memory, the snapshots and the false-positive rate) at
	// every capacity insertions instead of every capacity distinct tokens.
	// A token the filter already answers for adds nothing; it only keeps
	// the filter alive (updated is persisted with a dirty segment, at most
	// once an hour for repeats alone).
	if f.has(d) {
		if now > f.updated {
			if now-f.updated >= 3600 && len(f.segs) > 0 {
				f.markDirty(len(f.segs) - 1)
			}
			f.updated = now
		}
		return
	}
	if len(f.segs) == 0 || f.segs[len(f.segs)-1].count >= f.segs[len(f.segs)-1].capacity {
		f.segs = append(f.segs, newBloomSeg(capacity))
	}
	i := len(f.segs) - 1
	f.segs[i].add(d)
	f.markDirty(i)
	if now > f.updated {
		f.updated = now
	}
}

func (f *filter) markDirty(i int) {
	if f.dirty == nil {
		f.dirty = map[int]bool{}
	}
	f.dirty[i] = true
}

func (f *filter) has(d digest) bool {
	for _, s := range f.segs {
		if s.has(d) {
			return true
		}
	}
	return false
}

func (f *filter) count() uint64 {
	var n uint64
	for _, s := range f.segs {
		n += s.count
	}
	return n
}

type filterKey struct{ epoch, kid string }
