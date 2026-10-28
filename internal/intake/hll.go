package intake

import (
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"sort"
)

// HLL is a HyperLogLog cardinality sketch (Flajolet et al., with the usual
// small-range linear-counting correction). It stores only 64-bit hashes of
// the values, never the values themselves, which is what lets the intake
// count distinct values of a field without keeping them.
//
// Small sketches use a sparse representation (a sorted list of
// register/rank pairs) and switch to the dense register array when the
// sparse list would take more memory. The estimate is identical in both
// modes. An HLL is not safe for concurrent use.
type HLL struct {
	p      uint8
	sparse []uint32 // sorted; (index << 6) | rank, one entry per non-zero register
	dense  []uint8  // 1<<p registers, nil while sparse
}

// NewHLL returns an empty sketch with 2^p registers; p is clamped to 4..18.
func NewHLL(p uint8) *HLL {
	if p < 4 {
		p = 4
	}
	if p > 18 {
		p = 18
	}
	return &HLL{p: p}
}

// Precision returns p.
func (h *HLL) Precision() uint8 { return h.p }

// HashString hashes a string for [HLL.AddHash]: FNV-1a followed by the
// murmur3 64-bit finalizer, so that every output bit is well mixed.
func HashString(s string) uint64 {
	x := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		x ^= uint64(s[i])
		x *= 1099511628211
	}
	return mix64(x)
}

// HashBytes is [HashString] for a byte slice.
func HashBytes(b []byte) uint64 {
	x := uint64(14695981039346656037)
	for _, c := range b {
		x ^= uint64(c)
		x *= 1099511628211
	}
	return mix64(x)
}

func mix64(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

// AddString adds a value.
func (h *HLL) AddString(s string) bool { return h.AddHash(HashString(s)) }

// AddHash adds a value already hashed with [HashString]. It reports whether
// the sketch changed (a register increased), which is the only case in which
// the estimate can have moved.
func (h *HLL) AddHash(x uint64) bool {
	idx := uint32(x >> (64 - h.p))
	w := x<<h.p | 1<<(h.p-1) // guard bit bounds the rank
	rank := uint8(bits.LeadingZeros64(w)) + 1
	return h.setMax(idx, rank)
}

func (h *HLL) setMax(idx uint32, rank uint8) bool {
	if h.dense != nil {
		if h.dense[idx] < rank {
			h.dense[idx] = rank
			return true
		}
		return false
	}
	key := idx << 6
	i := sort.Search(len(h.sparse), func(i int) bool { return h.sparse[i] >= key })
	if i < len(h.sparse) && h.sparse[i]>>6 == idx {
		if uint8(h.sparse[i]&63) < rank {
			h.sparse[i] = key | uint32(rank)
			return true
		}
		return false
	}
	h.sparse = append(h.sparse, 0)
	copy(h.sparse[i+1:], h.sparse[i:])
	h.sparse[i] = key | uint32(rank)
	// 4 bytes per sparse entry versus 1 byte per dense register.
	if len(h.sparse)*4 > 1<<h.p {
		h.toDense()
	}
	return true
}

func (h *HLL) toDense() {
	d := make([]uint8, 1<<h.p)
	for _, e := range h.sparse {
		d[e>>6] = uint8(e & 63)
	}
	h.dense = d
	h.sparse = nil
}

// Merge adds the contents of o (same precision) to h.
func (h *HLL) Merge(o *HLL) error {
	if o.p != h.p {
		return errors.New("intake: HLL precision mismatch")
	}
	if o.dense != nil {
		for i, r := range o.dense {
			if r != 0 {
				h.setMax(uint32(i), r)
			}
		}
		return nil
	}
	for _, e := range o.sparse {
		h.setMax(e>>6, uint8(e&63))
	}
	return nil
}

// Estimate returns the estimated number of distinct values added.
func (h *HLL) Estimate() float64 {
	m := float64(uint64(1) << h.p)
	var sum float64
	var zeros float64
	if h.dense != nil {
		for _, r := range h.dense {
			sum += math.Ldexp(1, -int(r))
			if r == 0 {
				zeros++
			}
		}
	} else {
		zeros = m - float64(len(h.sparse))
		sum = zeros
		for _, e := range h.sparse {
			sum += math.Ldexp(1, -int(e&63))
		}
	}
	var alpha float64
	switch {
	case h.p == 4:
		alpha = 0.673
	case h.p == 5:
		alpha = 0.697
	case h.p == 6:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1 + 1.079/m)
	}
	est := alpha * m * m / sum
	if est <= 2.5*m && zeros > 0 {
		return m * math.Log(m/zeros) // linear counting
	}
	return est
}

// Count returns the estimate rounded to the nearest integer.
func (h *HLL) Count() int { return int(h.Estimate() + 0.5) }

// Empty reports whether nothing was added.
func (h *HLL) Empty() bool { return h.dense == nil && len(h.sparse) == 0 }

// MarshalBinary encodes the sketch: precision byte, mode byte (0 sparse,
// 1 dense) and the body.
func (h *HLL) MarshalBinary() []byte {
	if h.dense != nil {
		out := make([]byte, 2+len(h.dense))
		out[0], out[1] = h.p, 1
		copy(out[2:], h.dense)
		return out
	}
	out := make([]byte, 2+4*len(h.sparse))
	out[0], out[1] = h.p, 0
	for i, e := range h.sparse {
		binary.LittleEndian.PutUint32(out[2+4*i:], e)
	}
	return out
}

// UnmarshalHLL decodes a sketch written by MarshalBinary.
func UnmarshalHLL(b []byte) (*HLL, error) {
	if len(b) < 2 || b[0] < 4 || b[0] > 18 {
		return nil, errors.New("intake: bad HLL encoding")
	}
	h := &HLL{p: b[0]}
	body := b[2:]
	switch b[1] {
	case 1:
		if len(body) != 1<<h.p {
			return nil, errors.New("intake: bad HLL encoding")
		}
		h.dense = append([]uint8(nil), body...)
	case 0:
		if len(body)%4 != 0 {
			return nil, errors.New("intake: bad HLL encoding")
		}
		h.sparse = make([]uint32, len(body)/4)
		prev := int64(-1)
		for i := range h.sparse {
			e := binary.LittleEndian.Uint32(body[4*i:])
			if int64(e>>6) <= prev || e>>6 >= 1<<h.p || e&63 == 0 || e&63 > 64-uint32(h.p)+1 {
				return nil, errors.New("intake: bad HLL encoding")
			}
			prev = int64(e >> 6)
			h.sparse[i] = e
		}
	default:
		return nil, errors.New("intake: bad HLL encoding")
	}
	return h, nil
}
