package world

import "math"

// rng is the generator's own pseudo-random source (SplitMix64). It is
// written here, not taken from math/rand, so that the same seed produces the
// same bytes with every Go release.
type rng struct{ s uint64 }

func newRNG(seed uint64, stream uint64) *rng {
	r := &rng{s: seed ^ (stream * 0x9e3779b97f4a7c15)}
	r.next()
	return r
}

func (r *rng) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// intn returns a uniform integer in [0, n). n must be > 0.
func (r *rng) intn(n int64) int64 {
	if n <= 1 {
		return 0
	}
	un := uint64(n)
	limit := math.MaxUint64 - math.MaxUint64%un
	for {
		v := r.next()
		if v < limit {
			return int64(v % un)
		}
	}
}

// between returns a uniform integer in [lo, hi].
func (r *rng) between(lo, hi int64) int64 {
	if hi <= lo {
		return lo
	}
	return lo + r.intn(hi-lo+1)
}

// float returns a uniform float64 in [0, 1).
func (r *rng) float() float64 { return float64(r.next()>>11) / (1 << 53) }

// weighted picks an index with probability proportional to w. Weights that
// are not positive are never picked unless all are; then index 0.
func (r *rng) weighted(w []float64) int {
	var sum float64
	for _, x := range w {
		if x > 0 {
			sum += x
		}
	}
	if sum <= 0 {
		return 0
	}
	u := r.float() * sum
	last := 0
	for i, x := range w {
		if x <= 0 {
			continue
		}
		last = i
		if u < x {
			return i
		}
		u -= x
	}
	return last
}
