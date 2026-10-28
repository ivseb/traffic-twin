package contract

import (
	"sort"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/dateoff"
)

// Relative dates (docs/spec/pack.md 4.4): for a bucket(time) field the
// inference counts, per offset between the field's bucket and the instant
// of the exchange, the events and (up to KMin) the distinct subjects. The
// published range covers the central 90% of the events, its ends each
// backed by at least KMin distinct subjects, rounded outwards: no new value
// leaves the sources, and no end describes fewer than KMin subjects.

// maxOffsetBins bounds the bins of one node (the offsets beyond a year are
// already grouped by week, beyond ten years by month).
const maxOffsetBins = 1024

type offBin struct {
	n    int64
	subj map[uint64]struct{}
}

// offsetAcc accumulates the offsets of a node, in days ("d") or hours
// ("h", for hour buckets).
type offsetAcc struct {
	bins map[string]map[int64]*offBin // unit -> offset -> bin
	over int64
}

// timeTokenStart parses a time token (time:2026, time:2026-10,
// time:2026-10-19, time:2026-10-19T10) into the start of its bucket.
func timeTokenStart(tok string) (time.Time, string, bool) {
	r, ok := strings.CutPrefix(tok, "time:")
	if !ok {
		return time.Time{}, "", false
	}
	layouts := map[int][2]string{4: {"2006", "year"}, 7: {"2006-01", "month"}, 10: {"2006-01-02", "day"}, 13: {"2006-01-02T15", "hour"}}
	l, ok := layouts[len(r)]
	if !ok {
		return time.Time{}, "", false
	}
	t, err := time.Parse(l[0], r)
	if err != nil {
		return time.Time{}, "", false
	}
	return t.UTC(), l[1], true
}

// coarse groups far offsets: by week beyond a year, by 30 days beyond ten
// years (days), by day beyond two days (hours).
func coarse(v int64, unit string) int64 {
	floorTo := func(v, g int64) int64 {
		if v >= 0 {
			return v / g * g
		}
		return -((-v + g - 1) / g * g)
	}
	a := v
	if a < 0 {
		a = -a
	}
	switch {
	case unit == "h" && a > 48:
		return floorTo(v, 24)
	case unit == "d" && a > 3660:
		return floorTo(v, 30)
	case unit == "d" && a > 366:
		return floorTo(v, 7)
	}
	return v
}

func (a *accNode) observeOffset(tok string, c *obsCtx) {
	if c.at.IsZero() {
		return
	}
	start, unit, ok := timeTokenStart(tok)
	if !ok {
		return
	}
	at := c.at.UTC()
	var v int64
	u := "d"
	switch unit {
	case "hour":
		u = "h"
		v = int64(start.Sub(at.Truncate(time.Hour)) / time.Hour)
	case "day":
		d0 := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		v = int64(start.Sub(d0) / (24 * time.Hour))
	case "month":
		v = int64((start.Year()-at.Year())*12+int(start.Month())-int(at.Month())) * 30
	case "year":
		v = int64(start.Year()-at.Year()) * 365
	}
	v = coarse(v, u)
	if a.offs == nil {
		a.offs = &offsetAcc{bins: map[string]map[int64]*offBin{}}
	}
	bins := a.offs.bins[u]
	if bins == nil {
		bins = map[int64]*offBin{}
		a.offs.bins[u] = bins
	}
	b := bins[v]
	if b == nil {
		if len(bins) >= maxOffsetBins {
			a.offs.over++
			return
		}
		b = &offBin{}
		bins[v] = b
	}
	b.n++
	if len(b.subj) < c.cfg.KMin {
		if h, ok := c.subjectHash(); ok {
			if b.subj == nil {
				b.subj = map[uint64]struct{}{}
			}
			b.subj[h] = struct{}{}
		}
	}
}

// dateOffset computes the published range, nil when the evidence is too
// thin (fewer than KMin distinct subjects at an end).
func (o *offsetAcc) dateOffset(kmin int) *dateoff.Range {
	if o == nil {
		return nil
	}
	unit, best := "", int64(-1)
	for u, bins := range o.bins {
		var n int64
		for _, b := range bins {
			n += b.n
		}
		if n > best || (n == best && u < unit) {
			unit, best = u, n
		}
	}
	bins := o.bins[unit]
	keys := make([]int64, 0, len(bins))
	var total int64
	for k, b := range bins {
		keys = append(keys, k)
		total += b.n
	}
	if len(keys) == 0 || total == 0 {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	end := func(order []int64) (int64, bool) {
		var cum int64
		subj := map[uint64]struct{}{}
		for _, k := range order {
			b := bins[k]
			cum += b.n
			for h := range b.subj {
				subj[h] = struct{}{}
			}
			if cum*20 >= total && len(subj) >= kmin {
				return k, true
			}
		}
		return 0, false
	}
	lo, ok1 := end(keys)
	rev := make([]int64, len(keys))
	for i, k := range keys {
		rev[len(keys)-1-i] = k
	}
	hi, ok2 := end(rev)
	if !ok1 || !ok2 || lo > hi {
		return nil
	}
	lo, hi = roundOut(lo, hi, unit)
	d := 24 * time.Hour
	if unit == "h" {
		d = time.Hour
	}
	return &dateoff.Range{Min: dateoff.FormatOffset(time.Duration(lo) * d), Max: dateoff.FormatOffset(time.Duration(hi) * d)}
}

// roundOut widens the ends to a coarse grid (no end at an exact value).
func roundOut(lo, hi int64, unit string) (int64, int64) {
	g := func(v int64) int64 {
		a := v
		if a < 0 {
			a = -a
		}
		switch {
		case unit == "h" && a > 48:
			return 24
		case unit == "h":
			return 1
		case a > 366:
			return 30
		case a > 31:
			return 7
		}
		return 1
	}
	down := func(v, s int64) int64 {
		if v >= 0 {
			return v / s * s
		}
		return -((-v + s - 1) / s * s)
	}
	up := func(v, s int64) int64 { return -down(-v, s) }
	return down(lo, g(lo)), up(hi, g(hi))
}
