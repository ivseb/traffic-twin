package miner

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Batch rules: state changes that no user write precedes, concentrated at
// the same clock hour on many days across many objects, are a scheduled job
// (cron) that moves a fraction of the objects in the old state. Triggered
// changes are spread over the clock because their causes are; a batch is a
// spike that repeats every day at the same hour.

type transition struct {
	obj    int32
	k      int // segment index of the new state
	bucket time.Time
	prev   string
}

// mineBatches finds the batch rules of entity i.
func (m *miner) mineBatches(i int) []*Mined {
	e, lf := m.ents[i], m.lifes[i]
	if lf == nil || e.stateField == "" || e.timeField == "" || !e.literalState() {
		return nil
	}
	var out []*Mined
	for _, b := range lf.states {
		if b == lf.initial {
			continue
		}
		if mm := m.mineBatchInto(i, b); mm != nil {
			out = append(out, mm)
		}
	}
	return out
}

func dayOf(t time.Time) time.Time { return t.Truncate(24 * time.Hour) }

func (m *miner) mineBatchInto(i int, b string) *Mined {
	e, lf, cfg := m.ents[i], m.lifes[i], m.cfg
	var trs []transition
	for _, o := range lf.objs {
		h := m.hist[o]
		if h == nil {
			continue
		}
		for k := 1; k < len(h.segs); k++ {
			s := h.segs[k]
			if s.state != b || s.width != time.Hour || s.bucket.IsZero() {
				continue
			}
			if !h.segs[k-1].last.Before(s.bucket) {
				continue // observed in the old state inside the hour: not at its start
			}
			trs = append(trs, transition{obj: o, k: k, bucket: s.bucket, prev: h.segs[k-1].state})
		}
	}
	perDay := map[time.Time]*[24]int{}
	for _, t := range trs {
		d := dayOf(t.bucket)
		if perDay[d] == nil {
			perDay[d] = &[24]int{}
		}
		perDay[d][t.bucket.Hour()]++
	}
	var days []time.Time
	for d := range perDay {
		days = append(days, d)
	}
	sort.Slice(days, func(a, c int) bool { return days[a].Before(days[c]) })
	active := 0
	spikes := map[int][]time.Time{}
	baseline := map[time.Time]float64{}
	for _, d := range days {
		c := perDay[d]
		total := 0
		for _, n := range c {
			total += n
		}
		if total < cfg.KMin {
			continue
		}
		active++
		for h, n := range c {
			mean := float64(total-n) / 23
			if n >= cfg.KMin && float64(n) >= cfg.BatchSpikeRatio*math.Max(mean, 0.5) {
				spikes[h] = append(spikes[h], d)
				baseline[d.Add(time.Duration(h)*time.Hour)] = mean
			}
		}
	}
	hour, best := -1, 0
	for h := 0; h < 24; h++ {
		if len(spikes[h]) > best {
			hour, best = h, len(spikes[h])
		}
	}
	if hour < 0 || best < 2 || float64(best) < cfg.BatchMinDays*float64(active) {
		return nil
	}
	runs := map[time.Time]bool{}
	for _, d := range spikes[hour] {
		runs[d.Add(time.Duration(hour)*time.Hour)] = true
	}
	// The moved objects: previous state, spontaneity, spread of entries.
	prevN := map[string]int{}
	spont, movedN := 0, 0
	entryHours := map[int]bool{}
	subjects := map[int32]bool{}
	for _, t := range trs {
		if !runs[t.bucket] {
			continue
		}
		movedN++
		prevN[t.prev] = prevN[t.prev] + 1
		h := m.hist[t.obj]
		if !m.writtenBetween(t.obj, h.segs[t.k-1].last, h.segs[t.k].first) {
			spont++
		}
		if lo, hi, ok := h.entry(t.k - 1); ok {
			entryHours[mid(lo, hi).Hour()] = true
		}
		if s := m.owner[t.obj]; s >= 0 {
			subjects[s] = true
		}
	}
	from := ""
	if len(lf.pred[b]) == 1 {
		from = lf.pred[b][0]
	} else {
		from = argmax(prevN)
	}
	if from == "" || float64(spont) < cfg.MinShare*float64(movedN) || len(entryHours) < 6 || len(subjects) < cfg.KMin {
		return nil
	}
	// Fraction: objects moved at each run over objects in the old state then.
	var moved, eligible float64
	runList := make([]time.Time, 0, len(runs))
	for r := range runs {
		runList = append(runList, r)
	}
	sort.Slice(runList, func(a, c int) bool { return runList[a].Before(runList[c]) })
	for _, T := range runList {
		n := 0
		for _, t := range trs {
			if t.bucket.Equal(T) {
				n++
			}
		}
		moved += float64(n) - baseline[T]
		eligible += float64(m.inStateAt(lf, from, b, T))
	}
	if eligible <= 0 || moved <= 0 {
		return nil
	}
	frac := math.Round(moved/eligible*100) / 100
	if frac <= 0 {
		return nil
	}
	if frac > 1 {
		frac = 1
	}
	conf := float64(best) / float64(active)
	level := "low"
	switch {
	case conf >= 0.9:
		level = "high"
	case conf >= 0.6:
		level = "medium"
	}
	sched := fmt.Sprintf("0 %d * * *", hour)
	r := &BatchRule{Kind: KindBatch, Status: StatusDraft, Schedule: sched, Entity: e.def.Name,
		Where: map[string]any{e.stateField: e.literal(from)}, Set: map[string]any{e.stateField: e.literal(b)}, Fraction: frac,
		Evidence: BatchEvidence{Counts: BatchCounts{Runs: len(runs), EntitiesChanged: int(math.Round(moved))},
			Hints: &BatchHints{ScheduleConfidence: level}}}
	r.Title = fmt.Sprintf("Ogni giorno alle %02d:00 UTC una quota di %s passa da %s a %s", hour, e.def.Name, from, b)
	return &Mined{Rule: Rule{Batch: r}, Signature: "batch|" + e.def.Name + "|" + from + "|" + b + "|" + sched,
		Structure: fmt.Sprintf("%s|%s=%s|%s=%s", sched, e.stateField, from, e.stateField, b), Confidence: conf}
}

// writtenBetween reports whether a write exchange cites obj in (lo, hi].
func (m *miner) writtenBetween(obj int32, lo, hi time.Time) bool {
	for _, o := range m.l.occ[obj] {
		ev := &m.l.evs[o.ev]
		if m.l.ops[ev.op].write && ev.ts.After(lo) && !ev.ts.After(hi) {
			return true
		}
	}
	return false
}

// inStateAt counts the objects in state a at instant T (moving to b at T
// included); objects whose state at T cannot be told are left out.
func (m *miner) inStateAt(lf *lifecycle, a, b string, T time.Time) int {
	n := 0
	for _, o := range lf.objs {
		h := m.hist[o]
		if h == nil {
			continue
		}
		for k, s := range h.segs {
			if s.state == b && k > 0 && h.segs[k-1].state != a && s.bucket.Equal(T) && h.segs[k-1].last.Before(T) {
				n++ // a skipped between two observations, moved at T
				break
			}
			if s.state != a {
				continue
			}
			lo, hi, ok := h.entry(k)
			if !ok || !mid(lo, hi).Before(T) {
				break
			}
			if k+1 < len(h.segs) {
				nlo, nhi, _ := h.entry(k + 1)
				if !mid(nlo, nhi).Before(T) {
					n++
				}
			} else if !s.last.Before(T) {
				n++
			}
			break
		}
	}
	return n
}
