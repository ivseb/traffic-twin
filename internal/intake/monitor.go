package intake

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	monitorPrecision = 14 // keep, name, segment, host sketches
	discPrecision    = 12 // discovery sketches (docs/spec/event.md 5.3: >= 12)
	numShards        = 32
	numObsKinds      = int(obsHostLabel) + 1
)

type dayBucket struct {
	day   int64 // days since the Unix epoch (UTC)
	h     *HLL
	dirty bool
}

// monitor watches the cardinality of one element (a keep field, the names
// under a parent, the segments at a position, the hosts of a source) with
// HyperLogLog sketches per day over the retention window.
type monitor struct {
	kind        obsKind
	key         string
	all         *HLL        // union of the buckets
	buckets     []dayBucket // ascending by day; empty for discovery sketches
	quarantined bool
	dirty       bool // all changed (discovery sketches only)
}

type monShard struct {
	mu sync.Mutex
	m  [numObsKinds]map[string]*monitor
}

// monitorSet is the set of all cardinality monitors, sharded by key hash.
type monitorSet struct {
	cfg       *Config
	shards    [numShards]monShard
	count     atomic.Int64 // cardinality monitors (keep, name, segment, host, host label)
	discCount atomic.Int64 // discovery sketches, bounded separately
	retention atomic.Int64 // nanoseconds
}

func newMonitorSet(cfg *Config) *monitorSet {
	ms := &monitorSet{cfg: cfg}
	ms.retention.Store(int64(cfg.Retention))
	for i := range ms.shards {
		for k := range ms.shards[i].m {
			ms.shards[i].m[k] = map[string]*monitor{}
		}
	}
	return ms
}

func (ms *monitorSet) counter(k obsKind) *atomic.Int64 {
	if k == obsDisc {
		return &ms.discCount
	}
	return &ms.count
}

func (ms *monitorSet) threshold(k obsKind) int {
	switch k {
	case obsKeep:
		return ms.cfg.KeepDistinct
	case obsName:
		return ms.cfg.NameDistinct
	case obsSegment:
		return ms.cfg.SegmentDistinct
	case obsHost:
		return ms.cfg.HostDistinct
	case obsHostLabel:
		return ms.cfg.HostLabelDistinct
	}
	return 0
}

func (ms *monitorSet) windowDays() int64 {
	d := ms.retention.Load() / int64(24*time.Hour)
	if d < 1 {
		d = 1
	}
	return d
}

// newQuarantine reports an element whose estimate crossed the threshold.
type newQuarantine struct {
	kind      obsKind
	key       string
	estimate  int
	threshold int
}

// observe adds the observations of an accepted event. It returns the
// elements that just crossed their threshold and whether some monitor could
// not be created (memory bound).
func (ms *monitorSet) observe(b *obsBuf, now time.Time) (raised []newQuarantine, overflow bool) {
	day := now.Unix() / 86400
	for _, it := range b.items {
		key := b.key(it)
		sh := &ms.shards[HashBytes(key)%numShards]
		sh.mu.Lock()
		mm := sh.m[it.kind]
		mon := mm[string(key)]
		if mon == nil {
			if ms.counter(it.kind).Load() >= int64(ms.cfg.MaxMonitors) {
				sh.mu.Unlock()
				if it.kind != obsDisc {
					overflow = true
				}
				continue
			}
			mon = &monitor{kind: it.kind, key: string(key)}
			if it.kind == obsDisc {
				mon.all = NewHLL(discPrecision)
			} else {
				mon.all = NewHLL(monitorPrecision)
			}
			mm[mon.key] = mon
			ms.counter(it.kind).Add(1)
		}
		if mon.quarantined {
			sh.mu.Unlock()
			continue
		}
		var changed bool
		if it.kind == obsDisc {
			changed = mon.all.AddHash(it.val)
			if changed {
				mon.dirty = true
			}
		} else {
			bk := mon.bucketFor(day, ms.windowDays())
			if bk.h.AddHash(it.val) {
				bk.dirty = true
			}
			changed = mon.all.AddHash(it.val)
			if changed {
				if thr := ms.threshold(it.kind); thr > 0 {
					if est := mon.all.Count(); est > thr {
						mon.quarantined = true
						raised = append(raised, newQuarantine{kind: it.kind, key: mon.key, estimate: est, threshold: thr})
					}
				}
			}
		}
		sh.mu.Unlock()
	}
	return raised, overflow
}

// bucketFor returns the bucket of day, creating it and dropping buckets
// older than the window (which requires rebuilding the union).
func (m *monitor) bucketFor(day, window int64) *dayBucket {
	if n := len(m.buckets); n > 0 && m.buckets[n-1].day == day {
		return &m.buckets[n-1]
	}
	cut := 0
	for cut < len(m.buckets) && m.buckets[cut].day <= day-window {
		cut++
	}
	if cut > 0 {
		m.buckets = append(m.buckets[:0], m.buckets[cut:]...)
		m.all = NewHLL(monitorPrecision)
		for i := range m.buckets {
			_ = m.all.Merge(m.buckets[i].h)
		}
	}
	m.buckets = append(m.buckets, dayBucket{day: day, h: NewHLL(monitorPrecision), dirty: true})
	return &m.buckets[len(m.buckets)-1]
}

// mark flags a key as quarantined (creating a stub monitor if none exists)
// so that it is never counted again; used at start-up.
func (ms *monitorSet) mark(kind obsKind, key string) {
	sh := &ms.shards[HashBytes([]byte(key))%numShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	mon := sh.m[kind][key]
	if mon == nil {
		mon = &monitor{kind: kind, key: key, all: NewHLL(monitorPrecision)}
		sh.m[kind][key] = mon
		ms.counter(kind).Add(1)
	}
	mon.quarantined = true
}

// forget removes a monitor (after a quarantine is released).
func (ms *monitorSet) forget(kind obsKind, key string) {
	sh := &ms.shards[HashBytes([]byte(key))%numShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.m[kind][key]; ok {
		delete(sh.m[kind], key)
		ms.counter(kind).Add(-1)
	}
}

// estimate returns the current estimate of a monitor.
func (ms *monitorSet) estimate(kind obsKind, key string) (int, bool) {
	sh := &ms.shards[HashBytes([]byte(key))%numShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	mon := sh.m[kind][key]
	if mon == nil {
		return 0, false
	}
	return mon.all.Count(), true
}

// dirtyRow is a sketch to persist.
type dirtyRow struct {
	kind obsKind
	key  string
	day  int64
	data []byte
}

// takeDirty collects the sketches changed since the last call.
func (ms *monitorSet) takeDirty() []dirtyRow {
	var out []dirtyRow
	for i := range ms.shards {
		sh := &ms.shards[i]
		sh.mu.Lock()
		for k := range sh.m {
			for _, mon := range sh.m[k] {
				if mon.kind == obsDisc {
					if mon.dirty {
						mon.dirty = false
						out = append(out, dirtyRow{mon.kind, mon.key, 0, mon.all.MarshalBinary()})
					}
					continue
				}
				for b := range mon.buckets {
					if mon.buckets[b].dirty {
						mon.buckets[b].dirty = false
						out = append(out, dirtyRow{mon.kind, mon.key, mon.buckets[b].day, mon.buckets[b].h.MarshalBinary()})
					}
				}
			}
		}
		sh.mu.Unlock()
	}
	return out
}

// restore loads a persisted sketch row.
func (ms *monitorSet) restore(kind obsKind, key string, day int64, h *HLL) {
	sh := &ms.shards[HashBytes([]byte(key))%numShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	mon := sh.m[kind][key]
	if mon == nil {
		mon = &monitor{kind: kind, key: key}
		if kind == obsDisc {
			mon.all = NewHLL(discPrecision)
		} else {
			mon.all = NewHLL(monitorPrecision)
		}
		sh.m[kind][key] = mon
		ms.counter(kind).Add(1)
	}
	if kind == obsDisc {
		if mon.all.Precision() == h.Precision() {
			_ = mon.all.Merge(h)
		}
		return
	}
	if h.Precision() != monitorPrecision {
		return
	}
	i := sort.Search(len(mon.buckets), func(i int) bool { return mon.buckets[i].day >= day })
	if i < len(mon.buckets) && mon.buckets[i].day == day {
		_ = mon.buckets[i].h.Merge(h)
	} else {
		mon.buckets = append(mon.buckets, dayBucket{})
		copy(mon.buckets[i+1:], mon.buckets[i:])
		mon.buckets[i] = dayBucket{day: day, h: h}
	}
	_ = mon.all.Merge(h)
}

// DiscField is the estimated cardinality of one field seen in discovery
// mode (docs/spec/event.md 5.3).
type DiscField struct {
	PolicyID string
	// Service is the service of the events, exactly (host:<pattern> too).
	Service string
	// Op is the op of the events: for a raw route the method and the
	// sanitized path (value segments are shapes, e.g. "GET /orders/{drop:str:l32}").
	Op   string
	Path string
	// Distinct is the HyperLogLog estimate of distinct values.
	Distinct int
}

// discFields lists the discovery sketches of a policy id ("" for all).
func (ms *monitorSet) discFields(policyID string) []DiscField {
	var out []DiscField
	for i := range ms.shards {
		sh := &ms.shards[i]
		sh.mu.Lock()
		for key, mon := range sh.m[obsDisc] {
			parts := strings.SplitN(key, "\x1f", 4)
			if len(parts) != 4 || (policyID != "" && parts[0] != policyID) {
				continue
			}
			out = append(out, DiscField{PolicyID: parts[0], Service: parts[1], Op: parts[2], Path: parts[3], Distinct: mon.all.Count()})
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Op != b.Op {
			return a.Op < b.Op
		}
		return a.Path < b.Path
	})
	return out
}

// discUnion merges the discovery sketches of a policy whose operations map
// to the same key (an operation template of the policy assistant): the
// distinct estimate of a field is the one of the union, not a sum. Sketches
// whose operation the function rejects are skipped.
func (ms *monitorSet) discUnion(policyID string, opOf func(service, op string) (string, bool)) []DiscField {
	type k3 struct{ svc, op, path string }
	acc := map[k3]*HLL{}
	for i := range ms.shards {
		sh := &ms.shards[i]
		sh.mu.Lock()
		for key, mon := range sh.m[obsDisc] {
			parts := strings.SplitN(key, "\x1f", 4)
			if len(parts) != 4 || parts[0] != policyID {
				continue
			}
			op, ok := opOf(parts[1], parts[2])
			if !ok {
				continue
			}
			k := k3{parts[1], op, parts[3]}
			h := acc[k]
			if h == nil {
				h = NewHLL(discPrecision)
				acc[k] = h
			}
			_ = h.Merge(mon.all)
		}
		sh.mu.Unlock()
	}
	out := make([]DiscField, 0, len(acc))
	for k, h := range acc {
		out = append(out, DiscField{PolicyID: policyID, Service: k.svc, Op: k.op, Path: k.path, Distinct: h.Count()})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Op != b.Op {
			return a.Op < b.Op
		}
		return a.Path < b.Path
	})
	return out
}

// purgeDays drops buckets older than the window and returns how many
// monitors became empty (and were removed).
func (ms *monitorSet) purgeOld(now time.Time) {
	day := now.Unix() / 86400
	win := ms.windowDays()
	for i := range ms.shards {
		sh := &ms.shards[i]
		sh.mu.Lock()
		for k := range sh.m {
			if obsKind(k) == obsDisc {
				continue
			}
			for key, mon := range sh.m[k] {
				if mon.quarantined {
					continue
				}
				cut := 0
				for cut < len(mon.buckets) && mon.buckets[cut].day <= day-win {
					cut++
				}
				if cut == 0 {
					continue
				}
				mon.buckets = append(mon.buckets[:0], mon.buckets[cut:]...)
				mon.all = NewHLL(monitorPrecision)
				for b := range mon.buckets {
					_ = mon.all.Merge(mon.buckets[b].h)
				}
				if len(mon.buckets) == 0 {
					delete(sh.m[k], key)
					ms.counter(obsKind(k)).Add(-1)
				}
			}
		}
		sh.mu.Unlock()
	}
}
