package keyguard

import (
	"context"
	"database/sql"
	"sort"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/store"
)

// filterSet holds every real-token filter. Insertions are durable: each
// batch is written to a journal (digests only) before it is applied, and the
// journal is folded into per-segment snapshots periodically and at close.
type filterSet struct {
	db       *store.DB
	capacity uint64

	mu      sync.RWMutex
	filters map[filterKey]*filter
}

func newFilterSet(db *store.DB, capacity uint64) *filterSet {
	return &filterSet{db: db, capacity: capacity, filters: map[filterKey]*filter{}}
}

// load reads the snapshots and replays the journal.
func (fs *filterSet) load(ctx context.Context) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rows, err := fs.db.QueryContext(ctx, `SELECT epoch, kid, seg, capacity, count, m, k, bits, updated_at FROM kg_bloom ORDER BY epoch, kid, seg`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key filterKey
		var seg int
		var capacity, count, m int64
		var k int64
		var bits []byte
		var updated int64
		if err := rows.Scan(&key.epoch, &key.kid, &seg, &capacity, &count, &m, &k, &bits, &updated); err != nil {
			rows.Close()
			return err
		}
		s, err := unmarshalBloomSeg(uint64(capacity), uint64(count), uint64(m), uint32(k), bits)
		if err != nil {
			rows.Close()
			return err
		}
		f := fs.filters[key]
		if f == nil {
			f = &filter{}
			fs.filters[key] = f
		}
		if seg != len(f.segs) {
			rows.Close()
			return errBloomCorrupt
		}
		f.segs = append(f.segs, s)
		if updated > f.updated {
			f.updated = updated
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	jr, err := fs.db.QueryContext(ctx, `SELECT epoch, kid, digests, at FROM kg_bloom_journal ORDER BY id`)
	if err != nil {
		return err
	}
	defer jr.Close()
	for jr.Next() {
		var key filterKey
		var ds []byte
		var at int64
		if err := jr.Scan(&key.epoch, &key.kid, &ds, &at); err != nil {
			return err
		}
		if len(ds)%16 != 0 {
			return errBloomCorrupt
		}
		fs.applyLocked(key, ds, at)
	}
	return jr.Err()
}

func (fs *filterSet) applyLocked(key filterKey, ds []byte, at int64) {
	f := fs.filters[key]
	if f == nil {
		f = &filter{}
		fs.filters[key] = f
	}
	for i := 0; i+16 <= len(ds); i += 16 {
		var d digest
		copy(d[:], ds[i:i+16])
		f.add(d, fs.capacity, at)
	}
}

// add journals then applies a batch of digests for one filter.
func (fs *filterSet) add(ctx context.Context, key filterKey, ds []digest, now time.Time) error {
	if len(ds) == 0 {
		return nil
	}
	buf := make([]byte, 0, 16*len(ds))
	for _, d := range ds {
		buf = append(buf, d[:]...)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, err := fs.db.ExecContext(ctx, `INSERT INTO kg_bloom_journal (epoch, kid, digests, at) VALUES (?, ?, ?, ?)`,
		key.epoch, key.kid, buf, now.Unix()); err != nil {
		return err
	}
	fs.applyLocked(key, buf, now.Unix())
	return nil
}

// view runs fn with a read lock on the filters.
func (fs *filterSet) view(fn func(map[filterKey]*filter)) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	fn(fs.filters)
}

type segSnap struct {
	key                     filterKey
	seg                     int
	capacity, count, m, upd int64
	k                       int64
	bits                    []byte
}

// snapshot writes the dirty segments, drops the folded journal rows and
// deletes filters not updated since before retentionCutoff (zero: keep).
func (fs *filterSet) snapshot(ctx context.Context, retentionCutoff time.Time) error {
	fs.mu.Lock()
	var maxJournal sql.NullInt64
	if err := fs.db.QueryRowContext(ctx, `SELECT max(id) FROM kg_bloom_journal`).Scan(&maxJournal); err != nil {
		fs.mu.Unlock()
		return err
	}
	var snaps []segSnap
	var expired []filterKey
	for key, f := range fs.filters {
		if !retentionCutoff.IsZero() && f.updated < retentionCutoff.Unix() {
			expired = append(expired, key)
			delete(fs.filters, key)
			continue
		}
		for i := range f.dirty {
			s := f.segs[i]
			snaps = append(snaps, segSnap{key: key, seg: i, capacity: int64(s.capacity), count: int64(s.count), m: int64(s.m), k: int64(s.k), bits: s.marshalBits(), upd: f.updated})
		}
		f.dirty = nil
	}
	fs.mu.Unlock()
	if len(snaps) == 0 && len(expired) == 0 && !maxJournal.Valid {
		return nil
	}
	err := fs.db.InTx(ctx, func(tx *sql.Tx) error {
		for _, s := range snaps {
			if _, err := tx.ExecContext(ctx, `INSERT INTO kg_bloom (epoch, kid, seg, capacity, count, m, k, bits, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(epoch, kid, seg) DO UPDATE SET capacity = excluded.capacity, count = excluded.count, m = excluded.m, k = excluded.k, bits = excluded.bits, updated_at = excluded.updated_at`,
				s.key.epoch, s.key.kid, s.seg, s.capacity, s.count, s.m, s.k, s.bits, s.upd); err != nil {
				return err
			}
		}
		for _, key := range expired {
			if _, err := tx.ExecContext(ctx, `DELETE FROM kg_bloom WHERE epoch = ? AND kid = ?`, key.epoch, key.kid); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM kg_bloom_journal WHERE epoch = ? AND kid = ?`, key.epoch, key.kid); err != nil {
				return err
			}
		}
		if maxJournal.Valid {
			if _, err := tx.ExecContext(ctx, `DELETE FROM kg_bloom_journal WHERE id <= ?`, maxJournal.Int64); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// The journal is still there: mark everything dirty again so the
		// next snapshot rewrites it.
		fs.mu.Lock()
		for _, s := range snaps {
			if f := fs.filters[s.key]; f != nil {
				if f.dirty == nil {
					f.dirty = map[int]bool{}
				}
				f.dirty[s.seg] = true
			}
		}
		fs.mu.Unlock()
	}
	return err
}

// FilterInfo describes one filter (status endpoint): counts only.
type FilterInfo struct {
	Epoch    string `json:"epoch"`
	Kid      string `json:"kid"`
	Tokens   uint64 `json:"tokens"`
	Segments int    `json:"segments"`
}

func (fs *filterSet) info() []FilterInfo {
	var out []FilterInfo
	fs.view(func(m map[filterKey]*filter) {
		for k, f := range m {
			out = append(out, FilterInfo{Epoch: k.epoch, Kid: k.kid, Tokens: f.count(), Segments: len(f.segs)})
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Epoch != out[j].Epoch {
			return out[i].Epoch < out[j].Epoch
		}
		return out[i].Kid < out[j].Kid
	})
	return out
}
