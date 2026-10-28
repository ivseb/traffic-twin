package contract

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Snapshot compaction ("sintesi" of the contract history).
//
// One snapshot per service per window (a day by default) is 365 snapshots a
// year per service, each a gzip'd model. History older than a month is read
// at a coarser grain, so compaction keeps, per service:
//
//   - every snapshot whose window ended in the last KeepAll (30 days);
//   - then, until Weekly (180 days), the newest snapshot of each ISO week;
//   - then the newest snapshot of each calendar month, forever;
//   - always the newest snapshot of the service;
//   - always the protected snapshots: those referenced by drift alerts and
//     the contract baseline of published packs (core supplies the set).
//
// contract.keep_snapshots stays a hard cap on the count per service, and
// it too skips the protected snapshots. Deletions run in small transactions.
// The change counts (breaking, non_breaking) stored with a kept snapshot
// keep describing the change against the snapshot that preceded it when it
// was taken; a diff between any two kept snapshots is computed on demand.

// SnapshotPolicy configures the compaction.
type SnapshotPolicy struct {
	// KeepAll keeps every snapshot whose window ended this recently.
	KeepAll time.Duration
	// Weekly keeps one snapshot per ISO week up to this age (>= KeepAll);
	// older snapshots are kept one per calendar month.
	Weekly time.Duration
}

// DefaultSnapshotPolicy is 30 days of everything, one per week up to 180
// days, then one per month.
func DefaultSnapshotPolicy() SnapshotPolicy {
	return SnapshotPolicy{KeepAll: 30 * 24 * time.Hour, Weekly: 180 * 24 * time.Hour}
}

// Protector returns the snapshot sequence numbers that must never be
// deleted.
type Protector func(ctx context.Context) (map[int64]bool, error)

// ParseSnapshotID returns the sequence number of a snapshot id ("sn-...").
func ParseSnapshotID(id string) (int64, bool) { return parseSnapshotID(id) }

var protectorMu sync.RWMutex

// SetProtector installs the source of protected snapshots used by Prune and
// Compact.
func (s *SnapshotStore) SetProtector(p Protector) {
	protectorMu.Lock()
	s.protect = p
	protectorMu.Unlock()
}

func (s *SnapshotStore) protected(ctx context.Context) (map[int64]bool, error) {
	protectorMu.RLock()
	p := s.protect
	protectorMu.RUnlock()
	if p == nil {
		return map[int64]bool{}, nil
	}
	m, err := p(ctx)
	if err != nil {
		return nil, fmt.Errorf("contract: protected snapshots: %w", err)
	}
	if m == nil {
		m = map[int64]bool{}
	}
	return m, nil
}

type snapRef struct {
	id int64
	to time.Time
}

// keepSet decides which snapshots of one service survive (refs sorted by id
// ascending; window ends never decrease with the id in practice, but the
// decision only uses the window end).
func keepSet(refs []snapRef, now time.Time, p SnapshotPolicy, protected map[int64]bool) map[int64]bool {
	keep := map[int64]bool{}
	if len(refs) == 0 {
		return keep
	}
	keep[refs[len(refs)-1].id] = true
	weekly := map[string]int64{}
	monthly := map[string]int64{}
	for _, r := range refs {
		age := now.Sub(r.to)
		switch {
		case protected[r.id] || age <= p.KeepAll:
			keep[r.id] = true
		case age <= p.Weekly:
			y, w := r.to.ISOWeek()
			k := fmt.Sprintf("%d-%02d", y, w)
			if prev, ok := weekly[k]; !ok || r.id > prev {
				weekly[k] = r.id
			}
		default:
			k := r.to.Format("2006-01")
			if prev, ok := monthly[k]; !ok || r.id > prev {
				monthly[k] = r.id
			}
		}
	}
	for _, id := range weekly {
		keep[id] = true
	}
	for _, id := range monthly {
		keep[id] = true
	}
	return keep
}

// CompactResult reports a compaction.
type CompactResult struct {
	Services int   `json:"services"`
	Deleted  int64 `json:"deleted"`
	Kept     int64 `json:"kept"`
}

// Compact applies the policy to every service.
func (s *SnapshotStore) Compact(ctx context.Context, now time.Time, p SnapshotPolicy) (CompactResult, error) {
	var res CompactResult
	if p.Weekly < p.KeepAll {
		p.Weekly = p.KeepAll
	}
	prot, err := s.protected(ctx)
	if err != nil {
		return res, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, grp || char(31) || service, window_to_ms FROM contract_snapshots ORDER BY service, grp, id`)
	if err != nil {
		return res, err
	}
	bySvc := map[string][]snapRef{}
	for rows.Next() {
		var r snapRef
		var svc string
		var to int64
		if err := rows.Scan(&r.id, &svc, &to); err != nil {
			rows.Close()
			return res, err
		}
		r.to = time.UnixMilli(to).UTC()
		bySvc[svc] = append(bySvc[svc], r)
	}
	if err := rows.Close(); err != nil {
		return res, err
	}
	services := make([]string, 0, len(bySvc))
	for svc := range bySvc {
		services = append(services, svc)
	}
	sort.Strings(services)
	for _, svc := range services {
		refs := bySvc[svc]
		keep := keepSet(refs, now, p, prot)
		var drop []int64
		for _, r := range refs {
			if !keep[r.id] {
				drop = append(drop, r.id)
			}
		}
		res.Services++
		res.Kept += int64(len(keep))
		n, err := s.deleteIDs(ctx, drop)
		res.Deleted += n
		if err != nil {
			return res, err
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}
	return res, nil
}

// NewestAt returns the sequence number of the newest snapshot of service
// created at or before t (the contract baseline at that moment).
func (s *SnapshotStore) NewestAt(ctx context.Context, service string, t time.Time) (int64, bool, error) {
	return s.NewestAtIn(ctx, "", service, t)
}

// NewestAtEachGroup returns, for every group with a snapshot of service
// created at or before t, the sequence number of its newest one (the
// baseline of a pack built then, whatever group it was built for).
func (s *SnapshotStore) NewestAtEachGroup(ctx context.Context, service string, t time.Time) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT max(id) FROM contract_snapshots WHERE service = ? AND created_ms <= ? GROUP BY grp`, service, t.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// NewestAtIn is NewestAt for (group, service).
func (s *SnapshotStore) NewestAtIn(ctx context.Context, group, service string, t time.Time) (int64, bool, error) {
	var id sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(id) FROM contract_snapshots WHERE grp = ? AND service = ? AND created_ms <= ?`, group, service, t.UnixMilli()).Scan(&id); err != nil {
		return 0, false, err
	}
	return id.Int64, id.Valid, nil
}

// deleteIDs deletes snapshots by id, 200 per transaction.
func (s *SnapshotStore) deleteIDs(ctx context.Context, ids []int64) (int64, error) {
	var n int64
	for len(ids) > 0 {
		k := min(200, len(ids))
		chunk := ids[:k]
		ids = ids[k:]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		var r sql.Result
		err := s.db.InTx(ctx, func(tx *sql.Tx) error {
			var err error
			r, err = tx.ExecContext(ctx, `DELETE FROM contract_snapshots WHERE id IN (?`+strings.Repeat(", ?", len(chunk)-1)+`)`, args...)
			return err
		})
		if err != nil {
			return n, err
		}
		d, _ := r.RowsAffected()
		n += d
	}
	return n, nil
}
