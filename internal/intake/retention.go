package intake

import (
	"context"
	"time"
)

// Lifecycle helpers used by the core maintenance job (docs/DATA_LIFECYCLE.md).

// PurgeKeeping deletes the events received more than keep ago, whatever the
// configured retention (the shedding step of the size budget: keep is then
// the miner window or the emergency floor). It rolls up first, like Purge.
func (in *Intake) PurgeKeeping(ctx context.Context, keep time.Duration) (PurgeResult, error) {
	if keep <= 0 {
		return PurgeResult{}, nil
	}
	res, err := in.store.PurgeBefore(ctx, in.now().Add(-keep))
	if err == nil && (res.Events > 0 || res.Tokens > 0) {
		in.scrub(ctx)
	}
	return res, err
}

// PruneQuarantines deletes the released quarantines whose release is older
// than ttl: a released element is counted again from zero and its record
// only documents the past (the audit log keeps the approvals).
func (in *Intake) PruneQuarantines(ctx context.Context, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, nil
	}
	cut := in.now().Add(-ttl).UnixMilli()
	rows, err := in.db.QueryContext(ctx, `SELECT id FROM intake_quarantine WHERE state = 'released' AND coalesce(changed_ms, since_ms) < ?`, cut)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var n int64
	for _, id := range ids {
		r, err := in.db.ExecContext(ctx, `DELETE FROM intake_quarantine WHERE id = ? AND state = 'released'`, id)
		if err != nil {
			return n, err
		}
		k, _ := r.RowsAffected()
		n += k
		in.quar.mu.Lock()
		if q := in.quar.byID[id]; q != nil && q.State == StateReleased {
			delete(in.quar.byID, id)
		}
		in.quar.mu.Unlock()
	}
	return n, nil
}
