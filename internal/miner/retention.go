package miner

import (
	"context"
	"time"
)

// Retention of the miner tables (docs/DATA_LIFECYCLE.md).
//
// The miner reads raw events only within its window and persists, per rule,
// the evidence counts and confidence (miner_rules): rules are kept, also the
// rejected ones, whose signature stops the same candidate from being
// proposed again. miner_runs holds one row per run with its diagnostics (the
// bulk, a few KB to a few hundred KB): runs older than TTL are deleted,
// except the newest Keep (the status page and the stale strikes read the
// last ones only).

// PruneRuns deletes the runs that started more than ttl before now, keeping
// the newest keep runs.
func (rp *Repo) PruneRuns(ctx context.Context, now time.Time, ttl time.Duration, keep int) (int64, error) {
	if ttl <= 0 {
		return 0, nil
	}
	r, err := rp.db.ExecContext(ctx, `DELETE FROM miner_runs WHERE started_at < ?
		AND id NOT IN (SELECT id FROM miner_runs ORDER BY id DESC LIMIT ?)`, now.Add(-ttl).UnixMilli(), max(1, keep))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
