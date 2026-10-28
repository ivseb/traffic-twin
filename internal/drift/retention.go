package drift

import (
	"context"
	"time"
)

// Retention of the drift tables (docs/DATA_LIFECYCLE.md).
//
//   - drift_deliveries: one row per webhook notification with its payload.
//     Delivered and failed rows older than the deliveries retention are
//     deleted (the audit log keeps who configured what; the payloads are
//     only useful for debugging a receiver). Pending rows are never touched.
//   - drift_alerts: open and acknowledged alerts are kept; resolved alerts
//     are deleted when resolved longer ago than the alerts retention. The
//     snapshots they reference are protected only while they exist.

// PruneResult reports a prune.
type PruneResult struct {
	Deliveries int64 `json:"deliveries"`
	Alerts     int64 `json:"alerts"`
}

const pruneChunk = 2000

// Prune deletes finished deliveries older than deliveries and alerts
// resolved more than alerts ago (zero durations keep everything), in small
// transactions.
func (m *Manager) Prune(ctx context.Context, deliveries, alerts time.Duration) (PruneResult, error) {
	var res PruneResult
	now := m.now()
	if deliveries > 0 {
		cut := now.Add(-deliveries).UnixMilli()
		n, err := m.chunked(ctx, `DELETE FROM drift_deliveries WHERE id IN (SELECT id FROM drift_deliveries
			WHERE state IN ('delivered', 'failed') AND created_ms < ? ORDER BY id LIMIT ?)`, cut)
		res.Deliveries = n
		if err != nil {
			return res, err
		}
	}
	if alerts > 0 {
		cut := now.Add(-alerts).UnixMilli()
		n, err := m.chunked(ctx, `DELETE FROM drift_alerts WHERE id IN (SELECT id FROM drift_alerts
			WHERE state = 'resolved' AND resolved_ms > 0 AND resolved_ms < ? ORDER BY id LIMIT ?)`, cut)
		res.Alerts = n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func (m *Manager) chunked(ctx context.Context, q string, cut int64) (int64, error) {
	var total int64
	for {
		r, err := m.db.ExecContext(ctx, q, cut, pruneChunk)
		if err != nil {
			return total, err
		}
		n, _ := r.RowsAffected()
		total += n
		if n < pruneChunk || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

// ReferencedSnapshots returns the snapshot ids ("sn-...") referenced by
// the stored alerts: contract compaction keeps them.
func (m *Manager) ReferencedSnapshots(ctx context.Context) ([]string, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT snapshot_from FROM drift_alerts WHERE snapshot_from <> ''
		UNION SELECT snapshot_to FROM drift_alerts WHERE snapshot_to <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
