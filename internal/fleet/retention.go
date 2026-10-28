package fleet

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
)

// Retention of the Fleet tables (docs/DATA_LIFECYCLE.md).
//
//   - fleet_certs: one row per issued client certificate (renewed every
//     client_cert_ttl): rows expired longer ago than ExpiredCerts go.
//   - fleet_sources: a revoked source not seen for RevokedSources is
//     archived: an audit entry fleet.source.archive keeps its identity
//     (id, group, kind, service, enrollment and last contact), then the row
//     and its certificates are deleted. Active sources are never touched.
//   - fleet_tokens: enrollment tokens expired (or revoked) longer ago than
//     ExpiredTokens and used by no remaining source go.
//   - policy versions are kept: every signed version may be referenced by
//     stored events, packs and the keyguard log; they are small.

// RetentionPolicy configures Prune (zero durations keep everything).
type RetentionPolicy struct {
	RevokedSources time.Duration
	ExpiredTokens  time.Duration
	ExpiredCerts   time.Duration
}

// PruneResult reports a prune.
type PruneResult struct {
	Sources int64 `json:"sources"`
	Tokens  int64 `json:"tokens"`
	Certs   int64 `json:"certs"`
}

var fleetSystem = audit.Actor{Kind: audit.ActorSystem, ID: "tt-core", Name: "retention"}

// Prune applies the policy.
func (f *Fleet) Prune(ctx context.Context, p RetentionPolicy) (PruneResult, error) {
	var res PruneResult
	now := f.now()
	if p.ExpiredCerts > 0 {
		r, err := f.db.ExecContext(ctx, `DELETE FROM fleet_certs WHERE not_after < ?`, now.Add(-p.ExpiredCerts).Unix())
		if err != nil {
			return res, err
		}
		res.Certs, _ = r.RowsAffected()
	}
	if p.RevokedSources > 0 {
		cut := now.Add(-p.RevokedSources).Unix()
		rows, err := f.db.QueryContext(ctx, `SELECT id, grp, kind, service_name, enrolled_at, last_seen FROM fleet_sources
			WHERE revoked = 1 AND max(last_seen, enrolled_at) < ? ORDER BY id`, cut)
		if err != nil {
			return res, err
		}
		type src struct {
			id, grp, kind, svc string
			enrolled, seen     int64
		}
		var olds []src
		for rows.Next() {
			var s src
			if err := rows.Scan(&s.id, &s.grp, &s.kind, &s.svc, &s.enrolled, &s.seen); err != nil {
				rows.Close()
				return res, err
			}
			olds = append(olds, s)
		}
		if err := rows.Close(); err != nil {
			return res, err
		}
		for _, s := range olds {
			// The audit entry first: the identity of the source outlives its row.
			if _, err := f.audit.Record(ctx, audit.Event{Actor: fleetSystem, Action: "fleet.source.archive",
				Target: audit.Target{Type: "source", ID: audit.SafeValue(s.id)}, Outcome: audit.Success,
				Details: map[string]string{"group": audit.SafeValue(s.grp), "kind": audit.SafeValue(s.kind), "service": audit.SafeValue(s.svc),
					"enrolled_at": strconv.FormatInt(s.enrolled, 10), "last_seen": strconv.FormatInt(s.seen, 10)}}); err != nil {
				return res, err
			}
			err := f.db.InTx(ctx, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `DELETE FROM fleet_certs WHERE source_id = ?`, s.id); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `DELETE FROM fleet_sources WHERE id = ? AND revoked = 1`, s.id)
				return err
			})
			if err != nil {
				return res, err
			}
			res.Sources++
		}
	}
	if p.ExpiredTokens > 0 {
		cut := now.Add(-p.ExpiredTokens).Unix()
		r, err := f.db.ExecContext(ctx, `DELETE FROM fleet_tokens WHERE (expires_at < ? OR (revoked = 1 AND created_at < ?))
			AND id NOT IN (SELECT token_id FROM fleet_sources)`, cut, cut)
		if err != nil {
			return res, err
		}
		res.Tokens, _ = r.RowsAffected()
	}
	if res.Sources+res.Tokens+res.Certs > 0 {
		if err := f.reload(ctx); err != nil {
			return res, err
		}
	}
	return res, nil
}
