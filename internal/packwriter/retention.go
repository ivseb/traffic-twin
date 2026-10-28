package packwriter

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// Retention of the built packs (docs/DATA_LIFECYCLE.md).
//
// A pack row holds its manifest and gate report (small) and the archive and
// signature (the bulk: up to megabytes). Published packs are kept whole:
// they are what the mocks in CI were given. Unpublished packs (signed but
// never published, or gate-failed):
//
//   - keep their archive while they are among the newest KeepBuilt and not
//     past their manifest not_after;
//   - otherwise lose the archive and signature (publishing them answers 410
//     pack_pruned: build again), keeping the row for the history;
//   - rows older than RowTTL are deleted.
//
// Packs still "building" are never touched.

// RetentionPolicy configures Prune.
type RetentionPolicy struct {
	KeepBuilt int
	RowTTL    time.Duration
}

// PruneResult reports a prune.
type PruneResult struct {
	Archives int64 `json:"archives"`
	Rows     int64 `json:"rows"`
	Bytes    int64 `json:"bytes"`
}

// Prune applies the policy at now.
func (s *Service) Prune(ctx context.Context, now time.Time, p RetentionPolicy) (PruneResult, error) {
	var res PruneResult
	rows, err := s.o.DB.QueryContext(ctx, `SELECT id, created_at, manifest, length(archive) + length(sig) FROM packwriter_packs
		WHERE status IN ('signed', 'gate-failed') AND archive IS NOT NULL ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return res, err
	}
	type cand struct {
		id   string
		size int64
	}
	var drop []cand
	i := 0
	for rows.Next() {
		var id string
		var created int64
		var man []byte
		var size sql.NullInt64
		if err := rows.Scan(&id, &created, &man, &size); err != nil {
			rows.Close()
			return res, err
		}
		i++
		expired := false
		var m struct {
			NotAfter string `json:"not_after"`
		}
		if json.Unmarshal(man, &m) == nil && m.NotAfter != "" {
			if t, err := time.Parse(time.RFC3339, m.NotAfter); err == nil && now.After(t) {
				expired = true
			}
		}
		if expired || i > p.KeepBuilt {
			drop = append(drop, cand{id, size.Int64})
		}
	}
	if err := rows.Close(); err != nil {
		return res, err
	}
	for _, c := range drop {
		r, err := s.o.DB.ExecContext(ctx, `UPDATE packwriter_packs SET archive = NULL, sig = NULL WHERE id = ? AND status IN ('signed', 'gate-failed')`, c.id)
		if err != nil {
			return res, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			res.Archives++
			res.Bytes += c.size
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}
	if p.RowTTL > 0 {
		r, err := s.o.DB.ExecContext(ctx, `DELETE FROM packwriter_packs WHERE status IN ('signed', 'gate-failed') AND created_at < ?`, now.Add(-p.RowTTL).Unix())
		if err != nil {
			return res, err
		}
		res.Rows, _ = r.RowsAffected()
	}
	return res, nil
}

// PublishedRefs lists, for every published pack, its creation time, world
// and the services of its manifest: what the retention of worlds and
// contract snapshots must keep.
type PublishedRef struct {
	PackID    string
	WorldID   string
	CreatedAt time.Time
	Services  []string
}

// PackRefs returns the published packs and the world ids of every pack row
// (worlds referenced by any pack are kept).
func (s *Service) PackRefs(ctx context.Context) ([]PublishedRef, map[string]bool, error) {
	rows, err := s.o.DB.QueryContext(ctx, `SELECT id, world_id, status, created_at, manifest FROM packwriter_packs`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var pub []PublishedRef
	worlds := map[string]bool{}
	for rows.Next() {
		var id, world, status string
		var created int64
		var man []byte
		if err := rows.Scan(&id, &world, &status, &created, &man); err != nil {
			return nil, nil, err
		}
		worlds[world] = true
		if status != "published" {
			continue
		}
		ref := PublishedRef{PackID: id, WorldID: world, CreatedAt: time.Unix(created, 0).UTC()}
		var m struct {
			Services []struct {
				Name string `json:"name"`
			} `json:"services"`
		}
		if json.Unmarshal(man, &m) == nil {
			for _, sv := range m.Services {
				ref.Services = append(ref.Services, sv.Name)
			}
		}
		pub = append(pub, ref)
	}
	return pub, worlds, rows.Err()
}
