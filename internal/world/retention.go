package world

import (
	"context"
	"time"
)

// Retention of worlds and archetype builds (docs/DATA_LIFECYCLE.md).
//
// A world row holds the generated world and its synthetic records (the
// bulk). Worlds referenced by a pack are kept (a pack is regenerated from
// its world when published); otherwise a world is kept while among the
// newest Keep or younger than TTL. An archetype build is kept while a
// remaining world references it, and the newest KeepBuilds builds always.

// RetentionPolicy configures Prune.
type RetentionPolicy struct {
	Keep       int
	TTL        time.Duration
	KeepBuilds int
}

// PruneResult reports a prune.
type PruneResult struct {
	Worlds int64 `json:"worlds"`
	Builds int64 `json:"builds"`
}

// Prune deletes the worlds and builds the policy no longer keeps. referenced
// holds the world ids used by packs.
func (s *Service) Prune(ctx context.Context, now time.Time, p RetentionPolicy, referenced map[string]bool) (PruneResult, error) {
	var res PruneResult
	rows, err := s.o.DB.QueryContext(ctx, `SELECT id, created_at FROM world_worlds ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return res, err
	}
	var drop []string
	i := 0
	cut := now.Add(-p.TTL).Unix()
	for rows.Next() {
		var id string
		var created int64
		if err := rows.Scan(&id, &created); err != nil {
			rows.Close()
			return res, err
		}
		i++
		if i > p.Keep && created < cut && !referenced[id] {
			drop = append(drop, id)
		}
	}
	if err := rows.Close(); err != nil {
		return res, err
	}
	for _, id := range drop {
		r, err := s.o.DB.ExecContext(ctx, `DELETE FROM world_worlds WHERE id = ?`, id)
		if err != nil {
			return res, err
		}
		n, _ := r.RowsAffected()
		res.Worlds += n
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}
	r, err := s.o.DB.ExecContext(ctx, `DELETE FROM world_builds WHERE id NOT IN (SELECT build_id FROM world_worlds WHERE build_id IS NOT NULL)
		AND id NOT IN (SELECT id FROM world_builds ORDER BY id DESC LIMIT ?)`, max(1, p.KeepBuilds))
	if err != nil {
		return res, err
	}
	res.Builds, _ = r.RowsAffected()
	return res, nil
}
