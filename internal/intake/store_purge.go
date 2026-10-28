package intake

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Retention runs share the single SQLite writer with the intake. A delete
// holds the write lock for its whole transaction, and a writer that finds
// the lock taken backs off for up to a hundred milliseconds before it tries
// again: back-to-back purge transactions would starve it. Every chunk is
// therefore small (tokenChunk rows of the token index, 1000 events) and is
// followed by a pause as long as the chunk itself, so that the purge never
// takes more than about half of the writer's time.

// tokenChunk is the number of token index rows deleted per transaction.
const tokenChunk = 5000

// purgePauseFor sleeps for d (at least 2 ms, at most 200 ms) or until ctx
// is done.
func purgePauseFor(ctx context.Context, d time.Duration) error {
	d = min(max(d, 2*time.Millisecond), 200*time.Millisecond)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// purgeTokenHour deletes the token index partition of one hour, tokenChunk
// rows per transaction (one partition of a busy hour holds millions).
func (s *Store) purgeTokenHour(ctx context.Context, hour int64) (int64, error) {
	var total int64
	for {
		t0 := time.Now()
		var bound string
		err := s.db.QueryRowContext(ctx, `SELECT token FROM intake_tokens WHERE hour = ? ORDER BY token LIMIT 1 OFFSET ?`, hour, tokenChunk).Scan(&bound)
		var r sql.Result
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// The rest of the partition fits in one chunk.
			r, err = s.db.ExecContext(ctx, `DELETE FROM intake_tokens WHERE hour = ?`, hour)
			if err != nil {
				return total, err
			}
			n, _ := r.RowsAffected()
			return total + n, nil
		case err != nil:
			return total, err
		}
		r, err = s.db.ExecContext(ctx, `DELETE FROM intake_tokens WHERE hour = ? AND token < ?`, hour, bound)
		if err != nil {
			return total, err
		}
		n, _ := r.RowsAffected()
		if n == 0 {
			// One token fills the chunk by itself: delete its rows.
			if r, err = s.db.ExecContext(ctx, `DELETE FROM intake_tokens WHERE hour = ? AND token = ?`, hour, bound); err != nil {
				return total, err
			}
			n, _ = r.RowsAffected()
		}
		total += n
		if err := purgePauseFor(ctx, time.Since(t0)); err != nil {
			return total, err
		}
	}
}
