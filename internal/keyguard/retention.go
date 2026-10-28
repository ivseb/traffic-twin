package keyguard

import (
	"context"
	"path/filepath"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
)

// Data lifecycle of keyguard (docs/DATA_LIFECYCLE.md).
//
//   - kg_token_fps: the fingerprint of every approval ID token keyguard
//     accepted, to refuse a replay. A token older than ApprovalTokenMaxAge
//     (plus clock skew) is refused anyway, so a fingerprint is useful only
//     that long: rows used more than FingerprintMargin ago are deleted.
//   - the audit log: segments older than AuditArchiveAfter leave the
//     database as signed archive files (audit.Archive), never silently.
//   - kg_bloom and kg_bloom_journal: filters not updated for Retention are
//     dropped at the snapshot, the journal is folded into the snapshots
//     (filters.go).
//   - kg_signed and kg_approvals are the custody record of every signature:
//     append-only and kept (one row per policy signature or renewal).

// MaintainResult reports a maintenance pass.
type MaintainResult struct {
	Fingerprints int64 `json:"fingerprints"`
	AuditEntries int64 `json:"audit_entries"`
	Segments     int   `json:"segments"`
	Reclaimed    int64 `json:"reclaimed_bytes"`
}

const maintainEvery = time.Hour

func (s *Service) auditArchiveDir() string {
	if s.cfg.AuditArchiveDir != "" {
		return s.cfg.AuditArchiveDir
	}
	return filepath.Join(filepath.Dir(s.cfg.DBPath), "audit-archive")
}

// Maintain prunes the expired token fingerprints, archives the old audit
// segments and gives the freed pages back.
func (s *Service) Maintain(ctx context.Context) (MaintainResult, error) {
	var res MaintainResult
	now := s.now()
	rows, err := s.db.QueryContext(ctx, `SELECT fp, used_at FROM kg_token_fps`)
	if err != nil {
		return res, err
	}
	var old []string
	for rows.Next() {
		var fp, at string
		if err := rows.Scan(&fp, &at); err != nil {
			rows.Close()
			return res, err
		}
		if t, err := time.Parse(tsFormat, at); err == nil && now.Sub(t) > FingerprintMargin {
			old = append(old, fp)
		}
	}
	if err := rows.Close(); err != nil {
		return res, err
	}
	for _, fp := range old {
		r, err := s.db.ExecContext(ctx, `DELETE FROM kg_token_fps WHERE fp = ?`, fp)
		if err != nil {
			return res, err
		}
		n, _ := r.RowsAffected()
		res.Fingerprints += n
	}
	if s.cfg.AuditArchiveAfter > 0 {
		key, err := audit.LoadOrCreateArchiveKey(filepath.Join(filepath.Dir(s.cfg.DBPath), "audit-archive.key"))
		if err != nil {
			return res, err
		}
		ar, err := s.audit.Archive(ctx, audit.ArchiveOptions{Dir: s.auditArchiveDir(), Key: key, Before: now.Add(-s.cfg.AuditArchiveAfter),
			LogName: "keyguard", Actor: audit.Actor{Kind: audit.ActorSystem, ID: "keyguard", Name: "retention"}})
		res.AuditEntries, res.Segments = ar.Entries, len(ar.Segments)
		if err != nil {
			return res, err
		}
	}
	if res.Fingerprints > 0 || res.AuditEntries > 0 {
		res.Reclaimed, _ = s.db.Reclaim(ctx)
	}
	return res, nil
}
