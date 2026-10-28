package keyguard

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
)

func TestMaintainPrunesFingerprintsAndArchivesAudit(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	db := e.svc.db
	// Two fingerprints: one fresh, one used long ago.
	for fp, at := range map[string]time.Time{"fp-old": e.clock.Now().Add(-30 * 24 * time.Hour), "fp-new": e.clock.Now()} {
		if _, err := db.ExecContext(ctx, `INSERT INTO kg_token_fps (fp, op, ref, used_at) VALUES (?, 'policy', 'p', ?)`, fp, at.UTC().Format(tsFormat)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		if _, err := e.svc.record(ctx, "keyguard.tokens", audit.Success, "", audit.Target{Type: "filter", ID: "2026-10"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// A year later: the old fingerprint and the old audit months go.
	e.clock.Add(400 * 24 * time.Hour)
	res, err := e.svc.Maintain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fingerprints != 2 {
		// Both are older than the margin a year later.
		t.Fatalf("fingerprints pruned: %+v", res)
	}
	if res.Segments == 0 || res.AuditEntries == 0 {
		t.Fatalf("audit not archived: %+v", res)
	}
	if _, err := e.svc.VerifyAudit(ctx); err != nil {
		t.Fatalf("verify after archive: %v", err)
	}
	if _, err := audit.VerifyArchive(filepath.Join(e.dir, "audit-archive")); err != nil {
		t.Fatalf("archive: %v", err)
	}
	// A fingerprint inside the margin stays.
	if _, err := db.ExecContext(ctx, `INSERT INTO kg_token_fps (fp, op, ref, used_at) VALUES ('fp-recent', 'pack', 'x', ?)`, e.clock.Now().UTC().Format(tsFormat)); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.Maintain(ctx); err != nil || res.Fingerprints != 0 {
		t.Fatalf("recent fingerprint pruned: %+v %v", res, err)
	}
}
