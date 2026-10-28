package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fillMonths records n entries per day from start for days days.
func fillMonths(t *testing.T, l *Log, clock *time.Time, days, perDay int) {
	t.Helper()
	for d := 0; d < days; d++ {
		for i := 0; i < perDay; i++ {
			*clock = clock.Add(24 * time.Hour / time.Duration(perDay))
			if _, err := l.Record(context.Background(), ev("policy.approve")); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestArchiveSegmentsKeepsTheChainVerifiable(t *testing.T) {
	ctx := context.Background()
	l, db := newLog(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	fillMonths(t, l, &clock, 120, 10) // four months
	headSeq, headHash, _ := l.Head(ctx)

	// Without an archive nothing can leave the database.
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_entries WHERE seq = 1`); err == nil {
		t.Fatal("an entry outside any segment was deleted")
	}

	dir := t.TempDir()
	key, err := LoadOrCreateArchiveKey(filepath.Join(t.TempDir(), "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	before := clock.Add(-45 * 24 * time.Hour)
	res, err := l.Archive(ctx, ArchiveOptions{Dir: dir, Key: key, Before: before, SegmentEntries: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Segments) < 3 || res.Entries == 0 {
		t.Fatalf("archive: %+v", res)
	}
	for _, s := range res.Segments {
		if !s.To.Before(before) || s.From.Month() != s.To.Month() || s.Entries > 200 {
			t.Fatalf("segment crosses a boundary: %+v", s)
		}
	}
	v, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Archived != res.Entries || v.Entries+v.Archived != headSeq+int64(len(res.Segments)) {
		t.Fatalf("verify after archive: %+v (head was %d)", v, headSeq)
	}
	// The chain continues over the archive: the old head is still linked.
	var linked int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE hash = ?`, headHash).Scan(&linked); err != nil || linked != 1 {
		t.Fatalf("old head lost: %d %v", linked, err)
	}
	rep, err := VerifyArchive(dir, key.KeyID())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != res.Entries || rep.FirstSeq != 1 || rep.Segments != len(res.Segments) {
		t.Fatalf("archive report: %+v", rep)
	}
	// Idempotent: nothing more is old enough.
	if again, err := l.Archive(ctx, ArchiveOptions{Dir: dir, Key: key, Before: before, SegmentEntries: 200}); err != nil || len(again.Segments) != 0 {
		t.Fatalf("second run: %+v %v", again, err)
	}
	// Segment rows cannot be removed or rewritten.
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_segments`); err == nil {
		t.Fatal("segment deleted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_segments SET head_hash = 'x'`); err == nil {
		t.Fatal("segment rewritten")
	}
	// New entries continue the chain; a later archive continues the segments.
	fillMonths(t, l, &clock, 60, 5)
	if _, err := l.Archive(ctx, ArchiveOptions{Dir: dir, Key: key, Before: clock.Add(-10 * 24 * time.Hour), SegmentEntries: 200}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchive(dir); err != nil {
		t.Fatal(err)
	}

	// Tampering with an archive file is detected.
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl.gz"))
	if err := os.WriteFile(files[0], []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchive(dir); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered archive: %v", err)
	}
	// So is a missing segment.
	if err := os.Remove(files[1]); err != nil {
		t.Fatal(err)
	}
	m := files[1][:len(files[1])-len(".jsonl.gz")] + ".json"
	if err := os.Remove(m); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(files[0], nil, 0o600)
	if _, err := VerifyArchive(dir); err == nil {
		t.Fatal("gap not detected")
	}
}

func TestArchiveResumesAnInterruptedPrune(t *testing.T) {
	ctx := context.Background()
	l, db := newLog(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	fillMonths(t, l, &clock, 70, 4)
	dir := t.TempDir()
	key, _ := LoadOrCreateArchiveKey(filepath.Join(t.TempDir(), "k.pem"))
	o := ArchiveOptions{Dir: dir, Key: key, Before: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}
	// Export by hand without pruning, as a crash right after the export.
	s, ok, err := l.nextSegment(ctx, o)
	if err != nil || !ok {
		t.Fatalf("next segment: %v %v", ok, err)
	}
	if err := l.writeSegment(ctx, o, &s); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO audit_segments (first_seq, last_seq, entries, first_prev_hash, head_hash, from_ts, to_ts,
		file, file_sha256, key_id, signature, created_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'exported')`,
		s.FirstSeq, s.LastSeq, s.Entries, s.FirstPrevHash, s.HeadHash, s.From.Format(time.RFC3339Nano), s.To.Format(time.RFC3339Nano),
		s.File, s.FileSHA256, s.KeyID, s.sig, s.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	// Half of it deleted.
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_entries WHERE seq < ?`, s.FirstSeq+s.Entries/2); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(ctx); err != nil {
		t.Fatalf("verify in the middle of a prune: %v", err)
	}
	res, err := l.Archive(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != s.Entries-s.Entries/2 {
		t.Fatalf("resumed prune removed %d", res.Entries)
	}
	if _, err := l.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	segs, _ := l.Segments(ctx)
	if len(segs) != 1 || segs[0].State != "pruned" {
		t.Fatalf("segments %+v", segs)
	}
}

func TestEmptyLogAfterArchiveContinuesTheChain(t *testing.T) {
	ctx := context.Background()
	l, db := newLog(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	fillMonths(t, l, &clock, 40, 2)
	dir := t.TempDir()
	key, _ := LoadOrCreateArchiveKey(filepath.Join(t.TempDir(), "k.pem"))
	if _, err := l.Archive(ctx, ArchiveOptions{Dir: dir, Key: key, Before: clock}); err != nil {
		t.Fatal(err)
	}
	// Simulate all entries archived (the trigger allows deletion within segments only).
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_entries WHERE seq <= (SELECT max(last_seq) FROM audit_segments)`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Record(ctx, ev("policy.approve")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
