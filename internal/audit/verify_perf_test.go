package audit

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func fill(tb testing.TB, l *Log, n int) {
	tb.Helper()
	for i := 0; i < n; i++ {
		e := ev("rule.approve")
		e.Details = map[string]string{"n": fmt.Sprint(i)}
		if _, err := l.Record(context.Background(), e); err != nil {
			tb.Fatal(err)
		}
	}
}

// The parallel verification still finds a tampered entry in the middle of
// a block, and reports the first one.
func TestVerifyBlocksFindTampering(t *testing.T) {
	l, db := newLog(t)
	fill(t, l, 9000) // more than two blocks
	res, err := l.Verify(context.Background())
	if err != nil || res.Entries != 9000 || res.HeadSeq != 9000 {
		t.Fatalf("clean chain: %+v %v", res, err)
	}
	if _, err := db.Exec(`DROP TRIGGER audit_entries_no_update`); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []int64{6000, 5000} {
		if _, err := db.Exec(`UPDATE audit_entries SET target_id = 'other' WHERE seq = ?`, seq); err != nil {
			t.Fatal(err)
		}
	}
	_, err = l.Verify(context.Background())
	if !errors.Is(err, ErrTampered) || err.Error() != "audit: chain verification failed: seq 5000 content does not match its hash" {
		t.Fatalf("tampered chain: %v", err)
	}
}

// BenchmarkVerify measures GET /api/v1/audit/verify on a 20k-entry log
// (the lab runs it nightly on a log of about a million entries).
func BenchmarkVerify(b *testing.B) {
	l, _ := newLog(b)
	fill(b, l, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Verify(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
