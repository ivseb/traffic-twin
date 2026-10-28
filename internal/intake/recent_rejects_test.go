package intake

import (
	"testing"
	"time"
)

func TestRecentRejectsWindow(t *testing.T) {
	var r recentRejects
	t0 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 9147; i++ { // an old burst, 50 minutes ago
		r.add(ReasonResourceMismatch, t0.Add(-50*time.Minute))
	}
	r.add(ReasonResourceMismatch, t0.Add(-3*time.Minute))
	r.add(ReasonResourceMismatch, t0.Add(-1*time.Minute))

	got := r.snapshot(15*time.Minute, t0)
	if len(got) != 1 || got[0].Reason != ReasonResourceMismatch.String() || got[0].Count != 2 {
		t.Fatalf("15 minutes: %+v", got)
	}
	if !got[0].First.Equal(t0.Add(-3*time.Minute)) || !got[0].Last.Equal(t0.Add(-1*time.Minute)) {
		t.Errorf("times: %+v", got[0])
	}
	if all := r.snapshot(time.Hour, t0); len(all) != 1 || all[0].Count != 9149 {
		t.Errorf("one hour: %+v", all)
	}
	// Nothing in the window once the rejections stopped.
	if got := r.snapshot(15*time.Minute, t0.Add(30*time.Minute)); len(got) != 0 {
		t.Errorf("stopped rejections still listed: %+v", got)
	}
	// A bucket is reused an hour later without carrying the old count.
	r.add(ReasonResourceMismatch, t0.Add(time.Hour-3*time.Minute))
	if got := r.snapshot(15*time.Minute, t0.Add(time.Hour)); len(got) != 1 || got[0].Count != 1 {
		t.Errorf("reused bucket: %+v", got)
	}
}
