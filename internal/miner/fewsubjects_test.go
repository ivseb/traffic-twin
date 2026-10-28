package miner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Enough hours of traffic but fewer distinct sampled users than k: the status says so, with the
// numbers, instead of leaving "0 rules" unexplained (the policy sampling is per user).
func TestStatusFewSubjects(t *testing.T) {
	s, _, _ := newTestService(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	res := &Result{Events: 800, Observed: 3 * time.Hour, Subjects: 7, Window: Window{From: "2026-01-01T09:00:00Z", To: "2026-01-01T12:00:00Z"}}
	if _, err := s.repo.Apply(context.Background(), res, now, now); err != nil {
		t.Fatal(err)
	}
	st := getStatus(t, s)
	if st.State != StateFewSubjects || st.Subjects == nil || *st.Subjects != 7 || st.KMin != 20 {
		t.Fatalf("status: %+v", st)
	}
	if w := strings.Join(st.Warnings, "\n"); !strings.Contains(w, "7 < k=20") || !strings.Contains(w, "raise the policy sampling") {
		t.Fatalf("warnings: %v", st.Warnings)
	}
	// With enough users the same traffic is just "ok".
	res.Subjects = 45
	if _, err := s.repo.Apply(context.Background(), res, now, now); err != nil {
		t.Fatal(err)
	}
	if st := getStatus(t, s); st.State == StateFewSubjects || st.Subjects == nil || *st.Subjects != 45 {
		t.Fatalf("status with 45 users: %+v", st)
	}
}
