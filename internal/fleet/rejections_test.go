package fleet

import (
	"strings"
	"testing"
	"time"
)

type rejectCounts struct{ rs []Rejection }

func (rejectCounts) AcceptedEvents(string) uint64 { return 0 }

func (r rejectCounts) RecentRejections(string, time.Duration) []Rejection { return r.rs }

func TestIntakeRejectionsShowInSourceLastErrors(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenGroup, "sdk-node")
	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	s.heartbeat("capturing", 0)
	t0 := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)
	t1 := t0.Add(4 * time.Minute)
	e.fleet.SetEventCounter(rejectCounts{rs: []Rejection{
		{Reason: "schema", Count: 4, First: t0, Last: t0},
		{Reason: "resource_mismatch", Count: 123, First: t0, Last: t1},
		{Reason: "path_shape", Count: 0},
	}})

	var one SourceStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	var got []LastError
	for _, le := range one.LastErrors {
		if strings.HasPrefix(le.Code, "intake_rejected:") {
			got = append(got, le)
		}
	}
	if len(got) != 2 || got[0].Code != "intake_rejected:resource_mismatch" || got[0].Count != 123 ||
		got[1].Code != "intake_rejected:schema" || got[1].Count != 4 {
		t.Fatalf("intake rejections in last_errors: %+v (all: %+v)", got, one.LastErrors)
	}
	// The times are those of the rejections, not of the heartbeat.
	if got[0].FirstSeen == nil || !got[0].FirstSeen.Equal(t0) || got[0].LastSeen == nil || !got[0].LastSeen.Equal(t1) || !got[0].At.Equal(t1) {
		t.Fatalf("times of the rejection: %+v", got[0])
	}
	// Once the rejections stop (nothing in the window) the entries are gone.
	e.fleet.SetEventCounter(rejectCounts{})
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	for _, le := range one.LastErrors {
		if strings.HasPrefix(le.Code, "intake_rejected:") {
			t.Fatalf("a rejection that stopped is still listed: %+v", le)
		}
	}
}

func TestAppendIntakeRejectionsIsBounded(t *testing.T) {
	var rej []Rejection
	for _, r := range []string{"a", "b", "c", "d", "e"} {
		rej = append(rej, Rejection{Reason: r, Count: 1})
	}
	errs := make([]LastError, 18)
	if out := appendIntakeRejections(errs, rej); len(out) != maxLastErrorsShown {
		t.Fatalf("len %d, want %d", len(out), maxLastErrorsShown)
	}
	if out := appendIntakeRejections(nil, nil); len(out) != 0 {
		t.Fatalf("no rejections: %v", out)
	}
}

func TestWindowedErrorsGroupAndExpire(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	at := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }
	in := []LastError{
		{Code: "send_error", At: at(90)}, // outside the window: gone
		{Code: "send_error", At: at(10)},
		{Code: "queue_full", At: at(8)},
		{Code: "send_error", At: at(2)},
		{Code: "send_error", At: at(5)},
	}
	out := windowedErrors(in, now, 15*time.Minute)
	if len(out) != 2 || out[0].Code != "queue_full" || out[1].Code != "send_error" {
		t.Fatalf("windowed: %+v", out)
	}
	se := out[1]
	if se.Count != 3 || !se.FirstSeen.Equal(at(10)) || !se.LastSeen.Equal(at(2)) || !se.At.Equal(at(2)) {
		t.Errorf("send_error: %+v", se)
	}
	// A later look with the same list: the entry ages, its time does not move.
	later := windowedErrors(in, now.Add(10*time.Minute), 15*time.Minute)
	if len(later) != 1 || later[0].Code != "send_error" || later[0].Count != 2 {
		t.Errorf("later: %+v", later)
	}
	if out := windowedErrors(in, now.Add(time.Hour), 15*time.Minute); len(out) != 0 {
		t.Errorf("an old error must disappear: %+v", out)
	}
}

type doubleCaps struct{ rejectCounts }

func (doubleCaps) DoubleCaptured(string) bool { return true }

func TestDoubleCaptureIsAProblemOfTheSource(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenGroup, "sdk-node")
	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	s.heartbeat("capturing", 0)
	var one SourceStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	for _, p := range one.Problems {
		if p.Code == "double_capture" {
			t.Fatalf("no problem expected before detection: %+v", one.Problems)
		}
	}
	e.fleet.SetEventCounter(doubleCaps{})
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	found := false
	for _, p := range one.Problems {
		if p.Code == "double_capture" && strings.Contains(p.Hint, "either the SDK or tt-egress") {
			found = true
		}
	}
	if !found {
		t.Fatalf("double_capture problem missing: %+v", one.Problems)
	}
}
