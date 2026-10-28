package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestExportTailPaging(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	for range 9 {
		if _, err := l.Record(ctx, ev("policy.approve")); err != nil {
			t.Fatal(err)
		}
	}
	actor := func(*http.Request) (Actor, string) {
		return Actor{Kind: ActorUser, ID: "usr_aud", Name: "carla"}, "req"
	}
	get := func(q string) (int, []int64) {
		rec := httptest.NewRecorder()
		l.ExportHandler(actor).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x"+q, nil))
		var seqs []int64
		sc := bufio.NewScanner(rec.Body)
		for sc.Scan() {
			var e Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				continue // error body of a 400
			}
			if e.Seq > 0 {
				seqs = append(seqs, e.Seq)
			}
		}
		return rec.Code, seqs
	}
	// The export audits itself first (seq 10): the newest 3 are 8, 9, 10.
	code, seqs := get("?last=3")
	if code != 200 || !slices.Equal(seqs, []int64{8, 9, 10}) {
		t.Fatalf("last=3: %d %v", code, seqs)
	}
	// Walking back from the first seq received.
	if _, seqs = get("?last=3&before_seq=8"); !slices.Equal(seqs, []int64{5, 6, 7}) {
		t.Fatalf("before_seq=8: %v", seqs)
	}
	if _, seqs = get("?last=5&before_seq=3"); !slices.Equal(seqs, []int64{1, 2}) {
		t.Fatalf("start of the log: %v", seqs)
	}
	if _, seqs = get("?before_seq=3&limit=1"); !slices.Equal(seqs, []int64{2}) {
		t.Fatalf("limit as page size: %v", seqs)
	}
	for _, q := range []string{"?last=0", "?before_seq=0", "?last=x", "?last=2&after_seq=1", "?last=100001"} {
		if code, _ := get(q); code != http.StatusBadRequest {
			t.Errorf("%s = %d", q, code)
		}
	}
}
