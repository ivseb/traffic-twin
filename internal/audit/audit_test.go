package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ivseb/traffic-twin/internal/store"
)

func newLog(t testing.TB) (*Log, *store.DB) {
	t.Helper()
	r := store.NewRegistry()
	if err := r.Register(store.Namespace{Name: "audit", Migrations: migrations}); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenWith(context.Background(), filepath.Join(t.TempDir(), "a.db"), r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), db
}

func ev(action string) Event {
	return Event{
		Actor:   Actor{Kind: ActorUser, ID: "usr_1", Name: "alice"},
		Action:  action,
		Target:  Target{Type: "policy", ID: "p-shop"},
		Outcome: Success,
		Details: map[string]string{"version": "7"},
	}
}

func TestRecordAndVerify(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	for i := range 5 {
		e, err := l.Record(ctx, ev("policy.approve"))
		if err != nil {
			t.Fatal(err)
		}
		if e.Seq != int64(i+1) {
			t.Fatalf("seq = %d", e.Seq)
		}
	}
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seq, hash, _ := l.Head(ctx)
	if res.Entries != 5 || res.HeadSeq != seq || res.HeadHash != hash {
		t.Fatalf("verify = %+v, head = %d %s", res, seq, hash)
	}
}

func TestEmptyVerify(t *testing.T) {
	l, _ := newLog(t)
	res, err := l.Verify(context.Background())
	if err != nil || res.Entries != 0 || res.HeadHash != GenesisHash {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestConcurrentRecordsKeepChain(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := l.Record(ctx, ev("auth.login")); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	res, err := l.Verify(ctx)
	if err != nil || res.Entries != 20 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	ctx := context.Background()
	l, db := newLog(t)
	if _, err := l.Record(ctx, ev("auth.login")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_entries SET actor_name = 'mallory'`); err == nil {
		t.Error("UPDATE allowed")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_entries`); err == nil {
		t.Error("DELETE allowed")
	}
}

func TestTamperDetection(t *testing.T) {
	tamper := map[string]string{
		"modify field":   `UPDATE audit_entries SET actor_name = 'mallory' WHERE seq = 2`,
		"modify details": `UPDATE audit_entries SET details = '{"version":"8"}' WHERE seq = 3`,
		"delete middle":  `DELETE FROM audit_entries WHERE seq = 2`,
		"renumber":       `UPDATE audit_entries SET seq = seq + 100 WHERE seq = 4`,
		"rehash one":     `UPDATE audit_entries SET hash = '` + strings.Repeat("a", 64) + `' WHERE seq = 2`,
		"change outcome": `UPDATE audit_entries SET outcome = 'denied' WHERE seq = 1`,
	}
	for name, stmt := range tamper {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			l, db := newLog(t)
			for range 4 {
				if _, err := l.Record(ctx, ev("policy.approve")); err != nil {
					t.Fatal(err)
				}
			}
			// An attacker with file access can drop the triggers first.
			if _, err := db.ExecContext(ctx, `DROP TRIGGER audit_entries_no_update; DROP TRIGGER audit_entries_no_delete`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatal(err)
			}
			if _, err := l.Verify(ctx); !errors.Is(err, ErrTampered) {
				t.Fatalf("tampering not detected: %v", err)
			}
		})
	}
}

func TestRejectsPayloadLikeValues(t *testing.T) {
	l, _ := newLog(t)
	bad := []func(*Event){
		func(e *Event) { e.Details = map[string]string{"email": "giulia neri <giulia@example.com>"} },
		func(e *Event) { e.Details = map[string]string{"note": "free text with spaces"} },
		func(e *Event) { e.Details = map[string]string{"Bad Key": "x"} },
		func(e *Event) { e.Action = "login" },
		func(e *Event) { e.Outcome = "maybe" },
		func(e *Event) { e.Actor.Kind = "root" },
		func(e *Event) { e.Target.ID = strings.Repeat("x", 200) },
		func(e *Event) { e.Reason = "Something Went Wrong" },
		func(e *Event) {
			e.Details = map[string]string{}
			for i := range 20 {
				e.Details[string(rune('a'+i))] = "x"
			}
		},
	}
	for i, mut := range bad {
		e := ev("policy.approve")
		mut(&e)
		if _, err := l.Record(context.Background(), e); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
}

func TestExportAndVerifyHandlers(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	for range 3 {
		if _, err := l.Record(ctx, ev("policy.approve")); err != nil {
			t.Fatal(err)
		}
	}
	actor := func(*http.Request) (Actor, string) {
		return Actor{Kind: ActorUser, ID: "usr_aud", Name: "carla"}, "req1"
	}

	rec := httptest.NewRecorder()
	l.ExportHandler(actor).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?after_seq=1", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("export = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	var seqs []int64
	sc := bufio.NewScanner(rec.Body)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.computeHash() != e.Hash {
			t.Errorf("exported entry %d does not re-hash", e.Seq)
		}
		seqs = append(seqs, e.Seq)
	}
	// Entries 2, 3 plus the export's own audit entry (4).
	if len(seqs) != 3 || seqs[0] != 2 || seqs[2] != 4 {
		t.Fatalf("seqs = %v", seqs)
	}

	for _, q := range []string{"?limit=0", "?after_seq=-1", "?limit=x"} {
		rec = httptest.NewRecorder()
		l.ExportHandler(actor).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", q, rec.Code)
		}
	}

	rec = httptest.NewRecorder()
	l.VerifyHandler(actor).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["ok"] != true || body["entries"].(float64) != 4 {
		t.Fatalf("verify body = %v", body)
	}
}
