package core

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
)

func longJobCore(t *testing.T, wait time.Duration) *Core {
	t.Helper()
	cfg := config.Default()
	return &Core{cfg: &cfg, log: slog.New(slog.DiscardHandler), jobs: newJobs(t.TempDir(), time.Hour, slog.New(slog.DiscardHandler)),
		syncWaitOverride: wait}
}

func jobHandler(delay time.Duration, status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, _ := io.ReadAll(r.Body)
		time.Sleep(delay)
		if r.Context().Err() != nil {
			status, body = 499, `{"code":"canceled"}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, strings.ReplaceAll(body, "$IN", string(in)))
	})
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{UserID: "usr_1"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A quick operation answers as before: the handler's own answer.
func TestLongJobFastAnswersDirectly(t *testing.T) {
	c := longJobCore(t, time.Second)
	h := c.longJobs(map[string]string{"POST /x": "x.run"}, jobHandler(0, 202, `{"job_id":"job_a","status":"done","result":$IN}`))
	rec := post(h, "/x", `{"n":1}`)
	if rec.Code != 202 || rec.Body.String() != `{"job_id":"job_a","status":"done","result":{"n":1}}` {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Other routes go straight through.
	rec = post(h, "/other", `{}`)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), "job_a") {
		t.Fatalf("other route: %d %s", rec.Code, rec.Body)
	}
}

// A slow operation answers a running Job before the write timeout; its
// result (or its error) arrives in the job, and the work is not canceled
// with the request.
func TestLongJobSlowBecomesRunningJob(t *testing.T) {
	c := longJobCore(t, 50*time.Millisecond)
	h := c.longJobs(map[string]string{"POST /x": "x.run", "POST /bad": "x.bad"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			jobHandler(200*time.Millisecond, 422, `{"code":"no_archetypes","message":"m"}`).ServeHTTP(w, r)
			return
		}
		jobHandler(200*time.Millisecond, 202, `{"job_id":"job_inner","status":"done","result":{"in":$IN}}`).ServeHTTP(w, r)
	}))
	t0 := time.Now()
	rec := post(h, "/x", `{"n":2}`)
	if time.Since(t0) > 150*time.Millisecond {
		t.Fatalf("answered after %v", time.Since(t0))
	}
	var j Job
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil || rec.Code != 202 || j.Status != "running" || j.Kind != "x.run" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	got := waitDone(t, c, j.ID)
	if got.Status != "done" || got.owner != "usr_1" {
		t.Fatalf("job: %+v", got)
	}
	if b, _ := json.Marshal(got.Result); string(b) != `{"in":{"n":2}}` {
		t.Fatalf("result %s", b)
	}
	rec = post(h, "/bad", `{}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &j)
	if got := waitDone(t, c, j.ID); got.Status != "failed" || got.Error != "no_archetypes" {
		t.Fatalf("failed job: %+v", got)
	}
}

// A failed slow job keeps the details of its error answer (which rules,
// which services): the console says what to fix (no_usable_rules).
func TestLongJobFailureKeepsDetails(t *testing.T) {
	c := longJobCore(t, 20*time.Millisecond)
	h := c.longJobs(map[string]string{"POST /w": "world.generate"}, jobHandler(100*time.Millisecond, 422,
		`{"code":"no_usable_rules","message":"m","details":[{"rule":"r-0008","reason":"out_of_scope","services":["orders-api"]}]}`))
	rec := post(h, "/w", `{}`)
	var j Job
	_ = json.Unmarshal(rec.Body.Bytes(), &j)
	got := waitDone(t, c, j.ID)
	if got.Status != "failed" || got.Error != "no_usable_rules" || string(got.Details) != `[{"rule":"r-0008","reason":"out_of_scope","services":["orders-api"]}]` {
		t.Fatalf("failed job: %+v %s", got, got.Details)
	}
	if b, _ := json.Marshal(got); !strings.Contains(string(b), `"details":[{"rule":"r-0008"`) {
		t.Fatalf("job JSON %s", b)
	}
}

func waitDone(t *testing.T, c *Core, id string) *Job {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if j := c.jobs.get(id); j != nil && j.Status != "running" && j.Status != "queued" {
			return j
		}
	}
	t.Fatal("job still running")
	return nil
}

// syncWait stays under the write timeout of the admin listener.
func TestSyncWaitUnderWriteTimeout(t *testing.T) {
	c := longJobCore(t, 0)
	c.cfg.Admin.HTTP.WriteTimeout = 30 * time.Second
	if d := c.syncWait(); d != 20*time.Second {
		t.Fatalf("30s write timeout: wait %v", d)
	}
	c.cfg.Admin.HTTP.WriteTimeout = 15 * time.Second
	if d := c.syncWait(); d != 10*time.Second {
		t.Fatalf("15s write timeout: wait %v", d)
	}
}

// A key with a "{name}" segment matches one path segment: the contract
// snapshot of any service runs as a job (91 s on the lab, beyond the write
// timeout), a deeper or a different path does not.
func TestLongJobKindPattern(t *testing.T) {
	kinds := map[string]string{"POST /api/v1/contracts/{service}/snapshots": "contract.snapshot", "POST /x": "x.run"}
	for key, want := range map[string]string{
		"POST /api/v1/contracts/shop-api/snapshots": "contract.snapshot",
		"POST /x": "x.run",
		"GET /api/v1/contracts/shop-api/snapshots":      "",
		"POST /api/v1/contracts//snapshots":             "",
		"POST /api/v1/contracts/a/b/snapshots":          "",
		"POST /api/v1/contracts/shop-api/snapshots/s-1": "",
	} {
		got, ok := longJobKind(kinds, key)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", key, got, ok, want)
		}
	}
}

// A slow non-Job answer (the 201 of a snapshot) becomes the result of the
// running job.
func TestLongJobPlainAnswerBecomesResult(t *testing.T) {
	c := longJobCore(t, 20*time.Millisecond)
	h := c.longJobs(map[string]string{"POST /s/{id}": "s.run"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"snapshot_id":"s-1","ops":3}`))
	}))
	rec := post(h, "/s/shop", `{}`)
	var j struct {
		ID     string `json:"job_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil || rec.Code != 202 || j.Status != "running" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.jobs.get(j.ID); got != nil && got.Status == "done" {
			b, _ := json.Marshal(got.Result)
			if !strings.Contains(string(b), `"snapshot_id":"s-1"`) {
				t.Fatalf("result: %s", b)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job not done")
}
