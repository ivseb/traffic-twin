package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// The gate admits slots jobs at once, the others in arrival order.
func TestHeavyGateFIFO(t *testing.T) {
	g := newHeavyGate(1)
	rel, err := g.acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var order []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range 3 {
		queued := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := g.acquire(context.Background(), func() { close(queued) })
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			r()
		}()
		<-queued // the next one queues after this one
	}
	if run, wait := g.stats(); run != 1 || wait != 3 {
		t.Fatalf("stats %d running, %d waiting", run, wait)
	}
	rel()
	rel() // idempotent
	wg.Wait()
	if len(order) != 3 || order[0] != 0 || order[1] != 1 || order[2] != 2 {
		t.Fatalf("order %v", order)
	}
	if run, wait := g.stats(); run != 0 || wait != 0 {
		t.Fatalf("after: %d running, %d waiting", run, wait)
	}
}

// A waiter whose context ends leaves the queue; the slot is not lost.
func TestHeavyGateCancel(t *testing.T) {
	g := newHeavyGate(1)
	rel, _ := g.acquire(context.Background(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := g.acquire(ctx, cancel) // cancels itself once queued
		errc <- err
	}()
	if err := <-errc; err == nil {
		t.Fatal("canceled waiter admitted")
	}
	rel()
	r2, err := g.acquire(context.Background(), func() { t.Error("slot lost") })
	if err != nil {
		t.Fatal(err)
	}
	r2()
}

func TestHeavySlots(t *testing.T) {
	for limit, want := range map[uint64]int{0: 1, 4 << 30: 1, 8 << 30: 1, 15 << 30: 1, 16 << 30: 2, 32 << 30: 4, 128 << 30: 4} {
		if got := heavySlots(limit); got != want {
			t.Errorf("%d GiB: %d slots, want %d", limit>>30, got, want)
		}
	}
}

func operatorPost(h http.Handler, path, user string) *jobAnswer {
	req := newPost(path, `{}`, &auth.Principal{UserID: user, Roles: []auth.Role{auth.RoleOperator}})
	rec := serve(h, req)
	var j jobAnswer
	_ = json.Unmarshal(rec.Body.Bytes(), &j)
	j.code = rec.Code
	return &j
}

type jobAnswer struct {
	ID     string `json:"job_id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	code   int
}

// Heavy jobs run one at a time on a small host: a second one answers
// "queued" (visible in the job list) and runs when the first ends. A second
// mining request while one is queued or running joins it: one run, one job,
// readable by both users.
func TestLongJobsQueueAndJoin(t *testing.T) {
	c := longJobCore(t, 30*time.Millisecond)
	c.heavy = newHeavyGate(1)
	release := make(chan struct{})
	var runs atomic.Int32
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runs.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := c.longJobs(map[string]string{"POST /api/v1/rules/mine": "rules.mine", "POST /pack": "pack.build"}, slow)

	mine := operatorPost(h, "/api/v1/rules/mine", "usr_a")
	if mine.code != 202 || mine.Status != "running" || mine.Kind != "rules.mine" {
		t.Fatalf("first mining: %+v", mine)
	}
	again := operatorPost(h, "/api/v1/rules/mine", "usr_b")
	if again.code != 202 || again.ID != mine.ID {
		t.Fatalf("second mining did not join: %+v (first %s)", again, mine.ID)
	}
	pack := operatorPost(h, "/pack", "usr_b")
	if pack.code != 202 || pack.Status != "queued" {
		t.Fatalf("pack next to mining: %+v", pack)
	}
	// Without the operator role there is nothing to join: the request goes
	// its own way (its handler refuses it once admitted).
	aud := serve(h, newPost("/api/v1/rules/mine", `{}`, &auth.Principal{UserID: "usr_r", Roles: []auth.Role{auth.RoleAuditor}}))
	var audJob jobAnswer
	_ = json.Unmarshal(aud.Body.Bytes(), &audJob)
	if audJob.ID == mine.ID || audJob.Status != "queued" {
		t.Fatalf("auditor request: %+v", audJob)
	}
	list := c.jobs.list(func(*Job) bool { return true })
	if len(list) != 3 {
		t.Fatalf("jobs: %d", len(list))
	}
	if j := c.jobs.get(mine.ID); !j.visibleTo("usr_b") || !j.visibleTo("usr_a") || j.visibleTo("usr_c") {
		t.Fatalf("viewers %v owner %s", j.viewers, j.owner)
	}
	close(release)
	if got := waitDone(t, c, mine.ID); got.Status != "done" {
		t.Fatalf("mining: %+v", got)
	}
	if got := waitDone(t, c, pack.ID); got.Status != "done" {
		t.Fatalf("pack: %+v", got)
	}
	waitDone(t, c, audJob.ID)
	if n := runs.Load(); n != 3 {
		t.Fatalf("%d runs, want 3 (one mining for two users, the pack, the auditor's)", n)
	}
	if j, joined := c.jobs.startOrJoin("rules.mine", "usr_x", true); joined {
		t.Fatalf("joined a finished job %s", j.ID)
	}
}

func newPost(path, body string, p *auth.Principal) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	return req.WithContext(auth.WithPrincipal(req.Context(), p))
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The answer kept for a job is bounded.
func TestLongJobResultTooLarge(t *testing.T) {
	c := longJobCore(t, 20*time.Millisecond)
	big := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		chunk := []byte(strings.Repeat("x", 1<<20))
		for range maxLongJobResult/len(chunk) + 2 {
			_, _ = w.Write(chunk)
		}
	})
	h := c.longJobs(map[string]string{"POST /x": "x.run"}, big)
	j := operatorPost(h, "/x", "usr_a")
	if got := waitDone(t, c, j.ID); got.Status != "failed" || got.Error != "result_too_large" {
		t.Fatalf("job: %+v", got)
	}
	// Answered within the wait: an error instead of a truncated body.
	c.syncWaitOverride = time.Second
	rec := serve(h, newPost("/x", `{}`, &auth.Principal{UserID: "usr_a"}))
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "result_too_large") {
		t.Fatalf("sync: %d %.100s", rec.Code, rec.Body)
	}
}

// A quick answer that is not a job leaves no job behind; a handler that
// writes the request's job (mining) answers that same job.
func TestLongJobOneJobPerRequest(t *testing.T) {
	c := longJobCore(t, time.Second)
	plain := c.longJobs(map[string]string{"POST /s": "s.run"}, jobHandler(0, 201, `{"snapshot_id":"s-1"}`))
	if rec := serve(plain, newPost("/s", `{}`, &auth.Principal{UserID: "usr_a"})); rec.Code != 201 {
		t.Fatalf("%d", rec.Code)
	}
	if n := len(c.jobs.list(func(*Job) bool { return true })); n != 0 {
		t.Fatalf("%d jobs left by a quick plain answer", n)
	}
	own := c.longJobs(map[string]string{"POST /m": "rules.mine"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j := c.startJob(r.Context(), "rules.mine", "usr_a")
		c.jobs.done(j, map[string]int{"events": 3})
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(c.jobs.get(j.ID))
	}))
	j := operatorPost(own, "/m", "usr_a")
	list := c.jobs.list(func(*Job) bool { return true })
	if len(list) != 1 || list[0].ID != j.ID || j.Status != "done" {
		t.Fatalf("answer %+v, jobs %d", j, len(list))
	}
}
