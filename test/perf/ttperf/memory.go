package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The memory phase (-only memory) replays what got tt-core OOM-killed on the
// lab core (4 GiB, about 2 M events): one mining run, a second
// POST /rules/mine while the first runs, mining next to a contract snapshot
// and a pack build. It measures the peak of the Go heap, of the memory the
// Go runtime holds and of the RSS of the process (SQLite allocates outside
// the Go heap), what the jobs keep after the run and the size of their
// results, and writes heap profiles (pprof) at the peak of each scenario.

// memSampler records the peaks of the Go heap, the Go runtime and the RSS.
type memSampler struct {
	stop, done            chan struct{}
	heap, goMem, rs, live atomic.Uint64
	prof                  string // heap profile written at each new heap peak
	profAt                atomic.Uint64
}

var memSamples = []metrics.Sample{
	{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/memory/classes/heap/unused:bytes"},
	{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"},
	{Name: "/gc/heap/live:bytes"},
}

// memNow returns the Go heap (objects, garbage included, and unused
// spans), the memory the Go runtime holds from the system, and the live
// heap marked by the last collection.
func memNow() (heap, goMem, live uint64) {
	s := append([]metrics.Sample(nil), memSamples...)
	metrics.Read(s)
	v := func(i int) uint64 {
		if s[i].Value.Kind() == metrics.KindUint64 {
			return s[i].Value.Uint64()
		}
		return 0
	}
	return v(0) + v(1), v(2) - v(3), v(4)
}

// rssNow is the resident set of this process in bytes (ps: portable across
// macOS and Linux; 0 when unavailable).
func rssNow() uint64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return 0
	}
	kb, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return kb << 10
}

func startMemSampler(prof string) *memSampler {
	s := &memSampler{stop: make(chan struct{}), done: make(chan struct{}), prof: prof}
	go func() {
		defer close(s.done)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		n := 0
		for {
			h, g, lv := memNow()
			if h > s.heap.Load() {
				s.heap.Store(h)
			}
			if lv > s.live.Load() {
				s.live.Store(lv)
			}
			if g > s.goMem.Load() {
				s.goMem.Store(g)
			}
			if n%3 == 0 { // ps is a process: every 300 ms
				if r := rssNow(); r > s.rs.Load() {
					s.rs.Store(r)
				}
			}
			// A profile at every new live heap 5 % above the last one: the
			// last one shows the largest live data of the scenario.
			if s.prof != "" && lv > s.profAt.Load()*21/20 {
				s.profAt.Store(lv)
				if f, err := os.Create(s.prof); err == nil {
					_ = pprof.Lookup("heap").WriteTo(f, 0)
					f.Close()
				}
			}
			n++
			select {
			case <-s.stop:
				return
			case <-t.C:
			}
		}
	}()
	return s
}

func (s *memSampler) end() (heap, goMem, rss, live float64) {
	close(s.stop)
	<-s.done
	return float64(s.heap.Load()) / (1 << 20), float64(s.goMem.Load()) / (1 << 20), float64(s.rs.Load()) / (1 << 20), float64(s.live.Load()) / (1 << 20)
}

// memJob runs fn as a memory scenario: the detail gets the peaks, the heap
// in use before and after (a forced collection: what the jobs keep).
func (h *harness) memJob(name string, fn func() (map[string]any, error)) {
	runtime.GC()
	debug.FreeOSMemory()
	before, _, _ := memNow()
	rssBefore := rssNow()
	prof := filepath.Join(h.dir, "heap-"+name+".pprof")
	s := startMemSampler(prof)
	t0 := time.Now()
	det, err := fn()
	secs := time.Since(t0).Seconds()
	heap, goMem, rss, live := s.end()
	runtime.GC()
	after, _, _ := memNow()
	if det == nil {
		det = map[string]any{}
	}
	det["heap_before_mb"] = float64(before) / (1 << 20)
	det["heap_retained_mb"] = (float64(after) - float64(before)) / (1 << 20)
	det["go_peak_mb"] = goMem
	det["live_peak_mb"] = live
	det["rss_before_mb"] = float64(rssBefore) / (1 << 20)
	det["rss_peak_mb"] = rss
	det["heap_profile"] = filepath.Base(prof)
	j := &JobStats{Name: name, Seconds: secs, HeapPeakMB: heap, Detail: det, OK: err == nil}
	if err != nil {
		j.Error = err.Error()
	}
	fmt.Printf("    job %-32s %8.2f s  heap %6.0f MB  live %6.0f MB  go %6.0f MB  rss %6.0f MB  retained %+5.0f MB %v %v\n",
		name, secs, heap, live, goMem, rss, det["heap_retained_mb"], det["events"], errOr(err, ""))
	h.rep.Jobs = append(h.rep.Jobs, j)
}

// postNoWait starts a long operation and returns its Job answer at once.
func (h *harness) postNoWait(path string, body any) (*jobResp, error) {
	code, b, _, err := h.admin.do("POST", path, body)
	if err != nil {
		return nil, err
	}
	if code != 202 && code != 200 && code != 201 {
		return nil, fmt.Errorf("POST %s = %d: %.300s", path, code, b)
	}
	var j jobResp
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if j.Status == "" { // a final answer that is not a Job (a snapshot)
		j.Status = "done"
	}
	return &j, nil
}

// waitAny polls a job until it is done or failed ("queued" and "running"
// both mean not yet).
func (h *harness) waitAny(j *jobResp, limit time.Duration) error {
	for deadline := time.Now().Add(limit); j.Status == "running" || j.Status == "queued"; {
		if time.Now().After(deadline) {
			return fmt.Errorf("job %s still %s", j.JobID, j.Status)
		}
		time.Sleep(200 * time.Millisecond)
		if err := h.admin.json(200, "GET", "/api/v1/jobs/"+j.JobID, nil, j); err != nil {
			return err
		}
	}
	if j.Status != "done" {
		return fmt.Errorf("job %s: %v", j.Status, j.Error)
	}
	return nil
}

// jobBytes is the size of the job as GET /api/v1/jobs/{id} returns it.
func (h *harness) jobBytes(id string) int {
	if id == "" {
		return 0
	}
	_, b, _, _ := h.admin.do("GET", "/api/v1/jobs/"+id, nil)
	return len(b)
}

func (h *harness) benchMemory() {
	mine := func() (*jobResp, error) { return h.postNoWait("/api/v1/rules/mine", nil) }
	on := func(s string) bool { return len(h.memScenarios) == 0 || h.memScenarios[s] }
	if on("one") {
		h.memOne(mine)
	}
	if on("two") {
		h.memTwo(mine)
	}
	if on("mixed") {
		h.memMixed()
	}
}

func (h *harness) memOne(mine func() (*jobResp, error)) {
	h.memJob("mem.mine.one", func() (map[string]any, error) {
		j, err := mine()
		if err != nil {
			return nil, err
		}
		if err := h.waitAny(j, 30*time.Minute); err != nil {
			return nil, err
		}
		return map[string]any{"events": j.Result["events"], "job_bytes": h.jobBytes(j.JobID),
			"rule_diagnostics": count(j.Result["rule_diagnostics"]), "entities": count(j.Result["entities"])}, nil
	})
}

// memTwo is the incident: a second POST 1 s after the first (the first
// client had left), both followed to the end.
func (h *harness) memTwo(mine func() (*jobResp, error)) {
	h.memJob("mem.mine.two", func() (map[string]any, error) {
		a, err := mine()
		if err != nil {
			return nil, err
		}
		time.Sleep(time.Second)
		b, err := mine()
		if err != nil {
			return nil, err
		}
		if err := h.waitAny(a, 30*time.Minute); err != nil {
			return nil, err
		}
		if err := h.waitAny(b, 30*time.Minute); err != nil {
			return nil, err
		}
		runs := 2
		if a.JobID == b.JobID {
			runs = 1 // the second request joined the first job
		}
		return map[string]any{"events": a.Result["events"], "runs": runs}, nil
	})
}

// memMixed runs mining, a contract snapshot and a pack build at once.
func (h *harness) memMixed() {
	h.memJob("mem.mine.snapshot.pack", func() (map[string]any, error) {
		var wg sync.WaitGroup
		errs := make([]error, 3)
		run := func(i int, path string, body any) {
			defer wg.Done()
			j, err := h.postNoWait(path, body)
			if err == nil {
				err = h.waitAny(j, 30*time.Minute)
			}
			errs[i] = err
		}
		wg.Add(3)
		go run(0, "/api/v1/rules/mine", nil)
		go run(1, "/api/v1/contracts/"+url.PathEscape(h.ids["service"])+"/snapshots", nil)
		go run(2, "/api/v1/packs", map[string]any{"world_id": h.ids["world"]})
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
}
