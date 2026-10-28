package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Long operations of the admin API (mining, archetypes, worlds, packs,
// exports, contract snapshots) answer 202 with a Job. On a small
// installation they finish in a second and the answer carries the final
// status, as before. With real volumes they take minutes (test/perf:
// mining 10M events), longer than admin.write_timeout: the connection was
// cut and the user saw an error while the work went on. longJobs runs such
// a request in the background and waits for it at most syncWait; when it is
// not done by then the answer is the Job, "queued" or "running", and the
// result arrives at GET /api/v1/jobs/{job_id} (the UI follows it).
//
// Memory (OOM on a 4 GiB test core): every long operation is a heavy job and
// waits for a slot of the heavy gate (heavy.go) before it runs; a mining
// request while a mining job is queued or running joins that job instead
// of queueing a second run of the same window; the answer kept in the job
// is bounded (maxLongJobResult).

// syncWait is how long a long request is waited for before answering with
// a running Job: well under the write timeout of the admin listener.
func (c *Core) syncWait() time.Duration {
	d := 20 * time.Second
	if wt := c.cfg.Admin.HTTP.WriteTimeout; wt > 0 && wt*2/3 < d {
		d = wt * 2 / 3
	}
	if c.syncWaitOverride > 0 {
		d = c.syncWaitOverride
	}
	return d
}

// maxLongJobBody bounds the request body read ahead of a long request.
const maxLongJobBody = 1 << 20

// maxLongJobResult bounds the answer of a long request buffered in memory
// (and kept in its job for retention.exports): the answers are summaries
// (a pack id, counts, a snapshot); a larger one fails with result_too_large
// instead of holding megabytes per job.
const maxLongJobResult = 16 << 20

const resultTooLarge = `{"code":"result_too_large","message":"the answer of the operation is too large"}`

// joinKinds are the long jobs a request joins while one is queued or
// running, for the roles that may start one: a second mining of the same
// window only doubles the peak of memory (the lab OOM).
var joinKinds = map[string][]auth.Role{"rules.mine": {auth.RoleOperator}}

type longJobKey struct{}

// longJobFrom returns the Job of the long request ctx belongs to, if any.
func longJobFrom(ctx context.Context) *Job {
	j, _ := ctx.Value(longJobKey{}).(*Job)
	return j
}

// startJob starts a job of kind for owner; inside a long request it is the
// request's own job (one job per request, whatever answers first), marked
// as written by the handler.
func (c *Core) startJob(ctx context.Context, kind, owner string) *Job {
	if j := longJobFrom(ctx); j != nil {
		c.jobs.claim(j, kind)
		return j
	}
	return c.jobs.start(kind, owner)
}

// longJobs wraps h: the requests whose "METHOD path" is a key of kinds run
// as long jobs of that kind; every other request goes straight to h. A key
// segment "{name}" matches any one path segment
// ("POST /api/v1/contracts/{service}/snapshots").
func (c *Core) longJobs(kinds map[string]string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind, ok := longJobKind(kinds, r.Method+" "+r.URL.Path)
		if !ok {
			h.ServeHTTP(w, r)
			return
		}
		p, _ := auth.PrincipalFrom(r.Context())
		body, err := io.ReadAll(io.LimitReader(r.Body, maxLongJobBody+1))
		if err != nil || len(body) > maxLongJobBody {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return
		}
		owner := ""
		if p != nil {
			owner = p.UserID
		}
		roles, joinable := joinKinds[kind]
		j, joined := c.jobs.startOrJoin(kind, owner, joinable && p != nil && p.HasAny(roles...))
		if joined {
			c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "rule.mine_request", Target: audit.Target{Type: "rules"},
				Outcome: audit.Success, RequestID: httpx.RequestID(r.Context()), Details: map[string]string{"job": j.ID, "joined": "true"}})
			httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
			return
		}
		// The work outlives the request: its context keeps the values
		// (principal, request id) but not the cancellation.
		r2 := r.Clone(context.WithValue(context.WithoutCancel(r.Context()), longJobKey{}, j))
		r2.Body = io.NopCloser(bytes.NewReader(body))
		rec := &recordedResponse{header: http.Header{}, limit: maxLongJobResult}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if v := recover(); v != nil {
					c.log.Error("long job panicked", "kind", kind)
					rec.reset(http.StatusInternalServerError, `{"code":"internal","message":"internal error"}`)
				}
			}()
			release, err := c.heavy.acquire(c.jobs.context(), func() { c.jobs.setStatus(j, "queued") })
			if err != nil {
				rec.reset(http.StatusServiceUnavailable, `{"code":"shutting_down","message":"tt-core is stopping"}`)
				return
			}
			defer release()
			c.jobs.setStatus(j, "running")
			h.ServeHTTP(rec, r2)
		}()
		t := time.NewTimer(c.syncWait())
		defer t.Stop()
		select {
		case <-done:
			if c.jobs.claimed(j) {
				c.finishLongJob(j, rec)
			} else {
				// The handler's own answer is final: no job to keep.
				c.jobs.remove(j.ID)
				if rec.overflow {
					c.log.Error("long job answer too large", "kind", kind, "limit_mb", rec.limit>>20)
					rec.reset(http.StatusInternalServerError, resultTooLarge)
				}
			}
			rec.copyTo(w)
			return
		case <-t.C:
		}
		go func() {
			<-done
			c.finishLongJob(j, rec)
		}()
		httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	})
}

// longJobKind finds the kind of "METHOD path": an exact key, or a key whose
// "{name}" segments match any one non-empty segment of the path.
func longJobKind(kinds map[string]string, key string) (string, bool) {
	if k, ok := kinds[key]; ok {
		return k, true
	}
	ks := strings.Split(key, "/")
	for pat, kind := range kinds {
		ps := strings.Split(pat, "/")
		if len(ps) != len(ks) || !strings.Contains(pat, "{") {
			continue
		}
		match := true
		for i := range ps {
			if strings.HasPrefix(ps[i], "{") && strings.HasSuffix(ps[i], "}") {
				if ks[i] == "" {
					match = false
					break
				}
				continue
			}
			if ps[i] != ks[i] {
				match = false
				break
			}
		}
		if match {
			return kind, true
		}
	}
	return "", false
}

// finishLongJob stores the outcome of the background request in the job:
// its Job answer (status and result), or the error code of a failure. A
// job the handler finished itself (startJob) keeps what the handler wrote.
func (c *Core) finishLongJob(j *Job, rec *recordedResponse) {
	if rec.overflow {
		c.log.Error("long job answer too large", "kind", j.Kind, "limit_mb", rec.limit>>20)
		rec.reset(http.StatusInternalServerError, resultTooLarge)
		c.jobs.fail(j, "result_too_large")
		return
	}
	if c.jobs.claimed(j) {
		if st := c.jobs.status(j); st == "done" || st == "failed" {
			return
		}
	}
	var out struct {
		Status  string          `json:"status"`
		Result  json.RawMessage `json:"result"`
		Error   string          `json:"error"`
		Code    string          `json:"code"`
		Details json.RawMessage `json:"details"`
	}
	_ = json.Unmarshal(rec.body.Bytes(), &out)
	switch {
	case rec.status >= 200 && rec.status < 300 && (out.Status == "" || out.Status == "done"):
		var res any = json.RawMessage(bytes.Clone(rec.body.Bytes()))
		if len(out.Result) > 0 {
			res = out.Result
		}
		c.jobs.done(j, res)
	case out.Code != "":
		var details json.RawMessage
		if len(out.Details) > 0 && out.Details[0] == '[' {
			details = bytes.Clone(out.Details)
		}
		c.jobs.failWith(j, out.Code, details)
	case out.Error != "":
		c.jobs.fail(j, out.Error)
	default:
		c.jobs.fail(j, "failed")
	}
}

// recordedResponse buffers the answer of a long request, up to limit bytes
// (0: no limit); beyond, overflow is set and the body is dropped.
type recordedResponse struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	limit    int
	overflow bool
}

func (r *recordedResponse) Header() http.Header { return r.header }

func (r *recordedResponse) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recordedResponse) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.overflow {
		return len(b), nil
	}
	if r.limit > 0 && r.body.Len()+len(b) > r.limit {
		r.overflow = true
		r.body = bytes.Buffer{}
		return len(b), nil
	}
	return r.body.Write(b)
}

func (r *recordedResponse) reset(code int, body string) {
	r.header = http.Header{"Content-Type": {"application/json"}}
	r.status = code
	r.body = bytes.Buffer{}
	r.body.WriteString(body)
	r.overflow = false
}

func (r *recordedResponse) copyTo(w http.ResponseWriter) {
	for k, v := range r.header {
		w.Header()[k] = v
	}
	if r.status == 0 {
		r.status = http.StatusOK
	}
	w.WriteHeader(r.status)
	_, _ = w.Write(r.body.Bytes())
}
