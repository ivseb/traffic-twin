package mock

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// A long advance over a busy session lists at most maxAppliedShown effects
// and reports the total: the answer stays bounded whatever the advance.
func TestAdvanceListsBoundedApplied(t *testing.T) {
	e := newEnv(t, exact())
	sid := e.newSession(map[string]any{"seed": 1})
	for i := 0; i < 600; i++ {
		e.order(sid)
	}
	r := e.ctl("POST", "/sessions/"+sid+"/clock/advance", map[string]any{"by": "30d"})
	if r.status != 200 {
		t.Fatalf("advance: %d %s", r.status, r.body)
	}
	j := r.json()
	applied := j["applied"].([]any)
	total, _ := strconv.Atoi(fmt.Sprint(j["applied_total"]))
	if len(applied) != maxAppliedShown || j["applied_truncated"] != true || total <= maxAppliedShown {
		t.Fatalf("applied %d, total %v, truncated %v", len(applied), j["applied_total"], j["applied_truncated"])
	}
	// A short advance still lists everything, without the extra fields.
	sid2 := e.newSession(map[string]any{"seed": 2})
	e.order(sid2)
	r = e.ctl("POST", "/sessions/"+sid2+"/clock/advance", map[string]any{"by": "30d"})
	if _, ok := r.json()["applied_total"]; ok || r.status != 200 {
		t.Fatalf("short advance: %d %s", r.status, r.body)
	}
}

// The journal keeps the newest JournalMax entries; trimming is O(1) per
// request (no copy of the whole journal once it is full).
func TestJournalTrimKeepsNewest(t *testing.T) {
	e := newEnv(t, func(_ *packtest.Spec, c *Config) { c.JournalMax = 50 })
	sid := e.newSession(map[string]any{"seed": 1})
	for i := 0; i < 180; i++ {
		e.order(sid)
	}
	s := e.m.lookup(sid)
	s.mu.Lock()
	n, first, last := len(s.journal), s.journal[0].Seq, s.journal[len(s.journal)-1].Seq
	s.mu.Unlock()
	if n != 50 || last-first != 49 || last < 180 {
		t.Fatalf("journal: %d entries, seq %d..%d", n, first, last)
	}
}
