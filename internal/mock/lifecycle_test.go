package mock

import (
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

func TestIdleSessionsAreEvicted(t *testing.T) {
	e := newEnv(t, func(_ *packtest.Spec, c *Config) { c.SessionIdleTTL = time.Hour; c.MaxSessions = 3 })
	a := e.newSession(nil)
	b := e.newSession(nil)
	// Session a was last used two hours ago, b is in use.
	e.m.lookup(a).lastUsed.Store(e.m.cfg.Wall().Add(-2 * time.Hour).UnixNano())
	e.order(b)
	if n := e.m.EvictIdle(); n != 1 {
		t.Fatalf("evicted %d", n)
	}
	if e.m.lookup(a) != nil || e.m.lookup(b) == nil || e.m.lookup(defaultSession) == nil {
		t.Fatal("wrong session evicted")
	}
	// At the limit an idle session makes room for a new one.
	e.m.lookup(b).lastUsed.Store(0)
	e.newSession(nil)
	e.newSession(nil)
}

func TestJournalIsBoundedInBytes(t *testing.T) {
	e := newEnv(t, func(_ *packtest.Spec, c *Config) { c.JournalMaxBytes = 4096 })
	sid := e.newSession(nil)
	for i := 0; i < 40; i++ {
		e.order(sid)
	}
	s := e.m.lookup(sid)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.journal) == 0 || len(s.journal) >= 40 || s.jbytes > 4096+s.jsizes[len(s.jsizes)-1] {
		t.Fatalf("journal: %d entries, %d bytes", len(s.journal), s.jbytes)
	}
	var sum int64
	for _, n := range s.jsizes {
		sum += n
	}
	if sum != s.jbytes || len(s.jsizes) != len(s.journal) || s.journal[len(s.journal)-1].Seq != 40 {
		t.Fatalf("bookkeeping: %d vs %d", sum, s.jbytes)
	}
}
