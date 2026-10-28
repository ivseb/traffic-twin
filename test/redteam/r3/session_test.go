package r3_rt

import (
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/config"
)

// Session idle and absolute timeouts. The composed core does not pass its
// clock to the auth service (core.New -> authOptions has no Now), so this
// test runs on real time with the shortest timeouts the configuration
// allows: idle 2 min, absolute 4 min (about 4 minutes; skipped with -short).
func TestRT3_Session_Holds_Timeouts(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time session test")
	}
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}, "rita": {"rule-reviewer"}},
		cfg: func(c *config.Config) {
			c.Auth.Session.IdleTimeout, c.Auth.Session.AbsoluteTimeout = 2*time.Minute, 4*time.Minute
		}})
	olga, rita := e.u(t, "olga"), e.u(t, "rita")
	start := time.Now()
	at := func(d time.Duration) { time.Sleep(time.Until(start.Add(d))) }

	// rita stays active (a request every 61 s, so last_seen is touched);
	// olga stays idle.
	at(61 * time.Second)
	rita.must(200, "GET", "/api/v1/auth/me", nil)
	at(122 * time.Second)
	rita.must(200, "GET", "/api/v1/auth/me", nil)
	at(125 * time.Second)
	if code, _ := olga.req("GET", "/api/v1/auth/me", nil); code != 401 {
		t.Fatalf("session idle for 2+ minutes accepted: %d", code)
	}
	at(183 * time.Second)
	rita.must(200, "GET", "/api/v1/auth/me", nil)
	at(4*time.Minute + 3*time.Second)
	if code, _ := rita.req("GET", "/api/v1/auth/me", nil); code != 401 {
		t.Fatalf("active session beyond the absolute timeout accepted: %d", code)
	}
	// An expired session does not come back, and a new login is a new id.
	if code, _ := olga.req("GET", "/api/v1/fleet/groups", nil); code != 401 {
		t.Fatalf("expired session revived: %d", code)
	}
	again := e.login("rita")
	if again.cookie == rita.cookie {
		t.Fatal("login reused the expired session id")
	}
	var me struct {
		ExpiresAt     time.Time `json:"expires_at"`
		IdleExpiresAt time.Time `json:"idle_expires_at"`
	}
	again.t = t
	again.json(200, "GET", "/api/v1/auth/me", nil, &me)
	if me.IdleExpiresAt.After(me.ExpiresAt) {
		t.Fatalf("idle expiry %s after absolute %s", me.IdleExpiresAt, me.ExpiresAt)
	}
}
