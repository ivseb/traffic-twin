package auth

import (
	"testing"
	"time"
)

func TestTouchIntervalFollowsIdleTimeout(t *testing.T) {
	for _, c := range []struct{ idle, want time.Duration }{
		{30 * time.Minute, time.Minute},
		{4 * time.Minute, time.Minute},
		{2 * time.Minute, 30 * time.Second},
		{time.Minute, 15 * time.Second},
		{0, time.Minute},
	} {
		s := &Service{opts: Options{IdleTimeout: c.idle}}
		if got := s.touchInterval(); got != c.want {
			t.Errorf("idle %s: touch interval %s, want %s", c.idle, got, c.want)
		}
	}
}
