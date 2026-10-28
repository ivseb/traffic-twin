package fleet

import (
	"math"
	"net"
	"sync"
	"time"
)

// RateLimit is a token bucket: PerMinute tokens refill per minute, Burst
// is the bucket size. A zero value takes the default; PerMinute < 0
// disables the limit.
type RateLimit struct {
	PerMinute int
	Burst     int
}

// Enrollment rate limit defaults: generous for replicated deployments
// (a group token enrolling every pod of a rollout), tight enough to make
// token guessing and enrollment floods visible and slow.
var (
	DefaultEnrollIPLimit    = RateLimit{PerMinute: 60, Burst: 30}
	DefaultEnrollTokenLimit = RateLimit{PerMinute: 120, Burst: 60}
)

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	off     bool
	buckets map[string]*bucket
	sweep   time.Time
}

func newLimiter(l RateLimit, def RateLimit) *limiter {
	if l.PerMinute == 0 {
		l = def
	}
	if l.Burst <= 0 {
		l.Burst = def.Burst
	}
	return &limiter{rate: float64(l.PerMinute) / 60, burst: float64(l.Burst), off: l.PerMinute < 0, buckets: map[string]*bucket{}}
}

// allow takes one token for key; when refused it returns how long to wait.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l.off {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.sweep) > time.Minute {
		// Forget buckets that are full again.
		full := time.Duration(l.burst / l.rate * float64(time.Second))
		for k, b := range l.buckets {
			if now.Sub(b.last) > full {
				delete(l.buckets, k)
			}
		}
		l.sweep = now
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// ipKey groups IPv6 clients by /64 (one host usually owns the whole /64).
func ipKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if p.To4() != nil {
		return p.String()
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
