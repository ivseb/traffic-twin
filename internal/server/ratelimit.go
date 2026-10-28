package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// rateLimiter is a per-client token bucket. IPv6 clients are keyed by their
// /64 prefix so address rotation inside one allocation does not help.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	max     int
	now     func() time.Time
	swept   time.Time // last sweep (at most one per sweepEvery when full)
}

// sweepEvery bounds the full sweeps of a full table: a flood of new
// clients would otherwise cost a walk of maxTrackedClients buckets each.
const sweepEvery = time.Second

type bucket struct {
	tokens float64
	last   time.Time
}

// maxTrackedClients bounds memory; when full and nothing is stale the
// limiter refuses new clients (fail closed on the auth endpoints).
const maxTrackedClients = 100000

func newRateLimiter(perMinute, burst int) *rateLimiter {
	return &rateLimiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		buckets: map[string]*bucket{},
		max:     maxTrackedClients,
		now:     time.Now,
	}
}

func clientKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if p.To4() != nil {
		return p.String()
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// allow consumes a token; when refused it returns the wait until the next.
func (l *rateLimiter) allow(ip string) (bool, time.Duration) {
	key := clientKey(ip)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			if now.Sub(l.swept) >= sweepEvery {
				l.swept = now
				l.sweep(now)
			}
			if len(l.buckets) >= l.max {
				return false, time.Minute
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// sweep drops buckets that have refilled completely (idle clients).
func (l *rateLimiter) sweep(now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) >= full {
			delete(l.buckets, k)
		}
	}
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := l.allow(httpx.ClientIP(r))
		if !ok {
			secs := int(math.Ceil(wait.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}
