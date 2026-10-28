package auth

import (
	"strings"
	"sync"
	"time"
)

// AccountLimit bounds failed local logins per username, in addition to the
// per-client limit of the server (an attacker rotating client addresses
// still gets a handful of guesses per account). Burst failures are allowed,
// then one more every Refill. While an account is limited every attempt,
// also with the right password, is answered 429 with Retry-After; a
// successful login clears the account's counter. Unknown usernames are
// limited the same way (no enumeration through the limiter).
type AccountLimit struct {
	Burst  int
	Refill time.Duration
	// MaxAccounts bounds the memory of the limiter (default 10000).
	MaxAccounts int
}

// DefaultAccountLimit: 10 failures, then one every 2 minutes.
var DefaultAccountLimit = AccountLimit{Burst: 10, Refill: 2 * time.Minute, MaxAccounts: 10000}

type accountBucket struct {
	tokens float64
	at     time.Time
}

type accountLimiter struct {
	cfg AccountLimit
	mu  sync.Mutex
	m   map[string]*accountBucket
}

func newAccountLimiter(cfg AccountLimit) *accountLimiter {
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultAccountLimit.Burst
	}
	if cfg.Refill <= 0 {
		cfg.Refill = DefaultAccountLimit.Refill
	}
	if cfg.MaxAccounts <= 0 {
		cfg.MaxAccounts = DefaultAccountLimit.MaxAccounts
	}
	return &accountLimiter{cfg: cfg, m: map[string]*accountBucket{}}
}

func accountKey(username string) string {
	u := strings.ToLower(strings.TrimSpace(username))
	if len(u) > 128 {
		u = u[:128]
	}
	return u
}

// refill brings b to now; caller holds mu.
func (l *accountLimiter) refill(b *accountBucket, now time.Time) {
	if el := now.Sub(b.at); el > 0 {
		b.tokens = min(float64(l.cfg.Burst), b.tokens+float64(el)/float64(l.cfg.Refill))
		b.at = now
	}
}

// allow reports whether an attempt for username may proceed; when not, the
// wait until the next one.
func (l *accountLimiter) allow(username string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[accountKey(username)]
	if b == nil {
		return true, 0
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) * float64(l.cfg.Refill))
}

// fail consumes one token of username.
func (l *accountLimiter) fail(username string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := accountKey(username)
	b := l.m[k]
	if b == nil {
		if len(l.m) >= l.cfg.MaxAccounts {
			l.evict(now)
		}
		b = &accountBucket{tokens: float64(l.cfg.Burst), at: now}
		l.m[k] = b
	}
	l.refill(b, now)
	b.tokens = max(0, b.tokens-1)
}

// success clears username's counter.
func (l *accountLimiter) success(username string) {
	l.mu.Lock()
	delete(l.m, accountKey(username))
	l.mu.Unlock()
}

// evict drops refilled buckets, then (still full) the most refilled one;
// caller holds mu.
func (l *accountLimiter) evict(now time.Time) {
	var best string
	bestTokens := -1.0
	for k, b := range l.m {
		l.refill(b, now)
		if b.tokens >= float64(l.cfg.Burst) {
			delete(l.m, k)
			continue
		}
		if b.tokens > bestTokens {
			best, bestTokens = k, b.tokens
		}
	}
	if len(l.m) >= l.cfg.MaxAccounts && best != "" {
		delete(l.m, best)
	}
}
