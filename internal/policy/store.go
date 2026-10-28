package policy

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// State is the policy part of a source heartbeat state
// (api/fleet-api.v1.openapi.yaml, Heartbeat.state).
type State string

// Policy states.
const (
	StateCapturing      State = "capturing"
	StateNoPolicy       State = "no_policy"
	StatePolicyRejected State = "policy_rejected"
	StateExpiredPolicy  State = "expired_policy"
	StateKilled         State = "killed"
)

// Acceptance errors (policy.md 4 points 3-5).
var (
	ErrStale    = errors.New("policy: issued_seq not newer than the last accepted or below min_issued_seq")
	ErrGroup    = errors.New("policy: source group not in targets.groups")
	ErrNotAfter = errors.New("policy: not_after has passed")
)

// Accept applies the source acceptance rules of policy.md 4 to an envelope:
// Verify, then group membership, now < not_after and issued_seq strictly
// greater than lastSeq and not below minSeq.
func Accept(envelope []byte, ring *KeyRing, group string, now time.Time, lastSeq, minSeq int64) (*Verified, error) {
	v, err := Verify(envelope, ring)
	if err != nil {
		return nil, err
	}
	if err := CheckAcceptance(v.Policy, group, now, lastSeq, minSeq); err != nil {
		return nil, err
	}
	return v, nil
}

// CheckAcceptance applies policy.md 4 conditions 3-5 to a verified body.
func CheckAcceptance(p *Policy, group string, now time.Time, lastSeq, minSeq int64) error {
	if !p.HasGroup(group) {
		return ErrGroup
	}
	if !now.Before(p.NotAfter) {
		return ErrNotAfter
	}
	if p.IssuedSeq <= lastSeq || p.IssuedSeq < minSeq {
		return ErrStale
	}
	return nil
}

// Status is the outcome of Store.Current.
type Status struct {
	// Policy is the policy to sanitize with; nil when Capture is false.
	Policy *Verified
	State  State
	// Capture is true only when a valid, non-expired policy is in use and
	// the kill switch is off.
	Capture bool
}

// Store is the source-side holder of the active policy. It implements the
// fail-closed table of policy.md 4: no accepted policy ⇒ no capture;
// rejected policies keep the previous valid one; the cached policy stops
// being used policy_max_age after tt-core was last reached and in any case
// at not_after; the kill switch is persistent. It is safe for concurrent use.
type Store struct {
	mu            sync.Mutex
	ring          *KeyRing
	group         string
	maxAge        time.Duration
	cur           *Verified
	lastSeq       int64
	minSeq        int64
	lastConfirmed time.Time
	rejected      bool
	killed        bool
	heartbeatSeen bool
}

// NewStore returns an empty store for a source of the given group. maxAge
// <= 0 means DefaultMaxAge.
func NewStore(ring *KeyRing, group string, maxAge time.Duration) *Store {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	return &Store{ring: ring, group: group, maxAge: maxAge}
}

// Heartbeat records a heartbeat response: kill switch state and
// min_issued_seq. Capture never starts before the first heartbeat.
func (s *Store) Heartbeat(kill bool, minIssuedSeq int64, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeatSeen = true
	s.killed = kill
	if minIssuedSeq > s.minSeq {
		s.minSeq = minIssuedSeq
	}
	if s.cur != nil && s.cur.Policy.IssuedSeq < s.minSeq {
		s.cur = nil // the current policy has been superseded for good
	}
	if s.cur != nil && now.After(s.lastConfirmed) {
		s.lastConfirmed = now
	}
}

// Offer verifies a policy fetched from tt-core at now and makes it current
// if it is accepted. A rejected policy never replaces the current one.
// Offering the exact current policy again confirms that tt-core is reachable.
func (s *Store) Offer(envelope []byte, now time.Time) error {
	return s.offer(envelope, now, now)
}

func (s *Store) offer(envelope []byte, confirmedAt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil && string(envelope) == string(s.cur.Envelope) {
		if confirmedAt.After(s.lastConfirmed) {
			s.lastConfirmed = confirmedAt
		}
		return nil
	}
	v, err := Accept(envelope, s.ring, s.group, now, s.lastSeq, s.minSeq)
	if err != nil {
		s.rejected = true
		return err
	}
	s.cur = v
	s.lastSeq = v.Policy.IssuedSeq
	s.lastConfirmed = confirmedAt
	s.rejected = false
	return nil
}

// Confirm records that tt-core was reached at now and reported that the
// current policy is still the assigned one (for example HTTP 304).
func (s *Store) Confirm(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil && now.After(s.lastConfirmed) {
		s.lastConfirmed = now
	}
}

// Current returns the policy to use at now.
func (s *Store) Current(now time.Time) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.killed {
		return Status{State: StateKilled}
	}
	if s.cur == nil {
		if s.rejected {
			return Status{State: StatePolicyRejected}
		}
		return Status{State: StateNoPolicy}
	}
	if now.Sub(s.lastConfirmed) > s.maxAge || !now.Before(s.cur.Policy.NotAfter) {
		return Status{State: StateExpiredPolicy}
	}
	if !s.heartbeatSeen {
		return Status{State: StateNoPolicy}
	}
	st := StateCapturing
	if s.rejected {
		st = StatePolicyRejected
	}
	return Status{Policy: s.cur, State: st, Capture: true}
}

// Cache is what a source persists (policy.md 4): the signed envelope, the
// last accepted issued_seq, min_issued_seq, the kill switch and the time the
// policy was last confirmed by tt-core.
type Cache struct {
	Envelope      []byte
	LastIssuedSeq int64
	MinIssuedSeq  int64
	Killed        bool
	ConfirmedAt   time.Time
}

// Snapshot returns the state to persist.
func (s *Store) Snapshot() Cache {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Cache{LastIssuedSeq: s.lastSeq, MinIssuedSeq: s.minSeq, Killed: s.killed, ConfirmedAt: s.lastConfirmed}
	if s.cur != nil {
		c.Envelope = append([]byte(nil), s.cur.Envelope...)
	}
	return c
}

// Restore re-verifies a persisted cache at start-up. The kill switch and the
// sequence counters are restored even when the envelope is rejected.
func (s *Store) Restore(c Cache, now time.Time) error {
	s.mu.Lock()
	s.killed = c.Killed
	s.minSeq = c.MinIssuedSeq
	s.lastSeq = 0
	s.mu.Unlock()
	if len(c.Envelope) == 0 {
		s.mu.Lock()
		s.lastSeq = c.LastIssuedSeq
		s.mu.Unlock()
		return nil
	}
	confirmed := c.ConfirmedAt
	if confirmed.After(now) {
		confirmed = now
	}
	err := s.offer(c.Envelope, confirmed, now)
	s.mu.Lock()
	if c.LastIssuedSeq > s.lastSeq {
		s.lastSeq = c.LastIssuedSeq
	}
	s.mu.Unlock()
	return err
}

// MarshalCache writes a cache in tt canonical JSON.
func MarshalCache(c Cache) ([]byte, error) {
	o := ttjson.Obj(
		mem("format", ttjson.Str("tt.policy.cache/v1")),
		mem("envelope_b64", ttjson.Str(b64.EncodeToString(c.Envelope))),
		mem("last_issued_seq", ttjson.Num(strconv.FormatInt(c.LastIssuedSeq, 10))),
		mem("min_issued_seq", ttjson.Num(strconv.FormatInt(c.MinIssuedSeq, 10))),
		mem("killed", ttjson.BoolV(c.Killed)),
		mem("confirmed_at", ttjson.Str(c.ConfirmedAt.UTC().Format(time.RFC3339Nano))),
	)
	return ttjson.Encode(o)
}

// UnmarshalCache reads a cache written by MarshalCache.
func UnmarshalCache(b []byte) (Cache, error) {
	var c Cache
	v, err := ttjson.Parse(b, ttjson.ParseOptions{MaxDepth: 4, RejectDuplicates: true})
	if err != nil {
		return c, ErrEnvelope
	}
	m, err := fields(v, "cache", "format", "envelope_b64", "last_issued_seq", "min_issued_seq", "killed", "confirmed_at")
	if err != nil || require(m, "cache", "format", "envelope_b64", "last_issued_seq", "min_issued_seq", "killed", "confirmed_at") != nil {
		return c, ErrEnvelope
	}
	if f, _ := str(m["format"], ""); f != "tt.policy.cache/v1" {
		return c, ErrEnvelope
	}
	e, _ := str(m["envelope_b64"], "")
	if c.Envelope, err = b64.DecodeString(e); err != nil {
		return c, ErrEnvelope
	}
	if c.LastIssuedSeq, err = integer(m["last_issued_seq"], ""); err != nil {
		return c, ErrEnvelope
	}
	if c.MinIssuedSeq, err = integer(m["min_issued_seq"], ""); err != nil {
		return c, ErrEnvelope
	}
	if c.Killed, err = boolean(m["killed"], ""); err != nil {
		return c, ErrEnvelope
	}
	ts, _ := str(m["confirmed_at"], "")
	if c.ConfirmedAt, err = time.Parse(time.RFC3339Nano, ts); err != nil {
		return c, ErrEnvelope
	}
	return c, nil
}
