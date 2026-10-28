package sourceclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Heartbeat states (api/fleet-api.v1.openapi.yaml, Heartbeat.state).
const (
	StateStarting  = "starting"
	StateCapturing = "capturing"
	StateKeyMiss   = "key_missing"
	StateKeyMis    = "key_mismatch"
)

// Config configures a Source.
type Config struct {
	// EnrollURL and Token are used only while the source is not enrolled.
	EnrollURL string
	Token     string
	// StateDir holds the enrollment, client key and policy cache. Default:
	// DefaultStateDir(EnrollURL, ServiceName).
	StateDir string

	Kind        string // sdk-go, egress, ...
	Version     string // semver
	ServiceName string // requested service name (must be allowed for the token's group)
	Instance    string

	// Keys are the local HMAC keys; KeyKids their kids, reported at enrollment.
	Keys    sanitizer.KeySet
	KeyKids []string

	NoCSR bool // let tt-core generate the key pair (default: local CSR)

	// HeartbeatInterval and PolicyPollInterval override the intervals given
	// by tt-core (tests).
	HeartbeatInterval  time.Duration
	PolicyPollInterval time.Duration
	HTTPTimeout        time.Duration // Fleet calls, default 10s

	// Exporter tunables (queue bounds, batching, retry). URL, Client and the
	// source identity fields are filled by the Source.
	Exporter ExporterOptions

	Now    func() time.Time
	Logger *slog.Logger
	// OnPolicy is called (from the control goroutine) after a new policy was
	// accepted.
	OnPolicy func(*policy.Verified)
}

// Capture is what the capture layer needs for one exchange: the engine of
// the policy in force and the identity of the source.
type Capture struct {
	Engine      *sanitizer.Engine
	Policy      *policy.Verified
	OverrideBP  int // Fleet sampling override, -1 when none
	SourceID    string
	ServiceName string
	Kind        string
	Version     string
}

// Stats is a point-in-time view for health endpoints and logs.
type Stats struct {
	State        string
	Counters     CounterSnapshot
	OverheadP50  int64 // microseconds
	OverheadP99  int64
	QueueEvents  int
	QueueBytes   int64
	EventsPerMin int64
	Policy       *PolicyRef
	LastErrors   []LastError
}

type engineEntry struct {
	v   *policy.Verified
	eng *sanitizer.Engine
	err error
}

// Source is a source registered with tt-core. It owns the policy store (fail
// closed), the kill switch, the heartbeat and policy loops and the exporter.
type Source struct {
	cfg Config
	log *slog.Logger
	st  *StateDir

	counters Counters
	overhead overheadRing
	errs     errorLog
	rate     rateWindow

	id    atomic.Pointer[Identity]
	keyMu sync.Mutex // serializes writes of the key pair and identity
	mtls  *mtls
	fleet *fleetClient
	exp   atomic.Pointer[Exporter]
	expHC *http.Client
	ring  *policy.KeyRing

	store    atomic.Pointer[policy.Store]
	accepted atomic.Pointer[policy.Verified]
	engine   atomic.Pointer[engineEntry]
	override atomic.Int64
	hbOK     atomic.Bool
	// pollSoon makes the loop poll the policy right after a heartbeat that
	// announced a policy different from the one in force.
	pollSoon atomic.Bool

	kick   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
}

// New prepares a Source. It reads the saved state (no network): a source that
// was enrolled before starts with its certificate, its pinned signing keys,
// its cached policy and its kill switch, but it will not capture before its
// first heartbeat of this run (docs/spec/policy.md section 4).
func New(cfg Config) (*Source, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.Kind == "" || cfg.Version == "" || cfg.ServiceName == "" {
		return nil, errors.New("sourceclient: Kind, Version and ServiceName are required")
	}
	if cfg.StateDir == "" {
		cfg.StateDir = DefaultStateDir(cfg.EnrollURL, cfg.ServiceName)
	}
	st, err := OpenState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	s := &Source{cfg: cfg, log: cfg.Logger, st: st, kick: make(chan struct{}, 1), done: make(chan struct{})}
	s.override.Store(-1)
	if id, key := s.loadSaved(); id != nil {
		if err := s.activate(id, key); err != nil {
			s.log.Warn("saved enrollment unusable, will enroll again", "error", err.Error())
			s.st.Remove(fileEnrollment)
			s.st.Remove(fileClientKey)
		}
	}
	return s, nil
}

func (s *Source) now() time.Time { return s.cfg.Now() }

// loadSaved returns the saved enrollment unless it belongs to another CA than
// the one pinned by the current token.
func (s *Source) loadSaved() (*Identity, []byte) {
	raw, err := s.st.Read(fileEnrollment)
	if err != nil {
		return nil, nil
	}
	var id Identity
	if json.Unmarshal(raw, &id) != nil {
		return nil, nil
	}
	if pin, ok := TokenPin(s.cfg.Token); ok && pin != id.Pin {
		s.log.Info("saved enrollment belongs to another tt-core, ignoring it")
		return nil, nil
	}
	key, err := s.st.Read(fileClientKey)
	if err != nil {
		return nil, nil
	}
	return &id, key
}

// activate builds everything that depends on the enrollment.
func (s *Source) activate(id *Identity, keyPEM []byte) error {
	m, err := newMTLS([]byte(id.ClientCertPEM), keyPEM, []byte(id.CAChainPEM))
	if err != nil {
		return err
	}
	fc, err := newFleetClient(id.FleetURL, m, s.cfg.HTTPTimeout)
	if err != nil {
		return err
	}
	ring := policy.NewKeyRing()
	for _, k := range id.PinnedKeys {
		if err := ring.PinEncoded(k.Kid, k.Alg, k.PublicKey); err != nil {
			return fmt.Errorf("pinned key %q: %w", k.Kid, err)
		}
	}
	for _, kid := range id.RevokedKids {
		ring.Revoke(kid)
	}
	now := s.now()
	store := policy.NewStore(ring, id.Group, time.Duration(id.PolicyMaxAgeS)*time.Second)
	if raw, err := s.st.Read(filePolicyCache); err == nil {
		if c, err := policy.UnmarshalCache(raw); err == nil {
			// The kill switch and the sequence counters are restored even
			// when the cached envelope is no longer acceptable.
			if err := store.Restore(c, now); err != nil {
				s.log.Warn("cached policy not acceptable", "error", err.Error())
				code := "policy_cache_rejected"
				if errors.Is(err, policy.ErrUnsafe) {
					code = policy.CodeUnsafe
				}
				s.errs.add(code, now)
			}
		}
	}
	eo := s.cfg.Exporter
	eo.Client = m.client(4, 30*time.Second)
	eo.URL = id.IntakeURL
	eo.ServiceName, eo.SourceKind, eo.SourceVersion, eo.SourceID = id.ServiceName, s.cfg.Kind, s.cfg.Version, id.SourceID
	eo.Counters = &s.counters
	eo.OnError = func(code string) { s.errs.add(code, s.now()) }
	eo.Now = s.cfg.Now

	s.mtls, s.fleet, s.ring = m, fc, ring
	s.expHC = eo.Client
	s.exp.Store(NewExporter(eo))
	s.store.Store(store)
	s.id.Store(id)
	s.refreshAccepted()
	return nil
}

// Start runs the control loop (enrollment if needed, heartbeat, policy
// polling) until Close or ctx ends. It returns immediately.
func (s *Source) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		defer close(s.done)
		s.run(ctx)
	}()
}

// Close stops the control loop, flushes the export queue until ctx ends and
// persists the state.
func (s *Source) Close(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
		select {
		case <-s.done:
		case <-ctx.Done():
		}
	}
	if e := s.exp.Load(); e != nil {
		e.Close(ctx)
	}
	if s.store.Load() != nil {
		s.persistCache()
	}
	return nil
}

// AcceptedPolicy returns the verified policy in force (it may exist before the
// first heartbeat, when capture is still not allowed), or nil.
func (s *Source) AcceptedPolicy() *policy.Verified { return s.accepted.Load() }

// Kick asks the control loop to run a heartbeat and a policy poll now.
func (s *Source) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Counters exposes the counters so the capture layer can count exchanges and
// sanitizer errors.
func (s *Source) Counters() *Counters { return &s.counters }

// ObserveOverhead records the time tt spent on one exchange.
func (s *Source) ObserveOverhead(d time.Duration) { s.overhead.observe(d) }

// RecordError remembers an error code for the heartbeat.
func (s *Source) RecordError(code string) { s.errs.add(code, s.now()) }

// Identity returns a copy of the enrollment, or nil when not enrolled.
func (s *Source) Identity() *Identity {
	id := s.id.Load()
	if id == nil {
		return nil
	}
	c := *id
	c.PinnedKeys = append([]SigningKey(nil), id.PinnedKeys...)
	c.RevokedKids = append([]string(nil), id.RevokedKids...)
	return &c
}

// Active returns what is needed to capture one exchange, or false when the
// source must not capture (no policy, rejected or expired policy, missing key,
// kill switch, no heartbeat yet). It is cheap enough for the request path.
func (s *Source) Active() (Capture, bool) {
	st := s.store.Load()
	id := s.id.Load()
	if st == nil || id == nil {
		return Capture{}, false
	}
	cur := st.Current(s.now())
	if !cur.Capture {
		return Capture{}, false
	}
	ee := s.engineFor(cur.Policy)
	if ee.err != nil {
		return Capture{}, false
	}
	return Capture{Engine: ee.eng, Policy: cur.Policy, OverrideBP: int(s.override.Load()),
		SourceID: id.SourceID, ServiceName: id.ServiceName, Kind: s.cfg.Kind, Version: s.cfg.Version}, true
}

func (s *Source) engineFor(v *policy.Verified) *engineEntry {
	if e := s.engine.Load(); e != nil && e.v == v {
		return e
	}
	eng, err := sanitizer.NewEngine(v.Policy, s.cfg.Keys)
	e := &engineEntry{v: v, eng: eng, err: err}
	s.engine.Store(e)
	return e
}

// HasPolicy reports whether the source holds a signed policy (verified or
// cached), whatever its state.
func (s *Source) HasPolicy() bool {
	st := s.store.Load()
	return st != nil && st.Snapshot().Envelope != nil
}

// State returns the heartbeat state.
func (s *Source) State() string {
	st := s.store.Load()
	if st == nil || !s.hbOK.Load() {
		return StateStarting
	}
	cur := st.Current(s.now())
	if !cur.Capture {
		return string(cur.State)
	}
	if ee := s.engineFor(cur.Policy); ee.err != nil {
		if errors.Is(ee.err, sanitizer.ErrKeyMismatch) {
			return StateKeyMis
		}
		return StateKeyMiss
	}
	return string(cur.State)
}

// Emit queues one canonical event. It never blocks, and it drops the event
// when capture stopped meanwhile (for example the kill switch arrived).
func (s *Source) Emit(ev Event) {
	st, exp := s.store.Load(), s.exp.Load()
	if st == nil || exp == nil || !st.Current(s.now()).Capture {
		return
	}
	s.rate.add(s.now(), 1)
	exp.Enqueue(ev)
}

// Stats returns a snapshot for health endpoints.
func (s *Source) Stats() Stats {
	out := Stats{State: s.State(), Counters: s.counters.Snapshot(), LastErrors: s.errs.snapshot(), EventsPerMin: s.rate.perMinute(s.now())}
	if p50, p99, ok := s.overhead.percentiles(); ok {
		out.OverheadP50, out.OverheadP99 = p50, p99
	}
	if e := s.exp.Load(); e != nil {
		out.QueueEvents, out.QueueBytes = e.Size()
	}
	if a := s.accepted.Load(); a != nil {
		out.Policy = &PolicyRef{ID: a.Policy.PolicyID, Version: a.Policy.Version, IssuedSeq: a.Policy.IssuedSeq, Hash: a.Hash}
	}
	return out
}

// ---- control loop ----

func (s *Source) run(ctx context.Context) {
	backoff := time.Second
	for s.id.Load() == nil {
		err := s.enroll(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		s.log.Warn("enrollment failed", "error", err.Error())
		s.errs.add(enrollCode(err), s.now())
		if !sleep(ctx, backoff, s.kick) {
			return
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
	nextHB, nextPol := time.Now(), time.Time{}
	fails := 0
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextHB) {
			d, ok := s.heartbeat(ctx)
			if ok {
				fails = 0
				if nextPol.IsZero() || s.pollSoon.Swap(false) {
					nextPol = now
				}
			} else {
				fails++
				d = min(d, time.Duration(1<<min(fails, 5))*time.Second)
			}
			nextHB = time.Now().Add(d)
		}
		if !nextPol.IsZero() && !time.Now().Before(nextPol) {
			s.pollPolicy(ctx)
			nextPol = time.Now().Add(s.pollInterval())
		}
		wait := time.Until(nextHB)
		if !nextPol.IsZero() {
			wait = min(wait, time.Until(nextPol))
		}
		if !sleep(ctx, max(wait, 0), s.kick) {
			return
		}
		select {
		case <-s.kick:
		default:
		}
	}
}

// sleep waits d, returning false when ctx ended. A value on kick ends the
// wait early.
func sleep(ctx context.Context, d time.Duration, kick <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
	case <-kick:
	}
	return ctx.Err() == nil
}

func enrollCode(err error) string {
	var se *StatusError
	switch {
	case errors.Is(err, ErrPinMismatch):
		return "enroll_pin_mismatch"
	case errors.Is(err, ErrTokenMalformed):
		return "enroll_token_malformed"
	case errors.As(err, &se):
		return fmt.Sprintf("enroll_http_%d", se.Status)
	}
	return "enroll_failed"
}

func (s *Source) enroll(ctx context.Context) error {
	if s.cfg.Token == "" || s.cfg.EnrollURL == "" {
		return errors.New("not enrolled: enrollment url and token are required")
	}
	id, key, err := Enroll(ctx, EnrollOptions{
		EnrollURL: s.cfg.EnrollURL, Token: s.cfg.Token, NoCSR: s.cfg.NoCSR, Now: s.cfg.Now,
		Source: SourceInfo{Kind: s.cfg.Kind, Version: s.cfg.Version, ServiceName: s.cfg.ServiceName,
			Instance: s.cfg.Instance, Runtime: GoRuntime(), HMACKids: s.cfg.KeyKids},
	})
	if err != nil {
		return err
	}
	// The key first: an enrollment without its key is useless, a key without
	// enrollment is harmless.
	if err := s.st.Write(fileClientKey, key); err != nil {
		return err
	}
	if err := s.saveIdentity(id); err != nil {
		return err
	}
	if err := s.activate(id, key); err != nil {
		return err
	}
	s.log.Info("enrolled", "source_id", id.SourceID, "group", id.Group, "service", id.ServiceName)
	return nil
}

func (s *Source) saveIdentity(id *Identity) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	return s.st.Write(fileEnrollment, raw)
}

func (s *Source) persistCache() {
	st := s.store.Load()
	if st == nil {
		return
	}
	raw, err := policy.MarshalCache(st.Snapshot())
	if err == nil {
		err = s.st.Write(filePolicyCache, raw)
	}
	if err != nil {
		s.errs.add("state_write_failed", s.now())
		s.log.Warn("cannot persist policy cache", "error", err.Error())
	}
}

func (s *Source) hbInterval(fromCore int64) time.Duration {
	if s.cfg.HeartbeatInterval > 0 {
		return s.cfg.HeartbeatInterval
	}
	if fromCore > 0 {
		return time.Duration(fromCore) * time.Second
	}
	return time.Duration(s.id.Load().HeartbeatIntervalS) * time.Second
}

func (s *Source) pollInterval() time.Duration {
	if s.cfg.PolicyPollInterval > 0 {
		return s.cfg.PolicyPollInterval
	}
	return time.Duration(s.id.Load().PolicyPollIntervalS) * time.Second
}

func (s *Source) heartbeatBody() *Heartbeat {
	st := s.Stats()
	hb := &Heartbeat{SourceID: s.id.Load().SourceID, State: st.State, Policy: st.Policy, Counters: st.Counters,
		Queue: &QueueInfo{Events: st.QueueEvents, Bytes: st.QueueBytes}, LastErrors: st.LastErrors, Runtime: GoRuntime(),
		SigningKids: trustedKids(s.id.Load())}
	if st.OverheadP50 > 0 || st.OverheadP99 > 0 {
		hb.OverheadUS = &OverheadUS{P50: st.OverheadP50, P99: st.OverheadP99}
	}
	return hb
}

// heartbeat sends one heartbeat and applies the response. It returns the time
// to the next one and whether the call succeeded.
func (s *Source) heartbeat(ctx context.Context) (time.Duration, bool) {
	hctx, cancel := context.WithTimeout(ctx, s.cfg.HTTPTimeout)
	defer cancel()
	resp, err := s.fleet.heartbeat(hctx, s.heartbeatBody())
	var se *StatusError
	switch {
	case errors.As(err, &se) && se.Status == http.StatusForbidden:
		s.revoked()
		return s.hbInterval(0), false
	case err != nil:
		if ctx.Err() == nil {
			s.errs.add("heartbeat_failed", s.now())
			s.log.Warn("heartbeat failed", "error", err.Error())
		}
		return s.hbInterval(0), false
	}
	s.apply(resp)
	s.hbOK.Store(true)
	return s.hbInterval(resp.NextHeartbeatS), true
}

// revoked handles a 403: stop capturing, drop the queue and persist the stop.
func (s *Source) revoked() {
	now := s.now()
	st := s.store.Load()
	snap := st.Snapshot()
	st.Heartbeat(true, snap.MinIssuedSeq, now)
	s.hbOK.Store(true)
	s.exp.Load().Clear()
	s.persistCache()
	s.errs.add("source_revoked", now)
}

// apply processes a heartbeat response (docs/spec/policy.md section 4).
func (s *Source) apply(r *HeartbeatResponse) {
	now := s.now()
	id := *s.id.Load()
	keysChanged := false
	// Revocations first: they only remove trust.
	for _, kid := range r.RevokeSigningKeys {
		s.ring.Revoke(kid)
		id.PinnedKeys = removeKey(id.PinnedKeys, kid)
		if !contains(id.RevokedKids, kid) {
			id.RevokedKids = append(id.RevokedKids, kid)
		}
		keysChanged = true
	}
	for _, k := range r.AddSigningKeys {
		// tt-core repeats every endorsed key at each heartbeat: a key
		// already pinned (same bytes) or revoked is skipped silently.
		if contains(id.RevokedKids, k.Kid) || hasPinned(id.PinnedKeys, k) {
			continue
		}
		if err := s.ring.PinEndorsed(k.Kid, k.Alg, k.PublicKey, k.EndorsedBy, k.Endorsement); err != nil {
			s.errs.add(policy.SigningKeyErrorCode(err), now)
			s.log.Warn("signing key not accepted", "kid", k.Kid, "error", err.Error())
			continue
		}
		id.PinnedKeys = append(removeKey(id.PinnedKeys, k.Kid), SigningKey{Kid: k.Kid, Alg: "Ed25519", PublicKey: k.PublicKey})
		keysChanged = true
	}
	if len(r.RevokeSigningKeys) > 0 {
		s.rebuildStore(now, true)
	}
	if keysChanged {
		s.id.Store(&id)
		if err := s.saveIdentity(&id); err != nil {
			s.errs.add("state_write_failed", now)
		}
	}
	s.store.Load().Heartbeat(r.Kill, r.MinIssuedSeq, now)
	if r.SamplingOverrideBP != nil {
		s.override.Store(int64(*r.SamplingOverrideBP))
	} else {
		s.override.Store(-1)
	}
	if r.Kill {
		s.exp.Load().Clear()
	}
	s.persistCache()
	if r.RenewBefore != nil && !now.Before(*r.RenewBefore) {
		s.renew()
	}
	if pc := r.PolicyCurrent; pc != nil {
		if a := s.accepted.Load(); a == nil || a.Hash != pc.Hash {
			s.pollSoon.Store(true)
		}
	}
}

// hasPinned reports whether k is already pinned with the same public key.
func hasPinned(keys []SigningKey, k AddSigningKey) bool {
	for _, p := range keys {
		if p.Kid == k.Kid && p.PublicKey == k.PublicKey {
			return true
		}
	}
	return false
}

// trustedKids returns the pinned, non-revoked signing kids, sorted.
func trustedKids(id *Identity) []string {
	out := []string{}
	if id == nil {
		return out
	}
	for _, k := range id.PinnedKeys {
		if !contains(id.RevokedKids, k.Kid) && !contains(out, k.Kid) {
			out = append(out, k.Kid)
		}
	}
	sort.Strings(out)
	return out
}

func removeKey(keys []SigningKey, kid string) []SigningKey {
	out := keys[:0:0]
	for _, k := range keys {
		if k.Kid != kid {
			out = append(out, k)
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// rebuildStore re-verifies the current envelope against the (changed) key
// ring in a fresh store; counters, kill switch and min_issued_seq carry over.
// With dropEnvelope the policy is forgotten as well.
func (s *Source) rebuildStore(now time.Time, reverify bool) {
	old := s.store.Load()
	snap := old.Snapshot()
	if !reverify {
		snap.Envelope = nil
	}
	ns := policy.NewStore(s.ring, s.id.Load().Group, time.Duration(s.id.Load().PolicyMaxAgeS)*time.Second)
	_ = ns.Restore(snap, now)
	ns.Heartbeat(snap.Killed, snap.MinIssuedSeq, now)
	s.store.Store(ns)
	s.refreshAccepted()
}

// refreshAccepted recomputes the verified policy in force from the store.
func (s *Source) refreshAccepted() {
	st := s.store.Load()
	if st == nil {
		return
	}
	env := st.Snapshot().Envelope
	if len(env) == 0 {
		s.accepted.Store(nil)
		return
	}
	v, err := policy.Verify(env, s.ring)
	if err != nil {
		s.accepted.Store(nil)
		return
	}
	s.accepted.Store(v)
}

func (s *Source) pollPolicy(ctx context.Context) {
	etag := ""
	if a := s.accepted.Load(); a != nil {
		etag = `"` + a.Hash + `"`
	}
	pctx, cancel := context.WithTimeout(ctx, s.cfg.HTTPTimeout*2)
	defer cancel()
	r, err := s.fleet.policy(pctx, etag)
	now := s.now()
	if err != nil {
		if ctx.Err() == nil {
			s.errs.add("policy_fetch_failed", now)
			s.log.Warn("policy fetch failed", "error", err.Error())
		}
		return
	}
	switch r.status {
	case http.StatusOK:
		if err := s.store.Load().Offer(r.body, now); err != nil {
			code := "policy_rejected"
			if errors.Is(err, policy.ErrNotAfter) {
				code = "policy_expired"
			} else if errors.Is(err, policy.ErrUnsafe) {
				code = policy.CodeUnsafe
			}
			s.errs.add(code, now)
			s.log.Warn("policy rejected", "reason", err.Error())
		} else {
			before := s.accepted.Load()
			s.refreshAccepted()
			if a := s.accepted.Load(); a != nil && (before == nil || before.Hash != a.Hash) {
				s.log.Info("policy accepted", "policy", a.Policy.PolicyID, "version", a.Policy.Version, "issued_seq", a.Policy.IssuedSeq)
				if s.cfg.OnPolicy != nil {
					s.cfg.OnPolicy(a)
				}
			}
		}
		s.persistCache()
	case http.StatusNotModified:
		s.store.Load().Confirm(now)
		s.persistCache()
	case http.StatusNotFound:
		// No policy assigned: the source must not capture.
		s.rebuildStore(now, false)
		s.persistCache()
	case http.StatusForbidden:
		s.revoked()
	default:
		s.errs.add(fmt.Sprintf("policy_http_%d", r.status), now)
	}
}

// renew replaces the client certificate before it expires.
func (s *Source) renew() {
	now := s.now()
	key, csr, err := NewCSR(s.id.Load().ServiceName)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTPTimeout)
	defer cancel()
	rr, err := s.fleet.renew(ctx, csr)
	if err != nil {
		s.errs.add("renew_failed", now)
		return
	}
	cert := []byte(rr.ClientCert)
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		s.errs.add("renew_failed", now)
		return
	}
	leaf, err := parseCerts(cert)
	if err != nil || len(leaf) == 0 || !certHasSourceID(leaf[0], s.id.Load().SourceID) {
		s.errs.add("renew_failed", now)
		return
	}
	id := *s.id.Load()
	id.ClientCertPEM, id.NotAfter = rr.ClientCert, leaf[0].NotAfter
	if err := s.st.Write(fileClientKey, key); err != nil {
		s.errs.add("state_write_failed", now)
		return
	}
	if err := s.saveIdentity(&id); err != nil {
		s.errs.add("state_write_failed", now)
		return
	}
	if err := s.mtls.setCert(cert, key); err != nil {
		s.errs.add("renew_failed", now)
		return
	}
	s.id.Store(&id)
	// Connections already open keep the old certificate: start fresh ones.
	if t, ok := s.fleet.hc.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	if t, ok := s.expHC.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	s.log.Info("client certificate renewed")
}
