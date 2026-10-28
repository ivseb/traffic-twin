package intake

import (
	"context"
	"sync"
)

// SourceInfo is what the intake needs to know about an enrolled source. It
// is provided by the fleet package through [SourceRegistry].
type SourceInfo struct {
	// ID is the enrollment id (src-...), also the SAN of the client
	// certificate.
	ID string
	// Group is the source group assigned at enrollment.
	Group string
	// ServiceName is the service name assigned at enrollment (fixed in the
	// certificate): the name inbound events must carry. Empty if the
	// registry cannot tell, in which case only AllowedServices is checked.
	ServiceName string
	// AllowedServices are the service names allowed for the group.
	AllowedServices []string
	// Revoked sources are refused (403) without looking at their events.
	Revoked bool
}

// AllowsService reports whether name is one of the allowed service names.
func (s *SourceInfo) AllowsService(name string) bool {
	for _, a := range s.AllowedServices {
		if a == name {
			return true
		}
	}
	return false
}

// SourceRegistry resolves source identities. The fleet package implements
// it; [MemSourceRegistry] is an in-memory fake for tests.
type SourceRegistry interface {
	// LookupSource returns the source with the given enrollment id.
	LookupSource(id string) (SourceInfo, bool)
}

// PolicyRegistry resolves signed compiled policies by hash. Only policies
// signed by keyguard must be returned; the intake trusts the registry
// (docs/spec/event.md 5.1 point 3). Implementations keep every signed
// version because events produced under an older version can still arrive.
type PolicyRegistry interface {
	// LookupPolicy returns the policy whose body has the given hash
	// ("sha256:<hex>").
	LookupPolicy(hash string) (*Policy, bool)
}

// TokenSink receives the HMAC tokens of accepted events, to be inserted in
// keyguard's Bloom filter of real tokens (docs/spec/keyguard.md 2,
// POST /keyguard/v1/tokens). The intake delivers at least once, from a
// durable outbox, so implementations should tolerate duplicates.
type TokenSink interface {
	// AddTokens delivers tokens (tk1:...) observed under the given HMAC
	// epoch.
	AddTokens(ctx context.Context, epoch string, tokens []string) error
}

// AlarmSink is told when an element enters quarantine
// (docs/spec/event.md 5.2 point 3). It is called from the intake's
// goroutines and must not block for long.
type AlarmSink interface {
	QuarantineRaised(ctx context.Context, q Quarantine)
}

// ---------------------------------------------------------------------------
// In-memory fakes

// MemSourceRegistry is a [SourceRegistry] backed by a map.
type MemSourceRegistry struct {
	mu      sync.RWMutex
	sources map[string]SourceInfo
}

// NewMemSourceRegistry returns an empty registry.
func NewMemSourceRegistry() *MemSourceRegistry {
	return &MemSourceRegistry{sources: map[string]SourceInfo{}}
}

// Set adds or replaces a source.
func (r *MemSourceRegistry) Set(s SourceInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[s.ID] = s
}

// Revoke marks a source revoked.
func (r *MemSourceRegistry) Revoke(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sources[id]; ok {
		s.Revoked = true
		r.sources[id] = s
	}
}

// LookupSource implements SourceRegistry.
func (r *MemSourceRegistry) LookupSource(id string) (SourceInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sources[id]
	return s, ok
}

// MemPolicyRegistry is a [PolicyRegistry] backed by a map.
type MemPolicyRegistry struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

// NewMemPolicyRegistry returns an empty registry.
func NewMemPolicyRegistry() *MemPolicyRegistry {
	return &MemPolicyRegistry{policies: map[string]*Policy{}}
}

// Add registers a policy under its hash.
func (r *MemPolicyRegistry) Add(p *Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[p.Hash] = p
}

// LookupPolicy implements PolicyRegistry.
func (r *MemPolicyRegistry) LookupPolicy(hash string) (*Policy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.policies[hash]
	return p, ok
}

// MemTokenSink is a [TokenSink] that records what it receives.
type MemTokenSink struct {
	mu     sync.Mutex
	byEpoc map[string]map[string]struct{}
	// Fail makes AddTokens return this error (to test redelivery).
	Fail error
	// Calls counts AddTokens invocations.
	Calls int
}

// NewMemTokenSink returns an empty sink.
func NewMemTokenSink() *MemTokenSink {
	return &MemTokenSink{byEpoc: map[string]map[string]struct{}{}}
}

// AddTokens implements TokenSink.
func (s *MemTokenSink) AddTokens(_ context.Context, epoch string, tokens []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls++
	if s.Fail != nil {
		return s.Fail
	}
	m := s.byEpoc[epoch]
	if m == nil {
		m = map[string]struct{}{}
		s.byEpoc[epoch] = m
	}
	for _, t := range tokens {
		m[t] = struct{}{}
	}
	return nil
}

// Has reports whether token was delivered under epoch.
func (s *MemTokenSink) Has(epoch, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byEpoc[epoch][token]
	return ok
}

// Count returns the number of distinct tokens delivered under epoch.
func (s *MemTokenSink) Count(epoch string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byEpoc[epoch])
}

// SetFail sets the error returned by AddTokens (nil to succeed).
func (s *MemTokenSink) SetFail(err error) {
	s.mu.Lock()
	s.Fail = err
	s.mu.Unlock()
}

// MemAlarmSink records quarantine alarms.
type MemAlarmSink struct {
	mu     sync.Mutex
	Raised []Quarantine
}

// QuarantineRaised implements AlarmSink.
func (a *MemAlarmSink) QuarantineRaised(_ context.Context, q Quarantine) {
	a.mu.Lock()
	a.Raised = append(a.Raised, q)
	a.mu.Unlock()
}

// Snapshot returns a copy of the recorded alarms.
func (a *MemAlarmSink) Snapshot() []Quarantine {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Quarantine(nil), a.Raised...)
}
