package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
)

// Defaults.
const (
	DefaultClientCertTTL      = 7 * 24 * time.Hour
	DefaultHeartbeatInterval  = 30 * time.Second
	DefaultPolicyPollInterval = 60 * time.Second
	DefaultPolicyRenewBefore  = 7 * 24 * time.Hour
	DefaultKeyConfirmWindow   = 24 * time.Hour
	// MaxOneTimeTokenTTL and MaxGroupTokenTTL bound enrollment token expiry
	// (admin-api createEnrollmentToken).
	MaxOneTimeTokenTTL = 24 * time.Hour
	MaxGroupTokenTTL   = 365 * 24 * time.Hour
)

// Options configure Fleet.
type Options struct {
	DB     *store.DB
	Audit  *audit.Log
	Signer Signer
	// Alerts receives policy.admin_approval and similar alerts. Optional.
	Alerts Alerter
	Logger *slog.Logger
	Now    func() time.Time

	// PublicURL is the base URL sources use to reach the intake listener,
	// e.g. https://tt-core.internal:4318. Required.
	PublicURL string
	// ServerNames are the DNS names and IPs of the managed intake server
	// certificate (intake.tls.managed). Default: the host of PublicURL.
	ServerNames []string
	// CADir holds fleet-ca.crt and fleet-ca.key. Default: "fleet-ca" next
	// to the database file.
	CADir string

	ClientCertTTL      time.Duration // default 7 days
	HeartbeatInterval  time.Duration // default 30 s
	PolicyPollInterval time.Duration // default 60 s
	PolicyMaxAge       time.Duration // default policy.DefaultMaxAge (24 h)
	PolicyValidity     time.Duration // not_after - created_at, default 30 days
	// PolicyRenewBefore: active policies whose not_after is closer than
	// this are re-signed automatically through keyguard (keyguard.md 3.3).
	PolicyRenewBefore time.Duration

	// EnrollIPLimit and EnrollTokenLimit rate-limit the enrollment
	// endpoint per client IP (IPv6 per /64) and per token (429 with
	// Retry-After). Defaults: DefaultEnrollIPLimit, DefaultEnrollTokenLimit.
	EnrollIPLimit    RateLimit
	EnrollTokenLimit RateLimit

	// KeyRevokeMinConfirmed is the fraction (0..1) of the sources seen in
	// the last KeyConfirmWindow that must have confirmed, through their
	// heartbeat (signing_kids), another valid signing key before a policy
	// signing key can be revoked. Nil means 1 (every source); 0 disables
	// the check. KeyConfirmWindow defaults to 24 h.
	KeyRevokeMinConfirmed *float64
	KeyConfirmWindow      time.Duration

	// LastErrorsWindow is how far back SourceStatus.last_errors looks:
	// only errors seen within it are listed (grouped by code, with
	// first_seen, last_seen and count). Default DefaultLastErrorsWindow,
	// at most one hour. Historical totals are in the counters, not here.
	LastErrorsWindow time.Duration

	// KMin is the k-anonymity threshold of the installation (miner.k_min, default
	// DefaultKMin): the policy assistant uses it to say whether the sampling
	// of a policy lets enough distinct users through.
	KMin int

	// EgressHosts are extra host or host:port names the applications use to
	// reach tt-egress (for example the compose service "tt-egress:9090"), on
	// top of the hostnames the egress sources report. An SDK event whose
	// target is one of them raises double_capture (see EgressHosts).
	EgressHosts []string

	// Observe configures the observe phase (policy.md 7): the observe
	// version tt-core derives by itself. Zero value: disabled.
	Observe ObserveOptions

	// Bodies is the bodies object written into the compiled policies whose
	// author has none (sanitizer.md 22, spec v1.19, fleet.sanitizer); nil
	// writes none.
	Bodies *policy.Bodies
}

// DefaultKMin is the default Options.KMin.
const DefaultKMin = 20

// DefaultLastErrorsWindow is the default Options.LastErrorsWindow.
const DefaultLastErrorsWindow = 15 * time.Minute

// EventCounter reports how many events the intake accepted from a source
// (onboarding step "first events"). Optional; see SetEventCounter.
type EventCounter interface {
	AcceptedEvents(sourceID string) uint64
}

// Rejection is the events of one source rejected for one reason within a
// window: closed reason code, count and the time of the first and the last.
type Rejection struct {
	Reason string
	Count  uint64
	First  time.Time
	Last   time.Time
}

// RejectCounter is implemented by an EventCounter that also knows why the
// intake rejected a source's events: counts by closed reason code, never
// values, within a window (not since the beginning of time: a rejection that
// stopped must disappear). The fleet shows them in SourceStatus.last_errors.
type RejectCounter interface {
	RecentRejections(sourceID string, window time.Duration) []Rejection
}

// DoubleCaptureReporter is implemented by an EventCounter that detects the
// same outbound call captured by an SDK and by tt-egress. The fleet shows it
// as the problem double_capture of both sources.
type DoubleCaptureReporter interface {
	DoubleCaptured(sourceID string) bool
}

// Fleet is the source onboarding, enrollment, policy distribution and
// health component of tt-core.
type Fleet struct {
	db     *store.DB
	audit  *audit.Log
	signer Signer
	alerts Alerter
	log    *slog.Logger
	now    func() time.Time
	opts   Options
	ca     *ca

	publicURL string

	// policyMu serializes policy lifecycle changes (propose, approve,
	// reject, rollback, retarget, renew).
	policyMu sync.Mutex

	mu         sync.RWMutex
	sources    map[string]*memSource
	groups     map[string]*memGroup
	certs      map[string]memCert // serial -> cert (non-expired)
	active     map[string]*activePolicy
	signed     map[string][]byte // hash -> body of every signed version
	keys       []SigningKey      // non-revoked policy signing keys
	revoked    []string          // revoked signing kids
	killAll    bool
	events     EventCounter
	idTokens   map[string]idToken // policy/version/user -> fresh OIDC ID token
	tokens     ApprovalTokens     // approval step-up (nil: OIDC login disabled)
	enrollFail map[string]string  // token id -> last enrollment problem code
	// renewSkipped remembers the versions already reported as not renewed.
	renewSkipped map[string]bool
	kgStatus     SignerStatus // last approval settings read from keyguard
	kgKnown      bool
	discovery    DiscoverySource
	// observeRefused: per policy, the hash of the last observe version
	// refused because it would open values (audited once).
	observeRefused map[string]string

	enrollIP, enrollTok *limiter
}

type memSource struct {
	id, group, service, tokenID string
	revoked, killed             bool
	overrideBP                  *int
	certNotAfter                time.Time
}

type memGroup struct {
	allowed    []string
	killed     bool
	overrideBP *int
	policyID   string
}

type memCert struct {
	source   string
	notAfter time.Time
	revoked  bool
}

type activePolicy struct {
	policyID string
	version  int64
	seq      int64
	hash     string
	envelope []byte
	groups   []string
	rateBP   int
	notAfter time.Time
	// signerKid is the kid of the envelope signature: a policy signed by a
	// kid keyguard no longer signs with is re-signed (key rotation).
	signerKid string
}

type idToken struct {
	token string
	at    time.Time
	nonce string // approvebind nonce the token is bound to
}

// New opens Fleet: it creates the CA on first start and loads the
// registry. The database must have been opened with store.Open.
func New(ctx context.Context, o Options) (*Fleet, error) {
	if o.DB == nil || o.Audit == nil || o.Signer == nil {
		return nil, errors.New("fleet: DB, Audit and Signer are required")
	}
	u, err := url.Parse(o.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("fleet: PublicURL must be https://host[:port]")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CADir == "" {
		o.CADir = filepath.Join(filepath.Dir(o.DB.Path()), "fleet-ca")
	}
	if len(o.ServerNames) == 0 {
		o.ServerNames = []string{u.Hostname()}
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.ClientCertTTL, DefaultClientCertTTL)
	def(&o.HeartbeatInterval, DefaultHeartbeatInterval)
	if o.LastErrorsWindow <= 0 {
		o.LastErrorsWindow = DefaultLastErrorsWindow
	}
	if o.LastErrorsWindow > time.Hour {
		o.LastErrorsWindow = time.Hour
	}
	def(&o.PolicyPollInterval, DefaultPolicyPollInterval)
	def(&o.PolicyMaxAge, policy.DefaultMaxAge)
	def(&o.PolicyValidity, policy.DefaultValidity)
	def(&o.PolicyRenewBefore, DefaultPolicyRenewBefore)
	def(&o.KeyConfirmWindow, DefaultKeyConfirmWindow)
	observeDefaults(&o.Observe)
	if o.KeyRevokeMinConfirmed == nil {
		one := 1.0
		o.KeyRevokeMinConfirmed = &one
	}
	if v := *o.KeyRevokeMinConfirmed; v < 0 || v > 1 {
		return nil, errors.New("fleet: KeyRevokeMinConfirmed must be between 0 and 1")
	}
	if o.PolicyRenewBefore >= o.PolicyValidity {
		return nil, errors.New("fleet: PolicyRenewBefore must be shorter than PolicyValidity")
	}
	c, err := loadOrCreateCA(o.CADir, o.Now, o.ServerNames)
	if err != nil {
		return nil, err
	}
	f := &Fleet{
		db: o.DB, audit: o.Audit, signer: o.Signer, alerts: o.Alerts, log: o.Logger, now: o.Now, opts: o, ca: c,
		publicURL: "https://" + u.Host,
		idTokens:  map[string]idToken{}, enrollFail: map[string]string{}, renewSkipped: map[string]bool{},
		enrollIP:  newLimiter(o.EnrollIPLimit, DefaultEnrollIPLimit),
		enrollTok: newLimiter(o.EnrollTokenLimit, DefaultEnrollTokenLimit),
	}
	if err := f.reload(ctx); err != nil {
		return nil, err
	}
	if err := f.refreshSigningKeys(ctx); err != nil {
		// keyguard may be down at start: enrollment uses the stored keys.
		f.log.Warn("fleet: cannot fetch policy signing keys from keyguard", "err", err)
	}
	f.refreshSignerStatus(ctx)
	return f, nil
}

// SetEventCounter installs the intake's accepted-event counter (used by the
// onboarding status). Call it once the intake is built.
func (f *Fleet) SetEventCounter(ec EventCounter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = ec
}

// CAPin returns the pin embedded in enrollment tokens:
// base64url(SHA-256(DER of the root CA)).
func (f *Fleet) CAPin() string { return f.ca.pin }

// CACertificatePEM returns the Fleet root CA certificate (PEM).
func (f *Fleet) CACertificatePEM() []byte { return slices.Clone(f.ca.pem) }

// reload rebuilds the in-memory registry from the database.
func (f *Fleet) reload(ctx context.Context) error {
	sources := map[string]*memSource{}
	groups := map[string]*memGroup{}
	certs := map[string]memCert{}
	active := map[string]*activePolicy{}
	signed := map[string][]byte{}
	now := f.now().Unix()

	rows, err := f.db.QueryContext(ctx, `SELECT name, policy_id, allowed_service_names, sampling_override_bp, killed FROM fleet_groups`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, allowed string
		var pid sql.NullString
		var ov sql.NullInt64
		var killed int
		if err := rows.Scan(&name, &pid, &allowed, &ov, &killed); err != nil {
			rows.Close()
			return err
		}
		g := &memGroup{killed: killed == 1, overrideBP: intPtr(ov), policyID: pid.String}
		if err := json.Unmarshal([]byte(allowed), &g.allowed); err != nil {
			rows.Close()
			return err
		}
		groups[name] = g
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = f.db.QueryContext(ctx, `SELECT id, grp, service_name, token_id, revoked, killed, sampling_override_bp, cert_not_after FROM fleet_sources`)
	if err != nil {
		return err
	}
	for rows.Next() {
		s := &memSource{}
		var rev, killed int
		var ov sql.NullInt64
		var cna int64
		if err := rows.Scan(&s.id, &s.group, &s.service, &s.tokenID, &rev, &killed, &ov, &cna); err != nil {
			rows.Close()
			return err
		}
		s.revoked, s.killed, s.overrideBP, s.certNotAfter = rev == 1, killed == 1, intPtr(ov), time.Unix(cna, 0).UTC()
		sources[s.id] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = f.db.QueryContext(ctx, `SELECT serial, source_id, not_after, revoked FROM fleet_certs WHERE not_after > ?`, now)
	if err != nil {
		return err
	}
	for rows.Next() {
		var serial, src string
		var na int64
		var rev int
		if err := rows.Scan(&serial, &src, &na, &rev); err != nil {
			rows.Close()
			return err
		}
		certs[serial] = memCert{source: src, notAfter: time.Unix(na, 0).UTC(), revoked: rev == 1}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = f.db.QueryContext(ctx, `SELECT policy_id, version, status, issued_seq, hash, body, envelope FROM fleet_policy_versions WHERE body IS NOT NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var pid, status, hash string
		var ver, seq int64
		var body, env []byte
		if err := rows.Scan(&pid, &ver, &status, &seq, &hash, &body, &env); err != nil {
			rows.Close()
			return err
		}
		signed[hash] = body
		if status == "active" {
			ap, err := newActive(body, env, hash)
			if err != nil {
				rows.Close()
				return fmt.Errorf("fleet: stored policy %s v%d: %w", pid, ver, err)
			}
			active[pid] = ap
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	keys, revoked, err := f.loadSigningKeys(ctx)
	if err != nil {
		return err
	}
	g, err := getMeta(ctx, f.db, metaGlobalKill)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.sources, f.groups, f.certs, f.active, f.signed = sources, groups, certs, active, signed
	f.keys, f.revoked, f.killAll = keys, revoked, g == "1"
	f.mu.Unlock()
	return nil
}

func newActive(body, env []byte, hash string) (*activePolicy, error) {
	p, err := policy.DecodeBody(body)
	if err != nil {
		return nil, err
	}
	var e struct {
		Signature struct {
			Kid string `json:"kid"`
		} `json:"signature"`
	}
	_ = json.Unmarshal(env, &e)
	return &activePolicy{
		policyID: p.PolicyID, version: p.Version, seq: p.IssuedSeq, hash: hash, envelope: env,
		groups: p.Groups, rateBP: p.Sampling.RateBP, notAfter: p.NotAfter, signerKid: e.Signature.Kid,
	}, nil
}

// currentFor returns the policy a group must run: among the active
// versions whose signed targets.groups contain the group, the one with the
// highest issued_seq. Caller holds f.mu.
//
// A group that is not bound to any policy (policy_id null, for instance
// after an unbind) runs nothing: its sources stop at once, whatever the
// signed targets of an older active version still say (red team RT3-FLEET-1).
func (f *Fleet) currentFor(group string) *activePolicy {
	if g := f.groups[group]; g != nil && g.policyID == "" {
		return nil
	}
	var best *activePolicy
	for _, ap := range f.active {
		if slices.Contains(ap.groups, group) && (best == nil || ap.seq > best.seq) {
			best = ap
		}
	}
	return best
}

// maxActiveSeqLocked is the highest issued_seq among the active versions
// (0 when none). Caller holds f.mu.
func (f *Fleet) maxActiveSeqLocked() int64 {
	var m int64
	for _, ap := range f.active {
		m = max(m, ap.seq)
	}
	return m
}

// killedLocked reports the effective kill switch of a source. Caller holds f.mu.
func (f *Fleet) killedLocked(s *memSource) bool {
	if f.killAll || s.killed {
		return true
	}
	g := f.groups[s.group]
	return g != nil && g.killed
}

// ---------------------------------------------------------------------------
// Wiring

// Paths of the source-facing endpoints (api/fleet-api.v1.openapi.yaml).
const (
	PathEnroll    = "/fleet/v1/enroll"
	PathPolicy    = "/fleet/v1/policy"
	PathHeartbeat = "/fleet/v1/heartbeat"
	PathRenew     = "/fleet/v1/renew"
	// AdminPrefix is where the admin API is mounted on the admin listener.
	AdminPrefix = "/api/v1/fleet"
)

// Register mounts the source endpoints on the intake listener, the admin
// API on the admin listener, installs the intake TLS hooks (client CA pool,
// revocation check, managed server certificate) and a readiness check.
func (f *Fleet) Register(srv *server.Server) {
	srv.MountIntake(PathEnroll, http.HandlerFunc(f.handleEnroll), server.AllowNoClientCert())
	srv.MountIntake(PathPolicy, http.HandlerFunc(f.handlePolicy))
	srv.MountIntake(PathHeartbeat, http.HandlerFunc(f.handleHeartbeat))
	srv.MountIntake(PathRenew, http.HandlerFunc(f.handleRenew))
	srv.Mount(AdminPrefix, f.AdminHandler(), auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyApprover, auth.RoleAdmin)
	srv.SetIntakeTLS(f.IntakeTLSHooks())
	srv.AddReadinessCheck("fleet", func(ctx context.Context) error {
		f.mu.RLock()
		n := len(f.keys)
		f.mu.RUnlock()
		if n == 0 {
			return errors.New("no policy signing key known")
		}
		return nil
	})
}

// IntakeTLSHooks returns the hooks for server.SetIntakeTLS: the Fleet root
// as client CA, a revocation and identity check on every handshake, and
// the managed server certificate (used when intake.tls.managed is true;
// it chains to the root pinned by enrollment tokens).
func (f *Fleet) IntakeTLSHooks() server.IntakeTLSHooks {
	return server.IntakeTLSHooks{
		ClientCAs:  func() *x509.CertPool { return f.ca.pool },
		VerifyPeer: f.verifyPeer,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return f.ca.serverCertificate()
		},
	}
}

// Errors of the TLS verification hook.
var (
	ErrUnknownCert   = errors.New("fleet: certificate not issued by fleet or expired")
	ErrRevokedCert   = errors.New("fleet: certificate revoked")
	ErrSourceRevoked = errors.New("fleet: source revoked")
)

// verifyPeer runs after chain verification: the certificate must carry a
// source id, be one Fleet issued (known serial) and be neither revoked nor
// belong to a revoked source.
func (f *Fleet) verifyPeer(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
	id, ok := SourceIDFromCert(leaf)
	if !ok {
		return ErrUnknownCert
	}
	serial := hex.EncodeToString(leaf.SerialNumber.Bytes())
	f.mu.RLock()
	defer f.mu.RUnlock()
	c, ok := f.certs[serial]
	if !ok || c.source != id {
		return ErrUnknownCert
	}
	if c.revoked {
		return ErrRevokedCert
	}
	if s := f.sources[id]; s == nil || s.revoked {
		return ErrSourceRevoked
	}
	return nil
}

// Run performs periodic maintenance until ctx is done: automatic renewal
// of expiring policies through keyguard, signing key refresh and pruning
// of expired certificates and ID tokens.
func (f *Fleet) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	obs := time.NewTicker(f.opts.Observe.Interval)
	defer obs.Stop()
	for {
		f.Maintain(ctx)
		for done := false; !done; {
			select {
			case <-ctx.Done():
				return
			case <-obs.C:
				f.ObserveTick(ctx)
			case <-t.C:
				done = true
			}
		}
	}
}

// Maintain runs one maintenance pass (exported for tests and for callers
// that schedule it themselves).
func (f *Fleet) Maintain(ctx context.Context) {
	if err := f.refreshSigningKeys(ctx); err != nil {
		f.log.Warn("fleet: signing key refresh failed", "err", err)
	}
	f.refreshSignerStatus(ctx)
	f.RenewExpiringPolicies(ctx)
	f.ObserveTick(ctx)
	now := f.now()
	f.mu.Lock()
	for s, c := range f.certs {
		if !now.Before(c.notAfter) {
			delete(f.certs, s)
		}
	}
	for k, t := range f.idTokens {
		if now.Sub(t.at) > idTokenMaxAge {
			delete(f.idTokens, k)
		}
	}
	f.mu.Unlock()
}

// SourceView is what other components (the intake) need to know about an
// enrolled source.
type SourceView struct {
	ID              string
	Group           string
	ServiceName     string   // assigned at enrollment, fixed in the certificate
	AllowedServices []string // allowed for the group (current)
	Revoked         bool
	// Killed is the effective kill switch (global, group or source): the
	// intake must reject the source's events while it is on.
	Killed bool
}

// Source returns the current view of a source.
func (f *Fleet) Source(id string) (SourceView, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s := f.sources[id]
	if s == nil {
		return SourceView{}, false
	}
	v := SourceView{ID: s.id, Group: s.group, ServiceName: s.service, Revoked: s.revoked, Killed: f.killedLocked(s)}
	if g := f.groups[s.group]; g != nil {
		v.AllowedServices = slices.Clone(g.allowed)
	}
	return v, true
}

// SignedPolicyBody returns the compiled body of a policy version signed by
// keyguard, by hash ("sha256:<hex>"). Every signed version is kept, because
// events produced under an older version can still arrive.
func (f *Fleet) SignedPolicyBody(hash string) ([]byte, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, ok := f.signed[hash]
	return b, ok
}

// KnownPolicyHashes returns the hashes of every signed policy version.
func (f *Fleet) KnownPolicyHashes() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.signed))
	for h := range f.signed {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}
