package config

import (
	"encoding/hex"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// Keyguard tells tt-core how to reach tt keyguard, the zone-B key custodian
// (docs/spec/keyguard.md). tt-core holds no key of keyguard: only its own
// TLS client identity.
type Keyguard struct {
	// URL is "https://host:port" (mTLS, the production layout: keyguard on
	// another host or pod) or "unix:///absolute/path.sock" (same host,
	// test installations and `tt dev up`). Required.
	URL string `yaml:"url"`
	// ClientCertFile and ClientKeyFile are tt-core's client identity
	// (mTLS only; keyguard pins its SPKI).
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
	// CAFile verifies keyguard's certificate chain and host name;
	// ServerPin ("sha256:<hex SPKI>", `tt keyguard pin`) pins its key. At
	// least one is required for mTLS; with both, both are checked.
	CAFile    string `yaml:"ca_file"`
	ServerPin string `yaml:"server_pin"`
	// Timeout bounds one keyguard call (pack signing can take long).
	Timeout time.Duration `yaml:"timeout"`
}

// Transport returns "unix", "mtls" or "".
func (k Keyguard) Transport() string {
	switch {
	case strings.HasPrefix(k.URL, "unix://"):
		return "unix"
	case strings.HasPrefix(k.URL, "https://"):
		return "mtls"
	}
	return ""
}

// Fleet configures source enrollment, the Fleet CA and policy distribution.
type Fleet struct {
	// PublicURL is the base URL sources use to reach the intake listener
	// (embedded in enrollment snippets, host of the managed intake
	// certificate), e.g. https://tt-core.internal:4318. Default, only when
	// intake.addr is a loopback address: https://localhost:<intake port>.
	PublicURL string `yaml:"public_url"`
	// ServerNames are the DNS names and IPs of the managed intake
	// certificate. Default: the host of public_url (plus 127.0.0.1 and ::1
	// for localhost).
	ServerNames []string `yaml:"server_names"`
	// CADir holds fleet-ca.crt and fleet-ca.key (mode 0600). Default:
	// "fleet-ca" next to the database file.
	CADir string `yaml:"ca_dir"`
	// ClientCertTTL is the validity of source client certificates.
	ClientCertTTL time.Duration `yaml:"client_cert_ttl"`
	// HeartbeatInterval and PolicyPollInterval are sent to the sources.
	HeartbeatInterval  time.Duration `yaml:"heartbeat_interval"`
	PolicyPollInterval time.Duration `yaml:"policy_poll_interval"`
	// PolicyMaxAge: a source stops capturing when tt-core has not confirmed
	// its policy for this long (policy.md 4).
	PolicyMaxAge time.Duration `yaml:"policy_max_age"`
	// PolicyValidity is not_after - created_at of signed policies (keyguard
	// caps it with TT_KEYGUARD_POLICY_MAX_VALIDITY).
	PolicyValidity time.Duration `yaml:"policy_validity"`
	// EnrollRateLimit throttles POST /fleet/v1/enroll.
	EnrollRateLimit EnrollRateLimit `yaml:"enroll_rate_limit"`
	// KeyRotation guards the revocation of a policy signing key.
	KeyRotation KeyRotation `yaml:"key_rotation"`
	// LastErrorsWindow is the look-back of a source's last_errors (default
	// 15m, at most 1h): older errors are not listed.
	LastErrorsWindow time.Duration `yaml:"last_errors_window"`
	// EgressHosts are the host or host:port names applications use to reach
	// tt-egress (for example "tt-egress:9090"), besides the hostnames the
	// egress sources report: an SDK calling one of them is capturing the
	// same call as tt-egress (double_capture warning).
	EgressHosts []string `yaml:"egress_hosts"`
	// Observe configures the observe phase (policy.md 7): tt-core derives by
	// itself, without approval, a policy version that masks identifiers.
	Observe Observe `yaml:"observe"`
	// Sanitizer configures what tt-core writes into the compiled policies
	// for the sources' sanitizer (spec v1.19).
	Sanitizer SanitizerDefaults `yaml:"sanitizer"`
}

// SanitizerDefaults: the bodies object tt-core writes into every compiled
// policy whose author does not set one (sanitizer.md 22, spec v1.19). Sources
// older than v1.19 refuse a policy with bodies and keep the previous one:
// set Bodies false until every source of the installation is updated.
type SanitizerDefaults struct {
	// Bodies writes the bodies object (default true).
	Bodies bool `yaml:"bodies"`
	// XML, Multipart and Docs are its switches (default true).
	XML       bool `yaml:"xml"`
	Multipart bool `yaml:"multipart"`
	Docs      bool `yaml:"docs"`
	// MaxLargeBodyBytes is the large-body limit (default 8 MiB, 0 = off,
	// at most 64 MiB): a source keeps this many body bytes in memory.
	MaxLargeBodyBytes int64 `yaml:"max_large_body_bytes"`
	// LargeArray and LargeNestedArray are the elements kept in the outer and
	// nested arrays of a large body (default 50 and 5).
	LargeArray       int `yaml:"large_array"`
	LargeNestedArray int `yaml:"large_nested_array"`
}

// Observe: after the starter policy is active, once MinEvents calls were
// seen or After has passed (with at least one call), tt-core applies hmac
// to the fields it classifies as identifiers and sets the automatic
// identity detected from the data (bearer JWT sub, or the request header
// that behaves like a user id). keyguard must sign observe-safe
// changes without approvals (TT_KEYGUARD_OBSERVE_AUTO, default true).
type Observe struct {
	Enabled   bool          `yaml:"enabled"`
	After     time.Duration `yaml:"after"`
	MinEvents int           `yaml:"min_events"`
	// Interval of the observe pass (default 1m).
	Interval time.Duration `yaml:"interval"`
	// Codes lets the observe version put `code` on status- and code-like
	// fields (sanitizer.md 5.6, default true). Sources older than v1.11
	// refuse a policy with `code` and keep the previous one: set it false
	// until every source of the installation is updated.
	Codes bool `yaml:"codes"`
	// CodeDigits lets the observe version propose code(alnum), the code
	// shape with digits and dots (sanitizer.md 5.6, spec v1.19, default
	// true). Sources older than v1.19 refuse it: set it false until they
	// are updated (Codes false turns off both).
	CodeDigits bool `yaml:"code_digits"`
	// GraphQL lets the observe version put `graphql` on the document of the
	// GraphQL endpoints it recognizes and on the names of their
	// introspection result (sanitizer.md 5.7, default true). Sources older
	// than v1.14 refuse a policy with `graphql`: set it false until every
	// source is updated.
	GraphQL bool `yaml:"graphql"`
}

// KeyRotation: tt-core refuses to revoke a policy signing key until at
// least MinConfirmed (0..1, default 1 = 100%) of the sources seen in the
// last Window (default 24 h) confirmed, through their heartbeat, that they
// trust another valid key (policy.md 3.1). 0 disables the check (emergency
// revocation of a compromised key).
type KeyRotation struct {
	MinConfirmed float64       `yaml:"min_confirmed"`
	Window       time.Duration `yaml:"window"`
}

// EnrollRateLimit holds the per-IP and per-token enrollment buckets.
type EnrollRateLimit struct {
	IP    RateLimit `yaml:"ip"`
	Token RateLimit `yaml:"token"`
}

// Contract configures contract inference and snapshots.
type Contract struct {
	// SnapshotWindow is the snapshot window (aligned to the Unix epoch, UTC
	// days for 24h).
	SnapshotWindow time.Duration `yaml:"snapshot_window"`
	// Grace is how long after a window ends its snapshot runs.
	Grace time.Duration `yaml:"grace"`
	// MinSamples is N: a field is required only when present in every
	// observed object and at least N objects were observed.
	MinSamples int `yaml:"min_samples"`
	// KMin: a keep value is published only when seen for at least k
	// distinct subjects.
	KMin int `yaml:"k_min"`
	// KeepSnapshots per service.
	KeepSnapshots int `yaml:"keep_snapshots"`
}

// Drift configures drift alerts and their webhooks.
type Drift struct {
	// WebhookAllow lists the webhook destinations ("host", "host:port",
	// "*.suffix"). Empty (default): no webhook can be configured. Names are
	// re-checked at delivery on the address they resolve to: an internal
	// address (loopback, link-local, RFC 1918, CGNAT, ULA, multicast) is
	// reached only when that exact IP literal is an entry.
	WebhookAllow []string `yaml:"webhook_allow"`
	// WebhookAllowHTTP accepts http:// destinations (default https only).
	WebhookAllowHTTP bool `yaml:"webhook_allow_http"`
	// NotifyNonBreaking sends non-breaking changes to webhooks too.
	NotifyNonBreaking bool `yaml:"notify_non_breaking"`
}

// Miner configures the rule miner.
type Miner struct {
	// Schedule is the interval of the mining job; 0 disables the schedule
	// (runs are then started from the admin API only).
	Schedule time.Duration `yaml:"schedule"`
	// Window is the event-time window of a run (ending now).
	Window time.Duration `yaml:"window"`
	// KMin: link keys, rules and outcomes need at least k distinct subjects.
	KMin int `yaml:"k_min"`
	// MaxEvents bounds the events loaded by one run (memory guard: about
	// 1.5 KB of memory per event at the peak of a run). A window with more
	// events is narrowed to its newest MaxEvents. 0 (the default) sizes it
	// from the memory limit (cgroup, /proc/meminfo, GOMEMLIMIT): half of it
	// per heavy-job slot, between 100 000 and 5 000 000 events; 1 000 000
	// without a known limit. A larger value is lowered to what fits when
	// the limit is known (core/heavy.go).
	MaxEvents int `yaml:"max_events"`
	// CandidateMaxEvents (rules v1.9, C0): a group with more events than
	// this is not mined a second time with a lower k for the candidates
	// below the threshold (the second pass costs about as much as the
	// first). 0 = the default (2 000 000); -1 turns the candidates off.
	CandidateMaxEvents int `yaml:"candidate_max_events"`
	// MinBirthShare is the least share of an entity's objects whose creation
	// exchange was captured (0 = default 0.6). Objects first seen without
	// their creation (app restarts, retention cutoffs, sampling) count as
	// pre-existing, so this is a floor on evidence, not on completeness.
	MinBirthShare float64 `yaml:"min_birth_share"`
	// StaleRuns is how many consecutive runs an approved rule must fail
	// before it becomes stale (0 = default 3). One bad run never does.
	StaleRuns int `yaml:"stale_runs"`
	// MinHorizon is the least span of observed traffic (in capture time) a
	// run needs before it decides any rule, and the least completion horizon
	// of a cause (0 = default 1h). Lower it only for an accelerated demo,
	// whose effects complete in seconds of real time.
	MinHorizon time.Duration `yaml:"min_horizon"`
}

// World configures archetypes and synthetic worlds.
type World struct {
	// KMin is the minimum archetype size (distinct real subjects).
	KMin int `yaml:"k_min"`
	// ProfileWindow is the event window of archetype builds.
	ProfileWindow time.Duration `yaml:"profile_window"`
	// Locale of invented names: it or en.
	Locale string `yaml:"locale"`
}

// Gate configures the publication gate and the pack writer.
type Gate struct {
	// KMin of published values, outcomes and archetypes.
	KMin int `yaml:"k_min"`
	// ValidDays is the default validity of a pack (manifest not_after)
	// when the build request does not give one.
	ValidDays int `yaml:"valid_days"`
	// PIIDetectors documents that the PII detectors (e-mail, phone, IBAN,
	// card, fiscal code, IP, ...) run on every pack. It cannot be turned
	// off: false is a configuration error.
	PIIDetectors bool `yaml:"pii_detectors"`
}

// Mock configures the mocks connected to the console (Mock page):
// the URL they use to reach tt-core and, optionally, the mocks tt-core
// starts itself in Kubernetes.
type Mock struct {
	// ConsoleURL is the URL of tt-core as the mocks see it (https://...).
	// Empty: the snippets use the URL of the browser; required for
	// mock.kubernetes (the URL inside the cluster).
	ConsoleURL string `yaml:"console_url"`
	// ConsoleCAFile is a PEM bundle of the CA of the admin certificate,
	// given to the managed mocks ("" when it is a public CA).
	ConsoleCAFile string `yaml:"console_ca_file"`
	// Image of the mock container; default ghcr.io/ivseb/traffic-twin:<version>.
	Image string `yaml:"image"`
	// ReportInterval bounds how long the console holds a report of a mock
	// (long poll, default 3s): the delay of the journal on the Mock page.
	ReportInterval time.Duration  `yaml:"report_interval"`
	Kubernetes     MockKubernetes `yaml:"kubernetes"`
}

// MockKubernetes lets tt-core start the mocks in one namespace of its
// cluster (Deployment, Service, Secret, OpenShift Route), with the RBAC of
// deploy/helm/tt-core (mockManager).
type MockKubernetes struct {
	Enabled bool `yaml:"enabled"`
	// Namespace of the mocks (default: the namespace of tt-core).
	Namespace       string `yaml:"namespace"`
	ImagePullPolicy string `yaml:"image_pull_policy"`
	// ServiceAccount of the mock pods (no token is mounted).
	ServiceAccount string `yaml:"service_account"`
	CPURequest     string `yaml:"cpu_request"`
	MemoryRequest  string `yaml:"memory_request"`
	CPULimit       string `yaml:"cpu_limit"`
	MemoryLimit    string `yaml:"memory_limit"`
	// Route: auto (when the cluster has OpenShift routes), on or off.
	Route string `yaml:"route"`
}

// Retention configures how long zone-B data is kept (docs/DATA_LIFECYCLE.md).
type Retention struct {
	// Events is how long stored raw events and the token index are kept
	// (by reception time): 1 to 365 days, default 7. Before deletion every
	// event is counted into the rollups (Rollups).
	Events time.Duration `yaml:"events"`
	// PurgeInterval is how often the purge and the maintenance job run.
	PurgeInterval time.Duration `yaml:"purge_interval"`
	// Exports is how long export archives (pack exports, event exports)
	// stay downloadable.
	Exports time.Duration `yaml:"exports"`

	Rollups   Rollups           `yaml:"rollups"`
	Snapshots SnapshotRetention `yaml:"snapshots"`
	Audit     AuditRetention    `yaml:"audit"`
	// Deliveries: finished webhook deliveries (0 keeps them).
	Deliveries time.Duration `yaml:"deliveries"`
	// ResolvedAlerts: drift alerts resolved longer ago (0 keeps them).
	ResolvedAlerts time.Duration `yaml:"resolved_alerts"`
	// MinerRuns: run records older than this go, the newest KeepMinerRuns stay.
	MinerRuns     time.Duration  `yaml:"miner_runs"`
	KeepMinerRuns int            `yaml:"keep_miner_runs"`
	Packs         PackRetention  `yaml:"packs"`
	Worlds        WorldRetention `yaml:"worlds"`
	Fleet         FleetRetention `yaml:"fleet"`
	// ReleasedQuarantines: released quarantine records older than this go.
	ReleasedQuarantines time.Duration `yaml:"released_quarantines"`
}

// DefaultIntakeAddr binds the intake to loopback only.
const DefaultIntakeAddr = "127.0.0.1:4318"

func defaultComponents(c *Config) {
	c.Keyguard = Keyguard{Timeout: 2 * time.Minute}
	c.Fleet = Fleet{
		ClientCertTTL:      7 * 24 * time.Hour,
		HeartbeatInterval:  30 * time.Second,
		PolicyPollInterval: 60 * time.Second,
		PolicyMaxAge:       24 * time.Hour,
		PolicyValidity:     30 * 24 * time.Hour,
		KeyRotation:        KeyRotation{MinConfirmed: 1, Window: 24 * time.Hour},
		Observe:            Observe{Enabled: true, After: 15 * time.Minute, MinEvents: 200, Interval: time.Minute, Codes: true, CodeDigits: true, GraphQL: true},
		Sanitizer: SanitizerDefaults{Bodies: true, XML: true, Multipart: true, Docs: true, MaxLargeBodyBytes: 8 << 20,
			LargeArray: 50, LargeNestedArray: 5},
		EnrollRateLimit: EnrollRateLimit{
			IP:    RateLimit{RequestsPerMinute: 60, Burst: 30},
			Token: RateLimit{RequestsPerMinute: 120, Burst: 60},
		},
	}
	c.Contract = Contract{SnapshotWindow: 24 * time.Hour, Grace: 5 * time.Minute, MinSamples: 20, KMin: 20, KeepSnapshots: 400}
	c.Drift = Drift{NotifyNonBreaking: true}
	c.Miner = Miner{Schedule: 6 * time.Hour, Window: 7 * 24 * time.Hour, KMin: 20, MaxEvents: 0, MinBirthShare: 0.6, StaleRuns: 3}
	c.World = World{KMin: 20, ProfileWindow: 30 * 24 * time.Hour, Locale: "it"}
	c.Gate = Gate{KMin: 20, ValidDays: 30, PIIDetectors: true}
	c.Retention = Retention{Events: 7 * 24 * time.Hour, PurgeInterval: time.Hour, Exports: 24 * time.Hour}
	c.Mock = Mock{ReportInterval: 3 * time.Second, Kubernetes: MockKubernetes{Route: "auto", CPURequest: "50m", MemoryRequest: "64Mi", MemoryLimit: "512Mi"}}
}

// FleetPublicURL returns fleet.public_url, or the loopback default derived
// from intake.addr ("" when none applies).
func (c *Config) FleetPublicURL() string {
	if c.Fleet.PublicURL != "" {
		return strings.TrimSuffix(c.Fleet.PublicURL, "/")
	}
	host, port, err := net.SplitHostPort(c.Intake.Addr)
	if err != nil || !isLoopbackHost(host) {
		return ""
	}
	return "https://localhost:" + port
}

// FleetServerNames returns fleet.server_names or the default derived from
// the public URL.
func (c *Config) FleetServerNames() []string {
	if len(c.Fleet.ServerNames) > 0 {
		return c.Fleet.ServerNames
	}
	u, err := url.Parse(c.FleetPublicURL())
	if err != nil || u.Hostname() == "" {
		return nil
	}
	if h := u.Hostname(); h == "localhost" {
		return []string{"localhost", "127.0.0.1", "::1"}
	}
	return []string{u.Hostname()}
}

func validateComponents(c *Config, add func(string, string, ...any)) {
	// Keyguard.
	k := c.Keyguard
	switch k.Transport() {
	case "":
		if k.URL == "" {
			add("keyguard.url", "required: tt-core signs nothing itself (for a local trial use `tt dev up`)")
		} else {
			add("keyguard.url", "must be https://host:port or unix:///absolute/path")
		}
	case "unix":
		p := strings.TrimPrefix(k.URL, "unix://")
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "?#") {
			add("keyguard.url", "unix socket path must be absolute")
		}
		if k.ClientCertFile != "" || k.ClientKeyFile != "" || k.CAFile != "" || k.ServerPin != "" {
			add("keyguard", "client_cert_file, client_key_file, ca_file and server_pin apply to https only")
		}
	case "mtls":
		u, err := url.Parse(k.URL)
		if err != nil || u.Host == "" || u.Port() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			add("keyguard.url", "must be https://host:port")
		}
		if k.ClientCertFile == "" || k.ClientKeyFile == "" {
			add("keyguard", "client_cert_file and client_key_file are required for https (keyguard pins tt-core's certificate)")
		}
		if k.CAFile == "" && k.ServerPin == "" {
			add("keyguard", "set ca_file or server_pin (or both) to authenticate keyguard")
		}
		if k.ServerPin != "" && !validPin(k.ServerPin) {
			add("keyguard.server_pin", "must be sha256:<64 hex digits> (tt keyguard pin CERT.pem)")
		}
	}
	if k.Timeout < time.Second || k.Timeout > 10*time.Minute {
		add("keyguard.timeout", "must be between 1s and 10m")
	}

	// Fleet.
	f := c.Fleet
	if c.Intake.Addr != "" {
		pub := c.FleetPublicURL()
		if pub == "" {
			add("fleet.public_url", "required when intake.addr is not a loopback address")
		} else if u, err := url.Parse(pub); err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
			add("fleet.public_url", "must be https://host[:port]")
		}
	}
	for _, n := range f.ServerNames {
		if n == "" || (strings.ContainsAny(n, " /:@") && net.ParseIP(n) == nil) {
			add("fleet.server_names", "invalid name %q", n)
		}
	}
	durIn := func(key string, d, lo, hi time.Duration) {
		if d < lo || d > hi {
			add(key, "must be between %s and %s", lo, hi)
		}
	}
	durIn("fleet.client_cert_ttl", f.ClientCertTTL, time.Hour, 90*24*time.Hour)
	durIn("fleet.heartbeat_interval", f.HeartbeatInterval, 10*time.Millisecond, 10*time.Minute)
	durIn("fleet.policy_poll_interval", f.PolicyPollInterval, 10*time.Millisecond, time.Hour)
	durIn("fleet.policy_max_age", f.PolicyMaxAge, time.Minute, 30*24*time.Hour)
	durIn("fleet.policy_validity", f.PolicyValidity, 2*24*time.Hour, 365*24*time.Hour)
	durIn("fleet.key_rotation.window", f.KeyRotation.Window, time.Minute, 90*24*time.Hour)
	durIn("fleet.observe.after", f.Observe.After, time.Second, 7*24*time.Hour)
	durIn("fleet.observe.interval", f.Observe.Interval, 10*time.Millisecond, time.Hour)
	if f.Observe.MinEvents < 1 || f.Observe.MinEvents > 1000000 {
		add("fleet.observe.min_events", "must be between 1 and 1000000")
	}
	if s := f.Sanitizer; s.MaxLargeBodyBytes < 0 || s.MaxLargeBodyBytes > 64<<20 {
		add("fleet.sanitizer.max_large_body_bytes", "must be between 0 and 67108864")
	}
	if s := f.Sanitizer; s.LargeArray < 0 || s.LargeArray > 1024 || s.LargeNestedArray < 0 || s.LargeNestedArray > 1024 {
		add("fleet.sanitizer.large_array", "large_array and large_nested_array must be between 0 and 1024")
	}
	if f.KeyRotation.MinConfirmed < 0 || f.KeyRotation.MinConfirmed > 1 {
		add("fleet.key_rotation.min_confirmed", "must be between 0 and 1")
	}
	for key, rl := range map[string]RateLimit{"fleet.enroll_rate_limit.ip": f.EnrollRateLimit.IP, "fleet.enroll_rate_limit.token": f.EnrollRateLimit.Token} {
		if rl.RequestsPerMinute < 1 || rl.RequestsPerMinute > 100000 || rl.Burst < 1 || rl.Burst > 10000 {
			add(key, "requests_per_minute must be in [1, 100000] and burst in [1, 10000]")
		}
	}

	// k-anonymity thresholds: 2 is the floor of the gate; below 5 the
	// guarantee is weak, but small trials need it.
	kIn := func(key string, v int) {
		if v < 2 || v > 10000 {
			add(key, "must be between 2 and 10000")
		}
	}
	kIn("contract.k_min", c.Contract.KMin)
	kIn("miner.k_min", c.Miner.KMin)
	kIn("world.k_min", c.World.KMin)
	kIn("gate.k_min", c.Gate.KMin)
	if c.World.KMin < c.Gate.KMin {
		add("world.k_min", "must be >= gate.k_min (the gate refuses smaller archetypes)")
	}
	if c.Contract.KMin < c.Gate.KMin {
		add("contract.k_min", "must be >= gate.k_min (the gate refuses values and linked fields seen by fewer subjects: every pack build would fail)")
	}
	if c.Miner.KMin < c.Gate.KMin {
		add("miner.k_min", "must be >= gate.k_min (the gate refuses rules and outcomes seen by fewer subjects)")
	}

	// Contract.
	durIn("contract.snapshot_window", c.Contract.SnapshotWindow, time.Hour, 7*24*time.Hour)
	durIn("contract.grace", c.Contract.Grace, 0, 6*time.Hour)
	if c.Contract.MinSamples < 1 || c.Contract.MinSamples > 100000 {
		add("contract.min_samples", "must be between 1 and 100000")
	}
	if c.Contract.KeepSnapshots < 1 || c.Contract.KeepSnapshots > 100000 {
		add("contract.keep_snapshots", "must be between 1 and 100000")
	}

	// Drift.
	for _, a := range c.Drift.WebhookAllow {
		if a == "" || strings.ContainsAny(a, " /?#@") || a == "*" || strings.HasPrefix(a, "*") && !strings.HasPrefix(a, "*.") {
			add("drift.webhook_allow", "invalid entry %q (host, host:port or *.suffix)", a)
		}
	}

	// Miner.
	if c.Miner.Schedule != 0 {
		durIn("miner.schedule", c.Miner.Schedule, 5*time.Minute, 7*24*time.Hour)
	}
	durIn("miner.window", c.Miner.Window, time.Hour, 90*24*time.Hour)
	if c.Miner.CandidateMaxEvents < -1 || c.Miner.CandidateMaxEvents > 100_000_000 {
		add("miner.candidate_max_events", "must be -1 (off), 0 (default) or at most 100000000")
	}
	if c.Miner.MaxEvents != 0 && (c.Miner.MaxEvents < 1000 || c.Miner.MaxEvents > 100_000_000) {
		add("miner.max_events", "must be 0 (automatic) or between 1000 and 100000000")
	}
	if c.Miner.MinBirthShare < 0.1 || c.Miner.MinBirthShare > 1 {
		add("miner.min_birth_share", "must be between 0.1 and 1")
	}
	if c.Miner.StaleRuns < 1 || c.Miner.StaleRuns > 100 {
		add("miner.stale_runs", "must be between 1 and 100")
	}

	// World and gate.
	durIn("world.profile_window", c.World.ProfileWindow, time.Hour, 365*24*time.Hour)
	if c.World.Locale != "it" && c.World.Locale != "en" {
		add("world.locale", "must be it or en")
	}
	if c.Gate.ValidDays < 1 || c.Gate.ValidDays > 365 {
		add("gate.valid_days", "must be between 1 and 365")
	}
	if !c.Gate.PIIDetectors {
		add("gate.pii_detectors", "cannot be disabled: the PII detectors always run on every pack")
	}

	// Mock.
	if u := c.Mock.ConsoleURL; u != "" {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" || pu.RawQuery != "" || pu.User != nil {
			add("mock.console_url", "must be an http(s) URL without query or credentials")
		}
	}
	durIn("mock.report_interval", c.Mock.ReportInterval, time.Second, 5*time.Minute)
	if k := c.Mock.Kubernetes; k.Enabled {
		if c.Mock.ConsoleURL == "" {
			add("mock.console_url", "is required with mock.kubernetes.enabled (the URL of tt-core seen from the mock pods)")
		}
		switch k.Route {
		case "auto", "on", "off":
		default:
			add("mock.kubernetes.route", "must be auto, on or off")
		}
	}

	// Retention.
	durIn("retention.events", c.Retention.Events, 24*time.Hour, 365*24*time.Hour)
	durIn("retention.purge_interval", c.Retention.PurgeInterval, time.Minute, 24*time.Hour)
	durIn("retention.exports", c.Retention.Exports, time.Minute, 30*24*time.Hour)
}

func validPin(p string) bool {
	h, ok := strings.CutPrefix(p, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}
