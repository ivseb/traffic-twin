package keyguard

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Environment variables read by tt keyguard (and only by it: tt-core never
// reads any of them, threat model G12).
const (
	EnvListen          = "TT_KEYGUARD_LISTEN"         // host:port for mTLS
	EnvSocket          = "TT_KEYGUARD_SOCKET"         // Unix socket path (same host only)
	EnvSocketMode      = "TT_KEYGUARD_SOCKET_MODE"    // 0600 (default) or 0660
	EnvTLSCert         = "TT_KEYGUARD_TLS_CERT_FILE"  // server certificate (PEM)
	EnvTLSKey          = "TT_KEYGUARD_TLS_KEY_FILE"   // server private key (PEM, mode 0600)
	EnvClientPins      = "TT_KEYGUARD_CLIENT_PINS"    // sha256:<hex SPKI> of tt-core's client certificate, comma separated
	EnvClientCA        = "TT_KEYGUARD_CLIENT_CA_FILE" // optional: also verify the client chain
	EnvDB              = "TT_KEYGUARD_DB"             // SQLite path (separate from tt-core's)
	EnvHMACKeysFile    = "TT_KEYGUARD_HMAC_KEYS_FILE" // kid:base64url lines
	EnvHMACKeys        = "TT_KEYGUARD_HMAC_KEYS"      // inline alternative
	EnvPolicyKeyFile   = "TT_KEYGUARD_POLICY_SIGNING_KEY_FILE"
	EnvPolicyKey       = "TT_KEYGUARD_POLICY_SIGNING_KEY"
	EnvPackKeyFile     = "TT_KEYGUARD_PACK_SIGNING_KEY_FILE"
	EnvPackKey         = "TT_KEYGUARD_PACK_SIGNING_KEY"
	EnvRevokedKids     = "TT_KEYGUARD_REVOKED_KIDS" // comma separated kids (HMAC or signing)
	EnvOIDCIssuer      = "TT_KEYGUARD_OIDC_ISSUER"
	EnvOIDCAudience    = "TT_KEYGUARD_OIDC_AUDIENCE"
	EnvOIDCJWKSFile    = "TT_KEYGUARD_OIDC_JWKS_FILE"
	EnvOIDCJWKSURL     = "TT_KEYGUARD_OIDC_JWKS_URL"
	EnvOIDCRolesClaim  = "TT_KEYGUARD_OIDC_ROLES_CLAIM"  // claim (string or list) carrying the approver's groups or roles
	EnvOIDCRoleMapping = "TT_KEYGUARD_OIDC_ROLE_MAPPING" // group=role pairs, comma separated (empty: claim values are role names)
	EnvAlertWebhook    = "TT_KEYGUARD_ALERT_WEBHOOK"
	EnvOpeningApproval = "TT_KEYGUARD_OPENING_APPROVALS" // 1 or 2 (default 2)
	EnvAdminOverride   = "TT_KEYGUARD_ADMIN_OVERRIDE"    // true (default) or false
	EnvObserveAuto     = "TT_KEYGUARD_OBSERVE_AUTO"      // true (default) or false: sign observe-safe changes without approvals
	EnvMatchMaxBatch   = "TT_KEYGUARD_MATCH_MAX_BATCH"
	EnvMatchInterval   = "TT_KEYGUARD_MATCH_INTERVAL"
	EnvMatchBudget     = "TT_KEYGUARD_MATCH_DAILY_BUDGET"
	EnvPackInterval    = "TT_KEYGUARD_PACK_INTERVAL"
	EnvBloomCapacity   = "TT_KEYGUARD_BLOOM_CAPACITY"
	EnvRetention       = "TT_KEYGUARD_FILTER_RETENTION"
	EnvAuditArchive    = "TT_KEYGUARD_AUDIT_ARCHIVE_AFTER" // 0 disables (the log stays whole)
	EnvAuditArchiveDir = "TT_KEYGUARD_AUDIT_ARCHIVE_DIR"   // default audit-archive next to the database
	EnvSnapshot        = "TT_KEYGUARD_SNAPSHOT_INTERVAL"
	EnvPolicyValidity  = "TT_KEYGUARD_POLICY_MAX_VALIDITY"
	EnvLogLevel        = "TT_KEYGUARD_LOG_LEVEL"
	EnvLogFormat       = "TT_KEYGUARD_LOG_FORMAT"
)

// Defaults (keyguard.md 3.1, policy.md 2).
const (
	DefaultDBPath        = "data/tt-keyguard.db"
	DefaultMatchMaxBatch = 10000
	DefaultMatchInterval = time.Second
	DefaultMatchBudget   = 5000000
	DefaultPackInterval  = time.Second
	DefaultBloomCapacity = 1000000
	DefaultRetention     = 90 * 24 * time.Hour
	DefaultAuditArchive  = 180 * 24 * time.Hour
	// FingerprintMargin is how long after its use the fingerprint of an
	// approval ID token is kept: far beyond ApprovalTokenMaxAge plus clock
	// skew, after which keyguard refuses the token as stale anyway.
	FingerprintMargin     = 7 * 24 * time.Hour
	DefaultSnapshot       = time.Minute
	DefaultPolicyValidity = 30 * 24 * time.Hour
	// ApprovalTokenMaxAge is how old an approver's ID token may be (keyguard.md 3.2).
	ApprovalTokenMaxAge = 10 * time.Minute
)

// Config configures a keyguard Service and its listener.
type Config struct {
	Listen     string
	Socket     string
	SocketMode uint32
	TLSCert    string
	TLSKey     string
	ClientPins []string
	ClientCA   string
	DBPath     string

	HMACKeys     KeySource
	PolicyKey    KeySource
	PackKey      KeySource
	RevokedKids  map[string]bool
	OIDCIssuer   string
	OIDCAudience string
	OIDCJWKSFile string
	OIDCJWKSURL  string
	// OIDCRolesClaim names the verified ID token claim keyguard reads the
	// approver's roles from (keyguard.md 3.2 step 4); OIDCRoleMapping maps
	// its values (IdP groups) to tt roles. Without a mapping the values
	// are role names.
	OIDCRolesClaim  string
	OIDCRoleMapping map[string][]string
	AlertWebhook    string
	OpeningApprove  int
	AdminOverride   bool
	// ObserveAuto: keyguard signs, without approvals, a change it
	// classifies itself as observe-safe (policy.md 7, spec v1.6).
	ObserveAuto bool

	MatchMaxBatch  int
	MatchInterval  time.Duration
	MatchBudget    int64
	PackInterval   time.Duration
	BloomCapacity  uint64
	Retention      time.Duration
	Snapshot       time.Duration
	PolicyValidity time.Duration
	// AuditArchiveAfter: audit entries older than this leave the database
	// as signed archive segments in AuditArchiveDir (0: never).
	AuditArchiveAfter time.Duration
	AuditArchiveDir   string

	LogLevel  string
	LogFormat string
}

// DefaultConfig returns a configuration with every default set and no
// listener or key.
func DefaultConfig() Config {
	return Config{
		SocketMode:        0o600,
		DBPath:            DefaultDBPath,
		RevokedKids:       map[string]bool{},
		OpeningApprove:    2,
		AdminOverride:     true,
		ObserveAuto:       true,
		MatchMaxBatch:     DefaultMatchMaxBatch,
		MatchInterval:     DefaultMatchInterval,
		MatchBudget:       DefaultMatchBudget,
		PackInterval:      DefaultPackInterval,
		BloomCapacity:     DefaultBloomCapacity,
		Retention:         DefaultRetention,
		Snapshot:          DefaultSnapshot,
		AuditArchiveAfter: DefaultAuditArchive,
		PolicyValidity:    DefaultPolicyValidity,
		LogLevel:          "info",
		LogFormat:         "json",
	}
}

// ConfigFromEnv builds a configuration from environment entries
// ("KEY=value", as os.Environ returns them).
func ConfigFromEnv(environ []string) (Config, error) {
	env := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "TT_KEYGUARD_") {
			env[k] = v
		}
	}
	c := DefaultConfig()
	c.Listen = env[EnvListen]
	c.Socket = env[EnvSocket]
	c.TLSCert = env[EnvTLSCert]
	c.TLSKey = env[EnvTLSKey]
	c.ClientCA = env[EnvClientCA]
	c.ClientPins = splitList(env[EnvClientPins])
	if v := env[EnvDB]; v != "" {
		c.DBPath = v
	}
	c.HMACKeys = KeySource{File: env[EnvHMACKeysFile], Inline: env[EnvHMACKeys]}
	c.PolicyKey = KeySource{File: env[EnvPolicyKeyFile], Inline: env[EnvPolicyKey]}
	c.PackKey = KeySource{File: env[EnvPackKeyFile], Inline: env[EnvPackKey]}
	for _, k := range splitList(env[EnvRevokedKids]) {
		c.RevokedKids[k] = true
	}
	c.OIDCIssuer = env[EnvOIDCIssuer]
	c.OIDCAudience = env[EnvOIDCAudience]
	c.OIDCJWKSFile = env[EnvOIDCJWKSFile]
	c.OIDCJWKSURL = env[EnvOIDCJWKSURL]
	c.OIDCRolesClaim = strings.TrimSpace(env[EnvOIDCRolesClaim])
	if v := env[EnvOIDCRoleMapping]; v != "" {
		c.OIDCRoleMapping = map[string][]string{}
		for _, pair := range splitList(v) {
			g, r, ok := strings.Cut(pair, "=")
			g, r = strings.TrimSpace(g), strings.TrimSpace(r)
			if !ok || g == "" || r == "" {
				return c, fmt.Errorf("keyguard: %s: entries are group=role", EnvOIDCRoleMapping)
			}
			c.OIDCRoleMapping[g] = append(c.OIDCRoleMapping[g], r)
		}
	}
	c.AlertWebhook = env[EnvAlertWebhook]
	var err error
	if v := env[EnvSocketMode]; v != "" {
		m, perr := strconv.ParseUint(v, 8, 32)
		if perr != nil {
			return c, fmt.Errorf("keyguard: %s: not an octal mode", EnvSocketMode)
		}
		c.SocketMode = uint32(m)
	}
	if v := env[EnvOpeningApproval]; v != "" {
		if c.OpeningApprove, err = strconv.Atoi(v); err != nil {
			return c, fmt.Errorf("keyguard: %s must be 1 or 2", EnvOpeningApproval)
		}
	}
	if v := env[EnvAdminOverride]; v != "" {
		if c.AdminOverride, err = strconv.ParseBool(v); err != nil {
			return c, fmt.Errorf("keyguard: %s must be true or false", EnvAdminOverride)
		}
	}
	if v := env[EnvObserveAuto]; v != "" {
		if c.ObserveAuto, err = strconv.ParseBool(v); err != nil {
			return c, fmt.Errorf("keyguard: %s must be true or false", EnvObserveAuto)
		}
	}
	ints := []struct {
		name string
		dst  *int64
	}{{EnvMatchBudget, &c.MatchBudget}}
	for _, it := range ints {
		if v := env[it.name]; v != "" {
			if *it.dst, err = strconv.ParseInt(v, 10, 64); err != nil {
				return c, fmt.Errorf("keyguard: %s: not an integer", it.name)
			}
		}
	}
	if v := env[EnvMatchMaxBatch]; v != "" {
		if c.MatchMaxBatch, err = strconv.Atoi(v); err != nil {
			return c, fmt.Errorf("keyguard: %s: not an integer", EnvMatchMaxBatch)
		}
	}
	if v := env[EnvBloomCapacity]; v != "" {
		if c.BloomCapacity, err = strconv.ParseUint(v, 10, 64); err != nil {
			return c, fmt.Errorf("keyguard: %s: not an integer", EnvBloomCapacity)
		}
	}
	durs := []struct {
		name string
		dst  *time.Duration
	}{
		{EnvMatchInterval, &c.MatchInterval}, {EnvPackInterval, &c.PackInterval}, {EnvRetention, &c.Retention},
		{EnvSnapshot, &c.Snapshot}, {EnvPolicyValidity, &c.PolicyValidity}, {EnvAuditArchive, &c.AuditArchiveAfter},
	}
	for _, d := range durs {
		if v := env[d.name]; v != "" {
			if *d.dst, err = time.ParseDuration(v); err != nil {
				return c, fmt.Errorf("keyguard: %s: not a duration", d.name)
			}
		}
	}
	if v := env[EnvAuditArchiveDir]; v != "" {
		c.AuditArchiveDir = v
	}
	if v := env[EnvLogLevel]; v != "" {
		c.LogLevel = v
	}
	if v := env[EnvLogFormat]; v != "" {
		c.LogFormat = v
	}
	return c, c.Validate()
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate checks the service settings (not the listener: see
// ValidateListener).
func (c *Config) Validate() error {
	switch {
	case c.OpeningApprove != 1 && c.OpeningApprove != 2:
		return fmt.Errorf("keyguard: %s must be 1 or 2", EnvOpeningApproval)
	case c.MatchMaxBatch < 1 || c.MatchMaxBatch > 100000:
		return errors.New("keyguard: match max batch must be between 1 and 100000")
	case c.MatchInterval < 0 || c.PackInterval < 0:
		return errors.New("keyguard: rate intervals must not be negative")
	case c.MatchBudget < 1:
		return errors.New("keyguard: match daily budget must be positive")
	case c.BloomCapacity < 1000 || c.BloomCapacity > 1<<30:
		return errors.New("keyguard: bloom capacity must be between 1000 and 2^30")
	case c.Snapshot < time.Second:
		return errors.New("keyguard: snapshot interval must be at least 1s")
	case c.PolicyValidity < time.Hour:
		return errors.New("keyguard: policy max validity must be at least 1h")
	case c.Retention < 0:
		return errors.New("keyguard: retention must not be negative")
	case c.AuditArchiveAfter != 0 && c.AuditArchiveAfter < 30*24*time.Hour:
		return fmt.Errorf("keyguard: %s must be 0 (never) or at least 720h", EnvAuditArchive)
	case (c.OIDCIssuer == "") != (c.OIDCAudience == ""):
		return fmt.Errorf("keyguard: %s and %s go together", EnvOIDCIssuer, EnvOIDCAudience)
	case c.OIDCIssuer != "" && c.OIDCJWKSFile == "" && c.OIDCJWKSURL == "":
		return fmt.Errorf("keyguard: OIDC needs %s or %s", EnvOIDCJWKSFile, EnvOIDCJWKSURL)
	case c.OIDCIssuer != "" && c.OIDCRolesClaim == "":
		// Roles come from the verified token, never from tt-core (RT3-KG-2).
		return fmt.Errorf("keyguard: OIDC needs %s (approver roles are read from the ID token)", EnvOIDCRolesClaim)
	case c.OIDCIssuer == "" && (c.OIDCRolesClaim != "" || len(c.OIDCRoleMapping) > 0):
		return fmt.Errorf("keyguard: %s and %s need %s", EnvOIDCRolesClaim, EnvOIDCRoleMapping, EnvOIDCIssuer)
	}
	for g, roles := range c.OIDCRoleMapping {
		for _, r := range roles {
			if g == "" || !reUser.MatchString(r) {
				return fmt.Errorf("keyguard: %s: malformed entry", EnvOIDCRoleMapping)
			}
		}
	}
	if c.AlertWebhook != "" {
		u, err := url.Parse(c.AlertWebhook)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("keyguard: %s must be an absolute http(s) URL", EnvAlertWebhook)
		}
	}
	return nil
}

// ValidateListener checks that exactly one transport is configured and,
// for mTLS, that the server certificate and at least one client pin are set.
func (c *Config) ValidateListener() error {
	switch {
	case (c.Listen == "") == (c.Socket == ""):
		return fmt.Errorf("keyguard: set exactly one of %s (mTLS) and %s (Unix socket)", EnvListen, EnvSocket)
	case c.Socket != "" && c.SocketMode != 0o600 && c.SocketMode != 0o660:
		return fmt.Errorf("keyguard: %s must be 0600 or 0660", EnvSocketMode)
	case c.Listen != "" && (c.TLSCert == "" || c.TLSKey == ""):
		return fmt.Errorf("keyguard: mTLS needs %s and %s", EnvTLSCert, EnvTLSKey)
	case c.Listen != "" && len(c.ClientPins) == 0:
		return fmt.Errorf("keyguard: mTLS needs %s (tt-core's pinned client certificate)", EnvClientPins)
	}
	for _, p := range c.ClientPins {
		if _, err := parsePin(p); err != nil {
			return err
		}
	}
	return nil
}
