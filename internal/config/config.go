// Package config loads the tt-core configuration: a YAML file, then
// environment overrides (TT_CORE_*), then strict validation.
//
// Unknown YAML keys and unknown TT_CORE_* variables are errors, so a typo
// never silently falls back to a default. Defaults are secure: the admin
// listener binds to loopback, any non-loopback listener requires TLS, the
// intake listener is disabled until configured and always requires TLS.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/auth"
)

// Config is the full tt-core configuration.
type Config struct {
	Admin     Admin     `yaml:"admin"`
	Intake    Intake    `yaml:"intake"`
	Storage   Storage   `yaml:"storage"`
	Auth      Auth      `yaml:"auth"`
	Log       Log       `yaml:"log"`
	Keyguard  Keyguard  `yaml:"keyguard"`
	Fleet     Fleet     `yaml:"fleet"`
	Contract  Contract  `yaml:"contract"`
	Drift     Drift     `yaml:"drift"`
	Miner     Miner     `yaml:"miner"`
	World     World     `yaml:"world"`
	Gate      Gate      `yaml:"gate"`
	Retention Retention `yaml:"retention"`
	Mock      Mock      `yaml:"mock"`
}

// HTTP holds the per-listener HTTP limits.
type HTTP struct {
	MaxBodyBytes      int64         `yaml:"max_body_bytes"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
}

// Admin is the UI + admin API listener.
type Admin struct {
	// Addr is host:port. Default 127.0.0.1:7070 (loopback only).
	Addr string `yaml:"addr"`
	// TLS is required when Addr is not a loopback address.
	TLS  TLSFiles `yaml:"tls"`
	HTTP HTTP     `yaml:"http"`
	// ShutdownTimeout bounds graceful shutdown of both listeners.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// TLSFiles points to a PEM certificate chain and private key.
type TLSFiles struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether both files are set.
func (t TLSFiles) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Intake is the listener sources talk to (OTLP intake, fleet source
// endpoints). It is mTLS-capable and never plaintext.
type Intake struct {
	// Addr is host:port; empty disables the intake listener. Default
	// 127.0.0.1:4318 (loopback only).
	Addr string    `yaml:"addr"`
	TLS  IntakeTLS `yaml:"tls"`
	HTTP HTTP      `yaml:"http"`
}

// IntakeTLS configures server and client certificates of the intake.
type IntakeTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ClientCAFile is a PEM bundle of CAs that sign source certificates.
	// Optional when the fleet package supplies the CA pool at runtime.
	ClientCAFile string `yaml:"client_ca_file"`
	// Managed means the server certificate is supplied at runtime by the
	// fleet package instead of cert_file/key_file (default true: the
	// certificate chains to the Fleet root pinned by enrollment tokens).
	Managed bool `yaml:"managed"`
}

// Storage configures the SQLite database.
type Storage struct {
	// Path of the database file. Put it on an encrypted volume.
	Path string `yaml:"path"`
	// MaxBytes is the size budget of the database (file plus write-ahead
	// log): 0 means none. Crossing HighWatermarkPct and
	// CriticalWatermarkPct of it raises storage.high_watermark; above the
	// critical level the maintenance sheds the least valuable data first
	// (raw events beyond the miner window, then down to
	// MinEventsRetention). Ingestion is never blocked.
	MaxBytes             ByteSize `yaml:"max_bytes"`
	HighWatermarkPct     int      `yaml:"high_watermark_pct"`
	CriticalWatermarkPct int      `yaml:"critical_watermark_pct"`
	// Quotas bounds single datasets (config.Datasets); file-only. A dataset
	// over its quota raises storage.high_watermark and, for events and
	// rollups, is shed like the whole database.
	Quotas map[string]ByteSize `yaml:"quotas"`
	// MinEventsRetention is the floor of the shedding of raw events.
	MinEventsRetention time.Duration `yaml:"min_events_retention"`
}

// Auth configures authentication and sessions.
type Auth struct {
	Session   Session   `yaml:"session"`
	Local     Local     `yaml:"local"`
	OIDC      OIDC      `yaml:"oidc"`
	RateLimit RateLimit `yaml:"rate_limit"`
}

// Session timeouts.
type Session struct {
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	AbsoluteTimeout time.Duration `yaml:"absolute_timeout"`
}

// Local accounts (username + password, argon2id).
type Local struct {
	Enabled bool `yaml:"enabled"`
}

// OIDC login (authorization code + PKCE).
type OIDC struct {
	Enabled          bool     `yaml:"enabled"`
	IssuerURL        string   `yaml:"issuer_url"`
	ClientID         string   `yaml:"client_id"`
	ClientSecretFile string   `yaml:"client_secret_file"`
	RedirectURL      string   `yaml:"redirect_url"`
	Scopes           []string `yaml:"scopes"`
	// RolesClaim names the ID token claim (string or array of strings)
	// mapped to roles through RoleMapping. When empty, roles of OIDC users
	// are managed locally by an admin.
	RolesClaim  string              `yaml:"roles_claim"`
	RoleMapping map[string][]string `yaml:"role_mapping"`

	// ClientSecret is never read from YAML: it comes from ClientSecretFile
	// or the TT_CORE_AUTH_OIDC_CLIENT_SECRET environment variable.
	ClientSecret string `yaml:"-" env:"AUTH_OIDC_CLIENT_SECRET"`

	// ApprovalClientID enables the approval step-up (keyguard.md 3.2 step
	// 4): a second client at the same provider whose client id is
	// keyguard's approval audience (TT_KEYGUARD_OIDC_AUDIENCE). It must
	// differ from ClientID. Its redirect URL is the login redirect URL
	// with the path /api/v1/auth/oidc/stepup/callback.
	ApprovalClientID         string `yaml:"approval_client_id"`
	ApprovalClientSecretFile string `yaml:"approval_client_secret_file"`
	// ApprovalClientSecret comes from ApprovalClientSecretFile or
	// TT_CORE_AUTH_OIDC_APPROVAL_CLIENT_SECRET (empty: public client, PKCE).
	ApprovalClientSecret string `yaml:"-" env:"AUTH_OIDC_APPROVAL_CLIENT_SECRET"`
}

// RateLimit applies per client IP to the authentication endpoints.
type RateLimit struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst             int `yaml:"burst"`
}

// Log configures the structured logger (log/slog).
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

// DefaultAdminAddr binds the admin listener to loopback only.
const DefaultAdminAddr = "127.0.0.1:7070"

// Default returns the secure default configuration.
func Default() Config {
	c := Config{
		Admin: Admin{
			Addr:            DefaultAdminAddr,
			HTTP:            defaultHTTP(),
			ShutdownTimeout: 10 * time.Second,
		},
		Intake: Intake{Addr: DefaultIntakeAddr, TLS: IntakeTLS{Managed: true}, HTTP: defaultIntakeHTTP()},
		Storage: Storage{
			Path: "data/tt-core.db",
		},
		Auth: Auth{
			Session:   Session{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 12 * time.Hour},
			Local:     Local{Enabled: true},
			OIDC:      OIDC{Scopes: []string{"openid", "profile", "email"}},
			RateLimit: RateLimit{RequestsPerMinute: 10, Burst: 5},
		},
		Log: Log{Level: "info", Format: "json"},
	}
	defaultComponents(&c)
	defaultLifecycle(&c)
	return c
}

func defaultHTTP() HTTP {
	return HTTP{
		MaxBodyBytes:      1 << 20,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// defaultIntakeHTTP allows 4 MiB requests, the OTLP/HTTP limit the intake
// accepts (docs/spec/event.md).
func defaultIntakeHTTP() HTTP {
	h := defaultHTTP()
	h.MaxBodyBytes = 4 << 20
	return h
}

// EnvConfigPath names the variable that may hold the config file path.
const EnvConfigPath = "TT_CORE_CONFIG"

// Load reads the YAML file at path (optional: "" means defaults only),
// applies TT_CORE_* overrides from environ (os.Environ() format), resolves
// secret files and validates the result.
func Load(path string, environ []string) (*Config, error) {
	cfg := Default()
	if path != "" {
		if err := loadFile(path, &cfg); err != nil {
			return nil, err
		}
	}
	if err := applyEnv(&cfg, environ); err != nil {
		return nil, err
	}
	if err := cfg.resolveSecrets(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

const maxConfigBytes = 1 << 20

func loadFile(path string, cfg *Config) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if st.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("config: %s is world-writable; fix its permissions", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return fmt.Errorf("config: %s is larger than %d bytes", path, maxConfigBytes)
	}
	return Parse(data, cfg)
}

// Parse decodes YAML into cfg (which should hold defaults), rejecting
// unknown keys and multiple documents.
func Parse(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // empty file: defaults
		}
		return fmt.Errorf("config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config: exactly one YAML document expected")
	}
	return nil
}

func (c *Config) resolveSecrets() error {
	o := &c.Auth.OIDC
	if o.ClientSecretFile != "" {
		if o.ClientSecret != "" {
			return errors.New("config: auth.oidc: set client_secret_file or TT_CORE_AUTH_OIDC_CLIENT_SECRET, not both")
		}
		b, err := os.ReadFile(o.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("config: auth.oidc.client_secret_file: %w", err)
		}
		o.ClientSecret = strings.TrimSpace(string(b))
		if o.ClientSecret == "" {
			return errors.New("config: auth.oidc.client_secret_file is empty")
		}
	}
	if o.ApprovalClientSecretFile != "" {
		if o.ApprovalClientSecret != "" {
			return errors.New("config: auth.oidc: set approval_client_secret_file or TT_CORE_AUTH_OIDC_APPROVAL_CLIENT_SECRET, not both")
		}
		b, err := os.ReadFile(o.ApprovalClientSecretFile)
		if err != nil {
			return fmt.Errorf("config: auth.oidc.approval_client_secret_file: %w", err)
		}
		o.ApprovalClientSecret = strings.TrimSpace(string(b))
		if o.ApprovalClientSecret == "" {
			return errors.New("config: auth.oidc.approval_client_secret_file is empty")
		}
	}
	return nil
}

// Validate checks the configuration and returns every problem found.
func (c *Config) Validate() error {
	var errs []error
	add := func(key, format string, args ...any) {
		errs = append(errs, fmt.Errorf("config: %s: %s", key, fmt.Sprintf(format, args...)))
	}

	// Admin listener.
	if loop, err := isLoopbackAddr(c.Admin.Addr); err != nil {
		add("admin.addr", "%v", err)
	} else if !loop && !c.Admin.TLS.Enabled() {
		add("admin.tls", "cert_file and key_file are required when admin.addr is not a loopback address")
	}
	if (c.Admin.TLS.CertFile == "") != (c.Admin.TLS.KeyFile == "") {
		add("admin.tls", "cert_file and key_file must be set together")
	}
	validateHTTP("admin.http", c.Admin.HTTP, add)
	if c.Admin.ShutdownTimeout <= 0 || c.Admin.ShutdownTimeout > 5*time.Minute {
		add("admin.shutdown_timeout", "must be in (0, 5m]")
	}

	// Intake listener.
	if c.Intake.Addr != "" {
		if _, err := isLoopbackAddr(c.Intake.Addr); err != nil {
			add("intake.addr", "%v", err)
		}
		t := c.Intake.TLS
		if t.Managed && (t.CertFile != "" || t.KeyFile != "") {
			add("intake.tls", "managed excludes cert_file/key_file")
		}
		if !t.Managed && (t.CertFile == "" || t.KeyFile == "") {
			add("intake.tls", "the intake never runs in plaintext: set cert_file and key_file (or managed: true)")
		}
		if c.Intake.Addr == c.Admin.Addr {
			add("intake.addr", "must differ from admin.addr")
		}
		validateHTTP("intake.http", c.Intake.HTTP, add)
	}

	// Storage.
	if strings.TrimSpace(c.Storage.Path) == "" || c.Storage.Path == ":memory:" || strings.HasPrefix(c.Storage.Path, "file:") {
		add("storage.path", "a plain file path is required")
	}

	// Auth.
	s := c.Auth.Session
	if s.IdleTimeout < time.Minute || s.IdleTimeout > 24*time.Hour {
		add("auth.session.idle_timeout", "must be between 1m and 24h")
	}
	if s.AbsoluteTimeout < s.IdleTimeout || s.AbsoluteTimeout > 7*24*time.Hour {
		add("auth.session.absolute_timeout", "must be >= idle_timeout and <= 168h")
	}
	if !c.Auth.Local.Enabled && !c.Auth.OIDC.Enabled {
		add("auth", "enable at least one of local or oidc")
	}
	if c.Auth.OIDC.Enabled {
		validateOIDC(c.Auth.OIDC, add)
	}
	if rl := c.Auth.RateLimit; rl.RequestsPerMinute < 1 || rl.RequestsPerMinute > 10000 || rl.Burst < 1 || rl.Burst > 1000 {
		add("auth.rate_limit", "requests_per_minute must be in [1, 10000] and burst in [1, 1000]")
	}

	// Log.
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level", "must be one of debug, info, warn, error")
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		add("log.format", "must be json or text")
	}
	validateComponents(c, add)
	validateLifecycle(c, add)
	return errors.Join(errs...)
}

func validateHTTP(key string, h HTTP, add func(string, string, ...any)) {
	if h.MaxBodyBytes < 1024 || h.MaxBodyBytes > 64<<20 {
		add(key+".max_body_bytes", "must be between 1024 and 67108864")
	}
	for name, d := range map[string]time.Duration{
		"read_header_timeout": h.ReadHeaderTimeout,
		"read_timeout":        h.ReadTimeout,
		"write_timeout":       h.WriteTimeout,
		"idle_timeout":        h.IdleTimeout,
	} {
		if d <= 0 || d > 10*time.Minute {
			add(key+"."+name, "must be in (0, 10m]")
		}
	}
}

func validateOIDC(o OIDC, add func(string, string, ...any)) {
	checkURL := func(key, raw string) *url.URL {
		u, err := url.Parse(raw)
		if raw == "" || err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
			add(key, "must be an absolute URL")
			return nil
		}
		if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
			add(key, "must use https (http is accepted only for loopback hosts)")
		}
		return u
	}
	checkURL("auth.oidc.issuer_url", o.IssuerURL)
	if u := checkURL("auth.oidc.redirect_url", o.RedirectURL); u != nil && u.Path != "/api/v1/auth/oidc/callback" {
		add("auth.oidc.redirect_url", "path must be /api/v1/auth/oidc/callback")
	}
	if o.ClientID == "" {
		add("auth.oidc.client_id", "required")
	}
	if o.ApprovalClientID != "" && o.ApprovalClientID == o.ClientID {
		add("auth.oidc.approval_client_id", "must differ from client_id (login ID tokens must not approve changes)")
	}
	if o.ApprovalClientID == "" && (o.ApprovalClientSecret != "" || o.ApprovalClientSecretFile != "") {
		add("auth.oidc.approval_client_id", "required with an approval client secret")
	}
	hasOpenID := false
	for _, s := range o.Scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		add("auth.oidc.scopes", "must include openid")
	}
	if len(o.RoleMapping) > 0 && o.RolesClaim == "" {
		add("auth.oidc.role_mapping", "requires roles_claim")
	}
	for group, roles := range o.RoleMapping {
		if group == "" || len(roles) == 0 {
			add("auth.oidc.role_mapping", "empty group or role list")
		}
		for _, r := range roles {
			if _, err := auth.ParseRole(r); err != nil {
				add("auth.oidc.role_mapping."+group, "%v", err)
			}
		}
	}
}

func isLoopbackAddr(addr string) (bool, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("invalid host:port %q", addr)
	}
	if port == "" {
		return false, fmt.Errorf("missing port in %q", addr)
	}
	return isLoopbackHost(host), nil
}

// isLoopbackHost: "" (all interfaces) and non-literal names other than
// "localhost" count as non-loopback.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AdminIsLoopback reports whether the admin listener binds loopback only.
func (c *Config) AdminIsLoopback() bool {
	loop, _ := isLoopbackAddr(c.Admin.Addr)
	return loop
}
