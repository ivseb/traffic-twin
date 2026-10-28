package egress

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// Environment variables. The enrollment and key variables are shared with the
// SDKs, so one deployment convention covers every kind of source.
const (
	EnvConfig         = "TT_EGRESS_CONFIG"
	EnvListen         = "TT_EGRESS_LISTEN"
	EnvUpstreams      = "TT_EGRESS_UPSTREAMS" // alias=url,alias=url
	EnvCAFile         = "TT_EGRESS_CA_FILE"
	EnvAliasFromPol   = "TT_EGRESS_ALIAS_FROM_POLICY"
	EnvLogLevel       = "TT_EGRESS_LOG_LEVEL"
	EnvEnrollURL      = "TT_ENROLL_URL"
	EnvEnrollToken    = "TT_ENROLL_TOKEN"
	EnvServiceName    = "TT_SERVICE_NAME"
	EnvStateDir       = "TT_STATE_DIR"
	DefaultListenAddr = "127.0.0.1:9090"
)

// fileConfig is the optional YAML configuration file.
type fileConfig struct {
	Listen                string        `yaml:"listen"`
	Upstreams             []Upstream    `yaml:"upstreams"`
	AliasFromPolicy       bool          `yaml:"alias_from_policy"`
	CAFile                string        `yaml:"ca_file"`
	StateDir              string        `yaml:"state_dir"`
	EnrollURL             string        `yaml:"enroll_url"`
	ServiceName           string        `yaml:"service_name"`
	LogLevel              string        `yaml:"log_level"`
	DialTimeout           time.Duration `yaml:"dial_timeout"`
	TLSHandshakeTimeout   time.Duration `yaml:"tls_handshake_timeout"`
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout"`
	IdleConnTimeout       time.Duration `yaml:"idle_conn_timeout"`
	MaxIdleConnsPerHost   int           `yaml:"max_idle_conns_per_host"`
	Capture               CaptureConfig `yaml:"capture"`
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

var semverRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)

// SourceVersion maps the build version ("v0.1.0", "dev", ...) to the semver
// the Fleet API and the event schema require.
func SourceVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if semverRE.MatchString(v) {
		return v
	}
	return "0.0.0-dev"
}

// RunCLI implements "tt egress". It returns the process exit code: 0 clean
// stop, 1 runtime error, 2 invalid usage or configuration.
func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer, buildVersion string) int {
	fs := flag.NewFlagSet("tt egress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", os.Getenv(EnvConfig), "YAML configuration file (env "+EnvConfig+"); optional")
	listen := fs.String("listen", "", "listen address (env "+EnvListen+", default "+DefaultListenAddr+")")
	var ups, origins multiFlag
	fs.Var(&ups, "upstream", "route /<alias>/ to a service: alias=https://host[/base] (repeatable; env "+EnvUpstreams+")")
	fs.Var(&origins, "capture-origin", "origin the policy knows an upstream by: alias=scheme://host[:port] (repeatable)")
	stateDir := fs.String("state-dir", "", "directory of the enrollment, key and policy cache (env "+EnvStateDir+")")
	enrollURL := fs.String("enroll-url", "", "tt-core source endpoint, https (env "+EnvEnrollURL+"); the token comes from env "+EnvEnrollToken+" only")
	service := fs.String("service-name", "", "service name to enroll with (env "+EnvServiceName+")")
	caFile := fs.String("ca-file", "", "PEM CA added to the system roots for every upstream (env "+EnvCAFile+")")
	aliasPol := fs.Bool("alias-from-policy", false, "also route /<service>/ to the base URL of the policy's external services (env "+EnvAliasFromPol+")")
	logLevel := fs.String("log-level", "", "debug, info, warn or error (env "+EnvLogLevel+", default info)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tt egress: unexpected arguments: %v\n", fs.Args())
		return 2
	}

	// defaults < file < environment < flags
	var fc fileConfig
	if *cfgPath != "" {
		raw, err := os.ReadFile(*cfgPath)
		if err != nil {
			fmt.Fprintf(stderr, "tt egress: %v\n", err)
			return 2
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintf(stderr, "tt egress: %s: %v\n", *cfgPath, err)
			return 2
		}
	}
	pick := func(flagV, envName, fileV, def string) string {
		switch {
		case flagV != "":
			return flagV
		case os.Getenv(envName) != "":
			return os.Getenv(envName)
		case fileV != "":
			return fileV
		}
		return def
	}
	addr := pick(*listen, EnvListen, fc.Listen, DefaultListenAddr)
	level := pick(*logLevel, EnvLogLevel, fc.LogLevel, "info")
	logger, err := newLogger(stderr, level)
	if err != nil {
		fmt.Fprintf(stderr, "tt egress: %v\n", err)
		return 2
	}

	cfg := Config{
		Upstreams: fc.Upstreams, DialTimeout: fc.DialTimeout, TLSHandshakeTimeout: fc.TLSHandshakeTimeout,
		ResponseHeaderTimeout: fc.ResponseHeaderTimeout, IdleConnTimeout: fc.IdleConnTimeout,
		MaxIdleConnsPerHost: fc.MaxIdleConnsPerHost, Capture: fc.Capture, Logger: logger, Version: buildVersion,
		AliasFromPolicy: fc.AliasFromPolicy,
	}
	if v := os.Getenv(EnvAliasFromPol); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			fmt.Fprintf(stderr, "tt egress: %s: %v\n", EnvAliasFromPol, err)
			return 2
		}
		cfg.AliasFromPolicy = b
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["alias-from-policy"] {
		cfg.AliasFromPolicy = *aliasPol
	}
	// Upstreams: file, then environment and flags override by alias.
	byAlias := map[string]int{}
	for i, u := range cfg.Upstreams {
		byAlias[u.Alias] = i
	}
	var specs []string
	if v := os.Getenv(EnvUpstreams); v != "" {
		specs = append(specs, strings.Split(v, ",")...)
	}
	specs = append(specs, ups...)
	for _, s := range specs {
		u, err := ParseUpstreamFlag(strings.TrimSpace(s))
		if err != nil {
			fmt.Fprintf(stderr, "tt egress: %v\n", err)
			return 2
		}
		if i, ok := byAlias[u.Alias]; ok {
			u.CaptureOrigin, u.CAFile = cfg.Upstreams[i].CaptureOrigin, cfg.Upstreams[i].CAFile
			cfg.Upstreams[i] = u
			continue
		}
		byAlias[u.Alias] = len(cfg.Upstreams)
		cfg.Upstreams = append(cfg.Upstreams, u)
	}
	for _, s := range origins {
		alias, o, ok := strings.Cut(s, "=")
		i, found := byAlias[alias]
		if !ok || !found {
			fmt.Fprintf(stderr, "tt egress: --capture-origin %q: want alias=origin for a configured upstream\n", s)
			return 2
		}
		cfg.Upstreams[i].CaptureOrigin = o
	}
	if ca := pick(*caFile, EnvCAFile, fc.CAFile, ""); ca != "" {
		pemData, err := os.ReadFile(ca)
		if err != nil {
			fmt.Fprintf(stderr, "tt egress: %v\n", err)
			return 2
		}
		cfg.ExtraCAPEM = pemData
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "tt egress: %v\n", err)
		return 2
	}

	var px *Proxy // set before the source starts, so the callback never sees nil
	src, err := newSource(pick(*enrollURL, EnvEnrollURL, fc.EnrollURL, ""), pick(*service, EnvServiceName, fc.ServiceName, ""),
		pick(*stateDir, EnvStateDir, fc.StateDir, ""), buildVersion, logger, func(v *policy.Verified) {
			if px != nil {
				px.SetPolicy(v)
			}
		})
	if err != nil {
		fmt.Fprintf(stderr, "tt egress: %v\n", err)
		return 2
	}
	cfg.Source = src
	px, err = New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "tt egress: %v\n", err)
		return 2
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(stderr, "tt egress: %v\n", err)
		return 1
	}
	srv := &http.Server{Handler: px, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	fmt.Fprintf(stdout, "tt egress %s listening on %s (%d upstream(s))\n", buildVersion, ln.Addr(), len(cfg.Upstreams))
	if src != nil {
		src.Start(ctx)
	} else {
		logger.Warn("capture disabled: no enrollment configured; the proxy only forwards")
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	code := 0
	select {
	case <-ctx.Done():
	case err := <-errc:
		fmt.Fprintf(stderr, "tt egress: %v\n", err)
		code = 1
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = px.Close(sctx)
	if src != nil {
		_ = src.Close(sctx)
	}
	return code
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l})), nil
}

// newSource builds the Fleet source when an enrollment is configured. It
// returns nil (proxy only, nothing captured) otherwise.
func newSource(enrollURL, service, stateDir, buildVersion string, logger *slog.Logger, onPolicy func(*policy.Verified)) (*sourceclient.Source, error) {
	token := os.Getenv(EnvEnrollToken)
	if enrollURL == "" {
		if token != "" {
			return nil, fmt.Errorf("%s is set but there is no enrollment url (%s or --enroll-url)", EnvEnrollToken, EnvEnrollURL)
		}
		return nil, nil
	}
	if service == "" {
		return nil, fmt.Errorf("service name required to enroll (%s or --service-name)", EnvServiceName)
	}
	keys, kids, kerr := loadKeys()
	if kerr != nil {
		logger.Warn("no usable HMAC key: the proxy will forward but not capture", "error", kerr.Error())
	}
	host, _ := os.Hostname()
	return sourceclient.New(sourceclient.Config{
		EnrollURL: enrollURL, Token: token, StateDir: stateDir,
		Kind: "egress", Version: SourceVersion(buildVersion), ServiceName: service, Instance: host,
		Keys: keys, KeyKids: kids, Logger: logger,
		OnPolicy: onPolicy,
	})
}

// loadKeys reads TT_HMAC_KEY or TT_HMAC_KEY_FILE. The kids (never the
// secrets) are also returned for the enrollment request.
func loadKeys() (sanitizer.KeySet, []string, error) {
	ks, err := sanitizer.LoadKeysFromEnv()
	if err != nil {
		return sanitizer.KeySet{}, nil, err
	}
	text := os.Getenv("TT_HMAC_KEY")
	if text == "" {
		if b, err := os.ReadFile(os.Getenv("TT_HMAC_KEY_FILE")); err == nil {
			text = string(b)
		}
	}
	var kids []string
	for _, line := range strings.Split(text, "\n") {
		if kid, _, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ":"); ok && kid != "" {
			kids = append(kids, kid)
		}
	}
	return ks, kids, nil
}
