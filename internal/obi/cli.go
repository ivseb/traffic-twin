package obi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// Environment variables. The enrollment and key variables are shared with
// the SDKs and tt-egress, so one deployment convention covers every source.
const (
	EnvListen       = "TT_OBI_LISTEN"
	EnvConfigOut    = "TT_OBI_CONFIG_OUT"
	EnvServiceMatch = "TT_OBI_SERVICE_FILTER"
	EnvCaptureBytes = "TT_OBI_CAPTURE_BYTES"
	EnvOpenPorts    = "TT_OBI_OPEN_PORTS"
	EnvExePath      = "TT_OBI_EXE_PATH"
	EnvEndpoint     = "TT_OBI_ENDPOINT"
	EnvLogLevel     = "TT_OBI_LOG_LEVEL"
	EnvEnrollURL    = "TT_ENROLL_URL"
	EnvEnrollToken  = "TT_ENROLL_TOKEN"
	EnvServiceName  = "TT_SERVICE_NAME"
	EnvStateDir     = "TT_STATE_DIR"

	DefaultListenAddr = "127.0.0.1:4318"
)

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

func pick(flagV, envName, def string) string {
	switch {
	case flagV != "":
		return flagV
	case os.Getenv(envName) != "":
		return os.Getenv(envName)
	}
	return def
}

// RunCLI implements "tt obi". It returns the process exit code: 0 clean
// stop, 1 runtime error, 2 invalid usage or configuration.
//
//	tt obi [flags]            run the bridge
//	tt obi config [flags]     print the OBI configuration for a policy file
func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer, buildVersion string) int {
	if len(args) > 0 && args[0] == "config" {
		return runConfig(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("tt obi", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "OTLP/HTTP receiver address (env "+EnvListen+", default "+DefaultListenAddr+"); keep it on loopback: what OBI sends is raw")
	cfgOut := fs.String("config-out", "", "write the generated OBI configuration here whenever a new policy is accepted (env "+EnvConfigOut+")")
	svcFilter := fs.String("service-filter", "", "accept only spans whose resource service.name equals this (env "+EnvServiceMatch+", default the enrolled service name, \"*\" = any)")
	capBytes := fs.String("capture-bytes", "", "OBI HTTP payload buffer in bytes, at most 262144 (env "+EnvCaptureBytes+", default 8192)")
	ports := fs.String("open-ports", "", "OBI discovery: port or range to instrument (env "+EnvOpenPorts+")")
	exe := fs.String("exe-path", "", "OBI discovery: executable path to instrument (env "+EnvExePath+")")
	endpoint := fs.String("obi-endpoint", "", "OTLP endpoint OBI is told to export to (env "+EnvEndpoint+", default http://<listen>)")
	stateDir := fs.String("state-dir", "", "directory of the enrollment, key and policy cache (env "+EnvStateDir+")")
	enrollURL := fs.String("enroll-url", "", "tt-core source endpoint, https (env "+EnvEnrollURL+"); the token comes from env "+EnvEnrollToken+" only")
	service := fs.String("service-name", "", "service name to enroll with (env "+EnvServiceName+")")
	logLevel := fs.String("log-level", "", "debug, info, warn or error (env "+EnvLogLevel+", default info)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tt obi: unexpected arguments: %v\n", fs.Args())
		return 2
	}
	logger, err := newLogger(stderr, pick(*logLevel, EnvLogLevel, "info"))
	if err != nil {
		fmt.Fprintf(stderr, "tt obi: %v\n", err)
		return 2
	}
	addr := pick(*listen, EnvListen, DefaultListenAddr)
	capture := int64(DefaultCaptureSize)
	if v := pick(*capBytes, EnvCaptureBytes, ""); v != "" {
		capture, err = strconv.ParseInt(v, 10, 64)
		if err != nil || capture < 1 || capture > MaxCaptureSize {
			fmt.Fprintf(stderr, "tt obi: capture bytes must be between 1 and %d\n", MaxCaptureSize)
			return 2
		}
	}
	enrol := pick(*enrollURL, EnvEnrollURL, "")
	name := pick(*service, EnvServiceName, "")
	if enrol == "" || name == "" {
		fmt.Fprintf(stderr, "tt obi: enrollment required: set %s (or --enroll-url) and %s (or --service-name), and %s\n",
			EnvEnrollURL, EnvServiceName, EnvEnrollToken)
		return 2
	}
	if !policy.ValidServiceName(name) {
		fmt.Fprintf(stderr, "tt obi: service name %q is not valid\n", name)
		return 2
	}
	if h, _, err := net.SplitHostPort(addr); err != nil {
		fmt.Fprintf(stderr, "tt obi: listen %q: %v\n", addr, err)
		return 2
	} else if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
		logger.Warn("the receiver is not on loopback: what OBI sends is raw traffic, keep this network private", "listen", addr)
	}

	src, err := newSource(enrol, name, pick(*stateDir, EnvStateDir, ""), buildVersion, logger)
	if err != nil {
		fmt.Fprintf(stderr, "tt obi: %v\n", err)
		return 2
	}
	filter := pick(*svcFilter, EnvServiceMatch, name)
	if filter == "*" {
		filter = ""
	}
	br := NewBridge(BridgeConfig{Sink: src, ServiceFilter: filter, CaptureLimit: capture, Logger: logger})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(stderr, "tt obi: %v\n", err)
		return 1
	}
	exportTo := pick(*endpoint, EnvEndpoint, "http://"+ln.Addr().String())
	srv := &http.Server{Handler: br.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	fmt.Fprintf(stdout, "tt obi %s receiving OTLP/JSON traces on %s as service %q\n", buildVersion, ln.Addr(), name)
	src.Start(ctx)

	opts := ConfigOptions{ServiceName: name, Endpoint: exportTo, OpenPorts: pick(*ports, EnvOpenPorts, ""),
		ExePath: pick(*exe, EnvExePath, ""), CaptureBytes: capture}
	out := pick(*cfgOut, EnvConfigOut, "")
	wctx, stopWatch := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		if out != "" {
			watchPolicy(wctx, src, opts, out, logger)
		}
	}()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	code := 0
	select {
	case <-ctx.Done():
	case err := <-errc:
		fmt.Fprintf(stderr, "tt obi: %v\n", err)
		code = 1
	}
	stopWatch()
	<-watchDone
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	br.Close()
	_ = src.Close(sctx)
	return code
}

// watchPolicy writes the OBI configuration each time the accepted policy
// changes (and once for the policy already in force at start).
func watchPolicy(ctx context.Context, src *sourceclient.Source, o ConfigOptions, path string, log *slog.Logger) {
	last := ""
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		if v := src.AcceptedPolicy(); v != nil && v.Hash != last {
			g, err := GenerateConfig(v.Policy, o)
			if err != nil {
				log.Error("cannot generate the OBI configuration", "error", err.Error())
			} else if err := writeAtomic(path, g.YAML); err != nil {
				log.Error("cannot write the OBI configuration", "error", err.Error())
			} else {
				log.Info("OBI configuration written: restart OBI to apply it", "path", path, "policy", v.Policy.PolicyID, "version", v.Policy.Version)
				last = v.Hash
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// writeAtomic replaces path with data (rename), so OBI never reads half a file.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".obi-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l})), nil
}

func newSource(enrollURL, service, stateDir, buildVersion string, logger *slog.Logger) (*sourceclient.Source, error) {
	keys, kids, kerr := loadKeys()
	if kerr != nil {
		logger.Warn("no usable HMAC key: the bridge will run but not capture", "error", kerr.Error())
	}
	host, _ := os.Hostname()
	return sourceclient.New(sourceclient.Config{
		EnrollURL: enrollURL, Token: os.Getenv(EnvEnrollToken), StateDir: stateDir,
		Kind: "obi", Version: SourceVersion(buildVersion), ServiceName: service, Instance: host,
		Keys: keys, KeyKids: kids, Logger: logger,
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

// runConfig implements "tt obi config": print the OBI configuration for a
// policy file, without enrolling. The file is a compiled policy body
// (tt.policy.body/v1) or a signed envelope. The signature is NOT verified:
// the output can only make OBI hand over less, and the running bridge
// verifies the policy it actually enforces.
func runConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tt obi config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("policy", "", "compiled policy body or signed envelope (JSON); required")
	service := fs.String("service-name", "", "service name of the bridge (inbound services with another name are ignored)")
	endpoint := fs.String("obi-endpoint", "", "OTLP endpoint OBI exports to (default "+DefaultEndpoint+")")
	ports := fs.String("open-ports", "", "OBI discovery: port or range to instrument")
	exe := fs.String("exe-path", "", "OBI discovery: executable path to instrument")
	capBytes := fs.Int64("capture-bytes", DefaultCaptureSize, "OBI HTTP payload buffer in bytes (at most 262144)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *file == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "tt obi config: --policy FILE is required")
		return 2
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(stderr, "tt obi config: %v\n", err)
		return 2
	}
	p, err := decodePolicy(raw)
	if err != nil {
		fmt.Fprintf(stderr, "tt obi config: %s: %v\n", *file, err)
		return 2
	}
	g, err := GenerateConfig(p, ConfigOptions{ServiceName: *service, Endpoint: *endpoint, OpenPorts: *ports, ExePath: *exe, CaptureBytes: *capBytes})
	if err != nil {
		fmt.Fprintf(stderr, "tt obi config: %v\n", err)
		return 2
	}
	_, _ = stdout.Write(g.YAML)
	return 0
}

func decodePolicy(raw []byte) (*policy.Policy, error) {
	var env struct {
		BodyB64 string `json:"body_b64"`
	}
	if json.Unmarshal(raw, &env) == nil && env.BodyB64 != "" {
		b, err := base64.RawURLEncoding.DecodeString(env.BodyB64)
		if err != nil {
			return nil, errors.New("envelope body_b64 is not base64url")
		}
		raw = b
	}
	return policy.DecodeBody(raw)
}
