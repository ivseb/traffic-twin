package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/ui"
)

func runCore(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "init" {
		return runCoreInit(args[1:], stdout, stderr)
	}
	fs := newFlagSet("core", stderr)
	cfgPath := fs.String("config", os.Getenv(config.EnvConfigPath), "path of the YAML configuration file (env "+config.EnvConfigPath+")")
	addr := fs.String("addr", "", "override admin.addr, the UI/API listen address (default "+config.DefaultAdminAddr+")")
	printToken := fs.Bool("print-setup-token", false, "print the one-time setup token on stdout (development; by default it is written to DATA_DIR/"+core.SetupTokenFile+", mode 0600, because a service manager keeps stdout in its journal)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: tt core [-config core.yaml] [-addr host:port] [-print-setup-token]   run tt-core (needs a running tt keyguard)")
		fmt.Fprintln(stderr, "       tt core init [-dir DIR] [-keyguard-url URL]     write a configuration and the data directory")
		fmt.Fprintln(stderr, "       tt dev up                                       single-host trial, keyguard included")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	cfg, err := loadConfig(*cfgPath, *addr)
	if err != nil {
		fmt.Fprintf(stderr, "tt core: %v\n", err)
		return 1
	}
	if err := serveCore(ctx, cfg, nil, nil, stdout, stderr, *printToken); err != nil {
		fmt.Fprintf(stderr, "tt core: %v\n", err)
		return 1
	}
	return 0
}

func loadConfig(path, addr string) (*config.Config, error) {
	cfg, err := config.Load(path, os.Environ())
	if err != nil {
		return nil, err
	}
	if addr != "" {
		cfg.Admin.Addr = addr
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// serveCore composes tt-core and serves until ctx is cancelled. The
// listeners are optional (nil: the configured addresses).
func serveCore(ctx context.Context, cfg *config.Config, adminLn, intakeLn net.Listener, stdout, stderr io.Writer, printToken bool) error {
	logger := server.NewLogger(stderr, cfg.Log.Level, cfg.Log.Format)
	c, err := core.New(ctx, core.Options{Config: cfg, Version: version, Commit: commit, Logger: logger, UI: ui.Handler(),
		AdminListener: adminLn, IntakeListener: intakeLn})
	if err != nil {
		return err
	}
	base := c.AdminScheme() + "://" + c.AdminAddr().String()
	fmt.Fprintf(stdout, "tt core %s listening on %s\n", version, base)
	if a := c.IntakeAddr(); a != nil {
		fmt.Fprintf(stdout, "intake (sources) on %s, public URL %s\n", a, cfg.FleetPublicURL())
	}
	if err := announceSetupToken(c, base, printToken, stdout, stderr); err != nil {
		return errors.Join(err, c.Close())
	}
	return c.Run(ctx)
}

// announceSetupToken makes the one-time setup token available to the
// operator. By default it goes to a 0600 file in the data directory and the
// console only shows the path: stdout is the journal under systemd. With
// printToken it is written to stdout (development). Once an administrator
// exists a file left by an earlier start is removed.
func announceSetupToken(c *core.Core, base string, printToken bool, stdout, stderr io.Writer) error {
	tok := c.SetupToken()
	if tok == "" {
		core.RemoveSetupTokenFile(c.DataDir())
		return nil
	}
	if printToken {
		core.PrintSetupToken(stdout, tok, base)
		return nil
	}
	path, err := core.WriteSetupToken(c.DataDir(), tok)
	if err != nil {
		return fmt.Errorf("cannot write the setup token file (use -print-setup-token to print it): %w", err)
	}
	core.PrintSetupTokenFile(stdout, path, base)
	return nil
}

// runCoreInit writes a configuration and creates the data directory. The
// setup token is printed by `tt core` at its first start: it is replaced at
// every start until used (internal/auth), so one printed here would be dead.
func runCoreInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("core init", stderr)
	dir := fs.String("dir", "tt-data", "data directory (database, Fleet CA, exports); put it on an encrypted volume")
	out := fs.String("config", "", "configuration file to write (default DIR/core.yaml)")
	kgURL := fs.String("keyguard-url", "", "keyguard: https://host:port (production) or unix:///path.sock (default unix://DIR/keyguard.sock)")
	publicURL := fs.String("public-url", "", "URL sources use to reach the intake, e.g. https://tt-core.internal:4318 (default https://localhost:4318)")
	intakeAddr := fs.String("intake-addr", config.DefaultIntakeAddr, "intake listen address (non-loopback needs -public-url)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "tt core init: %v\n", err)
		return 1
	}
	if *out == "" {
		*out = filepath.Join(abs, "core.yaml")
	}
	if *kgURL == "" {
		*kgURL = "unix://" + filepath.Join(abs, "keyguard.sock")
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		fmt.Fprintf(stderr, "tt core init: %v\n", err)
		return 1
	}
	_ = os.Chmod(abs, 0o700)
	var b strings.Builder
	fmt.Fprintf(&b, "# tt-core configuration written by `tt core init`.\n")
	fmt.Fprintf(&b, "# Every key and its default: deploy/examples/core.production.yaml.\n")
	fmt.Fprintf(&b, "admin:\n  addr: %s\n", config.DefaultAdminAddr)
	fmt.Fprintf(&b, "  # A non-loopback address needs tls.cert_file and tls.key_file.\n")
	fmt.Fprintf(&b, "intake:\n  addr: %s\n  tls:\n    managed: true   # certificate from the Fleet CA, pinned by enrollment tokens\n", *intakeAddr)
	fmt.Fprintf(&b, "storage:\n  path: %s\n", filepath.Join(abs, "tt-core.db"))
	fmt.Fprintf(&b, "keyguard:\n  url: %s\n", *kgURL)
	if strings.HasPrefix(*kgURL, "https://") {
		fmt.Fprintf(&b, "  client_cert_file: /etc/tt/tt-core-client.crt   # pinned by keyguard (TT_KEYGUARD_CLIENT_PINS)\n")
		fmt.Fprintf(&b, "  client_key_file: /etc/tt/tt-core-client.key\n")
		fmt.Fprintf(&b, "  server_pin: sha256:REPLACE   # tt keyguard pin keyguard.crt\n")
	}
	if *publicURL != "" {
		fmt.Fprintf(&b, "fleet:\n  public_url: %s\n", *publicURL)
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "tt core init: %v (an existing configuration is never overwritten)\n", err)
		return 1
	}
	_, werr := f.WriteString(b.String())
	if err := errors.Join(werr, f.Close()); err != nil {
		fmt.Fprintf(stderr, "tt core init: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Wrote %s and created %s.\n\nNext steps:\n", *out, abs)
	if strings.HasPrefix(*kgURL, "unix://") {
		fmt.Fprintln(stdout, "  1. Generate keyguard's keys and start it on the socket (same host: test installations only):")
		fmt.Fprintf(stdout, "       tt keyguard genkey -type hmac -kid k1 -out %s\n", filepath.Join(abs, "hmac.keys"))
		fmt.Fprintf(stdout, "       tt keyguard genkey -type ed25519 -kid policy-1 -out %s\n", filepath.Join(abs, "policy.key"))
		fmt.Fprintf(stdout, "       tt keyguard genkey -type ed25519 -kid pack-1 -out %s\n", filepath.Join(abs, "pack.key"))
		fmt.Fprintf(stdout, "       TT_KEYGUARD_HMAC_KEYS_FILE=%s TT_KEYGUARD_POLICY_SIGNING_KEY_FILE=%s \\\n", filepath.Join(abs, "hmac.keys"), filepath.Join(abs, "policy.key"))
		fmt.Fprintf(stdout, "       TT_KEYGUARD_PACK_SIGNING_KEY_FILE=%s TT_KEYGUARD_DB=%s \\\n", filepath.Join(abs, "pack.key"), filepath.Join(abs, "tt-keyguard.db"))
		fmt.Fprintf(stdout, "       tt keyguard -socket %s\n", strings.TrimPrefix(*kgURL, "unix://"))
	} else {
		fmt.Fprintln(stdout, "  1. Start tt keyguard on its own host and fill keyguard.client_cert_file, client_key_file and server_pin.")
	}
	fmt.Fprintf(stdout, "  2. tt core -config %s\n", *out)
	fmt.Fprintln(stdout, "     It prints a one-time setup token: create the first administrator with it in the UI.")
	fmt.Fprintln(stdout, "For a quick local trial with everything in one process, use `tt dev up` instead.")
	return 0
}

// runDev implements `tt dev up`.
func runDev(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "up" {
		fmt.Fprintln(stderr, "Usage: tt dev up [-dir DIR] [-admin host:port] [-intake host:port] [-miner-horizon DUR]")
		return 2
	}
	fs := newFlagSet("dev up", stderr)
	dir := fs.String("dir", "tt-dev", "data directory of the trial (keys, databases, certificates)")
	admin := fs.String("admin", config.DefaultAdminAddr, "UI/admin listen address (loopback only)")
	intakeAddr := fs.String("intake", config.DefaultIntakeAddr, "intake listen address (loopback only)")
	horizon := fs.Duration("miner-horizon", 0, "least span of traffic the rule miner needs (default 1h; for the accelerated demo use e.g. 5m)")
	if code, ok := parseFlags(fs, args[1:]); !ok {
		return code
	}
	if *horizon < 0 {
		fmt.Fprintln(stderr, "tt dev up: -miner-horizon must not be negative")
		return 2
	}
	for _, a := range []string{*admin, *intakeAddr} {
		host, _, err := net.SplitHostPort(a)
		if ip := net.ParseIP(host); err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			fmt.Fprintf(stderr, "tt dev up: %s: the trial listens on loopback only\n", a)
			return 2
		}
	}
	if err := devUp(ctx, *dir, *admin, *intakeAddr, *horizon, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "tt dev up: %v\n", err)
		return 1
	}
	return 0
}

func devUp(ctx context.Context, dir, adminAddr, intakeAddr string, minerHorizon time.Duration, stdout, stderr io.Writer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	kg, err := core.StartDevKeyguard(ctx, core.DevKeyguardOptions{Dir: dir, Logger: keyguard.NewLogger(stderr, "warn", "text")})
	if err != nil {
		return fmt.Errorf("keyguard: %w", err)
	}
	cfg, err := core.DevConfig(dir, kg.URL, adminAddr, intakeAddr)
	if err != nil {
		return errors.Join(err, kg.Close())
	}
	cfg.Miner.MinHorizon = minerHorizon
	logger := server.NewLogger(stderr, "warn", "text")
	c, err := core.New(ctx, core.Options{Config: cfg, Version: version, Commit: commit, Logger: logger, UI: ui.Handler()})
	if err != nil {
		return errors.Join(err, kg.Close())
	}
	base := "https://" + c.AdminAddr().String()
	fmt.Fprintf(stdout, "tt dev up %s: single-host trial. NOT for production: keyguard shares this host and its keys sit in %s.\n\n", version, filepath.Join(dir, "keys"))
	fmt.Fprintf(stdout, "  UI and admin API   %s/   (self-signed certificate %s)\n", base, cfg.Admin.TLS.CertFile)
	fmt.Fprintf(stdout, "  intake (sources)   %s   (Fleet CA pinned by enrollment tokens)\n", cfg.FleetPublicURL())
	fmt.Fprintf(stdout, "  keyguard           %s\n", kg.URL)
	fmt.Fprintf(stdout, "  HMAC key for sources: TT_HMAC_KEY_FILE=%s (kid %s; starter policy hmac_kid %s)\n", kg.HMACKeyFile, core.DevHMACKid, core.DevHMACKid)
	if tok := c.SetupToken(); tok != "" {
		core.PrintSetupToken(stdout, tok, base)
	} else {
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "Press Ctrl+C to stop.")
	runErr := c.Run(ctx)
	return errors.Join(runErr, kg.Close())
}
