package mock

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// RunCLI implements `tt mock`: it parses args (everything after "mock"),
// reads TT_GATE_PUBKEYS and TT_CONTROL_TOKEN from the environment, runs the
// mock until ctx ends and returns a process exit code (0 ok, 1 failure, 2
// usage error).
func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := ParseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "tt mock: %v\n", err)
		return 2
	}
	level := slog.LevelInfo
	if cfg.quiet {
		level = slog.LevelWarn
	}
	cfg.Config.Logger = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	cfg.Config.ControlToken = envOr("TT_CONTROL_TOKEN", "")
	if id := cfg.Config.Identity; id != nil && len(id.Key) == 0 {
		cfg.Config.Logger.Warn("session per user without " + EnvIdentityKey + ": a random key is used, so users get other sessions and customers after a restart")
	}
	run := func() error { return Run(ctx, cfg.Config) }
	if cfg.Console != nil {
		run = func() error { return RunConsole(ctx, cfg.Config, *cfg.Console) }
	}
	if err := run(); err != nil {
		fmt.Fprintf(stderr, "tt mock: %v\n", err)
		if h := KeyHint(err); h != "" {
			fmt.Fprintln(stderr, h)
		}
		return 1
	}
	return 0
}

// keyHintText says where the trusted gate keys come from.
const keyHintText = `hint: TT_GATE_PUBKEYS lists the public keys of the publication gate (kid:base64url, e.g. pack-1:...),
      not the policy signing key. Copy the exact value from the console:
      Pacchetti twin (Twin packs) > open a pack > "Come usarlo nei test" ("Use it in tests", copy button),
      or download gate-keys.txt there and run
      TT_GATE_PUBKEYS=./gate-keys.txt tt mock --pack <file.ttpack>.
      The same value is served to any console user at GET /api/v1/gate/keys (?format=txt for the file).`

// KeyHint returns the explanation printed after a key or signature error
// ("" for other errors).
func KeyHint(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, pack.ErrNoKeys) || errors.Is(err, pack.ErrBadSignature) || errors.Is(err, pack.ErrUnknownKey) {
		return keyHintText
	}
	msg := err.Error()
	for _, s := range []string{pack.EnvGatePubKeys, "trusted keys", "malformed key entry", "Ed25519 public key", "key file"} {
		if strings.Contains(msg, s) {
			return keyHintText
		}
	}
	return ""
}

// CLIConfig is the result of flag parsing.
type CLIConfig struct {
	Config
	// Console is set in console mode (--console): the packs come from tt-core.
	Console *ConsoleConfig
	quiet   bool
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

// ParseFlags parses the `tt mock` flags. The control token is not a flag (it
// would show up in the process list): it comes from TT_CONTROL_TOKEN.
func ParseFlags(args []string, out io.Writer) (*CLIConfig, error) {
	var c CLIConfig
	fs := flag.NewFlagSet("tt mock", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {
		fmt.Fprintln(out, "Usage: tt mock --pack <dir|file.ttpack> [flags]          (file mode, for CI)")
		fmt.Fprintln(out, "       tt mock --console <url> --group <group> [flags]   (console mode: the console sends the packs)")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Console mode: the mock downloads the latest published pack of the group from the console, verifies it as")
		fmt.Fprintln(out, "a file (TT_GATE_PUBKEYS), switches to a newer one as soon as it is published and shows itself on the")
		fmt.Fprintln(out, "console's Mock page (URLs, last calls, scenarios). The mock token (TT_MOCK_TOKEN, shown once on the Mock")
		fmt.Fprintln(out, "page) can only download that group's pack and report: it opens nothing else of the console.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Serves a signed twin pack as a stateful mock. The words are the console's (Italian / English):")
		fmt.Fprintln(out, "  scenari / scenarios  presets of faults and forced outcomes (console: Scenari mock; GET /__tt/scenarios)")
		fmt.Fprintln(out, "  guasti / faults      errors, network failures and latency injected into responses (--faults, --latency)")
		fmt.Fprintln(out, "  orologio / clock     the virtual time of a session: advances on command, never backwards (POST /__tt/sessions/{id}/clock/advance)")
		fmt.Fprintln(out, "  sessioni / sessions  the isolated state of one test, chosen with the X-TT-Session header (POST /__tt/sessions)")
		fmt.Fprintln(out, "                       or, with --identity-header, by the caller's identity: one session and one synthetic customer per user")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Environment: TT_GATE_PUBKEYS (trusted gate keys, kid:base64url,... or a file), TT_CONTROL_TOKEN (bearer token for /__tt/).")
		fmt.Fprintln(out, "Console mode: TT_MOCK_TOKEN (mock token), TT_MOCK_CONSOLE, TT_MOCK_GROUP, TT_MOCK_PUBLIC_URL, TT_MOCK_CONSOLE_CA (flags win).")
		fmt.Fprintln(out, "The gate keys are in the console: Pacchetti twin (Twin packs) > a pack > \"Come usarlo nei test\" (\"Use it in tests\"): copy, or download gate-keys.txt.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Example:")
		fmt.Fprintln(out, "  export TT_GATE_PUBKEYS=./gate-keys.txt TT_CONTROL_TOKEN=\"$(openssl rand -hex 24)\"")
		fmt.Fprintln(out, "  tt mock --pack twin.ttpack --addr 127.0.0.1:8480 &")
		fmt.Fprintln(out, "  curl localhost:8480/__tt/health                       # public; the other /__tt/ calls need the bearer token")
		fmt.Fprintln(out, "  curl -H 'X-TT-Session: t1' -X POST localhost:8480/__svc/<service>/<path>   # <service> as listed by GET /__tt/pack")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Full guide: Aiuto > Manuale utente (User guide) in the console, section 10 (docs/USER_GUIDE.md).")
		fmt.Fprintln(out)
		fs.PrintDefaults()
	}
	fs.StringVar(&c.Pack, "pack", "", "twin pack (pacchetto twin): directory or .ttpack archive (required; a positional argument also works)")
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8480", "listen address of the mock (/__svc/...) and of the control API (/__tt/...); non-loopback needs TT_CONTROL_TOKEN")
	var seed string
	fs.StringVar(&seed, "seed", "", "seed of the default session (sessione default); default: the pack seed")
	fs.StringVar(&c.Faults, "faults", "observed", "faults (guasti) of new sessions: observed (as seen in the traffic, from faults.json of the pack) or off. Custom rules (status, net_error, latency_ms, p, times) are set per session: PUT /__tt/sessions/{id}/faults")
	fs.StringVar(&c.Latency, "latency", LatencyReal, "latency (latenza) of responses: real (sleep for the observed time), record (only write it in the journal, fast tests) or off")
	fs.DurationVar(&c.NetTimeout, "net-timeout", 30*time.Second, "how long a simulated network timeout holds the connection")
	fs.DurationVar(&c.MaxPackAge, "max-pack-age", 0, "refuse packs created longer ago than this (0 = packs without not_after older than 90d; negative = no age check)")
	fs.IntVar(&c.MaxSessions, "max-sessions", 1000, "maximum number of concurrent sessions")
	fs.Int64Var(&c.MaxBodyBytes, "max-body", 1<<20, "maximum request body size in bytes")
	fs.IntVar(&c.JournalMax, "journal-max", 10000, "journal entries kept per session")
	fs.Int64Var(&c.JournalMaxBytes, "journal-max-bytes", 32<<20, "journal bytes kept per session (JSON size; oldest entries go first)")
	fs.DurationVar(&c.SessionIdleTTL, "session-idle-ttl", 24*time.Hour, "evict sessions (sessioni, except default) idle for this long; negative = never")
	fs.DurationVar(&c.MaxAdvance, "max-advance", 3660*24*time.Hour, "largest single advance of the virtual clock (orologio)")
	fs.BoolVar(&c.quiet, "quiet", false, "log warnings only")
	var idc IdentityConfig
	var idMap string
	fs.StringVar(&idc.Header, "identity-header", "", "session per user (sessione per utente): request header whose value chooses the session and the synthetic customer when X-TT-Session is absent, any name (e.g. x-user-id) ($"+EnvIdentityHeader+"); the value is only hashed, never logged")
	fs.StringVar(&idc.Claim, "identity-claim", "", "with --identity-header: the header carries a JWT (Bearer or bare) and this claim is the identity, e.g. sub; the signature is not verified ($"+EnvIdentityClaim+")")
	fs.StringVar(&idMap, "identity-map", "", "with --identity-header: JSON file {\"<test user>\": \"<customer id>\"} giving chosen users a specific synthetic customer ($"+EnvIdentityMap+"); the hashing key is $"+EnvIdentityKey+" (at least 32 bytes; without it the mapping changes at every start)")
	var s3c S3Config
	var s3Hosts, s3Buckets string
	fs.BoolVar(&s3c.Enabled, "s3", envOr("TT_MOCK_S3", "") == "true", "serve a minimal S3-compatible API (put/get/head/delete, ListObjectsV2, multipart) at /__s3/<bucket>/<key> and on --s3-host; any SigV4 signature is accepted (no auth check: test only) ($TT_MOCK_S3=true)")
	fs.StringVar(&s3Hosts, "s3-host", envOr("TT_MOCK_S3_HOSTS", ""), "comma-separated S3 endpoint host names: <host>/<bucket>/<key> (path style) and <bucket>.<host>/<key> (virtual-host style) ($TT_MOCK_S3_HOSTS)")
	fs.StringVar(&s3Buckets, "s3-buckets", envOr("TT_MOCK_S3_BUCKETS", ""), "comma-separated bucket names that exist in every session; empty: any bucket, created on first write ($TT_MOCK_S3_BUCKETS)")
	fs.Int64Var(&s3c.MaxObjectBytes, "s3-max-object", 16<<20, "largest S3 object in bytes")
	fs.Int64Var(&s3c.MaxSessionBytes, "s3-max-bytes", 256<<20, "S3 bytes kept per session")
	var pagesFile string
	fs.StringVar(&pagesFile, "pages", envOr("TT_MOCK_PAGES", ""), "JSON file of third-party pages (pagine di terzi: payment, e-signature) with their buttons, return URLs and callbacks ($TT_MOCK_PAGES); in console mode they come from the console")
	var cc ConsoleConfig
	fs.StringVar(&cc.URL, "console", envOr(EnvConsoleURL, ""), "console mode: URL of the traffic-twin console (tt-core); the packs come from there ($"+EnvConsoleURL+")")
	fs.StringVar(&cc.Group, "group", envOr(EnvMockGroup, ""), "console mode: group (team) whose published pack is served ($"+EnvMockGroup+")")
	fs.StringVar(&cc.Token, "token", "", "console mode: mock token; prefer $"+EnvMockToken+" (a flag shows up in the process list)")
	fs.StringVar(&cc.PublicURL, "public-url", envOr(EnvPublicURL, ""), "console mode: URL your tests use to reach this mock, shown in the console ($"+EnvPublicURL+"; default http://<addr>)")
	fs.StringVar(&cc.CAFile, "console-ca", envOr(EnvConsoleCA, ""), "console mode: PEM file of the CA of the console certificate, if it is not a public one ($"+EnvConsoleCA+")")
	fs.StringVar(&cc.Instance, "instance", envOr(EnvInstanceName, ""), "console mode: name of this mock in the console (default: the host name)")
	fs.DurationVar(&cc.Interval, "report-interval", 5*time.Second, "console mode: how often the mock reports to the console and picks up new packs and commands")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if c.Pack == "" && fs.NArg() == 1 {
		c.Pack = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return nil, errors.New("unexpected arguments")
	}
	if cc.URL != "" {
		if c.Pack != "" {
			return nil, errors.New("--pack and --console exclude each other: a file (CI) or the console")
		}
		if cc.Token == "" {
			cc.Token = envOr(EnvMockToken, "")
		}
		if err := cc.validate(); err != nil {
			return nil, err
		}
		c.Console = &cc
		c.Pack = "console"
	}
	if c.Pack == "" {
		return nil, errors.New("--pack is required (or --console <url> --group <group> for console mode)")
	}
	if seed != "" {
		n, err := strconv.ParseUint(seed, 10, 64)
		if err != nil {
			return nil, errors.New("--seed must be a non-negative integer")
		}
		c.Seed = &n
	}
	if err := idc.fromEnv(idMap); err != nil {
		return nil, err
	}
	if idc.Header != "" {
		c.Identity = &idc
	}
	if s3c.Enabled || s3Hosts != "" || s3Buckets != "" {
		s3c.Enabled = true
		s3c.Hosts, s3c.Buckets = splitList(s3Hosts), splitList(s3Buckets)
		c.S3 = &s3c
	}
	if pagesFile != "" {
		pc, err := LoadPages(pagesFile)
		if err != nil {
			return nil, err
		}
		c.Pages = pc
	}
	if err := c.Config.applyDefaults(); err != nil {
		return nil, err
	}
	return &c, nil
}
