// Command tt is the single traffic-twin binary. Each component (core, egress,
// mock, export) is exposed as a subcommand.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Build metadata, injected at link time:
//
//	go build -ldflags "-X main.version=... -X main.commit=... -X main.date=..."
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

func commands() []command {
	return []command{
		{"version", "print version information", runVersion},
		{"core", "run tt-core (intake, analysis, review UI, publication gate); \"core init\" writes a configuration", runCore},
		{"dev", "\"dev up\": single-host trial (keyguard on a Unix socket + core on loopback with TLS)", runDev},
		{"keyguard", "run tt keyguard, the zone-B key custodian (reverse-HMAC, policy and pack signing)", runKeyguard},
		{"egress", "run tt-egress, the outbound reverse proxy for stacks without an SDK", runEgress},
		{"obi", "run the OBI (eBPF) adapter: OTLP traces from OpenTelemetry eBPF Instrumentation to sanitized events", runObi},
		{"mock", "serve a twin package as a stateful mock", runMock},
		{"export", "convert a twin package to third-party mock formats", runExport},
		{"audit", "\"audit verify-archive\": verify archived audit segments offline (signatures, digests, hash chain)", runAudit},
		{"compact", "one-time maintenance: switch an existing core database to incremental auto_vacuum so purges free disk space", runCompact},
		{"injector", "run the Kubernetes mutating webhook that injects the SDK into annotated pods", runInjector},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		usage(stdout)
		return 0
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(ctx, args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "tt: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: tt <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, `Run "tt <command> -h" for command flags.`)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("tt "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags returns (exitCode, ok). ok is false when the caller must return
// exitCode immediately (help requested or invalid flags).
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "%s: unexpected arguments: %v\n", fs.Name(), fs.Args())
		return 2, false
	}
	return 0, true
}

func runVersion(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("version", stderr)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	fmt.Fprintf(stdout, "tt version %s (commit %s, built %s)\n", version, commit, date)
	return 0
}
