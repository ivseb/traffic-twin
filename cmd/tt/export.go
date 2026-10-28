package main

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/ivseb/traffic-twin/internal/export"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/pack"
)

func runMock(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return mock.RunCLI(ctx, args, stdout, stderr)
}

// runExport verifies the pack with internal/pack (TT_GATE_PUBKEYS) before any
// exporter sees its content.
func runExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("export", stderr)
	var f export.Flags
	f.Register(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if f.Pack == "" && fs.NArg() == 1 {
		f.Pack = fs.Arg(0)
	}
	if f.Pack == "" {
		fmt.Fprintln(stderr, "tt export: --pack is required")
		return 2
	}
	keys, err := pack.KeySetFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "tt export: %v\n", err)
		return 1
	}
	revoked, err := pack.RevokedKIDsFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "tt export: %v\n", err)
		return 1
	}
	p, err := pack.Load(f.Pack, pack.Options{Keys: keys, RevokedKIDs: revoked})
	if err != nil {
		fmt.Fprintf(stderr, "tt export: refusing pack: %v\n", err)
		return 1
	}
	res, err := export.Run(ctx, f.Config(export.PackSource{Pack: p}))
	if err != nil {
		fmt.Fprintf(stderr, "tt export: %v\n", err)
		return 1
	}
	targets := make([]string, 0, len(res.Reports))
	for t := range res.Reports {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	fmt.Fprintf(stdout, "exported %d files to %s (%v)\n", len(res.Files), f.Out, targets)
	return 0
}
