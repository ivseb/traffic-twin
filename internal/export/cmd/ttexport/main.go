// Command ttexport is a development front end of internal/export. It reads an
// UNVERIFIED unpacked pack directory (see export.DirSource); the production
// entry point is `tt export`, which verifies the pack first.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/ivseb/traffic-twin/internal/export"
)

func main() {
	var f export.Flags
	fs := flag.NewFlagSet("ttexport", flag.ExitOnError)
	f.Register(fs)
	_ = fs.Parse(os.Args[1:])
	if f.Pack == "" {
		fmt.Fprintln(os.Stderr, "ttexport: --pack is required")
		os.Exit(2)
	}
	res, err := export.Run(context.Background(), f.Config(export.DirSource{Dir: f.Pack}))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ttexport:", err)
		os.Exit(1)
	}
	targets := make([]string, 0, len(res.Reports))
	for t := range res.Reports {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		r := res.Reports[t]
		fmt.Printf("%s: %d files, losses by kind %v\n", t, r.Counts["files"], r.LossByKind)
	}
}
