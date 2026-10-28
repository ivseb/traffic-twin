package main

import (
	"context"
	"io"

	"github.com/ivseb/traffic-twin/internal/obi"
)

// runObi runs the OBI (eBPF) adapter bridge (internal/obi).
func runObi(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return obi.RunCLI(ctx, args, stdout, stderr, version)
}
