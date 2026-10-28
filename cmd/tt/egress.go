package main

import (
	"context"
	"io"

	"github.com/ivseb/traffic-twin/internal/egress"
)

// runEgress runs tt-egress, the outbound reverse proxy (internal/egress).
// MITM mode is not implemented.
func runEgress(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return egress.RunCLI(ctx, args, stdout, stderr, version)
}
