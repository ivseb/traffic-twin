// Command mkpack writes a signed demo twin package for the Kubernetes end-to-end
// test (deploy/test/kind-e2e.sh) and prints the matching TT_GATE_PUBKEYS value.
//
//	go run ./deploy/test/mkpack OUTDIR
//
// The package is synthetic and signed with a throwaway key: it is a test
// fixture, never a release artifact.
package main

import (
	"fmt"
	"os"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mkpack OUTDIR")
		os.Exit(2)
	}
	b, err := packtest.Build(os.Args[1], packtest.DemoSpec())
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkpack: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(b.Keys)
}
