package ttsdk

import (
	"os/exec"
	"strings"
	"testing"
)

// The SDK module has no runtime dependency beyond the Go standard library and
// the shared internal packages of the traffic-twin module (which themselves
// use the standard library only). In particular it does not import
// OpenTelemetry, Gin or chi.
func TestZeroRuntimeDependencies(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not found")
	}
	out, err := exec.Command(goBin, "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		if !strings.HasPrefix(p, "github.com/ivseb/traffic-twin/") {
			t.Errorf("third-party dependency: %s", p)
		}
	}
}
