package mock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack"
)

func TestKeyHintSaysWhereTheGateKeysAre(t *testing.T) {
	_, empty := pack.ParseKeySet("")
	for _, err := range []error{empty, fmt.Errorf("mock: refusing pack: %w", pack.ErrBadSignature), fmt.Errorf("x: %w", pack.ErrUnknownKey)} {
		if h := KeyHint(err); !strings.Contains(h, "Use it in tests") || !strings.Contains(h, "gate-keys.txt") {
			t.Errorf("hint for %v: %q", err, h)
		}
	}
	if h := KeyHint(errors.New("listen tcp: address already in use")); h != "" {
		t.Errorf("hint for an unrelated error: %q", h)
	}
}

func TestRunCLIPrintsTheKeyHint(t *testing.T) {
	t.Setenv(pack.EnvGatePubKeys, "")
	var out, errb bytes.Buffer
	code := RunCLI(context.Background(), []string{"--pack", t.TempDir()}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "TT_GATE_PUBKEYS") || !strings.Contains(errb.String(), "Use it in tests") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}
