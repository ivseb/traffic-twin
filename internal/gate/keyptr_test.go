package gate

import (
	"context"
	"strings"
	"testing"
)

// Red team round 2: a positive on an object KEY (or below such a key) never
// reaches a finding pointer: the key becomes "@k<index>" in every check.
func TestGateKeyPositiveNotInPointer(t *testing.T) {
	ctx := context.Background()
	w := strings.Replace(okWorld, `"profile":{`, `"profile":{"ORD-2026-000777":{"status":"x"},`, 1)
	res, err := Run(ctx, input(w, &fakeMatcher{real: map[string]bool{"ORD-2026-000777": true}}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed() {
		t.Fatal("key positive passed")
	}
	seen := false
	for _, c := range res.Report.Checks {
		for _, f := range c.Findings {
			if strings.Contains(f.Pointer, "ORD-2026") || strings.ContainsAny(f.Pointer, "\x00\x01") {
				t.Errorf("%s finding pointer %q carries the key", c.ID, f.Pointer)
			}
			if c.ID == CheckReverseHMAC && f.Pointer == "2:/profile/@k0" {
				seen = true
			}
		}
	}
	if !seen {
		t.Errorf("no reverse-hmac finding at 2:/profile/@k0: %+v", res.Report.Checks)
	}
	if strings.Contains(string(res.Report.File()), "ORD-2026") {
		t.Error("gate-report.json carries the key")
	}
}

func TestRenderPointerEscapes(t *testing.T) {
	ptr := "/" + escapePointer("a/b~c") + "\x00" + "0" + "/" + escapePointer("secret") + "\x00" + "3" + keyMark
	if got := renderPointer(ptr, map[string]bool{"secret": true}); got != "/a~1b~0c/@k3" {
		t.Errorf("render = %q", got)
	}
	if k, ok := keyOf(ptr); !ok || k != "secret" {
		t.Errorf("keyOf = %q %v", k, ok)
	}
}
