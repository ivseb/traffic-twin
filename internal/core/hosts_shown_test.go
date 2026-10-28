package core

import (
	"testing"

	"github.com/ivseb/traffic-twin/internal/hostpat"
)

// TestShownPatternOfDeclaredBase: a service declared on an IP literal is
// shown as its class, never as the address (usability test 3: the registry
// showed 127.0.0.1:9101 under a domain "0.1").
func TestShownPatternOfDeclaredBase(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:9101":      "ip:private:9101",
		"8.8.8.8":             "ip:public",
		"api.carrier.example": "api.carrier.example",
		"tt-egress:9090":      "tt-egress:9090",
		"[::1]:8080":          "ip:private:8080",
	} {
		got := shownPattern(in)
		if got != want {
			t.Errorf("shownPattern(%q) = %q, want %q", in, got, want)
		}
		if d := hostpat.Domain(got); d == "0.1" || d == "1" {
			t.Errorf("shownPattern(%q): domain %q", in, d)
		}
	}
}
