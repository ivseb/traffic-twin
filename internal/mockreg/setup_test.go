package mockreg

import (
	"strings"
	"testing"
)

// TestSetupSnippets: with an https console the Docker and tt commands pass
// the console CA, the tt command of the kit is there, and the version of the
// image is said (usability test #4, m1).
func TestSetupSnippets(t *testing.T) {
	s := setup("https://console.example.test:7443", "orders", "ghcr.io/ivseb/traffic-twin:0.1.0-lab.abc", "k1:pub", "ttm_secret")
	for _, want := range []string{`-v "$PWD/console-ca.pem:/etc/tt/console-ca.pem:ro"`, "--console-ca /etc/tt/console-ca.pem", "mock --console https://console.example.test:7443 --group orders"} {
		if !strings.Contains(s.Docker, want) {
			t.Errorf("docker lacks %q:\n%s", want, s.Docker)
		}
	}
	for _, want := range []string{"tt mock --console https://console.example.test:7443 --group orders", "--console-ca ./console-ca.pem", "version 0.1.0-lab.abc", "export TT_MOCK_TOKEN='ttm_secret'"} {
		if !strings.Contains(s.CLI, want) {
			t.Errorf("cli lacks %q:\n%s", want, s.CLI)
		}
	}
	if s.Version != "0.1.0-lab.abc" || !strings.Contains(s.Env, "TT_MOCK_CONSOLE_CA=") {
		t.Errorf("version %q env %q", s.Version, s.Env)
	}
	// Every line of a command but the last continues it (a comment inside would cut it).
	for name, text := range map[string]string{"docker": s.Docker, "cli": s.CLI} {
		lines := strings.Split(strings.TrimSpace(text), "\n")
		started := false
		for i, l := range lines {
			if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "export ") {
				continue
			}
			started = true
			if i < len(lines)-1 && !strings.HasSuffix(l, `\`) {
				t.Errorf("%s line %d does not continue: %q", name, i, l)
			}
		}
		if !started {
			t.Errorf("%s: no command", name)
		}
	}
	plain := setup("http://127.0.0.1:7080", "orders", "ghcr.io/ivseb/traffic-twin:latest", "", "ttm_x")
	if strings.Contains(plain.Docker, "console-ca") || strings.Contains(plain.CLI, "console-ca") || !strings.Contains(plain.CLI, "same version as the console") {
		t.Errorf("http console: %s\n%s", plain.Docker, plain.CLI)
	}
}
