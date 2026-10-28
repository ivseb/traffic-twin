// Package deploytest checks that the Helm charts render configuration that the real
// binaries accept: the core.yaml of the tt-core chart must pass config.Load, the environment
// of the tt-keyguard chart must pass keyguard.ConfigFromEnv, and the webhook list must drive
// both drift.webhook_allow and the NetworkPolicy egress rules.
//
// The tests need helm (or Docker, for the official alpine/helm image) and skip without them.
package deploytest

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/keyguard"
)

const helmImage = "alpine/helm:3.14.4"

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// render runs `helm template` and returns the decoded manifests.
func render(t *testing.T, chart string, args ...string) []map[string]any {
	t.Helper()
	root := repoRoot(t)
	var cmd *exec.Cmd
	base := append([]string{"template", "t", "deploy/helm/" + chart, "-n", "tt-test"}, args...)
	if p, err := exec.LookPath("helm"); err == nil {
		cmd = exec.Command(p, base...)
		cmd.Dir = root
	} else if d, err := exec.LookPath("docker"); err == nil {
		cmd = exec.Command(d, append([]string{"run", "--rm", "-v", root + ":/work", "-w", "/work", helmImage}, base...)...)
	} else {
		t.Skip("neither helm nor docker available")
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template %s %v: %v\n%s", chart, args, err, errb.String())
	}
	var docs []map[string]any
	dec := yaml.NewDecoder(&out)
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func find(t *testing.T, docs []map[string]any, kind string) map[string]any {
	t.Helper()
	for _, d := range docs {
		if d["kind"] == kind {
			return d
		}
	}
	t.Fatalf("no %s rendered", kind)
	return nil
}

func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("path %v: not an object at %q", path, k)
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("path %v: no element %d", path, k)
			}
			v = a[k]
		}
	}
	return v
}

// loadCoreConfig writes the rendered core.yaml (0600, like a mounted file) and loads it with the real loader.
func loadCoreConfig(t *testing.T, docs []map[string]any) *config.Config {
	t.Helper()
	cm := find(t, docs, "ConfigMap")
	text, _ := at(t, cm, "data", "config.yaml").(string)
	path := filepath.Join(t.TempDir(), "core.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, nil)
	if err != nil {
		t.Fatalf("tt-core rejects the rendered configuration: %v\n%s", err, text)
	}
	return cfg
}

func TestCoreChartRendersValidConfig(t *testing.T) {
	variants := map[string][]string{
		"defaults":     nil,
		"cert-manager": {"--set", "tls.certManager.enabled=true", "--set", "tls.certManager.issuerRef.name=ca"},
		"pin only":     {"--set", "keyguard.caFromSecret=false", "--set", "keyguard.serverPin=sha256:" + strings.Repeat("ab", 32)},
		"custom ports": {"--set", "config.admin.addr=:8443", "--set", "config.intake.addr=:9443", "--set", "keyguard.url=https://kg.example:9000"},
		"explicit fleet": {"--set", "config.fleet.public_url=https://tt.example.com:4318",
			"--set", "config.fleet.server_names={tt.example.com}", "--set", "config.fleet.client_cert_ttl=72h"},
		"other sections": {"--set", "config.miner.schedule=12h", "--set", "config.gate.k_min=25", "--set", "config.world.k_min=25", "--set", "config.contract.k_min=25", "--set", "config.miner.k_min=25", "--set", "config.retention.events=360h"},
	}
	for name, args := range variants {
		t.Run(name, func(t *testing.T) {
			docs := render(t, "tt-core", args...)
			cfg := loadCoreConfig(t, docs)
			if !cfg.Intake.TLS.Managed {
				t.Error("the intake certificate must be managed by Fleet")
			}
			if !strings.HasPrefix(cfg.Keyguard.URL, "https://") {
				t.Errorf("keyguard url = %q", cfg.Keyguard.URL)
			}
			if name == "defaults" {
				want := "https://t-tt-core-intake.tt-test.svc.cluster.local:4318"
				if cfg.Fleet.PublicURL != want {
					t.Errorf("fleet.public_url = %q, want %q", cfg.Fleet.PublicURL, want)
				}
				if cfg.Fleet.CADir != "/data/fleet-ca" || cfg.Storage.Path != "/data/tt-core.db" {
					t.Errorf("paths: %q %q", cfg.Fleet.CADir, cfg.Storage.Path)
				}
			}
		})
	}
}

// One list drives both the allow list of tt-core and the egress rules of the NetworkPolicy.
func TestCoreWebhooksDriveConfigAndNetworkPolicy(t *testing.T) {
	docs := render(t, "tt-core",
		"--set", "webhooks[0].host=alerts.tt.internal", "--set", "webhooks[0].cidr=10.20.30.40/32",
		"--set", "webhooks[1].host=chat.example.com", "--set", "webhooks[1].port=8443", "--set", "webhooks[1].cidr=192.0.2.0/24",
		"--set", "webhooks[2].host=*.hooks.example.org") // no cidr: allowed by the config, no rule in the network
	cfg := loadCoreConfig(t, docs)
	wantAllow := []string{"alerts.tt.internal", "chat.example.com:8443", "*.hooks.example.org"}
	if !reflect.DeepEqual(cfg.Drift.WebhookAllow, wantAllow) {
		t.Fatalf("drift.webhook_allow = %v, want %v", cfg.Drift.WebhookAllow, wantAllow)
	}
	np := find(t, docs, "NetworkPolicy")
	got := map[string]string{} // cidr -> port
	for _, r := range at(t, np, "spec", "egress").([]any) {
		for _, to := range r.(map[string]any)["to"].([]any) {
			if ip, ok := to.(map[string]any)["ipBlock"].(map[string]any); ok {
				ports := r.(map[string]any)["ports"].([]any)
				got[ip["cidr"].(string)] = strings.TrimSpace(strings.Join([]string{toStr(ports[0].(map[string]any)["port"])}, ""))
			}
		}
	}
	want := map[string]string{"10.20.30.40/32": "443", "192.0.2.0/24": "8443"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NetworkPolicy ipBlocks = %v, want %v", got, want)
	}
	// Nothing leaves towards the Internet: every rule is DNS, keyguard or one of the ipBlocks above.
	if n := len(at(t, np, "spec", "egress").([]any)); n != 2+len(want) {
		t.Errorf("egress rules = %d, want %d", n, 2+len(want))
	}
}

func toStr(v any) string {
	switch x := v.(type) {
	case int:
		return strings.TrimSpace(strings.Join([]string{itoa(x)}, ""))
	case string:
		return x
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestCoreWithoutWebhooksAllowsNone(t *testing.T) {
	cfg := loadCoreConfig(t, render(t, "tt-core"))
	if len(cfg.Drift.WebhookAllow) != 0 {
		t.Errorf("webhook_allow = %v", cfg.Drift.WebhookAllow)
	}
}

func TestKeyguardChartRendersValidEnvironment(t *testing.T) {
	variants := map[string][]string{
		"defaults":  nil,
		"client CA": {"--set", "tls.clientCASecret=core-ca"},
		"settings":  {"--set", "settings.TT_KEYGUARD_ADMIN_OVERRIDE=false", "--set", "settings.TT_KEYGUARD_POLICY_MAX_VALIDITY=720h"},
	}
	pin := "sha256:" + strings.Repeat("0a", 32)
	for name, extra := range variants {
		t.Run(name, func(t *testing.T) {
			docs := render(t, "tt-keyguard", append([]string{"--set", "clientPins[0]=" + pin}, extra...)...)
			sts := find(t, docs, "StatefulSet")
			var env []string
			for _, e := range at(t, sts, "spec", "template", "spec", "containers", 0, "env").([]any) {
				m := e.(map[string]any)
				env = append(env, m["name"].(string)+"="+toStr(m["value"]))
			}
			cfg, err := keyguard.ConfigFromEnv(env)
			if err != nil {
				t.Fatalf("keyguard rejects the rendered environment: %v\n%v", err, env)
			}
			if err := cfg.ValidateListener(); err != nil {
				t.Fatalf("keyguard listener: %v", err)
			}
			if cfg.Listen != ":7443" || len(cfg.ClientPins) != 1 || cfg.ClientPins[0] != pin {
				t.Errorf("listen %q pins %v", cfg.Listen, cfg.ClientPins)
			}
			if name == "settings" && (cfg.AdminOverride || cfg.PolicyValidity.Hours() != 720) {
				t.Errorf("settings not applied: override=%v validity=%v", cfg.AdminOverride, cfg.PolicyValidity)
			}
		})
	}
}
