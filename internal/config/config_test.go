package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tt.yaml")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// kgEnv supplies the one key without a default.
var kgEnv = []string{"TT_CORE_KEYGUARD_URL=unix:///run/tt/keyguard.sock"}

func TestDefaultsAreValidAndSecure(t *testing.T) {
	cfg, err := Load("", kgEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Addr != "127.0.0.1:7070" || !cfg.AdminIsLoopback() {
		t.Errorf("admin addr = %q", cfg.Admin.Addr)
	}
	if cfg.Intake.Addr != "127.0.0.1:4318" || !cfg.Intake.TLS.Managed || cfg.FleetPublicURL() != "https://localhost:4318" {
		t.Errorf("intake defaults: %+v %s", cfg.Intake, cfg.FleetPublicURL())
	}
	if len(cfg.Drift.WebhookAllow) != 0 || !cfg.Gate.PIIDetectors || cfg.Gate.KMin != 20 || cfg.Contract.KMin != 20 || cfg.Miner.KMin != 20 {
		t.Errorf("component defaults: %+v %+v", cfg.Drift, cfg.Gate)
	}
	if _, err := Load("", nil); err == nil || !strings.Contains(err.Error(), "keyguard.url") {
		t.Errorf("missing keyguard.url accepted: %v", err)
	}
	if cfg.Auth.OIDC.Enabled || !cfg.Auth.Local.Enabled {
		t.Errorf("auth defaults: %+v", cfg.Auth)
	}
}

func TestExampleFile(t *testing.T) {
	cfg, err := Load("testdata/example.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.OIDC.RoleMapping["tt-auditors"][0] != "auditor" {
		t.Errorf("role mapping not parsed: %v", cfg.Auth.OIDC.RoleMapping)
	}
	if cfg.Auth.Session.IdleTimeout != 30*time.Minute {
		t.Errorf("idle = %v", cfg.Auth.Session.IdleTimeout)
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	for _, doc := range []string{
		"admin:\n  adr: 127.0.0.1:1\n",
		"nope: 1\n",
		"auth:\n  oidc:\n    client_secret: x\n", // secrets never come from YAML
		"admin: {}\n---\nadmin: {}\n",
	} {
		p := writeFile(t, doc, 0o600)
		if _, err := Load(p, kgEnv); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}

func TestEmptyFileIsDefaults(t *testing.T) {
	p := writeFile(t, "", 0o600)
	if _, err := Load(p, kgEnv); err != nil {
		t.Fatal(err)
	}
}

func TestWorldWritableRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	p := writeFile(t, "log: {level: info}\n", 0o666)
	if _, err := Load(p, kgEnv); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"non-loopback without tls":   "admin:\n  addr: 0.0.0.0:7070\n",
		"all interfaces without tls": "admin:\n  addr: :7070\n",
		"hostname without tls":       "admin:\n  addr: tt.example:7070\n",
		"bad addr":                   "admin:\n  addr: nope\n",
		"contract k below gate":      "contract:\n  k_min: 5\n",
		"miner k below gate":         "miner:\n  k_min: 5\n",
		"half tls":                   "admin:\n  tls:\n    cert_file: a\n",
		"intake without tls":         "intake:\n  addr: 127.0.0.1:4318\n  tls: {managed: false}\n",
		"intake public no url":       "intake:\n  addr: 0.0.0.0:4318\n",
		"fleet public url http":      "fleet:\n  public_url: http://tt.example:4318\n",
		"keyguard bad scheme":        "keyguard:\n  url: http://kg.example:7443\n",
		"keyguard relative socket":   "keyguard:\n  url: unix://kg.sock\n",
		"keyguard mtls no identity":  "keyguard:\n  url: https://kg.example:7443\n  server_pin: sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
		"keyguard mtls no server id": "keyguard:\n  url: https://kg.example:7443\n  client_cert_file: a\n  client_key_file: b\n",
		"keyguard bad pin":           "keyguard:\n  url: https://kg.example:7443\n  client_cert_file: a\n  client_key_file: b\n  server_pin: abc\n",
		"keyguard socket with tls":   "keyguard:\n  url: unix:///run/kg.sock\n  ca_file: a\n",
		"k too small":                "gate:\n  k_min: 1\n",
		"world k below gate":         "world:\n  k_min: 10\n",
		"pii off":                    "gate:\n  pii_detectors: false\n",
		"valid days":                 "gate:\n  valid_days: 0\n",
		"retention":                  "retention:\n  events: 1h\n",
		"webhook allow star":         "drift:\n  webhook_allow: ['*']\n",
		"miner schedule":             "miner:\n  schedule: 1s\n",
		"cert ttl":                   "fleet:\n  client_cert_ttl: 1m\n",
		"enroll rate":                "fleet:\n  enroll_rate_limit: {ip: {requests_per_minute: 0, burst: 1}}\n",
		"intake managed and files":   "intake:\n  addr: 127.0.0.1:4318\n  tls: {managed: true, cert_file: a, key_file: b}\n",
		"intake same addr":           "intake:\n  addr: 127.0.0.1:7070\n  tls: {managed: true}\n",
		"memory db":                  "storage:\n  path: ':memory:'\n",
		"idle too short":             "auth:\n  session: {idle_timeout: 10s}\n",
		"absolute < idle":            "auth:\n  session: {idle_timeout: 2h, absolute_timeout: 1h}\n",
		"no auth":                    "auth:\n  local: {enabled: false}\n",
		"oidc http issuer":           "auth:\n  oidc: {enabled: true, issuer_url: 'http://idp.example', client_id: c, redirect_url: 'https://tt.example/api/v1/auth/oidc/callback'}\n",
		"oidc bad redirect path":     "auth:\n  oidc: {enabled: true, issuer_url: 'https://idp.example', client_id: c, redirect_url: 'https://tt.example/cb'}\n",
		"oidc no client":             "auth:\n  oidc: {enabled: true, issuer_url: 'https://idp.example', redirect_url: 'https://tt.example/api/v1/auth/oidc/callback'}\n",
		"oidc unknown role":          "auth:\n  oidc: {enabled: true, issuer_url: 'https://idp.example', client_id: c, redirect_url: 'https://tt.example/api/v1/auth/oidc/callback', roles_claim: groups, role_mapping: {g: [root]}}\n",
		"oidc mapping no claim":      "auth:\n  oidc: {enabled: true, issuer_url: 'https://idp.example', client_id: c, redirect_url: 'https://tt.example/api/v1/auth/oidc/callback', role_mapping: {g: [admin]}}\n",
		"oidc no openid scope":       "auth:\n  oidc: {enabled: true, issuer_url: 'https://idp.example', client_id: c, redirect_url: 'https://tt.example/api/v1/auth/oidc/callback', scopes: [email]}\n",
		"rate limit zero":            "auth:\n  rate_limit: {requests_per_minute: 0}\n",
		"log level":                  "log: {level: trace}\n",
		"body limit":                 "admin:\n  http: {max_body_bytes: 1}\n",
		"timeout zero":               "admin:\n  http: {read_timeout: 0s}\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, doc, 0o600)
			env := kgEnv
			if strings.Contains(doc, "keyguard:") {
				env = nil // the environment would override the file
			}
			if _, err := Load(p, env); err == nil {
				t.Errorf("accepted:\n%s", doc)
			}
		})
	}
}

func TestValidNonLoopbackWithTLS(t *testing.T) {
	p := writeFile(t, "admin:\n  addr: 0.0.0.0:7443\n  tls: {cert_file: a.crt, key_file: a.key}\nintake:\n  addr: 0.0.0.0:4318\n  tls: {managed: true}\nfleet:\n  public_url: https://tt.example:4318\n"+
		"keyguard:\n  url: https://kg.example:7443\n  client_cert_file: c.crt\n  client_key_file: c.key\n  server_pin: sha256:0000000000000000000000000000000000000000000000000000000000000000\n", 0o600)
	if _, err := Load(p, nil); err != nil {
		t.Fatal(err)
	}
	p = writeFile(t, "auth:\n  oidc: {enabled: true, issuer_url: 'http://127.0.0.1:9999', client_id: c, redirect_url: 'http://localhost:7070/api/v1/auth/oidc/callback'}\n", 0o600)
	if _, err := Load(p, kgEnv); err != nil {
		t.Fatalf("loopback http OIDC should be allowed for development: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	env := []string{
		"PATH=/bin",
		"TT_CORE_CONFIG=/ignored",
		"TT_CORE_ADMIN_ADDR=127.0.0.1:9000",
		"TT_CORE_AUTH_SESSION_IDLE_TIMEOUT=45m",
		"TT_CORE_AUTH_RATE_LIMIT_BURST=7",
		"TT_CORE_AUTH_OIDC_ENABLED=true",
		"TT_CORE_AUTH_OIDC_ISSUER_URL=https://idp.example",
		"TT_CORE_AUTH_OIDC_CLIENT_ID=tt",
		"TT_CORE_AUTH_OIDC_REDIRECT_URL=https://tt.example/api/v1/auth/oidc/callback",
		"TT_CORE_AUTH_OIDC_SCOPES=openid, email",
		"TT_CORE_AUTH_OIDC_CLIENT_SECRET=s3cr3t-value",
		"TT_CORE_ADMIN_HTTP_MAX_BODY_BYTES=2048",
		"TT_CORE_KEYGUARD_URL=unix:///run/tt/keyguard.sock",
		"TT_CORE_DRIFT_WEBHOOK_ALLOW=hooks.example, *.alerts.example",
		"TT_CORE_FLEET_ENROLL_RATE_LIMIT_TOKEN_BURST=9",
	}
	cfg, err := Load("", env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Addr != "127.0.0.1:9000" || cfg.Auth.Session.IdleTimeout != 45*time.Minute ||
		cfg.Auth.RateLimit.Burst != 7 || !cfg.Auth.OIDC.Enabled || cfg.Auth.OIDC.ClientSecret != "s3cr3t-value" ||
		len(cfg.Auth.OIDC.Scopes) != 2 || cfg.Admin.HTTP.MaxBodyBytes != 2048 ||
		len(cfg.Drift.WebhookAllow) != 2 || cfg.Fleet.EnrollRateLimit.Token.Burst != 9 {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestEnvErrors(t *testing.T) {
	if _, err := Load("", []string{"TT_CORE_ADMIN_ADR=x"}); err == nil {
		t.Error("unknown env var accepted")
	}
	_, err := Load("", []string{"TT_CORE_AUTH_SESSION_IDLE_TIMEOUT=secret-looking-value"})
	if err == nil {
		t.Fatal("invalid duration accepted")
	}
	if strings.Contains(err.Error(), "secret-looking-value") {
		t.Error("error message echoes the env value")
	}
}

func TestClientSecretFile(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "secret")
	if err := os.WriteFile(sec, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "auth:\n  oidc: {enabled: true, issuer_url: 'https://idp.example', client_id: c, redirect_url: 'https://tt.example/api/v1/auth/oidc/callback', client_secret_file: '" + sec + "'}\n"
	p := writeFile(t, doc, 0o600)
	cfg, err := Load(p, kgEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.OIDC.ClientSecret != "from-file" {
		t.Errorf("secret = %q", cfg.Auth.OIDC.ClientSecret)
	}
	if _, err := Load(p, []string{"TT_CORE_AUTH_OIDC_CLIENT_SECRET=x"}); err == nil {
		t.Error("both secret sources accepted")
	}
}

func TestEnvNamesCoverSecret(t *testing.T) {
	names := strings.Join(EnvNames(), " ")
	for _, want := range []string{"TT_CORE_ADMIN_ADDR", "TT_CORE_AUTH_OIDC_CLIENT_SECRET", "TT_CORE_INTAKE_TLS_CLIENT_CA_FILE"} {
		if !strings.Contains(names, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(names, "ROLE_MAPPING") {
		t.Error("maps must not be env-overridable")
	}
}

func TestDeployExamples(t *testing.T) {
	for _, f := range []string{"core.dev.yaml", "core.production.yaml"} {
		if _, err := Load(filepath.Join("..", "..", "deploy", "examples", f), nil); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
