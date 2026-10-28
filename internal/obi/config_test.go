package obi

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func generate(t *testing.T, author string, o ConfigOptions) (*Generated, map[string]any) {
	t.Helper()
	v, _ := compile(t, author)
	g, err := GenerateConfig(v.Policy, o)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(g.YAML, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n%s", err, g.YAML)
	}
	return g, doc
}

func rulesOf(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	en := doc["ebpf"].(map[string]any)["payload_extraction"].(map[string]any)["http"].(map[string]any)["enrichment"].(map[string]any)
	var out []map[string]any
	for _, r := range en["rules"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func strsOf(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestConfigDeniesByDefault(t *testing.T) {
	g, doc := generate(t, shopPolicy, ConfigOptions{ServiceName: "shop-api", OpenPorts: "3000"})

	traces := doc["otel_traces_export"].(map[string]any)
	if traces["protocol"] != "http/json" || traces["endpoint"] != DefaultEndpoint {
		t.Errorf("traces export = %v", traces)
	}
	if got := strsOf(traces["instrumentations"]); len(got) != 1 || got[0] != "http" {
		t.Errorf("instrumentations = %v: only HTTP is needed", got)
	}
	disc := doc["discovery"].(map[string]any)["instrument"].([]any)[0].(map[string]any)
	if disc["open_ports"] != "3000" || disc["name"] != "shop-api" {
		t.Errorf("discovery = %v", disc)
	}
	ebpf := doc["ebpf"].(map[string]any)
	if ebpf["buffer_sizes"].(map[string]any)["http"] != DefaultCaptureSize {
		t.Errorf("buffer = %v", ebpf["buffer_sizes"])
	}
	en := ebpf["payload_extraction"].(map[string]any)["http"].(map[string]any)["enrichment"].(map[string]any)
	pol := en["policy"].(map[string]any)["default_action"].(map[string]any)
	if en["enabled"] != true || pol["headers"] != "exclude" || pol["body"] != "exclude" {
		t.Errorf("enrichment = %v", en)
	}

	// Headers: only what the policy and the sanitizer need.
	var includeReq, includeResp []string
	var obfuscated []string
	for _, r := range rulesOf(t, doc) {
		if r["type"] != "headers" {
			continue
		}
		pats := strsOf(r["match"].(map[string]any)["patterns"])
		switch {
		case r["action"] == "obfuscate":
			obfuscated = append(obfuscated, pats...)
		case r["scope"] == "all":
			includeReq, includeResp = append(includeReq, pats...), append(includeResp, pats...)
		case r["scope"] == "request":
			includeReq = append(includeReq, pats...)
		case r["scope"] == "response":
			includeResp = append(includeResp, pats...)
		}
	}
	wantReq := "content-encoding content-length content-type x-customer-id"
	wantResp := "content-encoding content-length content-type"
	if got := strings.Join(sortedCopy(includeReq), " "); got != wantReq {
		t.Errorf("request headers = %q, want %q", got, wantReq)
	}
	if got := strings.Join(sortedCopy(includeResp), " "); got != wantResp {
		t.Errorf("response headers = %q, want %q", got, wantResp)
	}
	// Credentials nobody needs are obfuscated explicitly, never included.
	for _, h := range []string{"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"} {
		if !contains(obfuscated, h) || contains(includeReq, h) || contains(includeResp, h) {
			t.Errorf("header %s: obfuscated=%v in=%v/%v", h, contains(obfuscated, h), includeReq, includeResp)
		}
	}
	if len(g.RequestHeaders) == 0 {
		t.Error("RequestHeaders empty")
	}
}

func TestConfigBodiesOnlyForPolicyOperations(t *testing.T) {
	_, doc := generate(t, shopPolicy, ConfigOptions{ServiceName: "shop-api"})
	type key struct{ action, scope, method string }
	pats := map[key][]string{}
	obf := map[key][]string{}
	for _, r := range rulesOf(t, doc) {
		if r["type"] != "body" {
			continue
		}
		m := r["match"].(map[string]any)
		k := key{r["action"].(string), r["scope"].(string), ""}
		if ms, ok := m["methods"]; ok {
			k.method = strsOf(ms)[0]
		}
		pats[k] = append(pats[k], strsOf(m["url_path_patterns"])...)
		if p, ok := m["obfuscation_json_paths"]; ok {
			obf[k] = append(obf[k], strsOf(p)...)
		}
	}
	// Request bodies: POST /orders (own rules), POST /v1/shipments (carrier), and the
	// global content rules do not open request bodies elsewhere.
	check := func(k key, want string) {
		t.Helper()
		if got := strings.Join(sortedCopy(pats[k]), " "); got != want {
			t.Errorf("%+v patterns = %q, want %q", k, got, want)
		}
	}
	check(key{"include", "request", "POST"}, "/orders /v1/shipments")
	check(key{"include", "request", "GET"}, "")
	// Responses: every listed operation (the global errors rules may apply to any of them).
	check(key{"include", "response", "POST"}, "/orders /v1/shipments")
	check(key{"include", "response", "GET"}, "/orders/* /v1/shipments/*")
	// The policy has a global errors rule ($.error.code), which applies to any
	// operation: that is the only catch-all, and only for response bodies.
	check(key{"include", "response", ""}, "/*")
	check(key{"include", "request", ""}, "")
	for k, ps := range pats {
		for _, p := range ps {
			if strings.Contains(p, "admin") {
				t.Errorf("foreign pattern %q in %+v", p, k)
			}
		}
	}
	// The explicit drop of the card number is obfuscated by OBI as well.
	if got := obf[key{"obfuscate", "request", "POST"}]; len(got) != 1 || got[0] != "$.card.number" {
		t.Errorf("obfuscated json paths = %v", got)
	}
}

func TestConfigHeadersFromRulesSubjectAndBaggage(t *testing.T) {
	const author = `{
 "format":"tt.policy/v1","policy_id":"p-x","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization","jwt_claim":"sub"}},
 "sampling":{"rate":0.5,"trust_baggage":true},
 "services":{
  "svc":{"match":{"inbound":true,"internal":true},"ops":{
    "GET /a/{id}":{"request":{"headers":{"x-request-id":"hmac","accept":"keep"},"cookies":{"sid":"hmac"}},"response":{"headers":{"x-request-id":"hmac","set-cookie":"drop"}}}}}}}`
	_, doc := generate(t, author, ConfigOptions{ServiceName: "svc"})
	got := map[string][]string{}
	var obf []string
	for _, r := range rulesOf(t, doc) {
		if r["type"] != "headers" {
			continue
		}
		p := strsOf(r["match"].(map[string]any)["patterns"])
		if r["action"] == "obfuscate" {
			obf = append(obf, p...)
			continue
		}
		got[r["scope"].(string)] = append(got[r["scope"].(string)], p...)
	}
	all := strings.Join(sortedCopy(got["all"]), " ")
	if all != "content-encoding content-length content-type set-cookie x-request-id" && all != "content-encoding content-length content-type x-request-id" {
		t.Errorf("headers needed on both sides = %q", all)
	}
	req := strings.Join(sortedCopy(got["request"]), " ")
	if req != "accept authorization baggage cookie" {
		t.Errorf("request-only headers = %q (subject authorization, trusted baggage, cookie rule)", req)
	}
	// authorization and cookie are needed here, so they are not obfuscated.
	if contains(obf, "authorization") || contains(obf, "cookie") || !contains(obf, "x-api-key") {
		t.Errorf("obfuscated = %v", obf)
	}
}

func TestConfigContainerDropWithDeeperRuleIsNotObfuscated(t *testing.T) {
	const author = `{
 "format":"tt.policy/v1","policy_id":"p-x","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},
 "sampling":{"rate":1},
 "services":{"svc":{"match":{"inbound":true},"ops":{
   "POST /a":{"request":{"body":{"$.user.id":"hmac","$.user":"drop","$.secret":"drop"}}}}}}}`
	_, doc := generate(t, author, ConfigOptions{ServiceName: "svc"})
	for _, r := range rulesOf(t, doc) {
		if r["action"] != "obfuscate" || r["type"] != "body" {
			continue
		}
		paths := strsOf(r["match"].(map[string]any)["obfuscation_json_paths"])
		if len(paths) != 1 || paths[0] != "$.secret" {
			t.Errorf("obfuscated paths = %v: $.user must stay readable for $.user.id", paths)
		}
	}
}

func TestConfigIsDeterministicAndValidated(t *testing.T) {
	v, _ := compile(t, shopPolicy)
	a, err := GenerateConfig(v.Policy, ConfigOptions{ServiceName: "shop-api"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		b, _ := GenerateConfig(v.Policy, ConfigOptions{ServiceName: "shop-api"})
		if !bytes.Equal(a.YAML, b.YAML) {
			t.Fatal("the same policy gave two different files")
		}
	}
	if _, err := GenerateConfig(v.Policy, ConfigOptions{CaptureBytes: MaxCaptureSize + 1}); err == nil {
		t.Error("capture size over the OBI maximum accepted")
	}
	if _, err := GenerateConfig(nil, ConfigOptions{}); err == nil {
		t.Error("nil policy accepted")
	}
	// Another bridge's inbound service does not leak into this configuration.
	other, _ := GenerateConfig(v.Policy, ConfigOptions{ServiceName: "billing"})
	if bytes.Contains(other.YAML, []byte("/orders")) {
		t.Errorf("shop-api operations appear in the configuration of service billing:\n%s", other.YAML)
	}
	if !bytes.Contains(other.YAML, []byte("/v1/shipments")) {
		t.Error("external services must be in every bridge's configuration")
	}
	if !bytes.HasPrefix(a.YAML, []byte("# Generated by")) {
		t.Error("missing header comment")
	}
}

func TestCLI(t *testing.T) {
	var out, errb bytes.Buffer
	// No enrollment: usage error, exit 2, nothing started.
	if code := RunCLI(context.Background(), nil, &out, &errb, "dev"); code != 2 || !strings.Contains(errb.String(), "enrollment required") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	errb.Reset()
	if code := RunCLI(context.Background(), []string{"--bogus"}, &out, &errb, "dev"); code != 2 {
		t.Fatalf("bad flag: exit %d", code)
	}
	if code := RunCLI(context.Background(), []string{"--capture-bytes", "999999", "--enroll-url", "https://x", "--service-name", "a"}, &out, &errb, "dev"); code != 2 {
		t.Fatalf("capture bytes: exit %d", code)
	}

	// tt obi config on a compiled body and on an envelope.
	v, _ := compile(t, shopPolicy)
	dir := t.TempDir()
	bodyFile := filepath.Join(dir, "body.json")
	envFile := filepath.Join(dir, "env.json")
	_ = os.WriteFile(bodyFile, v.Body, 0o600)
	_ = os.WriteFile(envFile, []byte(`{"body_b64":"`+base64.RawURLEncoding.EncodeToString(v.Body)+`"}`), 0o600)
	var first string
	for _, f := range []string{bodyFile, envFile} {
		out.Reset()
		errb.Reset()
		if code := RunCLI(context.Background(), []string{"config", "--policy", f, "--service-name", "shop-api", "--open-ports", "3000"}, &out, &errb, "dev"); code != 0 {
			t.Fatalf("config exit %d: %s", code, errb.String())
		}
		if first == "" {
			first = out.String()
		} else if out.String() != first {
			t.Error("body and envelope gave different configurations")
		}
		if !strings.Contains(out.String(), "default_action") || !strings.Contains(out.String(), "open_ports") {
			t.Errorf("unexpected output:\n%s", out.String())
		}
	}
	errb.Reset()
	if code := RunCLI(context.Background(), []string{"config"}, &out, &errb, "dev"); code != 2 {
		t.Fatalf("config without --policy: exit %d", code)
	}
	_ = os.WriteFile(bodyFile, []byte(`{"format":"nope"}`), 0o600)
	if code := RunCLI(context.Background(), []string{"config", "--policy", bodyFile}, &out, &errb, "dev"); code != 2 {
		t.Fatalf("invalid policy: exit %d", code)
	}
}

func TestSourceVersion(t *testing.T) {
	for in, want := range map[string]string{"v1.2.3": "1.2.3", "1.2.3-rc.1": "1.2.3-rc.1", "dev": "0.0.0-dev", "": "0.0.0-dev"} {
		if got := SourceVersion(in); got != want {
			t.Errorf("SourceVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
