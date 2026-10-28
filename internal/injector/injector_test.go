package injector

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- helpers ----

func testConfig() Config {
	c := DefaultConfig()
	c.SDKImages = map[string]string{
		"node":   "registry.example/tt/sdk-node:0.1.0",
		"python": "registry.example/tt/sdk-python:0.1.0",
		"java":   "registry.example/tt/sdk-java:0.1.0",
		"dotnet": "registry.example/tt/sdk-dotnet:0.1.0",
	}
	return c
}

func newMutator(t *testing.T, mod func(*Config)) *Mutator {
	t.Helper()
	cfg := testConfig()
	if mod != nil {
		mod(&cfg)
	}
	m, err := NewMutator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func loadReview(t *testing.T, name string) *AdmissionReview {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var r AdmissionReview
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &r
}

// ptr walks a decoded JSON value by keys (string) and indexes (int).
func ptr(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("path %v: %T is not an object at %q", path, v, k)
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

type rawOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func ops2(t *testing.T, patch []byte) []rawOp {
	var ops []rawOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatal(err)
	}
	return ops
}

// applyPatchPtr applies an RFC 6902 patch limited to add and replace, enough
// for what the webhook emits.
func applyPatchPtr(t *testing.T, doc json.RawMessage, ops []rawOp) json.RawMessage {
	t.Helper()
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		parts := strings.Split(strings.TrimPrefix(op.Path, "/"), "/")
		for i, p := range parts {
			parts[i] = strings.NewReplacer("~1", "/", "~0", "~").Replace(p)
		}
		var val any
		if err := json.Unmarshal(op.Value, &val); err != nil {
			t.Fatalf("%s: %v", op.Path, err)
		}
		root = patchAt(t, root, parts, op.Op, val, op.Path)
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func patchAt(t *testing.T, node any, parts []string, op string, val any, full string) any {
	key := parts[0]
	if len(parts) == 1 {
		switch n := node.(type) {
		case map[string]any:
			_, exists := n[key]
			if op == "replace" && !exists {
				t.Fatalf("replace of a missing member: %s", full)
			}
			if op != "add" && op != "replace" {
				t.Fatalf("unsupported op %q", op)
			}
			n[key] = val
			return n
		case []any:
			if key == "-" {
				if op != "add" {
					t.Fatalf("only add may use '-': %s", full)
				}
				return append(n, val)
			}
			i, err := strconv.Atoi(key)
			if err != nil || i >= len(n) {
				t.Fatalf("bad index in %s", full)
			}
			if op == "replace" {
				n[i] = val
				return n
			}
			t.Fatalf("add at an index is not used by the webhook: %s", full)
		}
		t.Fatalf("patch target is a scalar: %s", full)
	}
	switch n := node.(type) {
	case map[string]any:
		c, ok := n[key]
		if !ok {
			t.Fatalf("patch path does not exist: %s", full)
		}
		n[key] = patchAt(t, c, parts[1:], op, val, full)
		return n
	case []any:
		i, err := strconv.Atoi(key)
		if err != nil || i >= len(n) {
			t.Fatalf("bad index in %s", full)
		}
		n[i] = patchAt(t, n[i], parts[1:], op, val, full)
		return n
	}
	t.Fatalf("patch walks through a scalar: %s", full)
	return nil
}

// review runs the webhook and returns the response and the patched pod.
func review(t *testing.T, m *Mutator, name string) (*AdmissionResponse, Outcome, any) {
	t.Helper()
	in := loadReview(t, name)
	out, oc := m.Review(in)
	if out.APIVersion != "admission.k8s.io/v1" || out.Kind != "AdmissionReview" {
		t.Fatalf("bad envelope: %+v", out)
	}
	resp := out.Response
	if resp == nil || resp.UID != in.Request.UID {
		t.Fatalf("response uid not echoed: %+v", resp)
	}
	return resp, oc, patched(t, in.Request.Object, resp)
}

func patched(t *testing.T, obj json.RawMessage, resp *AdmissionResponse) any {
	t.Helper()
	doc := obj
	if len(resp.Patch) > 0 {
		if resp.PatchType != "JSONPatch" {
			t.Fatalf("patchType = %q", resp.PatchType)
		}
		doc = applyPatchPtr(t, obj, ops2(t, resp.Patch))
	}
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// envMap returns the env of container i as name -> variable object.
func envMap(t *testing.T, pod any, i int) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	env, _ := ptr(t, pod, "spec", "containers", i).(map[string]any)["env"].([]any)
	for _, e := range env {
		m := e.(map[string]any)
		name := m["name"].(string)
		if _, dup := out[name]; dup {
			t.Errorf("duplicate env var %s", name)
		}
		out[name] = m
	}
	return out
}

func envValue(t *testing.T, pod any, i int, name string) string {
	t.Helper()
	e, ok := envMap(t, pod, i)[name]
	if !ok {
		t.Fatalf("env %s missing", name)
	}
	s, _ := e["value"].(string)
	return s
}

func volumeNames(pod any) []string {
	var out []string
	spec := pod.(map[string]any)["spec"].(map[string]any)
	vs, _ := spec["volumes"].([]any)
	for _, v := range vs {
		out = append(out, v.(map[string]any)["name"].(string))
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func mustNoPatch(t *testing.T, resp *AdmissionResponse) {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("pod denied: %+v", resp.Status)
	}
	if len(resp.Patch) != 0 {
		t.Fatalf("unexpected patch: %s", resp.Patch)
	}
}

func annotation(t *testing.T, pod any, key string) string {
	t.Helper()
	a, _ := ptr(t, pod, "metadata", "annotations").(map[string]any)
	s, _ := a[key].(string)
	return s
}

// ---- tests ----

func TestNodeBasic(t *testing.T) {
	resp, oc, pod := review(t, newMutator(t, nil), "node_basic")
	if !resp.Allowed || oc.Result != "injected" || oc.Language != "node" {
		t.Fatalf("resp=%+v oc=%+v", resp, oc)
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("warnings = %v", resp.Warnings)
	}

	// Init container.
	init := ptr(t, pod, "spec", "initContainers", 0).(map[string]any)
	if init["name"] != InitContainerName || init["image"] != "registry.example/tt/sdk-node:0.1.0" || init["imagePullPolicy"] != "IfNotPresent" {
		t.Errorf("init container = %v", init)
	}
	sc := init["securityContext"].(map[string]any)
	if sc["runAsNonRoot"] != true || sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false {
		t.Errorf("init securityContext = %v", sc)
	}
	if drop := sc["capabilities"].(map[string]any)["drop"].([]any); len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("capabilities = %v", sc["capabilities"])
	}

	// Volumes.
	vols := volumeNames(pod)
	for _, v := range []string{SDKVolumeName, StateVolumeName, HMACVolumeName} {
		if !contains(vols, v) {
			t.Errorf("volume %s missing in %v", v, vols)
		}
	}
	hv := ptr(t, pod, "spec", "volumes", 2, "secret").(map[string]any)
	if hv["secretName"] != "tt-hmac" || hv["optional"] != true || hv["defaultMode"] != float64(0o444) {
		t.Errorf("hmac volume = %v", hv)
	}

	// Environment.
	env := envMap(t, pod, 0)
	if envValue(t, pod, 0, "NODE_ENV") != "production" {
		t.Error("NODE_ENV changed")
	}
	if got := envValue(t, pod, 0, "NODE_OPTIONS"); got != "--import /tt/sdk/node/dist/esm/register.js" {
		t.Errorf("NODE_OPTIONS = %q", got)
	}
	if got := envValue(t, pod, 0, "TT_SERVICE_NAME"); got != "shop-api" {
		t.Errorf("TT_SERVICE_NAME = %q", got)
	}
	if got := envValue(t, pod, 0, "TT_HMAC_KEY_FILE"); got != "/var/run/secrets/traffic-twin/hmac-key" {
		t.Errorf("TT_HMAC_KEY_FILE = %q", got)
	}
	if got := envValue(t, pod, 0, "TT_STATE_DIR"); got != StateDir {
		t.Errorf("TT_STATE_DIR = %q", got)
	}
	for key, name := range map[string]string{"TT_ENROLL_URL": "url", "TT_ENROLL_TOKEN": "token"} {
		ref := env[key]["valueFrom"].(map[string]any)["secretKeyRef"].(map[string]any)
		if ref["name"] != "tt-enroll" || ref["key"] != name || ref["optional"] != true {
			t.Errorf("%s secretKeyRef = %v", key, ref)
		}
		if _, plain := env[key]["value"]; plain {
			t.Errorf("%s must not carry a plain value", key)
		}
	}

	// Mounts.
	mounts := ptr(t, pod, "spec", "containers", 0, "volumeMounts").([]any)
	got := map[string]string{}
	for _, m := range mounts {
		mm := m.(map[string]any)
		got[mm["name"].(string)] = mm["mountPath"].(string)
	}
	want := map[string]string{SDKVolumeName: SDKMountPath, StateVolumeName: StateMountPath, HMACVolumeName: HMACMountPath}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mounts = %v, want %v", got, want)
	}
	if annotation(t, pod, AnnotationStatus) != "injected" {
		t.Errorf("status = %q", annotation(t, pod, AnnotationStatus))
	}
}

func TestNodeCoexistsWithOpenTelemetry(t *testing.T) {
	in := loadReview(t, "node_with_otel")
	var before map[string]any
	_ = json.Unmarshal(in.Request.Object, &before)

	resp, oc, pod := review(t, newMutator(t, nil), "node_with_otel")
	if oc.Result != "injected" || oc.Language != "node" { // "Node" is case-insensitive
		t.Fatalf("oc = %+v", oc)
	}
	// NODE_OPTIONS keeps the OpenTelemetry entry and gains ours, after it.
	wantOpts := "--max-old-space-size=512 --require /otel-auto-instrumentation-nodejs/autoinstrumentation.js --import /tt/sdk/node/dist/esm/register.js"
	if got := envValue(t, pod, 0, "NODE_OPTIONS"); got != wantOpts {
		t.Errorf("NODE_OPTIONS = %q", got)
	}
	// No OTEL_* variable is touched, added or removed.
	beforeEnv := ptr(t, before, "spec", "containers", 0, "env").([]any)
	after := envMap(t, pod, 0)
	for _, e := range beforeEnv {
		m := e.(map[string]any)
		if n := m["name"].(string); strings.HasPrefix(n, "OTEL_") && !reflect.DeepEqual(after[n], m) {
			t.Errorf("%s changed: %v -> %v", n, m, after[n])
		}
	}
	for n := range after {
		if strings.HasPrefix(n, "OTEL_") {
			found := false
			for _, e := range beforeEnv {
				found = found || e.(map[string]any)["name"] == n
			}
			if !found {
				t.Errorf("OTEL variable %s was added", n)
			}
		}
	}
	// OTEL_SERVICE_NAME is the service name: TT_SERVICE_NAME is not set.
	if _, ok := after["TT_SERVICE_NAME"]; ok {
		t.Error("TT_SERVICE_NAME set although OTEL_SERVICE_NAME exists")
	}
	// The OpenTelemetry init container and volume survive, ours come after.
	if ptr(t, pod, "spec", "initContainers", 0, "name") != "opentelemetry-auto-instrumentation-nodejs" ||
		ptr(t, pod, "spec", "initContainers", 1, "name") != InitContainerName {
		t.Errorf("init containers = %v", ptr(t, pod, "spec", "initContainers"))
	}
	if !contains(volumeNames(pod), "opentelemetry-auto-instrumentation-nodejs") {
		t.Error("OpenTelemetry volume lost")
	}
	// The second container is not instrumented.
	if _, ok := ptr(t, pod, "spec", "containers", 1).(map[string]any)["env"]; ok {
		t.Error("sidecar was modified")
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("warnings = %v", resp.Warnings)
	}
}

func TestPythonSelectedContainerAndSecretOverride(t *testing.T) {
	resp, oc, pod := review(t, newMutator(t, nil), "python_two_containers")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	if got := envValue(t, pod, 0, "PYTHONPATH"); got != "/tt/sdk/python/bootstrap:/tt/sdk/python/site:/app/lib" {
		t.Errorf("PYTHONPATH = %q", got)
	}
	if got := envValue(t, pod, 0, "TT_SERVICE_NAME"); got != "billing_api" {
		t.Errorf("TT_SERVICE_NAME = %q", got)
	}
	ref := envMap(t, pod, 0)["TT_ENROLL_TOKEN"]["valueFrom"].(map[string]any)["secretKeyRef"].(map[string]any)
	if ref["name"] != "billing-tt-enroll" {
		t.Errorf("secret = %v", ref["name"])
	}
	if _, ok := ptr(t, pod, "spec", "containers", 1).(map[string]any)["env"]; ok {
		t.Error("worker container was modified")
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], `"ghost"`) {
		t.Errorf("warnings = %v", resp.Warnings)
	}
}

func TestJavaWithOTelAgent(t *testing.T) {
	_, oc, pod := review(t, newMutator(t, nil), "java_otel_agent")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	// The OpenTelemetry agent stays first and untouched; the extension and our -javaagent are appended.
	want := "-javaagent:/otel-auto-instrumentation-java/javaagent.jar -Dotel.javaagent.extensions=/tt/sdk/java/ext/sdk-otel-extension.jar -javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar"
	if got := envValue(t, pod, 0, "JAVA_TOOL_OPTIONS"); got != want {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", got)
	}
	if _, ok := envMap(t, pod, 0)["CLASSPATH"]; ok {
		t.Error("CLASSPATH must not be touched in zero-code mode")
	}
	if got := envValue(t, pod, 0, "OTEL_TRACES_EXPORTER"); got != "otlp" {
		t.Errorf("OTEL_TRACES_EXPORTER = %q", got)
	}
	if got := envValue(t, pod, 0, "TT_SERVICE_NAME"); got != "ledger" {
		t.Errorf("TT_SERVICE_NAME = %q", got)
	}
}

func TestJavaOTelExtensionNotAddedWhenConfigured(t *testing.T) {
	in := loadReview(t, "java_otel_agent")
	obj := strings.Replace(string(in.Request.Object), `{"name": "OTEL_TRACES_EXPORTER", "value": "otlp"}`,
		`{"name": "OTEL_JAVAAGENT_EXTENSIONS", "value": "/ext/mine.jar"}`, 1)
	if !strings.Contains(obj, "OTEL_JAVAAGENT_EXTENSIONS") {
		// The fixture is indented differently once re-marshalled: rebuild it.
		var v map[string]any
		_ = json.Unmarshal(in.Request.Object, &v)
		c := ptr(t, v, "spec", "containers", 0).(map[string]any)
		c["env"] = []any{c["env"].([]any)[0], map[string]any{"name": "OTEL_JAVAAGENT_EXTENSIONS", "value": "/ext/mine.jar"}}
		b, _ := json.Marshal(v)
		obj = string(b)
	}
	in.Request.Object = json.RawMessage(obj)
	out, _ := newMutator(t, nil).Review(in)
	pod := patched(t, in.Request.Object, out.Response)
	if got := envValue(t, pod, 0, "JAVA_TOOL_OPTIONS"); strings.Contains(got, "otel.javaagent.extensions") || !strings.HasSuffix(got, " -javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar") {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", got)
	}
	if got := envValue(t, pod, 0, "OTEL_JAVAAGENT_EXTENSIONS"); got != "/ext/mine.jar" {
		t.Errorf("OTEL_JAVAAGENT_EXTENSIONS = %q", got)
	}
	if len(out.Response.Warnings) != 1 || !strings.Contains(out.Response.Warnings[0], "extensions already configured") {
		t.Errorf("warnings = %v", out.Response.Warnings)
	}
}

func TestJavaPlainAddsTheAgentAndTheEnvironment(t *testing.T) {
	_, oc, pod := review(t, newMutator(t, nil), "java_plain")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	env := envMap(t, pod, 0)
	if got := envValue(t, pod, 0, "JAVA_TOOL_OPTIONS"); got != "-javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar" {
		t.Errorf("JAVA_TOOL_OPTIONS = %q (no OTel extension without an OTel agent)", got)
	}
	if _, ok := env["CLASSPATH"]; ok {
		t.Error("CLASSPATH must not be set without opt-in")
	}
	if _, ok := env["TT_ENROLL_URL"]; !ok {
		t.Error("TT_ENROLL_URL missing")
	}
	if got := envValue(t, pod, 0, "TT_SERVICE_NAME"); got != "ledger" { // container name fallback
		t.Errorf("TT_SERVICE_NAME = %q", got)
	}
}

func TestJavaOTelExtensionForcedByAnnotation(t *testing.T) {
	in := loadReview(t, "java_plain")
	var v map[string]any
	_ = json.Unmarshal(in.Request.Object, &v)
	ptr(t, v, "metadata", "annotations").(map[string]any)[AnnotationJavaOTelExtension] = "true"
	in.Request.Object, _ = json.Marshal(v)
	out, _ := newMutator(t, nil).Review(in)
	pod := patched(t, in.Request.Object, out.Response)
	if got := envValue(t, pod, 0, "JAVA_TOOL_OPTIONS"); got != "-Dotel.javaagent.extensions=/tt/sdk/java/ext/sdk-otel-extension.jar -javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar" {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", got)
	}
}

// Other -javaagent flags (a vendor APM, the OpenTelemetry Operator's) are never replaced, reordered or
// duplicated: ours is appended after them.
func TestJavaNeverReplacesAnExistingJavaAgent(t *testing.T) {
	_, oc, pod := review(t, newMutator(t, nil), "java_two_agents")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	want := "-Xmx512m -javaagent:/apm/vendor-agent.jar=mode=full -javaagent:/otel-auto-instrumentation-java/javaagent.jar" +
		" -Dotel.javaagent.extensions=/tt/sdk/java/ext/sdk-otel-extension.jar -javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar"
	if got := envValue(t, pod, 0, "JAVA_TOOL_OPTIONS"); got != want {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", got)
	}
}

// java-classpath is library mode: the agent would start a second SDK, so it is not added.
func TestJavaLibraryModeAddsNoAgent(t *testing.T) {
	_, oc, pod := review(t, newMutator(t, nil), "java_library_mode")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	if got := envValue(t, pod, 0, "JAVA_TOOL_OPTIONS"); strings.Contains(got, "traffic-twin-agent") {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", got)
	}
	if got := envValue(t, pod, 0, "CLASSPATH"); got != "/tt/sdk/java/lib/*" {
		t.Errorf("CLASSPATH = %q", got)
	}
}

func TestJavaToolOptionsFromAValueSourceIsNotModified(t *testing.T) {
	in := loadReview(t, "java_plain")
	var v map[string]any
	_ = json.Unmarshal(in.Request.Object, &v)
	c := ptr(t, v, "spec", "containers", 0).(map[string]any)
	c["env"] = []any{map[string]any{"name": "JAVA_TOOL_OPTIONS", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "jvm", "key": "opts"}}}}
	in.Request.Object, _ = json.Marshal(v)
	out, _ := newMutator(t, nil).Review(in)
	pod := patched(t, in.Request.Object, out.Response)
	if _, ok := envMap(t, pod, 0)["JAVA_TOOL_OPTIONS"]["valueFrom"]; !ok {
		t.Error("JAVA_TOOL_OPTIONS valueFrom must be left alone")
	}
	if len(out.Response.Warnings) == 0 {
		t.Error("expected a warning telling to add the -javaagent by hand")
	}
}

func TestForeignJavaAgent(t *testing.T) {
	for opts, want := range map[string]bool{
		"": false, "-Xmx1g": false, "-javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar": false,
		"-javaagent:/a/b.jar": true, "-Xmx1g -javaagent:/a/b.jar=x -javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar": true,
		"-Dfoo=-javaagent:x": false,
	} {
		if got := foreignJavaAgent(opts); got != want {
			t.Errorf("foreignJavaAgent(%q) = %v, want %v", opts, got, want)
		}
	}
}

func TestUnknownLanguageIsRefusedWithoutBlocking(t *testing.T) {
	resp, oc, pod := review(t, newMutator(t, nil), "unknown_language")
	if !resp.Allowed {
		t.Fatal("unknown language must not deny the pod")
	}
	if oc.Result != "refused" {
		t.Fatalf("oc = %+v", oc)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], `unknown language "ruby"`) {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	// Only the status annotation is added: nothing else of the pod changes.
	var ops []patchOp
	if err := json.Unmarshal(resp.Patch, &ops); err != nil || len(ops) != 1 || !strings.HasPrefix(ops[0].Path, "/metadata/annotations/") {
		t.Fatalf("patch = %s", resp.Patch)
	}
	if !strings.HasPrefix(annotation(t, pod, AnnotationStatus), "refused: unknown language") {
		t.Errorf("status = %q", annotation(t, pod, AnnotationStatus))
	}
	if _, ok := ptr(t, pod, "spec").(map[string]any)["initContainers"]; ok {
		t.Error("init container added for an unknown language")
	}
}

func TestUnknownLanguageDeniedOnlyWhenAsked(t *testing.T) {
	m := newMutator(t, func(c *Config) { c.DenyUnknown = true })
	out, oc := m.Review(loadReview(t, "unknown_language"))
	if out.Response.Allowed || out.Response.Status == nil || out.Response.Status.Code != 403 || oc.Result != "refused" {
		t.Fatalf("resp = %+v", out.Response)
	}
}

func TestLanguageWithoutImageIsRefused(t *testing.T) {
	m := newMutator(t, func(c *Config) { delete(c.SDKImages, "node") })
	resp, oc, _ := review(t, m, "node_basic")
	if !resp.Allowed || oc.Result != "refused" || !strings.Contains(oc.Reason, "no SDK image") {
		t.Fatalf("resp=%+v oc=%+v", resp, oc)
	}
	if strings.Contains(string(resp.Patch), "initContainers") {
		t.Error("init container added without an image")
	}
}

func TestDotnetStartupHookAndHostingStartup(t *testing.T) {
	resp, oc, pod := review(t, newMutator(t, nil), "dotnet_basic")
	if oc.Result != "injected" || !resp.Allowed {
		t.Fatalf("oc = %+v", oc)
	}
	inits := ptr(t, pod, "spec", "initContainers").([]any)
	if len(inits) != 1 || inits[0].(map[string]any)["image"] != "registry.example/tt/sdk-dotnet:0.1.0" {
		t.Errorf("init containers = %v", inits)
	}
	if !contains(volumeNames(pod), SDKVolumeName) {
		t.Error("SDK volume expected for dotnet")
	}
	env := envMap(t, pod, 0)
	for _, n := range []string{"TT_ENROLL_URL", "TT_ENROLL_TOKEN", "TT_SERVICE_NAME", "TT_HMAC_KEY_FILE", "TT_STATE_DIR"} {
		if _, ok := env[n]; !ok {
			t.Errorf("%s missing", n)
		}
	}
	if got := envValue(t, pod, 0, "DOTNET_STARTUP_HOOKS"); got != "/tt/sdk/dotnet/TrafficTwin.StartupHook.dll" {
		t.Errorf("DOTNET_STARTUP_HOOKS = %q", got)
	}
	if got := envValue(t, pod, 0, "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES"); got != "TrafficTwin.Sdk.AspNetCore" {
		t.Errorf("ASPNETCORE_HOSTINGSTARTUPASSEMBLIES = %q", got)
	}
	if got := envValue(t, pod, 0, "TT_SERVICE_NAME"); got != "orders" {
		t.Errorf("TT_SERVICE_NAME = %q (ReplicaSet hash must be stripped)", got)
	}
	if st := annotation(t, pod, AnnotationStatus); st != "injected" {
		t.Errorf("status = %q", st)
	}
}

// A startup hook that is already there (OpenTelemetry .NET automatic instrumentation) keeps running first.
func TestDotnetAppendsToExistingHooksAndHostingStartups(t *testing.T) {
	_, oc, pod := review(t, newMutator(t, nil), "dotnet_with_hooks")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	if got := envValue(t, pod, 0, "DOTNET_STARTUP_HOOKS"); got != "/otel-dotnet-auto/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll:/tt/sdk/dotnet/TrafficTwin.StartupHook.dll" {
		t.Errorf("DOTNET_STARTUP_HOOKS = %q", got)
	}
	if got := envValue(t, pod, 0, "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES"); got != "Contoso.Diagnostics;TrafficTwin.Sdk.AspNetCore" {
		t.Errorf("ASPNETCORE_HOSTINGSTARTUPASSEMBLIES = %q", got)
	}
}

func TestDotnetWithoutImageIsRefused(t *testing.T) {
	m := newMutator(t, func(c *Config) { delete(c.SDKImages, "dotnet") })
	resp, oc, _ := review(t, m, "dotnet_basic")
	if oc.Result != "refused" || !resp.Allowed {
		t.Errorf("oc = %+v", oc)
	}
}

func TestPodsWithoutAnnotationAndOtherOperationsAreUntouched(t *testing.T) {
	m := newMutator(t, nil)
	for _, name := range []string{"no_annotation", "pod_update"} {
		resp, oc, _ := review(t, m, name)
		mustNoPatch(t, resp)
		if oc.Result != "skipped" {
			t.Errorf("%s: oc = %+v", name, oc)
		}
	}
}

func TestOptOutValues(t *testing.T) {
	m := newMutator(t, nil)
	for _, v := range []string{"", "false", "none", "disabled", " No "} {
		in := loadReview(t, "node_basic")
		var obj map[string]any
		_ = json.Unmarshal(in.Request.Object, &obj)
		ptr(t, obj, "metadata", "annotations").(map[string]any)[AnnotationInject] = v
		in.Request.Object, _ = json.Marshal(obj)
		out, _ := m.Review(in)
		mustNoPatch(t, out.Response)
		if len(out.Response.Warnings) != 0 {
			t.Errorf("%q: warnings = %v", v, out.Response.Warnings)
		}
	}
}

func TestValueFromAndExistingTTVariablesAreRespected(t *testing.T) {
	resp, oc, pod := review(t, newMutator(t, nil), "node_valuefrom")
	if oc.Result != "injected" {
		t.Fatalf("oc = %+v", oc)
	}
	env := envMap(t, pod, 0)
	if _, ok := env["NODE_OPTIONS"]["valueFrom"]; !ok || env["NODE_OPTIONS"]["value"] != nil {
		t.Errorf("NODE_OPTIONS = %v, must stay valueFrom", env["NODE_OPTIONS"])
	}
	if env["TT_ENROLL_URL"]["value"] != "https://tt-core.prod.example:4318" || env["TT_ENROLL_URL"]["valueFrom"] != nil {
		t.Errorf("TT_ENROLL_URL overridden: %v", env["TT_ENROLL_URL"])
	}
	if envValue(t, pod, 0, "TT_SERVICE_NAME") != "cfg-app" {
		t.Errorf("TT_SERVICE_NAME = %q", envValue(t, pod, 0, "TT_SERVICE_NAME"))
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "NODE_OPTIONS is set from valueFrom") {
		t.Errorf("warnings = %v", resp.Warnings)
	}
}

// Every injected pod, patched and submitted again (reinvocation, or a retry),
// produces no further change.
func TestIdempotent(t *testing.T) {
	m := newMutator(t, nil)
	for _, name := range []string{"node_basic", "node_with_otel", "python_two_containers", "java_otel_agent", "java_plain", "java_two_agents", "java_library_mode", "dotnet_basic", "dotnet_with_hooks", "node_valuefrom", "unknown_language"} {
		in := loadReview(t, name)
		out, _ := m.Review(in)
		if len(out.Response.Patch) == 0 {
			t.Fatalf("%s: no patch on the first pass", name)
		}
		once := applyPatchPtr(t, in.Request.Object, ops2(t, out.Response.Patch))
		again := *in
		again.Request = &AdmissionRequest{}
		*again.Request = *in.Request
		again.Request.Object = once
		out2, _ := m.Review(&again)
		if len(out2.Response.Patch) != 0 {
			t.Errorf("%s: second pass produced a patch: %s", name, out2.Response.Patch)
		}
	}
}

// The OpenTelemetry Operator may add -javaagent after us: with
// reinvocationPolicy IfNeeded the webhook runs again and completes the wiring
// without repeating what it already did.
func TestJavaReinvocationAfterOTelOperator(t *testing.T) {
	m := newMutator(t, nil)
	in := loadReview(t, "java_plain")
	out, _ := m.Review(in)
	pod1 := applyPatchPtr(t, in.Request.Object, ops2(t, out.Response.Patch))

	var v map[string]any
	_ = json.Unmarshal(pod1, &v)
	c := ptr(t, v, "spec", "containers", 0).(map[string]any)
	// The Operator extends the JAVA_TOOL_OPTIONS we already set (our agent is in it).
	for _, e := range c["env"].([]any) {
		if e.(map[string]any)["name"] == "JAVA_TOOL_OPTIONS" {
			e.(map[string]any)["value"] = e.(map[string]any)["value"].(string) + " -javaagent:/otel-auto-instrumentation-java/javaagent.jar"
		}
	}
	pod2, _ := json.Marshal(v)

	again := *in
	again.Request = &AdmissionRequest{}
	*again.Request = *in.Request
	again.Request.Object = pod2
	out2, _ := m.Review(&again)
	pod3 := patched(t, pod2, out2.Response)
	got := envValue(t, pod3, 0, "JAVA_TOOL_OPTIONS")
	if !strings.HasSuffix(got, "-Dotel.javaagent.extensions=/tt/sdk/java/ext/sdk-otel-extension.jar") || strings.Count(got, "traffic-twin-agent.jar") != 1 {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", got)
	}
	if !strings.HasPrefix(got, "-javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar -javaagent:/otel-auto-instrumentation-java/javaagent.jar") {
		t.Errorf("the Operator's agent after ours must be left where it is: %q", got)
	}
	if n := strings.Count(string(out2.Response.Patch), "initContainers"); n != 0 {
		t.Errorf("init container added twice (%d)", n)
	}
}

func TestMalformedRequestsAreAllowed(t *testing.T) {
	m := newMutator(t, nil)
	out, oc := m.Review(nil)
	if !out.Response.Allowed || oc.Result != "error" {
		t.Errorf("nil: %+v", out.Response)
	}
	in := loadReview(t, "node_basic")
	in.Request.Object = json.RawMessage(`{"metadata": 5}`)
	out, oc = m.Review(in)
	if !out.Response.Allowed || len(out.Response.Patch) != 0 || oc.Result != "error" || out.Response.UID != in.Request.UID {
		t.Errorf("garbage pod: %+v", out.Response)
	}
	in = loadReview(t, "node_basic")
	in.Request.Kind.Kind = "Deployment"
	out, _ = m.Review(in)
	mustNoPatch(t, out.Response)
}

func TestServiceNameDerivation(t *testing.T) {
	mk := func(mod func(p *pod)) string {
		var p pod
		p.Spec.Containers = []container{{Name: "Main_Container"}}
		mod(&p)
		pl := &plan{pod: &p}
		return pl.serviceName(0)
	}
	owner := func(kind, name string) func(*pod) {
		return func(p *pod) {
			p.Metadata.OwnerReferences = []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			}{{Kind: kind, Name: name}}
		}
	}
	cases := []struct {
		name string
		mod  func(*pod)
		want string
	}{
		{"annotation first", func(p *pod) {
			p.Metadata.Annotations = map[string]string{AnnotationServiceName: "Shop Front"}
			p.Metadata.Labels = map[string]string{"app.kubernetes.io/name": "x"}
		}, "shop-front"},
		{"recommended label", func(p *pod) { p.Metadata.Labels = map[string]string{"app.kubernetes.io/name": "api", "app": "other"} }, "api"},
		{"app label", func(p *pod) { p.Metadata.Labels = map[string]string{"app": "legacy"} }, "legacy"},
		{"replicaset", owner("ReplicaSet", "cart-5c4d6f7b9"), "cart"},
		{"statefulset", owner("StatefulSet", "ledger-db"), "ledger-db"},
		{"cronjob job", owner("Job", "nightly-export-28744320"), "nightly-export"},
		{"generateName", func(p *pod) { p.Metadata.GenerateName = "batch-runner-" }, "batch-runner"},
		{"container name", func(*pod) {}, "main_container"},
		{"long names are cut", func(p *pod) { p.Metadata.Labels = map[string]string{"app": strings.Repeat("a", 90)} }, strings.Repeat("a", 63)},
	}
	for _, c := range cases {
		if got := mk(c.mod); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.PullPolicy = "Sometimes" },
		func(c *Config) { c.EnrollSecret = "Not_Valid" },
		func(c *Config) { c.HMACSecret = "" },
		func(c *Config) { c.HMACMode = 0o1777 },
		func(c *Config) { c.SDKImages["go"] = "x/y:1" }, // env-only language: no image can be configured
		func(c *Config) { c.SDKImages["ruby"] = "x/y:1" },
		func(c *Config) { c.SDKImages["nodejs"] = "x/y:1" },
		func(c *Config) { c.SDKImages["node"] = "has space" },
	}
	for i, mod := range bad {
		c := testConfig()
		mod(&c)
		if _, err := NewMutator(c); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	if _, err := NewMutator(testConfig()); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// ---- HTTP ----

func post(t *testing.T, h http.Handler, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	var logs bytes.Buffer
	h := Handler(newMutator(t, nil), slog.New(slog.NewJSONHandler(&logs, nil)))

	raw, _ := os.ReadFile("testdata/node_basic.json")
	rec := post(t, h, "application/json", raw)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, %v", rec.Code, rec.Header())
	}
	var out AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Response.Allowed || out.Response.PatchType != "JSONPatch" || len(out.Response.Patch) == 0 {
		t.Errorf("response = %+v", out.Response)
	}
	// The patch travels base64 encoded, as the API server expects.
	var wire map[string]map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &wire)
	if s, _ := wire["response"]["patch"].(string); s == "" || strings.HasPrefix(s, "[") {
		t.Errorf("patch on the wire = %q", s)
	}
	// Logs carry names, not values.
	if !strings.Contains(logs.String(), `"pod":"shop-api-7d9c8b6f4-"`) || strings.Contains(logs.String(), "production") || strings.Contains(logs.String(), "registry.example") {
		t.Errorf("log = %s", logs.String())
	}

	if rec := post(t, h, "text/plain", raw); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", rec.Code)
	}
	if rec := post(t, h, "application/json", []byte("{nope")); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", rec.Code)
	}
	if rec := post(t, h, "application/json", []byte(`{"apiVersion":"admission.k8s.io/v1beta1","kind":"AdmissionReview","request":{"uid":"u"}}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("v1beta1: %d", rec.Code)
	}
	if rec := post(t, h, "application/json", []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("no request: %d", rec.Code)
	}
	big := bytes.Repeat([]byte(" "), MaxReviewBytes+10)
	if rec := post(t, h, "application/json", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("big body: %d", rec.Code)
	}
	for _, p := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 200 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mutate", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /mutate: %d", rec.Code)
	}
}

func selfSigned(t *testing.T, dir, cn string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return
}

func TestServeTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, pool := selfSigned(t, dir, "tt-injector")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, certFile, keyFile, Handler(newMutator(t, nil), slog.New(slog.NewJSONHandler(io.Discard, nil))))
	}()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	raw, _ := os.ReadFile("testdata/python_two_containers.json")
	url := "https://" + ln.Addr().String() + "/mutate"
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Post(url, "application/json", bytes.NewReader(raw))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out AdmissionReview
	if resp.StatusCode != 200 || json.Unmarshal(body, &out) != nil || len(out.Response.Patch) == 0 {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	// Plaintext is not served.
	if r, err := http.Get(fmt.Sprintf("http://%s/healthz", ln.Addr())); err == nil {
		if r.StatusCode == 200 {
			t.Error("plaintext request answered with 200")
		}
		r.Body.Close()
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestServeNeedsCertificate(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	err := Serve(context.Background(), ln, "/nonexistent/tls.crt", "/nonexistent/tls.key", http.NotFoundHandler())
	if err == nil {
		t.Fatal("expected an error without a certificate")
	}
}

func TestCertReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := selfSigned(t, dir, "first")
	rl := &certReloader{certFile: certFile, keyFile: keyFile}
	c1, err := rl.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Rotate in place and pretend the check interval elapsed.
	selfSigned(t, dir, "second")
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, future, future)
	rl.checked = time.Now().Add(-time.Hour)
	c2, err := rl.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Error("certificate not reloaded")
	}
	// A broken rotation keeps the last good certificate.
	_ = os.WriteFile(keyFile, []byte("garbage"), 0o600)
	later := future.Add(time.Minute)
	_ = os.Chtimes(keyFile, later, later)
	rl.checked = time.Now().Add(-time.Hour)
	c3, err := rl.get(nil)
	if err != nil || c3 != c2 {
		t.Errorf("c3=%v err=%v", c3 == c2, err)
	}
}
