package deploytest

import (
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/mock"
)

// The tt-core chart with mockManager: the configuration tt-core accepts, a
// Role in the mock namespace only on the objects of a mock, the token
// mounted, the NetworkPolicy open to the Kubernetes API and to the mocks.
func TestCoreMockManagerScope(t *testing.T) {
	docs := render(t, "tt-core", "--set", "mockManager.enabled=true", "--set", "mockManager.namespace=mocks",
		"--set", "mockManager.apiServer.cidr=10.96.0.1/32", "--set", "mockManager.apiServer.port=443")
	cfg := loadCoreConfig(t, docs)
	k := cfg.Mock.Kubernetes
	if !k.Enabled || k.Namespace != "mocks" || k.Route != "auto" || cfg.Mock.ConsoleURL != "https://t-tt-core.tt-test.svc.cluster.local:7070" ||
		!strings.HasPrefix(cfg.Mock.Image, "ghcr.io/ivseb/traffic-twin:") {
		t.Fatalf("mock config: %+v", cfg.Mock)
	}
	var roles, bindings []map[string]any
	for _, d := range docs {
		switch d["kind"] {
		case "Role":
			roles = append(roles, d)
		case "RoleBinding":
			bindings = append(bindings, d)
		case "ClusterRole", "ClusterRoleBinding":
			t.Fatalf("cluster-wide RBAC rendered: %v", d["metadata"])
		}
	}
	if len(roles) != 1 || len(bindings) != 1 {
		t.Fatalf("roles %d bindings %d", len(roles), len(bindings))
	}
	if at(t, roles[0], "metadata", "namespace") != "mocks" || at(t, bindings[0], "metadata", "namespace") != "mocks" {
		t.Fatal("the Role is not in the mock namespace")
	}
	allowed := map[string][]string{"": {"secrets", "services"}, "apps": {"deployments"}, "route.openshift.io": {"routes"}}
	for _, r := range at(t, roles[0], "rules").([]any) {
		rule := r.(map[string]any)
		for _, g := range rule["apiGroups"].([]any) {
			for _, res := range rule["resources"].([]any) {
				if !slices.Contains(allowed[g.(string)], res.(string)) {
					t.Errorf("resource outside the mock objects: %v/%v", g, res)
				}
			}
		}
		for _, v := range rule["verbs"].([]any) {
			if !slices.Contains([]string{"get", "create", "patch", "update", "delete"}, v.(string)) {
				t.Errorf("verb %v", v)
			}
		}
	}
	subj := at(t, bindings[0], "subjects", 0).(map[string]any)
	if subj["kind"] != "ServiceAccount" || subj["namespace"] != "tt-test" {
		t.Errorf("subject: %v", subj)
	}
	sts := find(t, docs, "StatefulSet")
	if at(t, sts, "spec", "template", "spec", "automountServiceAccountToken") != true {
		t.Error("the token of tt-core is not mounted")
	}
	np := findNamed(t, docs, "NetworkPolicy", "t-tt-core")
	egress := at(t, np, "spec", "egress").([]any)
	found := false
	for _, e := range egress {
		if strings.Contains(dump(e), "10.96.0.1/32") {
			found = true
		}
	}
	if !found {
		t.Error("no egress rule to the Kubernetes API")
	}
	if !strings.Contains(dump(at(t, np, "spec", "ingress")), "tt-mock") {
		t.Error("the mocks cannot reach the admin listener")
	}

	// Off by default: no RBAC, no token.
	docs = render(t, "tt-core")
	for _, d := range docs {
		if d["kind"] == "Role" || d["kind"] == "RoleBinding" {
			t.Fatal("RBAC rendered without mockManager")
		}
	}
	if at(t, find(t, docs, "StatefulSet"), "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Error("token mounted without mockManager")
	}
}

// The tt-mock chart in console mode renders arguments `tt mock` accepts.
func TestMockChartConsoleMode(t *testing.T) {
	docs := render(t, "tt-mock", "--set", "console.url=https://tt-core.traffic-twin.svc.cluster.local:7070", "--set", "console.group=shop",
		"--set", "console.tokenSecret=tt-mock-token", "--set", "route.enabled=true", "--set", "route.host=mock-shop.apps.example",
		"--set", "gatePubKeys=gate-1:"+strings.Repeat("A", 43))
	dep := find(t, docs, "Deployment")
	c := at(t, dep, "spec", "template", "spec", "containers", 0).(map[string]any)
	var args []string
	for _, a := range c["args"].([]any) {
		args = append(args, a.(string))
	}
	if args[0] != "mock" {
		t.Fatalf("args: %v", args)
	}
	t.Setenv(mock.EnvMockToken, "ttm_0123456789abcdef01234567.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
	cc, err := mock.ParseFlags(args[1:], io.Discard)
	if err != nil {
		t.Fatalf("tt mock rejects the chart's arguments %v: %v", args, err)
	}
	if cc.Console == nil || cc.Console.Group != "shop" || cc.Console.PublicURL != "https://mock-shop.apps.example" {
		t.Fatalf("console: %+v", cc.Console)
	}
	if !strings.Contains(dump(c["env"]), "tt-mock-token") {
		t.Error("the token Secret is not used")
	}
	route := find(t, docs, "Route")
	if at(t, route, "spec", "host") != "mock-shop.apps.example" {
		t.Errorf("route: %v", route)
	}
	np := find(t, docs, "NetworkPolicy")
	if !strings.Contains(dump(at(t, np, "spec", "egress")), "7070") {
		t.Error("console mode cannot reach the console")
	}

	// File mode keeps egress closed.
	docs = render(t, "tt-mock", "--set", "pack.configMap=twin")
	if eg := at(t, find(t, docs, "NetworkPolicy"), "spec", "egress"); len(eg.([]any)) != 0 {
		t.Errorf("file mode egress: %v", eg)
	}
}

func dump(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
