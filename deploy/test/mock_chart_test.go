package deploytest

import (
	"net/http"
	"slices"
	"testing"

	"github.com/ivseb/traffic-twin/internal/mockreg"
)

func findNamed(t *testing.T, docs []map[string]any, kind, name string) map[string]any {
	t.Helper()
	for _, d := range docs {
		if d["kind"] == kind && at(t, d, "metadata", "name") == name {
			return d
		}
	}
	t.Fatalf("no %s %s rendered", kind, name)
	return nil
}

// Managed mocks (mockManager, security review r4): the Role is least privilege and the managed mock
// pods get a NetworkPolicy whose egress is DNS and tt-core's admin port only, selecting exactly the
// labels tt-core puts on the pods.
func TestCoreMockManagerRBACAndNetworkPolicy(t *testing.T) {
	docs := render(t, "tt-core", "--set", "mockManager.enabled=true", "--set", "mockManager.namespace=mocks")
	role := find(t, docs, "Role")
	np := findNamed(t, docs, "NetworkPolicy", "t-tt-core-managed-mocks")
	if ns := at(t, role, "metadata", "namespace"); ns != "mocks" {
		t.Errorf("Role namespace = %v", ns)
	}
	for _, r := range at(t, role, "rules").([]any) {
		rm := r.(map[string]any)
		var verbs, res []string
		for _, v := range rm["verbs"].([]any) {
			verbs = append(verbs, v.(string))
		}
		for _, v := range rm["resources"].([]any) {
			res = append(res, v.(string))
		}
		for _, bad := range []string{"list", "watch", "update", "*", "deletecollection"} {
			if slices.Contains(verbs, bad) {
				t.Errorf("Role grants %s on %v", bad, res)
			}
		}
		if slices.Contains(res, "secrets") && slices.Contains(verbs, "get") {
			t.Errorf("Role can read Secrets: %v", verbs)
		}
		if slices.Contains(res, "pods") || slices.Contains(res, "pods/exec") || slices.Contains(res, "*") {
			t.Errorf("Role grants %v", res)
		}
	}

	if ns := at(t, np, "metadata", "namespace"); ns != "mocks" {
		t.Errorf("NetworkPolicy namespace = %v", ns)
	}
	sel := at(t, np, "spec", "podSelector", "matchLabels").(map[string]any)
	k, err := mockreg.NewKube(mockreg.KubeConfig{Namespace: "mocks", Image: "img:1", ConsoleURL: "https://c", APIServer: "https://k", Token: "x", Client: http.DefaultClient, Route: "off"})
	if err != nil {
		t.Fatal(err)
	}
	podLabels := at(t, k.DeploymentObject("tt-mock-g", "http://x", mockreg.ManagedSpec{Group: "g"}), "spec", "template", "metadata", "labels").(map[string]any)
	for key, v := range sel {
		if podLabels[key] != v {
			t.Errorf("NetworkPolicy selects %s=%v, managed pods have %v", key, v, podLabels[key])
		}
	}
	egress := at(t, np, "spec", "egress").([]any)
	if len(egress) != 2 {
		t.Fatalf("egress rules = %d, want 2 (DNS, console)", len(egress))
	}
	console := egress[1].(map[string]any)
	if p := toStr(at(t, console, "ports", 0, "port")); p != "7070" {
		t.Errorf("console port = %v", p)
	}
	if _, ok := at(t, console, "to", 0).(map[string]any)["ipBlock"]; ok {
		t.Errorf("console rule is an ipBlock")
	}
	if pt := at(t, np, "spec", "policyTypes").([]any); !slices.Contains(pt, any("Egress")) {
		t.Errorf("policyTypes = %v", pt)
	}
}
