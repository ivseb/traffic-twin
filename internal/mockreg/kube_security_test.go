package mockreg

import (
	"context"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Security review r4 (managed mocks): whatever group a user names, tt-core
// only writes DNS-1123 objects with valid labels in the configured
// namespace, with the configured image and the fixed `tt mock --console`
// arguments (the group is one argument value, never a flag or a command).

var labelValueRE = regexp.MustCompile(`^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$`)

func TestManagedObjectsStayInNamespaceAndShape(t *testing.T) {
	fk := &fakeKube{objects: map[string]map[string]any{}, routes: true}
	api := httptest.NewTLSServer(fk)
	defer api.Close()
	const img = "ghcr.io/ivseb/traffic-twin:0.1.0"
	kube, err := NewKube(KubeConfig{Namespace: "mocks", Image: img, ConsoleURL: "https://tt-core.tt.svc:7070",
		APIServer: api.URL, Token: "sa", Client: api.Client()})
	if err != nil {
		t.Fatal(err)
	}
	groups := []string{"shop", "team.", "team_", "a", "0", strings.Repeat("x", 63), strings.Repeat("a.", 31) + "b",
		"x--y", "team.a", "team_a", "9-." + strings.Repeat("z", 60)}
	for _, g := range groups {
		if !GroupRE.MatchString(g) {
			t.Fatalf("test group %q is not a valid group", g)
		}
		fk.reqs = nil
		if _, err := kube.Apply(context.Background(), ManagedSpec{Group: g, MockToken: "ttm_x", ControlToken: "c", GatePubKeys: "k"}); err != nil {
			t.Fatalf("group %q: %v", g, err)
		}
		for _, r := range fk.reqs {
			if r.Path == "/apis/route.openshift.io/v1" {
				continue
			}
			if !strings.Contains(r.Path, "/namespaces/mocks/") || strings.Count(r.Path, "/namespaces/") != 1 {
				t.Errorf("group %q: request outside the namespace: %s %s", g, r.Method, r.Path)
			}
			md, _ := r.Body["metadata"].(map[string]any)
			name, _ := md["name"].(string)
			if md["namespace"] != "mocks" || !dnsLabelRE.MatchString(name) || len(name) > 63 || !strings.HasPrefix(name, "tt-mock-") {
				t.Errorf("group %q: object metadata %v", g, md)
			}
			if !strings.HasSuffix(r.Path, "/"+name) {
				t.Errorf("group %q: path %s does not name %s", g, r.Path, name)
			}
			for k, v := range md["labels"].(map[string]any) {
				s := v.(string)
				if len(s) > 63 || !labelValueRE.MatchString(s) {
					t.Errorf("group %q: label %s=%q is not a valid label value", g, k, s)
				}
			}
			if r.Body["kind"] != "Deployment" {
				continue
			}
			pod := r.Body["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			if pod["automountServiceAccountToken"] != false || pod["hostNetwork"] != nil || pod["hostPID"] != nil {
				t.Errorf("group %q: pod spec %v", g, pod)
			}
			cs := pod["containers"].([]any)
			if len(cs) != 1 {
				t.Fatalf("containers: %v", cs)
			}
			c := cs[0].(map[string]any)
			if c["image"] != img || c["command"] != nil {
				t.Errorf("group %q: image %v command %v", g, c["image"], c["command"])
			}
			var args []string
			for _, a := range c["args"].([]any) {
				args = append(args, a.(string))
			}
			i := slices.Index(args, "--group")
			if args[0] != "mock" || args[1] != "--console" || args[2] != "https://tt-core.tt.svc:7070" || i < 0 || args[i+1] != g ||
				slices.Index(args[i+1:], "--group") >= 0 {
				t.Errorf("group %q: args %v", g, args)
			}
		}
	}
	// Two groups differing only by . or _ never share objects.
	if ObjectName("team.a") == ObjectName("team_a") || groupLabel("team.a") == groupLabel("team_a") {
		t.Error("team.a and team_a collide")
	}
}

// Malformed groups (paths, namespaces, flags, upper case) are refused by
// the API before any Kubernetes request.
func TestManagedRejectsMalformedGroups(t *testing.T) {
	fk := &fakeKube{objects: map[string]map[string]any{}}
	api := httptest.NewTLSServer(fk)
	defer api.Close()
	kube, err := NewKube(KubeConfig{Namespace: "mocks", Image: "img:1", ConsoleURL: "https://tt", APIServer: api.URL, Token: "t", Client: api.Client(), Route: "off"})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, kube)
	for _, g := range []string{"", "../kube-system", "a/b", "-x", "--image=evil", "Shop", "shop\n", "a b", strings.Repeat("x", 64), "namespaces/x"} {
		code, _ := e.adminDo(olga, "POST", "/api/v1/mocks/managed", map[string]any{"group": g})
		if code != 422 {
			t.Errorf("group %q: status %d, want 422", g, code)
		}
	}
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if len(fk.reqs) != 0 {
		t.Errorf("Kubernetes called for malformed groups: %v", fk.reqs)
	}
}
