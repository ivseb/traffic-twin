package mockreg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/store"
)

type fakePacks struct {
	mu     sync.Mutex
	latest map[string]string
	gets   []string
}

func (f *fakePacks) LatestPublished(_ context.Context, g string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.latest[g], nil
}

func (f *fakePacks) Archive(_ context.Context, id, g string, a audit.Actor) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latest[g] != id {
		return nil, errNotFound
	}
	f.gets = append(f.gets, g+"/"+id+"/"+a.ID)
	return []byte("archive-of-" + id), nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t     *testing.T
	reg   *Registry
	packs *fakePacks
	clk   *clock
	audit *audit.Log
	db    *store.DB
	agent http.Handler
	admin http.Handler
}

var olga = &auth.Principal{UserID: "u-olga", Username: "olga", Roles: []auth.Role{auth.RoleOperator}}

func newEnv(t *testing.T, kube *Kube) *env {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	a := audit.New(db)
	clk := &clock{t: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)}
	fp := &fakePacks{latest: map[string]string{"shop": "pk-20261025-0001", "other": "pk-20261025-0009"}}
	reg, err := New(Options{DB: db, Audit: a, Now: clk.now, Packs: fp, Kube: kube, ReportInterval: 50 * time.Millisecond, ConsoleURL: "https://tt.example.internal",
		GatePubKeys: func(context.Context) (string, error) { return "gate-1:AAAA", nil },
		RealBases:   func(string) map[string]string { return map[string]string{"carrier": "https://api.carrier.example"} }})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, reg: reg, packs: fp, clk: clk, audit: a, db: db, agent: reg.AgentHandler(), admin: reg.AdminHandler(a, nil)}
}

func (e *env) agentDo(method, path, token string, body any) (*httptest.ResponseRecorder, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.agent.ServeHTTP(rec, req)
	return rec, rec.Body.Bytes()
}

func (e *env) adminDo(p *auth.Principal, method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	e.admin.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *env) actions() []string {
	var out []string
	if err := e.audit.Iterate(context.Background(), 0, 10000, func(x audit.Entry) error {
		out = append(out, x.Action)
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func TestTokensAgentAndRegistry(t *testing.T) {
	e := newEnv(t, nil)
	code, body := e.adminDo(olga, "POST", "/api/v1/mocks/tokens", map[string]any{"group": "shop", "label": "CI pipeline"})
	if code != 201 {
		t.Fatalf("create token: %d %s", code, body)
	}
	var nt NewToken
	_ = json.Unmarshal(body, &nt)
	if !reToken.MatchString(nt.Token) || nt.Setup == nil || !strings.Contains(nt.Setup.Docker, "--group shop") || !strings.Contains(nt.Setup.HelmValues, "tokenSecret") {
		t.Fatalf("token: %+v", nt)
	}
	// only the hash is stored
	var stored string
	_ = e.db.QueryRow(`SELECT secret_hash FROM mockreg_tokens WHERE id = ?`, nt.TokenID).Scan(&stored)
	if stored == "" || strings.Contains(nt.Token, stored) || strings.Contains(stored, strings.Split(nt.Token, ".")[1]) {
		t.Fatalf("stored secret: %q", stored)
	}
	// an auditor cannot create tokens
	if code, _ := e.adminDo(&auth.Principal{UserID: "u-a", Roles: []auth.Role{auth.RoleAuditor}}, "POST", "/api/v1/mocks/tokens", map[string]any{"group": "shop"}); code != 403 {
		t.Fatalf("auditor created a token: %d", code)
	}

	// The token downloads its group's pack only.
	rec, b := e.agentDo("GET", "/api/v1/mock-agent/pack", nt.Token, nil)
	if rec.Code != 200 || string(b) != "archive-of-pk-20261025-0001" || rec.Header().Get(mock.HeaderPackID) != "pk-20261025-0001" {
		t.Fatalf("pack: %d %s", rec.Code, b)
	}
	if got := e.packs.gets; len(got) != 1 || got[0] != "shop/pk-20261025-0001/tt-mock/"+nt.TokenID {
		t.Fatalf("downloads: %v", got)
	}
	for _, bad := range []string{"", "ttm_x", nt.Token + "x", strings.Replace(nt.Token, nt.Token[len(nt.Token)-3:], "AAA", 1)} {
		if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", bad, nil); rec.Code != 401 {
			t.Fatalf("token %q: %d", bad, rec.Code)
		}
	}

	// Report: stored, listed, commands go back.
	rep := mock.Report{Instance: "ci-1", Version: "0.1.0", Group: "shop", Status: "serving", PackID: "pk-20261025-0001", PublicURL: "http://mock:8480",
		Services: []mock.ServiceURL{{Name: "carrier", BaseURL: "http://mock:8480/__svc/carrier"}, {Name: "host:api.pay.example", BaseURL: "http://mock:8480/__svc/api.pay.example"}},
		Calls:    []mock.Call{{Method: "GET", Path: "/__svc/carrier/shipments/1", Status: 200, Session: "default", Matched: true}}}
	rec, b = e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep)
	if rec.Code != 200 {
		t.Fatalf("report: %d %s", rec.Code, b)
	}
	var ans mock.ReportAnswer
	_ = json.Unmarshal(b, &ans)
	if ans.PackID != "pk-20261025-0001" || len(ans.Commands) != 0 {
		t.Fatalf("answer: %+v", ans)
	}
	// a report for another group is refused
	other := rep
	other.Group = "other"
	if rec, _ := e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, other); rec.Code != 403 {
		t.Fatalf("report for another group: %d", rec.Code)
	}

	code, body = e.adminDo(olga, "GET", "/api/v1/mocks?group=shop", nil)
	var lv ListView
	_ = json.Unmarshal(body, &lv)
	if code != 200 || len(lv.Mocks) != 1 || !lv.Mocks[0].Online || !lv.Mocks[0].UpToDate || lv.Environment.Kubernetes {
		t.Fatalf("list: %d %s", code, body)
	}
	m := lv.Mocks[0]
	if m.Services[0].RealBase != "https://api.carrier.example" || m.Services[1].RealBase != "https://api.pay.example" {
		t.Fatalf("services: %+v", m.Services)
	}
	if code, body = e.adminDo(olga, "GET", "/api/v1/mocks?group=other", nil); !strings.Contains(string(body), `"mocks":[]`) {
		t.Fatalf("group filter: %s", body)
	}
	code, body = e.adminDo(olga, "GET", "/api/v1/mocks/"+m.MockID+"/calls?since=0", nil)
	if code != 200 || !strings.Contains(string(body), "/__svc/carrier/shipments/1") {
		t.Fatalf("calls: %d %s", code, body)
	}

	// A command: queued, delivered with the next answer, its result read back.
	if code, _ := e.adminDo(olga, "POST", "/api/v1/mocks/"+m.MockID+"/commands", map[string]any{"method": "GET", "path": "/__tt/sessions/x/journal"}); code != 422 {
		t.Fatalf("journal command accepted: %d", code)
	}
	code, body = e.adminDo(olga, "POST", "/api/v1/mocks/"+m.MockID+"/commands", map[string]any{"method": "POST", "path": "/__tt/sessions/default/clock/advance", "body": map[string]any{"by": "P1D"}})
	if code != 202 {
		t.Fatalf("command: %d %s", code, body)
	}
	var cq struct {
		CommandID string `json:"command_id"`
	}
	_ = json.Unmarshal(body, &cq)
	rec, b = e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep)
	_ = json.Unmarshal(b, &ans)
	if len(ans.Commands) != 1 || ans.Commands[0].ID != cq.CommandID || ans.Commands[0].Path != "/__tt/sessions/default/clock/advance" {
		t.Fatalf("commands: %+v", ans.Commands)
	}
	rep2 := rep
	rep2.Calls = nil
	rep2.Results = []mock.CommandResult{{ID: cq.CommandID, Status: 200, Body: json.RawMessage(`{"now":"2026-10-20T00:00:00Z"}`)}}
	e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep2)
	code, body = e.adminDo(olga, "GET", "/api/v1/mocks/"+m.MockID+"/commands/"+cq.CommandID, nil)
	if code != 200 || !strings.Contains(string(body), `"status":"done"`) || !strings.Contains(string(body), "2026-10-20") {
		t.Fatalf("command result: %d %s", code, body)
	}

	// The mock token opens nothing of the admin API (it is no session) and
	// the agent API has nothing else.
	if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/tokens", nt.Token, nil); rec.Code != 404 {
		t.Fatalf("agent extra path: %d", rec.Code)
	}

	// Revoked: refused from the next call on, shown as revoked.
	if code, _ := e.adminDo(olga, "DELETE", "/api/v1/mocks/tokens/"+nt.TokenID, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if rec, _ := e.agentDo("POST", "/api/v1/mock-agent/report", nt.Token, rep); rec.Code != 401 {
		t.Fatalf("revoked token: %d", rec.Code)
	}
	if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", nt.Token, nil); rec.Code != 401 {
		t.Fatalf("revoked token pack: %d", rec.Code)
	}
	_, body = e.adminDo(olga, "GET", "/api/v1/mocks", nil)
	if !strings.Contains(string(body), `"status":"revoked"`) {
		t.Fatalf("revoked mock: %s", body)
	}

	// Expiry.
	_, body = e.adminDo(olga, "POST", "/api/v1/mocks/tokens", map[string]any{"group": "shop", "expires_in_days": 1})
	_ = json.Unmarshal(body, &nt)
	e.clk.add(25 * time.Hour)
	if rec, _ := e.agentDo("GET", "/api/v1/mock-agent/pack", nt.Token, nil); rec.Code != 401 {
		t.Fatalf("expired token: %d", rec.Code)
	}
	for _, want := range []string{"mock.token_create", "mock.token_revoke", "mock.command", "authz.deny"} {
		if !slices.Contains(e.actions(), want) {
			t.Errorf("audit lacks %s: %v", want, e.actions())
		}
	}
}

// fakeKube is a Kubernetes API server recording every request.
type fakeKube struct {
	mu      sync.Mutex
	reqs    []kubeReq
	objects map[string]map[string]any
	routes  bool
	deny    bool
}

type kubeReq struct {
	Method, Path, Query, Type, Auth string
	Body                            map[string]any
}

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kr := kubeReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Type: r.Header.Get("Content-Type"), Auth: r.Header.Get("Authorization")}
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		_ = json.Unmarshal(b, &kr.Body)
	}
	f.reqs = append(f.reqs, kr)
	if f.deny {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"kind":"Status","reason":"Forbidden"}`))
		return
	}
	if r.URL.Path == "/apis/route.openshift.io/v1" {
		if !f.routes {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"kind":"APIResourceList"}`))
		return
	}
	switch r.Method {
	case "PATCH":
		obj := kr.Body
		if strings.Contains(r.URL.Path, "/routes/") {
			obj["spec"].(map[string]any)["host"] = "tt-mock-shop-mocks.apps.cluster.example"
		}
		f.objects[r.URL.Path] = obj
		_ = json.NewEncoder(w).Encode(obj)
	case "GET":
		obj, ok := f.objects[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"NotFound"}`))
			return
		}
		obj["status"] = map[string]any{"readyReplicas": 1}
		_ = json.NewEncoder(w).Encode(obj)
	case "DELETE":
		if _, ok := f.objects[r.URL.Path]; !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"NotFound"}`))
			return
		}
		delete(f.objects, r.URL.Path)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
	default:
		w.WriteHeader(405)
	}
}

func TestManagedMockInKubernetes(t *testing.T) {
	for _, routes := range []bool{true, false} {
		fk := &fakeKube{objects: map[string]map[string]any{}, routes: routes}
		api := httptest.NewTLSServer(fk)
		defer api.Close()
		kube, err := NewKube(KubeConfig{Namespace: "mocks", Image: "ghcr.io/ivseb/traffic-twin:0.1.0", ConsoleURL: "https://tt-core.traffic-twin.svc:7070",
			ConsoleCA: []byte("-----BEGIN CERTIFICATE-----\nZZZ\n-----END CERTIFICATE-----\n"), CPURequest: "50m", MemoryLimit: "512Mi",
			APIServer: api.URL, Token: "sa-token", Client: api.Client()})
		if err != nil {
			t.Fatal(err)
		}
		e := newEnv(t, kube)
		code, body := e.adminDo(olga, "POST", "/api/v1/mocks/managed", map[string]any{"group": "shop"})
		if code != 200 {
			t.Fatalf("start: %d %s", code, body)
		}
		var mv ManagedView
		_ = json.Unmarshal(body, &mv)
		wantURL := "http://tt-mock-shop.mocks.svc.cluster.local:8480"
		if routes {
			wantURL = "https://tt-mock-shop-mocks.apps.cluster.example"
		}
		if mv.URL != wantURL || mv.Name != "tt-mock-shop" {
			t.Fatalf("managed: %+v", mv)
		}

		// RBAC scope: only the namespace, only these resources, and the
		// route discovery; server-side apply with tt-core as field manager.
		allowed := []string{"/api/v1/namespaces/mocks/secrets/", "/api/v1/namespaces/mocks/services/", "/apis/apps/v1/namespaces/mocks/deployments/",
			"/apis/route.openshift.io/v1/namespaces/mocks/routes/"}
		var kinds []string
		for _, r := range fk.reqs {
			if r.Auth != "Bearer sa-token" {
				t.Fatalf("auth: %q", r.Auth)
			}
			if r.Path == "/apis/route.openshift.io/v1" && r.Method == "GET" {
				continue
			}
			ok := false
			for _, a := range allowed {
				ok = ok || strings.HasPrefix(r.Path, a)
			}
			if !ok {
				t.Fatalf("request outside the namespace scope: %s %s", r.Method, r.Path)
			}
			if r.Method == "PATCH" {
				if r.Type != "application/apply-patch+yaml" || r.Query != "fieldManager=tt-core&force=true" {
					t.Fatalf("not a server-side apply: %+v", r)
				}
				kinds = append(kinds, r.Body["kind"].(string))
			}
		}
		want := []string{"Secret", "Service", "Deployment"}
		if routes {
			want = []string{"Secret", "Service", "Route", "Deployment"}
		}
		if !slices.Equal(kinds, want) {
			t.Fatalf("objects: %v", kinds)
		}

		// The exact objects.
		sec := fk.objects["/api/v1/namespaces/mocks/secrets/tt-mock-shop"]
		data := sec["data"].(map[string]any)
		tok, _ := base64.StdEncoding.DecodeString(data["mock-token"].(string))
		if !reToken.Match(tok) || data["control-token"] == "" || data["console-ca.crt"] == nil {
			t.Fatalf("secret: %v", sec)
		}
		dep := fk.objects["/apis/apps/v1/namespaces/mocks/deployments/tt-mock-shop"]
		pod := dep["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		if pod["automountServiceAccountToken"] != false {
			t.Fatal("the mock pod mounts a service account token")
		}
		c := pod["containers"].([]any)[0].(map[string]any)
		args, _ := json.Marshal(c["args"])
		wantArgs := `["mock","--console","https://tt-core.traffic-twin.svc:7070","--group","shop","--addr","0.0.0.0:8480","--public-url","` + wantURL + `","--console-ca","/etc/tt-mock/console-ca.crt"]`
		if string(args) != wantArgs {
			t.Fatalf("args: %s", args)
		}
		env, _ := json.Marshal(c["env"])
		if !strings.Contains(string(env), `{"name":"TT_MOCK_TOKEN","valueFrom":{"secretKeyRef":{"key":"mock-token","name":"tt-mock-shop"}}}`) ||
			!strings.Contains(string(env), `"TT_GATE_PUBKEYS","value":"gate-1:AAAA"`) || strings.Contains(string(env), "ttm_") {
			t.Fatalf("env: %s", env)
		}
		sc, _ := json.Marshal(c["securityContext"])
		if !strings.Contains(string(sc), `"readOnlyRootFilesystem":true`) || !strings.Contains(string(sc), `"drop":["ALL"]`) {
			t.Fatalf("security context: %s", sc)
		}
		svc := fk.objects["/api/v1/namespaces/mocks/services/tt-mock-shop"]
		if svc["spec"].(map[string]any)["type"] != "ClusterIP" {
			t.Fatalf("service: %v", svc)
		}

		// Listed with its pods.
		_, body = e.adminDo(olga, "GET", "/api/v1/mocks", nil)
		var lv ListView
		_ = json.Unmarshal(body, &lv)
		if !lv.Environment.Kubernetes || lv.Environment.Namespace != "mocks" || len(lv.Managed) != 1 || lv.Managed[0].Pods.Ready != 1 {
			t.Fatalf("list: %s", body)
		}
		// Refresh: a new token, the old one revoked.
		first := mv.TokenID
		if code, body = e.adminDo(olga, "POST", "/api/v1/mocks/managed/shop/restart", nil); code != 200 {
			t.Fatalf("restart: %d %s", code, body)
		}
		var revoked int
		_ = e.db.QueryRow(`SELECT revoked FROM mockreg_tokens WHERE id = ?`, first).Scan(&revoked)
		if revoked != 1 {
			t.Fatal("the previous managed token stays valid")
		}

		// Stop: every object deleted, token revoked.
		if code, body = e.adminDo(olga, "DELETE", "/api/v1/mocks/managed/shop", nil); code != 204 {
			t.Fatalf("stop: %d %s", code, body)
		}
		if len(fk.objects) != 0 {
			t.Fatalf("left in the cluster: %v", fk.objects)
		}
		for _, want := range []string{"mock.start", "mock.restart", "mock.stop", "mock.token_create"} {
			if !slices.Contains(e.actions(), want) {
				t.Errorf("audit lacks %s", want)
			}
		}
	}
}

func TestManagedMockErrors(t *testing.T) {
	e := newEnv(t, nil)
	if code, body := e.adminDo(olga, "POST", "/api/v1/mocks/managed", map[string]any{"group": "shop"}); code != 409 || !strings.Contains(string(body), "kubernetes_disabled") {
		t.Fatalf("without kubernetes: %d %s", code, body)
	}
	fk := &fakeKube{objects: map[string]map[string]any{}, deny: true}
	api := httptest.NewTLSServer(fk)
	defer api.Close()
	kube, _ := NewKube(KubeConfig{Namespace: "mocks", Image: "img:1", ConsoleURL: "https://tt", APIServer: api.URL, Token: "t", Client: api.Client(), Route: "off"})
	e = newEnv(t, kube)
	code, body := e.adminDo(olga, "POST", "/api/v1/mocks/managed", map[string]any{"group": "shop"})
	if code != 502 || !strings.Contains(string(body), "kubernetes_forbidden") {
		t.Fatalf("forbidden: %d %s", code, body)
	}
	var n int
	_ = e.db.QueryRow(`SELECT count(*) FROM mockreg_tokens WHERE revoked = 0`).Scan(&n)
	if n != 0 {
		t.Fatal("a token of a mock that never started stays valid")
	}
}

func TestObjectName(t *testing.T) {
	for g, want := range map[string]string{"shop": "tt-mock-shop", "team-a": "tt-mock-team-a"} {
		if got := ObjectName(g); got != want {
			t.Errorf("%s: %s", g, got)
		}
	}
	a, b := ObjectName("team.a"), ObjectName("team_a")
	if a == b || !dnsLabelRE.MatchString(a) || !dnsLabelRE.MatchString(b) {
		t.Errorf("names: %s %s", a, b)
	}
	long := ObjectName(strings.Repeat("x", 63))
	if len(long) > 63 || !dnsLabelRE.MatchString(long) {
		t.Errorf("long: %s", long)
	}
}
