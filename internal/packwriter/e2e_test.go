package packwriter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
	"github.com/ivseb/traffic-twin/internal/world"
)

// The conformance HMAC key 0x00..0x1f (sanitizer 7.3): invented, public.
func k1() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// token computes a real-looking token as a source would (sanitizer 7.2).
func token(epoch, domain, value string) string {
	m := hmac.New(sha256.New, k1())
	m.Write([]byte(epoch + "\x00" + domain + "\x00" + value))
	return "tk1:k1:" + b64(m.Sum(nil)[:16])
}

func writeKey(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startKeyguard runs a real keyguard in-process on a Unix socket, with a
// signed source policy p-shop v7.
func startKeyguard(t *testing.T) (*keyguard.Service, *client.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	seed := func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }
	writeKey(t, filepath.Join(dir, "hmac.keys"), "k1:"+b64(k1())+"\n")
	writeKey(t, filepath.Join(dir, "policy.key"), "policy-test-1:"+b64(seed())+"\n")
	writeKey(t, filepath.Join(dir, "pack.key"), "gate-test-1:"+b64(seed())+"\n")
	cfg := keyguard.DefaultConfig()
	cfg.DBPath = filepath.Join(dir, "kg.db")
	cfg.HMACKeys = keyguard.KeySource{File: filepath.Join(dir, "hmac.keys")}
	cfg.PolicyKey = keyguard.KeySource{File: filepath.Join(dir, "policy.key")}
	cfg.PackKey = keyguard.KeySource{File: filepath.Join(dir, "pack.key")}
	cfg.BloomCapacity = 10000
	cfg.MatchInterval, cfg.PackInterval = 0, 0
	cfg.Socket = filepath.Join(dir, "kg.sock")
	svc, err := keyguard.New(context.Background(), cfg, keyguard.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, _, err := keyguard.Listen(&cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done; _ = svc.Close() })

	author := `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},
 "identity":{"subject":{"from":"header","name":"authorization"}},"sampling":{"rate":0.05},
 "services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep"}}}}}}`
	d := json.NewDecoder(strings.NewReader(author))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	body, _, err := policy.Compile(a, policy.CompileMeta{Version: 7, IssuedSeq: 1, CreatedAt: now.Add(-time.Minute), Groups: []string{"shop"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignPolicy(context.Background(), body, "alice", []keyguard.Approval{
		{User: "alice", Roles: []string{"policy-approver"}, At: now}, {User: "bob", Roles: []string{"policy-approver"}, At: now}}); err != nil {
		t.Fatal(err)
	}
	kc, err := client.New(client.Config{URL: "unix://" + cfg.Socket})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kc.Close)
	return svc, kc
}

type staticContracts []world.Contract

func (s staticContracts) Contracts(context.Context) ([]world.Contract, error) { return s, nil }

type staticRules []byte

func (s staticRules) ApprovedRules(context.Context) (*world.RuleSet, error) {
	return &world.RuleSet{Doc: s}, nil
}

type staticPolicies []client.PolicyRef

func (s staticPolicies) SourcePolicies(context.Context) ([]client.PolicyRef, error) { return s, nil }

type memEvents []*intake.StoredEvent

func (m memEvents) Scan(_ context.Context, q intake.Query, fn func(*intake.StoredEvent) error) error {
	for _, e := range m {
		if (q.Dir != "" && e.Event.Dir != q.Dir) || (!q.From.IsZero() && e.Event.Time.Before(q.From)) || (!q.To.IsZero() && !e.Event.Time.Before(q.To)) {
			continue
		}
		if err := fn(e); err != nil {
			return nil
		}
	}
	return nil
}

func demoEvents(now time.Time) memEvents {
	var out memEvents
	for i := 0; i < 30; i++ {
		subj := fmt.Sprintf("tk1:k1:S%021d", i)
		for c := 0; c < 4; c++ {
			at := now.Add(-time.Duration(c+1) * 24 * time.Hour).Truncate(24 * time.Hour).Add(19 * time.Hour)
			out = append(out, &intake.StoredEvent{Event: &event.Event{Dir: event.Inbound, Service: "shop-api", Op: "POST /orders", Status: 201, Subject: subj, Time: at, LatencyMS: 120}})
			out = append(out, &intake.StoredEvent{Event: &event.Event{Dir: event.Inbound, Service: "shop-api", Op: "GET /orders/{id}", Status: 200, Subject: subj, Time: at.Add(time.Minute), LatencyMS: 40}})
		}
	}
	return out
}

type core struct {
	t        *testing.T
	h        http.Handler
	sessions map[string][2]string
	authSvc  *auth.Service
}

var fastParams = auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

const testPassword = "correct-horse-battery-1"

func (c *core) user(name string, roles ...auth.Role) {
	c.t.Helper()
	if _, err := c.authSvc.CreateLocalUser(context.Background(), name, testPassword, roles); err != nil {
		c.t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, name, testPassword)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		c.t.Fatalf("login %s: %d %s", name, rec.Code, rec.Body)
	}
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	for _, ck := range rec.Result().Cookies() {
		if strings.HasSuffix(ck.Name, "tt_session") {
			c.sessions[name] = [2]string{ck.Name + "=" + ck.Value, me.CSRF}
		}
	}
}

func (c *core) do(user, method, path string, body any) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	s := c.sessions[user]
	req.Header.Set("Cookie", s[0])
	req.Header.Set(auth.CSRFHeader, s[1])
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (c *core) must(code int, want int, body []byte) {
	c.t.Helper()
	if code != want {
		c.t.Fatalf("status %d (want %d): %s", code, want, body)
	}
}

func TestEndToEndPublishWithRealKeyguard(t *testing.T) {
	kgSvc, kc := startKeyguard(t)
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "tt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	al := audit.New(db)
	authSvc, err := auth.New(db, al, auth.Options{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, LocalEnabled: true, PasswordParams: &fastParams})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(dir, "tt.db")
	cfg.Auth.RateLimit = config.RateLimit{RequestsPerMinute: 10000, Burst: 1000}
	srv, err := server.New(cfg, server.Deps{Auth: authSvc, Audit: al, DB: db})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	contracts := staticContracts(demoContracts(t))
	rules := staticRules(demoFile(t, "rules.json"))
	ws, err := world.New(world.Options{DB: db, Audit: al, Events: demoEvents(now), Contracts: contracts, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	pw, err := New(Options{DB: db, Audit: al, Worlds: ws, Keyguard: kc, Policies: staticPolicies{{ID: "p-shop", Version: 7}},
		Rules: rules, Faults: &EventFaults{Events: demoEvents(now)}, TempDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	world.Mount(srv, ws)
	gate.Mount(srv, pw, nil)
	c := &core{t: t, h: srv.AdminHandler(), sessions: map[string][2]string{}, authSvc: authSvc}
	c.user("olga", auth.RoleOperator)
	c.user("paul", auth.RolePublisher)
	c.user("ada", auth.RoleAdmin)
	c.user("audrey", auth.RoleAuditor)

	code, body := c.do("olga", "POST", "/api/v1/archetypes/build", map[string]any{"k_min": 20})
	c.must(code, 202, body)
	code, body = c.do("audrey", "GET", "/api/v1/archetypes", nil)
	c.must(code, 200, body)
	var archList world.ArchetypeList
	_ = json.Unmarshal(body, &archList)
	arch := archList.Archetypes
	if archList.KMin != 20 || !archList.Built || len(arch) != 1 || arch[0].Size != 30 || strings.Contains(string(body), "tk1:") {
		t.Fatalf("archetypes: %s", body)
	}
	code, body = c.do("paul", "POST", "/api/v1/worlds", map[string]any{"seed": 42, "customers": 30})
	c.must(code, 403, body)
	code, body = c.do("olga", "POST", "/api/v1/worlds", map[string]any{"seed": 42, "customers": 30})
	c.must(code, 202, body)
	var job struct {
		Result world.Info `json:"result"`
	}
	_ = json.Unmarshal(body, &job)
	wid := job.Result.WorldID
	code, body = c.do("audrey", "GET", "/api/v1/worlds/"+wid+"/customers/CUS-SYN-0001", nil)
	c.must(code, 200, body)
	if !strings.Contains(string(body), `CUS-SYN-0001`) {
		t.Fatalf("preview: %s", body)
	}
	// World explorer: a page of synthetic customers, searchable and paged.
	code, body = c.do("audrey", "GET", "/api/v1/worlds/"+wid+"/customers?limit=10", nil)
	c.must(code, 200, body)
	var custPage world.CustomerPage
	if err := json.Unmarshal(body, &custPage); err != nil || custPage.All != 30 || custPage.Total != 30 || len(custPage.Customers) != 10 || custPage.Customers[0].ID != "CUS-SYN-0001" {
		t.Fatalf("customers page: %v %s", err, body)
	}
	code, body = c.do("audrey", "GET", "/api/v1/worlds/"+wid+"/customers?q=cus-syn-0030", nil)
	c.must(code, 200, body)
	_ = json.Unmarshal(body, &custPage)
	if custPage.Total != 1 || custPage.Customers[0].ID != "CUS-SYN-0030" {
		t.Fatalf("customers search: %s", body)
	}
	code, body = c.do("audrey", "GET", "/api/v1/worlds/"+wid+"/customers?offset=25&limit=10", nil)
	c.must(code, 200, body)
	_ = json.Unmarshal(body, &custPage)
	if len(custPage.Customers) != 5 || custPage.Offset != 25 {
		t.Fatalf("customers last page: %s", body)
	}
	code, body = c.do("audrey", "GET", "/api/v1/worlds/"+wid+"/customers?offset=-1", nil)
	c.must(code, 400, body)
	code, body = c.do("audrey", "GET", "/api/v1/worlds/w-20000101-0001/customers", nil)
	c.must(code, 404, body)
	code, body = c.do("paul", "GET", "/api/v1/worlds/"+wid+"/customers", nil)
	c.must(code, 200, body)

	build := func() gate.PackInfo {
		t.Helper()
		code, body := c.do("olga", "POST", "/api/v1/packs", map[string]any{"world_id": wid, "valid_days": 30})
		c.must(code, 202, body)
		var j struct {
			Result gate.PackInfo `json:"result"`
		}
		_ = json.Unmarshal(body, &j)
		return j.Result
	}
	p1 := build()
	if p1.Status != gate.StatusSigned || p1.ResidualRisk == nil || p1.ResidualRisk.MinArchetypeSize != 30 {
		t.Fatalf("pack 1: %+v %s", p1, p1.GateReport)
	}
	// The warnings of a pack built on little traffic are stored with it and
	// listed (the demo window is short: "few observations" on the pack).
	if p1.Warnings == nil {
		t.Fatalf("pack 1 has no warnings list: %+v", p1)
	}
	code, body = c.do("audrey", "GET", "/api/v1/packs/"+p1.PackID, nil)
	c.must(code, 200, body)
	var again gate.PackInfo
	_ = json.Unmarshal(body, &again)
	if again.WarningsTotal != p1.WarningsTotal || len(again.Warnings) != len(p1.Warnings) || !strings.Contains(string(body), `"warnings":[`) {
		t.Fatalf("stored warnings differ: built %d/%d, read %d/%d", len(p1.Warnings), p1.WarningsTotal, len(again.Warnings), again.WarningsTotal)
	}
	t.Logf("demo pack: %d warnings", p1.WarningsTotal)
	code, body = c.do("paul", "GET", "/api/v1/packs/"+p1.PackID+"/download", nil)
	c.must(code, 409, body)
	code, body = c.do("olga", "POST", "/api/v1/packs/"+p1.PackID+"/publish", nil)
	c.must(code, 403, body)
	code, body = c.do("paul", "POST", "/api/v1/packs/"+p1.PackID+"/publish", nil)
	c.must(code, 200, body)
	var pub gate.PackInfo
	_ = json.Unmarshal(body, &pub)
	if pub.Status != gate.StatusPublished || pub.ApprovalMode != "standard" || pub.PublishedAt == nil {
		t.Fatalf("published: %s", body)
	}
	code, body = c.do("paul", "GET", "/api/v1/packs/"+p1.PackID+"/download", nil)
	c.must(code, 200, body)
	// The downloaded .ttpack verifies with internal/pack and keyguard's keys.
	pks, err := kc.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pack.ParseKeySet(pks.GatePubKeys())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, p1.PackID+".ttpack")
	if err := os.WriteFile(f, body, 0o600); err != nil {
		t.Fatal(err)
	}
	pk, err := pack.Load(f, pack.Options{Keys: keys})
	if err != nil {
		t.Fatalf("pack.Load: %v", err)
	}
	if len(pk.World.Customers) != 30 || len(pk.World.Pending) == 0 || pk.NotAfter.IsZero() || pk.Scenarios == nil {
		t.Fatalf("loaded pack: customers %d pending %d", len(pk.World.Customers), len(pk.World.Pending))
	}

	// Admin override: a reason is mandatory, then approval_mode admin.
	p2 := build()
	code, body = c.do("ada", "POST", "/api/v1/packs/"+p2.PackID+"/publish", nil)
	c.must(code, 403, body)
	code, body = c.do("ada", "POST", "/api/v1/packs/"+p2.PackID+"/publish", map[string]any{"reason": "solo maintainer release"})
	c.must(code, 200, body)
	if !strings.Contains(string(body), `"approval_mode":"admin"`) {
		t.Fatalf("admin publish: %s", body)
	}

	// A real token appears among the values the pack would publish: the
	// reverse-HMAC pre-check of the real keyguard blocks the pack.
	if err := kgSvc.AddTokens(ctx, "2026-10", []string{token("2026-10", "order", "no such order")}); err != nil {
		t.Fatal(err)
	}
	p3 := build()
	if p3.Status != gate.StatusGateFailed || !strings.Contains(string(p3.GateReport), `"id":"reverse-hmac","status":"fail"`) ||
		strings.Contains(string(p3.GateReport), "no such order") {
		t.Fatalf("pack with real value: %s", p3.GateReport)
	}
	code, body = c.do("paul", "POST", "/api/v1/packs/"+p3.PackID+"/publish", nil)
	c.must(code, 409, body)

	code, body = c.do("audrey", "GET", "/api/v1/packs", nil)
	c.must(code, 200, body)
	var list []gate.PackInfo
	_ = json.Unmarshal(body, &list)
	if len(list) != 3 {
		t.Fatalf("list: %s", body)
	}
	// Audit chain has the publication.
	n := 0
	_ = al.Iterate(ctx, 0, 1000, func(e audit.Entry) error {
		if e.Action == "pack.publish" && e.Outcome == audit.Success {
			n++
		}
		return nil
	})
	if n != 2 {
		t.Fatalf("pack.publish audit entries: %d", n)
	}
}
