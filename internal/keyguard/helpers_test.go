package keyguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Invented test data only: the HMAC key k1 is the conformance key
// 0x00..0x1f (sanitizer 7.3); other keys are random per test.

var t0 = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

func k1Secret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func randSecret(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testEnv is a keyguard with key files in a temp dir and a fake clock.
type testEnv struct {
	t          *testing.T
	dir        string
	clock      *fakeClock
	cfg        Config
	svc        *Service
	logs       *syncBuffer
	k2         []byte
	policySeed []byte
	packSeed   []byte

	mu     sync.Mutex
	alerts []Alert
}

func writeKeyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T, mut func(*Config)) *testEnv {
	t.Helper()
	e := &testEnv{t: t, dir: t.TempDir(), clock: &fakeClock{t: t0}, logs: &syncBuffer{},
		k2: randSecret(32), policySeed: randSecret(32), packSeed: randSecret(32)}
	writeKeyFile(t, filepath.Join(e.dir, "hmac.keys"), "k1:"+b64(k1Secret())+"\nk2:"+b64(e.k2)+"\n")
	writeKeyFile(t, filepath.Join(e.dir, "policy.key"), "policy-2026-1:"+b64(e.policySeed)+"\n")
	writeKeyFile(t, filepath.Join(e.dir, "pack.key"), "gate-2026-1:"+b64(e.packSeed)+"\n")
	cfg := DefaultConfig()
	cfg.DBPath = filepath.Join(e.dir, "kg.db")
	cfg.HMACKeys = KeySource{File: filepath.Join(e.dir, "hmac.keys")}
	cfg.PolicyKey = KeySource{File: filepath.Join(e.dir, "policy.key")}
	cfg.PackKey = KeySource{File: filepath.Join(e.dir, "pack.key")}
	cfg.BloomCapacity = 10000
	cfg.LogLevel = "debug"
	if mut != nil {
		mut(&cfg)
	}
	e.cfg = cfg
	e.start()
	t.Cleanup(func() {
		if e.svc != nil {
			_ = e.svc.Close()
		}
	})
	return e
}

func (e *testEnv) start() {
	e.t.Helper()
	svc, err := New(context.Background(), e.cfg, Options{
		Logger: NewLogger(e.logs, "debug", "json"),
		Now:    e.clock.Now,
		OnAlert: func(a Alert) {
			e.mu.Lock()
			e.alerts = append(e.alerts, a)
			e.mu.Unlock()
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc = svc
}

func (e *testEnv) restart() {
	e.t.Helper()
	if err := e.svc.Close(); err != nil {
		e.t.Fatal(err)
	}
	e.start()
}

func (e *testEnv) alertTypes() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, a := range e.alerts {
		out = append(out, a.Type)
	}
	return out
}

func (e *testEnv) policyPub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(e.policySeed).Public().(ed25519.PublicKey)
}

func (e *testEnv) packPub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(e.packSeed).Public().(ed25519.PublicKey)
}

// ---- policies ----

// shopRules is the services block of the test policy; variants edit it.
const shopRules = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},
   "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}}}}`

func authorJSON(policyID, hmacBlock, rules string) string {
	if hmacBlock == "" {
		hmacBlock = `{"kid":"k1","epoch":"2026-10"}`
	}
	return `{"format":"tt.policy/v1","policy_id":"` + policyID + `","default":"drop","hmac":` + hmacBlock + `,
 "identity":{"subject":{"from":"header","name":"authorization"}},
 "sampling":{"rate":0.05},` + rules + `}`
}

type bodyOpts struct {
	id       string
	version  int64
	seq      int64
	groups   []string
	created  time.Time
	notAfter time.Time
	hmac     string
	rules    string
}

func compileBody(t *testing.T, o bodyOpts) []byte {
	t.Helper()
	if o.id == "" {
		o.id = "p-shop"
	}
	if o.groups == nil {
		o.groups = []string{"shop"}
	}
	if o.created.IsZero() {
		o.created = t0
	}
	if o.rules == "" {
		o.rules = shopRules
	}
	d := json.NewDecoder(strings.NewReader(authorJSON(o.id, o.hmac, o.rules)))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := policy.Compile(a, policy.CompileMeta{Version: o.version, IssuedSeq: o.seq, CreatedAt: o.created, NotAfter: o.notAfter, Groups: o.groups})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func appr(user string, roles ...string) Approval {
	if len(roles) == 0 {
		roles = []string{RolePolicyApprover}
	}
	return Approval{User: user, Roles: roles, At: t0}
}

func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "go:" + err.Error()
}

// signFirst signs a first (opening) policy with two approvals.
func (e *testEnv) signFirst(o bodyOpts) []byte {
	e.t.Helper()
	body := compileBody(e.t, o)
	if _, err := e.svc.SignPolicy(context.Background(), body, "alice", []Approval{appr("alice"), appr("bob")}); err != nil {
		e.t.Fatalf("sign first: %v", err)
	}
	return body
}
