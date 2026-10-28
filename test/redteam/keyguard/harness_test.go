// Package keyguard_rt holds red-team tests for internal/keyguard.
// All keys, users and values are invented and generated per test.
package keyguard_rt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/policy"
)

var t0 = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rnd(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type env struct {
	t        *testing.T
	dir      string
	clk      *clock
	svc      *keyguard.Service
	logs     *lockedBuf
	hmacKey  []byte
	alerts   []keyguard.Alert
	alertsMu sync.Mutex
	// OIDC (optional)
	idpPriv ed25519.PrivateKey
}

const (
	issuer   = "https://idp.rt.example"
	audience = "tt-core-rt"
)

func newEnv(t *testing.T, withOIDC bool, mut func(*keyguard.Config)) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), clk: &clock{t: t0}, logs: &lockedBuf{}, hmacKey: rnd(32)}
	write := func(name, content string) string {
		p := filepath.Join(e.dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := keyguard.DefaultConfig()
	cfg.DBPath = filepath.Join(e.dir, "kg.db")
	cfg.HMACKeys = keyguard.KeySource{File: write("hmac.keys", "k1:"+b64(e.hmacKey)+"\n")}
	cfg.PolicyKey = keyguard.KeySource{File: write("policy.key", "policy-rt-1:"+b64(rnd(32))+"\n")}
	cfg.PackKey = keyguard.KeySource{File: write("pack.key", "gate-rt-1:"+b64(rnd(32))+"\n")}
	cfg.BloomCapacity = 10000
	cfg.LogLevel = "debug"
	if withOIDC {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		e.idpPriv = priv
		jwks := `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"idp-rt","x":"` + b64(pub) + `"}]}`
		cfg.OIDCIssuer = issuer
		cfg.OIDCAudience = audience
		cfg.OIDCJWKSFile = write("jwks.json", jwks)
		cfg.OIDCRolesClaim = "tt_roles"
	}
	if mut != nil {
		mut(&cfg)
	}
	svc, err := keyguard.New(context.Background(), cfg, keyguard.Options{
		Logger: keyguard.NewLogger(e.logs, "debug", "json"),
		Now:    e.clk.Now,
		OnAlert: func(a keyguard.Alert) {
			e.alertsMu.Lock()
			e.alerts = append(e.alerts, a)
			e.alertsMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	t.Cleanup(func() { _ = svc.Close() })
	return e
}

// idToken mints a step-up ID token from the test IdP for sub, bound to
// body (approvebind nonce), with the policy-approver role in its roles
// claim and a fresh auth_time (keyguard.md 3.2 step 4).
func (e *env) idToken(sub string, body []byte) string {
	hdr := b64([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"idp-rt"}`))
	now := e.clk.Now()
	p, err := policy.DecodeBody(body)
	if err != nil {
		panic(err)
	}
	nonce, err := approvebind.PolicyBodyNonce(p.PolicyID, p.Version, body)
	if err != nil {
		panic(err)
	}
	claims, _ := json.Marshal(map[string]any{
		"iss": issuer, "aud": audience, "sub": sub,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(),
		"nonce": nonce, "tt_roles": []string{keyguard.RolePolicyApprover},
		"preferred_username": sub,
	})
	signing := hdr + "." + b64(claims)
	sig := ed25519.Sign(e.idpPriv, []byte(signing))
	return signing + "." + b64(sig)
}

const shopRules = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep"}}}}}`

func body(t *testing.T, id string, version, seq int64, groups []string, rules string) []byte {
	t.Helper()
	if rules == "" {
		rules = shopRules
	}
	author := `{"format":"tt.policy/v1","policy_id":"` + id + `","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},
 "sampling":{"rate":0.05},` + rules + `}`
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
	b, _, err := policy.Compile(a, policy.CompileMeta{Version: version, IssuedSeq: seq, CreatedAt: t0, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func appr(user string, roles ...string) keyguard.Approval {
	if len(roles) == 0 {
		roles = []string{keyguard.RolePolicyApprover}
	}
	return keyguard.Approval{User: user, Roles: roles, At: t0}
}
