// Package r3_rt holds the red-team round 3 tests: OIDC end to end (real Dex
// IdP in Docker), session timeouts, policy signing key rotation and
// revocation, renewals.
//
// Run:  go test ./test/redteam/r3/ -count=1 -v
//
// The Dex tests (dex_*_test.go) need Docker and pull
// ghcr.io/dexidp/dex:v2.41.1; they are skipped when Docker is not usable
// or RT3_NO_DOCKER=1. Every user, key and value is invented.
//
// Naming: TestRT3_*_Fails are FAILING reproducers of open findings (they
// fail while the bug exists); TestRT3_*_Fixed are the same reproducers
// once the finding is fixed, kept as regressions; TestRT3_*_Holds_* are
// guards that pass.
package r3_rt

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// kgEnv is an in-process keyguard with its own key files, restartable with
// a different policy key file or revocation list.
type kgEnv struct {
	t       *testing.T
	dir     string
	clk     *clock
	svc     *keyguard.Service
	idpPriv ed25519.PrivateKey
	mut     func(*keyguard.Config)
	oidc    bool
}

const (
	kgIssuer     = "https://idp.rt3.example"
	kgAudience   = "tt-approve-rt3" // dedicated approval audience, not the login client
	kgRolesClaim = "tt_roles"
)

func writeFile(t testing.TB, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newKG(t *testing.T, withOIDC bool, mut func(*keyguard.Config)) *kgEnv {
	t.Helper()
	e := &kgEnv{t: t, dir: t.TempDir(), clk: &clock{t: t0}, mut: mut, oidc: withOIDC}
	writeFile(t, filepath.Join(e.dir, "hmac.keys"), "k1:"+b64(rnd(32))+"\n")
	writeFile(t, filepath.Join(e.dir, "policy.key"), "policy-rt3-1:"+b64(rnd(32))+"\n")
	writeFile(t, filepath.Join(e.dir, "pack.key"), "gate-rt3-1:"+b64(rnd(32))+"\n")
	if withOIDC {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		e.idpPriv = priv
		writeFile(t, filepath.Join(e.dir, "jwks.json"), `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"idp-rt3","x":"`+b64(pub)+`"}]}`)
	}
	e.start(nil)
	return e
}

func (e *kgEnv) start(extra func(*keyguard.Config)) {
	e.t.Helper()
	cfg := keyguard.DefaultConfig()
	cfg.DBPath = filepath.Join(e.dir, "kg.db")
	cfg.HMACKeys = keyguard.KeySource{File: filepath.Join(e.dir, "hmac.keys")}
	cfg.PolicyKey = keyguard.KeySource{File: filepath.Join(e.dir, "policy.key")}
	cfg.PackKey = keyguard.KeySource{File: filepath.Join(e.dir, "pack.key")}
	cfg.BloomCapacity = 10000
	if e.oidc {
		cfg.OIDCIssuer, cfg.OIDCAudience = kgIssuer, kgAudience
		cfg.OIDCJWKSFile = filepath.Join(e.dir, "jwks.json")
		cfg.OIDCRolesClaim = kgRolesClaim
	}
	if e.mut != nil {
		e.mut(&cfg)
	}
	if extra != nil {
		extra(&cfg)
	}
	svc, err := keyguard.New(context.Background(), cfg, keyguard.Options{Logger: keyguard.NewLogger(&strings.Builder{}, "error", "json"), Now: e.clk.Now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.svc = svc
	e.t.Cleanup(func() { _ = svc.Close() })
}

func (e *kgEnv) restart(extra func(*keyguard.Config)) {
	e.t.Helper()
	_ = e.svc.Close()
	e.start(extra)
}

// jwt signs claims with the test IdP (EdDSA).
func (e *kgEnv) jwt(claims map[string]any) string {
	hdr := b64([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"idp-rt3"}`))
	c, _ := json.Marshal(claims)
	in := hdr + "." + b64(c)
	return in + "." + b64(ed25519.Sign(e.idpPriv, []byte(in)))
}

// claims are those of a step-up ID token for the approval audience: fresh
// iat and auth_time, the given nonce, the policy-approver role in the
// roles claim.
func (e *kgEnv) claims(sub, nonce string) map[string]any {
	now := e.clk.Now()
	return map[string]any{"iss": kgIssuer, "aud": kgAudience, "sub": sub, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"auth_time": now.Unix(), "nonce": nonce, kgRolesClaim: []string{keyguard.RolePolicyApprover}}
}

// bound is a step-up token bound to body (approvebind.PolicyBodyNonce),
// with roles in the roles claim (default policy-approver).
func (e *kgEnv) bound(sub string, body []byte, roles ...string) string {
	e.t.Helper()
	p, err := policy.DecodeBody(body)
	if err != nil {
		e.t.Fatal(err)
	}
	n, err := approvebind.PolicyBodyNonce(p.PolicyID, p.Version, body)
	if err != nil {
		e.t.Fatal(err)
	}
	c := e.claims(sub, n)
	if len(roles) > 0 {
		c[kgRolesClaim] = roles
	}
	return e.jwt(c)
}

const shopRules = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep"}}}}}`

func body(t *testing.T, id string, version, seq int64, groups []string, rules string, created time.Time, notAfter time.Time) []byte {
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
	b, _, err := policy.Compile(a, policy.CompileMeta{Version: version, IssuedSeq: seq, CreatedAt: created, NotAfter: notAfter, Groups: groups})
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

func withTok(a keyguard.Approval, tok string) keyguard.Approval { a.IDToken = tok; return a }

func errCode(err error) string {
	if err == nil {
		return ""
	}
	for e := err; e != nil; {
		if ke, ok := e.(*keyguard.Error); ok {
			return ke.Code
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return "go:" + err.Error()
}

// reencodeSig returns the same JWT with the signature segment written in a
// different, non-canonical base64url form (one unused low bit of the last
// character set): the decoded signature bytes are identical.
func reencodeSig(tok string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.LastIndexByte(tok, '.')
	sig := tok[i+1:]
	last := strings.IndexByte(alpha, sig[len(sig)-1])
	return tok[:i+1] + sig[:len(sig)-1] + string(alpha[last^1])
}

// ---------------------------------------------------------------------------
// Approval ID tokens (keyguard.md 3.2 step 4)

// RT3-KG-1 (fixed): the "same token never twice" defence hashed the raw
// token string; the signature segment could be re-encoded (non-canonical
// base64url trailing bits are ignored by go-jose), so the very same ID
// token was accepted again under a different hash. keyguard now refuses
// non-canonical base64url and fingerprints iss/sub/jti (or iat) and the
// decoded signature.
func TestRT3_KG_TokenReuseViaReencodedSignature_Fixed(t *testing.T) {
	e := newKG(t, true, nil)
	ctx := context.Background()
	b1 := body(t, "p-shop", 1, 1, []string{"shop"}, "", t0, time.Time{})
	tokA := e.bound("sub-alice", b1)
	if _, err := e.svc.SignPolicy(ctx, b1, "olga", []keyguard.Approval{withTok(appr("alice"), tokA), withTok(appr("bob"), e.bound("sub-bob", b1))}); err != nil {
		t.Fatalf("first signing: %v", err)
	}
	// The exact token is refused a second time (round 1 guard)...
	b2 := body(t, "p-other", 1, 2, []string{"other"}, "", t0, time.Time{})
	_, err := e.svc.SignPolicy(ctx, b2, "olga", []keyguard.Approval{withTok(appr("alice"), tokA), withTok(appr("dave"), e.bound("sub-dave", b2))})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("exact reuse: %q", errCode(err))
	}
	// ...and so is the same token with a re-encoded signature.
	re := reencodeSig(tokA)
	if re == tokA {
		t.Fatal("re-encoding did not change the token")
	}
	_, err = e.svc.SignPolicy(ctx, b2, "olga", []keyguard.Approval{withTok(appr("alice"), re), withTok(appr("dave"), e.bound("sub-dave2", b2))})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("FINDING RT3-KG-1: re-encoded token: %q", errCode(err))
	}
	// A non-canonical spelling is refused also for the change it is bound
	// to (only one spelling of a token is accepted).
	_, err = e.svc.SignPolicy(ctx, b2, "olga", []keyguard.Approval{withTok(appr("erin"), reencodeSig(e.bound("sub-erin", b2))), withTok(appr("dave"), e.bound("sub-dave3", b2))})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("non-canonical token for its own change: %q", errCode(err))
	}
}

// RT3-KG-2 (fixed): keyguard took the approver's roles from tt-core, also
// with OIDC. A compromised tt-core holding ONE fresh ID token of ANY user
// declared that user "admin" and signed an opening policy alone. keyguard
// now reads the roles from the verified roles claim of the token.
func TestRT3_KG_AdminRoleNotBoundToToken_Fixed(t *testing.T) {
	e := newKG(t, true, nil)
	opening := body(t, "p-shop", 1, 1, []string{"shop"}, `"global":{"request":{"headers":{"x-user-email":"keep"}}},`+shopRules, t0, time.Time{})
	// An operator's token (bound to this very change: the worst case),
	// declared admin by tt-core.
	a := withTok(appr("olga", keyguard.RoleAdmin), e.bound("sub-olga-operator", opening, "operator"))
	a.Reason = "routine"
	res, err := e.svc.SignPolicy(context.Background(), opening, "olga", []keyguard.Approval{a})
	if err == nil {
		t.Fatalf("FINDING RT3-KG-2: keyguard signed an opening policy (mode %s) on a single token of a user whose admin role only tt-core asserts", res.ApprovalMode)
	}
	if errCode(err) != "role_unverified" {
		t.Fatalf("got %q, want role_unverified", errCode(err))
	}
	// policy-approver declared, not in the token: refused as well.
	b := withTok(appr("bob"), e.bound("sub-bob", opening, "operator"))
	c := withTok(appr("carol"), e.bound("sub-carol", opening))
	if _, err := e.svc.SignPolicy(context.Background(), opening, "olga", []keyguard.Approval{b, c}); errCode(err) != "role_unverified" {
		t.Fatalf("policy-approver not in token: %q", errCode(err))
	}
	// The real admin, with admin in its token, still can.
	adm := withTok(appr("ada", keyguard.RoleAdmin), e.bound("sub-ada", opening, keyguard.RoleAdmin))
	adm.Reason = "single maintainer"
	if res, err := e.svc.SignPolicy(context.Background(), opening, "olga", []keyguard.Approval{adm}); err != nil || res.ApprovalMode != keyguard.ModeAdmin {
		t.Fatalf("verified admin: %v %+v", err, res)
	}
}

// RT3-KG-3 (fixed): an approval token was not bound to the change it
// approves: a token minted for a login (nonce of the login, issued before
// the proposal existed) signed any policy. keyguard now requires the
// step-up nonce H(policy_id, version, body digest) and a fresh auth_time.
func TestRT3_KG_TokenNotBoundToChange_Fixed(t *testing.T) {
	e := newKG(t, true, nil)
	loginA := e.claims("sub-alice", "nonce-of-a-ui-login")
	loginB := e.claims("sub-bob", "nonce-of-another-ui-login")
	tA, tB := e.jwt(loginA), e.jwt(loginB)
	e.clk.Add(3 * time.Minute) // the proposal is created after both logins
	b := body(t, "p-shop", 1, 1, []string{"shop"}, `"global":{"request":{"headers":{"x-user-email":"keep"}}},`+shopRules, e.clk.Now(), time.Time{})
	_, err := e.svc.SignPolicy(context.Background(), b, "olga", []keyguard.Approval{withTok(appr("alice"), tA), withTok(appr("bob"), tB)})
	if err == nil {
		t.Fatal("FINDING RT3-KG-3: login ID tokens minted before the proposal existed approved an opening policy (no per-approval binding)")
	}
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("got %q", errCode(err))
	}
	// A step-up for another version of the same policy does not fit either.
	other := body(t, "p-shop", 2, 1, []string{"shop"}, `"global":{"request":{"headers":{"x-user-email":"keep"}}},`+shopRules, e.clk.Now(), time.Time{})
	_, err = e.svc.SignPolicy(context.Background(), b, "olga", []keyguard.Approval{withTok(appr("alice"), e.bound("sub-alice", other)), withTok(appr("bob"), e.bound("sub-bob", b))})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("token of another version: %q", errCode(err))
	}
	// An old IdP session (auth_time 20 minutes ago) does not count as a
	// step-up even with the right nonce.
	n, _ := approvebind.PolicyBodyNonce("p-shop", 1, b)
	stale := e.claims("sub-alice", n)
	stale["auth_time"] = e.clk.Now().Add(-20 * time.Minute).Unix()
	_, err = e.svc.SignPolicy(context.Background(), b, "olga", []keyguard.Approval{withTok(appr("alice"), e.jwt(stale)), withTok(appr("bob"), e.bound("sub-bob", b))})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("old auth_time: %q", errCode(err))
	}
	// Bound step-up tokens sign.
	if _, err := e.svc.SignPolicy(context.Background(), b, "olga", []keyguard.Approval{withTok(appr("alice"), e.bound("sub-alice2", b)), withTok(appr("bob"), e.bound("sub-bob2", b))}); err != nil {
		t.Fatalf("bound tokens: %v", err)
	}
}

// RT3-KG-4 (fixed): in admin mode keyguard stored only the admin approval
// row, so the token hashes of the other approvals of the same call were
// not recorded and could be replayed. Every presented token is now
// recorded (and, with the binding, a token only fits its own change).
func TestRT3_KG_AdminModeForgetsOtherTokens_Fixed(t *testing.T) {
	e := newKG(t, true, nil)
	ctx := context.Background()
	b1 := body(t, "p-shop", 1, 1, []string{"shop"}, "", t0, time.Time{})
	tokPia := e.bound("sub-pia", b1)
	adm := withTok(appr("ada", keyguard.RoleAdmin), e.bound("sub-ada", b1, keyguard.RoleAdmin))
	adm.Reason = "single maintainer"
	res, err := e.svc.SignPolicy(ctx, b1, "olga", []keyguard.Approval{withTok(appr("pia"), tokPia), adm})
	if err != nil || res.ApprovalMode != keyguard.ModeAdmin {
		t.Fatalf("admin signing: %v %+v", err, res)
	}
	b2 := body(t, "p-other", 1, 2, []string{"other"}, "", t0, time.Time{})
	_, err = e.svc.SignPolicy(ctx, b2, "olga", []keyguard.Approval{withTok(appr("pia"), tokPia), withTok(appr("pete"), e.bound("sub-pete", b2))})
	if err == nil {
		t.Fatal("FINDING RT3-KG-4: pia's token, already presented with an admin approval, was accepted again")
	}
	// pia's token was recorded although only ada's approval counted: it is
	// refused also as a pack publish approval (any later use).
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("got %q", errCode(err))
	}
}

// Guards: forged or unfit approval tokens are refused.
func TestRT3_KG_Holds_ForgedApprovalTokens(t *testing.T) {
	e := newKG(t, true, nil)
	ctx := context.Background()
	jwkPub := e.idpPriv.Public().(ed25519.PublicKey)
	hs := func(secret []byte, claims map[string]any) string {
		hdr := b64([]byte(`{"alg":"HS256","typ":"JWT","kid":"idp-rt3"}`))
		c, _ := json.Marshal(claims)
		in := hdr + "." + b64(c)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(in))
		return in + "." + b64(m.Sum(nil))
	}
	none := func(claims map[string]any) string {
		c, _ := json.Marshal(claims)
		return b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64(c) + "."
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	attacker := func(claims map[string]any) string {
		hdr := b64([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"idp-rt3"}`))
		c, _ := json.Marshal(claims)
		in := hdr + "." + b64(c)
		return in + "." + b64(ed25519.Sign(otherPriv, []byte(in)))
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = rsaKey
	type mk func(nonce string) string
	mod := func(f func(map[string]any)) mk {
		return func(n string) string { c := e.claims("sub-x", n); f(c); return e.jwt(c) }
	}
	cases := map[string]mk{
		"alg none":              func(n string) string { return none(e.claims("sub-x", n)) },
		"alg none no dot":       func(n string) string { return strings.TrimSuffix(none(e.claims("sub-x", n)), ".") },
		"HS256 with public key": func(n string) string { return hs(jwkPub, e.claims("sub-x", n)) },
		"HS256 with jwk json": func(n string) string {
			return hs([]byte(`{"kty":"OKP","crv":"Ed25519","x":"`+b64(jwkPub)+`"}`), e.claims("sub-x", n))
		},
		"attacker key, same kid":   func(n string) string { return attacker(e.claims("sub-x", n)) },
		"wrong audience":           mod(func(c map[string]any) { c["aud"] = "another-app" }),
		"audience list without us": mod(func(c map[string]any) { c["aud"] = []string{"another-app", "x"} }),
		"wrong issuer (mix-up)":    mod(func(c map[string]any) { c["iss"] = "https://other-idp.rt3.example" }),
		"expired":                  mod(func(c map[string]any) { c["exp"] = e.clk.Now().Add(-time.Second).Unix() }),
		"iat older than 10 min":    mod(func(c map[string]any) { c["iat"] = e.clk.Now().Add(-11 * time.Minute).Unix() }),
		"iat in the future":        mod(func(c map[string]any) { c["iat"] = e.clk.Now().Add(10 * time.Minute).Unix() }),
		"no iat":                   mod(func(c map[string]any) { delete(c, "iat") }),
		"no sub":                   mod(func(c map[string]any) { delete(c, "sub") }),
		"no auth_time":             mod(func(c map[string]any) { delete(c, "auth_time") }),
		"auth_time in the future":  mod(func(c map[string]any) { c["auth_time"] = e.clk.Now().Add(10 * time.Minute).Unix() }),
		"no nonce":                 mod(func(c map[string]any) { delete(c, "nonce") }),
		"padded signature":         func(n string) string { return e.jwt(e.claims("sub-x", n)) + "=" },
		"garbage":                  func(string) string { return "a.b.c" },
	}
	seq := int64(0)
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			seq++
			b := body(t, "p-f"+string(rune('a'+seq)), 1, seq, []string{"g"}, "", t0, time.Time{})
			n, _ := approvebind.PolicyBodyNonce("p-f"+string(rune('a'+seq)), 1, b)
			_, err := e.svc.SignPolicy(ctx, b, "olga", []keyguard.Approval{withTok(appr("alice"), tok(n)), withTok(appr("bob"), e.bound("sub-bob-"+name, b))})
			if errCode(err) != "approval_unverifiable" {
				t.Fatalf("got %q, want approval_unverifiable", errCode(err))
			}
		})
	}
	// Same subject twice (two different tokens): duplicate_approver.
	b := body(t, "p-dup", 1, 100, []string{"g"}, "", t0, time.Time{})
	t1 := e.bound("sub-same", b)
	e.clk.Add(time.Second)
	t2 := e.bound("sub-same", b)
	_, err := e.svc.SignPolicy(ctx, b, "olga", []keyguard.Approval{withTok(appr("alice"), t1), withTok(appr("bob"), t2)})
	if errCode(err) != "duplicate_approver" {
		t.Fatalf("same sub twice: %q", errCode(err))
	}
	// The token expires exactly at 10 minutes of age, measured on keyguard's clock.
	b = body(t, "p-late", 1, 101, []string{"g"}, "", t0, time.Time{})
	fresh := e.bound("sub-late", b)
	e.clk.Add(10*time.Minute + time.Second)
	_, err = e.svc.SignPolicy(ctx, b, "olga", []keyguard.Approval{withTok(appr("alice"), fresh), withTok(appr("bob"), e.bound("sub-bob-late", b))})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("token older than 10 minutes: %q", errCode(err))
	}
}

// ---------------------------------------------------------------------------
// Renewals (keyguard.md 3.3)

func TestRT3_KG_Holds_Renewals(t *testing.T) {
	ctx := context.Background()
	two := func(a, b string) []keyguard.Approval { return []keyguard.Approval{appr(a), appr(b)} }

	t.Run("cannot change targets", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 2, 2, []string{"g1", "g2"}, "", t0.Add(time.Minute), time.Time{}))
		if errCode(err) != "fields_differ" {
			t.Fatalf("got %q", errCode(err))
		}
	})
	t.Run("cannot resurrect an expired policy", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, t0.Add(24*time.Hour)), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		e.clk.Add(25 * time.Hour)
		now := e.clk.Now()
		_, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 2, 2, []string{"g1"}, "", now, time.Time{}))
		if errCode(err) != "expired" {
			t.Fatalf("got %q", errCode(err))
		}
	})
	t.Run("cannot renew a policy superseded in its group", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-b", 1, 2, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 2, 3, []string{"g1"}, "", t0.Add(time.Minute), time.Time{}))
		if errCode(err) != "superseded" {
			t.Fatalf("got %q", errCode(err))
		}
	})
	t.Run("cannot renew an older version of the same policy", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		closing := `"services":{"shop-api":{"match":{"inbound":true},"ops":{"POST /orders":{"response":{"$.id":"hmac(order)"}}}}}`
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 2, 2, []string{"g1"}, closing, t0, time.Time{}), "olga", []keyguard.Approval{appr("pia")}); err != nil {
			t.Fatal(err)
		}
		// Renewing v1's rules (status keep) as v3: they differ from the last body.
		_, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 3, 3, []string{"g1"}, "", t0.Add(time.Minute), time.Time{}))
		if errCode(err) != "fields_differ" {
			t.Fatalf("got %q", errCode(err))
		}
	})
	t.Run("version must not decrease, issued_seq must grow", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 5, 10, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 4, 11, []string{"g1"}, "", t0.Add(time.Minute), time.Time{})); errCode(err) != "version_not_increasing" {
			t.Fatalf("version down: %q", errCode(err))
		}
		if _, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 6, 10, []string{"g1"}, "", t0.Add(time.Minute), time.Time{})); errCode(err) != "issued_seq_not_increasing" {
			t.Fatalf("seq equal: %q", errCode(err))
		}
	})
	t.Run("renewal beyond max validity refused", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 2, 2, []string{"g1"}, "", t0, t0.Add(31*24*time.Hour)))
		if errCode(err) != "invalid_times" {
			t.Fatalf("got %q", errCode(err))
		}
	})
	t.Run("renewal with a revoked HMAC kid refused", func(t *testing.T) {
		e := newKG(t, false, nil)
		if _, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete")); err != nil {
			t.Fatal(err)
		}
		e.restart(func(c *keyguard.Config) { c.RevokedKids = map[string]bool{"k1": true} })
		_, err := e.svc.RenewPolicy(ctx, body(t, "p-a", 2, 2, []string{"g1"}, "", t0.Add(time.Minute), time.Time{}))
		if errCode(err) != "kid_revoked" {
			t.Fatalf("got %q", errCode(err))
		}
	})
	t.Run("renewal after signing-key rotation uses the new key, never the revoked one", func(t *testing.T) {
		e := newKG(t, false, nil)
		r, err := e.svc.SignPolicy(ctx, body(t, "p-a", 1, 1, []string{"g1"}, "", t0, time.Time{}), "olga", two("pia", "pete"))
		if err != nil || r.Kid != "policy-rt3-1" {
			t.Fatal(err, r)
		}
		old, _ := os.ReadFile(filepath.Join(e.dir, "policy.key"))
		writeFile(t, filepath.Join(e.dir, "policy.key"), "policy-rt3-2:"+b64(rnd(32))+"\n"+string(old))
		e.restart(func(c *keyguard.Config) { c.RevokedKids = map[string]bool{"policy-rt3-1": true} })
		r, err = e.svc.RenewPolicy(ctx, body(t, "p-a", 2, 2, []string{"g1"}, "", t0.Add(time.Minute), time.Time{}))
		if err != nil || r.Kid != "policy-rt3-2" {
			t.Fatalf("renew after rotation: %v %+v", err, r)
		}
		for _, k := range e.svc.PublicKeys()["policy"] {
			if k.Kid == "policy-rt3-1" {
				t.Fatal("revoked kid still announced")
			}
		}
		// A revoked FIRST line must stop keyguard from starting.
		writeFile(t, filepath.Join(e.dir, "policy.key"), string(old))
		cfg := keyguard.DefaultConfig()
		cfg.DBPath = filepath.Join(t.TempDir(), "x.db")
		cfg.HMACKeys = keyguard.KeySource{File: filepath.Join(e.dir, "hmac.keys")}
		cfg.PolicyKey = keyguard.KeySource{File: filepath.Join(e.dir, "policy.key")}
		cfg.PackKey = keyguard.KeySource{File: filepath.Join(e.dir, "pack.key")}
		cfg.RevokedKids = map[string]bool{"policy-rt3-1": true}
		if s, err := keyguard.New(ctx, cfg, keyguard.Options{Logger: keyguard.NewLogger(&strings.Builder{}, "error", "json")}); err == nil {
			s.Close()
			t.Fatal("keyguard started with a revoked active signing key")
		}
	})
}

// RT3-KEY-1 (keyguard side): after a rotation keyguard announced the new
// policy signing key WITHOUT an endorsement by the retired one, so sources
// already enrolled could never learn it through add_signing_keys. Fixed:
// the retired seed endorses the new key at load time (keyguard.md 6).
func TestRT3_KG_RotationHasNoEndorsement_Fixed(t *testing.T) {
	e := newKG(t, false, nil)
	old, _ := os.ReadFile(filepath.Join(e.dir, "policy.key"))
	writeFile(t, filepath.Join(e.dir, "policy.key"), "policy-rt3-2:"+b64(rnd(32))+"\n"+string(old))
	e.restart(nil)
	raw, _ := json.Marshal(e.svc.PublicKeys())
	var pk map[string][]map[string]any
	_ = json.Unmarshal(raw, &pk)
	var found map[string]any
	for _, k := range pk["policy"] {
		if k["kid"] == "policy-rt3-2" {
			found = k
		}
	}
	if found == nil {
		t.Fatalf("new key not announced: %s", raw)
	}
	if found["endorsed_by"] != "policy-rt3-1" || found["endorsement"] == nil {
		t.Fatalf("FINDING RT3-KEY-1: rotated policy key announced without endorsement by the retired key: %s", raw)
	}
	// The endorsement verifies on a ring that only pins the retired key.
	ring := policy.NewKeyRing()
	for _, k := range pk["policy"] {
		if k["kid"] == "policy-rt3-1" {
			if err := ring.PinEncoded("policy-rt3-1", "Ed25519", fmt.Sprint(k["public_key"])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := ring.PinEndorsed("policy-rt3-2", "Ed25519", fmt.Sprint(found["public_key"]), "policy-rt3-1", fmt.Sprint(found["endorsement"])); err != nil {
		t.Fatalf("endorsement does not verify: %v", err)
	}
}
