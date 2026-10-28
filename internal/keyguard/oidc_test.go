package keyguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
)

type idp struct {
	priv ed25519.PrivateKey
	jwks string
}

const (
	testIssuer     = "https://idp.example"
	testAudience   = "tt-approve"
	testRolesClaim = "groups"
)

func newIDP(t *testing.T, dir string) *idp {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(pub), "kid": "t1", "use": "sig"}}})
	p := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(p, jwks, 0o644); err != nil {
		t.Fatal(err)
	}
	return &idp{priv: priv, jwks: p}
}

// tokenOpts are the claims of a test approval token.
type tokenOpts struct {
	sub, aud, nonce string
	iat             time.Time
	authTime        *time.Time // nil: same as iat
	noAuthTime      bool
	groups          []string // nil: tt-approvers
}

func (i *idp) mint(o tokenOpts) string {
	if o.aud == "" {
		o.aud = testAudience
	}
	if o.groups == nil {
		o.groups = []string{"tt-approvers"}
	}
	claims := map[string]any{"iss": testIssuer, "aud": o.aud, "sub": o.sub, "iat": o.iat.Unix(), "exp": o.iat.Add(time.Hour).Unix(),
		"nonce": o.nonce, testRolesClaim: o.groups}
	switch {
	case o.noAuthTime:
	case o.authTime != nil:
		claims["auth_time"] = o.authTime.Unix()
	default:
		claims["auth_time"] = o.iat.Unix()
	}
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "t1"})
	p, _ := json.Marshal(claims)
	msg := b64(h) + "." + b64(p)
	return msg + "." + b64(ed25519.Sign(i.priv, []byte(msg)))
}

func oidcEnv(t *testing.T, mut func(*Config)) (*testEnv, *idp) {
	p := newIDP(t, t.TempDir())
	e := newEnv(t, func(c *Config) {
		c.OIDCIssuer, c.OIDCAudience, c.OIDCJWKSFile = testIssuer, testAudience, p.jwks
		c.OIDCRolesClaim = testRolesClaim
		c.OIDCRoleMapping = map[string][]string{"tt-approvers": {RolePolicyApprover}, "tt-admins": {RoleAdmin}, "tt-publishers": {RolePublisher}}
		if mut != nil {
			mut(c)
		}
	})
	return e, p
}

func bodyNonce(t *testing.T, body []byte) string {
	t.Helper()
	p, err := decodeSigned(body)
	if err != nil {
		t.Fatal(err)
	}
	n, err := approvebind.PolicyBodyNonce(p.PolicyID, p.Version, body)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApprovalsUnverifiedWithoutOIDC(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	st, _ := e.svc.Status(ctx)
	if !st.ApprovalsUnverified || st.OIDC != nil {
		t.Fatal("approvals_unverified must be true without OIDC")
	}
	e.signFirst(bodyOpts{version: 1, seq: 1})
	entries, _ := e.svc.Audit(ctx, 0, 0)
	last := entries[len(entries)-1]
	if last.Op != "keyguard.policy_sign" || last.Detail["approvals_unverified"] != "true" || last.Detail["approvals_bound"] != "false" {
		t.Fatalf("audit %+v", last)
	}
}

func TestOIDCConfigNeedsRolesClaim(t *testing.T) {
	c := DefaultConfig()
	c.OIDCIssuer, c.OIDCAudience, c.OIDCJWKSFile = testIssuer, testAudience, "x"
	if err := c.Validate(); err == nil {
		t.Fatal("OIDC without roles claim accepted")
	}
	c.OIDCRolesClaim = "groups"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	env := []string{EnvOIDCIssuer + "=" + testIssuer, EnvOIDCAudience + "=a", EnvOIDCJWKSFile + "=x", EnvOIDCRolesClaim + "=groups",
		EnvOIDCRoleMapping + "=g1=admin, g1=publisher,g2=policy-approver"}
	got, err := ConfigFromEnv(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.OIDCRoleMapping["g1"]) != 2 || got.OIDCRoleMapping["g2"][0] != RolePolicyApprover {
		t.Fatalf("mapping %+v", got.OIDCRoleMapping)
	}
	if _, err := ConfigFromEnv(append(env[:4:4], EnvOIDCRoleMapping+"=nogroup")); err == nil {
		t.Fatal("malformed mapping accepted")
	}
}

func TestApprovalsVerifiedWithOIDC(t *testing.T) {
	e, p := oidcEnv(t, nil)
	ctx := context.Background()
	st, _ := e.svc.Status(ctx)
	if st.ApprovalsUnverified || st.OIDC == nil || st.OIDC.Audience != testAudience || st.OIDC.RolesClaim != testRolesClaim {
		t.Fatalf("status %+v", st)
	}
	body := compileBody(t, bodyOpts{version: 1, seq: 1})
	nonce := bodyNonce(t, body)
	fresh := t0.Add(-time.Minute)
	with := func(user string, o tokenOpts) Approval {
		a := appr(user)
		if o.iat.IsZero() {
			o.iat = fresh
		}
		if o.nonce == "" {
			o.nonce = nonce
		}
		a.IDToken = p.mint(o)
		return a
	}
	old := t0.Add(-11 * time.Minute)
	carol := func() Approval { return with("carol", tokenOpts{sub: "sub-carol"}) }
	cases := []struct {
		name string
		apps []Approval
		code string
	}{
		{"missing token", []Approval{appr("bob"), carol()}, "approval_unverifiable"},
		{"wrong audience (login client)", []Approval{with("bob", tokenOpts{sub: "sub-bob", aud: "tt-core-login"}), carol()}, "approval_unverifiable"},
		{"stale token", []Approval{with("bob", tokenOpts{sub: "sub-bob", iat: old}), carol()}, "approval_unverifiable"},
		{"old authentication", []Approval{with("bob", tokenOpts{sub: "sub-bob", authTime: &old}), carol()}, "approval_unverifiable"},
		{"no auth_time", []Approval{with("bob", tokenOpts{sub: "sub-bob", noAuthTime: true}), carol()}, "approval_unverifiable"},
		{"no nonce (login token)", []Approval{with("bob", tokenOpts{sub: "sub-bob", nonce: "-"}), carol()}, "approval_unverifiable"},
		{"nonce of another change", []Approval{with("bob", tokenOpts{sub: "sub-bob", nonce: approvebind.PolicyNonce("p-shop", 2, "x")}), carol()}, "approval_unverifiable"},
		{"role not in token", []Approval{with("bob", tokenOpts{sub: "sub-bob", groups: []string{"tt-publishers"}}), carol()}, "role_unverified"},
		{"no roles claim", []Approval{with("bob", tokenOpts{sub: "sub-bob", groups: []string{}}), carol()}, "role_unverified"},
		{"same subject twice", []Approval{with("bob", tokenOpts{sub: "sub-bob"}), with("carol", tokenOpts{sub: "sub-bob"})}, "duplicate_approver"},
		{"forged signature", []Approval{func() Approval { a := with("bob", tokenOpts{sub: "sub-bob"}); a.IDToken += "x"; return a }(), carol()}, "approval_unverifiable"},
	}
	for _, c := range cases {
		if _, err := e.svc.SignPolicy(ctx, body, "alice", c.apps); errCode(err) != c.code {
			t.Errorf("%s: got %v want %s", c.name, err, c.code)
		}
	}
	bob := with("bob", tokenOpts{sub: "sub-bob"})
	if _, err := e.svc.SignPolicy(ctx, body, "alice", []Approval{bob, carol()}); err != nil {
		t.Fatalf("valid approvals: %v", err)
	}
	// A captured ID token cannot be replayed for another policy: it is
	// bound to the first one, and it was already used.
	closing := compileBody(t, bodyOpts{version: 2, seq: 2, rules: rulesClosing})
	if _, err := e.svc.SignPolicy(ctx, closing, "alice", []Approval{bob}); errCode(err) != "approval_unverifiable" {
		t.Fatalf("replayed token: %v", err)
	}
	// The proposer is recognised by OIDC subject too.
	opening := compileBody(t, bodyOpts{version: 2, seq: 2, rules: rulesOpening})
	on := bodyNonce(t, opening)
	if _, err := e.svc.SignPolicy(ctx, opening, "sub-dave", []Approval{with("dave", tokenOpts{sub: "sub-dave", nonce: on})}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("proposer alone: %v", err)
	}
	// An admin approval needs admin in the token.
	adm := appr("ada", RoleAdmin)
	adm.Reason = "single maintainer"
	adm.IDToken = p.mint(tokenOpts{sub: "sub-ada", iat: fresh, nonce: on})
	if _, err := e.svc.SignPolicy(ctx, opening, "olga", []Approval{adm}); errCode(err) != "role_unverified" {
		t.Fatalf("admin not in token: %v", err)
	}
	adm.IDToken = p.mint(tokenOpts{sub: "sub-ada", iat: fresh, nonce: on, groups: []string{"tt-admins"}})
	if res, err := e.svc.SignPolicy(ctx, opening, "olga", []Approval{adm}); err != nil || res.ApprovalMode != ModeAdmin {
		t.Fatalf("admin approval: %v %+v", err, res)
	}
	entries, _ := e.svc.Audit(ctx, 0, 0)
	if last := entries[len(entries)-1]; last.Detail["approvals_bound"] != "true" || last.Detail["approvals_unverified"] != "false" {
		t.Fatalf("audit %+v", last)
	}
}

func TestPackRequesterTokenBound(t *testing.T) {
	e, p := oidcEnv(t, func(c *Config) { c.PackInterval = 0 })
	ctx := context.Background()
	body := compileBody(t, bodyOpts{version: 7, seq: 1})
	n := bodyNonce(t, body)
	fresh := t0.Add(-time.Minute)
	a1, a2 := appr("alice"), appr("bob")
	a1.IDToken = p.mint(tokenOpts{sub: "sub-alice", iat: fresh, nonce: n})
	a2.IDToken = p.mint(tokenOpts{sub: "sub-bob", iat: fresh, nonce: n})
	if _, err := e.svc.SignPolicy(ctx, body, "olga", []Approval{a1, a2}); err != nil {
		t.Fatal(err)
	}
	files, arc := demoPack(t, nil)
	sum := sha256.Sum256(files["manifest.json"])
	packNonce := approvebind.PackNonce("pk-20261019-0001", hex.EncodeToString(sum[:]))
	pub := appr("pat", RolePublisher)
	pub.IDToken = p.mint(tokenOpts{sub: "sub-pat", iat: fresh, nonce: packNonce})
	if _, err := e.svc.SignPack(ctx, arc, &pub); errCode(err) != "role_unverified" {
		t.Fatalf("publisher not in token: %v", err)
	}
	pub.IDToken = p.mint(tokenOpts{sub: "sub-pat", iat: fresh, nonce: n, groups: []string{"tt-publishers"}})
	if _, err := e.svc.SignPack(ctx, arc, &pub); errCode(err) != "approval_unverifiable" {
		t.Fatalf("token bound to a policy: %v", err)
	}
	pub.IDToken = p.mint(tokenOpts{sub: "sub-pat", iat: fresh, nonce: packNonce, groups: []string{"tt-publishers"}})
	if _, err := e.svc.SignPack(ctx, arc, &pub); err != nil {
		t.Fatalf("bound publisher token: %v", err)
	}
	if _, err := e.svc.SignPack(ctx, arc, &pub); errCode(err) != "approval_unverifiable" {
		t.Fatalf("pack token reused: %v", err)
	}
	// Building (no requester) needs no token.
	if _, err := e.svc.SignPack(ctx, arc, nil); err != nil {
		t.Fatal(err)
	}
}

// RT3-KG-4: in admin mode the fingerprints of every presented token are
// stored, not only the admin's.
func TestAdminModeRecordsEveryToken(t *testing.T) {
	e, p := oidcEnv(t, nil)
	ctx := context.Background()
	body := compileBody(t, bodyOpts{version: 1, seq: 1})
	n := bodyNonce(t, body)
	fresh := t0.Add(-time.Minute)
	pia := appr("pia")
	pia.IDToken = p.mint(tokenOpts{sub: "sub-pia", iat: fresh, nonce: n})
	adm := appr("ada", RoleAdmin)
	adm.Reason = "single maintainer"
	adm.IDToken = p.mint(tokenOpts{sub: "sub-ada", iat: fresh, nonce: n, groups: []string{"tt-admins"}})
	res, err := e.svc.SignPolicy(ctx, body, "olga", []Approval{pia, adm})
	if err != nil || res.ApprovalMode != ModeAdmin {
		t.Fatalf("%v %+v", err, res)
	}
	var fps int
	if err := e.svc.db.QueryRowContext(ctx, `SELECT count(*) FROM kg_token_fps`).Scan(&fps); err != nil || fps != 4 {
		t.Fatalf("fingerprints stored: %d %v", fps, err)
	}
}
