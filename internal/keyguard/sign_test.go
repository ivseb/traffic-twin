package keyguard

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Rule variants of shopRules.
const (
	rulesClosing = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.total":"bucket(num, [0, 100, 250])"}},
   "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}}}}`
	rulesOpening = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"keep","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},
   "GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}}}}`
)

func verifyEnvelope(t *testing.T, e *testEnv, body []byte, res *SignResult) *policy.Verified {
	t.Helper()
	ring := policy.NewKeyRing()
	pk := e.svc.PublicKeys()["policy"][0]
	if err := ring.PinEncoded(pk.Kid, pk.Alg, pk.PublicKey); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(res.Sig)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.DecodeBody(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := policy.Envelope(body, p, res.Kid, sig)
	if err != nil {
		t.Fatal(err)
	}
	v, err := policy.Verify(env, ring)
	if err != nil {
		t.Fatalf("policy.Verify: %v", err)
	}
	return v
}

func TestSignPolicyTwoPersonRule(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	first := compileBody(t, bodyOpts{version: 1, seq: 1})

	// First policy: opening, 2 distinct approvers needed.
	if _, err := e.svc.SignPolicy(ctx, first, "alice", []Approval{appr("alice")}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("proposer alone on an opening change: %v", err)
	}
	if _, err := e.svc.SignPolicy(ctx, first, "alice", []Approval{appr("bob")}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("one approver on an opening change: %v", err)
	}
	if _, err := e.svc.SignPolicy(ctx, first, "alice", []Approval{appr("bob"), appr("bob")}); errCode(err) != "duplicate_approver" {
		t.Fatalf("same user twice: %v", err)
	}
	if _, err := e.svc.SignPolicy(ctx, first, "alice", []Approval{appr("bob"), appr("carol", "operator")}); errCode(err) != "missing_role" {
		t.Fatalf("missing role: %v", err)
	}
	res, err := e.svc.SignPolicy(ctx, first, "alice", []Approval{appr("alice"), appr("bob")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Classification != ClassOpening || res.ApprovalMode != ModeStandard {
		t.Fatalf("result %+v", res)
	}
	v := verifyEnvelope(t, e, first, res)
	if v.Policy.IssuedSeq != 1 {
		t.Fatal("verified body")
	}

	// Closing change: 1 approval is enough, even the proposer's.
	closing := compileBody(t, bodyOpts{version: 2, seq: 2, rules: rulesClosing})
	res, err = e.svc.SignPolicy(ctx, closing, "alice", []Approval{appr("alice")})
	if err != nil {
		t.Fatalf("closing with one approval: %v", err)
	}
	if res.Classification != ClassClosing || res.ApprovalMode != ModeStandard {
		t.Fatalf("closing result %+v", res)
	}
	verifyEnvelope(t, e, closing, res)

	// Opening change after it: refused with 1, accepted with 2.
	opening := compileBody(t, bodyOpts{version: 3, seq: 3, rules: rulesOpening})
	if _, err := e.svc.SignPolicy(ctx, opening, "alice", []Approval{appr("bob")}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("opening with one approval: %v", err)
	}
	if res, err = e.svc.SignPolicy(ctx, opening, "alice", []Approval{appr("bob"), appr("carol")}); err != nil || res.Classification != ClassOpening {
		t.Fatalf("opening with two: %v %+v", err, res)
	}
	types := e.alertTypes()
	if !slices.Contains(types, AlertApprovalRefuse) {
		t.Fatalf("alerts %v", types)
	}
}

func TestSignPolicyGroupCurrentPolicy(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	// p-a (lax) and then p-b (strict) target group shop.
	e.signFirst(bodyOpts{id: "p-a", version: 1, seq: 1, rules: rulesOpening})
	e.signFirst(bodyOpts{id: "p-b", version: 1, seq: 2, rules: rulesClosing})
	// A tweak of p-a that only closes relative to p-a v1 would, with a
	// higher issued_seq, replace p-b on the sources of group shop: it opens.
	pa2 := compileBody(t, bodyOpts{id: "p-a", version: 2, seq: 3, rules: shopRules})
	if _, err := e.svc.SignPolicy(ctx, pa2, "alice", []Approval{appr("alice")}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("group current policy ignored: %v", err)
	}
	// Adding a group opens.
	pb2 := compileBody(t, bodyOpts{id: "p-b", version: 2, seq: 3, rules: rulesClosing, groups: []string{"edge", "shop"}})
	if _, err := e.svc.SignPolicy(ctx, pb2, "alice", []Approval{appr("alice")}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("group added: %v", err)
	}
	// An expired current policy: the group has no policy, the change opens.
	e.clock.Add(31 * 24 * time.Hour)
	pb3 := compileBody(t, bodyOpts{id: "p-b", version: 3, seq: 4, rules: rulesClosing, created: e.clock.Now()})
	if _, err := e.svc.SignPolicy(ctx, pb3, "alice", []Approval{appr("alice")}); errCode(err) != "insufficient_approvals" {
		t.Fatalf("expired current policy: %v", err)
	}
}

func TestSignPolicyApprovalModes(t *testing.T) {
	ctx := context.Background()
	t.Run("single", func(t *testing.T) {
		e := newEnv(t, func(c *Config) { c.OpeningApprove = 1 })
		res, err := e.svc.SignPolicy(ctx, compileBody(t, bodyOpts{version: 1, seq: 1}), "alice", []Approval{appr("alice")})
		if err != nil || res.ApprovalMode != ModeSingle || res.Classification != ClassOpening {
			t.Fatalf("%v %+v", err, res)
		}
		closing := compileBody(t, bodyOpts{version: 2, seq: 2, rules: rulesClosing})
		if res, err = e.svc.SignPolicy(ctx, closing, "alice", []Approval{appr("bob")}); err != nil || res.ApprovalMode != ModeStandard {
			t.Fatalf("%v %+v", err, res)
		}
		st, _ := e.svc.Status(ctx)
		if st.OpeningApprovals != 1 {
			t.Fatal("status")
		}
	})
	t.Run("admin", func(t *testing.T) {
		e := newEnv(t, nil)
		body := compileBody(t, bodyOpts{version: 1, seq: 1})
		admin := Approval{User: "root", Roles: []string{RoleAdmin}, At: t0}
		if _, err := e.svc.SignPolicy(ctx, body, "root", []Approval{admin}); errCode(err) != "admin_reason_required" {
			t.Fatalf("no reason: %v", err)
		}
		admin.Reason = "solo operator, onboarding of the demo shop"
		res, err := e.svc.SignPolicy(ctx, body, "root", []Approval{admin})
		if err != nil || res.ApprovalMode != ModeAdmin || res.Classification != ClassOpening {
			t.Fatalf("%v %+v", err, res)
		}
		if !slices.Contains(e.alertTypes(), AlertAdminApproval) {
			t.Fatalf("alerts %v", e.alertTypes())
		}
		entries, _ := e.svc.Audit(ctx, 0, 0)
		last := entries[len(entries)-1]
		if last.Detail["approval_mode"] != ModeAdmin || !strings.Contains(last.Detail["admin_reason"], "solo_operator") {
			t.Fatalf("audit %+v", last)
		}
		// Standard approvals still give standard mode even with an admin among them.
		next := compileBody(t, bodyOpts{version: 2, seq: 2, rules: rulesOpening})
		if res, err = e.svc.SignPolicy(ctx, next, "alice", []Approval{appr("bob"), appr("carol"), admin}); err != nil || res.ApprovalMode != ModeStandard {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("admin override disabled", func(t *testing.T) {
		e := newEnv(t, func(c *Config) { c.AdminOverride = false })
		admin := Approval{User: "root", Roles: []string{RoleAdmin}, At: t0, Reason: "please"}
		if _, err := e.svc.SignPolicy(ctx, compileBody(t, bodyOpts{version: 1, seq: 1}), "root", []Approval{admin}); errCode(err) != "admin_override_disabled" {
			t.Fatalf("%v", err)
		}
	})
}

func TestSignPolicyBodyChecks(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	two := []Approval{appr("bob"), appr("carol")}
	body := compileBody(t, bodyOpts{version: 1, seq: 1})
	// Not canonical: same JSON with a space.
	if _, err := e.svc.SignPolicy(ctx, append([]byte(" "), body...), "alice", two); errCode(err) != "invalid_body" && errCode(err) != "not_canonical" {
		t.Fatalf("non canonical: %v", err)
	}
	// Unknown HMAC kid.
	if _, err := e.svc.SignPolicy(ctx, compileBody(t, bodyOpts{version: 1, seq: 1, hmac: `{"kid":"k9","epoch":"2026-10"}`}), "alice", two); errCode(err) != "kid_not_held" {
		t.Fatalf("unknown kid: %v", err)
	}
	// Validity above 30 days.
	long := compileBody(t, bodyOpts{version: 1, seq: 1, notAfter: t0.Add(31 * 24 * time.Hour)})
	if _, err := e.svc.SignPolicy(ctx, long, "alice", two); errCode(err) != "invalid_times" {
		t.Fatalf("long validity: %v", err)
	}
	if _, err := e.svc.SignPolicy(ctx, body, "alice", two); err != nil {
		t.Fatal(err)
	}
	// Version must grow per policy_id.
	if _, err := e.svc.SignPolicy(ctx, compileBody(t, bodyOpts{version: 1, seq: 2}), "alice", two); errCode(err) != "version_not_increasing" {
		t.Fatalf("version: %v", err)
	}
}

func TestSignPolicyRevokedHMACKid(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RevokedKids = map[string]bool{"k2": true} })
	body := compileBody(t, bodyOpts{version: 1, seq: 1, hmac: `{"kid":"k1","accept_kids":["k2"],"epoch":"2026-10"}`})
	if _, err := e.svc.SignPolicy(context.Background(), body, "alice", []Approval{appr("bob"), appr("carol")}); errCode(err) != "kid_revoked" {
		t.Fatalf("%v", err)
	}
}

func TestIssuedSeqMonotonicAcrossRestarts(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	two := []Approval{appr("bob"), appr("carol")}
	if _, err := e.svc.SignPolicy(ctx, compileBody(t, bodyOpts{version: 1, seq: 5}), "alice", two); err != nil {
		t.Fatal(err)
	}
	e.restart()
	for _, seq := range []int64{5, 4} {
		body := compileBody(t, bodyOpts{id: "p-other", version: 1, seq: seq})
		if _, err := e.svc.SignPolicy(ctx, body, "alice", two); errCode(err) != "issued_seq_not_increasing" {
			t.Fatalf("seq %d after restart: %v", seq, err)
		}
	}
	if _, err := e.svc.SignPolicy(ctx, compileBody(t, bodyOpts{id: "p-other", version: 1, seq: 6}), "alice", two); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Status(ctx)
	if st.LastIssuedSeq != 6 {
		t.Fatalf("last seq %d", st.LastIssuedSeq)
	}
}

func TestRenewPolicy(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	if _, err := e.svc.RenewPolicy(ctx, compileBody(t, bodyOpts{version: 1, seq: 1})); errCode(err) != "no_signed_policy" {
		t.Fatalf("renew before sign: %v", err)
	}
	e.signFirst(bodyOpts{version: 1, seq: 1})
	e.clock.Add(25 * 24 * time.Hour)
	now := e.clock.Now()
	renewed := compileBody(t, bodyOpts{version: 2, seq: 2, created: now})
	res, err := e.svc.RenewPolicy(ctx, renewed)
	if err != nil {
		t.Fatal(err)
	}
	v := verifyEnvelope(t, e, renewed, res)
	if !v.Policy.NotAfter.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("not_after %v", v.Policy.NotAfter)
	}
	// Any other change needs the approval flow.
	changed := compileBody(t, bodyOpts{version: 3, seq: 3, created: now, rules: rulesClosing})
	if _, err := e.svc.RenewPolicy(ctx, changed); errCode(err) != "fields_differ" {
		t.Fatalf("other field: %v", err)
	}
	groups := compileBody(t, bodyOpts{version: 3, seq: 3, created: now, groups: []string{"edge", "shop"}})
	if _, err := e.svc.RenewPolicy(ctx, groups); errCode(err) != "fields_differ" {
		t.Fatalf("groups: %v", err)
	}
	// Superseded in its group by another policy: no silent comeback.
	e.signFirst(bodyOpts{id: "p-new", version: 1, seq: 3, created: now})
	if _, err := e.svc.RenewPolicy(ctx, compileBody(t, bodyOpts{version: 3, seq: 4, created: now})); errCode(err) != "superseded" {
		t.Fatalf("superseded: %v", err)
	}
	// Expired: renewal refused.
	e.clock.Add(31 * 24 * time.Hour)
	later := e.clock.Now()
	if _, err := e.svc.RenewPolicy(ctx, compileBody(t, bodyOpts{id: "p-new", version: 2, seq: 5, created: later})); errCode(err) != "expired" {
		t.Fatalf("expired: %v", err)
	}
}

func TestClassify(t *testing.T) {
	dec := func(o bodyOpts) *policy.Policy {
		p, err := policy.DecodeBody(compileBody(t, o))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := dec(bodyOpts{version: 1, seq: 1})
	svc := func(ops string) string {
		return `"services":{"shop-api":{"match":{"inbound":true},"ops":{` + ops + `}}}`
	}
	cases := []struct {
		name    string
		o       bodyOpts
		closing bool
	}{
		{"same", bodyOpts{}, true},
		{"keep removed", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.id":"hmac(order)","$.total":"bucket(num, [0, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}`)}, true},
		{"keep to drop", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"drop","$.total":"bucket(num, [0, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}`)}, true},
		{"keep to hmac", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"hmac(st)","$.total":"bucket(num, [0, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}`)}, true},
		{"bounds removed", bodyOpts{rules: rulesClosing}, true},
		{"hmac to keep", bodyOpts{rules: rulesOpening}, false},
		{"bounds added", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 25, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}`)}, false},
		{"hmac removed", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}`)}, false},
		{"new rule", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.id":"hmac(order)","$.email":"drop","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}}`)}, false},
		{"new op", bodyOpts{rules: svc(`"POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep","$.total":"bucket(num, [0, 50, 100, 250])"}},"GET /orders/{id}":{"request":{"path":{"id":"hmac(order)"}}},"GET /orders":{}`)}, false},
		{"epoch", bodyOpts{hmac: `{"kid":"k1","epoch":"2026-11"}`}, false},
		{"accept kid added", bodyOpts{hmac: `{"kid":"k1","accept_kids":["k2"],"epoch":"2026-10"}`}, false},
		{"group added", bodyOpts{groups: []string{"edge", "shop"}}, false},
	}
	for _, c := range cases {
		o := c.o
		o.version, o.seq = 2, 2
		ok, reason := classify(base, dec(o), true)
		if ok != c.closing {
			t.Errorf("%s: closing=%v (%s), want %v", c.name, ok, reason, c.closing)
		}
	}
	// Reverse directions.
	if ok, _ := classify(dec(bodyOpts{version: 1, seq: 1, hmac: `{"kid":"k1","accept_kids":["k2"],"epoch":"2026-10"}`}), base, true); !ok {
		t.Error("accept kid removed must close")
	}
	if ok, _ := classify(dec(bodyOpts{version: 1, seq: 1, groups: []string{"edge", "shop"}}), base, true); !ok {
		t.Error("group removed must close")
	}
}

func TestKeyFilePermissionsAndFormats(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	if err := os.WriteFile(p, []byte("k1:"+b64(k1Secret())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o644)
	if _, err := LoadHMACKeys(KeySource{File: p}); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("0644 accepted: %v", err)
	}
	_ = os.Chmod(p, 0o640)
	if _, err := LoadHMACKeys(KeySource{File: p}); err == nil {
		t.Fatal("0640 accepted")
	}
	_ = os.Chmod(p, 0o400)
	ks, err := LoadHMACKeys(KeySource{File: p})
	if err != nil || !ks.Has("k1") {
		t.Fatalf("0400: %v", err)
	}
	// The error and the String form never contain key material.
	if strings.Contains(ks.String(), b64(k1Secret())) {
		t.Fatal("String leaks")
	}
	bad := []string{
		"k1:" + b64(randSecret(16)),                             // short
		"k1:" + b64(k1Secret()) + "\nk1:" + b64(randSecret(32)), // duplicate kid
		"K1:" + b64(k1Secret()),                                 // kid grammar
		"k1:" + b64(k1Secret()) + "=",                           // padding
		"k1: " + b64(k1Secret()),                                // space
		"",
	}
	for i, s := range bad {
		if _, err := ParseHMACKeys([]byte(s)); err == nil {
			t.Errorf("bad hmac config %d accepted", i)
		} else if strings.Contains(err.Error(), b64(k1Secret())) {
			t.Errorf("error leaks key material")
		}
	}
	// Signing keys: seed size, revocation of the active key, retired keys.
	seed1, seed2 := randSecret(32), randSecret(32)
	sk, err := ParseSigningKeys([]byte("new:"+b64(seed1)+"\nold:"+b64(seed2)+"\n"), nil)
	if err != nil || sk.Kid() != "new" || len(sk.Public()) != 2 {
		t.Fatalf("rotation: %v", err)
	}
	if _, err := ParseSigningKeys([]byte("new:"+b64(seed1)+"\nold:"+b64(seed2)), map[string]bool{"new": true}); err == nil {
		t.Fatal("revoked active signer accepted")
	}
	sk, _ = ParseSigningKeys([]byte("new:"+b64(seed1)+"\nold:"+b64(seed2)), map[string]bool{"old": true})
	if len(sk.Public()) != 1 || sk.Public()[0].EndorsedBy != "" {
		t.Fatal("revoked retired key still announced")
	}
	// Endorsements (RT3-KEY-1): each announced key is endorsed by the next
	// older announced one; a revoked middle key is skipped.
	seed3 := randSecret(32)
	pubOf := func(seed []byte) ed25519.PublicKey { return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey) }
	sk, err = ParseSigningKeys([]byte("k3:"+b64(seed3)+"\nk2:"+b64(seed2)+"\nk1:"+b64(seed1)), nil)
	if err != nil {
		t.Fatal(err)
	}
	ring := policy.NewKeyRing()
	_ = ring.Pin("k1", pubOf(seed1))
	pk := sk.Public()
	if pk[2].EndorsedBy != "" || pk[1].EndorsedBy != "k1" || pk[0].EndorsedBy != "k2" {
		t.Fatalf("endorsement chain: %+v", pk)
	}
	for _, i := range []int{1, 0} {
		if err := ring.PinEndorsed(pk[i].Kid, pk[i].Alg, pk[i].PublicKey, pk[i].EndorsedBy, pk[i].Endorsement); err != nil {
			t.Fatalf("endorsement of %s: %v", pk[i].Kid, err)
		}
	}
	sk, _ = ParseSigningKeys([]byte("k3:"+b64(seed3)+"\nk2:"+b64(seed2)+"\nk1:"+b64(seed1)), map[string]bool{"k2": true})
	if pk = sk.Public(); len(pk) != 2 || pk[0].EndorsedBy != "k1" {
		t.Fatalf("endorsement over a revoked key: %+v", pk)
	}
	if _, err := ParseSigningKeys([]byte("k3:"+b64(seed3)+"\nk3:"+b64(seed2)), nil); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if _, err := ParseSigningKeys([]byte("s:"+b64(randSecret(31))), nil); err == nil {
		t.Fatal("short seed accepted")
	}
	// The service refuses to start with a permissive key file.
	e := newEnv(t, nil)
	_ = e.svc.Close()
	_ = os.Chmod(e.cfg.PolicyKey.File, 0o604)
	if _, err := New(context.Background(), e.cfg, Options{}); err == nil {
		t.Fatal("service started with a world-readable signing key")
	}
	e.svc = nil
	// Zeroing.
	sk, _ = ParseSigningKeys([]byte("z:"+b64(seed1)), nil)
	sk.Zero()
	if !slices.Equal([]byte(sk.priv), make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("private key not zeroed")
	}
}

func TestPublicKeysNeverPrivate(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := json.Marshal(e.svc.PublicKeys())
	s := string(b)
	if strings.Contains(s, b64(e.policySeed)) || strings.Contains(s, b64(e.packSeed)) {
		t.Fatal("seed in public keys")
	}
	if !strings.Contains(s, b64(e.policyPub())) || !strings.Contains(s, b64(e.packPub())) {
		t.Fatalf("public keys %s", s)
	}
}
