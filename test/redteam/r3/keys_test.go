package r3_rt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/core"
	"github.com/ivseb/traffic-twin/internal/policy"
)

const newKid = "policy-rt3-2"

// rotate puts a new policy signing key first in keyguard's key file (the
// old one stays as a retired, announced key: keyguard.md 1 and 6).
func (e *coreEnv) rotate() {
	e.restartKG(func(keys string) {
		p := filepath.Join(keys, "policy.key")
		old, err := os.ReadFile(p)
		if err != nil {
			e.t.Fatal(err)
		}
		writeFile(e.t, p, newKid+":"+b64(rnd(32))+"\n"+string(old))
	}, nil)
}

// plainAuthor is a minimal policy without discovery window (renewable).
func plainAuthor(pid string, rate string) string {
	return `{"format":"tt.policy/v1","policy_id":"` + pid + `","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},"sampling":{"rate":` + rate + `}}`
}

func (e *coreEnv) signingKeys(t *testing.T) []map[string]any {
	var ks []map[string]any
	e.u(t, "ada").json(200, "GET", "/api/v1/fleet/signing-keys", nil, &ks)
	return ks
}

// waitRevocable waits until the admin API reports that the revocation of
// kid would be accepted (every recently seen source confirmed the new key
// through its heartbeat: RT3-KEY-1 fix).
func (e *coreEnv) waitRevocable(t *testing.T, kid string) {
	t.Helper()
	eventually(t, 5*time.Second, kid+" revocable", func() bool {
		for _, k := range e.signingKeys(t) {
			if r, ok := k["revoke"].(map[string]any); ok && k["kid"] == kid && r["ok"] == true {
				return true
			}
		}
		return false
	})
}

// RT3-KEY-1 (end to end): rotate the policy signing key in keyguard, sign a
// new version. Before the fix tt-core learned the new kid without any
// endorsement, so the heartbeat never carried add_signing_keys and the
// already enrolled source refused every policy signed with the new key.
// Fixed: keyguard endorses the new key with the retired one.
func TestRT3_Key_RotationReachesEnrolledSource_Fixed(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}})
	src := e.source(e.group("demo", "p-demo"), "rot-1")
	cp, _ := src.Active()
	if cp.Policy.SignerKid != core.DevPolicyKid {
		t.Fatalf("signer kid = %s", cp.Policy.SignerKid)
	}
	e.rotate()
	v := e.propose(plainAuthor("p-demo", "0.5"))
	b := e.adminApprove(v.PolicyID, v.Version)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if got["status"] != "active" {
		t.Fatalf("new version not active: %s", b)
	}
	ks := e.signingKeys(t)
	endorsed := false
	for _, k := range ks {
		if k["kid"] == newKid && k["endorsed_by"] == core.DevPolicyKid {
			endorsed = true
		}
	}
	// Let the source poll for a while.
	deadline := time.Now().Add(3 * time.Second)
	accepted := false
	for time.Now().Before(deadline) {
		if cp, ok := src.Active(); ok && cp.Policy.Policy.Version == v.Version {
			accepted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !endorsed || !accepted {
		ksj, _ := json.Marshal(ks)
		t.Fatalf("FINDING RT3-KEY-1: after rotation the new key is not endorsed (signing-keys %s) and the enrolled source accepted v%d: %v (state %s)",
			ksj, v.Version, accepted, src.State())
	}
}

// RT3-KEY-1 impact: revoking the old key after the rotation was allowed
// (another key existed in tt-core) and turned every enrolled source off.
// Fixed: the source learns the endorsed new key, and tt-core accepts the
// revocation only once the source confirmed it.
func TestRT3_Key_RevokeAfterRotationStopsEnrolledSource_Fixed(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}})
	src := e.source(e.group("demo", "p-demo"), "rot-2")
	e.rotate()
	v := e.propose(plainAuthor("p-demo", "0.5"))
	e.adminApprove(v.PolicyID, v.Version)
	e.waitRevocable(t, core.DevPolicyKid)
	e.u(t, "ada").must(204, "POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil)
	time.Sleep(1500 * time.Millisecond)
	if _, ok := src.Active(); !ok {
		t.Fatalf("FINDING RT3-KEY-1 (impact): after a rotation and the revocation of the old key the enrolled source stopped capturing for good (state %s); only re-enrolment recovers it", src.State())
	}
}

// RT3-KEY-2: tt-core let an admin revoke the kid keyguard is signing with
// (it only checked that another non-revoked kid was known); every later
// signature was then unverifiable. Fixed: 409 active_signing_key.
func TestRT3_Key_RevokeKeyguardActiveKid_Fixed(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}})
	e.source(e.group("demo", "p-demo"), "rot-3")
	e.rotate()
	v := e.propose(plainAuthor("p-demo", "0.5"))
	e.adminApprove(v.PolicyID, v.Version)
	code, b := e.u(t, "ada").req("POST", "/api/v1/fleet/signing-keys/"+newKid+"/revoke", nil)
	if code == 409 && errCodeOf(b) != "active_signing_key" {
		t.Fatalf("refused for another reason: %s", b)
	}
	if code/100 == 2 {
		v2 := e.propose(plainAuthor("p-demo", "0.25"))
		c2, b2 := e.u(t, "ada").req("POST", fmt.Sprintf("/api/v1/fleet/policies/p-demo/versions/%d/approve", v2.Version), map[string]any{"reason": "rt3"})
		t.Fatalf("FINDING RT3-KEY-2: revoking keyguard's ACTIVE kid was accepted (%d %s); the next approval answers %d %.200s", code, b, c2, b2)
	}
}

// Guards on revocation through the admin API.
func TestRT3_Key_Holds_RevocationGuards(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}, "audrey": {"auditor"}}})
	src := e.source(e.group("demo", "p-demo"), "rev-1")
	ada := e.u(t, "ada")
	// The only key cannot be revoked.
	if code, b := ada.req("POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil); code != 409 || errCodeOf(b) != "last_signing_key" {
		t.Fatalf("revoke last key: %d %s", code, b)
	}
	// Only admins; unknown kid is 404; CSRF required.
	if code, _ := e.u(t, "olga").req("POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil); code != 403 {
		t.Fatalf("operator revoke: %d", code)
	}
	if code, _ := ada.req("POST", "/api/v1/fleet/signing-keys/no-such-kid/revoke", nil); code != 404 {
		t.Fatalf("unknown kid: %d", code)
	}
	noCSRF := *ada
	noCSRF.csrf = ""
	if code, _ := noCSRF.req("POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil); code != 403 {
		t.Fatalf("revoke without CSRF: %d", code)
	}
	// After a rotation, a source enrolled AFTERWARDS pins both keys; once
	// the old key is revoked it keeps capturing with the new one and a
	// policy signed with the revoked key no longer verifies.
	oldEnv, _ := src.Active()
	e.rotate()
	v := e.propose(plainAuthor("p-demo", "0.5"))
	e.adminApprove(v.PolicyID, v.Version)
	var tok struct {
		Token string `json:"token"`
	}
	e.u(t, "olga").json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "demo", "token_type": "one_time"}, &tok)
	src2 := e.source(tok.Token, "rev-2")
	e.waitRevocable(t, core.DevPolicyKid)
	ada.must(204, "POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil)
	if code, b := ada.req("POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil); code != 409 || errCodeOf(b) != "already_revoked" {
		t.Fatalf("revoke twice: %d %s", code, b)
	}
	time.Sleep(500 * time.Millisecond)
	cp2, ok := src2.Active()
	if !ok || cp2.Policy.SignerKid != newKid {
		t.Fatalf("source enrolled after rotation: capturing=%v state=%s", ok, src2.State())
	}
	ring := policy.NewKeyRing()
	for _, k := range e.signingKeys(t) {
		if k["revoked"] == true {
			ring.Revoke(fmt.Sprint(k["kid"]))
			continue
		}
		if err := ring.PinEncoded(fmt.Sprint(k["kid"]), "Ed25519", fmt.Sprint(k["public_key"])); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := policy.Verify(oldEnv.Policy.Envelope, ring); err == nil {
		t.Fatal("an envelope signed with the revoked key still verifies")
	}
	// A revoked kid is never re-pinned, not even endorsed by a valid key.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r2 := policy.NewKeyRing()
	_ = r2.Pin("good", pub)
	r2.Revoke("old")
	op, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := r2.PinEndorsed("old", "Ed25519", b64(op), "good", policy.Endorse(priv, "old", op)); err == nil {
		t.Fatal("revoked kid re-pinned through an endorsement")
	}
	// A forged endorsement (signed by a key that is not pinned) is refused,
	// as is one by a revoked key.
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	np, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := r2.PinEndorsed("new", "Ed25519", b64(np), "good", policy.Endorse(evil, "new", np)); err == nil {
		t.Fatal("forged endorsement accepted")
	}
	if err := r2.PinEndorsed("new", "Ed25519", b64(np), "old", policy.Endorse(priv, "new", np)); err == nil {
		t.Fatal("endorsement by a revoked kid accepted")
	}
	// Endorsement over another kid name is refused (kid is bound).
	if err := r2.PinEndorsed("new2", "Ed25519", b64(np), "good", policy.Endorse(priv, "new", np)); err == nil {
		t.Fatal("endorsement for another kid accepted")
	}
}

// RT3-KEY-1 guard: a source seen in the last 24 h that never confirmed the
// new key (stopped before the rotation) blocks the revocation of the old
// key; once it is older than the window, or with min_confirmed 0, the
// revocation is accepted. The admin API shows the counts.
func TestRT3_Key_Holds_UnconfirmedSourceBlocksRevocation(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}})
	tok := e.group("demo", "p-demo")
	live := e.source(tok, "live-1")
	var t2 struct {
		Token string `json:"token"`
	}
	e.u(t, "olga").json(201, "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-go", "group": "demo", "token_type": "one_time"}, &t2)
	gone := e.source(t2.Token, "gone-1")
	_ = gone.Close(context.Background())
	e.rotate()
	v := e.propose(plainAuthor("p-demo", "0.5"))
	e.adminApprove(v.PolicyID, v.Version)
	eventually(t, 5*time.Second, "live source on the rotated key", func() bool {
		cp, ok := live.Active()
		return ok && cp.Policy.SignerKid == newKid
	})
	var ready map[string]any
	eventually(t, 5*time.Second, "live source confirmed", func() bool {
		for _, k := range e.signingKeys(t) {
			if k["kid"] == core.DevPolicyKid {
				ready, _ = k["revoke"].(map[string]any)
			}
		}
		return ready != nil && ready["confirmed_sources"] == float64(1)
	})
	if ready["seen_sources"] != float64(2) || ready["ok"] != false || ready["blocker"] != "rotation_unconfirmed" {
		t.Fatalf("revoke readiness: %v", ready)
	}
	ada := e.u(t, "ada")
	if code, b := ada.req("POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil); code != 409 || errCodeOf(b) != "rotation_unconfirmed" {
		t.Fatalf("revocation with an unconfirmed source: %d %s", code, b)
	}
	// 25 hours later the stopped source is out of the window (the live one
	// keeps heartbeating).
	e.clock.Advance(25 * time.Hour)
	e.relogin()
	ada = e.u(t, "ada")
	e.waitRevocable(t, core.DevPolicyKid)
	ada.must(204, "POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil)
	time.Sleep(300 * time.Millisecond)
	if cp, ok := live.Active(); !ok || cp.Policy.SignerKid != newKid {
		t.Fatalf("live source after the revocation: %s", live.State())
	}
}

// RT3-KEY-1 guard: a rotation with no new policy version. The active policy
// is still signed by the old key, so its sources do not count as confirmed;
// tt-core's maintenance re-signs it with keyguard's active key, the source
// moves to it, and only then the old key becomes revocable.
func TestRT3_Key_Holds_RotationWithoutNewVersion(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}})
	src := e.source(e.group("demo", "p-demo"), "resign-1")
	v := e.propose(plainAuthor("p-demo", "0.5")) // renewable (no discovery window)
	e.adminApprove(v.PolicyID, v.Version)
	eventually(t, 5*time.Second, "source on the plain policy", func() bool {
		cp, ok := src.Active()
		return ok && cp.Policy.Policy.Version == v.Version
	})
	e.rotate()
	e.core.Fleet().Maintain(e.ctx) // learns the new key: add_signing_keys
	eventually(t, 5*time.Second, "source trusts the new key", func() bool {
		for _, k := range e.signingKeys(t) {
			if k["kid"] == newKid && k["trusted_by"] == float64(1) {
				return true
			}
		}
		return false
	})
	// Maintenance re-signs the active policy with the new key.
	e.core.Fleet().Maintain(e.ctx)
	eventually(t, 5*time.Second, "source on the re-signed policy", func() bool {
		cp, ok := src.Active()
		return ok && cp.Policy.SignerKid == newKid
	})
	e.waitRevocable(t, core.DevPolicyKid)
	e.u(t, "ada").must(204, "POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil)
	time.Sleep(300 * time.Millisecond)
	if cp, ok := src.Active(); !ok || cp.Policy.SignerKid != newKid {
		t.Fatalf("source after the revocation: %s", src.State())
	}
}

// With fleet.key_rotation.min_confirmed 0 (emergency revocation of a
// compromised key) the confirmation is not required, but the active kid
// stays protected.
func TestRT3_Key_Holds_EmergencyRevocation(t *testing.T) {
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}, cfg: func(c *config.Config) { c.Fleet.KeyRotation.MinConfirmed = 0 }})
	src := e.source(e.group("demo", "p-demo"), "emg-1")
	_ = src.Close(context.Background())
	e.rotate()
	v := e.propose(plainAuthor("p-demo", "0.5"))
	e.adminApprove(v.PolicyID, v.Version)
	ada := e.u(t, "ada")
	if code, b := ada.req("POST", "/api/v1/fleet/signing-keys/"+newKid+"/revoke", nil); code != 409 || errCodeOf(b) != "active_signing_key" {
		t.Fatalf("active kid: %d %s", code, b)
	}
	ada.must(204, "POST", "/api/v1/fleet/signing-keys/"+core.DevPolicyKid+"/revoke", nil)
}

// RT3-FLEET-1: unbinding a group from its policy (PUT group with
// policy_id null) leaves the old policy active for that group: the source
// keeps capturing, and tt-core keeps renewing the orphaned policy, so the
// capture never ends by itself.
func TestRT3_Fleet_UnboundGroupKeepsCapturing_Fixed(t *testing.T) {
	// Long certificates and policy_max_age: the test isolates policy validity.
	e := newCoreEnv(t, envOpts{team: map[string][]string{"olga": {"operator"}}, cfg: func(c *config.Config) {
		c.Fleet.ClientCertTTL, c.Fleet.PolicyMaxAge = 90*24*time.Hour, 30*24*time.Hour
	}})
	src := e.source(e.group("ga", "p-ga"), "unbind-1")
	// A plain policy (no discovery window, so tt-core can renew it).
	v := e.propose(plainAuthor("p-ga", "0.5"))
	e.adminApprove(v.PolicyID, v.Version)
	eventually(t, 5*time.Second, "source on the plain policy", func() bool {
		cp, ok := src.Active()
		return ok && cp.Policy.Policy.Version == v.Version
	})
	olga := e.u(t, "olga")
	var g map[string]any
	olga.json(200, "GET", "/api/v1/fleet/groups/ga", nil, &g)
	g["policy_id"] = nil
	olga.must(200, "PUT", "/api/v1/fleet/groups/ga", g)
	// 40 days later, with tt-core's maintenance (renewals) running daily.
	for d := range 40 {
		e.clock.Advance(24 * time.Hour)
		e.kgClock.Advance(24 * time.Hour)
		e.core.Fleet().Maintain(e.ctx)
		time.Sleep(300 * time.Millisecond)
		if _, ok := src.Active(); !ok {
			t.Logf("day %d: source state %s", d+1, src.State())
		}
	}
	e.users["olga"] = e.login("olga") // the session of 40 days ago has expired (tt-core runs on the virtual clock)
	var pol []map[string]any
	e.u(t, "olga").json(200, "GET", "/api/v1/fleet/policies", nil, &pol)
	pj, _ := json.Marshal(pol)
	t.Logf("policies: %.1500s", pj)
	if cp, ok := src.Active(); ok {
		t.Fatalf("FINDING RT3-FLEET-1: 40 days after unbinding group ga from p-ga its source still captures under p-ga v%d (renewed, not_after %s)",
			cp.Policy.Policy.Version, cp.Policy.Policy.NotAfter)
	}
}
