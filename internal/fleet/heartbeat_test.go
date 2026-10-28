package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/policy"
)

func TestHeartbeatSemantics(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenGroup, "sdk-node")
	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	s2 := e.enrollSource(nt.Token, "sdk-node", "shop-api")

	// Before any policy: no policy, min 0, no kill, no 404 confusion.
	hb, r := s.heartbeat("starting", 0)
	if r.code != 200 || hb.Kill || hb.MinIssuedSeq != 0 || hb.PolicyCurrent != nil || hb.SamplingOverrideBP != nil || hb.RenewBefore == nil {
		t.Fatalf("first heartbeat: %d %+v", r.code, hb)
	}
	if hb.NextHeartbeatS != 30 || hb.RevokeSigningKeys == nil || hb.AddSigningKeys == nil {
		t.Fatalf("defaults: %+v", hb)
	}
	if r, _ := s.do("GET", PathPolicy, nil, nil); r.code != 404 {
		t.Fatalf("no policy: %d", r.code)
	}
	// A heartbeat naming another source is refused.
	z := 0
	if r, _ := s.do("POST", PathHeartbeat, map[string]any{"source_id": s2.id, "state": "starting", "counters": map[string]any{
		"exchanges_seen": z, "exchanges_sampled": z, "events_sent": z, "events_dropped_queue": z, "events_rejected": z, "send_errors": z, "sanitizer_errors": z}}, nil); r.code != 403 {
		t.Fatalf("mismatch: %d", r.code)
	}
	if r, _ := s.do("POST", PathHeartbeat, map[string]any{"source_id": s.id, "state": "dancing", "counters": map[string]any{}}, nil); r.code != 422 {
		t.Fatalf("bad state: %d", r.code)
	}

	act := e.activateV1()
	hb, _ = s.heartbeat("capturing", 100)
	if hb.MinIssuedSeq != *act.IssuedSeq || hb.PolicyCurrent == nil || hb.PolicyCurrent.Hash != act.Hash || hb.PolicyCurrent.Version != act.Version {
		t.Fatalf("policy in heartbeat: %+v", hb)
	}

	// Sampling override only lowers: the policy rate is 500 bp.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/sources/"+s.id+"/sampling", map[string]any{"sampling_override_bp": 9000}), 204)
	if hb, _ = s.heartbeat("capturing", 100); hb.SamplingOverrideBP != nil {
		t.Fatalf("override above the policy rate must not be sent: %v", *hb.SamplingOverrideBP)
	}
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/sources/"+s.id+"/sampling", map[string]any{"sampling_override_bp": 100}), 204)
	if hb, _ = s.heartbeat("capturing", 100); hb.SamplingOverrideBP == nil || *hb.SamplingOverrideBP != 100 {
		t.Fatalf("override: %+v", hb.SamplingOverrideBP)
	}
	// The group override applies when lower.
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop", map[string]any{"name": "shop", "policy_id": "p-shop", "allowed_service_names": []string{"shop-api"}, "sampling_override_bp": 20}), 200)
	if hb, _ = s.heartbeat("capturing", 100); *hb.SamplingOverrideBP != 20 {
		t.Fatalf("group override: %v", *hb.SamplingOverrideBP)
	}
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/sources/"+s.id+"/sampling", map[string]any{"sampling_override_bp": nil}), 204)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/sources/"+s.id+"/sampling", map[string]any{}), 422)
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/sources/"+s.id+"/sampling", map[string]any{"sampling_override_bp": 10001}), 422)

	// Kill switch per source, persisted across a restart, and in the intake view.
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"source_id": s.id}}), 204)
	if hb, _ = s.heartbeat("capturing", 100); !hb.Kill {
		t.Fatal("kill not delivered")
	}
	if hb2, _ := s2.heartbeat("capturing", 0); hb2.Kill {
		t.Fatal("kill leaked to another source")
	}
	if v, _ := e.fleet.IntakeSources().LookupSource(s.id); !v.Revoked {
		t.Fatal("intake must reject a killed source")
	}
	f2, err := New(context.Background(), e.fleet.opts)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := f2.Source(s.id); !v.Killed {
		t.Fatal("kill switch not persisted")
	}
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": false, "scope": map[string]any{"source_id": s.id}}), 204)
	// Global kill.
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"all": true}}), 204)
	if hb2, _ := s2.heartbeat("capturing", 0); !hb2.Kill {
		t.Fatal("global kill not delivered")
	}
	f3, _ := New(context.Background(), e.fleet.opts)
	if v, _ := f3.Source(s2.id); !v.Killed {
		t.Fatal("global kill not persisted")
	}
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": false, "scope": map[string]any{"all": true}}), 204)
	// Group kill and invalid scopes.
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"group": "shop"}}), 204)
	if hb2, _ := s2.heartbeat("capturing", 0); !hb2.Kill {
		t.Fatal("group kill not delivered")
	}
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"group": "shop", "all": true}}), 422)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/kill", map[string]any{"active": true, "scope": map[string]any{"group": "nope"}}), 404)
	if !containsStr(e.alerts.list, "fleet.kill") {
		t.Fatal("kill not alerted")
	}

	// Health in the source list.
	var ss []SourceStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources?group=shop", nil), 200).json(t, &ss)
	if len(ss) != 2 {
		t.Fatalf("sources: %d", len(ss))
	}
	var one SourceStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/sources/"+s.id, nil), 200).json(t, &one)
	if one.State != "capturing" || !one.Killed || one.OverheadUS == nil || *one.OverheadUS.P50 != 1100 ||
		one.SanitizerErrors != 1 || one.LastSeen == nil || one.Kind != "sdk-node" {
		t.Fatalf("source status: %+v", one)
	}

	// Signing key rotation (endorsed by the pinned key) and revocation
	// reach sources through the heartbeat.
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	e.signer.extra = []SigningKey{{Kid: "policy-2026-2", PublicKey: newPub,
		EndorsedBy: e.signer.kid, Endorsement: policy.Endorse(e.signer.priv, "policy-2026-2", newPub)}}
	e.fleet.Maintain(context.Background())
	sys := audit.Actor{Kind: audit.ActorSystem, ID: "test"}
	// RT3-KEY-1: the old key cannot be revoked until every source seen in
	// the last 24 h confirmed the new one through its heartbeat.
	if err := e.fleet.RevokeSigningKey(context.Background(), "policy-2026-1", sys); err == nil || !strings.Contains(err.Error(), "rotation_unconfirmed") {
		t.Fatalf("revocation before confirmation: %v", err)
	}
	s.kids, s2.kids = []string{"policy-2026-1", "policy-2026-2"}, []string{"policy-2026-1", "policy-2026-2"}
	s.heartbeat("capturing", 0)
	if err := e.fleet.RevokeSigningKey(context.Background(), "policy-2026-1", sys); err == nil || !strings.Contains(err.Error(), "rotation_unconfirmed") {
		t.Fatalf("revocation with 1 of 2 confirmations: %v", err)
	}
	s2.heartbeat("capturing", 0)
	// RT3-KEY-2: never the kid keyguard signs with.
	e.signer.mu.Lock()
	e.signer.status.PolicyKid = "policy-2026-1"
	e.signer.mu.Unlock()
	if err := e.fleet.RevokeSigningKey(context.Background(), "policy-2026-1", sys); err == nil || !strings.Contains(err.Error(), "active_signing_key") {
		t.Fatalf("revocation of the active kid: %v", err)
	}
	e.signer.mu.Lock()
	e.signer.status.PolicyKid = "policy-2026-2"
	e.signer.mu.Unlock()
	var ks []SigningKeyInfo
	e.must(e.as("olivia", "GET", "/api/v1/fleet/signing-keys", nil), 200).json(t, &ks)
	if len(ks) != 2 || ks[0].Revoke == nil || !ks[0].Revoke.OK || ks[0].Revoke.Confirmed != 2 || ks[0].TrustedBy != 2 ||
		!ks[1].Active || ks[1].Revoke.Blocker != "active_signing_key" || ks[1].EndorsedBy != "policy-2026-1" {
		t.Fatalf("signing key status: %+v", ks)
	}
	if err := e.fleet.RevokeSigningKey(context.Background(), "policy-2026-1", sys); err != nil {
		t.Fatal(err)
	}
	hb, _ = s2.heartbeat("capturing", 0)
	if len(hb.AddSigningKeys) != 1 || hb.AddSigningKeys[0].Kid != "policy-2026-2" || len(hb.RevokeSigningKeys) != 1 || hb.RevokeSigningKeys[0] != "policy-2026-1" {
		t.Fatalf("key rotation: %+v", hb)
	}
	ring := policy.NewKeyRing()
	_ = ring.PinEncoded(s2.enr.PolicySigningKeys[0].Kid, "Ed25519", s2.enr.PolicySigningKeys[0].PublicKey)
	k := hb.AddSigningKeys[0]
	if err := ring.PinEndorsed(k.Kid, k.Alg, k.PublicKey, k.EndorsedBy, k.Endorsement); err != nil {
		t.Fatalf("endorsement does not verify on the source: %v", err)
	}
}

func TestOnboardingStatus(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenGroup, "sdk-node")
	var st OnboardingStatus
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/"+nt.TokenID+"/status", nil), 200).json(t, &st)
	if st.Steps.Enrolled || st.Steps.PolicyReceived || st.Steps.FirstEvents != 0 {
		t.Fatalf("initial: %+v", st)
	}
	// A failed enrollment shows up as a problem with a hint.
	_, _ = e.enroll(nt.Token, map[string]any{"source": srcInfo("sdk-node", "billing")})
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/"+nt.TokenID+"/status", nil), 200).json(t, &st)
	if len(st.Problems) != 1 || st.Problems[0].Code != "service_not_allowed" || st.Problems[0].Hint == "" {
		t.Fatalf("problem: %+v", st.Problems)
	}
	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	s.heartbeat("no_policy", 0)
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/"+nt.TokenID+"/status", nil), 200).json(t, &st)
	if !st.Steps.Enrolled || st.Steps.PolicyReceived || len(st.Problems) != 1 || st.Problems[0].Code != "no_policy" {
		t.Fatalf("enrolled: %+v", st)
	}
	act := e.activateV1()
	z := int64(0)
	sent := int64(20)
	r, _ := s.do("POST", PathHeartbeat, map[string]any{"source_id": s.id, "state": "capturing",
		"policy": map[string]any{"id": "p-shop", "version": act.Version, "issued_seq": *act.IssuedSeq, "hash": act.Hash},
		"counters": map[string]any{"exchanges_seen": sent, "exchanges_sampled": sent, "events_sent": sent, "events_dropped_queue": z,
			"events_rejected": z, "send_errors": z, "sanitizer_errors": z}}, nil)
	e.must(r, 200)
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/"+nt.TokenID+"/status", nil), 200).json(t, &st)
	if !st.Steps.PolicyReceived || st.Steps.FirstEvents != 20 || len(st.Problems) != 0 {
		t.Fatalf("running: %+v", st)
	}
	e.fleet.SetEventCounter(countFn(func(string) uint64 { return 7 }))
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/"+nt.TokenID+"/status", nil), 200).json(t, &st)
	if st.Steps.FirstEvents != 7 {
		t.Fatalf("intake counter not used: %+v", st)
	}
	e.must(e.as("olivia", "GET", "/api/v1/fleet/onboarding/tok-nothere/status", nil), 404)
}

type countFn func(string) uint64

func (c countFn) AcceptedEvents(id string) uint64 { return c(id) }
