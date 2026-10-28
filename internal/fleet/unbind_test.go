package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// RT3-FLEET-1: unbinding a group stops its sources at once (no policy
// served, min_issued_seq beyond the old policy), drafts a closing version
// without the group while others are bound, and a policy nobody is bound
// to any more is not renewed.
func TestUnbindStopsGroup(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.setup()
	act := e.activateV1()
	nt := e.newToken(TokenGroup, "sdk-node")
	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	if r, _ := s.do("GET", PathPolicy, nil, nil); r.code != 200 {
		t.Fatalf("policy before unbind: %d", r.code)
	}

	// A second group joins the policy (approved), so the policy outlives the unbind.
	var g Group
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{
		"name": "shop-eu", "policy_id": "p-shop", "allowed_service_names": []string{"shop-api"},
	}), 201).json(t, &g)
	join := PolicyVersion{PolicyID: "p-shop", Version: g.PolicyDraft.Version}
	e.must(e.approve("bob", join, nil), 200)
	e.must(e.approve("carol", join, nil), 200)

	var shop Group
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop", nil), 200).json(t, &shop)
	shop.PolicyID = nil
	var out Group
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop", shop), 200).json(t, &out)
	if out.PolicyDraft == nil {
		t.Fatal("no closing draft after the unbind")
	}
	d, _ := e.fleet.GetPolicyVersion(ctx, "p-shop", out.PolicyDraft.Version)
	if d.Origin != OriginRetarget || d.Classification != Closing || len(d.Targets.Groups) != 1 || d.Targets.Groups[0] != "shop-eu" {
		t.Fatalf("unbind draft: %+v", d)
	}
	if r, _ := s.do("GET", PathPolicy, nil, nil); r.code != 404 {
		t.Fatalf("an unbound group is still served a policy: %d", r.code)
	}
	hb, _ := s.heartbeat("capturing", 10)
	if hb.PolicyCurrent != nil || hb.MinIssuedSeq <= *act.IssuedSeq {
		t.Fatalf("heartbeat of an unbound group: %+v", hb)
	}

	// Unbinding the last group: no draft is possible, and nothing renews the policy.
	var eu Group
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/shop-eu", nil), 200).json(t, &eu)
	eu.PolicyID = nil
	var out2 Group
	e.must(e.as("olivia", "PUT", "/api/v1/fleet/groups/shop-eu", eu), 200).json(t, &out2)
	if out2.PolicyDraft != nil {
		t.Fatalf("draft for a policy without groups: %+v", out2.PolicyDraft)
	}
	before := e.signer.renews
	e.clk.Add(policy.DefaultValidity - 3*24*time.Hour)
	e.fleet.Maintain(ctx)
	if e.signer.renews != before {
		t.Fatal("a policy with no bound group was renewed")
	}
}
