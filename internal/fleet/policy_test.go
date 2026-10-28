package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

func TestPolicyLifecycleTwoPersonRule(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("bob", auth.RolePolicyApprover)
	e.user("carol", auth.RolePolicyApprover)
	e.user("pat", auth.RolePolicyApprover, auth.RoleOperator)

	// Invalid policies are rejected with 422; no target group → 409.
	r := e.as("olivia", "POST", "/api/v1/fleet/policies", "format: tt.policy/v1\npolicy_id: p-shop\n", "application/yaml")
	if r.code != 422 {
		t.Fatalf("invalid: %d %s", r.code, r.body)
	}
	r = e.as("olivia", "POST", "/api/v1/fleet/policies", strings.Replace(policyV1, "p-shop", "p-none", 1), "application/yaml")
	if r.code != 409 || r.errCode() != "no_target_groups" {
		t.Fatalf("no group: %d %s", r.code, r.body)
	}
	e.must(e.as("olivia", "POST", "/api/v1/fleet/policies", policyV1, "text/plain"), 415)

	v := e.propose("pat", policyV1)
	if v.Status != StatusDraft || v.Classification != Opening || v.ApprovalsRequired != 2 || len(v.Diff) == 0 {
		t.Fatalf("first draft: %+v", v)
	}
	// The author cannot approve; the same approver cannot approve twice.
	if r := e.approve("pat", v, nil); r.code != 409 || r.errCode() != "self_approval" {
		t.Fatalf("self: %d %s", r.code, r.body)
	}
	var mid PolicyVersion
	e.must(e.approve("bob", v, nil), 200).json(t, &mid)
	if mid.Status != StatusDraft || len(mid.Approvals) != 1 {
		t.Fatalf("one approval must not activate: %+v", mid)
	}
	if r := e.approve("bob", v, nil); r.code != 409 || r.errCode() != "duplicate_approval" {
		t.Fatalf("dup: %d %s", r.code, r.body)
	}
	// A keyguard refusal is reported (502) and the approval is not kept.
	e.signer.refuse = "approvals_insufficient"
	if r := e.approve("carol", v, nil); r.code != 502 || r.errCode() != "keyguard_refused" {
		t.Fatalf("refused: %d %s", r.code, r.body)
	}
	e.signer.refuse = ""
	var act PolicyVersion
	// Local accounts cannot attach OIDC ID tokens (RT3-OIDC-2).
	if r := e.approve("carol", v, map[string]any{"id_token": "eyJ.fake.token"}); r.code != 403 || r.errCode() != "id_token_not_allowed" {
		t.Fatalf("local id_token: %d %s", r.code, r.body)
	}
	e.must(e.approve("carol", v, nil), 200).json(t, &act)
	if act.Status != StatusActive || act.IssuedSeq == nil || act.Hash == "" || act.ApprovalMode != ApprovalStandard || len(act.Approvals) != 2 {
		t.Fatalf("activation: %+v", act)
	}
	if act.Targets.Groups[0] != "shop" || act.NotAfter == nil {
		t.Fatalf("targets/not_after: %+v", act)
	}
	if got := e.signer.signs[len(e.signer.signs)-1].Approvals; got[1].IDToken != "" {
		t.Fatalf("ID token forwarded to a keyguard without OIDC: %+v", got)
	}

	// Sources get the signed envelope; it verifies with the enrollment keys
	// and passes the source acceptance rules.
	s := e.enrollSource(e.newToken(TokenOneTime, "sdk-node").Token, "sdk-node", "shop-api")
	r, err := s.do("GET", PathPolicy, nil, nil)
	if err != nil || r.code != 200 {
		t.Fatalf("fetch: %v %d %s", err, r.code, r.body)
	}
	ring := policy.NewKeyRing()
	for _, k := range s.enr.PolicySigningKeys {
		if err := ring.PinEncoded(k.Kid, k.Alg, k.PublicKey); err != nil {
			t.Fatal(err)
		}
	}
	hb, _ := s.heartbeat("starting", 0)
	vf, err := policy.Accept(r.body, ring, s.enr.Group, time.Now(), 0, hb.MinIssuedSeq)
	if err != nil || vf.Hash != act.Hash {
		t.Fatalf("accept: %v", err)
	}
	if r.hdr.Get("ETag") != `"`+act.Hash+`"` {
		t.Fatalf("etag %q", r.hdr.Get("ETag"))
	}
	r, _ = s.do("GET", PathPolicy, nil, map[string]string{"If-None-Match": `"` + act.Hash + `"`})
	if r.code != 304 {
		t.Fatalf("If-None-Match: %d", r.code)
	}
	// The intake policy registry knows the signed hash, and only that.
	if p, ok := e.fleet.IntakePolicies().LookupPolicy(act.Hash); !ok || p.ID != "p-shop" {
		t.Fatal("intake registry misses the signed policy")
	}
	if _, ok := e.fleet.IntakePolicies().LookupPolicy("sha256:" + strings.Repeat("0", 64)); ok {
		t.Fatal("unknown hash returned")
	}

	// Closing change: 1 approval.
	c := e.propose("olivia", policyClosing)
	if c.Classification != Closing || c.ApprovalsRequired != 1 {
		t.Fatalf("closing: %+v", c)
	}
	var cact PolicyVersion
	e.must(e.approve("bob", c, nil), 200).json(t, &cact)
	if cact.Status != StatusActive || *cact.IssuedSeq <= *act.IssuedSeq {
		t.Fatalf("closing activation: %+v", cact)
	}
	old, _ := e.fleet.GetPolicyVersion(context.Background(), "p-shop", act.Version)
	if old.Status != StatusSuperseded {
		t.Fatalf("previous not superseded: %s", old.Status)
	}
	if hb, _ := s.heartbeat("capturing", 10); hb.MinIssuedSeq != *cact.IssuedSeq || hb.PolicyCurrent == nil || hb.PolicyCurrent.Hash != cact.Hash {
		t.Fatalf("heartbeat after closing: %+v", hb)
	}

	// Opening change, then reject.
	o := e.propose("olivia", policyOpening)
	if o.Classification != Opening || o.ApprovalsRequired != 2 {
		t.Fatalf("opening: %+v", o)
	}
	var rej PolicyVersion
	e.must(e.as("bob", "POST", fmt.Sprintf("/api/v1/fleet/policies/p-shop/versions/%d/reject", o.Version), map[string]any{"note": "too open"}), 200).json(t, &rej)
	if rej.Status != StatusRejected {
		t.Fatalf("reject: %+v", rej)
	}
	if r := e.approve("carol", o, nil); r.code != 409 {
		t.Fatalf("approve rejected: %d", r.code)
	}

	// Rollback to v1 always needs the opening quorum.
	var rb PolicyVersion
	e.must(e.as("olivia", "POST", "/api/v1/fleet/policies/p-shop/rollback", map[string]any{"to_version": act.Version}), 201).json(t, &rb)
	if rb.Origin != OriginRollback || rb.ApprovalsRequired != 2 || rb.Classification != Opening {
		t.Fatalf("rollback: %+v", rb)
	}
	e.must(e.as("olivia", "POST", "/api/v1/fleet/policies/p-shop/rollback", map[string]any{"to_version": o.Version}), 422)

	// GET version carries the author YAML; list carries every version.
	var gv PolicyVersion
	e.must(e.as("bob", "GET", fmt.Sprintf("/api/v1/fleet/policies/p-shop/versions/%d", act.Version), nil), 200).json(t, &gv)
	if !strings.Contains(gv.AuthorYAML, "policy_id: p-shop") {
		t.Fatal("author_yaml missing")
	}
	var all []PolicyVersion
	e.must(e.as("bob", "GET", "/api/v1/fleet/policies", nil), 200).json(t, &all)
	if len(all) != 4 {
		t.Fatalf("versions: %d", len(all))
	}
}

func TestAdminSingleApproval(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("ada", auth.RoleAdmin)
	e.user("bob", auth.RolePolicyApprover)
	v := e.propose("olivia", policyV1)

	// An admin without policy-approver must give a reason.
	if r := e.approve("ada", v, nil); r.code != 422 || r.errCode() != "reason_required" {
		t.Fatalf("no reason: %d %s", r.code, r.body)
	}
	// A reason from a non-admin is refused.
	if r := e.approve("bob", v, map[string]any{"reason": "ship it"}); r.code != 403 {
		t.Fatalf("non-admin reason: %d", r.code)
	}
	// Disabled in keyguard.
	e.signer.status.AdminOverride = false
	e.fleet.refreshSignerStatus(context.Background())
	if r := e.approve("ada", v, map[string]any{"reason": "solo install"}); r.code != 403 || r.errCode() != "admin_override_disabled" {
		t.Fatalf("disabled: %d %s", r.code, r.body)
	}
	e.signer.status.AdminOverride = true
	e.fleet.refreshSignerStatus(context.Background())

	const reason = "single operator install, reviewed the diff"
	var act PolicyVersion
	e.must(e.approve("ada", v, map[string]any{"reason": reason}), 200).json(t, &act)
	if act.Status != StatusActive || act.ApprovalMode != ApprovalAdmin || len(act.Approvals) != 1 || !act.Approvals[0].Admin || act.Approvals[0].Reason != reason {
		t.Fatalf("admin approval: %+v", act)
	}
	if !strings.Contains(e.auditDump(), `"action":"policy.admin_approval"`) {
		t.Fatal("policy.admin_approval not audited")
	}
	if strings.Contains(e.auditDump(), "reviewed") {
		t.Fatal("reason text in the audit log")
	}
	if !containsStr(e.alerts.list, "policy.admin_approval") {
		t.Fatalf("alert not emitted: %v", e.alerts.list)
	}

	// Settings come from keyguard.
	var st ApprovalSettings
	e.must(e.as("ada", "GET", "/api/v1/fleet/approval-settings", nil), 200).json(t, &st)
	if st.OpeningRequired != 2 || !st.AdminOverride || !st.Known {
		t.Fatalf("settings: %+v", st)
	}
}

func TestOpeningApprovalsFromKeyguard(t *testing.T) {
	e := newEnv(t, nil)
	e.signer.status.OpeningApprovals = 1
	e.fleet.refreshSignerStatus(context.Background())
	e.setup()
	e.user("bob", auth.RolePolicyApprover)
	v := e.propose("olivia", policyV1)
	if v.ApprovalsRequired != 1 {
		t.Fatalf("required: %d", v.ApprovalsRequired)
	}
	var act PolicyVersion
	e.must(e.approve("bob", v, nil), 200).json(t, &act)
	if act.Status != StatusActive || act.ApprovalMode != ApprovalStandard {
		t.Fatalf("single opening: %+v", act)
	}
}

func TestRetargetAndRenewal(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	act := e.activateV1()

	// Binding a second group to an active policy creates an opening draft.
	var g Group
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{
		"name": "shop-eu", "policy_id": "p-shop", "allowed_service_names": []string{"shop-api"},
	}), 201).json(t, &g)
	if g.PolicyDraft == nil {
		t.Fatal("no retarget draft")
	}
	d, _ := e.fleet.GetPolicyVersion(context.Background(), "p-shop", g.PolicyDraft.Version)
	if d.Origin != OriginRetarget || d.Classification != Opening || len(d.Targets.Groups) != 2 {
		t.Fatalf("retarget: %+v", d)
	}

	// Renewal near not_after through keyguard renew, no approvals.
	e.clk.Add(policy.DefaultValidity - 3*24*time.Hour)
	e.fleet.Maintain(context.Background())
	if e.signer.renews != 1 {
		t.Fatalf("renews: %d", e.signer.renews)
	}
	vs, _ := e.fleet.ListPolicies(context.Background())
	var renewed *PolicyVersion
	for _, v := range vs {
		if v.Status == StatusActive {
			renewed = v
		}
	}
	if renewed == nil || renewed.Origin != OriginRenew || *renewed.IssuedSeq <= *act.IssuedSeq || !renewed.NotAfter.After(*act.NotAfter) {
		t.Fatalf("renewed: %+v", renewed)
	}
	if renewed.Targets.Groups[0] != "shop" || len(renewed.Targets.Groups) != 1 {
		t.Fatal("renewal must not change targets")
	}
	// The retarget draft (older than the renewal) can still be approved.
	e.must(e.approve("bob", *d, nil), 200)
	var done PolicyVersion
	e.must(e.approve("carol", *d, nil), 200).json(t, &done)
	if done.Status != StatusActive || len(done.Targets.Groups) != 2 {
		t.Fatalf("retarget activation: %+v", done)
	}
}

func TestStarterPolicy(t *testing.T) {
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	y, err := StarterPolicyYAML(StarterOptions{PolicyID: "p-shop", HMACKid: "k1", Epoch: "2026-10", InboundServices: []string{"shop-api"}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthor([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: now, Groups: []string{"shop"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.DiscoveryActive(now) || !p.AutoWordsActive(now) || p.DiscoveryActive(now.Add(73*time.Hour)) {
		t.Fatal("starter windows")
	}
	if c, _ := Classify(nil, p); c != Opening {
		t.Fatal("starter must open")
	}
	for _, s := range p.Services {
		if !s.Request.IsEmpty() || !s.Response.IsEmpty() || len(s.Ops) != 0 {
			t.Fatal("starter must have no rules")
		}
	}
	if _, err := StarterPolicyYAML(StarterOptions{PolicyID: "p", HMACKid: "k1", Epoch: "e", Now: now, Window: 8 * 24 * time.Hour}); err == nil {
		t.Fatal("window over 7 days accepted")
	}
	// Discovery beyond 7 days is rejected at proposal (policy.md 1.4).
	long := strings.Replace(y, now.Add(72*time.Hour).Format(time.RFC3339), now.Add(9*24*time.Hour).Format(time.RFC3339), -1)
	a2, _ := ParseAuthor([]byte(long))
	if _, _, err := policy.Compile(a2, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: now, Groups: []string{"shop"}}); err == nil {
		t.Fatal("9-day discovery accepted")
	}
}

func classifyYAML(t *testing.T, from, to string) (string, []DiffEntry) {
	t.Helper()
	comp := func(y string) *policy.Policy {
		a, err := ParseAuthor([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		_, p, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Groups: []string{"shop"}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return Classify(comp(from), comp(to))
}

func TestClassify(t *testing.T) {
	rep := func(old, nw string) string { return strings.Replace(policyV1, old, nw, 1) }
	cases := []struct {
		name, to, want string
	}{
		{"same", policyV1, Closing},
		{"keep to drop", rep("$.status: keep", "$.status: drop"), Closing},
		{"keep to hmac", rep("$.status: keep", "$.status: hmac(st)"), Closing},
		{"keep removed", rep("          $.status: keep\n", ""), Closing},
		{"hmac to keep", rep("$.id: hmac(order)", "$.id: keep"), Opening},
		{"hmac domain change", rep("$.id: hmac(order)", "$.id: hmac(other)"), Opening},
		{"new rule", policyOpening, Opening},
		{"lower sampling", rep("rate: 0.05", "rate: 0.01"), Closing},
		{"raise sampling", rep("rate: 0.05", "rate: 0.5"), Opening},
		{"epoch change", rep(`epoch: "2026-10"`, `epoch: "2026-11"`), Opening},
		{"new op", rep(`"POST /orders":`, "\"GET /x\": {}\n      \"POST /orders\":"), Opening},
		{"accept kid added", rep("kid: k1,", "kid: k1, accept_kids: [k2],"), Opening},
		{"lower limit", rep("sampling:", "limits: { max_depth: 8 }\nsampling:"), Closing},
	}
	for _, c := range cases {
		got, diff := classifyYAML(t, policyV1, c.to)
		if got != c.want {
			t.Errorf("%s: got %s want %s (%+v)", c.name, got, c.want, diff)
		}
	}
	// Bucket bounds: subset closes, finer opens; coarser time unit closes.
	b1 := rep("$.status: keep", "$.status: bucket(num, [0, 50, 100])")
	if c, _ := classifyYAML(t, b1, strings.Replace(b1, "[0, 50, 100]", "[0, 100]", 1)); c != Closing {
		t.Error("bucket subset must close")
	}
	if c, _ := classifyYAML(t, b1, strings.Replace(b1, "[0, 50, 100]", "[0, 25, 50, 100]", 1)); c != Opening {
		t.Error("finer bucket must open")
	}
	t1 := rep("$.status: keep", "$.status: bucket(time, day)")
	if c, _ := classifyYAML(t, t1, strings.Replace(t1, "day", "month", 1)); c != Closing {
		t.Error("coarser time must close")
	}
	if c, _ := classifyYAML(t, t1, strings.Replace(t1, "day", "hour", 1)); c != Opening {
		t.Error("finer time must open")
	}
	// Discovery: turning on opens, turning off closes.
	disc := strings.Replace(policyV1, "sampling:", "discovery: { enabled: true, expires_at: \"2026-10-22T00:00:00Z\" }\nsampling:", 1)
	if c, _ := classifyYAML(t, policyV1, disc); c != Opening {
		t.Error("discovery on must open")
	}
	if c, _ := classifyYAML(t, disc, policyV1); c != Closing {
		t.Error("discovery off must close")
	}
	if c, _ := classifyYAML(t, disc, strings.Replace(disc, "2026-10-22", "2026-10-21", 1)); c != Closing {
		t.Error("earlier discovery expiry must close")
	}
}
