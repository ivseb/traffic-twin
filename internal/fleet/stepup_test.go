package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// fakeTokens stands for internal/auth's step-up: a token is available once
// per grant, for an OIDC user, bound to the nonce fleet asks for.
type fakeTokens struct {
	mu      sync.Mutex
	granted map[string]bool // user id + "|" + ref
	nonces  map[string]string
}

func (f *fakeTokens) grant(user, ref string) {
	f.mu.Lock()
	f.granted[user+"|"+ref] = true
	f.mu.Unlock()
}

func (f *fakeTokens) ApprovalToken(_ context.Context, p *auth.Principal, purpose, ref, nonce, explicit string) (string, error) {
	if p.OIDCSubject == "" {
		return "", auth.ErrLocalApprover
	}
	if purpose != approvebind.PurposePolicy {
		return "", auth.ErrApprovalToken
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.granted[p.UserID+"|"+ref] {
		return "", auth.ErrStepUpRequired
	}
	delete(f.granted, p.UserID+"|"+ref)
	tok := "tok." + p.OIDCSubject + "." + nonce
	f.nonces[tok] = nonce
	return tok, nil
}

func (f *fakeTokens) CheckApprovalAudience(issuer, audience string) error {
	if issuer != "https://idp.example" || audience != "tt-approve" {
		return auth.ErrApprovalToken
	}
	return nil
}

func (e *env) oidcUser(name string, roles ...auth.Role) string {
	e.t.Helper()
	e.user(name, roles...)
	var id string
	if err := e.db.QueryRowContext(context.Background(), `SELECT id FROM auth_users WHERE username = ?`, name).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.db.ExecContext(context.Background(), `UPDATE auth_users SET oidc_issuer = ?, oidc_subject = ? WHERE id = ?`, "https://idp.example", "sub-"+name, id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// With OIDC in keyguard every approval needs a step-up token bound to the
// change; tokens expire after 10 minutes and are renewed by approving
// again (RT3-KG-3, RT3-OIDC-1/2).
func TestApprovalStepUpWithOIDC(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	tokens := &fakeTokens{granted: map[string]bool{}, nonces: map[string]string{}}
	e.fleet.SetApprovalTokens(tokens)
	e.signer.mu.Lock()
	e.signer.status = SignerStatus{OpeningApprovals: 2, AdminOverride: true, OIDCIssuer: "https://idp.example", OIDCAudience: "tt-approve"}
	e.signer.mu.Unlock()
	e.fleet.refreshSignerStatus(context.Background())

	e.user("pat", auth.RoleOperator)
	e.user("dave", auth.RolePolicyApprover)
	bob := e.oidcUser("bob", auth.RolePolicyApprover)
	carol := e.oidcUser("carol", auth.RolePolicyApprover)
	v := e.propose("pat", policyV1)
	ref := StepUpRef(v.PolicyID, v.Version)

	if r := e.approve("dave", v, nil); r.code != 403 || r.errCode() != "oidc_required" {
		t.Fatalf("local approver: %d %s", r.code, r.body)
	}
	if r := e.approve("bob", v, nil); r.code != 403 || r.errCode() != "stepup_required" {
		t.Fatalf("no step-up: %d %s", r.code, r.body)
	}
	tokens.grant(bob, ref)
	var mid PolicyVersion
	e.must(e.approve("bob", v, nil), 200).json(t, &mid)
	if mid.Status != StatusDraft || len(mid.Approvals) != 1 || mid.Approvals[0].TokenFresh == nil || !*mid.Approvals[0].TokenFresh {
		t.Fatalf("first approval: %+v", mid)
	}
	// Bob's token expires before carol approves: the quorum is counted but
	// not signed; bob renews.
	e.clk.Add(11 * time.Minute)
	tokens.grant(carol, ref)
	e.must(e.approve("carol", v, nil), 200).json(t, &mid)
	if mid.Status != StatusDraft || len(mid.Approvals) != 2 || len(e.signer.signs) != 0 {
		t.Fatalf("quorum with an expired token must wait: %+v (%d signs)", mid, len(e.signer.signs))
	}
	for _, a := range mid.Approvals {
		if a.TokenFresh == nil || *a.TokenFresh != (a.By == "carol") {
			t.Fatalf("token_fresh: %+v", mid.Approvals)
		}
	}
	if r := e.approve("bob", v, nil); r.code != 403 || r.errCode() != "stepup_required" {
		t.Fatalf("renewal without step-up: %d %s", r.code, r.body)
	}
	tokens.grant(bob, ref)
	var act PolicyVersion
	e.must(e.approve("bob", v, nil), 200).json(t, &act)
	if act.Status != StatusActive || len(act.Approvals) != 2 {
		t.Fatalf("activation after renewal: %+v", act)
	}
	last := e.signer.signs[len(e.signer.signs)-1]
	want, err := approvebind.PolicyBodyNonce(v.PolicyID, v.Version, last.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range last.Approvals {
		if !strings.HasSuffix(a.IDToken, "."+want) {
			t.Fatalf("token not bound to the signed body: %+v", last.Approvals)
		}
	}
	if p, _ := policy.DecodeBody(last.Body); p.Version != v.Version {
		t.Fatal("signed another version")
	}
	if !strings.Contains(e.auditDump(), "policy.approve") {
		t.Fatal("no audit")
	}
	// The binding is exposed for the step-up of a new draft; an unknown
	// draft is not found.
	if _, err := e.fleet.ApprovalNonce(context.Background(), "p-nope", 1); err == nil {
		t.Fatal("nonce for an unknown draft")
	}
}
