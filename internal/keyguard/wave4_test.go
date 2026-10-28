package keyguard

import (
	"context"
	"strings"
	"testing"
)

// Spec v1.18: joining HMAC domains (hmac.families) and reading the subject
// from a member of a JSON header are observe-safe for keyguard too (same
// classification as tt-core, policy.ClassifyValues).
func TestSignFamiliesAndJSONSubjectWithoutApprovals(t *testing.T) {
	g := []string{"shop"}
	const ops = `"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.customerId":"hmac(customer)"}},
   "GET /clients/{id}":{"request":{"path":{"id":"hmac(client)"}}}}}}`
	e := newEnv(t, nil)
	ctx := context.Background()
	if _, err := e.svc.SignPolicy(ctx, observeBody(t, 1, 1, g, ops), "system", nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	joined := familiesBody(t, 2, 2, g, `{"customer":["customer","client"]}`, ops)
	if !strings.Contains(string(joined), `"domain":"customer"`) || strings.Contains(string(joined), `"domain":"client"`) {
		t.Fatalf("families not compiled: %s", joined)
	}
	res, err := e.svc.SignPolicy(ctx, joined, "system", nil)
	if err != nil || res.ApprovalMode != ModeObserve || res.OpensValues == nil || *res.OpensValues {
		t.Fatalf("families without approvals: %v %+v", err, res)
	}
	sub := observeBody(t, 3, 3, g, `"identity":{"subject":{"from":"header","name":"x-auth-context","json_path":"user.id"}},`+ops)
	if res, err := e.svc.SignPolicy(ctx, sub, "system", nil); err != nil || res.ApprovalMode != ModeObserve {
		t.Fatalf("json_path identity without approvals: %v %+v", err, res)
	}
	// The same credential-like header without json_path needs approvals.
	e2 := newEnv(t, nil)
	if _, err := e2.svc.SignPolicy(ctx, observeBody(t, 1, 1, g, ops), "system", nil); err != nil {
		t.Fatal(err)
	}
	bad := observeBody(t, 2, 2, g, `"identity":{"subject":{"from":"header","name":"x-auth-context"}},`+ops)
	if _, err := e2.svc.SignPolicy(ctx, bad, "system", nil); errCode(err) != "insufficient_approvals" {
		t.Fatalf("credential-like header without json_path: %v", err)
	}
}

// familiesBody is observeBody with hmac.families.
func familiesBody(t *testing.T, version, seq int64, groups []string, families, extra string) []byte {
	t.Helper()
	orig := observeHMAC
	observeHMAC = `"hmac":{"kid":"k1","epoch":"2026-10","families":` + families + `}`
	defer func() { observeHMAC = orig }()
	return observeBody(t, version, seq, groups, extra)
}
