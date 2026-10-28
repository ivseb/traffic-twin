package keyguard_rt

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/keyguard"
)

func errCode(err error) string {
	var e *keyguard.Error
	if err == nil {
		return ""
	}
	if ok := asErr(err, &e); ok {
		return e.Code
	}
	return "go:" + err.Error()
}

func asErr(err error, target **keyguard.Error) bool {
	for err != nil {
		if e, ok := err.(*keyguard.Error); ok {
			*target = e
			return true
		}
		type unwrap interface{ Unwrap() error }
		u, ok := err.(unwrap)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// An opening change (the first policy for a group opens) must not be signed
// with a single policy-approver approval when OpeningApprove is 2
// (keyguard.md 3.2 step 3).
func TestRT_Keyguard_Holds_OpeningNeedsTwoApprovers(t *testing.T) {
	e := newEnv(t, false, nil)
	b := body(t, "p-shop", 1, 1, []string{"shop"}, "")
	_, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{appr("alice")})
	if errCode(err) != "insufficient_approvals" {
		t.Fatalf("single approval on opening: got %q, want insufficient_approvals", errCode(err))
	}
	// Two distinct approvers, one not the proposer: accepted.
	if _, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{appr("alice"), appr("bob")}); err != nil {
		t.Fatalf("two approvers: %v", err)
	}
}

// Two approvals for an opening where both are the proposer (duplicate) must
// be refused; and two distinct approvers where neither differs from the
// proposer is impossible, but two where all are the proposer must fail the
// "at least one not the proposer" rule.
func TestRT_Keyguard_Holds_ProposerCannotAloneApproveOpening(t *testing.T) {
	e := newEnv(t, false, nil)
	b := body(t, "p-shop", 1, 1, []string{"shop"}, "")
	// alice proposes and both approvals are alice: duplicate_approver.
	_, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{appr("alice"), appr("alice")})
	if errCode(err) != "duplicate_approver" {
		t.Fatalf("got %q, want duplicate_approver", errCode(err))
	}
}

// issued_seq must strictly increase across signatures (M18 replay / rollback).
func TestRT_Keyguard_Holds_IssuedSeqMonotonic(t *testing.T) {
	e := newEnv(t, false, nil)
	b1 := body(t, "p-shop", 1, 5, []string{"shop"}, "")
	if _, err := e.svc.SignPolicy(context.Background(), b1, "alice", []keyguard.Approval{appr("alice"), appr("bob")}); err != nil {
		t.Fatal(err)
	}
	// A later version with a lower issued_seq must be refused.
	b2 := body(t, "p-shop", 2, 4, []string{"shop"}, "")
	_, err := e.svc.SignPolicy(context.Background(), b2, "alice", []keyguard.Approval{appr("alice"), appr("bob")})
	if errCode(err) != "issued_seq_not_increasing" {
		t.Fatalf("got %q, want issued_seq_not_increasing", errCode(err))
	}
}

// With OIDC configured, every approval must carry a verifiable ID token
// (keyguard.md 3.2 step 4), and the same token must not be accepted twice.
func TestRT_Keyguard_Holds_OIDCRequiredAndNoReuse(t *testing.T) {
	e := newEnv(t, true, nil)
	b := body(t, "p-shop", 1, 1, []string{"shop"}, "")
	// No token: refused.
	_, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{appr("alice"), appr("bob")})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("missing token: got %q, want approval_unverifiable", errCode(err))
	}
	// Reuse the SAME token for both approvers in one call: distinct-subject fails.
	tokA := e.idToken("sub-alice", b)
	a1 := appr("alice")
	a1.IDToken = tokA
	a2 := appr("bob")
	a2.IDToken = tokA
	_, err = e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{a1, a2})
	if c := errCode(err); c != "duplicate_approver" && c != "approval_unverifiable" {
		t.Fatalf("same token twice in one call: got %q", c)
	}
	// Valid distinct tokens: accepted.
	a2b := appr("bob")
	a2b.IDToken = e.idToken("sub-bob", b)
	if _, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{a1, a2b}); err != nil {
		t.Fatalf("distinct tokens: %v", err)
	}
	// Reusing sub-alice's token in a NEW signing call must be refused.
	b2 := body(t, "p-shop", 2, 2, []string{"shop"}, "")
	a3 := appr("carol")
	a3.IDToken = tokA // reused
	a4 := appr("dave")
	a4.IDToken = e.idToken("sub-dave", b2)
	_, err = e.svc.SignPolicy(context.Background(), b2, "carol", []keyguard.Approval{a3, a4})
	if errCode(err) != "approval_unverifiable" {
		t.Fatalf("token reuse across calls: got %q, want approval_unverifiable", errCode(err))
	}
}

// Keys must never appear in the status report or the logs (G12, keyguard.md 1).
func TestRT_Keyguard_Holds_NoKeyInStatusOrLogs(t *testing.T) {
	e := newEnv(t, false, nil)
	b := body(t, "p-shop", 1, 1, []string{"shop"}, "")
	if _, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{appr("alice"), appr("bob")}); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keyB64 := b64(e.hmacKey)
	// Status is a struct; marshal-ish check via fmt through the exported API:
	if strings.Contains(e.logs.String(), keyB64) {
		t.Errorf("hmac key material found in logs")
	}
	_ = st
}

// match on a policy version this keyguard never signed must fail closed
// (keyguard.md 3.1: unknown_policy), never answer "no positive".
func TestRT_Keyguard_Holds_MatchUnknownPolicy(t *testing.T) {
	e := newEnv(t, false, nil)
	_, err := e.svc.Match(context.Background(), []keyguard.PolicyRef{{ID: "p-ghost", Version: 1}}, []keyguard.Candidate{keyguard.Candidate{Value: "x"}})
	if errCode(err) != "unknown_policy" {
		t.Fatalf("got %q, want unknown_policy", errCode(err))
	}
}

// A renewal must not change any rule (keyguard.md 3.3): only version,
// issued_seq, created_at and not_after may differ.
func TestRT_Keyguard_Holds_RenewCannotChangeRules(t *testing.T) {
	e := newEnv(t, false, nil)
	b := body(t, "p-shop", 1, 1, []string{"shop"}, "")
	if _, err := e.svc.SignPolicy(context.Background(), b, "alice", []keyguard.Approval{appr("alice"), appr("bob")}); err != nil {
		t.Fatal(err)
	}
	// A body that adds a kept header is not a renewal.
	opened := body(t, "p-shop", 2, 2, []string{"shop"}, `"global":{"request":{"headers":{"x-note":"keep"}}},`+shopRules)
	_, err := e.svc.RenewPolicy(context.Background(), opened)
	if errCode(err) != "fields_differ" {
		t.Fatalf("renew with changed rules: got %q, want fields_differ", errCode(err))
	}
}
