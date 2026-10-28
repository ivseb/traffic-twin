package approvebind

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestNonceVector(t *testing.T) {
	sum := sha256.Sum256([]byte("tt.approve/v1\x00policy-approve\x00p-shop\x0012\x00abc"))
	if got, want := PolicyNonce("p-shop", 12, "abc"), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if PolicyNonce("p-1", 23, "x") == PolicyNonce("p-12", 3, "x") {
		t.Fatal("ambiguous preimage")
	}
	if PackNonce("pk-1", "x") == Nonce(PurposePolicy, "pk-1", "x") {
		t.Fatal("purpose not separated")
	}
	if !ValidPurpose(PurposeQuarantine) || ValidPurpose("login") {
		t.Fatal("ValidPurpose")
	}
}

func TestBodyDigestIgnoresSigningFields(t *testing.T) {
	a := []byte(`{"created_at":"2026-10-20T10:00:00Z","format":"tt.policy.body/v1","issued_seq":1,"not_after":"2026-11-19T10:00:00Z","policy_id":"p","version":1}`)
	b := []byte(`{"created_at":"2026-10-21T10:00:00Z","format":"tt.policy.body/v1","issued_seq":7,"not_after":"2026-11-20T10:00:00Z","policy_id":"p","version":1}`)
	c := []byte(`{"created_at":"2026-10-21T10:00:00Z","format":"tt.policy.body/v1","issued_seq":7,"not_after":"2026-11-20T10:00:00Z","policy_id":"p","version":2}`)
	da, err := BodyDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := BodyDigest(b)
	dc, _ := BodyDigest(c)
	if da != db || da == dc {
		t.Fatalf("digests: %s %s %s", da, db, dc)
	}
	if _, err := BodyDigest([]byte(`[1]`)); err == nil {
		t.Fatal("non-object accepted")
	}
}
