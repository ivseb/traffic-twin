// Package approvebind computes the binding between an approval and the
// change it approves (keyguard.md 3.2 step 4, red team round 3 RT3-KG-3).
//
// With OIDC an approver authenticates again at the identity provider for
// every approval (step-up); the authentication request carries
//
//	nonce = base64url(SHA-256("tt.approve/v1" 0x00 purpose 0x00 field_1 0x00 ... field_n))
//
// so the ID token the provider returns is good for that one change only.
// keyguard (policies, packs) and tt-core (quarantine) recompute the nonce
// from what they are asked to sign or apply and refuse a token whose nonce
// differs. The fields are joined with 0x00 so no two field lists share a
// preimage.
package approvebind

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Domain separates approval nonces from any other hash.
const Domain = "tt.approve/v1"

// Purposes of an approval step-up.
const (
	PurposePolicy     = "policy-approve"
	PurposePack       = "pack-publish"
	PurposeQuarantine = "quarantine-dismiss"
)

// ValidPurpose reports whether p is one of the purposes above.
func ValidPurpose(p string) bool {
	return p == PurposePolicy || p == PurposePack || p == PurposeQuarantine
}

// Nonce returns the approval nonce of purpose over fields.
func Nonce(purpose string, fields ...string) string {
	h := sha256.New()
	h.Write([]byte(Domain))
	h.Write([]byte{0})
	h.Write([]byte(purpose))
	for _, f := range fields {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// PolicyNonce binds an approval to a policy version and to the body that
// will be signed (bodySHA256 is BodyDigest of that body).
func PolicyNonce(policyID string, version int64, bodySHA256 string) string {
	return Nonce(PurposePolicy, policyID, strconv.FormatInt(version, 10), bodySHA256)
}

// PackNonce binds a publish approval to a pack and its manifest
// (manifestSHA256: lowercase hex SHA-256 of manifest.json).
func PackNonce(packID, manifestSHA256 string) string {
	return Nonce(PurposePack, packID, manifestSHA256)
}

// QuarantineNonce binds a dismiss approval to a quarantine item ("q-<n>").
func QuarantineNonce(itemID string) string {
	return Nonce(PurposeQuarantine, itemID)
}

// unboundFields are the body fields an approval does not cover: they are
// only known when the quorum is reached and the body is compiled for
// signing (issued_seq is allocated then; created_at and not_after follow
// the signing time, and keyguard bounds them on its own).
var unboundFields = []string{"issued_seq", "created_at", "not_after"}

// BodyDigest is the lowercase hex SHA-256 of the canonical policy body
// without issued_seq, created_at and not_after. Everything else (rules,
// targets.groups, hmac, version) is covered: a draft recompiled with other
// groups or rules no longer matches the approvals given for it.
func BodyDigest(body []byte) (string, error) {
	v, err := ttjson.Parse(body, ttjson.ParseOptions{MaxDepth: 16, RejectDuplicates: true})
	if err != nil || v.Kind != ttjson.Object {
		return "", errors.New("approvebind: invalid policy body")
	}
	kept := v.Obj[:0:0]
	for _, m := range v.Obj {
		if !slices.Contains(unboundFields, m.Key) {
			kept = append(kept, m)
		}
	}
	v.Obj = kept
	b, err := ttjson.Encode(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// PolicyBodyNonce is PolicyNonce over BodyDigest(body).
func PolicyBodyNonce(policyID string, version int64, body []byte) (string, error) {
	d, err := BodyDigest(body)
	if err != nil {
		return "", err
	}
	return PolicyNonce(policyID, version, d), nil
}
