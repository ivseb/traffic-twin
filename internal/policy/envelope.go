package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Verification errors. All of them mean "reject the policy".
var (
	ErrEnvelope      = errors.New("policy: malformed envelope")
	ErrUnknownKid    = errors.New("policy: unknown signing kid")
	ErrBadSignature  = errors.New("policy: bad signature")
	ErrHashMismatch  = errors.New("policy: hash mismatch")
	ErrIDMismatch    = errors.New("policy: envelope and body policy_id/version/issued_seq differ")
	ErrBadEndorsment = errors.New("policy: bad signing key endorsement")

	// Reasons behind a rejected rotation key (docs/spec/policy.md §3.1). Each
	// one wraps ErrBadEndorsment, except ErrKeyConflict (a Pin error).
	ErrKeyMalformed       = fmt.Errorf("%w: malformed entry", ErrBadEndorsment)
	ErrEndorserUnknown    = fmt.Errorf("%w: endorser not pinned or revoked", ErrBadEndorsment)
	ErrEndorsementInvalid = fmt.Errorf("%w: signature does not verify", ErrBadEndorsment)
	ErrKeyConflict        = errors.New("policy: kid already pinned to another key")
)

var b64enc = base64.RawURLEncoding.Strict()

// b64 decodes base64url without padding, rejecting any byte outside the
// alphabet (the stdlib decoder silently skips CR and LF).
var b64 = strictB64{}

type strictB64 struct{}

func (strictB64) EncodeToString(b []byte) string { return b64enc.EncodeToString(b) }

func (strictB64) DecodeString(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isAlpha(c) || isDigit(c) || c == '-' || c == '_') {
			return nil, ErrEnvelope
		}
	}
	return b64enc.DecodeString(s)
}

// Hash returns "sha256:" + lowercase hex SHA-256 of the body bytes.
func Hash(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verified is a policy whose envelope passed every check.
type Verified struct {
	Policy    *Policy
	Hash      string
	Body      []byte // exact compiled body bytes
	Envelope  []byte // exact envelope bytes (what a source caches)
	SignerKid string
}

// KeyRing holds the pinned Fleet policy-signing public keys. It is safe for
// concurrent use.
type KeyRing struct {
	mu      sync.RWMutex
	keys    map[string]ed25519.PublicKey
	revoked map[string]bool
}

// NewKeyRing returns an empty key ring.
func NewKeyRing() *KeyRing {
	return &KeyRing{keys: map[string]ed25519.PublicKey{}, revoked: map[string]bool{}}
}

// Revoke removes a signing key for good (revoke_signing_keys): it can never
// be pinned again in this ring.
func (r *KeyRing) Revoke(kid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, kid)
	r.revoked[kid] = true
}

// Pin adds a key received at enrollment.
func (r *KeyRing) Pin(kid string, pub ed25519.PublicKey) error {
	if !ValidSigningKid(kid) || len(pub) != ed25519.PublicKeySize {
		return ErrEnvelope
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked[kid] {
		return fmt.Errorf("policy: kid %q is revoked", kid)
	}
	if old, ok := r.keys[kid]; ok && !bytes.Equal(old, pub) {
		return fmt.Errorf("%w (kid %q)", ErrKeyConflict, kid)
	}
	r.keys[kid] = append(ed25519.PublicKey(nil), pub...)
	return nil
}

// PinEncoded pins a key given as base64url (no padding) raw bytes, the
// enrollment format of api/fleet-api.v1.openapi.yaml.
func (r *KeyRing) PinEncoded(kid, alg, publicKey string) error {
	if alg != "Ed25519" {
		return ErrEnvelope
	}
	pub, err := b64.DecodeString(publicKey)
	if err != nil {
		return ErrEnvelope
	}
	return r.Pin(kid, pub)
}

func (r *KeyRing) get(kid string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.revoked[kid] {
		return nil, false
	}
	k, ok := r.keys[kid]
	return k, ok
}

// SignedMessage is the message Ed25519 signs for a policy body:
// "tt.policy.body/v1" || 0x00 || body (policy.md 3).
func SignedMessage(body []byte) []byte {
	m := make([]byte, 0, len(FormatBody)+1+len(body))
	m = append(m, FormatBody...)
	m = append(m, 0)
	return append(m, body...)
}

func endorsementMessage(kid string, pub []byte) []byte {
	m := []byte("tt-fleet-key/v1")
	m = append(m, 0)
	m = append(m, kid...)
	m = append(m, 0)
	return append(m, pub...)
}

// Endorse signs a new signing key with an existing one (key rotation, see
// add_signing_keys in the Fleet API). The result is base64url without padding.
func Endorse(priv ed25519.PrivateKey, newKid string, newPub ed25519.PublicKey) string {
	return b64.EncodeToString(ed25519.Sign(priv, endorsementMessage(newKid, newPub)))
}

// PinEndorsed pins a new key only if it is endorsed by an already pinned key.
// A refusal wraps one of ErrKeyMalformed, ErrKeyConflict, ErrEndorserUnknown
// or ErrEndorsementInvalid (see SigningKeyErrorCode).
func (r *KeyRing) PinEndorsed(kid, alg, publicKey, endorsedBy, endorsement string) error {
	if alg != "Ed25519" || !ValidSigningKid(kid) {
		return ErrKeyMalformed
	}
	pub, err := b64.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrKeyMalformed
	}
	sig, err := b64.DecodeString(endorsement)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrKeyMalformed
	}
	r.mu.RLock()
	have, pinned := r.keys[kid]
	r.mu.RUnlock()
	if pinned && !bytes.Equal(have, pub) {
		return fmt.Errorf("%w (kid %q)", ErrKeyConflict, kid)
	}
	signer, ok := r.get(endorsedBy)
	if !ok {
		return ErrEndorserUnknown
	}
	if !ed25519.Verify(signer, endorsementMessage(kid, pub), sig) {
		return ErrEndorsementInvalid
	}
	return r.Pin(kid, pub)
}

// SigningKeyErrorCode maps an error from PinEndorsed to the canonical
// heartbeat error code (docs/spec/policy.md §3.1).
func SigningKeyErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrKeyConflict):
		return "signing_key_conflict"
	case errors.Is(err, ErrEndorserUnknown):
		return "signing_key_endorser_unknown"
	case errors.Is(err, ErrEndorsementInvalid):
		return "signing_key_endorsement_invalid"
	default:
		return "signing_key_rejected"
	}
}

// Sign wraps compiled body bytes in a signed envelope
// (tt.policy.compiled/v1). In production signing is done by tt keyguard;
// this helper serves keyguard, tests and fixtures. The body is validated
// first; the envelope is written in tt canonical JSON.
func Sign(body []byte, kid string, priv ed25519.PrivateKey) ([]byte, error) {
	if !ValidSigningKid(kid) || len(priv) != ed25519.PrivateKeySize {
		return nil, ErrEnvelope
	}
	p, err := DecodeBody(body)
	if err != nil {
		return nil, err
	}
	return Envelope(body, p, kid, ed25519.Sign(priv, SignedMessage(body)))
}

// Envelope assembles an envelope from body bytes, the decoded policy and a
// signature over SignedMessage(body) (for example one returned by keyguard).
func Envelope(body []byte, p *Policy, kid string, sig []byte) ([]byte, error) {
	if !ValidSigningKid(kid) || len(sig) != ed25519.SignatureSize {
		return nil, ErrEnvelope
	}
	env := ttjson.Obj(
		mem("format", ttjson.Str(FormatEnvelope)),
		mem("policy_id", ttjson.Str(p.PolicyID)),
		mem("version", ttjson.Num(strconv.FormatInt(p.Version, 10))),
		mem("issued_seq", ttjson.Num(strconv.FormatInt(p.IssuedSeq, 10))),
		mem("hash", ttjson.Str(Hash(body))),
		mem("body_b64", ttjson.Str(b64.EncodeToString(body))),
		mem("signature", ttjson.Obj(
			mem("alg", ttjson.Str("Ed25519")),
			mem("kid", ttjson.Str(kid)),
			mem("sig", ttjson.Str(b64.EncodeToString(sig))),
		)),
	)
	return ttjson.Encode(env)
}

// MaxEnvelopeBytes bounds the envelope size a source accepts.
const MaxEnvelopeBytes = 5 << 20

// Verify checks a signed envelope against the key ring (policy.md 3 and
// 4 points 1-2): schema, pinned and non-revoked kid, Ed25519 signature over
// SignedMessage(body), hash, policy_id/version/issued_seq coherence and every
// body rule (including reserved HMAC domains). Group, expiry and sequence are
// checked by Accept. Any failure returns an error and no policy.
func Verify(envelope []byte, ring *KeyRing) (*Verified, error) {
	if ring == nil || len(envelope) > MaxEnvelopeBytes {
		return nil, ErrEnvelope
	}
	v, err := ttjson.Parse(envelope, ttjson.ParseOptions{MaxDepth: 4, RejectDuplicates: true})
	if err != nil {
		return nil, ErrEnvelope
	}
	m, err := fields(v, "envelope", "format", "policy_id", "version", "issued_seq", "hash", "body_b64", "signature")
	if err != nil || require(m, "envelope", "format", "policy_id", "version", "issued_seq", "hash", "body_b64", "signature") != nil {
		return nil, ErrEnvelope
	}
	if f, err := str(m["format"], ""); err != nil || f != FormatEnvelope {
		return nil, ErrEnvelope
	}
	pid, err := str(m["policy_id"], "")
	if err != nil || !ValidPolicyID(pid) {
		return nil, ErrEnvelope
	}
	ver, err := integer(m["version"], "")
	if err != nil || ver < 1 {
		return nil, ErrEnvelope
	}
	seq, err := integer(m["issued_seq"], "")
	if err != nil || seq < 1 {
		return nil, ErrEnvelope
	}
	hash, err := str(m["hash"], "")
	if err != nil || len(hash) != 71 || hash[:7] != "sha256:" {
		return nil, ErrEnvelope
	}
	for i := 7; i < len(hash); i++ {
		if !(isDigit(hash[i]) || (hash[i] >= 'a' && hash[i] <= 'f')) {
			return nil, ErrEnvelope
		}
	}
	bodyB64, err := str(m["body_b64"], "")
	if err != nil || bodyB64 == "" {
		return nil, ErrEnvelope
	}
	sm, err := fields(m["signature"], "signature", "alg", "kid", "sig")
	if err != nil || require(sm, "signature", "alg", "kid", "sig") != nil {
		return nil, ErrEnvelope
	}
	alg, err1 := str(sm["alg"], "")
	kid, err2 := str(sm["kid"], "")
	sigS, err3 := str(sm["sig"], "")
	if err1 != nil || err2 != nil || err3 != nil || alg != "Ed25519" || !ValidSigningKid(kid) || len(sigS) != 86 {
		return nil, ErrEnvelope
	}
	body, err := b64.DecodeString(bodyB64)
	if err != nil {
		return nil, ErrEnvelope
	}
	sig, err := b64.DecodeString(sigS)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrEnvelope
	}
	pub, ok := ring.get(kid)
	if !ok {
		return nil, ErrUnknownKid
	}
	if !ed25519.Verify(pub, SignedMessage(body), sig) {
		return nil, ErrBadSignature
	}
	if Hash(body) != hash {
		return nil, ErrHashMismatch
	}
	p, err := DecodeBody(body)
	if err != nil {
		return nil, err
	}
	if p.PolicyID != pid || p.Version != ver || p.IssuedSeq != seq {
		return nil, ErrIDMismatch
	}
	return &Verified{Policy: p, Hash: hash, Body: body, Envelope: append([]byte(nil), envelope...), SignerKid: kid}, nil
}
