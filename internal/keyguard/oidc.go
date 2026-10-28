package keyguard

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// approvalVerifier verifies approvers' OIDC ID tokens (keyguard.md 3.2 step
// 4): signature with the issuer's JWKS (a local file, or a configured URL),
// iss, aud (the dedicated approval audience, never the login client), exp,
// an issue and authentication time less than ApprovalTokenMaxAge ago, the
// nonce binding the token to the change (approvebind), and the approver's
// roles read from the configured claim.
type approvalVerifier struct {
	verifier    *oidc.IDTokenVerifier
	now         func() time.Time
	issuer      string
	audience    string
	rolesClaim  string
	roleMapping map[string][]string
}

// verifiedToken is what keyguard learns from a valid approval ID token.
type verifiedToken struct {
	Subject string
	// Roles are the tt roles of the approver according to the token
	// (rolesClaim mapped through roleMapping).
	Roles []string
	// Fingerprints identify the token for the "never twice" rule: one over
	// iss, sub and jti (or iat and nonce), one over the decoded signature
	// bytes. Both are stored; either seen before is a reuse.
	Fingerprints []string
}

var (
	errTokenInvalid  = errors.New("approval id token invalid")
	errNonceMismatch = errors.New("approval id token bound to another change")
)

func newApprovalVerifier(c *Config, now func() time.Time) (*approvalVerifier, error) {
	var ks oidc.KeySet
	switch {
	case c.OIDCJWKSFile != "":
		b, err := os.ReadFile(c.OIDCJWKSFile)
		if err != nil {
			return nil, fmt.Errorf("keyguard: read JWKS file: %w", err)
		}
		keys, err := parseJWKS(b)
		if err != nil {
			return nil, err
		}
		ks = &oidc.StaticKeySet{PublicKeys: keys}
	case c.OIDCJWKSURL != "":
		hc := &http.Client{Timeout: 10 * time.Second}
		ks = oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), hc), c.OIDCJWKSURL)
	default:
		return nil, errors.New("keyguard: OIDC needs a JWKS file or URL")
	}
	v := oidc.NewVerifier(c.OIDCIssuer, ks, &oidc.Config{
		ClientID: c.OIDCAudience,
		Now:      now,
		SupportedSigningAlgs: []string{
			oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA,
		},
	})
	return &approvalVerifier{verifier: v, now: now, issuer: c.OIDCIssuer, audience: c.OIDCAudience,
		rolesClaim: c.OIDCRolesClaim, roleMapping: c.OIDCRoleMapping}, nil
}

// strictSegments decodes the three segments of a compact JWS, refusing
// any non-canonical base64url (unused trailing bits, padding): the same
// token has exactly one accepted spelling (RT3-KG-1).
func strictSegments(raw string) (sig []byte, ok bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	var seg [3][]byte
	for i, p := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(p)
		if err != nil || len(b) == 0 {
			return nil, false
		}
		seg[i] = b
	}
	return seg[2], true
}

// verify checks raw and its binding to wantNonce. Errors never include
// token content.
func (v *approvalVerifier) verify(ctx context.Context, raw, wantNonce string) (*verifiedToken, error) {
	sig, ok := strictSegments(raw)
	if !ok {
		return nil, errTokenInvalid
	}
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, errTokenInvalid
	}
	now := v.now()
	fresh := func(t time.Time) bool {
		return !t.IsZero() && now.Sub(t) <= ApprovalTokenMaxAge && !t.After(now.Add(time.Minute))
	}
	if tok.Subject == "" || !fresh(tok.IssuedAt) {
		return nil, errTokenInvalid
	}
	var all map[string]any
	if err := tok.Claims(&all); err != nil {
		return nil, errTokenInvalid
	}
	// auth_time: the approver authenticated at the provider for this
	// approval (step-up with prompt=login and max_age), not minutes or
	// hours before.
	at, ok := all["auth_time"].(float64)
	if !ok || at != float64(int64(at)) || !fresh(time.Unix(int64(at), 0)) {
		return nil, errTokenInvalid
	}
	if wantNonce == "" || subtle.ConstantTimeCompare([]byte(tok.Nonce), []byte(wantNonce)) != 1 {
		return nil, errNonceMismatch
	}
	jti, _ := all["jti"].(string)
	id := "jti:" + jti
	if jti == "" {
		id = "iat:" + strconv.FormatInt(tok.IssuedAt.Unix(), 10) + "\x00" + tok.Nonce
	}
	return &verifiedToken{
		Subject: tok.Subject,
		Roles:   v.mapRoles(all[v.rolesClaim]),
		Fingerprints: []string{
			fingerprint("claims", tok.Issuer, tok.Subject, id),
			fingerprint("sig", string(sig)),
		},
	}, nil
}

func fingerprint(kind string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte("tt.keyguard.token/v1\x00" + kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return kind + ":" + hex.EncodeToString(h.Sum(nil))
}

// mapRoles turns the roles claim (a string or a list of strings) into tt
// roles: through the mapping when one is configured, else as role names.
func (v *approvalVerifier) mapRoles(claim any) []string {
	var vals []string
	switch c := claim.(type) {
	case string:
		vals = []string{c}
	case []any:
		for _, x := range c {
			if s, ok := x.(string); ok {
				vals = append(vals, s)
			}
		}
	}
	var out []string
	for _, g := range vals {
		if len(v.roleMapping) == 0 {
			out = append(out, g)
			continue
		}
		out = append(out, v.roleMapping[g]...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// parseJWKS reads a JSON Web Key Set with stdlib only: RSA, EC (P-256,
// P-384, P-521) and OKP (Ed25519) signature keys.
func parseJWKS(b []byte) ([]crypto.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Crv string `json:"crv"`
			N   string `json:"n"`
			E   string `json:"e"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, errors.New("keyguard: JWKS is not valid JSON")
	}
	dec := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	var out []crypto.PublicKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := dec(k.N)
			e, err2 := dec(k.E)
			if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
				return nil, errors.New("keyguard: JWKS has a malformed RSA key")
			}
			out = append(out, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())})
		case "EC":
			var curve elliptic.Curve
			switch k.Crv {
			case "P-256":
				curve = elliptic.P256()
			case "P-384":
				curve = elliptic.P384()
			case "P-521":
				curve = elliptic.P521()
			default:
				continue
			}
			x, err1 := dec(k.X)
			y, err2 := dec(k.Y)
			if err1 != nil || err2 != nil {
				return nil, errors.New("keyguard: JWKS has a malformed EC key")
			}
			out = append(out, &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)})
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			x, err := dec(k.X)
			if err != nil || len(x) != ed25519.PublicKeySize {
				return nil, errors.New("keyguard: JWKS has a malformed Ed25519 key")
			}
			out = append(out, ed25519.PublicKey(x))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("keyguard: JWKS has no usable signature key")
	}
	return out, nil
}
