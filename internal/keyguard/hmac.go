package keyguard

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"strings"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// macer computes the sanitizer token MAC (sanitizer 7.2):
// HMAC-SHA256(key, epoch || 0x00 || domain || 0x00 || value). Not safe for
// concurrent use.
type macer struct {
	mac hash.Hash
	sum [sha256.Size]byte
}

func newMacer(secret []byte) *macer { return &macer{mac: hmac.New(sha256.New, secret)} }

// mac16 returns the first 16 bytes of the MAC, the part a token carries.
func (m *macer) mac16(epoch, domain string, val []byte) [16]byte {
	m.mac.Reset()
	m.mac.Write([]byte(epoch))
	m.mac.Write([]byte{0})
	m.mac.Write([]byte(domain))
	m.mac.Write([]byte{0})
	m.mac.Write(val)
	s := m.mac.Sum(m.sum[:0])
	var out [16]byte
	copy(out[:], s[:16])
	return out
}

// tokenFor returns the token string "tk1:<kid>:<base64url(mac16)>". Used by
// tests only: keyguard never returns tokens.
func tokenFor(secret []byte, kid, epoch, domain string, val []byte) string {
	m := newMacer(secret).mac16(epoch, domain, val)
	return "tk1:" + kid + ":" + base64.RawURLEncoding.EncodeToString(m[:])
}

// parseToken splits a token "tk1:<kid>:<22 chars>" into kid and the 16 MAC
// bytes, with the exact grammar of the API (^tk1:[a-z0-9]{1,8}:[A-Za-z0-9_-]{22}$)
// and strict base64 (no non-zero trailing bits).
func parseToken(tok string) (kid string, mac [16]byte, ok bool) {
	rest, found := strings.CutPrefix(tok, "tk1:")
	if !found {
		return "", mac, false
	}
	kid, enc, found := strings.Cut(rest, ":")
	if !found || !policy.ValidKid(kid) || len(enc) != 22 {
		return "", mac, false
	}
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return "", mac, false
		}
	}
	n, err := base64.RawURLEncoding.Strict().Decode(mac[:], []byte(enc))
	if err != nil || n != 16 {
		return "", mac, false
	}
	return kid, mac, true
}

// Number lexeme limits of sanitizer 5.3: at most 64 bytes and a written
// exponent of absolute value at most 9999.
const (
	maxNumLexeme   = 64
	maxNumExponent = 9999
)

func numberUsable(lex []byte) bool {
	if len(lex) > maxNumLexeme {
		return false
	}
	i := bytes.IndexAny(lex, "eE")
	if i < 0 {
		return true
	}
	e := lex[i+1:]
	if len(e) > 0 && (e[0] == '+' || e[0] == '-') {
		e = e[1:]
	}
	v := 0
	for _, c := range e {
		v = v*10 + int(c-'0')
		if v > maxNumExponent {
			return false
		}
	}
	return true
}

// Candidate is one value submitted to the reverse-HMAC check: a JSON string
// (its bytes) or a JSON number (its lexeme).
type Candidate struct {
	Value    string
	IsNumber bool
}

// representations returns the byte strings whose tokens must be tested for a
// candidate (keyguard.md 3.1, sanitizer 7.2):
//   - a string: its bytes; and, when the string is a JSON number lexeme
//     within the limits of sanitizer 5.3, its canonical form (a source that
//     received it as a number hashed the canonical form);
//   - a number: its canonical form when within the limits; its lexeme bytes
//     as well (the same characters may have travelled as a string).
//
// Testing more representations can only add positives: the safe direction.
func (c Candidate) representations() []string {
	reps := []string{c.Value}
	lex := []byte(c.Value)
	if ttjson.IsNumberLexeme(lex) && numberUsable(lex) {
		if canon, err := ttjson.CanonicalNumber(lex); err == nil && canon != c.Value {
			reps = append(reps, canon)
		}
	}
	return reps
}
