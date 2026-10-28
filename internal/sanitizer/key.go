package sanitizer

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Key errors (sanitizer section 7.1). With any of them the source must not
// capture.
var (
	ErrKeyMissing   = errors.New("sanitizer: hmac key missing")
	ErrKeyMalformed = errors.New("sanitizer: hmac key malformed or shorter than 32 bytes")
	ErrKeyMismatch  = errors.New("sanitizer: hmac key kid differs from policy hmac.kid")
)

// MinKeyBytes is the minimum HMAC key length.
const MinKeyBytes = 32

// Key is the local HMAC key of a source. The secret never leaves the
// process and is never logged.
type Key struct {
	Kid    string
	secret []byte
}

// String never prints the secret.
func (k Key) String() string { return "hmac-key(" + k.Kid + ")" }

// NewKey builds a key from raw bytes (tests, tt-core gate).
func NewKey(kid string, secret []byte) (Key, error) {
	if !policy.ValidKid(kid) || len(secret) < MinKeyBytes {
		return Key{}, ErrKeyMalformed
	}
	return Key{Kid: kid, secret: append([]byte(nil), secret...)}, nil
}

// ParseKey parses "<kid>:<base64url-without-padding>".
func ParseKey(s string) (Key, error) {
	if s == "" {
		return Key{}, ErrKeyMissing
	}
	kid, enc, ok := strings.Cut(s, ":")
	if !ok || !policy.ValidKid(kid) {
		return Key{}, ErrKeyMalformed
	}
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return Key{}, ErrKeyMalformed
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil {
		return Key{}, ErrKeyMalformed
	}
	return NewKey(kid, raw)
}

// KeySet is the local key configuration: one or more keys, in file order.
type KeySet struct {
	keys []Key
}

// NewKeySet builds a key set from keys (tests, tools).
func NewKeySet(keys ...Key) KeySet { return KeySet{keys: append([]Key(nil), keys...)} }

// Len returns the number of keys.
func (ks KeySet) Len() int { return len(ks.keys) }

// ParseKeys parses the content of TT_HMAC_KEY or TT_HMAC_KEY_FILE
// (sanitizer 7.1): lines "<kid>:<base64url-nopad>" split on '\n', a final
// '\r' removed from each line, empty lines ignored, no other spaces. Any
// invalid or short line invalidates the whole configuration
// (ErrKeyMissing, reported as key_missing).
func ParseKeys(s string) (KeySet, error) {
	var ks KeySet
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		k, err := ParseKey(line)
		if err != nil {
			return KeySet{}, ErrKeyMissing
		}
		ks.keys = append(ks.keys, k)
	}
	if len(ks.keys) == 0 {
		return KeySet{}, ErrKeyMissing
	}
	return ks, nil
}

// Select returns the key to use with p: the one with kid = hmac.kid, else
// the first of hmac.accept_kids (in policy order) that is present.
func (ks KeySet) Select(p *policy.Policy) (Key, error) {
	if len(ks.keys) == 0 {
		return Key{}, ErrKeyMissing
	}
	find := func(kid string) (Key, bool) {
		for _, k := range ks.keys {
			if k.Kid == kid {
				return k, true
			}
		}
		return Key{}, false
	}
	if k, ok := find(p.HMAC.Kid); ok {
		return k, nil
	}
	for _, kid := range p.HMAC.AcceptKids {
		if k, ok := find(kid); ok {
			return k, nil
		}
	}
	return Key{}, ErrKeyMismatch
}

// LoadKeysFromEnv reads TT_HMAC_KEY, or the file named by TT_HMAC_KEY_FILE.
func LoadKeysFromEnv() (KeySet, error) {
	if v := os.Getenv("TT_HMAC_KEY"); v != "" {
		return ParseKeys(v)
	}
	if f := os.Getenv("TT_HMAC_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return KeySet{}, ErrKeyMissing
		}
		return ParseKeys(string(b))
	}
	return KeySet{}, ErrKeyMissing
}
