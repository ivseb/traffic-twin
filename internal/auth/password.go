package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// PasswordParams are the argon2id cost parameters.
type PasswordParams struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	SaltLen int
	KeyLen  uint32
}

// DefaultPasswordParams follow the OWASP argon2id guidance with headroom:
// 64 MiB, 3 passes, 2 lanes.
var DefaultPasswordParams = PasswordParams{Memory: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}

// Password length limits (in characters). The upper bound caps hashing cost.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// ErrWeakPassword reports a password outside the length policy.
var ErrWeakPassword = fmt.Errorf("password must be %d to %d characters", MinPasswordLen, MaxPasswordLen)

func checkPasswordPolicy(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen || n > MaxPasswordLen || !utf8.ValidString(pw) {
		return ErrWeakPassword
	}
	return nil
}

// hasher bounds concurrent argon2id computations, which cost Memory KiB
// each, so a login flood cannot exhaust memory.
type hasher struct {
	params PasswordParams
	sem    chan struct{}
	dummy  string
}

func newHasher(p PasswordParams, concurrency int) (*hasher, error) {
	h := &hasher{params: p, sem: make(chan struct{}, concurrency)}
	d, err := h.hash(context.Background(), "dummy-password-for-timing")
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

func (h *hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *hasher) release() { <-h.sem }

var b64 = base64.RawStdEncoding

// hash returns a PHC string: $argon2id$v=19$m=..,t=..,p=..$salt$key
func (h *hasher) hash(ctx context.Context, pw string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	p := h.params
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// verify compares pw with encoded in constant time. An empty encoded value
// (no password set) is checked against a dummy hash to keep timing uniform,
// and always fails.
func (h *hasher) verify(ctx context.Context, pw, encoded string) (bool, error) {
	usable := encoded != ""
	if !usable {
		encoded = h.dummy
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var m, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &threads); err != nil {
		return false, errBadHash
	}
	// Refuse absurd parameters from a tampered database (cost DoS).
	if m == 0 || m > 1<<20 || t == 0 || t > 20 || threads == 0 || threads > 16 {
		return false, errBadHash
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) < 16 || len(want) > 64 {
		return false, errBadHash
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, threads, uint32(len(want)))
	h.release()
	ok := subtle.ConstantTimeCompare(got, want) == 1
	return ok && usable, nil
}
