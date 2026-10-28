package keyguard

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Key loading errors. Messages never contain key material.
var (
	ErrKeyFilePerms = errors.New("keyguard: key file must not be accessible by group or others (use mode 0600 or 0400)")
	ErrKeyMalformed = errors.New("keyguard: key configuration is malformed")
	ErrKeyMissing   = errors.New("keyguard: key configuration is missing")
	ErrKeyRevoked   = errors.New("keyguard: the active signing key is revoked")
)

// MinHMACKeyBytes is the minimum HMAC key length (sanitizer 7.1).
const MinHMACKeyBytes = 32

// maxKeyFileBytes bounds a key file.
const maxKeyFileBytes = 1 << 20

// ReadKeyFile reads a key file, refusing anything but a regular file (a
// symlink to one is followed, as in Kubernetes secret volumes) whose mode
// grants no permission to group or others. The mode is checked on the
// opened descriptor, so the file cannot be swapped between check and read.
// The caller must zero the returned bytes after parsing.
func ReadKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrKeyMissing
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keyguard: open key file: %w", errors.Unwrap(err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("keyguard: stat key file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("keyguard: key file %s is not a regular file", st.Name())
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrKeyFilePerms, st.Name(), st.Mode().Perm())
	}
	if st.Size() > maxKeyFileBytes {
		return nil, ErrKeyMalformed
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		zero(b)
		return nil, fmt.Errorf("keyguard: read key file: %w", err)
	}
	if len(b) > maxKeyFileBytes {
		zero(b)
		return nil, ErrKeyMalformed
	}
	return b, nil
}

// zero overwrites b. Go may have copied key bytes elsewhere (string
// conversions are avoided for that reason), so this is best effort.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// keyLines splits a key configuration as sanitizer 7.1 does: on '\n', a final
// '\r' removed, empty lines ignored. Each line is "<id>:<base64url-nopad>".
// The returned secrets are fresh slices; text is not retained.
func keyLines(text []byte, validID func(string) bool) (ids []string, secrets [][]byte, err error) {
	fail := func() ([]string, [][]byte, error) {
		for _, s := range secrets {
			zero(s)
		}
		return nil, nil, ErrKeyMalformed
	}
	for _, line := range bytes.Split(text, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			continue
		}
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			return fail()
		}
		id, enc := string(line[:i]), line[i+1:]
		if !validID(id) {
			return fail()
		}
		for _, c := range enc {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return fail()
			}
		}
		raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(enc)))
		n, derr := base64.RawURLEncoding.Strict().Decode(raw, enc)
		if derr != nil {
			zero(raw)
			return fail()
		}
		for _, prev := range ids {
			if prev == id {
				zero(raw)
				return fail()
			}
		}
		ids = append(ids, id)
		secrets = append(secrets, raw[:n])
	}
	if len(ids) == 0 {
		return nil, nil, ErrKeyMissing
	}
	return ids, secrets, nil
}

// HMACKeys holds the HMAC keys of every kid. It never prints or logs the
// secrets.
type HMACKeys struct {
	kids    []string // file order
	secrets map[string][]byte
}

// ParseHMACKeys parses "<kid>:<base64url-nopad>" lines (sanitizer 7.1, the
// TT_KEYGUARD_HMAC_KEYS_FILE format). Every key must be at least 32 bytes
// and kids must be distinct. text is not retained.
func ParseHMACKeys(text []byte) (*HMACKeys, error) {
	ids, secrets, err := keyLines(text, policy.ValidKid)
	if err != nil {
		return nil, err
	}
	k := &HMACKeys{secrets: map[string][]byte{}}
	for i, id := range ids {
		if len(secrets[i]) < MinHMACKeyBytes {
			for _, s := range secrets {
				zero(s)
			}
			return nil, fmt.Errorf("%w: hmac key %q is shorter than %d bytes", ErrKeyMalformed, id, MinHMACKeyBytes)
		}
		k.kids = append(k.kids, id)
		k.secrets[id] = secrets[i]
	}
	return k, nil
}

// Kids returns the kids held, sorted.
func (k *HMACKeys) Kids() []string {
	out := append([]string(nil), k.kids...)
	sort.Strings(out)
	return out
}

// Has reports whether the key kid is held.
func (k *HMACKeys) Has(kid string) bool { _, ok := k.secrets[kid]; return ok }

func (k *HMACKeys) secret(kid string) ([]byte, bool) {
	s, ok := k.secrets[kid]
	return s, ok
}

// Zero overwrites every secret. The key set is unusable afterwards.
func (k *HMACKeys) Zero() {
	for kid, s := range k.secrets {
		zero(s)
		delete(k.secrets, kid)
	}
}

// String never prints secrets.
func (k *HMACKeys) String() string { return fmt.Sprintf("hmac-keys%v", k.kids) }

// GoString never prints secrets.
func (k *HMACKeys) GoString() string { return k.String() }

// LogValue never logs secrets.
func (k *HMACKeys) LogValue() slog.Value { return slog.StringValue(k.String()) }

// PublicKey is the public part of a signing key, as served by
// GET /keyguard/v1/public-keys.
type PublicKey struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	// EndorsedBy and Endorsement, when set, are the kid of the next older
	// key of the file and its signature over the new key (policy.Endorse:
	// "tt-fleet-key/v1" || 0x00 || kid || 0x00 || key). They let sources
	// already enrolled learn a rotated key through add_signing_keys.
	EndorsedBy  string `json:"endorsed_by,omitempty"`
	Endorsement string `json:"endorsement,omitempty"`
}

// SigningKeys holds one active Ed25519 signing key and the public parts of
// retired keys still announced for verification during a rotation.
type SigningKeys struct {
	kid    string
	priv   ed25519.PrivateKey
	public []PublicKey
}

// ParseSigningKeys parses "<kid>:<base64url-nopad 32-byte Ed25519 seed>"
// lines. The first line not revoked is the active signer; the following
// non-revoked lines are retired keys: only their public parts are kept and
// announced. Every announced key is endorsed by the next older announced key
// (the retired seed signs the newer key at load time, then all retired seeds
// are zeroed), so a rotation reaches already enrolled sources: keep the
// retired seed in the file until the old kid is revoked. A revoked first
// line is an error: keyguard must not start with a revoked signer.
func ParseSigningKeys(text []byte, revoked map[string]bool) (*SigningKeys, error) {
	ids, seeds, err := keyLines(text, policy.ValidSigningKid)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, s := range seeds {
			zero(s)
		}
	}()
	for _, s := range seeds {
		if len(s) != ed25519.SeedSize {
			return nil, fmt.Errorf("%w: a signing seed is not %d bytes", ErrKeyMalformed, ed25519.SeedSize)
		}
	}
	if revoked[ids[0]] {
		return nil, fmt.Errorf("%w: %q", ErrKeyRevoked, ids[0])
	}
	sk := &SigningKeys{kid: ids[0], priv: ed25519.NewKeyFromSeed(seeds[0])}
	type entry struct {
		kid  string
		priv ed25519.PrivateKey
	}
	var live []entry
	defer func() {
		for _, e := range live[1:] {
			zero(e.priv)
		}
	}()
	seen := map[string]bool{}
	for i, id := range ids {
		if revoked[id] {
			continue
		}
		if seen[id] {
			return nil, fmt.Errorf("%w: duplicate kid %q", ErrKeyMalformed, id)
		}
		seen[id] = true
		if i == 0 {
			live = append(live, entry{id, sk.priv})
		} else {
			live = append(live, entry{id, ed25519.NewKeyFromSeed(seeds[i])})
		}
	}
	for i, e := range live {
		pub := e.priv.Public().(ed25519.PublicKey)
		pk := PublicKey{Kid: e.kid, Alg: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}
		if i+1 < len(live) {
			older := live[i+1]
			pk.EndorsedBy, pk.Endorsement = older.kid, policy.Endorse(older.priv, e.kid, pub)
		}
		sk.public = append(sk.public, pk)
	}
	return sk, nil
}

// Kid returns the kid of the active signer.
func (s *SigningKeys) Kid() string { return s.kid }

// Sign signs msg with the active key.
func (s *SigningKeys) Sign(msg []byte) (kid string, sig []byte) {
	return s.kid, ed25519.Sign(s.priv, msg)
}

// Public returns the announced public keys, active key first.
func (s *SigningKeys) Public() []PublicKey { return append([]PublicKey(nil), s.public...) }

// ActivePublic returns the public key of the active signer.
func (s *SigningKeys) ActivePublic() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.priv.Public().(ed25519.PublicKey)...)
}

// Zero overwrites the private key. The signer is unusable afterwards.
func (s *SigningKeys) Zero() { zero(s.priv) }

// String never prints the private key.
func (s *SigningKeys) String() string { return "signing-key(" + s.kid + ")" }

// GoString never prints the private key.
func (s *SigningKeys) GoString() string { return s.String() }

// LogValue never logs the private key.
func (s *SigningKeys) LogValue() slog.Value { return slog.StringValue(s.String()) }

// KeySource tells where to read one key configuration: a file (checked by
// ReadKeyFile) or, when File is empty, inline text (an environment
// variable).
type KeySource struct {
	File   string
	Inline string
}

func (ks KeySource) read() ([]byte, error) {
	if ks.File != "" {
		return ReadKeyFile(ks.File)
	}
	if ks.Inline == "" {
		return nil, ErrKeyMissing
	}
	return []byte(ks.Inline), nil
}

// LoadHMACKeys reads and parses an HMAC key configuration.
func LoadHMACKeys(src KeySource) (*HMACKeys, error) {
	b, err := src.read()
	if err != nil {
		return nil, err
	}
	defer zero(b)
	return ParseHMACKeys(b)
}

// LoadSigningKeys reads and parses a signing key configuration.
func LoadSigningKeys(src KeySource, revoked map[string]bool) (*SigningKeys, error) {
	b, err := src.read()
	if err != nil {
		return nil, err
	}
	defer zero(b)
	return ParseSigningKeys(b, revoked)
}
