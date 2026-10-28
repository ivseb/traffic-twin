package pack

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"unicode"
)

// EnvGatePubKeys is the environment variable that carries the trusted keys.
const EnvGatePubKeys = "TT_GATE_PUBKEYS"

var kidRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// KeySet maps a key id to a trusted gate public key.
type KeySet map[string]ed25519.PublicKey

// ParseKeySet parses a key list. spec is either an inline list of
// "kid:base64url" entries separated by commas (or newlines), or the path of a
// file with one entry per line ("#" comments and blank lines are ignored).
func ParseKeySet(spec string) (KeySet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("pack: no trusted keys configured (" + EnvGatePubKeys + " is empty)")
	}
	text := spec
	if st, err := os.Stat(spec); err == nil && st.Mode().IsRegular() {
		// The key file is the root of trust of every pack: whoever can write
		// it can make the verifier trust their own key.
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("pack: key file %s is writable by group or others (mode %04o): chmod go-w it", spec, st.Mode().Perm())
		}
		b, err := os.ReadFile(spec)
		if err != nil {
			return nil, fmt.Errorf("pack: read key file: %w", err)
		}
		text = string(b)
	}
	ks := KeySet{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, entry := range strings.Split(line, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			kid, b64, ok := strings.Cut(entry, ":")
			if !ok || !kidRE.MatchString(kid) {
				return nil, errors.New("pack: malformed key entry (want kid:base64url)")
			}
			raw, err := decodeB64URL(b64)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("pack: key %q is not a base64url Ed25519 public key", kid)
			}
			if _, dup := ks[kid]; dup {
				return nil, fmt.Errorf("pack: duplicate key id %q", kid)
			}
			ks[kid] = ed25519.PublicKey(raw)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ks) == 0 {
		return nil, errors.New("pack: no trusted keys configured")
	}
	return ks, nil
}

// KeySetFromEnv reads TT_GATE_PUBKEYS.
func KeySetFromEnv() (KeySet, error) { return ParseKeySet(os.Getenv(EnvGatePubKeys)) }

// EnvGateRevokedKIDs is the environment variable that lists gate key ids
// that must no longer be trusted, even if they are still in
// TT_GATE_PUBKEYS (a rotation keeps old and new keys side by side; when the
// old key leaks or is retired, list it here).
const EnvGateRevokedKIDs = "TT_GATE_REVOKED_KIDS"

// ParseRevokedKIDs parses a comma, space or newline separated list of key ids.
func ParseRevokedKIDs(spec string) ([]string, error) {
	var out []string
	for _, kid := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if !kidRE.MatchString(kid) {
			return nil, fmt.Errorf("pack: malformed key id %q in %s", kid, EnvGateRevokedKIDs)
		}
		out = append(out, kid)
	}
	return out, nil
}

// RevokedKIDsFromEnv reads TT_GATE_REVOKED_KIDS.
func RevokedKIDsFromEnv() ([]string, error) {
	return ParseRevokedKIDs(os.Getenv(EnvGateRevokedKIDs))
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
