// Package packtest builds small signed twin packs for tests (demo carrier
// scenario). It is test support only: real packs are written and signed by the
// gate and keyguard, never by this package.
package packtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Spec is an unsigned pack: manifest fields plus the files to write.
type Spec struct {
	// Manifest holds every manifest field except "files".
	Manifest map[string]any
	// Files maps a pack path to its bytes (everything except the manifest and
	// its signature).
	Files map[string][]byte
}

// Built is a signed pack written to disk.
type Built struct {
	Dir  string
	KID  string
	Priv ed25519.PrivateKey
	// Keys is the TT_GATE_PUBKEYS value that trusts this pack.
	Keys string
}

// NewKey generates a signing key and its TT_GATE_PUBKEYS entry.
func NewKey(kid string) (ed25519.PrivateKey, string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, kid + ":" + base64.RawURLEncoding.EncodeToString(pub)
}

// Build completes the manifest (files list with hashes), signs it and writes
// the pack into dir.
func Build(dir string, spec Spec) (*Built, error) {
	priv, keys := NewKey("gate-test-1")
	b := &Built{Dir: dir, KID: "gate-test-1", Priv: priv, Keys: keys}
	if err := b.Write(spec); err != nil {
		return nil, err
	}
	return b, nil
}

// Write (re)writes the pack into b.Dir signed with b's key.
func (b *Built) Write(spec Spec) error {
	manifest, err := ManifestBytes(spec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.Dir, 0o755); err != nil {
		return err
	}
	for name, data := range spec.Files {
		p := filepath.Join(b.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(b.Dir, "manifest.json"), manifest, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(b.Dir, "manifest.sig.json"), b.Sign(manifest, b.KID), 0o644)
}

// Sign returns manifest.sig.json for the given manifest bytes and kid.
func (b *Built) Sign(manifest []byte, kid string) []byte {
	msg := append([]byte("tt.pack/v1\x00"), manifest...)
	sum := sha256.Sum256(manifest)
	sig := ed25519.Sign(b.Priv, msg)
	return CJSON(map[string]any{
		"format":          "tt.pack.sig/v1",
		"alg":             "Ed25519",
		"kid":             kid,
		"manifest_sha256": hex.EncodeToString(sum[:]),
		"sig":             base64.RawURLEncoding.EncodeToString(sig),
	})
}

// ManifestBytes renders the canonical manifest.json of a spec.
func ManifestBytes(spec Spec) ([]byte, error) {
	m := map[string]any{}
	for k, v := range spec.Manifest {
		m[k] = v
	}
	names := make([]string, 0, len(spec.Files))
	for n := range spec.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	files := []any{}
	for _, n := range names {
		sum := sha256.Sum256(spec.Files[n])
		files = append(files, map[string]any{"path": n, "sha256": hex.EncodeToString(sum[:]), "bytes": len(spec.Files[n])})
	}
	m["files"] = files
	return CJSON(m), nil
}

// CJSON renders v as canonical tt JSON (sorted keys, ASCII, no spaces) with a
// trailing newline. Supported: map[string]any, []any, string, bool, nil,
// json.Number, ints and float64.
func CJSON(v any) []byte {
	var buf bytes.Buffer
	writeC(&buf, v)
	buf.WriteByte('\n')
	return buf.Bytes()
}

// CLine is CJSON without the trailing newline.
func CLine(v any) []byte { return bytes.TrimSuffix(CJSON(v), []byte("\n")) }

// Lines joins values as canonical JSON lines (world.jsonl).
func Lines(vs ...any) []byte {
	var out []byte
	for _, v := range vs {
		out = append(out, CJSON(v)...)
	}
	return out
}

// JSON parses a JSON literal into generic values (numbers as json.Number).
func JSON(s string) any {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		panic(fmt.Sprintf("packtest: bad JSON literal: %v", err))
	}
	return v
}

// Canon parses a JSON literal and renders it canonically.
func Canon(s string) []byte { return CJSON(JSON(s)) }

func writeC(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case string:
		writeCString(buf, x)
	case json.Number:
		buf.WriteString(canonNumber(string(x)))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case float64:
		buf.WriteString(canonNumber(strconv.FormatFloat(x, 'f', -1, 64)))
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeC(buf, e)
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCString(buf, k)
			buf.WriteByte(':')
			writeC(buf, x[k])
		}
		buf.WriteByte('}')
	default:
		panic(fmt.Sprintf("packtest: unsupported type %T", v))
	}
}

func canonNumber(s string) string {
	if strings.ContainsAny(s, "eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			panic(err)
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	if s == "-0" || s == "" {
		return "0"
	}
	return s
}

func writeCString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r < 0x20 || r == 0x7f || r > 0x7e:
			if r > 0xffff {
				r -= 0x10000
				fmt.Fprintf(buf, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			} else {
				fmt.Fprintf(buf, `\u%04x`, r)
			}
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}
