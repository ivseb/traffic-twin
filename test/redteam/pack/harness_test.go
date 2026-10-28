// Package pack_rt red-teams twin-pack verification (red team round 3):
// the loader used by `tt mock` (internal/pack via internal/mock) and the
// signing step of keyguard (pack/sign, the publish path of tt-core).
//
// Run:  go test ./test/redteam/pack/ -count=1 -v
//
// Tests named TestRT3_Pack_*_Fails are reproducers of open findings: they fail
// while the weakness exists; once fixed they are renamed *_Fixed and stay as regressions. TestRT3_Pack_Holds_* are guards that pass.
// Every key and value is invented per test.
package pack_rt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

const kid = "gate-rt3-1"

// signer is a test gate key (same format as keyguard's pack key).
type signer struct {
	b    *packtest.Built
	keys string // TT_GATE_PUBKEYS entry
}

func newSigner(k string) *signer {
	priv, keys := packtest.NewKey(k)
	return &signer{b: &packtest.Built{KID: k, Priv: priv, Keys: keys}, keys: keys}
}

func (s *signer) sign(manifest []byte) []byte { return s.b.Sign(manifest, s.b.KID) }

func (s *signer) pub() ed25519.PublicKey { return s.b.Priv.Public().(ed25519.PublicKey) }

// demo returns the files of the demo pack (manifest.json and
// manifest.sig.json included), after mut has changed the manifest fields
// and the files. The manifest is recomputed (hashes) and signed by s.
func demo(t *testing.T, s *signer, mut func(m map[string]any, files map[string][]byte)) map[string][]byte {
	t.Helper()
	spec := packtest.DemoSpec()
	spec.Manifest["created_at"] = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if mut != nil {
		mut(spec.Manifest, spec.Files)
	}
	mb, err := packtest.ManifestBytes(spec)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for k, v := range spec.Files {
		out[k] = v
	}
	out["manifest.json"] = mb
	out["manifest.sig.json"] = s.sign(mb)
	return out
}

// entry is one tar entry; typ 0 means a regular file.
type entry struct {
	name  string
	typ   byte
	data  []byte
	link  string
	zeros int64 // when > 0: data is this many zero bytes (streamed)
	// headerOnly writes the header (with Size = zeros or len(data)) and
	// no content: a truncated archive whose header lies about the size.
	headerOnly bool
}

// entries turns a file map into sorted regular entries.
func entries(files map[string][]byte) []entry {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]entry, 0, len(names))
	for _, n := range names {
		out = append(out, entry{name: n, data: files[n]})
	}
	return out
}

// writeArchive writes a .ttpack (gzip tar) with exactly the given entries.
func writeArchive(t *testing.T, es []entry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pack.ttpack")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	tw := tar.NewWriter(zw)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := int64(len(e.data))
		if e.zeros > 0 {
			size = e.zeros
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Linkname: e.link, Format: tar.FormatPAX}
		if typ == tar.TypeReg {
			h.Size = size
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("header %q: %v", e.name, err)
		}
		if e.headerOnly {
			_ = tw.Flush() // error expected: content missing
			_ = zw.Close()
			return p
		}
		if typ != tar.TypeReg {
			continue
		}
		if e.zeros > 0 {
			if _, err := io.CopyN(tw, zeroReader{}, e.zeros); err != nil {
				t.Fatal(err)
			}
		} else if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// writeDir writes a pack directory.
func writeDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pack")
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// newMock loads a pack the way `tt mock` does (mock.New: key list, then
// pack.Load, then the model).
func newMock(path, keys string, maxAge time.Duration) (*mock.Mock, error) {
	return mock.New(mock.Config{Pack: path, GatePubKeys: keys, MaxPackAge: maxAge,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func mustLoad(t *testing.T, path, keys string) {
	t.Helper()
	if _, err := newMock(path, keys, 0); err != nil {
		t.Fatalf("valid pack refused: %v", err)
	}
}

func mustRefuse(t *testing.T, path, keys, what string) error {
	t.Helper()
	m, err := newMock(path, keys, 0)
	if err == nil {
		t.Fatalf("%s: tt mock accepted the pack %s", what, m.PackID())
	}
	return err
}

func contains(err error, s string) bool { return err != nil && strings.Contains(err.Error(), s) }

// clone copies a file map.
func clone(files map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range files {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func keySet(t *testing.T, spec string) pack.KeySet {
	t.Helper()
	ks, err := pack.ParseKeySet(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// syncBuf is a goroutine-safe buffer (mock logs while the test reads).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
