package pack_rt

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/mock"
	"github.com/ivseb/traffic-twin/internal/pack"
)

// ---------------------------------------------------------------------------
// Baseline

func TestRT3_Pack_Holds_BaselineArchiveAndDir(t *testing.T) {
	s := newSigner(kid)
	files := demo(t, s, nil)
	mustLoad(t, writeArchive(t, entries(files)), s.keys)
	mustLoad(t, writeDir(t, files), s.keys)
	// rotation list: the pack key among others
	other := newSigner("gate-rt3-0")
	mustLoad(t, writeArchive(t, entries(files)), other.keys+","+s.keys)
}

// ---------------------------------------------------------------------------
// Validity in time (pack.md 2.1)

func TestRT3_Pack_Holds_NotAfter(t *testing.T) {
	s := newSigner(kid)
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	cases := []struct {
		name, created, notAfter string
		want                    error
	}{
		{"expired", at(-48 * time.Hour), at(-time.Hour), pack.ErrExpired},
		{"not_after before created_at", at(-time.Hour), at(-2 * time.Hour), pack.ErrManifest},
		{"not_after equal to created_at", at(-time.Hour), at(-time.Hour), pack.ErrManifest},
		{"not_after not a date-time", at(-time.Hour), "tomorrow", pack.ErrManifest},
		{"not_after with offset already passed", at(-48 * time.Hour), now.Add(-30 * time.Minute).In(time.FixedZone("x", 3600)).Format(time.RFC3339), pack.ErrExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := demo(t, s, func(m map[string]any, _ map[string][]byte) {
				m["created_at"], m["not_after"] = c.created, c.notAfter
			})
			err := mustRefuse(t, writeArchive(t, entries(files)), s.keys, c.name)
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
	t.Run("boundary now == not_after is expired", func(t *testing.T) {
		na := now.Add(time.Hour).Truncate(time.Second)
		files := demo(t, s, func(m map[string]any, _ map[string][]byte) { m["not_after"] = na.Format(time.RFC3339) })
		_, err := pack.Load(writeArchive(t, entries(files)), pack.Options{Keys: keySet(t, s.keys), Now: func() time.Time { return na }})
		if !errors.Is(err, pack.ErrExpired) {
			t.Fatalf("want pack_expired at not_after, got %v", err)
		}
	})
	t.Run("not_after absent never expires (by spec)", func(t *testing.T) {
		files := demo(t, s, nil)
		mustLoad(t, writeArchive(t, entries(files)), s.keys)
	})
	t.Run("max-pack-age local policy", func(t *testing.T) {
		files := demo(t, s, func(m map[string]any, _ map[string][]byte) { m["created_at"] = at(-72 * time.Hour) })
		if _, err := newMock(writeArchive(t, entries(files)), s.keys, 24*time.Hour); !errors.Is(err, pack.ErrExpired) {
			t.Fatalf("want pack_expired for --max-pack-age, got %v", err)
		}
	})
}

// The CLI end to end: `tt mock --pack x.ttpack` with TT_GATE_PUBKEYS
// refuses an expired pack before listening (exit 1, pack_expired).
func TestRT3_Pack_Holds_CLIRefusesExpired(t *testing.T) {
	s := newSigner(kid)
	now := time.Now().UTC()
	files := demo(t, s, func(m map[string]any, _ map[string][]byte) {
		m["created_at"], m["not_after"] = now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339)
	})
	t.Setenv("TT_GATE_PUBKEYS", s.keys)
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := mock.RunCLI(ctx, []string{"--pack", writeArchive(t, entries(files)), "--addr", "127.0.0.1:0", "--quiet"}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "pack_expired") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

// RT3-PACK-2. created_at is never compared with the verifier's clock: a
// pack dated in the future passes --max-pack-age (now - created_at is
// negative), and keyguard signs such a manifest (see keyguard_test.go).
func TestRT3_Pack_FutureCreatedAtBypassesMaxPackAge_Fixed(t *testing.T) {
	s := newSigner(kid)
	files := demo(t, s, func(m map[string]any, _ map[string][]byte) {
		m["created_at"] = time.Now().UTC().AddDate(5, 0, 0).Format(time.RFC3339)
	})
	m, err := newMock(writeArchive(t, entries(files)), s.keys, 24*time.Hour)
	if err == nil {
		t.Fatalf("FINDING RT3-PACK-2: tt mock --max-pack-age 24h accepted pack %s created 5 years in the future", m.PackID())
	}
}

// ---------------------------------------------------------------------------
// Keys and signature

func TestRT3_Pack_Holds_Signature(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	cases := []struct {
		name string
		keys string
		mut  func(f map[string][]byte)
		want error
	}{
		{"unknown kid", newSigner("gate-rt3-x").keys, nil, pack.ErrUnknownKey},
		{"same kid, other key", newSigner(kid).keys, nil, pack.ErrBadSignature},
		{"unsigned", s.keys, func(f map[string][]byte) { delete(f, "manifest.sig.json") }, pack.ErrUnsigned},
		{"manifest changed after signing", s.keys, func(f map[string][]byte) {
			f["manifest.json"] = bytes.Replace(f["manifest.json"], []byte(`"seed":42`), []byte(`"seed":43`), 1)
		}, pack.ErrBadSignature},
		{"manifest changed and manifest_sha256 recomputed", s.keys, func(f map[string][]byte) {
			old := sha256.Sum256(f["manifest.json"])
			f["manifest.json"] = bytes.Replace(f["manifest.json"], []byte(`"seed":42`), []byte(`"seed":43`), 1)
			nw := sha256.Sum256(f["manifest.json"])
			f["manifest.sig.json"] = bytes.Replace(f["manifest.sig.json"], []byte(hex.EncodeToString(old[:])), []byte(hex.EncodeToString(nw[:])), 1)
		}, pack.ErrBadSignature},
		{"trailing newline removed from manifest", s.keys, func(f map[string][]byte) {
			f["manifest.json"] = bytes.TrimSuffix(f["manifest.json"], []byte("\n"))
		}, pack.ErrBadSignature},
		{"signature of another pack", s.keys, func(f map[string][]byte) {
			other := demo(t, s, func(m map[string]any, _ map[string][]byte) { m["pack_id"] = "pk-other-0001" })
			f["manifest.sig.json"] = other["manifest.sig.json"]
		}, pack.ErrBadSignature},
		{"alg none", s.keys, func(f map[string][]byte) {
			f["manifest.sig.json"] = bytes.Replace(f["manifest.sig.json"], []byte(`"Ed25519"`), []byte(`"none"`), 1)
		}, pack.ErrBadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := clone(base)
			if c.mut != nil {
				c.mut(f)
			}
			err := mustRefuse(t, writeArchive(t, entries(f)), c.keys, c.name)
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

// RT3-PACK-1. There is no way to tell tt mock that a gate key is revoked.
// During a rotation the documented setup trusts old and new kid together
// (TT_GATE_PUBKEYS "gate-old:…,gate-new:…"); when keyguard revokes the old
// one (TT_KEYGUARD_REVOKED_KIDS) it only stops announcing it, every mock
// configuration keeps trusting it, and packs have no expiry by default
// (valid_days unset), so a pack signed with a leaked old key is accepted
// forever. The fix is
// TT_GATE_REVOKED_KIDS.
func TestRT3_Pack_RevokedGateKeyStillTrusted_Fixed(t *testing.T) {
	old, nw := newSigner("gate-rt3-old"), newSigner("gate-rt3-new")
	files := demo(t, old, nil) // signed with the leaked, revoked key
	t.Setenv("TT_GATE_REVOKED_KIDS", "gate-rt3-old")
	m, err := newMock(writeArchive(t, entries(files)), old.keys+","+nw.keys, 0)
	if err == nil {
		t.Fatalf("FINDING RT3-PACK-1: pack %s signed by revoked kid gate-rt3-old accepted: tt mock has no revocation list for gate keys and the pack has no not_after", m.PackID())
	}
}

// ---------------------------------------------------------------------------
// Archive tampering

func TestRT3_Pack_Holds_ArchiveNames(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	bad := []string{
		"../evil.json", "../../tmp/evil.json", "/etc/evil.json", "/tmp/rules.json",
		`..\evil.json`, `contracts\..\..\evil.json`, "contracts/../rules.json", "./../evil.json",
		"contracts//shop.json", "C:/evil.json", ".hidden.json", "contracts/.x.json",
		"rul\u00e9s.json", "rule\u0301s.json", "rules.json ", "rules.json\n",
	}
	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			es := append(entries(base), entry{name: name, data: []byte("{}\n")})
			err := mustRefuse(t, writeArchive(t, es), s.keys, "entry "+name)
			if !errors.Is(err, pack.ErrFiles) {
				t.Fatalf("want ErrFiles, got %v", err)
			}
		})
	}
	// The loader writes nothing to disk, so a traversal could only matter
	// to a later extractor; also check nothing appeared next to the pack.
	dir := t.TempDir()
	es := append(entries(base), entry{name: "../rt3-escaped.json", data: []byte("{}\n")})
	p := writeArchive(t, es)
	_ = mustRefuse(t, p, s.keys, "traversal")
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(p)), "rt3-escaped.json")); err == nil {
		t.Fatal("a traversal entry was extracted")
	}
	_ = dir
}

func TestRT3_Pack_Holds_NonRegularEntries(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	cases := []struct {
		name string
		e    entry
	}{
		{"symlink as listed file", entry{name: "rules.json", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		{"symlink to sibling", entry{name: "rules.json", typ: tar.TypeSymlink, link: "faults.json"}},
		{"hard link", entry{name: "rules.json", typ: tar.TypeLink, link: "faults.json"}},
		{"char device", entry{name: "rules.json", typ: tar.TypeChar}},
		{"fifo", entry{name: "rules.json", typ: tar.TypeFifo}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := clone(base)
			delete(f, c.e.name)
			es := append(entries(f), c.e)
			err := mustRefuse(t, writeArchive(t, es), s.keys, c.name)
			if !errors.Is(err, pack.ErrFiles) {
				t.Fatalf("want ErrFiles, got %v", err)
			}
		})
	}
	t.Run("symlink in a pack directory", func(t *testing.T) {
		f := clone(base)
		delete(f, "rules.json")
		dir := writeDir(t, f)
		if err := os.WriteFile(filepath.Join(t.TempDir(), "x"), base["rules.json"], 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "faults.json"), filepath.Join(dir, "rules.json")); err != nil {
			t.Fatal(err)
		}
		if err := mustRefuse(t, dir, s.keys, "dir symlink"); !errors.Is(err, pack.ErrFiles) {
			t.Fatalf("want ErrFiles, got %v", err)
		}
	})
}

func TestRT3_Pack_Holds_DuplicateAndCaseEntries(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	evil := []byte(`{"format":"tt.rules/v1","rules":[]}` + "\n")
	cases := []struct {
		name  string
		extra []entry
	}{
		{"same name twice (second differs)", []entry{{name: "rules.json", data: evil}}},
		{"./ prefix duplicate", []entry{{name: "./rules.json", data: evil}}},
		{"second manifest", []entry{{name: "./manifest.json", data: base["manifest.json"]}}},
		{"second signature", []entry{{name: "./manifest.sig.json", data: base["manifest.sig.json"]}}},
		{"case variant", []entry{{name: "Rules.json", data: evil}}},
		{"case variant of manifest", []entry{{name: "MANIFEST.json", data: base["manifest.json"]}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			es := append(entries(base), c.extra...)
			err := mustRefuse(t, writeArchive(t, es), s.keys, c.name)
			if !errors.Is(err, pack.ErrFiles) {
				t.Fatalf("want ErrFiles, got %v", err)
			}
		})
	}
	t.Run("duplicate first, original second", func(t *testing.T) {
		es := append([]entry{{name: "rules.json", data: evil}}, entries(base)...)
		if err := mustRefuse(t, writeArchive(t, es), s.keys, "dup first"); !errors.Is(err, pack.ErrFiles) {
			t.Fatalf("want ErrFiles, got %v", err)
		}
	})
}

func TestRT3_Pack_Holds_ManifestFileList(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	cases := []struct {
		name string
		mut  func(f map[string][]byte)
		want error
	}{
		{"extra unlisted file", func(f map[string][]byte) { f["notes.json"] = []byte("{}\n") }, pack.ErrFiles},
		{"listed file missing", func(f map[string][]byte) { delete(f, "faults.json") }, pack.ErrFiles},
		{"hash mismatch, same size", func(f map[string][]byte) {
			b := f["world.jsonl"]
			i := bytes.Index(b, []byte("Giulia"))
			if i < 0 {
				i = len(b) / 2
			}
			b[i] ^= 0x01
		}, pack.ErrFiles},
		{"file grows", func(f map[string][]byte) { f["faults.json"] = append(f["faults.json"], ' ') }, pack.ErrFiles},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := clone(base)
			c.mut(f)
			for _, p := range []string{writeArchive(t, entries(f)), writeDir(t, f)} {
				if err := mustRefuse(t, p, s.keys, c.name); !errors.Is(err, c.want) {
					t.Fatalf("%s: want %v, got %v", p, c.want, err)
				}
			}
		})
	}
	// Signed manifests that are internally inconsistent.
	signed := []struct {
		name string
		mut  func(m map[string]any, files map[string][]byte)
	}{
		{"gate report of another pack", func(_ map[string]any, files map[string][]byte) {
			files["gate-report.json"] = bytes.Replace(files["gate-report.json"], []byte(`"pk-20261019-0001"`), []byte(`"pk-other-0001"`), 1)
		}},
		{"gate verdict fail", func(_ map[string]any, files map[string][]byte) {
			files["gate-report.json"] = bytes.Replace(files["gate-report.json"], []byte(`"verdict":"pass"`), []byte(`"verdict":"fail"`), 1)
		}},
		{"referenced contract not listed", func(m map[string]any, files map[string][]byte) {
			delete(files, "contracts/shipping-ext.openapi.json")
		}},
		{"unknown manifest field", func(m map[string]any, _ map[string][]byte) { m["extra"] = "x" }},
	}
	for _, c := range signed {
		t.Run(c.name, func(t *testing.T) {
			f := demo(t, s, c.mut)
			_ = mustRefuse(t, writeArchive(t, entries(f)), s.keys, c.name)
		})
	}
}

// Declared tar sizes: a header larger than the per-file cap is refused
// without reading; a header that lies about the size is refused.
func TestRT3_Pack_Holds_DeclaredSizes(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	t.Run("entry above 256 MiB", func(t *testing.T) {
		es := append(entries(base), entry{name: "zz.json", zeros: 300 << 20, headerOnly: true})
		if err := mustRefuse(t, writeArchive(t, es), s.keys, "huge entry"); !errors.Is(err, pack.ErrFiles) {
			t.Fatalf("want ErrFiles, got %v", err)
		}
	})
	t.Run("truncated entry", func(t *testing.T) {
		es := append(entries(base), entry{name: "zz.json", zeros: 1 << 20, headerOnly: true})
		if err := mustRefuse(t, writeArchive(t, es), s.keys, "truncated"); !errors.Is(err, pack.ErrFiles) {
			t.Fatalf("want ErrFiles, got %v", err)
		}
	})
	t.Run("not gzip", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.ttpack")
		_ = os.WriteFile(p, []byte("PK\x03\x04 not a tar.gz"), 0o644)
		if err := mustRefuse(t, p, s.keys, "zip"); !errors.Is(err, pack.ErrFiles) {
			t.Fatalf("want ErrFiles, got %v", err)
		}
	})
}

// RT3-PACK-3. The whole archive is decompressed into memory before the
// signature is checked: an unsigned .ttpack of ~200 KiB (gzip of zeros)
// makes tt mock allocate hundreds of MiB (up to the 1 GiB total cap, plus
// io.ReadAll growth) before refusing it. Expectation: an unsigned or
// untrusted pack is refused after reading O(manifest) bytes.
func TestRT3_Pack_ZipBombBeforeSignature_Fixed(t *testing.T) {
	s := newSigner(kid)
	base := demo(t, s, nil)
	delete(base, "manifest.sig.json") // not even signed
	es := append([]entry{{name: "aaa.json", zeros: 192 << 20}}, entries(base)...)
	p := writeArchive(t, es)
	st, _ := os.Stat(p)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := newMock(p, s.keys, 0)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("unsigned pack accepted")
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("archive %d KiB on disk, %d MiB allocated before refusing (%v)", st.Size()>>10, alloc>>20, err)
	if alloc > 64<<20 {
		t.Fatalf("FINDING RT3-PACK-3: an unsigned %d KiB archive made the loader allocate %d MiB before the signature check", st.Size()>>10, alloc>>20)
	}
}

// RT3-PACK-4. The spec makes every pack JSON file canonical tt JSON, but
// neither keyguard (encoding/json, see keyguard_test.go) nor the loader
// enforce it on manifest.json: duplicate keys (last one wins in Go, the
// first one in many other parsers) and case-variant keys (encoding/json
// matches "PACK_ID" to pack_id) are accepted, so two verifiers can read
// different manifests out of the same signed bytes.
func TestRT3_Pack_NonCanonicalManifestAccepted_Fixed(t *testing.T) {
	s := newSigner(kid)
	cases := map[string]func([]byte) []byte{
		"duplicate not_after (first expired, last valid)": func(m []byte) []byte {
			return bytes.Replace(m, []byte(`{"created_at"`), []byte(`{"not_after":"2026-01-01T00:00:00Z","created_at"`), 1)
		},
		"case-variant key": func(m []byte) []byte {
			return bytes.Replace(m, []byte(`"pack_id":`), []byte(`"PACK_ID":"pk-shadow-0001","pack_id":`), 1)
		},
		"pretty-printed": func(m []byte) []byte { return bytes.ReplaceAll(m, []byte(`,"`), []byte(", \"")) },
	}
	var accepted []string
	for name, mut := range cases {
		files := demo(t, s, func(m map[string]any, _ map[string][]byte) {
			m["not_after"] = time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)
		})
		mb := mut(files["manifest.json"])
		if bytes.Equal(mb, files["manifest.json"]) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		files["manifest.json"], files["manifest.sig.json"] = mb, s.sign(mb)
		if _, err := newMock(writeArchive(t, entries(files)), s.keys, 0); err == nil {
			accepted = append(accepted, name)
		}
	}
	if len(accepted) > 0 {
		t.Fatalf("FINDING RT3-PACK-4: signed non-canonical manifests accepted by tt mock: %q", accepted)
	}
}

// RT3-PACK-5 (info). A pack directory touched by a desktop file manager
// (.DS_Store on macOS) is refused as a whole with a confusing error: the
// loader refuses any unlisted file (right) but names starting with "." are
// rejected even before the listing check. Kept as a guard of the strict
// behaviour, reported as an operability note only.
func TestRT3_Pack_Holds_DirectoryRejectsDotFiles(t *testing.T) {
	s := newSigner(kid)
	f := demo(t, s, nil)
	dir := writeDir(t, f)
	_ = os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte{0, 0, 0, 1}, 0o644)
	if err := mustRefuse(t, dir, s.keys, ".DS_Store"); !errors.Is(err, pack.ErrFiles) {
		t.Fatalf("want ErrFiles, got %v", err)
	}
}

// A running mock warns when not_after passes (pack.md 2.1).
func TestRT3_Pack_Holds_RunningMockWarnsAtNotAfter(t *testing.T) {
	s := newSigner(kid)
	na := time.Now().UTC().Add(2 * time.Second).Truncate(time.Second).Add(time.Second)
	files := demo(t, s, func(m map[string]any, _ map[string][]byte) { m["not_after"] = na.Format(time.RFC3339) })
	t.Setenv("TT_GATE_PUBKEYS", s.keys)
	var out, errb syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- mock.RunCLI(ctx, []string{"--pack", writeArchive(t, entries(files)), "--addr", "127.0.0.1:0"}, &out, &errb)
	}()
	deadline := time.Now().Add(time.Until(na) + 3*time.Second)
	for !strings.Contains(errb.String(), "pack validity ended") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("no expiry warning; stderr: %s", errb.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
}
