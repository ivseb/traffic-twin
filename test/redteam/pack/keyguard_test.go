package pack_rt

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// kgEnv is an in-process keyguard with a known pack key and one signed
// policy (p-shop v7, the policy the demo manifest names).
type kgEnv struct {
	svc  *keyguard.Service
	keys string // TT_GATE_PUBKEYS entry for keyguard's pack key
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rndb(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }

func newKG(t *testing.T) *kgEnv {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	seed := rndb(32)
	cfg := keyguard.DefaultConfig()
	cfg.DBPath = filepath.Join(dir, "kg.db")
	cfg.HMACKeys = keyguard.KeySource{File: write("hmac.keys", "k1:"+b64u(rndb(32))+"\n")}
	cfg.PolicyKey = keyguard.KeySource{File: write("policy.key", "policy-rt3-1:"+b64u(rndb(32))+"\n")}
	cfg.PackKey = keyguard.KeySource{File: write("pack.key", "gate-rt3-kg:"+b64u(seed)+"\n")}
	cfg.BloomCapacity = 10000
	cfg.PackInterval = 0
	svc, err := keyguard.New(context.Background(), cfg, keyguard.Options{Logger: keyguard.NewLogger(io.Discard, "error", "json")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	e := &kgEnv{svc: svc, keys: "gate-rt3-kg:" + b64u(pub)}

	author := `{"format":"tt.policy/v1","policy_id":"p-shop","default":"drop","hmac":{"kid":"k1","epoch":"2026-10"},
 "sampling":{"rate":0.05},"services":{"shop-api":{"match":{"inbound":true},"ops":{
   "POST /orders":{"response":{"$.id":"hmac(order)","$.status":"keep"}}}}}}`
	d := json.NewDecoder(strings.NewReader(author))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := policy.Compile(a, policy.CompileMeta{Version: 7, IssuedSeq: 1, CreatedAt: time.Now().UTC().Truncate(time.Second), Groups: []string{"demo"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := svc.SignPolicy(context.Background(), body, "olga", []keyguard.Approval{
		{User: "pia", Roles: []string{keyguard.RolePolicyApprover}, At: now},
		{User: "pete", Roles: []string{keyguard.RolePolicyApprover}, At: now},
	}); err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	return e
}

// archiveBytes renders entries as a .ttpack without manifest.sig.json.
func archiveBytes(t *testing.T, es []entry) []byte {
	t.Helper()
	b, err := os.ReadFile(writeArchive(t, es))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unsigned(files map[string][]byte) map[string][]byte {
	f := clone(files)
	delete(f, "manifest.sig.json")
	return f
}

func kgCode(err error) string {
	var e *keyguard.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// The publish path end to end: keyguard signs the demo pack and tt mock,
// trusting keyguard's pack key, loads it.
func TestRT3_Pack_Holds_KeyguardSignedLoadsInMock(t *testing.T) {
	kg := newKG(t)
	s := newSigner(kid) // only to build the files; keyguard re-signs
	files := unsigned(demo(t, s, nil))
	res, err := kg.svc.SignPack(context.Background(), archiveBytes(t, entries(files)), nil)
	if err != nil {
		t.Fatalf("keyguard refused the demo pack: %v", err)
	}
	files["manifest.sig.json"] = res.Signature.SigFile()
	mustLoad(t, writeArchive(t, entries(files)), kg.keys)
	// Ed25519 is deterministic: the release signature equals the build one.
	res2, err := kg.svc.SignPack(context.Background(), archiveBytes(t, entries(unsigned(files))),
		&keyguard.Approval{User: "paul", Roles: []string{keyguard.RolePublisher}, At: time.Now().UTC()})
	if err != nil || res2.Signature.Sig != res.Signature.Sig {
		t.Fatalf("release signature differs or refused: %v", err)
	}
}

func TestRT3_Pack_Holds_KeyguardRefusesTamperedArchives(t *testing.T) {
	kg := newKG(t)
	s := newSigner(kid)
	base := unsigned(demo(t, s, nil))
	evil := []byte(`{"format":"tt.rules/v1","rules":[]}` + "\n")
	cases := []struct {
		name string
		es   func() []entry
		code string
	}{
		{"traversal name", func() []entry { return append(entries(base), entry{name: "../evil.json", data: []byte("{}\n")}) }, "invalid_pack"},
		{"absolute name", func() []entry { return append(entries(base), entry{name: "/tmp/evil.json", data: []byte("{}\n")}) }, "invalid_pack"},
		{"backslash name", func() []entry { return append(entries(base), entry{name: `..\evil.json`, data: []byte("{}\n")}) }, "invalid_pack"},
		{"symlink", func() []entry {
			f := clone(base)
			delete(f, "rules.json")
			return append(entries(f), entry{name: "rules.json", typ: tar.TypeSymlink, link: "/etc/passwd"})
		}, "invalid_pack"},
		{"hard link", func() []entry {
			f := clone(base)
			delete(f, "rules.json")
			return append(entries(f), entry{name: "rules.json", typ: tar.TypeLink, link: "faults.json"})
		}, "invalid_pack"},
		{"duplicate entry", func() []entry { return append(entries(base), entry{name: "rules.json", data: evil}) }, "invalid_pack"},
		{"./ duplicate", func() []entry { return append(entries(base), entry{name: "./rules.json", data: evil}) }, "invalid_pack"},
		{"signature inside", func() []entry {
			return append(entries(base), entry{name: "manifest.sig.json", data: []byte("{}\n")})
		}, "invalid_pack"},
		{"unlisted file", func() []entry { return append(entries(base), entry{name: "notes.json", data: []byte("{}\n")}) }, "hash_mismatch"},
		{"case variant unlisted", func() []entry { return append(entries(base), entry{name: "Rules.json", data: evil}) }, "hash_mismatch"},
		{"hash mismatch", func() []entry {
			f := clone(base)
			f["faults.json"] = append(f["faults.json"][:len(f["faults.json"])-2], ' ', '\n')
			return entries(f)
		}, "hash_mismatch"},
		{"listed file missing", func() []entry {
			f := clone(base)
			delete(f, "faults.json")
			return entries(f)
		}, "hash_mismatch"},
		{"entry above cap", func() []entry {
			return append(entries(base), entry{name: "zz.json", zeros: 300 << 20, headerOnly: true})
		}, "invalid_pack"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := kg.svc.SignPack(context.Background(), archiveBytes(t, c.es()), nil)
			if kgCode(err) != c.code {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
	signed := []struct {
		name string
		mut  func(m map[string]any, files map[string][]byte)
		code string
	}{
		{"gate report of another pack", func(_ map[string]any, f map[string][]byte) {
			f["gate-report.json"] = bytes.Replace(f["gate-report.json"], []byte(`"pk-20261019-0001"`), []byte(`"pk-other-0001"`), 1)
		}, "gate_report"},
		{"gate check missing", func(_ map[string]any, f map[string][]byte) {
			f["gate-report.json"] = bytes.Replace(f["gate-report.json"], []byte(`"provenance"`), []byte(`"provenance-x"`), 1)
		}, "gate_report"},
		{"not_after before created_at", func(m map[string]any, _ map[string][]byte) {
			m["not_after"] = time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
		}, "invalid_pack"},
		{"policy never signed", func(m map[string]any, _ map[string][]byte) {
			m["source"] = map[string]any{"window": map[string]any{"from": "2026-10-05T00:00:00Z", "to": "2026-10-19T00:00:00Z"},
				"policies": []any{map[string]any{"id": "p-shop", "version": 99}}}
		}, "unknown_policy"},
	}
	for _, c := range signed {
		t.Run(c.name, func(t *testing.T) {
			f := unsigned(demo(t, s, c.mut))
			_, err := kg.svc.SignPack(context.Background(), archiveBytes(t, entries(f)), nil)
			if kgCode(err) != c.code {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
}

// RT3-PACK-2, keyguard side: keyguard signs a manifest whose created_at is
// years in the future (it only parses it), so a compromised or buggy
// tt-core gets packs that defeat the --max-pack-age policy of every mock.
func TestRT3_Pack_KeyguardSignsFutureCreatedAt_Fixed(t *testing.T) {
	kg := newKG(t)
	s := newSigner(kid)
	files := unsigned(demo(t, s, func(m map[string]any, _ map[string][]byte) {
		m["created_at"] = time.Now().UTC().AddDate(5, 0, 0).Format(time.RFC3339)
	}))
	res, err := kg.svc.SignPack(context.Background(), archiveBytes(t, entries(files)), nil)
	if err != nil {
		return // fixed
	}
	files["manifest.sig.json"] = res.Signature.SigFile()
	_, merr := newMock(writeArchive(t, entries(files)), kg.keys, 24*time.Hour)
	t.Fatalf("FINDING RT3-PACK-2: keyguard signed a pack created 5 years in the future (kid %s); tt mock --max-pack-age 24h on it: err=%v", res.Signature.Kid, merr)
}

// RT3-PACK-4, keyguard side: keyguard signs manifest.json bytes that are
// not canonical (duplicate key, case-variant key); both it and tt mock
// read them with encoding/json (last duplicate wins, keys match without
// case), other readers may not.
func TestRT3_Pack_KeyguardSignsNonCanonicalManifest_Fixed(t *testing.T) {
	kg := newKG(t)
	s := newSigner(kid)
	files := unsigned(demo(t, s, func(m map[string]any, _ map[string][]byte) {
		m["not_after"] = time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)
	}))
	files["manifest.json"] = bytes.Replace(files["manifest.json"], []byte(`"pack_id":`), []byte(`"PACK_ID":"pk-shadow-0001","pack_id":`), 1)
	files["manifest.json"] = bytes.Replace(files["manifest.json"], []byte(`{"created_at"`), []byte(`{"not_after":"2026-01-01T00:00:00Z","created_at"`), 1)
	res, err := kg.svc.SignPack(context.Background(), archiveBytes(t, entries(files)), nil)
	if err == nil {
		t.Fatalf("FINDING RT3-PACK-4: keyguard signed a manifest with a duplicate not_after and a case-variant PACK_ID (kid %s)", res.Signature.Kid)
	}
}
