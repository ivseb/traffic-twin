package keyguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

// demoPack returns the demo pack files (manifest included) and the archive.
func demoPack(t *testing.T, edit func(*packtest.Spec)) (map[string][]byte, []byte) {
	t.Helper()
	spec := packtest.DemoSpec()
	if edit != nil {
		edit(&spec)
	}
	manifest, err := packtest.ManifestBytes(spec)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"manifest.json": manifest}
	for k, v := range spec.Files {
		files[k] = v
	}
	return files, archiveOf(files)
}

func archiveOf(files map[string][]byte) []byte {
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		_, _ = tw.Write(files[n])
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

// packEnv is a keyguard that signed p-shop version 7, the policy of the
// demo pack.
func packEnv(t *testing.T, mut func(*Config)) *testEnv {
	e := newEnv(t, func(c *Config) {
		c.PackInterval = 0
		if mut != nil {
			mut(c)
		}
	})
	e.signFirst(bodyOpts{version: 7, seq: 1})
	return e
}

func TestSignPackVerifies(t *testing.T) {
	e := packEnv(t, nil)
	ctx := context.Background()
	// Real tokens unrelated to the pack content.
	if err := e.svc.AddTokens(ctx, "2026-10", []string{tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("ORD-2026-000184"))}); err != nil {
		t.Fatal(err)
	}
	files, arc := demoPack(t, nil)
	res, err := e.svc.SignPack(ctx, arc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReverseHMAC.Status != "pass" || res.ReverseHMAC.StringsChecked < 100 || res.ApprovalMode != ModeStandard {
		t.Fatalf("result %+v", res.ReverseHMAC)
	}
	keys := pack.KeySet{res.Signature.Kid: e.packPub()}
	if _, err := pack.VerifySignature(files["manifest.json"], res.Signature.SigFile(), keys); err != nil {
		t.Fatalf("pack.VerifySignature: %v", err)
	}
	// The whole pack loads with internal/pack.
	dir := t.TempDir()
	files["manifest.sig.json"] = res.Signature.SigFile()
	for n, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(n))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pack.Load(dir, pack.Options{Keys: keys}); err != nil {
		t.Fatalf("pack.Load: %v", err)
	}
}

func TestSignPackRefusesRealToken(t *testing.T) {
	e := packEnv(t, nil)
	ctx := context.Background()
	// A real order id that ended up in the synthetic world by mistake.
	if err := e.svc.AddTokens(ctx, "2026-10", []string{tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("ORD-SYN-0042"))}); err != nil {
		t.Fatal(err)
	}
	_, arc := demoPack(t, nil)
	_, err := e.svc.SignPack(ctx, arc, nil)
	if errCode(err) != "reverse_hmac" {
		t.Fatalf("expected refusal, got %v", err)
	}
	rh := err.(*Error).Extra["reverse_hmac"].(ReverseHMAC)
	if rh.Status != "fail" || len(rh.Findings) == 0 {
		t.Fatalf("findings %+v", rh)
	}
	var inWorld bool
	for _, f := range rh.Findings {
		if strings.Contains(f.Pointer, "ORD-SYN") || strings.Contains(f.Reason, "ORD-SYN") {
			t.Fatal("finding carries the value")
		}
		inWorld = inWorld || (f.File == "world.jsonl" && strings.Contains(f.Pointer, ":/"))
	}
	if !inWorld {
		t.Fatalf("findings %+v", rh.Findings)
	}
	if !slices.Contains(e.alertTypes(), AlertPackPositive) {
		t.Fatalf("alerts %v", e.alertTypes())
	}
	// A number: the demo seed 42 is a real order id in canonical form.
	e2 := packEnv(t, nil)
	if err := e2.svc.AddTokens(ctx, "2026-10", []string{tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("42"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.svc.SignPack(ctx, arc, nil); errCode(err) != "reverse_hmac" {
		t.Fatalf("number not caught: %v", err)
	}
	// An admin cannot override a positive.
	admin := &Approval{User: "root", Roles: []string{RoleAdmin}, At: t0, Reason: "publish anyway"}
	if _, err := e2.svc.SignPack(ctx, arc, admin); errCode(err) != "reverse_hmac" {
		t.Fatalf("admin override bypassed reverse-HMAC: %v", err)
	}
}

func TestSignPackChecks(t *testing.T) {
	e := packEnv(t, nil)
	ctx := context.Background()
	// Hash mismatch: a file changed after the manifest was computed.
	files, _ := demoPack(t, nil)
	files["faults.json"] = append([]byte(nil), files["faults.json"]...)
	files["faults.json"][0] = ' '
	if _, err := e.svc.SignPack(ctx, archiveOf(files), nil); errCode(err) != "hash_mismatch" {
		t.Fatalf("hash: %v", err)
	}
	// Unlisted file.
	files, _ = demoPack(t, nil)
	files["extra.json"] = []byte("{}\n")
	if _, err := e.svc.SignPack(ctx, archiveOf(files), nil); errCode(err) != "hash_mismatch" {
		t.Fatalf("unlisted: %v", err)
	}
	// manifest.sig.json must not be sent.
	files, _ = demoPack(t, nil)
	files["manifest.sig.json"] = []byte("{}\n")
	if _, err := e.svc.SignPack(ctx, archiveOf(files), nil); errCode(err) != "invalid_pack" {
		t.Fatalf("sig file: %v", err)
	}
	// Gate report not passing.
	_, arc := demoPack(t, func(s *packtest.Spec) {
		s.Files["gate-report.json"] = []byte(strings.Replace(string(s.Files["gate-report.json"]), `"id":"k-thresholds","status":"pass"`, `"id":"k-thresholds","status":"fail"`, 1))
	})
	if _, err := e.svc.SignPack(ctx, arc, nil); errCode(err) != "gate_report" {
		t.Fatalf("gate report: %v", err)
	}
	// not_after must follow created_at (pack.md 2.1).
	_, arc = demoPack(t, func(s *packtest.Spec) { s.Manifest["not_after"] = "2026-10-19T03:20:00Z" })
	if _, err := e.svc.SignPack(ctx, arc, nil); errCode(err) != "invalid_pack" {
		t.Fatalf("not_after: %v", err)
	}
	// Unknown source policy.
	_, arc = demoPack(t, func(s *packtest.Spec) {
		s.Manifest["source"] = packtest.JSON(`{"window":{"from":"2026-10-05T00:00:00Z","to":"2026-10-19T00:00:00Z"},"policies":[{"id":"p-shop","version":8}]}`)
	})
	if _, err := e.svc.SignPack(ctx, arc, nil); errCode(err) != "unknown_policy" {
		t.Fatalf("unknown policy: %v", err)
	}
	// Not a gzip archive.
	if _, err := e.svc.SignPack(ctx, []byte("PK\x03\x04"), nil); errCode(err) != "invalid_pack" {
		t.Fatalf("not gzip: %v", err)
	}
}

func TestSignPackRequester(t *testing.T) {
	ctx := context.Background()
	_, arc := demoPack(t, nil)
	e := packEnv(t, nil)
	pub := &Approval{User: "pat", Roles: []string{RolePublisher}, At: t0}
	if res, err := e.svc.SignPack(ctx, arc, pub); err != nil || res.ApprovalMode != ModeStandard {
		t.Fatalf("publisher: %v", err)
	}
	if _, err := e.svc.SignPack(ctx, arc, &Approval{User: "olga", Roles: []string{"operator"}, At: t0}); errCode(err) != "missing_role" {
		t.Fatalf("operator: %v", err)
	}
	admin := &Approval{User: "root", Roles: []string{RoleAdmin}, At: t0}
	if _, err := e.svc.SignPack(ctx, arc, admin); errCode(err) != "admin_reason_required" {
		t.Fatalf("admin without reason: %v", err)
	}
	admin.Reason = "release for the demo"
	res, err := e.svc.SignPack(ctx, arc, admin)
	if err != nil || res.ApprovalMode != ModeAdmin {
		t.Fatalf("admin: %v %+v", err, res)
	}
	if !slices.Contains(e.alertTypes(), AlertPackAdmin) {
		t.Fatalf("alerts %v", e.alertTypes())
	}
	off := packEnv(t, func(c *Config) { c.AdminOverride = false })
	if _, err := off.svc.SignPack(ctx, arc, admin); errCode(err) != "admin_override_disabled" {
		t.Fatalf("override disabled: %v", err)
	}
	// Rate limit on pack signing.
	rl := packEnv(t, func(c *Config) {})
	rl.svc.cfg.PackInterval = time.Second
	if _, err := rl.svc.SignPack(ctx, arc, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := rl.svc.SignPack(ctx, arc, nil); errCode(err) != "rate_limited" {
		t.Fatalf("pack rate limit: %v", err)
	}
}
