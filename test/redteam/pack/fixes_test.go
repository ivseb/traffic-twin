package pack_rt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// Regressions of the round 3 fixes that the reproducers do not cover.

// RT3-PACK-1: a pack without not_after is refused after 90 days by default;
// one with not_after is governed by it; a negative limit turns the check
// off; revoked kids are refused through pack.Options too.
func TestRT3_Pack_Fixed_DefaultAgeAndRevocation(t *testing.T) {
	s := newSigner(kid)
	created := time.Now().UTC().Add(-100 * 24 * time.Hour)
	old := demo(t, s, func(m map[string]any, _ map[string][]byte) {
		m["created_at"] = created.Format(time.RFC3339)
	})
	p := writeArchive(t, entries(old))
	ks := keySet(t, s.keys)
	if _, err := pack.Load(p, pack.Options{Keys: ks}); !errors.Is(err, pack.ErrExpired) {
		t.Fatalf("100-day-old pack without not_after: want pack_expired, got %v", err)
	}
	if _, err := pack.Load(p, pack.Options{Keys: ks, MaxAge: -1}); err != nil {
		t.Fatalf("age check turned off: %v", err)
	}
	if _, err := pack.Load(p, pack.Options{Keys: ks, MaxAge: 200 * 24 * time.Hour}); err != nil {
		t.Fatalf("explicit longer limit: %v", err)
	}
	withNA := demo(t, s, func(m map[string]any, _ map[string][]byte) {
		m["created_at"] = created.Format(time.RFC3339)
		m["not_after"] = time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	})
	if _, err := pack.Load(writeArchive(t, entries(withNA)), pack.Options{Keys: ks}); err != nil {
		t.Fatalf("a pack with not_after is governed by it: %v", err)
	}
	if _, err := pack.Load(writeArchive(t, entries(withNA)), pack.Options{Keys: ks, RevokedKIDs: []string{kid}}); !errors.Is(err, pack.ErrRevokedKey) {
		t.Fatalf("revoked kid: %v", err)
	}
}

// RT3-PACK-2: created_at up to 5 minutes ahead is clock skew, more is refused.
func TestRT3_Pack_Fixed_CreatedAtSkew(t *testing.T) {
	s := newSigner(kid)
	ks := keySet(t, s.keys)
	for _, c := range []struct {
		ahead time.Duration
		ok    bool
	}{{2 * time.Minute, true}, {10 * time.Minute, false}} {
		f := demo(t, s, func(m map[string]any, _ map[string][]byte) {
			m["created_at"] = time.Now().UTC().Add(c.ahead).Format(time.RFC3339)
		})
		_, err := pack.Load(writeArchive(t, entries(f)), pack.Options{Keys: ks})
		if (err == nil) != c.ok {
			t.Fatalf("created_at %s ahead: err=%v", c.ahead, err)
		}
	}
}

// RT3-PACK-3, keyguard side: a gzip bomb as a first entry is skipped, not
// buffered, and the archive is refused for the missing/invalid manifest.
func TestRT3_Pack_Fixed_KeyguardZipBomb(t *testing.T) {
	kg := newKG(t)
	s := newSigner(kid)
	base := unsigned(demo(t, s, nil))
	es := append([]entry{{name: "aaa.json", zeros: 192 << 20}}, entries(base)...)
	archive := archiveBytes(t, es)
	res, err := kg.svc.SignPack(context.Background(), archive, nil)
	if err == nil {
		t.Fatalf("signed an archive with an unlisted 192 MiB file: %+v", res)
	}
	if kgCode(err) != "hash_mismatch" {
		t.Fatalf("code %s", kgCode(err))
	}
}

// RT3-PACK info: a TT_GATE_PUBKEYS file writable by group or others is refused.
func TestRT3_Pack_Fixed_KeyFileMustNotBeWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	s := newSigner(kid)
	f := filepath.Join(t.TempDir(), "gate.keys")
	if err := os.WriteFile(f, []byte(s.keys+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.ParseKeySet(f); err != nil {
		t.Fatalf("0600 key file: %v", err)
	}
	for _, mode := range []os.FileMode{0o664, 0o666, 0o620} {
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := pack.ParseKeySet(f); err == nil {
			t.Fatalf("key file with mode %o accepted", mode)
		}
	}
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.ParseKeySet(f); err != nil {
		t.Fatalf("0644 key file: %v", err)
	}
}
