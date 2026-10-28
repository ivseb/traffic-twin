package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupTokenFileIs0600AndNotPrinted(t *testing.T) {
	dir := t.TempDir()
	const tok = "tts_secretsecretsecret"
	path, err := WriteSetupToken(dir, tok)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, SetupTokenFile) {
		t.Fatalf("path %q", path)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("setup token file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != tok {
		t.Fatalf("content %q", b)
	}
	// Replaced at the next start, still 0600.
	if _, err := WriteSetupToken(dir, tok+"2"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after replace: %v", fi.Mode())
	}

	var out bytes.Buffer
	PrintSetupTokenFile(&out, path, "https://core.example:7070")
	if strings.Contains(out.String(), "tts_") || !strings.Contains(out.String(), path) {
		t.Fatalf("console text must name the file, never the token: %q", out.String())
	}

	RemoveSetupTokenFile(dir)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stale file not removed: %v", err)
	}
	RemoveSetupTokenFile(dir) // missing file: no error, no panic
}
