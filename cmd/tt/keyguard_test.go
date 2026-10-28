package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
)

func TestKeyguardGenkeyAndRun(t *testing.T) {
	dir, err := os.MkdirTemp("", "kgc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	hmacFile := filepath.Join(dir, "hmac.keys")
	polFile := filepath.Join(dir, "policy.key")
	packFile := filepath.Join(dir, "pack.key")
	if code, _, errOut := runArgs("keyguard", "genkey", "-type", "hmac", "-kid", "k1", "-out", hmacFile); code != 0 {
		t.Fatalf("genkey hmac: %s", errOut)
	}
	code, out, errOut := runArgs("keyguard", "genkey", "-type", "ed25519", "-kid", "policy-1", "-out", polFile)
	if code != 0 || !strings.HasPrefix(out, "policy-1:") {
		t.Fatalf("genkey ed25519: %s %s", out, errOut)
	}
	if code, _, _ := runArgs("keyguard", "genkey", "-type", "ed25519", "-kid", "gate-1", "-out", packFile); code != 0 {
		t.Fatal("genkey pack")
	}
	for _, f := range []string{hmacFile, polFile, packFile} {
		st, err := os.Stat(f)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, st.Mode())
		}
	}
	if code, _, _ := runArgs("keyguard", "genkey", "-type", "hmac", "-kid", "k1", "-out", hmacFile); code == 0 {
		t.Fatal("genkey overwrote an existing file")
	}

	sock := filepath.Join(dir, "kg.sock")
	t.Setenv("TT_KEYGUARD_SOCKET", sock)
	t.Setenv("TT_KEYGUARD_DB", filepath.Join(dir, "kg.db"))
	t.Setenv("TT_KEYGUARD_HMAC_KEYS_FILE", hmacFile)
	t.Setenv("TT_KEYGUARD_POLICY_SIGNING_KEY_FILE", polFile)
	t.Setenv("TT_KEYGUARD_PACK_SIGNING_KEY_FILE", packFile)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stdout, stderr bytes.Buffer
	go func() { done <- run(ctx, []string{"keyguard"}, &stdout, &stderr) }()
	kc, err := client.New(client.Config{URL: "unix://" + sock})
	if err != nil {
		t.Fatal(err)
	}
	var st *client.Status
	for i := 0; i < 100; i++ {
		if st, err = kc.Status(context.Background()); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || st.PolicyKid != "policy-1" || st.PackKid != "gate-1" || st.HMACKids[0] != "k1" {
		t.Fatalf("status %+v %v", st, err)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("keyguard exit %d: %s", code, stderr.String())
	}
	key, _ := os.ReadFile(hmacFile)
	secret := strings.TrimSpace(strings.SplitN(string(key), ":", 2)[1])
	if strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatal("key material in output")
	}

	// A world-readable key file stops keyguard.
	_ = os.Chmod(hmacFile, 0o644)
	if code, _, errOut := runArgs("keyguard"); code != 1 || !strings.Contains(errOut, "group or others") {
		t.Fatalf("permissive key file: code=%d %s", code, errOut)
	}
}

func TestKeyguardNeedsTransport(t *testing.T) {
	t.Setenv("TT_KEYGUARD_SOCKET", "")
	t.Setenv("TT_KEYGUARD_LISTEN", "")
	if code, _, errOut := runArgs("keyguard"); code != 1 || !strings.Contains(errOut, "exactly one") {
		t.Fatalf("code=%d %s", code, errOut)
	}
}
