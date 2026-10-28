package main

import (
	"strings"
	"testing"
)

func TestInjectorIsRegistered(t *testing.T) {
	code, out, _ := runArgs("help")
	if code != 0 || !strings.Contains(out, "injector") {
		t.Fatalf("help does not list injector: %q", out)
	}
	if code, _, _ := runArgs("injector", "-h"); code != 0 {
		t.Errorf("injector -h exit code = %d", code)
	}
}

func TestInjectorUsageErrors(t *testing.T) {
	t.Setenv("TT_INJECTOR_SDK_IMAGES", "")
	t.Setenv("TT_INJECTOR_TLS_CERT_FILE", "")
	t.Setenv("TT_INJECTOR_TLS_KEY_FILE", "")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no tls", []string{"-sdk-image", "node=r/n:1"}, "-tls-cert-file and -tls-key-file are required"},
		{"bad image arg", []string{"-sdk-image", "node"}, "want language=reference"},
		{"image for manual language", []string{"-sdk-image", "go=r/d:1"}, "no SDK image can be configured"},
		{"bad pull policy", []string{"-pull-policy", "Maybe"}, "pull policy"},
		{"bad mode", []string{"-hmac-mode", "rw"}, "-hmac-mode"},
		{"stray argument", []string{"extra"}, "unexpected arguments"},
	}
	for _, c := range cases {
		code, _, errOut := runArgs(append([]string{"injector"}, c.args...)...)
		if code != 2 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: code %d, stderr %q", c.name, code, errOut)
		}
	}
}
