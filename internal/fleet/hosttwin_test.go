package fleet

import (
	"strings"
	"testing"
)

func TestTwinBase(t *testing.T) {
	cases := []struct {
		pattern, base, scheme, want, code string
	}{
		{"api.payments.example", "", "https", "https://api.payments.example", ""},
		{"api.payments.example:8443", "", "https", "https://api.payments.example:8443", ""},
		{"localhost:8080", "", "http", "http://localhost:8080", ""},
		// The scheme is never guessed (the events do not carry it).
		{"localhost:8080", "", "", "", "scheme_required"},
		{"localhost:8080", "", "ftp", "", "invalid_scheme"},
		{"localhost:8080", "https://localhost:8080", "http", "", "base_mismatch"},
		{"api.payments.example", "http://api.payments.example/v1", "", "http://api.payments.example/v1", ""},
		{"{*}.tenant.example", "", "", "", "base_required"},
		{"{*}.tenant.example", "https://eu1.tenant.example", "", "https://eu1.tenant.example", ""},
		{"{*}.tenant.example", "https://a.b.tenant.example", "", "", "base_mismatch"},
		{"{*}.tenant.example:8443", "https://eu1.tenant.example", "", "", "base_mismatch"},
		{"ip:private:8080", "", "", "", "base_required"},
		{"ip:private:8080", "http://10.0.0.5:8080", "", "http://10.0.0.5:8080", ""},
		{"ip:private:8080", "http://8.8.8.8:8080", "", "", "base_mismatch"},
		{"api.payments.example", "ftp://api.payments.example", "", "", "invalid_base"},
	}
	for _, c := range cases {
		b, err := twinBase(c.pattern, c.base, c.scheme)
		if c.code != "" {
			ae, ok := err.(*APIError)
			if !ok || ae.Code != c.code {
				t.Errorf("twinBase(%q, %q) = %v, want %s", c.pattern, c.base, err, c.code)
			}
			continue
		}
		if err != nil || b.String() != c.want {
			t.Errorf("twinBase(%q, %q) = %q, %v; want %q", c.pattern, c.base, b.String(), err, c.want)
		}
	}
}

func TestAddServiceYAML(t *testing.T) {
	doc := `format: tt.policy/v1
policy_id: p-shop
default: drop
# the HMAC key
hmac: {kid: k1, epoch: "2026-10"}
sampling: {rate: 0.05}
`
	out, err := addServiceYAML([]byte(doc), "api.payments.example", "https://api.payments.example")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthor(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if s, ok := a.Services["api.payments.example"]; !ok || s.Base != "https://api.payments.example" {
		t.Fatalf("services: %+v\n%s", a.Services, out)
	}
	if !strings.Contains(string(out), "# the HMAC key") {
		t.Errorf("comment lost:\n%s", out)
	}
	// A second service goes into the same mapping.
	out, err = addServiceYAML(out, "tenant-ext", "https://eu1.tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	if a, err = ParseAuthor(out); err != nil || len(a.Services) != 2 {
		t.Fatalf("%v %+v\n%s", err, a, out)
	}
}
