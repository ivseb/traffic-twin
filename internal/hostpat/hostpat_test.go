package hostpat

import (
	"regexp"
	"strings"
	"testing"
)

// formats of sanitizer.md 6.3, to check that rule d is implied by a-c.
var formats = []*regexp.Regexp{
	regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`),
	regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`),
	regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`),
	regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$`),
	regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`),
	regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+$`),
	regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$`),
	regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`),
	regexp.MustCompile(`^-?[0-9]{1,19}$`),
	regexp.MustCompile(`^[0-9A-Fa-f]{16,}$`),
}

var (
	reA  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	reB  = regexp.MustCompile(`[0-9]{6}`)
	reC  = regexp.MustCompile(`[0-9a-f]{12}`)
	reV4 = formats[6]
)

func refSafe(l string) bool {
	if !reA.MatchString(l) || reB.MatchString(l) || reC.MatchString(l) {
		return false
	}
	for _, f := range formats {
		if f.MatchString(l) {
			return false
		}
	}
	return true
}

func TestSafeLabel(t *testing.T) {
	cases := map[string]bool{
		"api": true, "a": true, "xn--bcher-kva": true, "shard-12345": true, "build-9f8e7d6c5b4": true,
		"t-3912345678": false, "1password": false, "-edge": false, "cdn-": true, "deadbeefcafe": false,
		"a50e8400-e29b-41d4-a716-446655440000": false, "": false, strings.Repeat("k", 63): true,
		strings.Repeat("k", 64): false, "Api": false, "a_b": false, "a@b": false, "a.b": false,
		"eu-west-1": true, "ip-10-0-0-5": true, "{*}": false,
	}
	for l, want := range cases {
		if got := SafeLabel(l); got != want || refSafe(l) != want {
			t.Errorf("SafeLabel(%q) = %v, reference %v, want %v", l, got, refSafe(l), want)
		}
	}
}

// FuzzSafeLabel checks the hand-written rule against the regular
// expressions of the spec, including rule d.
func FuzzSafeLabel(f *testing.F) {
	for _, s := range []string{"api", "a50e8400-e29b-41d4-a716-446655440000", "abcdefabcdef1", "x123456", "aaaa-bbbb-cccc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, l string) {
		if SafeLabel(l) != refSafe(l) {
			t.Fatalf("SafeLabel(%q) = %v, reference %v", l, SafeLabel(l), refSafe(l))
		}
	})
}

func TestFromHost(t *testing.T) {
	cases := []struct{ host, port, want string }{
		{"api.carrier.example", "", "api.carrier.example"},
		{"api.carrier.example.", "8443", "api.carrier.example:8443"},
		{"t-3912345678.tenant.example", "", "{*}.tenant.example"},
		{"ab12cd34ef56.0012345678.cdn.example", "", "{*}.{*}.cdn.example"},
		{"10.0.0.5", "", "ip:private"},
		{"10.0.0.5.", "8080", "ip:private:8080"},
		{"8.8.8.8", "", "ip:public"},
		{"010.0.0.1", "", "{*}.{*}.{*}.{*}"},
		{"localhost", "3000", "localhost:3000"},
	}
	for _, c := range cases {
		got, ok := FromHost(c.host, c.port)
		if !ok || got != c.want {
			t.Errorf("FromHost(%q, %q) = %q, %v; want %q", c.host, c.port, got, ok, c.want)
		}
		if !Valid(got) {
			t.Errorf("Valid(%q) = false", got)
		}
	}
	for _, bad := range []string{"a..b", ".a", "a.b..", ".", ""} {
		if p, ok := FromHost(bad, ""); ok {
			t.Errorf("FromHost(%q) = %q, want invalid", bad, p)
		}
	}
}

func TestIPv6(t *testing.T) {
	cases := map[string]string{
		"::1": IPPrivate, "::": IPPrivate, "2001:db8::1": IPPrivate, "2606:4700::1111": IPPublic,
		"::ffff:10.0.0.1": IPPrivate, "::ffff:8.8.8.8": IPPublic, "fd12:3456::1": IPPrivate, "fe80::1": IPPrivate,
		"ff02::1": IPPrivate, "64:ff9b::808:808": IPPublic, "64:ff9b::a00:1": IPPrivate, "2001:470::203.0.113.9": IPPublic,
		"1:2:3:4:5:6:7::": IPPublic, "::2:3:4:5:6:7:8": IPPublic, "::5.6.7.8": IPPrivate, "1:2:3:4:5:6:7:8": IPPublic,
	}
	for s, want := range cases {
		a, ok := ParseIPv6(s)
		if !ok {
			t.Errorf("ParseIPv6(%q) failed", s)
			continue
		}
		if got := ClassIPv6(a); got != want {
			t.Errorf("ClassIPv6(%q) = %s, want %s", s, got, want)
		}
	}
	for _, bad := range []string{"", ":", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "fe80::1%eth0",
		"12345::", "g::", "::1.2.3", "::010.0.0.1", "1.2.3.4", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "::1.2.3.4:5"} {
		if _, ok := ParseIPv6(bad); ok {
			t.Errorf("ParseIPv6(%q) accepted", bad)
		}
	}
}

func TestIPv4Ranges(t *testing.T) {
	cases := map[string]string{
		"0.1.2.3": IPPrivate, "10.255.0.1": IPPrivate, "100.64.0.0": IPPrivate, "100.128.0.0": IPPublic,
		"127.0.0.1": IPPrivate, "169.254.169.254": IPPrivate, "172.16.0.1": IPPrivate, "172.31.255.255": IPPrivate,
		"172.32.0.1": IPPublic, "192.0.0.8": IPPrivate, "192.0.2.1": IPPrivate, "192.168.1.1": IPPrivate,
		"198.18.0.1": IPPrivate, "198.19.255.255": IPPrivate, "198.20.0.1": IPPublic, "198.51.100.7": IPPrivate,
		"203.0.113.9": IPPrivate, "224.0.0.1": IPPrivate, "255.255.255.255": IPPrivate, "8.8.8.8": IPPublic,
		"1.1.1.1": IPPublic,
	}
	for s, want := range cases {
		a, ok := ParseIPv4(s)
		if !ok || ClassIPv4(a) != want {
			t.Errorf("%s: got %v %s, want %s", s, ok, ClassIPv4(a), want)
		}
		if ok != reV4.MatchString(s) {
			t.Errorf("ParseIPv4(%q) disagrees with the 6.3 ipv4 format", s)
		}
	}
	for _, bad := range []string{"1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1..2.3", "a.b.c.d", ""} {
		if _, ok := ParseIPv4(bad); ok || reV4.MatchString(bad) {
			t.Errorf("ParseIPv4(%q) accepted", bad)
		}
	}
}

func TestValid(t *testing.T) {
	good := []string{"api.carrier.example", "{*}.example:8443", "ip:private", "ip:public:9000", "{*}", "localhost:3000",
		strings.TrimSuffix(strings.Repeat("{*}.", 127), ".")}
	for _, p := range good {
		if !Valid(p) {
			t.Errorf("Valid(%q) = false", p)
		}
	}
	bad := []string{"", "API.example", "t-3912345678.tenant.example", "a..b", "ip:other", "x.example:0", "x.example:08443",
		"x.example:65536", "{*}.{x}", "a:b:c", strings.TrimSuffix(strings.Repeat("{*}.", 128), ".")}
	for _, p := range bad {
		if Valid(p) {
			t.Errorf("Valid(%q) = true", p)
		}
	}
}

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"api.carrier.example:8443":        "carrier.example",
		"{*}.tracking.example":            "tracking.example",
		"a.b.shop.co.uk":                  "shop.co.uk",
		"co.uk":                           "co.uk",
		"localhost":                       "localhost",
		"ip:private:8080":                 "ip:private",
		"x.y.{*}.com":                     "{*}.com",
		"eu-west-1.compute.amazonaws.com": "amazonaws.com",
	}
	for p, want := range cases {
		if got := Domain(p); got != want {
			t.Errorf("Domain(%q) = %q, want %q", p, got, want)
		}
	}
	labels, reg := Registrable("a.b.carrier.example")
	if reg != 2 || labels[reg-1] != "b" {
		t.Errorf("Registrable: %v %d", labels, reg)
	}
}

func TestMatches(t *testing.T) {
	if !Matches("{*}.tracking.example", "eu1.tracking.example") || Matches("{*}.tracking.example", "a.b.tracking.example") ||
		Matches("api.x.example:8443", "api.x.example") || !Exact("api.x.example:8443") || Exact("{*}.x.example") || Exact("ip:private") {
		t.Error("Matches/Exact")
	}
}
