package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
)

func TestTeeIsBounded(t *testing.T) {
	const limit = 1000
	src := io.NopCloser(io.LimitReader(zeroReader{}, 10<<20))
	tp := newTee(src, limit)
	n, err := io.Copy(io.Discard, tp)
	if err != nil || n != 10<<20 {
		t.Fatalf("copied %d err %v", n, err)
	}
	b, total, eof := tp.snapshot()
	if len(b) != limit || cap(b) > limit {
		t.Fatalf("kept len %d cap %d, limit %d", len(b), cap(b), limit)
	}
	if total != 10<<20 || !eof {
		t.Fatalf("total %d eof %v", total, eof)
	}
}

func TestTeeKeepsSmallBodiesWhole(t *testing.T) {
	tp := newTee(io.NopCloser(strings.NewReader("hello")), 1000)
	_, _ = io.Copy(io.Discard, tp)
	b, total, eof := tp.snapshot()
	if string(b) != "hello" || total != 5 || !eof {
		t.Fatalf("%q %d %v", b, total, eof)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestStripTTBaggage(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
		chg  bool
	}{
		{[]string{"tt.s=1"}, nil, true},
		{[]string{"a=b, tt.s=0 ,c=d"}, []string{"a=b,c=d"}, true},
		{[]string{"tt.s=1, a=b"}, []string{"a=b"}, true},
		{[]string{"a=b;p=1,tt.s=1;x=y"}, []string{"a=b;p=1"}, true},
		{[]string{"a=b", "tt.s=1", "c=d"}, []string{"a=b", "c=d"}, true},
		{[]string{"a=b, c=d"}, []string{"a=b, c=d"}, false},
		{[]string{"x-tt.s=1, tt.sx=2"}, []string{"x-tt.s=1, tt.sx=2"}, false},
	}
	for _, c := range cases {
		h := http.Header{"Baggage": c.in}
		if got := stripTTBaggage(h); got != c.chg {
			t.Errorf("%v: changed = %v", c.in, got)
		}
		if got := h["Baggage"]; strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%v: got %v want %v", c.in, got, c.want)
		}
	}
}

func TestParseTraceparent(t *testing.T) {
	ok := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc, valid := parseTraceparent(ok)
	if !valid || tc.traceID != "4bf92f3577b34da6a3ce929d0e0e4736" || tc.parentID != "00f067aa0ba902b7" {
		t.Fatalf("%+v %v", tc, valid)
	}
	for _, bad := range []string{
		"", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", ok + "-x",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	} {
		if _, v := parseTraceparent(bad); v {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, v := parseTraceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"); !v {
		t.Error("future version with extra fields must be accepted")
	}
}

func TestClassifyNetError(t *testing.T) {
	cases := map[string]error{
		"dns":     &net.DNSError{Err: "no such host", Name: "x"},
		"refused": &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		"timeout": context.DeadlineExceeded,
		"reset":   &net.OpError{Op: "read", Err: syscall.ECONNRESET},
		"tls":     &tls.CertificateVerificationError{Err: errors.New("bad")},
		"other":   errors.New("something"),
	}
	for want, err := range cases {
		if got := classifyNetError(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

func TestSourceVersion(t *testing.T) {
	for in, want := range map[string]string{"v0.1.0": "0.1.0", "1.2.3-rc.1": "1.2.3-rc.1", "dev": "0.0.0-dev", "": "0.0.0-dev", "v1.2": "0.0.0-dev"} {
		if got := SourceVersion(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []Config{
		{},
		{Upstreams: []Upstream{{Alias: "Bad", URL: "https://x.example"}}},
		{Upstreams: []Upstream{{Alias: "a", URL: "ftp://x.example"}}},
		{Upstreams: []Upstream{{Alias: "a", URL: "https://u:p@x.example"}}},
		{Upstreams: []Upstream{{Alias: "a", URL: "https://x.example/?q=1"}}},
		{Upstreams: []Upstream{{Alias: "a", URL: "https://x.example"}, {Alias: "a", URL: "https://y.example"}}},
		{Upstreams: []Upstream{{Alias: "a", URL: "https://x.example", CaptureOrigin: "https://y.example/path"}}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	good := Config{Upstreams: []Upstream{{Alias: "carrier", URL: "https://api.carrier.example/base", CaptureOrigin: "https://api.carrier.example"}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseUpstreamFlag("x"); err == nil {
		t.Error("flag without = accepted")
	}
	_ = bytes.MinRead
}
