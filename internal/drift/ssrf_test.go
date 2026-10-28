package drift

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestInternalAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.9.9.9", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "fe80::1", "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1", "224.0.0.1", "ff02::1",
		"0.0.0.0", "::", "255.255.255.255", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "fd00:ec2::254"} {
		if !internalAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not internal", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111"} {
		if internalAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s internal", s)
		}
	}
}

func TestSafeDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ctx := context.Background()

	// Name allow-listed, address internal and not listed: refused.
	cli := newDeliveryClient([]string{"*.localhost"})
	if _, err := cli.Get("http://hook.localhost:" + port + "/"); err == nil || !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("loopback through an allowed name: %v", err)
	}
	d := &safeDialer{allowed: allowedIPs(nil), resolver: net.DefaultResolver, dialer: &net.Dialer{}}
	if _, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+port); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("literal loopback: %v", err)
	}
	// The exact IP allow-listed (with or without port): reachable.
	for _, a := range []string{"127.0.0.1", "127.0.0.1:" + port} {
		cli := newDeliveryClient([]string{a})
		resp, err := cli.Get("http://127.0.0.1:" + port + "/")
		if err != nil {
			t.Errorf("allow %q: %v", a, err)
			continue
		}
		resp.Body.Close()
	}
	if tr := cli.Transport.(*http.Transport); tr.Proxy != nil {
		t.Error("delivery transport uses a proxy")
	}
}
