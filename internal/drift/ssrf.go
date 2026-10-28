package drift

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Delivery transport (red team round 2, webhook SSRF): the allow list is
// matched on the URL host name, so an allow-listed name (or any name under a
// "*.suffix" entry) could resolve, at delivery time, to loopback, a private
// network or the cloud metadata address. The dialer below resolves the name
// itself, refuses every internal address unless that exact IP is written in
// the allow list, and connects to the address it checked (no second lookup:
// no DNS rebinding between check and connect). No proxy from the
// environment, no redirects.

// ErrBlockedAddress is returned by the delivery dialer for a destination
// that resolves only to internal addresses.
var ErrBlockedAddress = errors.New("drift: webhook destination resolves to an internal address")

var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, incl. broadcast
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 (embeds an IPv4)
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("2002::/16"),      // 6to4 (embeds an IPv4)
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("2001::/32"),      // Teredo (embeds an IPv4)
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast
	netip.MustParsePrefix("169.254.0.0/16"), // link-local (metadata 169.254.169.254); also IsLinkLocalUnicast
	netip.MustParsePrefix("fd00:ec2::/32"),  // AWS IMDS over IPv6 (inside fc00::/7 too)
	netip.MustParsePrefix("255.255.255.255/32"),
}

// internalAddr reports whether a is loopback, link-local, private (RFC 1918,
// ULA), CGNAT, multicast, unspecified or otherwise not a public unicast
// address.
func internalAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range extraBlocked {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// allowedIPs returns the IP literals written in the allow list ("10.0.0.5",
// "10.0.0.5:8443", "[fd00::1]:443"): only those internal addresses may be
// reached.
func allowedIPs(allow []string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, a := range allow {
		a = strings.TrimSpace(a)
		host := a
		if h, _, err := net.SplitHostPort(a); err == nil {
			host = h
		}
		if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			out[ip.Unmap()] = true
		}
	}
	return out
}

// safeDialer dials only addresses that are public or explicitly allowed.
type safeDialer struct {
	allowed  map[netip.Addr]bool
	resolver *net.Resolver
	dialer   *net.Dialer
}

func (d *safeDialer) permitted(a netip.Addr) bool {
	a = a.Unmap()
	return d.allowed[a] || !internalAddr(a)
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		ips, err := d.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		addrs = ips
	}
	var lastErr error = ErrBlockedAddress
	for _, a := range addrs {
		if !d.permitted(a) {
			continue
		}
		c, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// newDeliveryClient is the default webhook client: SSRF-safe dialer, no
// proxy, no redirects, bounded handshakes.
func newDeliveryClient(allow []string) *http.Client {
	d := &safeDialer{allowed: allowedIPs(allow), resolver: net.DefaultResolver, dialer: &net.Dialer{Timeout: 10 * time.Second}}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
