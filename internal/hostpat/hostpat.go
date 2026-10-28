// Package hostpat implements the host patterns of docs/spec/sanitizer.md
// 3.5 and 3.6 (spec v1.5): how an outbound host without a matching base
// leaves a source, privacy-preserving by construction, and the helpers the
// intake and tt-core use to read those patterns back (registrable domain,
// label positions).
//
// A pattern keeps a label literal only if it passes the safe-label rule;
// every other label becomes {*}. IP literals never leave: only their class
// (ip:private, ip:public). The package has no dependency on the rest of the
// repository so that the sanitizer, the event decoder, the intake and the
// admin API share one implementation.
package hostpat

import (
	"strconv"
	"strings"
)

// Star is the label that replaces a label failing the safe-label rule.
const Star = "{*}"

// IP classes (sanitizer.md 3.6).
const (
	IPPrivate = "ip:private"
	IPPublic  = "ip:public"
)

// Discovery modes of the policy field hosts.discovery (sanitizer.md 3.1).
const (
	ModeAuto = "auto"
	ModeOff  = "off"
)

// MaxHostLen is the longest valid host (sanitizer.md 3.1 point 4).
const MaxHostLen = 253

// SafeLabel reports whether a host label (already lower-cased) stays
// literal in a pattern (sanitizer.md 3.5):
//
//	a. it matches ^[a-z][a-z0-9-]{0,62}$ (ASCII, no "@", at most 63 bytes);
//	b. it has no run of 6 or more consecutive digits;
//	c. it has no run of 12 or more consecutive hexadecimal characters;
//	d. no value format of sanitizer.md 6.3 recognizes it.
//
// Rule d is implied by a-c for every string that passes a (uuid and hex are
// the only formats such a string can match, and both contain a run of 12
// hexadecimal characters); the test suite checks the equivalence.
func SafeLabel(l string) bool {
	if len(l) < 1 || len(l) > 63 || l[0] < 'a' || l[0] > 'z' {
		return false
	}
	digits, hexRun := 0, 0
	for i := 0; i < len(l); i++ {
		c := l[i]
		isDigit := c >= '0' && c <= '9'
		if !(c >= 'a' && c <= 'z' || isDigit || c == '-') {
			return false
		}
		if isDigit {
			digits++
			if digits >= 6 {
				return false
			}
		} else {
			digits = 0
		}
		if isDigit || c >= 'a' && c <= 'f' {
			hexRun++
			if hexRun >= 12 {
				return false
			}
		} else {
			hexRun = 0
		}
	}
	return true
}

// FromHost returns the pattern of a host already validated and normalized
// by sanitizer.md 3.1 (lower case, at most 253 bytes of [a-z0-9.-]) and its
// normalized port ("" when absent or default). ok is false when the host
// has an empty label (the service is then host:invalid). The pattern does
// not include the "host:" prefix.
func FromHost(host, port string) (pattern string, ok bool) {
	h := strings.TrimSuffix(host, ".")
	if h == "" {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(h) + 8)
	if a, isV4 := ParseIPv4(h); isV4 {
		b.WriteString(ClassIPv4(a))
	} else {
		start := 0
		for i := 0; i <= len(h); i++ {
			if i < len(h) && h[i] != '.' {
				continue
			}
			l := h[start:i]
			if l == "" {
				return "", false
			}
			if start > 0 {
				b.WriteByte('.')
			}
			if SafeLabel(l) {
				b.WriteString(l)
			} else {
				b.WriteString(Star)
			}
			start = i + 1
		}
	}
	if port != "" {
		b.WriteByte(':')
		b.WriteString(port)
	}
	return b.String(), true
}

// FromIPv6 returns the pattern of an IPv6 literal with its normalized port.
func FromIPv6(a [16]byte, port string) string {
	p := ClassIPv6(a)
	if port != "" {
		p += ":" + port
	}
	return p
}

// ---- IP literals (sanitizer.md 3.1, 3.6) ----

// ParseIPv4 recognizes the ipv4 format of sanitizer.md 6.3 (dotted quad,
// each part 0-255 without leading zeros).
func ParseIPv4(s string) ([4]byte, bool) {
	var a [4]byte
	part := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			continue
		}
		if part > 3 {
			return a, false
		}
		f := s[start:i]
		if len(f) < 1 || len(f) > 3 || (len(f) > 1 && f[0] == '0') {
			return a, false
		}
		n := 0
		for k := 0; k < len(f); k++ {
			if f[k] < '0' || f[k] > '9' {
				return a, false
			}
			n = n*10 + int(f[k]-'0')
		}
		if n > 255 {
			return a, false
		}
		a[part] = byte(n)
		part++
		start = i + 1
	}
	return a, part == 4
}

func hexGroup(s string) (uint16, bool) {
	if len(s) < 1 || len(s) > 4 {
		return 0, false
	}
	var n uint16
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		default:
			return 0, false
		}
		n = n<<4 | uint16(d)
	}
	return n, true
}

// groups parses colon-separated parts; the last may be a dotted IPv4 when
// tailOK (it then counts as two groups).
func groups(s string, tailOK bool) ([]uint16, bool) {
	if s == "" {
		return nil, true
	}
	parts := strings.Split(s, ":")
	out := make([]uint16, 0, 8)
	for i, p := range parts {
		if tailOK && i == len(parts)-1 && strings.IndexByte(p, '.') >= 0 {
			a, ok := ParseIPv4(p)
			if !ok {
				return nil, false
			}
			out = append(out, uint16(a[0])<<8|uint16(a[1]), uint16(a[2])<<8|uint16(a[3]))
			continue
		}
		g, ok := hexGroup(p)
		if !ok {
			return nil, false
		}
		out = append(out, g)
	}
	return out, true
}

// ParseIPv6 parses the text form of RFC 4291 2.2 in lower case: groups of
// 1-4 hexadecimal digits, at most one "::" standing for at least one zero
// group, an optional dotted IPv4 (6.3 ipv4) as the last 32 bits, no zone
// identifier (sanitizer.md 3.1, spec v1.5).
func ParseIPv6(s string) ([16]byte, bool) {
	var a [16]byte
	var g []uint16
	if i := strings.Index(s, "::"); i >= 0 {
		if strings.Contains(s[i+2:], "::") {
			return a, false
		}
		left, ok1 := groups(s[:i], false)
		right, ok2 := groups(s[i+2:], true)
		if !ok1 || !ok2 || len(left)+len(right) > 7 {
			return a, false
		}
		g = make([]uint16, 0, 8)
		g = append(g, left...)
		for k := len(left) + len(right); k < 8; k++ {
			g = append(g, 0)
		}
		g = append(g, right...)
	} else {
		var ok bool
		if g, ok = groups(s, true); !ok || len(g) != 8 {
			return a, false
		}
	}
	for i, v := range g {
		a[2*i], a[2*i+1] = byte(v>>8), byte(v)
	}
	return a, true
}

type prefix4 struct {
	a    [4]byte
	bits int
}

type prefix6 struct {
	a    [16]byte
	bits int
}

// sanitizer.md 3.6: every address not in these ranges is public.
var ipv4Private = []prefix4{
	{[4]byte{0, 0, 0, 0}, 8}, {[4]byte{10, 0, 0, 0}, 8}, {[4]byte{100, 64, 0, 0}, 10}, {[4]byte{127, 0, 0, 0}, 8},
	{[4]byte{169, 254, 0, 0}, 16}, {[4]byte{172, 16, 0, 0}, 12}, {[4]byte{192, 0, 0, 0}, 24}, {[4]byte{192, 0, 2, 0}, 24},
	{[4]byte{192, 168, 0, 0}, 16}, {[4]byte{198, 18, 0, 0}, 15}, {[4]byte{198, 51, 100, 0}, 24}, {[4]byte{203, 0, 113, 0}, 24},
	{[4]byte{224, 0, 0, 0}, 4}, {[4]byte{240, 0, 0, 0}, 4},
}

func mustV6(s string, bits int) prefix6 {
	a, ok := ParseIPv6(s)
	if !ok {
		panic("hostpat: bad prefix " + s)
	}
	return prefix6{a, bits}
}

var (
	ipv6EmbeddedV4 = []prefix6{mustV6("::ffff:0:0", 96), mustV6("64:ff9b::", 96)}
	ipv6Private    = []prefix6{mustV6("::", 96), mustV6("64:ff9b:1::", 48), mustV6("100::", 64), mustV6("2001::", 23),
		mustV6("2001:db8::", 32), mustV6("fc00::", 7), mustV6("fe80::", 10), mustV6("fec0::", 10), mustV6("ff00::", 8)}
)

func inPrefix(addr, pre []byte, bits int) bool {
	full := bits / 8
	for i := 0; i < full; i++ {
		if addr[i] != pre[i] {
			return false
		}
	}
	if rem := bits % 8; rem != 0 {
		mask := byte(0xff) << (8 - rem)
		return addr[full]&mask == pre[full]&mask
	}
	return true
}

// IPv4Private reports whether a is in a non-public range of 3.6.
func IPv4Private(a [4]byte) bool {
	for _, p := range ipv4Private {
		if inPrefix(a[:], p.a[:], p.bits) {
			return true
		}
	}
	return false
}

// IPv6Private reports whether a is in a non-public range of 3.6; IPv4-mapped
// and NAT64 addresses take the class of the embedded IPv4 address.
func IPv6Private(a [16]byte) bool {
	for _, p := range ipv6EmbeddedV4 {
		if inPrefix(a[:], p.a[:], p.bits) {
			return IPv4Private([4]byte{a[12], a[13], a[14], a[15]})
		}
	}
	for _, p := range ipv6Private {
		if inPrefix(a[:], p.a[:], p.bits) {
			return true
		}
	}
	return false
}

// ClassIPv4 returns ip:private or ip:public.
func ClassIPv4(a [4]byte) string {
	if IPv4Private(a) {
		return IPPrivate
	}
	return IPPublic
}

// ClassIPv6 returns ip:private or ip:public.
func ClassIPv6(a [16]byte) string {
	if IPv6Private(a) {
		return IPPrivate
	}
	return IPPublic
}

// ---- reading patterns back (intake, tt-core) ----

// SplitPort splits "pattern[:port]" (no "host:" prefix). The port is
// returned only when it is 1-5 digits.
func SplitPort(p string) (host, port string) {
	i := strings.LastIndexByte(p, ':')
	if i < 0 {
		return p, ""
	}
	pt := p[i+1:]
	if len(pt) < 1 || len(pt) > 5 {
		return p, ""
	}
	for k := 0; k < len(pt); k++ {
		if pt[k] < '0' || pt[k] > '9' {
			return p, ""
		}
	}
	return p[:i], pt
}

// IsIP reports whether the host part of a pattern is an IP class.
func IsIP(host string) bool { return host == IPPrivate || host == IPPublic }

// Valid reports whether p (without the "host:" prefix) is a pattern that a
// conformant source emits for a host without a base (sanitizer.md 3.5): an
// IP class or labels that are {*} or safe, standing for a host of at most
// 253 bytes, with an optional normalized port 1-65535 (no leading zeros;
// whether it is the default of the scheme cannot be checked, the scheme is
// not in the event).
func Valid(p string) bool {
	host, port := SplitPort(p)
	if port != "" {
		n, _ := strconv.Atoi(port)
		if n < 1 || n > 65535 || port[0] == '0' {
			return false
		}
	} else if strings.IndexByte(host, ':') >= 0 && !IsIP(host) {
		return false
	}
	if IsIP(host) {
		return true
	}
	if host == "" {
		return false
	}
	// Each {*} stands for at least one byte of the original host.
	min := 0
	for i, l := range strings.Split(host, ".") {
		if i > 0 {
			min++
		}
		switch {
		case l == Star:
			min++
		case SafeLabel(l):
			min += len(l)
		default:
			return false
		}
	}
	return min <= MaxHostLen
}

// multiSuffixes is the small, fixed subset of public suffixes with two
// labels (event.md 5.2, spec v1.5). Every other host has a one-label suffix.
var multiSuffixes = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`
		ac.uk co.uk gov.uk ltd.uk me.uk net.uk nhs.uk org.uk plc.uk sch.uk
		com.au edu.au gov.au net.au org.au
		co.nz govt.nz net.nz org.nz
		ac.jp co.jp go.jp ne.jp or.jp
		com.br gov.br net.br org.br
		com.cn gov.cn net.cn org.cn
		co.in gov.in net.in org.in
		co.za gov.za org.za
		co.kr or.kr
		com.ar com.hk com.mx com.my com.sg com.tr com.tw co.id co.il co.th
		gov.it`) {
		multiSuffixes[s] = true
	}
}

// MultiSuffixes returns the two-label public suffixes known to Registrable.
func MultiSuffixes() []string {
	out := make([]string, 0, len(multiSuffixes))
	for s := range multiSuffixes {
		out = append(out, s)
	}
	return out
}

// Registrable splits the host part of a pattern (no port, not an IP class)
// into labels and returns the index of the first label of its registrable
// domain (an approximation of eTLD+1): the last two labels, or the last
// three when the last two are a suffix of MultiSuffixes. A host with fewer
// labels is its own registrable domain (index 0). Positions are counted
// from the right of the registrable domain: label labels[reg-1] is position
// 1, labels[reg-2] position 2, and so on.
func Registrable(host string) (labels []string, reg int) {
	labels = strings.Split(host, ".")
	n := len(labels)
	size := 2
	if n >= 2 && multiSuffixes[labels[n-2]+"."+labels[n-1]] {
		size = 3
	}
	if n <= size {
		return labels, 0
	}
	return labels, n - size
}

// Domain returns the registrable domain of a pattern (with no "host:"
// prefix; the port is ignored): "carrier.example" for
// "{*}.api.carrier.example:8443", the IP class for IP patterns.
func Domain(p string) string {
	host, _ := SplitPort(p)
	if IsIP(host) {
		return host
	}
	labels, reg := Registrable(host)
	return strings.Join(labels[reg:], ".")
}

// Exact reports whether a pattern names exactly one host: no {*} label and
// not an IP class. Only those can become a match.base directly.
func Exact(p string) bool {
	host, _ := SplitPort(p)
	return !IsIP(host) && !strings.Contains(host, Star)
}

// Matches reports whether a concrete host[:port] (lower case, no trailing
// dot) is described by pattern p: same number of labels, every literal
// label equal, {*} matching any label, same port.
func Matches(p, hostPort string) bool {
	ph, pp := SplitPort(p)
	hh, hp := SplitPort(hostPort)
	if pp != hp || IsIP(ph) {
		return false
	}
	pl, hl := strings.Split(ph, "."), strings.Split(hh, ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if pl[i] != Star && pl[i] != hl[i] {
			return false
		}
	}
	return true
}
