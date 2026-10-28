package egress

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// traceContext is what egress reads from a W3C traceparent header. It never
// writes one: tt does not change the traffic of the application.
type traceContext struct {
	traceID  string // 32 lower-case hex, not all zero
	parentID string // 16 lower-case hex, not all zero
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool { return strings.Trim(s, "0") == "" }

// parseTraceparent reads version-traceid-parentid-flags (W3C Trace Context).
// Anything that does not parse is ignored.
func parseTraceparent(v string) (traceContext, bool) {
	if len(v) < 55 || v[2] != '-' || v[35] != '-' || v[52] != '-' {
		return traceContext{}, false
	}
	ver, tid, pid, flags := v[:2], v[3:35], v[36:52], v[53:55]
	if !isLowerHex(ver) || ver == "ff" || !isLowerHex(tid) || !isLowerHex(pid) || !isLowerHex(flags) || allZero(tid) || allZero(pid) {
		return traceContext{}, false
	}
	if ver == "00" && len(v) != 55 {
		return traceContext{}, false
	}
	if ver != "00" && len(v) > 55 && v[55] != '-' {
		return traceContext{}, false
	}
	return traceContext{traceID: tid, parentID: pid}, true
}

func randomSpanID() string {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		if b != [8]byte{} {
			return hex.EncodeToString(b[:])
		}
	}
}

// stripTTBaggage removes the tt.s member from the baggage headers and
// reports whether it changed anything (docs/spec/sanitizer.md section 12:
// tt-egress MUST NOT forward tt.s to an external service). Other members are
// left byte for byte; a header that becomes empty is removed.
func stripTTBaggage(h http.Header) bool {
	vals, ok := h["Baggage"]
	if !ok {
		return false
	}
	changed := false
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if !strings.Contains(v, "tt.s") {
			out = append(out, v)
			continue
		}
		parts := strings.Split(v, ",")
		kept := parts[:0:0]
		for _, m := range parts {
			key := m
			if i := strings.IndexAny(key, "=;"); i >= 0 {
				key = key[:i]
			}
			if strings.Trim(key, " \t") == "tt.s" {
				changed = true
				continue
			}
			kept = append(kept, m)
		}
		if len(kept) == 0 {
			continue
		}
		if len(kept) != len(parts) {
			kept[0] = strings.TrimLeft(kept[0], " \t")
		}
		out = append(out, strings.Join(kept, ","))
	}
	if !changed {
		return false
	}
	if len(out) == 0 {
		delete(h, "Baggage")
	} else {
		h["Baggage"] = out
	}
	return true
}

var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// toHeaders converts a header map into the sanitizer input, one entry per
// value, without the hop-by-hop headers the proxy does not forward.
func toHeaders(h http.Header) []sanitizer.Header {
	out := make([]sanitizer.Header, 0, len(h)+2)
	for k, vs := range h {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			out = append(out, sanitizer.Header{Name: k, Value: []byte(v)})
		}
	}
	return out
}

// samplingHeaders returns only the request headers the sampling decision can
// read (baggage, the subject header or cookie), so the common path copies
// almost nothing.
func samplingHeaders(h http.Header, subjectFrom, subjectName string) []sanitizer.Header {
	var out []sanitizer.Header
	add := func(k string) {
		for _, v := range h[http.CanonicalHeaderKey(k)] {
			out = append(out, sanitizer.Header{Name: k, Value: []byte(v)})
		}
	}
	add("baggage")
	switch subjectFrom {
	case "header":
		add(subjectName)
	case "cookie":
		add("cookie")
	}
	return out
}

// classifyNetError maps a transport error to the net_error vocabulary of the
// event schema.
func classifyNetError(err error) string {
	var dns *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var rec tls.RecordHeaderError
	var ne net.Error
	switch {
	case errors.As(err, &dns):
		return "dns"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalid), errors.As(err, &rec),
		strings.Contains(err.Error(), "tls:"):
		return "tls"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "reset"
	}
	return "other"
}
