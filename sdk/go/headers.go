package ttsdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// toHeaders copies a header map for the sanitizer. The sanitizer normalizes
// names and joins duplicates (docs/spec/sanitizer.md section 8.0), so map
// order does not matter.
func toHeaders(h http.Header, extra ...sanitizer.Header) []sanitizer.Header {
	out := make([]sanitizer.Header, 0, len(h)+len(extra))
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, sanitizer.Header{Name: k, Value: []byte(v)})
		}
	}
	return append(out, extra...)
}

// requestHeaders is toHeaders for a server request. Go removes Host and
// Transfer-Encoding from the header map; other runtimes show them as
// headers, so they are put back.
func requestHeaders(r *http.Request) []sanitizer.Header {
	var extra []sanitizer.Header
	if r.Host != "" {
		extra = append(extra, sanitizer.Header{Name: "Host", Value: []byte(r.Host)})
	}
	if len(r.TransferEncoding) > 0 {
		extra = append(extra, sanitizer.Header{Name: "Transfer-Encoding", Value: []byte(strings.Join(r.TransferEncoding, ", "))})
	}
	return toHeaders(r.Header, extra...)
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

func hasHeader(hs []sanitizer.Header, name string) bool {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return true
		}
	}
	return false
}

func headerValue(hs []sanitizer.Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return string(h.Value)
		}
	}
	return ""
}

// sniffedType reproduces the Content-Type the net/http server adds when the
// handler did not set one (it sniffs the first bytes), so that the event
// describes what the client really received. It returns "" when the server
// would not add one.
func sniffedType(status int, method string, hs []sanitizer.Header, body []byte) string {
	if len(body) == 0 || method == http.MethodHead || status < 200 || status == http.StatusNoContent || status == http.StatusNotModified {
		return ""
	}
	if hasHeader(hs, "Content-Type") || hasHeader(hs, "Transfer-Encoding") || headerValue(hs, "Content-Encoding") != "" {
		return ""
	}
	return http.DetectContentType(body[:min(len(body), 512)])
}

// withTTBaggage returns the baggage header value with the tt.s member in
// front. The reader of a baggage takes the first valid tt.s member
// (docs/spec/sanitizer.md section 12), so a tt.s that a client forged and
// the application forwarded can not override the decision made here; the
// other members are left untouched.
func withTTBaggage(existing string, sampled bool) string {
	member := "tt.s=0"
	if sampled {
		member = "tt.s=1"
	}
	if strings.TrimSpace(existing) == "" {
		return member
	}
	return member + "," + existing
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

// patternRoute returns the path part of a Go 1.22 ServeMux pattern
// ("[METHOD ][HOST]/[PATH]"), or "" when there is none. The sanitizer
// normalizes it (docs/spec/sanitizer.md section 3.4, framework "nethttp":
// {name} stays, a trailing {$} is dropped, {name...} is not normalizable).
func patternRoute(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		p = strings.TrimLeft(p[i+1:], " \t")
	}
	i := strings.IndexByte(p, '/')
	if i < 0 {
		return ""
	}
	return p[i:]
}

// rawTarget returns the not decoded path and query of a server request, as
// the client sent them.
func rawTarget(r *http.Request) (path, query []byte) {
	ru := r.RequestURI
	if ru == "" || ru[0] != '/' {
		// Absolute-form (proxy request), "*", or a request built in a test.
		p := r.URL.EscapedPath()
		if p == "" {
			p = "/"
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			return []byte(p), []byte(r.URL.RawQuery)
		}
		return []byte(p), nil
	}
	if i := strings.IndexByte(ru, '?'); i >= 0 {
		return []byte(ru[:i]), []byte(ru[i+1:])
	}
	return []byte(ru), nil
}
