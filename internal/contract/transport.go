package contract

import "strings"

// IsTransportHeader reports whether a request header describes the transport
// or the client software rather than the API: hop-by-hop headers, browser
// fetch metadata, proxy and tracing headers. A client of a mock or a test
// double never has to send them, so they are never contract requirements.
// Names are compared case-insensitively.
func IsTransportHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "host", "accept", "accept-encoding", "accept-language", "accept-charset",
		"user-agent", "connection", "keep-alive", "upgrade", "proxy-connection",
		"content-length", "transfer-encoding", "te", "trailer", "expect",
		"origin", "referer", "dnt", "cache-control", "pragma",
		"if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "range",
		"forwarded", "via", "traceparent", "tracestate", "baggage", "cookie":
		return true
	}
	return strings.HasPrefix(n, "sec-fetch-") || strings.HasPrefix(n, "sec-ch-") ||
		strings.HasPrefix(n, "x-forwarded-")
}

// neverRequiredHeader is true for request headers that must stay optional in
// a contract even when every observed call carried them: transport headers
// plus per-call correlation or de-duplication keys, which clients may omit.
func neverRequiredHeader(name string) bool {
	if IsTransportHeader(name) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "idempotency-key", "x-idempotency-key", "x-request-id", "x-correlation-id", "x-amzn-trace-id":
		return true
	}
	return false
}
