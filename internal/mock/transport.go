package mock

import "strings"

// isTransportHeader mirrors contract.IsTransportHeader (the mock does not
// import the inference package): transport, hop-by-hop, browser, proxy and
// tracing request headers are never validated, whatever the pack says.
func isTransportHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "host", "accept", "accept-encoding", "accept-language", "accept-charset",
		"user-agent", "connection", "keep-alive", "upgrade", "proxy-connection",
		"content-length", "transfer-encoding", "te", "trailer", "expect",
		"origin", "referer", "dnt", "cache-control", "pragma",
		"if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "range",
		"forwarded", "via", "traceparent", "tracestate", "baggage", "cookie",
		"idempotency-key", "x-idempotency-key", "x-request-id", "x-correlation-id", "x-amzn-trace-id":
		return true
	}
	return strings.HasPrefix(n, "sec-fetch-") || strings.HasPrefix(n, "sec-ch-") ||
		strings.HasPrefix(n, "x-forwarded-")
}
