package ttsdk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// traceContext is a W3C trace context read from a traceparent header or from
// the active span of the application.
type traceContext struct{ traceID, spanID string }

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

// parseTraceparent reads a W3C traceparent header value. The returned spanID
// is the parent-id field.
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
	return traceContext{traceID: tid, spanID: pid}, true
}

func randomHex(n int) string {
	b := make([]byte, n)
	for {
		_, _ = rand.Read(b)
		for _, c := range b {
			if c != 0 {
				return hex.EncodeToString(b)
			}
		}
	}
}

func validIDs(trace, span string) bool {
	return len(trace) == 32 && len(span) == 16 && isLowerHex(trace) && isLowerHex(span) && !allZero(trace) && !allZero(span)
}

// readContext returns the trace context the application already has: the
// active span if a TraceContextFunc is configured and finds one, else the
// traceparent header. Nothing is created and nothing is written.
func (a *Agent) readContext(ctx context.Context, h http.Header) (tc traceContext, fromSpan, ok bool) {
	if f := a.cfg.TraceContext; f != nil {
		if t, s, found := f(ctx); found && validIDs(t, s) {
			return traceContext{t, s}, true, true
		}
	}
	if v := h.Get("Traceparent"); v != "" {
		if tc, ok := parseTraceparent(v); ok {
			return tc, false, true
		}
	}
	return traceContext{}, false, false
}
