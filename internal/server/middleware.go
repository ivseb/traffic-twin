package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// ContentSecurityPolicy is the CSP of every admin response; it matches the
// one set by internal/ui for the embedded UI.
const ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

// NewLogger builds the process logger. As a second line of defence (the
// first is never passing values to the logger), attributes whose key looks
// sensitive are replaced by "[REDACTED]".
func NewLogger(w io.Writer, level, format string) *slog.Logger {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: lv, ReplaceAttr: redactAttr}
	if format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

var sensitiveKeys = []string{"password", "secret", "token", "cookie", "authorization", "csrf", "body", "header", "payload", "query"}

func redactAttr(_ []string, a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	return a
}

// routeInfo is filled by the matched route so the access log can report
// the route pattern instead of the raw path (which may carry identifiers
// or, for a misbehaving client, values).
type routeInfo struct{ pattern string }

type routeKey struct{}

func withRoute(pattern string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ri, ok := r.Context().Value(routeKey{}).(*routeInfo); ok {
			ri.pattern = pattern
		}
		h.ServeHTTP(w, r)
	})
}

// statusWriter records status and size; it keeps Flush and Unwrap working
// for streaming handlers (http.ResponseController).
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// accessLog assigns a request id and logs one line per request with only
// non-sensitive metadata: listener, method, route pattern, status, size,
// duration, request id and peer IP. Never paths, queries, headers or bodies.
func accessLog(log *slog.Logger, listener string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := httpx.NewID("req_")
		ri := &routeInfo{}
		ctx := context.WithValue(httpx.WithRequestID(r.Context(), id), routeKey{}, ri)
		w.Header().Set("X-Request-Id", id)
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			log.LogAttrs(ctx, slog.LevelInfo, "http request",
				slog.String("listener", listener),
				slog.String("method", safeMethod(r.Method)),
				slog.String("route", ri.pattern),
				slog.Int("status", status),
				slog.Int64("bytes", sw.bytes),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("request_id", id),
				slog.String("remote_ip", httpx.ClientIP(r)),
			)
		}()
		next.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func safeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "OTHER"
}

// recoverPanics turns a handler panic into a generic 500. The panic value
// is not logged (it may embed request data); only its type and the stack
// (function names and raw argument words) are.
func recoverPanics(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			log.LogAttrs(r.Context(), slog.LevelError, "panic recovered",
				slog.String("request_id", httpx.RequestID(r.Context())),
				slog.String("panic_type", fmt.Sprintf("%T", v)),
				slog.String("stack", string(debug.Stack())),
			)
			httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets the browser hardening headers on every response.
func securityHeaders(tlsOn bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if tlsOn {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin rejects unsafe cross-site browser requests (defence in depth
// with SameSite=Strict cookies and CSRF tokens; also covers the pre-auth
// login and setup endpoints). Requests without Origin and Sec-Fetch-Site
// (non-browser clients) pass.
func sameOrigin(tlsOn bool, next http.Handler) http.Handler {
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			httpx.WriteError(w, http.StatusForbidden, "cross_origin", "cross-origin request refused")
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || u.Scheme != scheme || !strings.EqualFold(u.Host, r.Host) {
				httpx.WriteError(w, http.StatusForbidden, "cross_origin", "cross-origin request refused")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody caps request bodies; handlers reading more get an error.
func limitBody(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > max {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}
