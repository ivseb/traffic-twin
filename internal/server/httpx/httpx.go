// Package httpx holds small HTTP helpers shared by tt-core packages: JSON
// responses in the common error format, strict JSON request decoding, request
// ids and client IP extraction. It has no dependency on other tt packages so
// any package (auth, fleet, ...) can import it without cycles.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
)

// Error is the common error body: {"code": "...", "message": "..."}.
// Messages are fixed strings chosen by the server: never echo request data.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Details, when present, name what the error is about in a structured form (service
	// names, rule ids: configuration names, never values) so that a client can write the
	// action in its own language.
	Details []map[string]any `json:"details,omitempty"`
}

// WriteJSON writes v with the given status. API responses are never cached.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an Error body.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, Error{Code: code, Message: message})
}

// WriteErrorDetails writes an Error body with details.
func WriteErrorDetails(w http.ResponseWriter, status int, code, message string, details []map[string]any) {
	WriteJSON(w, status, Error{Code: code, Message: message, Details: details})
}

// ErrBadRequest wraps every DecodeJSON failure.
var ErrBadRequest = errors.New("bad request")

// DecodeJSON decodes exactly one JSON object from r into dst, rejecting
// unknown fields, trailing data, a non-JSON Content-Type and bodies larger
// than maxBytes. Requiring application/json also forces a CORS preflight on
// cross-origin requests, which blocks form-based CSRF on pre-auth endpoints.
// Error messages never include body content.
func DecodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return fmt.Errorf("%w: Content-Type must be application/json", ErrBadRequest)
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return fmt.Errorf("%w: body too large", ErrBadRequest)
		}
		return fmt.Errorf("%w: invalid JSON body", ErrBadRequest)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data after JSON object", ErrBadRequest)
	}
	return nil
}

type ctxKey int

const requestIDKey ctxKey = iota

// WithRequestID stores id in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request id set by the server ("" if none).
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

var b32 = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// NewID returns prefix + 26 lowercase base32 characters (128 random bits).
func NewID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand never fails on supported platforms
	return prefix + b32.EncodeToString(b[:])
}

var reRequestID = regexp.MustCompile(`^req_[0-9a-z]{26}$`)

// ValidRequestID reports whether id has the server-generated shape.
func ValidRequestID(id string) bool { return reRequestID.MatchString(id) }

// ClientIP returns the peer IP of r. Proxy headers (X-Forwarded-For,
// Forwarded) are deliberately ignored: they are client-controlled unless a
// trusted proxy is configured, which tt-core does not support yet.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
