package keyguard

import (
	"io"
	"log/slog"
	"strings"
)

// NewLogger returns keyguard's structured logger. As defense in depth any
// attribute whose key suggests sensitive content is redacted; keyguard code
// only ever logs codes, counts and identifiers.
func NewLogger(w io.Writer, level, format string) *slog.Logger {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: lv, ReplaceAttr: redactAttr}
	if format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

var sensitiveKeys = []string{"secret", "seed", "private", "token", "candidate", "password", "body", "header", "payload", "query", "value", "reason", "string"}

func redactAttr(_ []string, a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	return a
}
