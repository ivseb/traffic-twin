// Package event_rt red-teams the intake's canonical-event requirement
// (THREAT_MODEL M21, I-series). Only events whose bytes are EXACTLY the
// tt-cjson form may be accepted; any alternative spelling is a covert
// channel and must be rejected as non_canonical. Invented data only.
package event_rt

import (
	"testing"

	"github.com/ivseb/traffic-twin/internal/event"
)

// Each value is semantically identical JSON written in a non-canonical way:
// ParseCanonical MUST reject every one (M21: a hidden bit in whitespace,
// key order, escapes, number spelling or duplicate keys). Interpreted
// (double-quoted) Go literals are used so that \\u escapes reach the parser
// as the two bytes backslash+u, not as the decoded rune.
func TestRT_Event_Holds_NonCanonicalRejected(t *testing.T) {
	cases := map[string]string{
		"leading-space":       " {\"a\":1}",
		"inner-space":         "{\"a\": 1}",
		"trailing-space":      "{\"a\":1} ",
		"newline":             "{\"a\":1}\n",
		"key-order":           "{\"b\":1,\"a\":2}",
		"duplicate-key":       "{\"a\":1,\"a\":2}",
		"number-plus-exp":     "{\"a\":1e+2}",
		"number-leadzero":     "{\"a\":01}",
		"number-trailzero":    "{\"a\":1.0}",
		"number-neg-zero":     "{\"a\":-0}",
		"number-cap-E":        "{\"a\":1E2}",
		"string-esc-slash":    "{\"a\":\"\\/\"}",     // \/ is not canonical
		"string-esc-ascii":    "{\"a\":\"\\u0041\"}", // \u0041 should be the byte A
		"string-raw-accent":   "{\"a\":\"\u00e9\"}",  // raw é must be escaped \u00e9
		"string-esc-upperhex": "{\"a\":\"\\u00E9\"}", // canonical hex is lowercase
		"array-space":         "[1, 2]",
		"bom":                 "\xef\xbb\xbf{\"a\":1}",
	}
	for name, s := range cases {
		if _, err := event.ParseCanonical([]byte(s)); err == nil {
			t.Errorf("%s: %q accepted as canonical (covert channel)", name, s)
		}
	}
}

// A sanity anchor: the canonical form of the same values is accepted, so the
// test above rejects spelling, not content. Non-ASCII is escaped as
// lowercase \uXXXX (sanitizer.md §10.1), which is the canonical form.
func TestRT_Event_Holds_CanonicalAccepted(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `{"a":2,"b":1}`, `[1,2]`, `{"a":100}`, `{"a":1.5}`, "{\"a\":\"\\u00e9\"}"} {
		if _, err := event.ParseCanonical([]byte(s)); err != nil {
			t.Errorf("canonical %q rejected: %v", s, err)
		}
	}
}
