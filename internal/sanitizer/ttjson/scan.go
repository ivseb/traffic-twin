// Package ttjson implements the strict JSON scanner, the exact-decimal number
// canonicalization and the canonical writer ("tt-cjson") defined in
// docs/spec/sanitizer.md sections 9.2 and 10.
//
// It deliberately does not use encoding/json: numbers must keep their lexeme,
// duplicate keys follow tt rules and the output bytes must be identical in
// every language.
package ttjson

import (
	"errors"
	"unicode/utf8"
)

// ErrSyntax is returned for any input that is not RFC 8259 JSON.
var ErrSyntax = errors.New("ttjson: invalid json")

// IsWS reports whether c is JSON insignificant whitespace.
func IsWS(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// SkipWS returns the index of the first non-whitespace byte at or after i.
func SkipWS(d []byte, i int) int {
	for i < len(d) && IsWS(d[i]) {
		i++
	}
	return i
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func hex4(d []byte, i int) (rune, bool) {
	if i+4 > len(d) {
		return 0, false
	}
	var r rune
	for k := 0; k < 4; k++ {
		h := hexVal(d[i+k])
		if h < 0 {
			return 0, false
		}
		r = r<<4 | rune(h)
	}
	return r, true
}

// appendWTF8 appends r using the generalized UTF-8 encoding, which also
// encodes lone surrogates as three bytes. Only used for strings that are
// flagged as invalid and therefore never written to the output.
func appendWTF8(b []byte, r rune) []byte {
	if r >= 0xD800 && r <= 0xDFFF {
		return append(b, byte(0xE0|(r>>12)), byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
	}
	return utf8.AppendRune(b, r)
}

// ScanString scans the JSON string starting at d[i] (which must be '"').
// It returns the index just after the closing quote and the decoded content.
// When the string has no escapes the content aliases d; otherwise it is
// appended to buf (which may be nil). lone is true when the string contains
// an unpaired \uD800-\uDFFF escape: the decoded content then uses the
// generalized UTF-8 encoding for that code unit and the string is invalid
// per sanitizer section 9.2.
//
// The caller must have verified that d is valid UTF-8.
func ScanString(d []byte, i int, buf []byte) (end int, s []byte, lone bool, err error) {
	if i >= len(d) || d[i] != '"' {
		return 0, nil, false, ErrSyntax
	}
	start := i + 1
	j := start
	for j < len(d) {
		c := d[j]
		if c == '"' {
			return j + 1, d[start:j], false, nil
		}
		if c == '\\' {
			break
		}
		if c < 0x20 {
			return 0, nil, false, ErrSyntax
		}
		j++
	}
	if j >= len(d) {
		return 0, nil, false, ErrSyntax
	}
	// Slow path with escapes.
	out := append(buf[:0], d[start:j]...)
	for j < len(d) {
		c := d[j]
		switch {
		case c == '"':
			return j + 1, out, lone, nil
		case c < 0x20:
			return 0, nil, false, ErrSyntax
		case c != '\\':
			out = append(out, c)
			j++
			continue
		}
		// Escape.
		if j+1 >= len(d) {
			return 0, nil, false, ErrSyntax
		}
		e := d[j+1]
		j += 2
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(d, j)
			if !ok {
				return 0, nil, false, ErrSyntax
			}
			j += 4
			if r >= 0xD800 && r <= 0xDBFF {
				// High surrogate: needs a following \uDC00-\uDFFF.
				if j+6 <= len(d) && d[j] == '\\' && d[j+1] == 'u' {
					if r2, ok2 := hex4(d, j+2); ok2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
						j += 6
						out = utf8.AppendRune(out, 0x10000+((r-0xD800)<<10)+(r2-0xDC00))
						continue
					}
				}
				lone = true
				out = appendWTF8(out, r)
			} else if r >= 0xDC00 && r <= 0xDFFF {
				lone = true
				out = appendWTF8(out, r)
			} else {
				out = utf8.AppendRune(out, r)
			}
		default:
			return 0, nil, false, ErrSyntax
		}
	}
	return 0, nil, false, ErrSyntax
}

// ScanNumber scans the RFC 8259 number starting at d[i]. It returns the end
// index and whether the lexeme is an integer lexeme -?(0|[1-9][0-9]*).
func ScanNumber(d []byte, i int) (end int, isInt bool, err error) {
	j := i
	if j < len(d) && d[j] == '-' {
		j++
	}
	if j >= len(d) {
		return 0, false, ErrSyntax
	}
	switch {
	case d[j] == '0':
		j++
	case d[j] >= '1' && d[j] <= '9':
		for j < len(d) && d[j] >= '0' && d[j] <= '9' {
			j++
		}
	default:
		return 0, false, ErrSyntax
	}
	isInt = true
	if j < len(d) && d[j] == '.' {
		isInt = false
		j++
		k := j
		for j < len(d) && d[j] >= '0' && d[j] <= '9' {
			j++
		}
		if j == k {
			return 0, false, ErrSyntax
		}
	}
	if j < len(d) && (d[j] == 'e' || d[j] == 'E') {
		isInt = false
		j++
		if j < len(d) && (d[j] == '+' || d[j] == '-') {
			j++
		}
		k := j
		for j < len(d) && d[j] >= '0' && d[j] <= '9' {
			j++
		}
		if j == k {
			return 0, false, ErrSyntax
		}
	}
	return j, isInt, nil
}

// ScanLiteral checks for true, false or null at d[i].
func ScanLiteral(d []byte, i int) (end int, err error) {
	for _, lit := range [...]string{"true", "false", "null"} {
		if len(d)-i >= len(lit) && string(d[i:i+len(lit)]) == lit {
			return i + len(lit), nil
		}
	}
	return 0, ErrSyntax
}

// SkipValue validates and skips the JSON value starting at the first
// non-whitespace byte at or after i, without recursion (nesting depth is
// bounded only by the input length). It returns the index after the value.
// It counts the direct members (objects) or elements (arrays) of the
// skipped value in n; for objects, keys are reported through onKey when it
// is not nil (used to count distinct keys).
func SkipValue(d []byte, i int, onKey func(key []byte, lone bool)) (end int, n int, err error) {
	var stack []byte // 'o' or 'a'
	var keyBuf []byte
	i = SkipWS(d, i)
	for {
		// Parse a value at i.
		if i >= len(d) {
			return 0, 0, ErrSyntax
		}
		switch c := d[i]; {
		case c == '{':
			i = SkipWS(d, i+1)
			if i < len(d) && d[i] == '}' {
				i++
				break
			}
			stack = append(stack, 'o')
			if len(stack) == 1 {
				n++
			}
			var k []byte
			var lone bool
			i, k, lone, err = ScanString(d, i, keyBuf)
			if err != nil {
				return 0, 0, err
			}
			if len(stack) == 1 && onKey != nil {
				onKey(k, lone)
			}
			i = SkipWS(d, i)
			if i >= len(d) || d[i] != ':' {
				return 0, 0, ErrSyntax
			}
			i = SkipWS(d, i+1)
			continue
		case c == '[':
			i = SkipWS(d, i+1)
			if i < len(d) && d[i] == ']' {
				i++
				break
			}
			stack = append(stack, 'a')
			if len(stack) == 1 {
				n++
			}
			continue
		case c == '"':
			i, _, _, err = ScanString(d, i, keyBuf[:0])
			if err != nil {
				return 0, 0, err
			}
		case c == 't' || c == 'f' || c == 'n':
			i, err = ScanLiteral(d, i)
			if err != nil {
				return 0, 0, err
			}
		default:
			i, _, err = ScanNumber(d, i)
			if err != nil {
				return 0, 0, err
			}
		}
		// After a value: close containers or move to the next item.
		for {
			if len(stack) == 0 {
				return i, n, nil
			}
			i = SkipWS(d, i)
			if i >= len(d) {
				return 0, 0, ErrSyntax
			}
			top := stack[len(stack)-1]
			if d[i] == ',' {
				i = SkipWS(d, i+1)
				if len(stack) == 1 {
					n++
				}
				if top == 'o' {
					var k []byte
					var lone bool
					i, k, lone, err = ScanString(d, i, keyBuf)
					if err != nil {
						return 0, 0, err
					}
					if len(stack) == 1 && onKey != nil {
						onKey(k, lone)
					}
					i = SkipWS(d, i)
					if i >= len(d) || d[i] != ':' {
						return 0, 0, ErrSyntax
					}
					i = SkipWS(d, i+1)
				}
				break
			}
			if (top == 'o' && d[i] == '}') || (top == 'a' && d[i] == ']') {
				stack = stack[:len(stack)-1]
				i++
				continue
			}
			return 0, 0, ErrSyntax
		}
	}
}
