package sanitizer

import (
	"strings"
	"time"
)

// ---- Length classes (section 0.3) ----

var lenClassTable = [...]struct {
	max  int64
	name string
}{
	{8, "l8"}, {32, "l32"}, {128, "l128"}, {1024, "l1024"},
}

// LenClassUnknown is the class used for unknown lengths.
const LenClassUnknown = "lmax"

// LenClass returns the length class of n (bytes, keys or elements).
func LenClass(n int64) string {
	for _, c := range lenClassTable {
		if n <= c.max {
			return c.name
		}
	}
	return "lmax"
}

// ---- Character helpers ----

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool  { return c >= 'A' && c <= 'Z' }
func isAlpha(c byte) bool  { return isLower(c) || isUpper(c) }
func isHex(c byte) bool    { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }
func isB64URL(c byte) bool { return isAlpha(c) || isDigit(c) || c == '_' || c == '-' }

func allPrintableASCII(s []byte) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

func allOf(s []byte, f func(byte) bool) bool {
	for _, c := range s {
		if !f(c) {
			return false
		}
	}
	return true
}

// ---- Recognized formats (section 6.3), tried in order ----

// Format names.
const (
	fmtUUID     = "uuid"
	fmtJWT      = "jwt"
	fmtEmail    = "email"
	fmtDatetime = "datetime"
	fmtDate     = "date"
	fmtURL      = "url"
	fmtIPv4     = "ipv4"
	fmtPhone    = "phone"
	fmtDigits   = "digits"
	fmtHex      = "hex"
)

// DetectFormat returns the first matching format name or "".
func DetectFormat(s []byte) string {
	if !allPrintableASCII(s) {
		return ""
	}
	switch {
	case isUUID(s):
		return fmtUUID
	case isJWT(s):
		return fmtJWT
	case isEmail(s):
		return fmtEmail
	case isDatetime(s):
		return fmtDatetime
	case isDate(s):
		return fmtDate
	case isURL(s):
		return fmtURL
	case isIPv4(s):
		return fmtIPv4
	case isPhone(s):
		return fmtPhone
	case isDigitsFmt(s):
		return fmtDigits
	case isHexFmt(s):
		return fmtHex
	}
	return ""
}

// ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$
func isUUID(s []byte) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !isHex(c) {
			return false
		}
	}
	return true
}

// ^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$
func isJWT(s []byte) bool {
	if len(s) < 3 || s[0] != 'e' || s[1] != 'y' || s[2] != 'J' {
		return false
	}
	i := 3
	for i < len(s) && isB64URL(s[i]) {
		i++
	}
	if i >= len(s) || s[i] != '.' {
		return false
	}
	i++
	k := i
	for i < len(s) && isB64URL(s[i]) {
		i++
	}
	if i == k || i >= len(s) || s[i] != '.' {
		return false
	}
	i++
	for i < len(s) && isB64URL(s[i]) {
		i++
	}
	return i == len(s)
}

// ^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$
func isEmail(s []byte) bool {
	at := -1
	for i, c := range s {
		if c == '@' {
			at = i
			break
		}
	}
	if at < 1 || at > 64 {
		return false
	}
	for _, c := range s[:at] {
		if !(isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-') {
			return false
		}
	}
	labels := 0
	start := at + 1
	for i := start; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			n := i - start
			if n < 1 || n > 63 {
				return false
			}
			labels++
			start = i + 1
			continue
		}
		c := s[i]
		if !(isAlpha(c) || isDigit(c) || c == '-') {
			return false
		}
	}
	return labels >= 2
}

func digitsAt(s []byte, i, n int) bool {
	if i+n > len(s) {
		return false
	}
	for k := i; k < i+n; k++ {
		if !isDigit(s[k]) {
			return false
		}
	}
	return true
}

// ^[0-9]{4}-[0-9]{2}-[0-9]{2}$
func isDate(s []byte) bool {
	return len(s) == 10 && digitsAt(s, 0, 4) && s[4] == '-' && digitsAt(s, 5, 2) && s[7] == '-' && digitsAt(s, 8, 2)
}

// ^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$
func isDatetime(s []byte) bool {
	_, ok := splitDatetime(s)
	return ok
}

// dtParts are the fixed-position offsets of a matched datetime.
type dtParts struct {
	tz int // index of the zone designator
}

func splitDatetime(s []byte) (dtParts, bool) {
	if len(s) < 20 || !isDate(s[:10]) {
		return dtParts{}, false
	}
	if c := s[10]; c != 'T' && c != 't' && c != ' ' {
		return dtParts{}, false
	}
	if !(digitsAt(s, 11, 2) && s[13] == ':' && digitsAt(s, 14, 2) && s[16] == ':' && digitsAt(s, 17, 2)) {
		return dtParts{}, false
	}
	i := 19
	if s[i] == '.' {
		i++
		k := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if n := i - k; n < 1 || n > 9 {
			return dtParts{}, false
		}
	}
	if i >= len(s) {
		return dtParts{}, false
	}
	switch s[i] {
	case 'Z', 'z':
		if i+1 != len(s) {
			return dtParts{}, false
		}
	case '+', '-':
		if !(i+6 == len(s) && digitsAt(s, i+1, 2) && s[i+3] == ':' && digitsAt(s, i+4, 2)) {
			return dtParts{}, false
		}
	default:
		return dtParts{}, false
	}
	return dtParts{tz: i}, true
}

// ^[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+$
func isURL(s []byte) bool {
	if len(s) == 0 || !isAlpha(s[0]) {
		return false
	}
	i := 1
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '+' || s[i] == '.' || s[i] == '-') {
		i++
	}
	if i > 16 || i+3 >= len(s) || s[i] != ':' || s[i+1] != '/' || s[i+2] != '/' {
		return false
	}
	for _, c := range s[i+3:] {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

// ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(...)){3}$
func isIPv4(s []byte) bool {
	parts := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			if !isDigit(s[i]) {
				return false
			}
			continue
		}
		o := s[start:i]
		if len(o) < 1 || len(o) > 3 || (len(o) > 1 && o[0] == '0') {
			return false
		}
		v := 0
		for _, c := range o {
			v = v*10 + int(c-'0')
		}
		if v > 255 {
			return false
		}
		parts++
		start = i + 1
	}
	return parts == 4
}

// ^\+[1-9][0-9]{6,14}$
func isPhone(s []byte) bool {
	return len(s) >= 8 && len(s) <= 16 && s[0] == '+' && s[1] >= '1' && s[1] <= '9' && allOf(s[2:], isDigit)
}

// ^-?[0-9]{1,19}$
func isDigitsFmt(s []byte) bool {
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	return len(s) >= 1 && len(s) <= 19 && allOf(s, isDigit)
}

// ^[0-9A-Fa-f]{16,}$
func isHexFmt(s []byte) bool { return len(s) >= 16 && allOf(s, isHex) }

// ---- Name rule (sections 8.0, 9.3 point 3) ----

// hasSixDigits reports [0-9]{6} anywhere in s.
func hasSixDigits(s []byte) bool {
	run := 0
	for _, c := range s {
		if isDigit(c) {
			run++
			if run >= 6 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// valueLikeName reports a name that is recognized as uuid, email, hex,
// digits or jwt, or that holds six or more consecutive digits.
func valueLikeName(k []byte) bool {
	return isUUID(k) || isEmail(k) || isHexFmt(k) || isDigitsFmt(k) || isJWT(k) || hasSixDigits(k)
}

// IsLiteralKey reports whether an object key, query name or cookie name is
// emitted literally: ASCII ^[A-Za-z_][A-Za-z0-9_.-]{0,63}$ and not
// value-like (section 9.3 point 3).
func IsLiteralKey(k []byte) bool {
	if len(k) < 1 || len(k) > 64 || !(isAlpha(k[0]) || k[0] == '_') {
		return false
	}
	for _, c := range k[1:] {
		if !(isAlpha(c) || isDigit(c) || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return !valueLikeName(k)
}

// IsLiteralHeaderName reports whether a lower-cased header name is emitted
// literally: ^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$ and not value-like (8.0).
func IsLiteralHeaderName(n []byte) bool {
	if len(n) < 1 || len(n) > 64 {
		return false
	}
	for _, c := range n {
		if isUpper(c) || !(isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+.^_`|~-", c) >= 0) {
			return false
		}
	}
	return !valueLikeName(n)
}

// ---- Path auto words (section 4.2) ----

// isAutoWord matches ^(?:[a-z]+(?:[-_][a-z]+)*|v[0-9]{1,3})$ with at most 40 bytes.
func isAutoWord(s []byte) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	if s[0] == 'v' && len(s) >= 2 && len(s) <= 4 && allOf(s[1:], isDigit) {
		return true
	}
	prevSep := true // a separator may not start the word
	for _, c := range s {
		switch {
		case isLower(c):
			prevSep = false
		case c == '-' || c == '_':
			if prevSep {
				return false
			}
			prevSep = true
		default:
			return false
		}
	}
	return !prevSep
}

// ---- Time buckets (section 5.5) ----

func atoi(s []byte) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// timeBucket returns the time:… token for a datetime or date string, or ""
// when the string is not a valid date/time (then drop applies). The zone
// offset must also be valid (hours 00–23, minutes 00–59) and the years,
// before and after the conversion to UTC, must stay within 0001–9999.
func timeBucket(s []byte, unit string) string {
	if !allPrintableASCII(s) {
		return ""
	}
	var hh, mm, ss, offset int
	switch {
	case isDate(s):
	default:
		p, ok := splitDatetime(s)
		if !ok {
			return ""
		}
		hh, mm, ss = atoi(s[11:13]), atoi(s[14:16]), atoi(s[17:19])
		if hh > 23 || mm > 59 || ss > 59 {
			return ""
		}
		if z := s[p.tz]; z == '+' || z == '-' {
			oh, om := atoi(s[p.tz+1:p.tz+3]), atoi(s[p.tz+4:p.tz+6])
			if oh > 23 || om > 59 {
				return ""
			}
			offset = oh*3600 + om*60
			if z == '-' {
				offset = -offset
			}
		}
	}
	y, mo, d := atoi(s[0:4]), atoi(s[5:7]), atoi(s[8:10])
	if y < 1 || mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) {
		return ""
	}
	t := time.Date(y, time.Month(mo), d, hh, mm, ss, 0, time.UTC).Add(-time.Duration(offset) * time.Second)
	if t.Year() < 1 || t.Year() > 9999 {
		return ""
	}
	switch unit {
	case "year":
		return t.Format("time:2006")
	case "month":
		return t.Format("time:2006-01")
	case "day":
		return t.Format("time:2006-01-02")
	case "hour":
		return t.Format("time:2006-01-02T15")
	}
	return ""
}

func daysIn(y, m int) int {
	switch m {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if (y%4 == 0 && y%100 != 0) || y%400 == 0 {
			return 29
		}
		return 28
	}
	return 31
}
