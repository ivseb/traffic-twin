package event

import (
	"strings"
	"unicode/utf8"
)

// TokenKind classifies a token string (docs/spec/sanitizer.md 6.1).
type TokenKind uint8

// Token kinds.
const (
	TokInvalid TokenKind = iota
	TokDrop
	TokKeep
	TokHMAC
	TokNum
	TokTime
	TokTrunc
	// TokGQL is a gql: token (sanitizer.md 5.7, spec v1.14): the shape of a
	// GraphQL document or a name of an introspection result.
	TokGQL
)

func (k TokenKind) String() string {
	switch k {
	case TokDrop:
		return "drop"
	case TokKeep:
		return "keep"
	case TokHMAC:
		return "tk1"
	case TokNum:
		return "num"
	case TokTime:
		return "time"
	case TokTrunc:
		return "trunc"
	case TokGQL:
		return "gql"
	}
	return "invalid"
}

// MaxTokenChars is the schema limit (maxLength) of a token, in characters.
const MaxTokenChars = 1100

// ClassifyToken returns the kind of s if it belongs to the token grammar of
// the event schema ($defs/token), or TokInvalid.
func ClassifyToken(s string) TokenKind {
	if len(s) < 5 {
		return TokInvalid
	}
	switch s[0] {
	case 'd':
		if strings.HasPrefix(s, "drop:") && ValidDrop(s) {
			return TokDrop
		}
	case 'k':
		if strings.HasPrefix(s, "keep:") {
			if len(s) > MaxTokenChars && utf8.RuneCountInString(s) > MaxTokenChars {
				return TokInvalid
			}
			return TokKeep
		}
	case 't':
		if strings.HasPrefix(s, "tk1:") {
			if ValidHMACToken(s) {
				return TokHMAC
			}
		} else if strings.HasPrefix(s, "time:") {
			if ValidTimeToken(s) {
				return TokTime
			}
		} else if strings.HasPrefix(s, "trunc:") && ValidTrunc(s) {
			return TokTrunc
		}
	case 'n':
		if strings.HasPrefix(s, "num:") && ValidNumToken(s) {
			return TokNum
		}
	case 'g':
		if strings.HasPrefix(s, "gql:") && ValidGQLToken(s) {
			return TokGQL
		}
	}
	return TokInvalid
}

// MaxGQLTokenBytes is the longest gql: token: the prefix and a shape of at
// most 32768 bytes (sanitizer.md 5.7).
const MaxGQLTokenBytes = 4 + 32768

// ValidGQLToken reports whether s is gql: followed by at least one byte of
// the shape alphabet (ASCII letters, digits, _, the GraphQL punctuators,
// ?, * and space), within MaxGQLTokenBytes. Whether the rest parses as a
// shape or a name is checked by the intake against the rule.
func ValidGQLToken(s string) bool {
	if len(s) <= 4 || len(s) > MaxGQLTokenBytes || s[:4] != "gql:" {
		return false
	}
	for i := 4; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			if strings.IndexByte("_!$&():=@[]{}|. ?*", c) < 0 {
				return false
			}
		}
	}
	return true
}

var lenClasses = map[string]bool{"l8": true, "l32": true, "l128": true, "l1024": true, "lmax": true}

// ValidLenClass reports whether s is one of the five length classes.
func ValidLenClass(s string) bool { return lenClasses[s] }

// LenClass returns the length class of n (docs/spec/sanitizer.md 0.3).
func LenClass(n int) string {
	switch {
	case n <= 8:
		return "l8"
	case n <= 32:
		return "l32"
	case n <= 128:
		return "l128"
	case n <= 1024:
		return "l1024"
	}
	return "lmax"
}

var dropFormats = map[string]bool{
	"invalid": true, "uuid": true, "jwt": true, "email": true, "datetime": true, "date": true,
	"url": true, "ipv4": true, "phone": true, "digits": true, "hex": true,
	"l8": true, "l32": true, "l128": true, "l1024": true, "lmax": true,
}

// Document kinds and classes of drop:doc and drop:file (sanitizer.md 22.3,
// 22.4, spec v1.19).
var (
	docKinds   = map[string]bool{"pdf": true, "png": true, "jpeg": true, "gif": true, "webp": true, "ole": true, "zip": true, "docx": true, "xlsx": true, "pptx": true}
	fileKinds  = map[string]bool{"text": true, "csv": true, "json": true, "xml": true, "bin": true}
	docClasses = map[string]bool{"l1k": true, "l16k": true, "l128k": true, "l1m": true, "l8m": true, "lmax": true}
)

// DocShape splits a drop:doc or drop:file token into (file, kind, class).
func DocShape(s string) (file bool, kind, class string, ok bool) {
	rest, isDoc := strings.CutPrefix(s, "drop:doc:")
	if !isDoc {
		if rest, ok = strings.CutPrefix(s, "drop:file:"); !ok {
			return false, "", "", false
		}
		file = true
	}
	kind, class, found := strings.Cut(rest, ":")
	if !found || !docClasses[class] || !(docKinds[kind] || (file && fileKinds[kind])) {
		return false, "", "", false
	}
	return file, kind, class, true
}

// ValidDrop reports whether s is a valid drop form ($defs/token, first pattern).
func ValidDrop(s string) bool {
	rest, ok := strings.CutPrefix(s, "drop:")
	if !ok {
		return false
	}
	switch rest {
	case "null", "bool", "int", "dec", "bytes":
		return true
	}
	if f, ok := strings.CutPrefix(rest, "str:"); ok {
		return dropFormats[f]
	}
	if strings.HasPrefix(rest, "doc:") || strings.HasPrefix(rest, "file:") {
		_, _, _, ok := DocShape(s)
		return ok
	}
	for _, p := range [...]string{"obj:", "arr:", "bytes:"} {
		if c, ok := strings.CutPrefix(rest, p); ok {
			return lenClasses[c]
		}
	}
	return false
}

// ValidTrunc reports whether s is a valid trunc marker.
func ValidTrunc(s string) bool {
	rest, ok := strings.CutPrefix(s, "trunc:")
	if !ok {
		return false
	}
	switch rest {
	case "depth", "invalid-json", "size", "invalid-xml", "invalid-multipart":
		return true
	}
	for _, p := range [...]string{"n:", "keys:"} {
		if c, ok := strings.CutPrefix(rest, p); ok {
			return lenClasses[c]
		}
	}
	return false
}

// ValidHMACToken reports whether s is tk1:<kid>:<22 base64url chars>.
func ValidHMACToken(s string) bool {
	_, _, ok := SplitHMACToken(s)
	return ok
}

// SplitHMACToken returns the kid and the 22-character MAC part of a token.
func SplitHMACToken(s string) (kid, mac string, ok bool) {
	rest, found := strings.CutPrefix(s, "tk1:")
	if !found {
		return "", "", false
	}
	i := strings.IndexByte(rest, ':')
	if i < 1 || i > 8 {
		return "", "", false
	}
	kid, mac = rest[:i], rest[i+1:]
	for k := 0; k < len(kid); k++ {
		c := kid[k]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return "", "", false
		}
	}
	if len(mac) != 22 {
		return "", "", false
	}
	for k := 0; k < 22; k++ {
		if !isB64URL(mac[k]) {
			return "", "", false
		}
	}
	return kid, mac, true
}

func isB64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// ValidDiscToken reports whether s is a discovery token tkd:<6 base64url>.
func ValidDiscToken(s string) bool {
	rest, ok := strings.CutPrefix(s, "tkd:")
	if !ok || len(rest) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if !isB64URL(rest[i]) {
			return false
		}
	}
	return true
}

// ValidNumToken reports whether s matches ^num:(<|>=)?-?[0-9][0-9.e+-]*$.
func ValidNumToken(s string) bool {
	rest, ok := strings.CutPrefix(s, "num:")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "<")
	if strings.HasPrefix(rest, ">=") {
		rest = rest[2:]
	}
	rest = strings.TrimPrefix(rest, "-")
	if rest == "" || rest[0] < '0' || rest[0] > '9' {
		return false
	}
	for i := 1; i < len(rest); i++ {
		c := rest[i]
		if !(c >= '0' && c <= '9' || c == '.' || c == 'e' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

// ValidTimeToken reports whether s is a time bucket: time:YYYY, time:YYYY-MM,
// time:YYYY-MM-DD or time:YYYY-MM-DDTHH with calendar-valid fields.
func ValidTimeToken(s string) bool {
	_, ok := TimeTokenUnit(s)
	return ok
}

// TimeTokenUnit returns the unit ("year", "month", "day", "hour") of a valid
// time token.
func TimeTokenUnit(s string) (string, bool) {
	r, ok := strings.CutPrefix(s, "time:")
	if !ok {
		return "", false
	}
	switch len(r) {
	case 4:
		y, ok := atoi(r)
		if !ok || y < 1 {
			return "", false
		}
		return "year", true
	case 7:
		if r[4] != '-' {
			return "", false
		}
		y, ok1 := atoi(r[:4])
		m, ok2 := atoi(r[5:])
		if !ok1 || !ok2 || y < 1 || m < 1 || m > 12 {
			return "", false
		}
		return "month", true
	case 10, 13:
		if r[4] != '-' || r[7] != '-' {
			return "", false
		}
		y, ok1 := atoi(r[:4])
		m, ok2 := atoi(r[5:7])
		d, ok3 := atoi(r[8:10])
		if !ok1 || !ok2 || !ok3 || y < 1 || m < 1 || m > 12 || d < 1 || d > daysIn(y, m) {
			return "", false
		}
		if len(r) == 10 {
			return "day", true
		}
		if r[10] != 'T' {
			return "", false
		}
		h, ok := atoi(r[11:])
		if !ok || h > 23 {
			return "", false
		}
		return "hour", true
	}
	return "", false
}

func atoi(s string) (int, bool) {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, len(s) > 0
}

func daysIn(y, m int) int {
	switch m {
	case 2:
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// KeepValue returns the value of a keep token.
func KeepValue(tok string) (string, bool) { return strings.CutPrefix(tok, "keep:") }

// ---------------------------------------------------------------------------
// Formats (docs/spec/sanitizer.md 6.3), hand-written so that they are cheap.

// Format returns the recognized format of s ("uuid", "jwt", "email",
// "datetime", "date", "url", "ipv4", "phone", "digits", "hex") or "".
// The formats are tried in the order of the specification.
func Format(s string) string {
	if !isPrintableASCII(s) {
		return ""
	}
	switch {
	case isUUID(s):
		return "uuid"
	case isJWT(s):
		return "jwt"
	case isEmail(s):
		return "email"
	case isDatetime(s):
		return "datetime"
	case isDate(s):
		return "date"
	case isURL(s):
		return "url"
	case isIPv4(s):
		return "ipv4"
	case isPhone(s):
		return "phone"
	case isDigits(s):
		return "digits"
	case isHex(s):
		return "hex"
	}
	return ""
}

// DropForm returns the drop form of a string value (docs/spec/sanitizer.md
// 6.2): drop:str:invalid for invalid UTF-8, drop:str:<format> or
// drop:str:<length class>.
func DropForm(s string) string {
	if !utf8.ValidString(s) {
		return "drop:str:invalid"
	}
	if f := Format(s); f != "" {
		return "drop:str:" + f
	}
	return "drop:str:" + LenClass(len(s))
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
		} else if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

func isB64Seg(s string, min int) bool {
	if len(s) < min {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isB64URL(s[i]) {
			return false
		}
	}
	return true
}

func isJWT(s string) bool {
	if !strings.HasPrefix(s, "eyJ") {
		return false
	}
	p := strings.Split(s, ".")
	return len(p) == 3 && isB64Seg(p[0], 3) && isB64Seg(p[1], 1) && isB64Seg(p[2], 0)
}

func isEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at < 1 || at > 64 {
		return false
	}
	for i := 0; i < at; i++ {
		c := s[i]
		if !(isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-') {
			return false
		}
	}
	labels := strings.Split(s[at+1:], ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			if !(isAlpha(l[i]) || isDigit(l[i]) || l[i] == '-') {
				return false
			}
		}
	}
	return true
}

func digitsAt(s string, i, n int) bool {
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

func isDate(s string) bool {
	return len(s) == 10 && digitsAt(s, 0, 4) && s[4] == '-' && digitsAt(s, 5, 2) && s[7] == '-' && digitsAt(s, 8, 2)
}

func isDatetime(s string) bool {
	if len(s) < 20 || !isDate(s[:10]) {
		return false
	}
	if c := s[10]; c != 'T' && c != 't' && c != ' ' {
		return false
	}
	if !(digitsAt(s, 11, 2) && s[13] == ':' && digitsAt(s, 14, 2) && s[16] == ':' && digitsAt(s, 17, 2)) {
		return false
	}
	rest := s[19:]
	if rest != "" && rest[0] == '.' {
		i := 1
		for i < len(rest) && isDigit(rest[i]) {
			i++
		}
		if i < 2 || i > 10 {
			return false
		}
		rest = rest[i:]
	}
	switch {
	case rest == "Z" || rest == "z":
		return true
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-'):
		return digitsAt(rest, 1, 2) && rest[3] == ':' && digitsAt(rest, 4, 2)
	}
	return false
}

func isURL(s string) bool {
	i := strings.Index(s, "://")
	if i < 1 || i > 16 || !isAlpha(s[0]) {
		return false
	}
	for k := 1; k < i; k++ {
		c := s[k]
		if !(isAlpha(c) || isDigit(c) || c == '+' || c == '.' || c == '-') {
			return false
		}
	}
	rest := s[i+3:]
	if rest == "" {
		return false
	}
	for k := 0; k < len(rest); k++ {
		if rest[k] < '!' || rest[k] > '~' {
			return false
		}
	}
	return true
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			if !isDigit(p[i]) {
				return false
			}
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isPhone(s string) bool {
	return len(s) >= 8 && len(s) <= 16 && s[0] == '+' && s[1] >= '1' && s[1] <= '9' && digitsAt(s, 2, len(s)-2)
}

func isDigits(s string) bool {
	t := strings.TrimPrefix(s, "-")
	return len(t) >= 1 && len(t) <= 19 && digitsAt(t, 0, len(t))
}

func isHex(s string) bool {
	if len(s) < 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// DynamicName reports whether a name (JSON key, query or cookie name, header
// name) violates the name rule of docs/spec/sanitizer.md 9.3 point 3 beyond
// its character set: it is recognized as uuid, email, hex, digits or jwt, or
// contains six or more consecutive digits. A conformant sanitizer collapses
// such names to {*}, so they must never appear literally in an event.
func DynamicName(name string) bool {
	run := 0
	for i := 0; i < len(name); i++ {
		if isDigit(name[i]) {
			run++
			if run >= 6 {
				return true
			}
		} else {
			run = 0
		}
	}
	if len(name) > 0 && isPrintableASCII(name) {
		return isUUID(name) || isJWT(name) || isEmail(name) || isDigits(name) || isHex(name)
	}
	return false
}
