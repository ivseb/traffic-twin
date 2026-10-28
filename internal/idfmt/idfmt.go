// Package idfmt implements the id formats of docs/spec/pack.md section 4.3:
// a template, chosen by a person, that synthetic identifiers follow so that
// a client that builds or parses ids (composite ids split on '-', the part
// after the last dot without leading zeros, numeric ids with leading zeros,
// base64url ids) keeps working against the world and the mock.
//
// A template never comes from the traffic: the sources only see HMAC
// tokens, so nothing of a real value (not even its skeleton) is used.
//
// Grammar (whole string, at most 64 characters):
//
//	N            a random digit 0-9
//	A            a random upper-case letter A-Z
//	a            a random lower-case letter a-z
//	X            a random upper-case letter or digit
//	0-9 - . _ : / + = # @    themselves (literal)
//	'text'       a quoted literal (letters too): 'XYZ'.NNNNNN
//	{field}      the value of another field of the same object
//	{field#k}    its k-th segment (split on - . _ : / and space; k < 0 counts from the end)
//	{...|trim0}  without leading zeros;  {...|pad6} left-padded with zeros to 6 characters
//	<...>        the base64url encoding (no padding) of what is inside
//
// The random part of the n-th id of a scope is a permutation of n, so ids
// never repeat until the random space (Capacity) is used up, and the same
// (template, scope, n) always gives the same id: the world generator and
// the mock agree on every id.
package idfmt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
)

// Limits of a template.
const (
	MaxLen = 64
	// MinCapacity is the smallest random space accepted: fewer than a
	// thousand distinct ids would repeat within one world.
	MinCapacity = 1000
	maxParts    = 32
	maxOut      = 256
	// MaxRefWidth bounds pad and the fallback of a copied field.
	MaxRefWidth = 32
	defaultRef  = 6
	permBits    = 62
)

// Error is a template error with a stable code (the console translates it)
// and the position (0-based byte offset) where it was found.
type Error struct {
	Code string `json:"code"`
	At   int    `json:"at"`
}

func (e *Error) Error() string {
	msg := map[string]string{
		"empty":          "the format is empty",
		"too_long":       "the format is longer than 64 characters",
		"bad_char":       "character not allowed",
		"unclosed_quote": "a quoted literal is not closed",
		"empty_literal":  "empty quoted literal",
		"bad_literal":    "a quoted literal may only contain letters, digits and - . _ : / + = # @",
		"unclosed_ref":   "a {field} is not closed",
		"bad_ref":        "malformed {field}: {name}, {name#2}, {name#-1|trim0}, {name|pad6}",
		"nested_b64":     "<...> cannot be nested",
		"unclosed_b64":   "a <...> is not closed",
		"empty_b64":      "empty <...>",
		"too_many_parts": "too many parts",
		"too_small":      "fewer than 1000 different ids: add random characters (N, A, a, X)",
	}[e.Code]
	if msg == "" {
		msg = e.Code
	}
	return fmt.Sprintf("id format: %s (at %d)", msg, e.At)
}

type partKind int

const (
	kRandom partKind = iota
	kLiteral
	kRef
	kB64Open
	kB64Close
)

const (
	alDigits = "0123456789"
	alUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alLower  = "abcdefghijklmnopqrstuvwxyz"
	alAlnum  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type part struct {
	kind  partKind
	alpha string // random: alphabet
	count int    // random: positions
	lit   string // literal
	// ref
	field string
	seg   int // 0 = whole value
	trim0 bool
	pad   int
}

// Template is a parsed id format.
type Template struct {
	src   string
	parts []part
	cap   float64
	re    *regexp.Regexp
	refs  []string
}

var (
	fieldRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)
	litBare   = "0123456789-._:/+=#@"
	litQuoted = regexp.MustCompile(`^[A-Za-z0-9._:/+=#@-]+$`)
	segSep    = func(r rune) bool { return strings.ContainsRune("-._:/ ", r) }
	refValRE  = `[A-Za-z0-9._:/+=#@ -]{1,128}`
	refValAll = regexp.MustCompile("^" + refValRE + "$")
)

// Parse parses and checks a template.
func Parse(s string) (*Template, error) {
	if s == "" {
		return nil, &Error{Code: "empty"}
	}
	if len(s) > MaxLen {
		return nil, &Error{Code: "too_long", At: MaxLen}
	}
	t := &Template{src: s, cap: 1}
	inB64, b64Start, b64Len := false, 0, 0
	add := func(p part, at int) error {
		if n := len(t.parts); n > 0 && p.kind == kRandom && t.parts[n-1].kind == kRandom && t.parts[n-1].alpha == p.alpha {
			t.parts[n-1].count++
			return nil
		}
		if n := len(t.parts); n > 0 && p.kind == kLiteral && t.parts[n-1].kind == kLiteral {
			t.parts[n-1].lit += p.lit
			return nil
		}
		if len(t.parts) >= maxParts {
			return &Error{Code: "too_many_parts", At: at}
		}
		t.parts = append(t.parts, p)
		return nil
	}
	for i := 0; i < len(s); {
		c := s[i]
		var err error
		switch {
		case c == 'N' || c == 'A' || c == 'a' || c == 'X':
			al := map[byte]string{'N': alDigits, 'A': alUpper, 'a': alLower, 'X': alAlnum}[c]
			t.cap *= float64(len(al))
			err = add(part{kind: kRandom, alpha: al, count: 1}, i)
			i++
		case strings.IndexByte(litBare, c) >= 0:
			err = add(part{kind: kLiteral, lit: string(c)}, i)
			i++
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, &Error{Code: "unclosed_quote", At: i}
			}
			lit := s[i+1 : i+1+j]
			if lit == "" {
				return nil, &Error{Code: "empty_literal", At: i}
			}
			if !litQuoted.MatchString(lit) {
				return nil, &Error{Code: "bad_literal", At: i}
			}
			err = add(part{kind: kLiteral, lit: lit}, i)
			i += j + 2
		case c == '{':
			j := strings.IndexByte(s[i+1:], '}')
			if j < 0 {
				return nil, &Error{Code: "unclosed_ref", At: i}
			}
			p, ok := parseRef(s[i+1 : i+1+j])
			if !ok {
				return nil, &Error{Code: "bad_ref", At: i}
			}
			t.refs = append(t.refs, p.field)
			err = add(p, i)
			i += j + 2
		case c == '<':
			if inB64 {
				return nil, &Error{Code: "nested_b64", At: i}
			}
			inB64, b64Start, b64Len = true, i, len(t.parts)
			err = add(part{kind: kB64Open}, i)
			i++
		case c == '>':
			if !inB64 {
				return nil, &Error{Code: "bad_char", At: i}
			}
			if len(t.parts) == b64Len+1 {
				return nil, &Error{Code: "empty_b64", At: b64Start}
			}
			inB64 = false
			err = add(part{kind: kB64Close}, i)
			i++
		default:
			return nil, &Error{Code: "bad_char", At: i}
		}
		if err != nil {
			return nil, err
		}
	}
	if inB64 {
		return nil, &Error{Code: "unclosed_b64", At: b64Start}
	}
	if t.cap < MinCapacity {
		return nil, &Error{Code: "too_small", At: 0}
	}
	t.re = regexp.MustCompile("^" + t.pattern() + "$")
	return t, nil
}

func parseRef(s string) (part, bool) {
	p := part{kind: kRef}
	fns := strings.Split(s, "|")
	name := fns[0]
	if k := strings.IndexByte(name, '#'); k >= 0 {
		n, err := strconv.Atoi(name[k+1:])
		if err != nil || n == 0 || n < -16 || n > 16 {
			return p, false
		}
		p.seg = n
		name = name[:k]
	}
	if !fieldRE.MatchString(name) {
		return p, false
	}
	p.field = name
	for _, f := range fns[1:] {
		switch {
		case f == "trim0":
			p.trim0 = true
		case strings.HasPrefix(f, "pad"):
			n, err := strconv.Atoi(f[3:])
			if err != nil || n < 1 || n > MaxRefWidth || strconv.Itoa(n) != f[3:] {
				return p, false
			}
			p.pad = n
		default:
			return p, false
		}
	}
	return p, true
}

// MustParse is Parse for constants and tests.
func MustParse(s string) *Template {
	t, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return t
}

// String is the template as written.
func (t *Template) String() string { return t.src }

// Capacity is the number of different random parts (how many ids the
// template can give before they repeat).
func (t *Template) Capacity() float64 { return t.cap }

// Refs lists the fields copied by the template, in order.
func (t *Template) Refs() []string { return append([]string(nil), t.refs...) }

// Match tells whether s has the shape of the template (copied fields and
// base64url groups are matched by their alphabet only).
func (t *Template) Match(s string) bool { return t.re.MatchString(s) }

func (t *Template) pattern() string {
	var b strings.Builder
	for i := 0; i < len(t.parts); i++ {
		p := t.parts[i]
		switch p.kind {
		case kRandom:
			cls := map[string]string{alDigits: "[0-9]", alUpper: "[A-Z]", alLower: "[a-z]", alAlnum: "[0-9A-Z]"}[p.alpha]
			fmt.Fprintf(&b, "%s{%d}", cls, p.count)
		case kLiteral:
			b.WriteString(regexp.QuoteMeta(p.lit))
		case kRef:
			b.WriteString(refValRE)
		case kB64Open:
			for i < len(t.parts) && t.parts[i].kind != kB64Close {
				i++
			}
			b.WriteString("[A-Za-z0-9_-]{1,512}")
		}
	}
	return b.String()
}

// Ref returns the value of a field copied by the template (ok false when
// the object has none: the template then uses random digits).
type Ref func(field string) (string, bool)

// ID is the n-th id (n >= 1) of scope (the id domain). ref gives the values
// of copied fields (nil: none).
func (t *Template) ID(n uint64, scope string, ref Ref) string {
	h := sha256.Sum256([]byte("tt.idfmt/v1\x00" + scope + "\x00" + t.src))
	seed := binary.LittleEndian.Uint64(h[16:24])
	// Random positions, left to right.
	type pos struct{ alpha string }
	var ps []pos
	for _, p := range t.parts {
		if p.kind == kRandom {
			for i := 0; i < p.count; i++ {
				ps = append(ps, pos{p.alpha})
			}
		}
	}
	// The rightmost positions whose space fits in 62 bits are a
	// permutation of n; the others come from a hash of n.
	vals := make([]byte, len(ps))
	space := uint64(1)
	low := len(ps)
	for low > 0 {
		r := uint64(len(ps[low-1].alpha))
		if space > (1<<permBits)/r {
			break
		}
		space *= r
		low--
	}
	if space > 1 {
		a := binary.LittleEndian.Uint64(h[0:8])%space | 1
		for gcd(a, space) != 1 {
			a = (a + 2) % space
			if a == 0 {
				a = 1
			}
		}
		b := binary.LittleEndian.Uint64(h[8:16]) % space
		hi, lo := bits.Mul64(a, n%space)
		v := bits.Rem64(hi, lo, space)
		v = (v + b) % space
		for i := len(ps) - 1; i >= low; i-- {
			r := uint64(len(ps[i].alpha))
			vals[i] = ps[i].alpha[v%r]
			v /= r
		}
	}
	for i := 0; i < low; i++ {
		x := mix(seed ^ mix(n) ^ uint64(i+1)*0x9e3779b97f4a7c15)
		vals[i] = ps[i].alpha[x%uint64(len(ps[i].alpha))]
	}
	var out, b64 strings.Builder
	w := &out
	k, refIdx := 0, 0
	for _, p := range t.parts {
		switch p.kind {
		case kRandom:
			w.Write(vals[k : k+p.count])
			k += p.count
		case kLiteral:
			w.WriteString(p.lit)
		case kRef:
			refIdx++
			v, ok := "", false
			if ref != nil {
				v, ok = ref(p.field)
			}
			if ok {
				v, ok = p.apply(v)
			}
			if !ok {
				width := p.pad
				if width == 0 {
					width = defaultRef
				}
				var sb strings.Builder
				x := mix(seed ^ mix(n^uint64(refIdx)<<48) ^ 0x5bd1e995)
				for i := 0; i < width; i++ {
					if i%16 == 15 {
						x = mix(x)
					}
					sb.WriteByte(alDigits[x%10])
					x /= 10
				}
				v = sb.String()
			}
			w.WriteString(v)
		case kB64Open:
			b64.Reset()
			w = &b64
		case kB64Close:
			out.WriteString(base64.RawURLEncoding.EncodeToString([]byte(b64.String())))
			w = &out
		}
	}
	s := out.String()
	if len(s) > maxOut {
		s = s[:maxOut]
	}
	return s
}

// apply selects the segment and applies trim0 and pad to a copied value.
func (p part) apply(v string) (string, bool) {
	if p.seg != 0 {
		segs := strings.FieldsFunc(v, segSep)
		i := p.seg - 1
		if p.seg < 0 {
			i = len(segs) + p.seg
		}
		if i < 0 || i >= len(segs) {
			return "", false
		}
		v = segs[i]
	}
	if p.trim0 {
		v = strings.TrimLeft(v, "0")
		if v == "" {
			v = "0"
		}
	}
	if p.pad > 0 && len(v) < p.pad {
		v = strings.Repeat("0", p.pad-len(v)) + v
	}
	if v == "" || len(v) > 128 || !refValAll.MatchString(v) {
		return "", false
	}
	return v, true
}

// Preview returns the first n ids of the template for scope, with no
// copied field (the console's preview).
func (t *Template) Preview(scope string, n int) []string {
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, t.ID(uint64(i), scope, nil))
	}
	return out
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// mix is the SplitMix64 finalizer.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// CapacityLabel renders a capacity for messages (1e+30 -> "more than 10^18").
func CapacityLabel(c float64) string {
	if c >= 1e18 {
		return "more than 10^18"
	}
	return strconv.FormatFloat(math.Floor(c), 'f', 0, 64)
}

// ValueString renders a scalar state value as a copied field sees it
// (strings as they are, numbers in their JSON form).
func ValueString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, x != ""
	case fmt.Stringer: // json.Number
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	}
	return "", false
}

// MapRef is a Ref over an object (dotted paths).
func MapRef(m map[string]any) Ref {
	if m == nil {
		return nil
	}
	return func(field string) (string, bool) {
		var cur any = m
		for _, k := range strings.Split(field, ".") {
			mm, ok := cur.(map[string]any)
			if !ok {
				return "", false
			}
			if cur, ok = mm[k]; !ok {
				return "", false
			}
		}
		return ValueString(cur)
	}
}
