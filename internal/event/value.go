package event

import (
	"bytes"
	"sort"
	"strconv"
	"unicode/utf8"
)

// Kind is the JSON type of a [Value].
type Kind uint8

// JSON kinds.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Value is a JSON value of an event body. Numbers keep their (canonical)
// lexeme in S; objects are slices of members sorted by key bytes.
type Value struct {
	Kind Kind
	B    bool
	S    string
	A    []Value
	O    []Member
}

// Member is one object member.
type Member struct {
	K string
	V Value
}

// Str returns a string value.
func Str(s string) Value { return Value{Kind: String, S: s} }

// Arr returns an array value.
func Arr(vs ...Value) Value { return Value{Kind: Array, A: vs} }

// Obj returns an object value with members sorted by key bytes.
func Obj(ms ...Member) Value {
	v := Value{Kind: Object, O: ms}
	v.SortMembers()
	return v
}

// SortMembers sorts the members of an object by key bytes (canonical order).
func (v *Value) SortMembers() {
	sort.SliceStable(v.O, func(i, j int) bool { return v.O[i].K < v.O[j].K })
}

// Get returns the member with the given key.
func (v *Value) Get(key string) (*Value, bool) {
	// Members are sorted: binary search for larger objects.
	if len(v.O) > 12 {
		i := sort.Search(len(v.O), func(i int) bool { return v.O[i].K >= key })
		if i < len(v.O) && v.O[i].K == key {
			return &v.O[i].V, true
		}
		return nil, false
	}
	for i := range v.O {
		if v.O[i].K == key {
			return &v.O[i].V, true
		}
	}
	return nil, false
}

// Clone returns a deep copy of v.
func (v Value) Clone() Value {
	out := v
	if v.A != nil {
		out.A = make([]Value, len(v.A))
		for i := range v.A {
			out.A[i] = v.A[i].Clone()
		}
	}
	if v.O != nil {
		out.O = make([]Member, len(v.O))
		for i := range v.O {
			out.O[i] = Member{K: v.O[i].K, V: v.O[i].V.Clone()}
		}
	}
	return out
}

// AppendCanonical appends the tt-cjson encoding of v to dst. Object members
// must already be sorted (see [Value.SortMembers]); number lexemes must be
// canonical.
func (v *Value) AppendCanonical(dst []byte) []byte {
	switch v.Kind {
	case Null:
		return append(dst, "null"...)
	case Bool:
		if v.B {
			return append(dst, "true"...)
		}
		return append(dst, "false"...)
	case Number:
		return append(dst, v.S...)
	case String:
		return AppendString(dst, v.S)
	case Array:
		dst = append(dst, '[')
		for i := range v.A {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = v.A[i].AppendCanonical(dst)
		}
		return append(dst, ']')
	default:
		dst = append(dst, '{')
		for i := range v.O {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = AppendString(dst, v.O[i].K)
			dst = append(dst, ':')
			dst = v.O[i].V.AppendCanonical(dst)
		}
		return append(dst, '}')
	}
}

// Canonical returns the tt-cjson bytes of v.
func (v *Value) Canonical() []byte { return v.AppendCanonical(nil) }

const hexLower = "0123456789abcdef"

// AppendString appends s as a tt-cjson string (docs/spec/sanitizer.md 10.1):
// only '"' and '\' use short escapes; control characters, 0x7f and every
// non-ASCII character use lowercase \uXXXX (surrogate pairs above U+FFFF).
func AppendString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' {
			i++
			continue
		}
		dst = append(dst, s[start:i]...)
		switch {
		case c == '"':
			dst = append(dst, '\\', '"')
			i++
		case c == '\\':
			dst = append(dst, '\\', '\\')
			i++
		case c < 0x80:
			dst = appendU(dst, rune(c))
			i++
		default:
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n <= 1 {
				r = 0xfffd
				n = 1
			}
			if r > 0xffff {
				r -= 0x10000
				dst = appendU(dst, 0xd800+(r>>10))
				dst = appendU(dst, 0xdc00+(r&0x3ff))
			} else {
				dst = appendU(dst, r)
			}
			i += n
		}
		start = i
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

func appendU(dst []byte, r rune) []byte {
	return append(dst, '\\', 'u', hexLower[(r>>12)&0xf], hexLower[(r>>8)&0xf], hexLower[(r>>4)&0xf], hexLower[r&0xf])
}

// CompareCanonical orders values by their canonical encoding (used to sort
// the values collected under the collapsed key {*}, docs/spec/sanitizer.md
// 9.3 point 4).
func CompareCanonical(a, b *Value) int {
	return bytes.Compare(a.AppendCanonical(nil), b.AppendCanonical(nil))
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
