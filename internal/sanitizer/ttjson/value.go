package ttjson

import (
	"bytes"
	"errors"
	"sort"
	"unicode/utf8"
)

// Kind is the type of a Value.
type Kind uint8

// Value kinds.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Value is a JSON value tree. For Number, Str holds the lexeme (written in
// canonical form by the encoder). For String, Str holds valid UTF-8.
type Value struct {
	Kind Kind
	Bool bool
	Str  string
	Arr  []Value
	Obj  []Member
}

// Member is one object member.
type Member struct {
	Key   string
	Value Value
}

// Constructors.

// Str returns a string Value.
func Str(s string) Value { return Value{Kind: String, Str: s} }

// Num returns a number Value from a lexeme.
func Num(lex string) Value { return Value{Kind: Number, Str: lex} }

// BoolV returns a boolean Value.
func BoolV(b bool) Value { return Value{Kind: Bool, Bool: b} }

// Arr returns an array Value.
func Arr(v ...Value) Value { return Value{Kind: Array, Arr: v} }

// Obj returns an object Value.
func Obj(m ...Member) Value { return Value{Kind: Object, Obj: m} }

// Get returns the member value for key and whether it exists.
func (v Value) Get(key string) (Value, bool) {
	for _, m := range v.Obj {
		if m.Key == key {
			return m.Value, true
		}
	}
	return Value{}, false
}

// ParseOptions configures Parse.
type ParseOptions struct {
	// MaxDepth limits nesting (root has depth 1). Zero means 64.
	MaxDepth int
	// RejectDuplicates makes duplicate object keys an error. Otherwise the
	// last occurrence wins and takes the position of that occurrence.
	RejectDuplicates bool
}

// ErrDuplicateKey is returned by Parse with RejectDuplicates.
var ErrDuplicateKey = errors.New("ttjson: duplicate object key")

// ErrDepth is returned by Parse when MaxDepth is exceeded.
var ErrDepth = errors.New("ttjson: nesting too deep")

// ErrLoneSurrogate is returned by Parse for strings with unpaired surrogates.
var ErrLoneSurrogate = errors.New("ttjson: unpaired surrogate escape")

// Parse parses a complete JSON document into a Value tree. The input must be
// valid UTF-8 with no byte order mark. Strings with unpaired surrogate
// escapes are rejected.
func Parse(d []byte, opt ParseOptions) (Value, error) {
	if !utf8.Valid(d) {
		return Value{}, ErrSyntax
	}
	if opt.MaxDepth <= 0 {
		opt.MaxDepth = 64
	}
	p := parser{d: d, opt: opt}
	v, i, err := p.value(SkipWS(d, 0), 1)
	if err != nil {
		return Value{}, err
	}
	if SkipWS(d, i) != len(d) {
		return Value{}, ErrSyntax
	}
	return v, nil
}

type parser struct {
	d   []byte
	opt ParseOptions
}

func (p *parser) value(i, depth int) (Value, int, error) {
	d := p.d
	if i >= len(d) {
		return Value{}, 0, ErrSyntax
	}
	switch c := d[i]; {
	case c == '{':
		if depth > p.opt.MaxDepth {
			return Value{}, 0, ErrDepth
		}
		var obj []Member
		i = SkipWS(d, i+1)
		if i < len(d) && d[i] == '}' {
			return Value{Kind: Object, Obj: []Member{}}, i + 1, nil
		}
		for {
			end, k, lone, err := ScanString(d, i, nil)
			if err != nil {
				return Value{}, 0, err
			}
			if lone {
				return Value{}, 0, ErrLoneSurrogate
			}
			key := string(k)
			i = SkipWS(d, end)
			if i >= len(d) || d[i] != ':' {
				return Value{}, 0, ErrSyntax
			}
			v, end2, err := p.value(SkipWS(d, i+1), depth+1)
			if err != nil {
				return Value{}, 0, err
			}
			for idx := range obj {
				if obj[idx].Key == key {
					if p.opt.RejectDuplicates {
						return Value{}, 0, ErrDuplicateKey
					}
					obj = append(obj[:idx], obj[idx+1:]...)
					break
				}
			}
			obj = append(obj, Member{Key: key, Value: v})
			i = SkipWS(d, end2)
			if i >= len(d) {
				return Value{}, 0, ErrSyntax
			}
			if d[i] == '}' {
				return Value{Kind: Object, Obj: obj}, i + 1, nil
			}
			if d[i] != ',' {
				return Value{}, 0, ErrSyntax
			}
			i = SkipWS(d, i+1)
		}
	case c == '[':
		if depth > p.opt.MaxDepth {
			return Value{}, 0, ErrDepth
		}
		arr := []Value{}
		i = SkipWS(d, i+1)
		if i < len(d) && d[i] == ']' {
			return Value{Kind: Array, Arr: arr}, i + 1, nil
		}
		for {
			v, end, err := p.value(i, depth+1)
			if err != nil {
				return Value{}, 0, err
			}
			arr = append(arr, v)
			i = SkipWS(d, end)
			if i >= len(d) {
				return Value{}, 0, ErrSyntax
			}
			if d[i] == ']' {
				return Value{Kind: Array, Arr: arr}, i + 1, nil
			}
			if d[i] != ',' {
				return Value{}, 0, ErrSyntax
			}
			i = SkipWS(d, i+1)
		}
	case c == '"':
		end, s, lone, err := ScanString(d, i, nil)
		if err != nil {
			return Value{}, 0, err
		}
		if lone {
			return Value{}, 0, ErrLoneSurrogate
		}
		return Value{Kind: String, Str: string(s)}, end, nil
	case c == 't':
		end, err := ScanLiteral(d, i)
		if err != nil || d[i+1] != 'r' {
			return Value{}, 0, ErrSyntax
		}
		return Value{Kind: Bool, Bool: true}, end, nil
	case c == 'f':
		end, err := ScanLiteral(d, i)
		if err != nil || d[i+1] != 'a' {
			return Value{}, 0, ErrSyntax
		}
		return Value{Kind: Bool}, end, nil
	case c == 'n':
		end, err := ScanLiteral(d, i)
		if err != nil || d[i+1] != 'u' {
			return Value{}, 0, ErrSyntax
		}
		return Value{Kind: Null}, end, nil
	default:
		end, _, err := ScanNumber(d, i)
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Kind: Number, Str: string(d[i:end])}, end, nil
	}
}

// ErrEncode is returned when a Value cannot be written canonically
// (invalid UTF-8 string, invalid number lexeme, duplicate key).
var ErrEncode = errors.New("ttjson: value cannot be encoded")

// Encode writes v in tt canonical JSON (sanitizer section 10).
func Encode(v Value) ([]byte, error) {
	return AppendEncode(nil, v)
}

// AppendEncode appends the canonical encoding of v to b.
func AppendEncode(b []byte, v Value) ([]byte, error) {
	var err error
	switch v.Kind {
	case Null:
		return append(b, "null"...), nil
	case Bool:
		if v.Bool {
			return append(b, "true"...), nil
		}
		return append(b, "false"...), nil
	case Number:
		if !IsNumberLexeme([]byte(v.Str)) {
			return nil, ErrEncode
		}
		return AppendCanonicalNumber(b, []byte(v.Str)), nil
	case String:
		return AppendString(b, v.Str)
	case Array:
		b = append(b, '[')
		for i, e := range v.Arr {
			if i > 0 {
				b = append(b, ',')
			}
			if b, err = AppendEncode(b, e); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case Object:
		idx := make([]int, len(v.Obj))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, c int) bool { return v.Obj[idx[a]].Key < v.Obj[idx[c]].Key })
		b = append(b, '{')
		for n, i := range idx {
			if n > 0 {
				if v.Obj[idx[n-1]].Key == v.Obj[i].Key {
					return nil, ErrEncode
				}
				b = append(b, ',')
			}
			if b, err = AppendString(b, v.Obj[i].Key); err != nil {
				return nil, err
			}
			b = append(b, ':')
			if b, err = AppendEncode(b, v.Obj[i].Value); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	}
	return nil, ErrEncode
}

const hexDigits = "0123456789abcdef"

func appendU(b []byte, r rune) []byte {
	return append(b, '\\', 'u', hexDigits[(r>>12)&0xF], hexDigits[(r>>8)&0xF], hexDigits[(r>>4)&0xF], hexDigits[r&0xF])
}

// AppendString appends s as a canonical JSON string. s must be valid UTF-8.
func AppendString(b []byte, s string) ([]byte, error) {
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"':
				b = append(b, '\\', '"')
			case c == '\\':
				b = append(b, '\\', '\\')
			case c < 0x20 || c == 0x7F:
				b = appendU(b, rune(c))
			default:
				b = append(b, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			return nil, ErrEncode
		}
		if r > 0xFFFF {
			r -= 0x10000
			b = appendU(b, 0xD800+(r>>10))
			b = appendU(b, 0xDC00+(r&0x3FF))
		} else {
			b = appendU(b, r)
		}
		i += size
	}
	return append(b, '"'), nil
}

// IsCanonical reports whether d is exactly the canonical encoding of the
// document it contains (duplicates rejected).
func IsCanonical(d []byte) bool {
	v, err := Parse(d, ParseOptions{MaxDepth: 1 << 20, RejectDuplicates: true})
	if err != nil {
		return false
	}
	out, err := Encode(v)
	return err == nil && bytes.Equal(out, d)
}
