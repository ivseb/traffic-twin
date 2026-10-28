package event

import (
	"unicode/utf8"
)

// Error codes of [DecodeError].
const (
	// CodeJSON: the bytes are not valid JSON (or contain a lone surrogate).
	CodeJSON = "json"
	// CodeNonCanonical: valid JSON that is not exactly the tt-cjson form.
	CodeNonCanonical = "non_canonical"
	// CodeSchema: canonical JSON that does not match the event schema.
	CodeSchema = "schema"
)

// DecodeError describes why bytes are not an acceptable event. It never
// contains payload values: Detail is a static description.
type DecodeError struct {
	Code   string
	Detail string
}

func (e *DecodeError) Error() string { return "event: " + e.Code + ": " + e.Detail }

func jsonErr(d string) *DecodeError  { return &DecodeError{CodeJSON, d} }
func canonErr(d string) *DecodeError { return &DecodeError{CodeNonCanonical, d} }
func schemaErr(d string) *DecodeError {
	return &DecodeError{CodeSchema, d}
}

// MaxNesting bounds the nesting depth accepted by the parser. Policies allow
// at most 128 levels in a body; the event wraps the body in a few more.
const MaxNesting = 160

type parser struct {
	b     []byte
	i     int
	depth int
}

// ParseCanonical parses b, which must be exactly the tt-cjson encoding of one
// JSON value: no whitespace, object keys in strictly increasing byte order
// (so no duplicates), strings escaped as in sanitizer.md 10.1 and numbers in
// canonical form (10.2). It returns CodeJSON for invalid JSON and
// CodeNonCanonical for valid JSON in any other spelling.
func ParseCanonical(b []byte) (Value, *DecodeError) {
	p := parser{b: b}
	v, err := p.value()
	if err != nil {
		return Value{}, err
	}
	if p.i != len(b) {
		if isWS(b[p.i]) {
			return Value{}, canonErr("whitespace")
		}
		return Value{}, jsonErr("trailing data")
	}
	return v, nil
}

func isWS(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (p *parser) unexpected() *DecodeError {
	if p.i < len(p.b) && isWS(p.b[p.i]) {
		return canonErr("whitespace")
	}
	return jsonErr("unexpected byte")
}

func (p *parser) value() (Value, *DecodeError) {
	if p.i >= len(p.b) {
		return Value{}, jsonErr("unexpected end")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.str()
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: String, S: s}, nil
	case c == 't':
		if p.lit("true") {
			return Value{Kind: Bool, B: true}, nil
		}
	case c == 'f':
		if p.lit("false") {
			return Value{Kind: Bool}, nil
		}
	case c == 'n':
		if p.lit("null") {
			return Value{Kind: Null}, nil
		}
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return Value{}, p.unexpected()
}

func (p *parser) lit(s string) bool {
	if len(p.b)-p.i >= len(s) && string(p.b[p.i:p.i+len(s)]) == s {
		p.i += len(s)
		return true
	}
	return false
}

func (p *parser) number() (Value, *DecodeError) {
	start := p.i
	i := p.i
	n := len(p.b)
	if p.b[i] == '-' {
		i++
	}
	if i >= n {
		return Value{}, jsonErr("bad number")
	}
	if p.b[i] == '0' {
		i++
	} else if p.b[i] >= '1' && p.b[i] <= '9' {
		for i < n && p.b[i] >= '0' && p.b[i] <= '9' {
			i++
		}
	} else {
		return Value{}, jsonErr("bad number")
	}
	simple := true
	if i < n && p.b[i] == '.' {
		simple = false
		i++
		fs := i
		for i < n && p.b[i] >= '0' && p.b[i] <= '9' {
			i++
		}
		if i == fs {
			return Value{}, jsonErr("bad number")
		}
	}
	if i < n && (p.b[i] == 'e' || p.b[i] == 'E') {
		simple = false
		i++
		if i < n && (p.b[i] == '+' || p.b[i] == '-') {
			i++
		}
		es := i
		for i < n && p.b[i] >= '0' && p.b[i] <= '9' {
			i++
		}
		if i == es {
			return Value{}, jsonErr("bad number")
		}
	}
	lex := p.b[start:i]
	p.i = i
	if simple && len(lex) <= 21 && !(len(lex) == 2 && lex[0] == '-' && lex[1] == '0') {
		// Plain integers up to 21 digits are their own canonical form
		// (the leading '-' of a negative number is not a digit, so
		// len(lex) <= 21 is a safe over-approximation).
		return Value{Kind: Number, S: string(lex)}, nil
	}
	s := string(lex)
	canon, ok := CanonicalNumber(s)
	if !ok {
		return Value{}, jsonErr("bad number")
	}
	if canon != s {
		return Value{}, canonErr("number form")
	}
	return Value{Kind: Number, S: s}, nil
}

// str parses a string whose opening quote is at p.i.
func (p *parser) str() (string, *DecodeError) {
	p.i++
	start := p.i
	b := p.b
	for p.i < len(b) {
		c := b[p.i]
		if c == '"' {
			s := string(b[start:p.i])
			p.i++
			return s, nil
		}
		if c == '\\' {
			return p.strSlow(start)
		}
		if c < 0x20 {
			return "", jsonErr("control character in string")
		}
		if c >= 0x7f {
			return "", canonErr("unescaped non-ASCII or DEL")
		}
		p.i++
	}
	return "", jsonErr("unterminated string")
}

func (p *parser) strSlow(start int) (string, *DecodeError) {
	b := p.b
	buf := append(make([]byte, 0, p.i-start+16), b[start:p.i]...)
	for p.i < len(b) {
		c := b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(buf), nil
		case c < 0x20:
			return "", jsonErr("control character in string")
		case c >= 0x7f:
			return "", canonErr("unescaped non-ASCII or DEL")
		case c != '\\':
			buf = append(buf, c)
			p.i++
			continue
		}
		// Escape sequence.
		if p.i+1 >= len(b) {
			return "", jsonErr("unterminated string")
		}
		switch e := b[p.i+1]; e {
		case '"', '\\':
			buf = append(buf, e)
			p.i += 2
		case 'u':
			cu, ok := hex4(b, p.i+2)
			if !ok {
				if hex4Any(b, p.i+2) {
					return "", canonErr("uppercase hex in escape")
				}
				return "", jsonErr("bad unicode escape")
			}
			p.i += 6
			switch {
			case cu >= 0xd800 && cu <= 0xdbff:
				if p.i+1 < len(b) && b[p.i] == '\\' && b[p.i+1] == 'u' {
					lo, ok := hex4(b, p.i+2)
					if !ok {
						if hex4Any(b, p.i+2) {
							return "", canonErr("uppercase hex in escape")
						}
						return "", jsonErr("bad unicode escape")
					}
					if lo < 0xdc00 || lo > 0xdfff {
						return "", jsonErr("lone surrogate")
					}
					p.i += 6
					r := 0x10000 + (rune(cu)-0xd800)<<10 + (rune(lo) - 0xdc00)
					buf = utf8.AppendRune(buf, r)
				} else {
					return "", jsonErr("lone surrogate")
				}
			case cu >= 0xdc00 && cu <= 0xdfff:
				return "", jsonErr("lone surrogate")
			case cu < 0x20 || cu == 0x7f || cu >= 0x80:
				buf = utf8.AppendRune(buf, rune(cu))
			default:
				return "", canonErr("needless unicode escape")
			}
		case '/', 'b', 'f', 'n', 'r', 't':
			return "", canonErr("short escape")
		default:
			return "", jsonErr("bad escape")
		}
	}
	return "", jsonErr("unterminated string")
}

// hex4 reads four lowercase hex digits at b[i:].
func hex4(b []byte, i int) (uint16, bool) {
	if i+4 > len(b) {
		return 0, false
	}
	var v uint16
	for _, c := range b[i : i+4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint16(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint16(c-'a'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// hex4Any reports whether b[i:i+4] are hex digits of any case.
func hex4Any(b []byte, i int) bool {
	if i+4 > len(b) {
		return false
	}
	for _, c := range b[i : i+4] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (p *parser) array() (Value, *DecodeError) {
	p.depth++
	if p.depth > MaxNesting {
		return Value{}, schemaErr("nesting too deep")
	}
	p.i++
	v := Value{Kind: Array}
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		p.depth--
		return v, nil
	}
	for {
		el, err := p.value()
		if err != nil {
			return Value{}, err
		}
		v.A = append(v.A, el)
		if p.i >= len(p.b) {
			return Value{}, jsonErr("unexpected end")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			p.depth--
			return v, nil
		default:
			return Value{}, p.unexpected()
		}
	}
}

func (p *parser) object() (Value, *DecodeError) {
	p.depth++
	if p.depth > MaxNesting {
		return Value{}, schemaErr("nesting too deep")
	}
	p.i++
	v := Value{Kind: Object}
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		p.depth--
		return v, nil
	}
	for {
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			if p.i >= len(p.b) {
				return Value{}, jsonErr("unexpected end")
			}
			return Value{}, p.unexpected()
		}
		k, err := p.str()
		if err != nil {
			return Value{}, err
		}
		if n := len(v.O); n > 0 && k <= v.O[n-1].K {
			if k == v.O[n-1].K {
				return Value{}, canonErr("duplicate key")
			}
			return Value{}, canonErr("key order")
		}
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			if p.i >= len(p.b) {
				return Value{}, jsonErr("unexpected end")
			}
			return Value{}, p.unexpected()
		}
		p.i++
		el, err := p.value()
		if err != nil {
			return Value{}, err
		}
		v.O = append(v.O, Member{K: k, V: el})
		if p.i >= len(p.b) {
			return Value{}, jsonErr("unexpected end")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			p.depth--
			return v, nil
		default:
			return Value{}, p.unexpected()
		}
	}
}
