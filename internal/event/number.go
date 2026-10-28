package event

import "strings"

// CanonicalNumber returns the canonical form (docs/spec/sanitizer.md 10.2) of
// a JSON number lexeme, computed in exact decimal arithmetic, or false when
// lex is not a valid JSON number.
func CanonicalNumber(lex string) (string, bool) {
	i, n := 0, len(lex)
	if n == 0 {
		return "", false
	}
	neg := false
	if lex[0] == '-' {
		neg = true
		i++
	}
	// Integer part.
	intStart := i
	if i >= n {
		return "", false
	}
	if lex[i] == '0' {
		i++
	} else if lex[i] >= '1' && lex[i] <= '9' {
		for i < n && lex[i] >= '0' && lex[i] <= '9' {
			i++
		}
	} else {
		return "", false
	}
	intPart := lex[intStart:i]
	fracPart := ""
	if i < n && lex[i] == '.' {
		i++
		fs := i
		for i < n && lex[i] >= '0' && lex[i] <= '9' {
			i++
		}
		if i == fs {
			return "", false
		}
		fracPart = lex[fs:i]
	}
	exp := 0
	if i < n && (lex[i] == 'e' || lex[i] == 'E') {
		i++
		eneg := false
		if i < n && (lex[i] == '+' || lex[i] == '-') {
			eneg = lex[i] == '-'
			i++
		}
		es := i
		for i < n && lex[i] >= '0' && lex[i] <= '9' {
			if i-es >= 7 { // absurd exponents are not supported
				return "", false
			}
			exp = exp*10 + int(lex[i]-'0')
			i++
		}
		if i == es {
			return "", false
		}
		if eneg {
			exp = -exp
		}
	}
	if i != n {
		return "", false
	}

	digits := intPart + fracPart
	exp10 := exp - len(fracPart)
	z := 0
	for z < len(digits) && digits[z] == '0' {
		z++
	}
	digits = digits[z:]
	t := len(digits)
	for t > 0 && digits[t-1] == '0' {
		t--
		exp10++
	}
	digits = digits[:t]
	if digits == "" {
		return "0", true
	}
	nd := len(digits)
	e := exp10 + nd
	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	if e > -6 && e <= 21 {
		switch {
		case e <= 0:
			sb.WriteString("0.")
			for k := 0; k < -e; k++ {
				sb.WriteByte('0')
			}
			sb.WriteString(digits)
		case e >= nd:
			sb.WriteString(digits)
			for k := 0; k < e-nd; k++ {
				sb.WriteByte('0')
			}
		default:
			sb.WriteString(digits[:e])
			sb.WriteByte('.')
			sb.WriteString(digits[e:])
		}
	} else {
		sb.WriteByte(digits[0])
		if nd > 1 {
			sb.WriteByte('.')
			sb.WriteString(digits[1:])
		}
		sb.WriteByte('e')
		k := e - 1
		if k < 0 {
			sb.WriteByte('-')
			k = -k
		} else {
			sb.WriteByte('+')
		}
		sb.WriteString(itoa(int64(k)))
	}
	return sb.String(), true
}

// NumberWithinLimits reports whether a canonical number lexeme could come
// from an input lexeme that respects the limits of sanitizer.md 5.3 (at most
// 64 bytes and |exponent| <= 9999). The canonical form can be a few bytes
// longer than the original (1.5e-3 becomes 0.0015), so the bounds are
// slightly wider than the source limits.
func NumberWithinLimits(canon string) bool {
	if len(canon) > 80 {
		return false
	}
	if k := strings.IndexByte(canon, 'e'); k >= 0 {
		x := 0
		for _, c := range canon[k+2:] {
			x = x*10 + int(c-'0')
			if x > 10100 {
				return false
			}
		}
	}
	return true
}
