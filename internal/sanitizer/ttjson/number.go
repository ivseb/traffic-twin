package ttjson

import (
	"math/big"
	"strconv"
)

// IsNumberLexeme reports whether s is exactly one RFC 8259 number.
func IsNumberLexeme(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	end, _, err := ScanNumber(s, 0)
	return err == nil && end == len(s)
}

// IsIntLexeme reports whether s matches -?(0|[1-9][0-9]*).
func IsIntLexeme(s []byte) bool {
	end, isInt, err := ScanNumber(s, 0)
	return err == nil && end == len(s) && isInt
}

// CanonicalNumber returns the canonical form (sanitizer section 10.2) of a
// JSON number lexeme, computed in exact decimal arithmetic.
func CanonicalNumber(lex []byte) (string, error) {
	return string(AppendCanonicalNumber(nil, lex)), validateLexeme(lex)
}

func validateLexeme(lex []byte) error {
	if !IsNumberLexeme(lex) {
		return ErrSyntax
	}
	return nil
}

// AppendCanonicalNumber appends the canonical form of lex to b. lex must be
// a valid number lexeme (see IsNumberLexeme); otherwise "0" is appended.
func AppendCanonicalNumber(b []byte, lex []byte) []byte {
	if !IsNumberLexeme(lex) {
		return append(b, '0')
	}
	i := 0
	neg := false
	if lex[0] == '-' {
		neg = true
		i = 1
	}
	intStart := i
	for i < len(lex) && lex[i] >= '0' && lex[i] <= '9' {
		i++
	}
	intPart := lex[intStart:i]
	var frac []byte
	if i < len(lex) && lex[i] == '.' {
		i++
		fs := i
		for i < len(lex) && lex[i] >= '0' && lex[i] <= '9' {
			i++
		}
		frac = lex[fs:i]
	}
	expNeg := false
	var expDigits []byte
	if i < len(lex) && (lex[i] == 'e' || lex[i] == 'E') {
		i++
		if lex[i] == '+' || lex[i] == '-' {
			expNeg = lex[i] == '-'
			i++
		}
		expDigits = lex[i:]
	}

	// digits = intPart || frac, value = digits * 10^(exp - len(frac)).
	// Strip leading zeros (value unchanged) and trailing zeros (exp grows).
	lead := 0
	total := len(intPart) + len(frac)
	digitAt := func(k int) byte {
		if k < len(intPart) {
			return intPart[k]
		}
		return frac[k-len(intPart)]
	}
	for lead < total && digitAt(lead) == '0' {
		lead++
	}
	if lead == total {
		return append(b, '0')
	}
	trail := 0
	for digitAt(total-1-trail) == '0' {
		trail++
	}
	n := total - lead - trail
	digits := make([]byte, 0, n)
	for k := lead; k < total-trail; k++ {
		digits = append(digits, digitAt(k))
	}
	// e = exp - len(frac) + trail + n  (position of the decimal point).
	adj := int64(-len(frac) + trail + n)

	var e int64
	small := false
	// Trim leading zeros of the exponent to decide whether it fits.
	ed := expDigits
	for len(ed) > 1 && ed[0] == '0' {
		ed = ed[1:]
	}
	if len(ed) <= 17 {
		var ev int64
		for _, c := range ed {
			ev = ev*10 + int64(c-'0')
		}
		if expNeg {
			ev = -ev
		}
		e = ev + adj
		small = true
	}
	if neg {
		b = append(b, '-')
	}
	if small && e > -6 && e <= 21 {
		switch {
		case e <= 0:
			b = append(b, '0', '.')
			for k := int64(0); k < -e; k++ {
				b = append(b, '0')
			}
			b = append(b, digits...)
		case e < int64(n):
			b = append(b, digits[:e]...)
			b = append(b, '.')
			b = append(b, digits[e:]...)
		default:
			b = append(b, digits...)
			for k := int64(n); k < e; k++ {
				b = append(b, '0')
			}
		}
		return b
	}
	// Exponential notation d[.ddd]e±k with k = e - 1.
	b = append(b, digits[0])
	if n > 1 {
		b = append(b, '.')
		b = append(b, digits[1:]...)
	}
	b = append(b, 'e')
	if small {
		k := e - 1
		if k >= 0 {
			b = append(b, '+')
		}
		return strconv.AppendInt(b, k, 10)
	}
	ev, _ := new(big.Int).SetString(string(ed), 10)
	if expNeg {
		ev.Neg(ev)
	}
	ev.Add(ev, big.NewInt(adj-1))
	if ev.Sign() >= 0 {
		b = append(b, '+')
	}
	return ev.Append(b, 10)
}

// ParseFloat converts a number lexeme to the nearest IEEE-754 double
// (correct rounding). Out-of-range values become ±Inf.
func ParseFloat(lex []byte) float64 {
	f, _ := strconv.ParseFloat(string(lex), 64)
	return f
}
