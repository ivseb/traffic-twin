// Package graphql parses GraphQL executable documents for traffic-twin.
//
// It has two users. The sanitizer (zone A) turns the text of a document into
// its shape (docs/spec/sanitizer.md 5.7): names are kept, every literal value
// becomes a placeholder, so no value written inline in a query ever leaves
// the source. The core and the mock parse shapes (the gql: tokens of the
// events) and real documents (the requests the mock answers) into the same
// tree, to split one GraphQL endpoint into its logical operations
// (docs/spec/event.md 6), build their contracts and answer them.
//
// The package has no dependency besides the standard library: the reference
// ports in the SDKs follow the same algorithm step by step.
package graphql

import (
	"errors"
)

// Limits of section 5.7 of the sanitizer specification.
const (
	// MaxNesting is the largest number of open brackets ({, ( and [ together).
	MaxNesting = 64
	// MaxShapeBytes is the largest shape; a longer one is not emitted.
	MaxShapeBytes = 32768
	// MaxNameBytes is the longest name emitted as written (longer names
	// become "*", like a JSON key that is not a literal name).
	MaxNameBytes = 64
)

// ErrSyntax is returned for any input that is not an executable document
// within the limits.
var ErrSyntax = errors.New("graphql: not an executable document")

type tokKind uint8

const (
	tPunct tokKind = iota // ! $ & ( ) ... : = @ [ ] { | }
	tName
	tInt
	tFloat
	tString // string or block string
	tHole   // shape placeholder ?s ?i ?f ?b ?n ?e (shape mode only)
)

type token struct {
	kind tokKind
	s    string // punctuator, name, or placeholder letter for tHole
	// value marks a name in value position (enum, true, false, null): the
	// parser sets it, the shape replaces the name with a placeholder.
	value bool
}

func isNameStart(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
func isNameCont(c byte) bool  { return isNameStart(c) || c >= '0' && c <= '9' }
func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// lex splits src into tokens (sanitizer.md 5.7, "Lexing"). shape accepts the
// placeholders of a shape (?s ?i ?f ?b ?n ?e) and "*" as a name.
func lex(src string, shape bool) ([]token, error) {
	var toks []token
	open := 0
	i := 0
	n := len(src)
	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
			continue
		case c == 0xEF && i+2 < n && src[i+1] == 0xBB && src[i+2] == 0xBF: // U+FEFF
			i += 3
			continue
		case c == '#':
			for i < n && src[i] != '\n' && src[i] != '\r' {
				i++
			}
			continue
		case c == '!' || c == '$' || c == '&' || c == ':' || c == '=' || c == '@' || c == '|':
			toks = append(toks, token{kind: tPunct, s: src[i : i+1]})
			i++
			continue
		case c == '(' || c == '[' || c == '{':
			open++
			if open > MaxNesting {
				return nil, ErrSyntax
			}
			toks = append(toks, token{kind: tPunct, s: src[i : i+1]})
			i++
			continue
		case c == ')' || c == ']' || c == '}':
			open--
			if open < 0 {
				return nil, ErrSyntax
			}
			toks = append(toks, token{kind: tPunct, s: src[i : i+1]})
			i++
			continue
		case c == '.':
			if i+2 < n && src[i+1] == '.' && src[i+2] == '.' {
				toks = append(toks, token{kind: tPunct, s: "..."})
				i += 3
				continue
			}
			return nil, ErrSyntax
		case isNameStart(c):
			j := i + 1
			for j < n && isNameCont(src[j]) {
				j++
			}
			toks = append(toks, token{kind: tName, s: src[i:j]})
			i = j
			continue
		case c == '-' || isDigit(c):
			j, k, err := lexNumber(src, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: k})
			i = j
			continue
		case c == '"':
			j, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tString})
			i = j
			continue
		case shape && c == '*':
			toks = append(toks, token{kind: tName, s: "*"})
			i++
			continue
		case shape && c == '?':
			if i+1 < n {
				switch src[i+1] {
				case 's', 'i', 'f', 'b', 'n', 'e':
					if i+2 >= n || !isNameCont(src[i+2]) {
						toks = append(toks, token{kind: tHole, s: src[i+1 : i+2]})
						i += 2
						continue
					}
				}
			}
			return nil, ErrSyntax
		}
		return nil, ErrSyntax
	}
	if open != 0 {
		return nil, ErrSyntax
	}
	return toks, nil
}

// lexNumber reads an IntValue or FloatValue starting at i.
func lexNumber(src string, i int) (int, tokKind, error) {
	n := len(src)
	j := i
	if src[j] == '-' {
		j++
	}
	if j >= n || !isDigit(src[j]) {
		return 0, 0, ErrSyntax
	}
	if src[j] == '0' {
		j++
		if j < n && isDigit(src[j]) {
			return 0, 0, ErrSyntax // leading zero
		}
	} else {
		for j < n && isDigit(src[j]) {
			j++
		}
	}
	kind := tInt
	if j < n && src[j] == '.' {
		j++
		if j >= n || !isDigit(src[j]) {
			return 0, 0, ErrSyntax
		}
		for j < n && isDigit(src[j]) {
			j++
		}
		kind = tFloat
	}
	if j < n && (src[j] == 'e' || src[j] == 'E') {
		j++
		if j < n && (src[j] == '+' || src[j] == '-') {
			j++
		}
		if j >= n || !isDigit(src[j]) {
			return 0, 0, ErrSyntax
		}
		for j < n && isDigit(src[j]) {
			j++
		}
		kind = tFloat
	}
	// Lookahead restriction: a number is not followed by '.' or a NameStart
	// (digits were consumed above).
	if j < n && (src[j] == '.' || isNameStart(src[j])) {
		return 0, 0, ErrSyntax
	}
	return j, kind, nil
}

// lexString reads a string or block string starting at the quote at i and
// returns the index after its end.
func lexString(src string, i int) (int, error) {
	n := len(src)
	if i+2 < n && src[i+1] == '"' && src[i+2] == '"' {
		// Block string: ends at the first """ not escaped as \""".
		j := i + 3
		for j < n {
			switch {
			case src[j] == '\\' && j+3 < n && src[j+1] == '"' && src[j+2] == '"' && src[j+3] == '"':
				j += 4
			case src[j] == '"' && j+2 < n && src[j+1] == '"' && src[j+2] == '"':
				return j + 3, nil
			case src[j] < 0x20 && src[j] != '\t' && src[j] != '\n' && src[j] != '\r':
				return 0, ErrSyntax
			default:
				j++
			}
		}
		return 0, ErrSyntax
	}
	j := i + 1
	for j < n {
		c := src[j]
		switch {
		case c == '"':
			return j + 1, nil
		case c == '\\':
			if j+1 >= n {
				return 0, ErrSyntax
			}
			switch src[j+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				j += 2
			case 'u':
				if j+5 >= n || !isHexDigit(src[j+2]) || !isHexDigit(src[j+3]) || !isHexDigit(src[j+4]) || !isHexDigit(src[j+5]) {
					return 0, ErrSyntax
				}
				j += 6
			default:
				return 0, ErrSyntax
			}
		case c < 0x20 && c != '\t':
			return 0, ErrSyntax // line terminators and control characters
		default:
			j++
		}
	}
	return 0, ErrSyntax
}
