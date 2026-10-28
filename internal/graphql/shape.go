package graphql

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ShapeResult is the outcome of [Shape].
type ShapeResult struct {
	// Shape is the canonical shape (without the "gql:" prefix).
	Shape string
	// Introspection is true when every operation of the document selects
	// only __schema, __type and __typename at its root, without aliases
	// (the introspection gate of sanitizer.md 5.7).
	Introspection bool
}

// Shape returns the shape of an executable document (sanitizer.md 5.7):
// the same tokens with every literal value replaced by a placeholder and
// every name that is not a safe literal name replaced by "*". ok is false
// when src is not an executable document within the limits; the caller then
// emits the drop form of the string.
func Shape(src string) (ShapeResult, bool) {
	toks, err := lex(src, false)
	if err != nil {
		return ShapeResult{}, false
	}
	p := &parser{src: src, toks: toks}
	if err := p.document(); err != nil {
		return ShapeResult{}, false
	}
	var sb strings.Builder
	prevWord := false
	for i := range toks {
		t := &toks[i]
		var out string
		switch t.kind {
		case tPunct:
			out = t.s
		case tName:
			if t.value {
				switch t.s {
				case "true", "false":
					out = "?b"
				case "null":
					out = "?n"
				default:
					out = "?e"
				}
			} else {
				out = SafeName(t.s)
			}
		case tInt:
			out = "?i"
		case tFloat:
			out = "?f"
		case tString:
			out = "?s"
		}
		word := isWordByte(out[0])
		if word && prevWord {
			sb.WriteByte(' ')
		}
		sb.WriteString(out)
		prevWord = isWordByte(out[len(out)-1])
		if sb.Len() > MaxShapeBytes {
			return ShapeResult{}, false
		}
	}
	return ShapeResult{Shape: sb.String(), Introspection: introspectionOnly(p.doc)}, true
}

func isWordByte(c byte) bool { return isNameCont(c) || c == '?' || c == '*' }

// SafeName returns name when it may leave a source as written, "*"
// otherwise: the key rule of sanitizer.md 9.3 restricted to GraphQL names
// (at most 64 bytes, not 16 or more hexadecimal digits only, no six
// consecutive digits).
func SafeName(name string) string {
	if !NameSafe(name) {
		return "*"
	}
	return name
}

// NameSafe reports whether a GraphQL name passes the key rule (see SafeName).
func NameSafe(name string) bool {
	if len(name) == 0 || len(name) > MaxNameBytes || !isNameStart(name[0]) {
		return false
	}
	allHex := len(name) >= 16
	run := 0
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isNameCont(c) {
			return false
		}
		if !isHexDigit(c) {
			allHex = false
		}
		if isDigit(c) {
			run++
			if run >= 6 {
				return false
			}
		} else {
			run = 0
		}
	}
	return !allHex
}

// IsName reports whether s is a GraphQL name (any length).
func IsName(s string) bool {
	if len(s) == 0 || !isNameStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isNameCont(s[i]) {
			return false
		}
	}
	return true
}

// introspectionOnly implements the gate condition of sanitizer.md 5.7.
func introspectionOnly(d *Document) bool {
	if d == nil || len(d.Operations) == 0 {
		return false
	}
	for _, op := range d.Operations {
		for _, s := range op.Selection {
			if s.Kind != SelField || s.Alias != "" {
				return false
			}
			switch s.Name {
			case "__schema", "__type", "__typename":
			default:
				return false
			}
		}
	}
	return true
}

// IsIntrospection reports whether every operation of d selects only
// introspection fields at its root (see ShapeResult.Introspection).
func IsIntrospection(d *Document) bool { return introspectionOnly(d) }

// ShapeHash is the name of an anonymous operation in a logical op key: "~"
// and the first 10 hexadecimal digits of SHA-256 of the shape.
func ShapeHash(shape string) string {
	h := sha256.Sum256([]byte(shape))
	return "~" + hex.EncodeToString(h[:])[:10]
}

// RunnableDocument turns a shape back into a document a client can send
// (a Postman request, an example): every placeholder becomes a neutral
// literal ("", 0, 0.0, false, null) and a collapsed name stays "*" (the
// person fills it in). It is for people, never for a source.
func RunnableDocument(shape string) string {
	var sb strings.Builder
	for i := 0; i < len(shape); i++ {
		if shape[i] == '?' && i+1 < len(shape) {
			switch shape[i+1] {
			case 's':
				sb.WriteString(`""`)
			case 'i':
				sb.WriteString("0")
			case 'f':
				sb.WriteString("0.0")
			case 'b':
				sb.WriteString("false")
			default:
				sb.WriteString("null")
			}
			i++
			continue
		}
		sb.WriteByte(shape[i])
	}
	return sb.String()
}
