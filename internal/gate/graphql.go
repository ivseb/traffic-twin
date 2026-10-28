package gate

import (
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
)

// graphqlKeys are the contract extensions that describe GraphQL operations
// and captured schemas (x-tt-graphql, x-tt-graphql-schemas).
var graphqlKeys = map[string]bool{"x-tt-graphql": true, "x-tt-graphql-schemas": true}

// graphqlStructural accepts the strings of the GraphQL extensions: a safe
// GraphQL name (operation, field, type, enum value, directive location),
// the hash name of an anonymous operation, a document shape, a type
// reference ("[ID!]!"), an endpoint ("/graphql", "POST /graphql"), an HTTP
// method, where the document is (json, query, body), or a date. Every one
// of them comes from gql: tokens or from the structure of the events.
func graphqlStructural(s string) bool {
	switch {
	case graphql.IsName(s) && graphql.NameSafe(s):
		return true
	case strings.HasPrefix(s, "~") && len(s) == 11 && isLowerHex(s[1:]):
		return true
	case strings.HasPrefix(s, "/") && event.ValidOp("GET "+s):
		return !strings.Contains(s, "#")
	case event.ValidOp(s) && !strings.Contains(s, "#"):
		return true
	case len(s) == 10 && s[4] == '-' && s[7] == '-':
		return true // captured_at date
	case typeRef(s):
		return true
	}
	_, err := graphql.ParseShape(s)
	return err == nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// typeRef accepts a GraphQL type reference: a name inside brackets, with !.
func typeRef(s string) bool {
	inner := strings.Trim(s, "[]!")
	if !graphql.IsName(inner) || !graphql.NameSafe(inner) {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[', ']', '!':
		default:
			if !(s[i] == '_' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= '0' && s[i] <= '9') {
				return false
			}
		}
	}
	return true
}

// xmlKeys is the contract extension of XML and SOAP bodies (x-tt-xml,
// sanitizer.md 22.2, spec v1.19): the fmt and the namespace patterns per
// element path.
var xmlKeys = map[string]bool{"x-tt-xml": true}

// xmlStructural accepts the strings of x-tt-xml: a fmt of an XML body or a
// namespace pattern as the sanitizer produces it (ns:, its value-like runs
// already replaced by {*} at the source and checked again by the intake).
func xmlStructural(s string) bool {
	return event.IsXMLFmt(s) || event.ValidNSToken(s)
}
