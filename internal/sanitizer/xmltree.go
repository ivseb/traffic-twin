package sanitizer

import (
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

// XML bodies for the mock (docs/spec/mock.md 10, spec v1.21). The mock
// reads the XML and SOAP requests of the tests with the same closed parser
// as the sources (section 22.2, hardening.md 3): no DTD, no entity other
// than the five predefined ones and character references, at most 256
// open elements, an error anywhere rejects the whole body. The tree has the
// shape the contracts and the rules know (attributes @name, mixed text
// #text, repeated elements as arrays), with the values in clear: the mock
// is a test tool and the request is the test's own.

// ErrInvalidXML is returned for a body outside the subset of section 22.2.
var ErrInvalidXML = errors.New("invalid xml body (closed subset of sanitizer.md 22.2: no DTD, no entities)")

// XMLDoc is a parsed XML body.
type XMLDoc struct {
	// Tree is { <local name of the root>: <value of the root> } (point 7):
	// a string for an element without attributes and children, otherwise an
	// object with "@name" attributes, children grouped by local name (an
	// array for a name that appears more than once) and "#text".
	Tree map[string]any
	// Format is "soap11", "soap12" or "xml" (point 10).
	Format string
	// Root is the local name of the root element.
	Root string
	// BodyElems are the local names of the element children of the SOAP
	// Body, in order of first appearance (nil when not a SOAP envelope).
	BodyElems []string
}

// ParseXML parses an XML body with the rules of section 22.2 points 1–7.
// Every element is kept: the size of the tree is bounded by the size of
// the body, which the caller limits.
func ParseXML(data []byte) (*XMLDoc, error) {
	x := &xmlParser{maxDepth: xmlMaxNesting + 1, maxKeys: math.MaxInt, storeCap: math.MaxInt}
	root, err := x.parse(data)
	if err != nil || root == nil {
		return nil, ErrInvalidXML
	}
	d := &XMLDoc{Format: "xml", Root: root.local}
	if root.local == "Envelope" {
		switch x.rootNS {
		case nsSOAP11:
			d.Format = "soap11"
		case nsSOAP12:
			d.Format = "soap12"
		}
	}
	if d.Format != "xml" {
		for _, g := range root.groups {
			if g.local != "Body" || len(g.vals) == 0 {
				continue
			}
			for _, bg := range g.vals[0].groups {
				d.BodyElems = append(d.BodyElems, bg.local)
			}
			break
		}
	}
	d.Tree = map[string]any{root.local: xmlTreeValue(root)}
	return d, nil
}

// xmlTreeValue is the value of an element (point 7), values in clear.
func xmlTreeValue(e *xElem) any {
	if len(e.attrs) == 0 && !e.children {
		return string(e.text)
	}
	m := make(map[string]any, len(e.attrs)+len(e.groups)+1)
	for _, a := range e.attrs {
		m["@"+a.local] = string(a.val)
	}
	for _, g := range e.groups {
		if len(g.vals) == 1 && g.count == 1 {
			m[g.local] = xmlTreeValue(g.vals[0])
			continue
		}
		arr := make([]any, len(g.vals))
		for i, v := range g.vals {
			arr[i] = xmlTreeValue(v)
		}
		m[g.local] = arr
	}
	if xmlText(e.text) {
		m["#text"] = string(e.text)
	}
	return m
}

// SOAPActionName is the name of a SOAP operation from the SOAPAction
// header (SOAP 1.1; present tells whether the request had the header) or
// the action parameter of the content type (SOAP 1.2), as section 22.2
// point 11 computes soap_action: quotes and spaces trimmed, the part after
// the last "/", "#" or ":", kept only when it follows the rule of the
// names. ok is false when there is no usable name.
func SOAPActionName(header string, present bool, contentType string) (string, bool) {
	raw := header
	if !present {
		a, ok := mediaParams([]byte(contentType), "action")
		if !ok {
			return "", false
		}
		raw = a
	}
	if !utf8.ValidString(raw) {
		return "", false
	}
	s := strings.Trim(raw, " \t")
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" {
		return "", false
	}
	name := s[strings.LastIndexAny(s, "/#:")+1:]
	if !IsLiteralKey([]byte(name)) {
		return "", false
	}
	return name, true
}
