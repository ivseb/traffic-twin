package graphql

import "strings"

// Operation types.
const (
	Query        = "query"
	Mutation     = "mutation"
	Subscription = "subscription"
)

// Document is a parsed executable document (a real one or a shape).
type Document struct {
	Operations []*Operation
	Fragments  map[string]*Fragment
}

// Operation is one operation definition.
type Operation struct {
	Type       string // query | mutation | subscription
	Name       string // "" when anonymous; "*" when the name was collapsed
	Variables  []VarDef
	Directives []Directive
	Selection  []*Selection
}

// VarDef is one variable definition.
type VarDef struct {
	Name    string
	Type    string // as written without spaces: "ID!", "[String!]"
	Default *Value
}

// Fragment is one fragment definition.
type Fragment struct {
	Name       string
	On         string
	Directives []Directive
	Selection  []*Selection
}

// Selection kinds.
const (
	SelField = iota
	SelSpread
	SelInline
)

// Selection is a field, a fragment spread or an inline fragment.
type Selection struct {
	Kind       int
	Alias      string // fields only, "" when none
	Name       string // field name or spread fragment name
	On         string // inline fragment type condition ("" when none)
	Args       []Arg
	Directives []Directive
	Selection  []*Selection
}

// ResponseKey is the key of a field in the response: the alias, or the name.
func (s *Selection) ResponseKey() string {
	if s.Alias != "" {
		return s.Alias
	}
	return s.Name
}

// Arg is one argument.
type Arg struct {
	Name  string
	Value Value
}

// Directive is one directive.
type Directive struct {
	Name string
	Args []Arg
}

// Value kinds.
const (
	ValVar = iota
	ValInt
	ValFloat
	ValString
	ValBool
	ValNull
	ValEnum
	ValList
	ValObject
)

// Value is an argument or default value. In a shape the scalar kinds carry
// no text; in a real document Raw is the source text of a scalar (strings
// keep their quotes and escapes) and Name the variable name.
type Value struct {
	Kind   int
	Raw    string
	Name   string // ValVar
	List   []Value
	Fields []ObjField
}

// ObjField is one field of an object value.
type ObjField struct {
	Name  string
	Value Value
}

type parser struct {
	src   string
	toks  []token
	pos   int
	shape bool
	doc   *Document
	// raw scalar text, real documents only (positions of literal tokens)
	raws []string
}

// Parse parses a real executable document.
func Parse(src string) (*Document, error) {
	toks, raws, err := lexRaw(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, toks: toks, raws: raws}
	if err := p.document(); err != nil {
		return nil, err
	}
	return p.doc, nil
}

// ParseShape parses a shape (the text after "gql:" in an event).
func ParseShape(shape string) (*Document, error) {
	toks, err := lex(shape, true)
	if err != nil {
		return nil, err
	}
	p := &parser{src: shape, toks: toks, shape: true}
	if err := p.document(); err != nil {
		return nil, err
	}
	return p.doc, nil
}

// ValidShape reports whether shape is a shape a conforming source can emit
// (sanitizer.md 5.7.1): it parses, it carries no literal (no string, no
// number, no name in a value position: values are only placeholders), and
// every name passes the name rule or is "*". The intake checks every gql:
// document with it.
func ValidShape(shape string) bool {
	toks, err := lex(shape, true)
	if err != nil {
		return false
	}
	p := &parser{src: shape, toks: toks, shape: true}
	if p.document() != nil {
		return false
	}
	for i := range toks {
		t := &toks[i]
		switch t.kind {
		case tInt, tFloat, tString:
			return false
		case tName:
			if t.value || (t.s != "*" && !NameSafe(t.s)) {
				return false
			}
		}
	}
	return true
}

// lexRaw lexes a real document and also returns the source text of each
// token (only used for scalar values).
func lexRaw(src string) ([]token, []string, error) {
	toks, err := lex(src, false)
	if err != nil {
		return nil, nil, err
	}
	// Re-scan to recover the text of literal tokens. The scan mirrors lex
	// exactly; it runs only for the mock (real requests), never in a source.
	raws := make([]string, len(toks))
	i, k := 0, 0
	n := len(src)
	for i < n && k < len(toks) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == 0xEF && i+2 < n && src[i+1] == 0xBB && src[i+2] == 0xBF:
			i += 3
		case c == '#':
			for i < n && src[i] != '\n' && src[i] != '\r' {
				i++
			}
		case c == '.':
			i += 3
			k++
		case isNameStart(c):
			j := i + 1
			for j < n && isNameCont(src[j]) {
				j++
			}
			raws[k] = src[i:j]
			i = j
			k++
		case c == '-' || isDigit(c):
			j, _, _ := lexNumber(src, i)
			raws[k] = src[i:j]
			i = j
			k++
		case c == '"':
			j, _ := lexString(src, i)
			raws[k] = src[i:j]
			i = j
			k++
		default:
			i++
			k++
		}
	}
	return toks, raws, nil
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) isPunct(s string) bool {
	t := p.peek()
	return t != nil && t.kind == tPunct && t.s == s
}

func (p *parser) isName() bool {
	t := p.peek()
	return t != nil && t.kind == tName
}

func (p *parser) expect(s string) error {
	if !p.isPunct(s) {
		return ErrSyntax
	}
	p.pos++
	return nil
}

func (p *parser) name() (string, error) {
	if !p.isName() {
		return "", ErrSyntax
	}
	s := p.toks[p.pos].s
	p.pos++
	return s, nil
}

func (p *parser) document() error {
	p.doc = &Document{Fragments: map[string]*Fragment{}}
	if len(p.toks) == 0 {
		return ErrSyntax
	}
	for p.pos < len(p.toks) {
		t := p.peek()
		switch {
		case t.kind == tPunct && t.s == "{":
			sel, err := p.selectionSet()
			if err != nil {
				return err
			}
			p.doc.Operations = append(p.doc.Operations, &Operation{Type: Query, Selection: sel})
		case t.kind == tName && (t.s == Query || t.s == Mutation || t.s == Subscription):
			op, err := p.operation()
			if err != nil {
				return err
			}
			p.doc.Operations = append(p.doc.Operations, op)
		case t.kind == tName && t.s == "fragment":
			f, err := p.fragment()
			if err != nil {
				return err
			}
			if _, dup := p.doc.Fragments[f.Name]; !dup {
				p.doc.Fragments[f.Name] = f
			}
		default:
			return ErrSyntax
		}
	}
	return nil
}

func (p *parser) operation() (*Operation, error) {
	op := &Operation{Type: p.toks[p.pos].s}
	p.pos++
	if p.isName() {
		op.Name = p.toks[p.pos].s
		p.pos++
	}
	if p.isPunct("(") {
		p.pos++
		for {
			if p.isPunct(")") {
				if len(op.Variables) == 0 {
					return nil, ErrSyntax
				}
				p.pos++
				break
			}
			v, err := p.varDef()
			if err != nil {
				return nil, err
			}
			op.Variables = append(op.Variables, v)
		}
	}
	var err error
	if op.Directives, err = p.directives(); err != nil {
		return nil, err
	}
	if op.Selection, err = p.selectionSet(); err != nil {
		return nil, err
	}
	return op, nil
}

func (p *parser) varDef() (VarDef, error) {
	var v VarDef
	if err := p.expect("$"); err != nil {
		return v, err
	}
	var err error
	if v.Name, err = p.name(); err != nil {
		return v, err
	}
	if err := p.expect(":"); err != nil {
		return v, err
	}
	var sb strings.Builder
	if err := p.typeRef(&sb); err != nil {
		return v, err
	}
	v.Type = sb.String()
	if p.isPunct("=") {
		p.pos++
		val, err := p.value()
		if err != nil {
			return v, err
		}
		v.Default = &val
	}
	// Directives on variable definitions are accepted and ignored.
	if _, err := p.directives(); err != nil {
		return v, err
	}
	return v, nil
}

func (p *parser) typeRef(sb *strings.Builder) error {
	if p.isPunct("[") {
		p.pos++
		sb.WriteByte('[')
		if err := p.typeRef(sb); err != nil {
			return err
		}
		if err := p.expect("]"); err != nil {
			return err
		}
		sb.WriteByte(']')
	} else {
		n, err := p.name()
		if err != nil {
			return err
		}
		sb.WriteString(n)
	}
	if p.isPunct("!") {
		p.pos++
		sb.WriteByte('!')
	}
	return nil
}

func (p *parser) fragment() (*Fragment, error) {
	p.pos++ // fragment
	f := &Fragment{}
	var err error
	if f.Name, err = p.name(); err != nil {
		return nil, err
	}
	if f.Name == "on" {
		return nil, ErrSyntax
	}
	if !p.isName() || p.peek().s != "on" {
		return nil, ErrSyntax
	}
	p.pos++
	if f.On, err = p.name(); err != nil {
		return nil, err
	}
	if f.Directives, err = p.directives(); err != nil {
		return nil, err
	}
	if f.Selection, err = p.selectionSet(); err != nil {
		return nil, err
	}
	return f, nil
}

func (p *parser) selectionSet() ([]*Selection, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	var out []*Selection
	for {
		if p.isPunct("}") {
			if len(out) == 0 {
				return nil, ErrSyntax
			}
			p.pos++
			return out, nil
		}
		s, err := p.selection()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
}

func (p *parser) selection() (*Selection, error) {
	var err error
	if p.isPunct("...") {
		p.pos++
		if p.isName() && p.peek().s != "on" {
			s := &Selection{Kind: SelSpread, Name: p.toks[p.pos].s}
			p.pos++
			if s.Directives, err = p.directives(); err != nil {
				return nil, err
			}
			return s, nil
		}
		s := &Selection{Kind: SelInline}
		if p.isName() { // "on"
			p.pos++
			if s.On, err = p.name(); err != nil {
				return nil, err
			}
		}
		if s.Directives, err = p.directives(); err != nil {
			return nil, err
		}
		if s.Selection, err = p.selectionSet(); err != nil {
			return nil, err
		}
		return s, nil
	}
	s := &Selection{Kind: SelField}
	if s.Name, err = p.name(); err != nil {
		return nil, err
	}
	if p.isPunct(":") {
		p.pos++
		s.Alias = s.Name
		if s.Name, err = p.name(); err != nil {
			return nil, err
		}
	}
	if p.isPunct("(") {
		if s.Args, err = p.arguments(); err != nil {
			return nil, err
		}
	}
	if s.Directives, err = p.directives(); err != nil {
		return nil, err
	}
	if p.isPunct("{") {
		if s.Selection, err = p.selectionSet(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (p *parser) arguments() ([]Arg, error) {
	if err := p.expect("("); err != nil {
		return nil, err
	}
	var out []Arg
	for {
		if p.isPunct(")") {
			if len(out) == 0 {
				return nil, ErrSyntax
			}
			p.pos++
			return out, nil
		}
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		if err := p.expect(":"); err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, Arg{Name: n, Value: v})
	}
}

func (p *parser) directives() ([]Directive, error) {
	var out []Directive
	for p.isPunct("@") {
		p.pos++
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		d := Directive{Name: n}
		if p.isPunct("(") {
			if d.Args, err = p.arguments(); err != nil {
				return nil, err
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (p *parser) value() (Value, error) {
	t := p.peek()
	if t == nil {
		return Value{}, ErrSyntax
	}
	raw := ""
	if p.raws != nil {
		raw = p.raws[p.pos]
	}
	switch t.kind {
	case tPunct:
		switch t.s {
		case "$":
			p.pos++
			n, err := p.name()
			if err != nil {
				return Value{}, err
			}
			return Value{Kind: ValVar, Name: n}, nil
		case "[":
			p.pos++
			v := Value{Kind: ValList}
			for !p.isPunct("]") {
				e, err := p.value()
				if err != nil {
					return Value{}, err
				}
				v.List = append(v.List, e)
			}
			p.pos++
			return v, nil
		case "{":
			p.pos++
			v := Value{Kind: ValObject}
			for !p.isPunct("}") {
				n, err := p.name()
				if err != nil {
					return Value{}, err
				}
				if err := p.expect(":"); err != nil {
					return Value{}, err
				}
				e, err := p.value()
				if err != nil {
					return Value{}, err
				}
				v.Fields = append(v.Fields, ObjField{Name: n, Value: e})
			}
			p.pos++
			return v, nil
		}
		return Value{}, ErrSyntax
	case tInt:
		p.pos++
		return Value{Kind: ValInt, Raw: raw}, nil
	case tFloat:
		p.pos++
		return Value{Kind: ValFloat, Raw: raw}, nil
	case tString:
		p.pos++
		return Value{Kind: ValString, Raw: raw}, nil
	case tHole:
		p.pos++
		switch t.s {
		case "s":
			return Value{Kind: ValString}, nil
		case "i":
			return Value{Kind: ValInt}, nil
		case "f":
			return Value{Kind: ValFloat}, nil
		case "b":
			return Value{Kind: ValBool}, nil
		case "n":
			return Value{Kind: ValNull}, nil
		}
		return Value{Kind: ValEnum}, nil
	case tName:
		t.value = true
		p.pos++
		switch t.s {
		case "true", "false":
			return Value{Kind: ValBool, Raw: t.s}, nil
		case "null":
			return Value{Kind: ValNull, Raw: t.s}, nil
		}
		return Value{Kind: ValEnum, Raw: t.s}, nil
	}
	return Value{}, ErrSyntax
}
