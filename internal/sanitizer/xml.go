package sanitizer

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// XML and SOAP bodies (section 22.2, spec v1.19).
//
// The parser is hand written and strict: it accepts exactly the subset of
// XML 1.0 + Namespaces of section 22.2 (no DTD, no entity other than the
// five predefined ones and character references) and never resolves
// anything external. It is iterative (an explicit stack of at most 256
// open elements) and stores only what the sanitizer can emit: the content
// of elements deeper than max_depth, of groups past max_keys and of
// repeated elements past the array limit is validated and counted, not
// kept. The tree is then sanitized with the rules of the JSON bodies.

var errInvalidXML = errors.New("sanitizer: invalid xml body")

var tokTruncXML = ttjson.Str("trunc:invalid-xml")

// Namespaces of section 22.2.
const (
	nsXMLPrefix = "http://www.w3.org/XML/1998/namespace"
	nsSOAP11    = "http://schemas.xmlsoap.org/soap/envelope/"
	nsSOAP12    = "http://www.w3.org/2003/05/soap-envelope"
)

// xmlMaxNesting is the maximum number of open elements (section 22.2
// point 4): a non-empty start tag with 256 elements open is invalid.
const xmlMaxNesting = 256

// xmlnsMaxEntries is the limit of the xmlns map (section 22.2 point 9).
const xmlnsMaxEntries = 64

// nsMaxBytes is the longest namespace URI given a pattern.
const nsMaxBytes = 512

// xAttr is one attribute of a stored element (local name, decoded value).
type xAttr struct {
	local string
	val   []byte
}

// xGroup is the group of the children of an element with one local name,
// in order of first appearance. count is the number of children; vals are
// the stored ones.
type xGroup struct {
	local string
	count int
	vals  []*xElem
}

// xElem is a stored element.
type xElem struct {
	local    string
	attrs    []xAttr   // deduplicated by local name: the last wins, at its position
	groups   []*xGroup // nil when the children are not stored (depth)
	text     []byte    // direct text and CDATA, references resolved
	children bool
}

// xSkel locates an element for the xmlns map: its parent, its path step
// and its group (repeated groups add [*]). Created only for elements with
// an xmlns entry and their ancestors.
type xSkel struct {
	parent *xSkel
	seg    string  // ".local" or ".*"
	grp    *xGroup // nil for the root
	id     int32   // path id + 1 (0 = not computed)
}

type xEvent struct {
	sk  *xSkel
	tok string
}

// xFrame is an open element.
type xFrame struct {
	qname   []byte
	local   string
	el      *xElem // nil when the content is not stored
	ns      string
	kids    bool // children stored
	tracks  bool // children grouped (depth < max_depth)
	hasKids bool
	groups  []*xGroup
	gmap    map[string]int
	grp     *xGroup
	skel    *xSkel
	nsMark  int
}

func (f *xFrame) group(local []byte) (*xGroup, int) {
	if f.gmap != nil {
		if i, ok := f.gmap[string(local)]; ok {
			return f.groups[i], i
		}
	} else {
		for i, g := range f.groups {
			if g.local == string(local) {
				return g, i
			}
		}
	}
	g := &xGroup{local: string(local)}
	f.groups = append(f.groups, g)
	i := len(f.groups) - 1
	switch {
	case f.gmap != nil:
		f.gmap[g.local] = i
	case len(f.groups) > 8:
		f.gmap = make(map[string]int, 32)
		for j, x := range f.groups {
			f.gmap[x.local] = j
		}
	}
	return g, i
}

type rawAttr struct {
	name, raw []byte
}

type xmlParser struct {
	s        []byte
	maxDepth int
	maxKeys  int
	storeCap int
	stack    []xFrame
	root     *xElem
	rootNS   string
	nsb      map[string][]string
	nsLog    []string
	events   []xEvent
	attrs    []rawAttr
	attrSet  map[string]struct{}
	patterns map[string]string
}

// xmlPrepare applies point 1: BOM removed, UTF-8 without C0 controls
// other than tab, LF and CR, without U+FFFE and U+FFFF; CR LF and lone CR
// become LF.
func xmlPrepare(d []byte) ([]byte, bool) {
	d = bytes.TrimPrefix(d, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(d) {
		return nil, false
	}
	cr := false
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case c < 0x20:
			if c == '\r' {
				cr = true
			} else if c != '\t' && c != '\n' {
				return nil, false
			}
		case c == 0xef:
			// U+FFFE and U+FFFF are EF BF BE and EF BF BF (EF is always a
			// lead byte in valid UTF-8).
			if i+2 < len(d) && d[i+1] == 0xbf && (d[i+2] == 0xbe || d[i+2] == 0xbf) {
				return nil, false
			}
		}
	}
	if !cr {
		return d, true
	}
	out := make([]byte, 0, len(d))
	for i := 0; i < len(d); i++ {
		if d[i] == '\r' {
			out = append(out, '\n')
			if i+1 < len(d) && d[i+1] == '\n' {
				i++
			}
			continue
		}
		out = append(out, d[i])
	}
	return out, true
}

func xmlNameStart(c byte) bool { return isAlpha(c) || c == '_' || c >= 0x80 }
func xmlNameChar(c byte) bool {
	return xmlNameStart(c) || isDigit(c) || c == '.' || c == '-' || c == ':'
}
func xmlWS(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

func (x *xmlParser) skipWS(p int) int {
	for p < len(x.s) && xmlWS(x.s[p]) {
		p++
	}
	return p
}

func (x *xmlParser) readName(p int) (int, error) {
	s := x.s
	if p >= len(s) || !xmlNameStart(s[p]) {
		return 0, errInvalidXML
	}
	p++
	for p < len(s) && xmlNameChar(s[p]) {
		p++
	}
	return p, nil
}

// misc skips a comment or a processing instruction at p (ok = false when
// none starts there).
func (x *xmlParser) misc(p int) (end int, ok bool, err error) {
	s := x.s[p:]
	switch {
	case bytes.HasPrefix(s, []byte("<!--")):
		e := bytes.Index(s[4:], []byte("-->"))
		if e < 0 {
			return 0, false, errInvalidXML
		}
		return p + 4 + e + 3, true, nil
	case bytes.HasPrefix(s, []byte("<?")):
		e := bytes.Index(s[2:], []byte("?>"))
		if e < 0 {
			return 0, false, errInvalidXML
		}
		return p + 2 + e + 2, true, nil
	}
	return 0, false, nil
}

// splitQName splits prefix:local; a name with ':' must have exactly one,
// neither first nor last.
func splitQName(q []byte) (prefix, local []byte, ok bool) {
	i := bytes.IndexByte(q, ':')
	if i < 0 {
		return nil, q, true
	}
	prefix, local = q[:i], q[i+1:]
	if len(prefix) == 0 || len(local) == 0 || bytes.IndexByte(local, ':') >= 0 {
		return nil, nil, false
	}
	return prefix, local, true
}

func xmlChar(cp int) bool {
	return cp == 0x9 || cp == 0xa || cp == 0xd || (cp >= 0x20 && cp <= 0xd7ff) ||
		(cp >= 0xe000 && cp <= 0xfffd) || (cp >= 0x10000 && cp <= 0x10ffff)
}

// xmlRefs resolves the references of raw (point 5) and appends the text
// to dst when store is set (otherwise it only validates). In attribute
// values (attr) a literal tab or LF becomes a space.
func xmlRefs(dst, raw []byte, attr, store bool) ([]byte, bool) {
	i := 0
	for {
		j := bytes.IndexByte(raw[i:], '&')
		seg := raw[i:]
		if j >= 0 {
			seg = raw[i : i+j]
		}
		if store {
			if attr {
				for _, c := range seg {
					if c == '\t' || c == '\n' {
						c = ' '
					}
					dst = append(dst, c)
				}
			} else {
				dst = append(dst, seg...)
			}
		}
		if j < 0 {
			return dst, true
		}
		i += j
		semi := bytes.IndexByte(raw[i+1:], ';')
		if semi < 0 {
			return nil, false
		}
		ent := raw[i+1 : i+1+semi]
		i += semi + 2
		var r byte
		switch string(ent) {
		case "lt":
			r = '<'
		case "gt":
			r = '>'
		case "amp":
			r = '&'
		case "apos":
			r = '\''
		case "quot":
			r = '"'
		}
		if r != 0 {
			if store {
				dst = append(dst, r)
			}
			continue
		}
		cp, ok := charRef(ent)
		if !ok {
			return nil, false
		}
		if store {
			dst = utf8.AppendRune(dst, rune(cp))
		}
	}
}

// charRef parses #N or #xH (any number of digits) to an XML character.
func charRef(ent []byte) (int, bool) {
	if len(ent) < 2 || ent[0] != '#' {
		return 0, false
	}
	cp := 0
	if ent[1] == 'x' && len(ent) > 2 && allOf(ent[2:], isHex) {
		for _, d := range ent[2:] {
			cp = cp*16 + int(unhex(d))
			if cp > 0x10ffff {
				return 0, false
			}
		}
	} else if allOf(ent[1:], isDigit) {
		for _, d := range ent[1:] {
			cp = cp*10 + int(d-'0')
			if cp > 0x10ffff {
				return 0, false
			}
		}
	} else {
		return 0, false
	}
	return cp, xmlChar(cp)
}

func (x *xmlParser) pushNS(prefix, uri string) {
	if x.nsb == nil {
		x.nsb = map[string][]string{}
	}
	x.nsb[prefix] = append(x.nsb[prefix], uri)
	x.nsLog = append(x.nsLog, prefix)
}

func (x *xmlParser) popNS(mark int) {
	for len(x.nsLog) > mark {
		p := x.nsLog[len(x.nsLog)-1]
		st := x.nsb[p]
		x.nsb[p] = st[:len(st)-1]
		x.nsLog = x.nsLog[:len(x.nsLog)-1]
	}
}

func (x *xmlParser) lookupNS(prefix []byte) (string, bool) {
	st := x.nsb[string(prefix)]
	if len(st) == 0 {
		return "", false
	}
	return st[len(st)-1], true
}

// attrDup reports a qualified attribute name already seen in this tag.
func (x *xmlParser) attrDup(name []byte) bool {
	if len(x.attrs) < 16 {
		for i := range x.attrs {
			if bytes.Equal(x.attrs[i].name, name) {
				return true
			}
		}
		return false
	}
	if len(x.attrSet) == 0 {
		if x.attrSet == nil {
			x.attrSet = map[string]struct{}{}
		}
		for i := range x.attrs {
			x.attrSet[string(x.attrs[i].name)] = struct{}{}
		}
	}
	if _, ok := x.attrSet[string(name)]; ok {
		return true
	}
	x.attrSet[string(name)] = struct{}{}
	return false
}

// startTag parses the start tag at p and opens the element (points 3, 4
// and 6); it returns the position after the tag.
func (x *xmlParser) startTag(p int) (int, error) {
	s := x.s
	qend, err := x.readName(p + 1)
	if err != nil {
		return 0, err
	}
	qname := s[p+1 : qend]
	p = qend
	x.attrs = x.attrs[:0]
	if len(x.attrSet) > 0 {
		clear(x.attrSet)
	}
	empty := false
	for {
		q := x.skipWS(p)
		if bytes.HasPrefix(s[q:], []byte("/>")) {
			p, empty = q+2, true
			break
		}
		if q < len(s) && s[q] == '>' {
			p = q + 1
			break
		}
		if q == p {
			return 0, errInvalidXML // attribute without a space before it
		}
		aend, err := x.readName(q)
		if err != nil {
			return 0, err
		}
		aname := s[q:aend]
		q = x.skipWS(aend)
		if q >= len(s) || s[q] != '=' {
			return 0, errInvalidXML
		}
		q = x.skipWS(q + 1)
		if q >= len(s) || (s[q] != '"' && s[q] != '\'') {
			return 0, errInvalidXML
		}
		e := bytes.IndexByte(s[q+1:], s[q])
		if e < 0 {
			return 0, errInvalidXML
		}
		raw := s[q+1 : q+1+e]
		if bytes.IndexByte(raw, '<') >= 0 || x.attrDup(aname) {
			return 0, errInvalidXML
		}
		x.attrs = append(x.attrs, rawAttr{name: aname, raw: raw})
		p = q + 1 + e + 1
	}

	// Namespace declarations (point 6).
	nsMark := len(x.nsLog)
	nonDecl := 0
	for i := range x.attrs {
		a := &x.attrs[i]
		switch {
		case string(a.name) == "xmlns":
			v, ok := xmlRefs(nil, a.raw, true, true)
			if !ok {
				return 0, errInvalidXML
			}
			x.pushNS("", string(v))
		case bytes.HasPrefix(a.name, []byte("xmlns:")):
			pre := a.name[6:]
			if len(pre) == 0 || bytes.IndexByte(pre, ':') >= 0 {
				return 0, errInvalidXML
			}
			v, ok := xmlRefs(nil, a.raw, true, true)
			if !ok {
				return 0, errInvalidXML
			}
			x.pushNS(string(pre), string(v))
		default:
			nonDecl++
		}
	}
	prefix, localB, ok := splitQName(qname)
	if !ok {
		return 0, errInvalidXML
	}
	var ns string
	switch {
	case prefix == nil:
		ns, _ = x.lookupNS(nil)
	case string(prefix) == "xml":
		ns = nsXMLPrefix
	default:
		if ns, ok = x.lookupNS(prefix); !ok {
			return 0, errInvalidXML
		}
	}

	// Place in the parent: group, and whether the content is stored.
	depth := len(x.stack) + 1
	parentNS := ""
	keep := true
	var g *xGroup
	if len(x.stack) > 0 {
		pf := &x.stack[len(x.stack)-1]
		parentNS = pf.ns
		pf.hasKids = true
		keep = false
		if pf.tracks {
			var gi int
			g, gi = pf.group(localB)
			g.count++
			keep = pf.kids && len(pf.el.attrs)+gi < x.maxKeys && len(g.vals) < x.storeCap
		}
	}
	local := string(localB)
	if g != nil {
		local = g.local
	}

	// Attributes (prefix check, references; stored when kept).
	var el *xElem
	if keep {
		el = &xElem{local: local}
		if nonDecl > 0 {
			el.attrs = make([]xAttr, 0, nonDecl)
		}
	}
	for i := range x.attrs {
		a := &x.attrs[i]
		if string(a.name) == "xmlns" || bytes.HasPrefix(a.name, []byte("xmlns:")) {
			continue
		}
		ap, al, ok := splitQName(a.name)
		if !ok {
			return 0, errInvalidXML
		}
		if ap != nil && string(ap) != "xml" {
			if _, ok := x.lookupNS(ap); !ok {
				return 0, errInvalidXML
			}
		}
		if !keep {
			if _, ok := xmlRefs(nil, a.raw, true, false); !ok {
				return 0, errInvalidXML
			}
			continue
		}
		v, ok := xmlRefs(nil, a.raw, true, true)
		if !ok {
			return 0, errInvalidXML
		}
		el.attrs = append(el.attrs, xAttr{local: string(al), val: v})
	}
	if keep {
		el.attrs = dedupAttrs(el.attrs)
	}
	if keep && g != nil {
		g.vals = append(g.vals, el)
	}

	// xmlns entry (point 9): elements up to XML depth max_depth.
	var sk *xSkel
	if depth <= x.maxDepth && ns != parentNS {
		sk = x.newSkel(local, g)
		tok, ok := x.patterns[ns]
		if !ok {
			tok = nsPattern(ns)
			if x.patterns == nil {
				x.patterns = map[string]string{}
			}
			x.patterns[ns] = tok
		}
		x.events = append(x.events, xEvent{sk: sk, tok: tok})
	}

	if len(x.stack) == 0 {
		x.root, x.rootNS = el, ns
	}
	if empty {
		x.popNS(nsMark)
		return p, nil
	}
	if len(x.stack) >= xmlMaxNesting {
		return 0, errInvalidXML
	}
	x.stack = append(x.stack, xFrame{qname: qname, local: local, el: el, ns: ns, kids: keep && depth < x.maxDepth,
		tracks: depth < x.maxDepth, grp: g, skel: sk, nsMark: nsMark})
	return p, nil
}

// dedupAttrs keeps, for each local name, only the last attribute, at its
// own position (point 7, as section 9.3 point 1).
func dedupAttrs(as []xAttr) []xAttr {
	if len(as) < 2 {
		return as
	}
	last := make(map[string]int, len(as))
	for i := range as {
		last[as[i].local] = i
	}
	if len(last) == len(as) {
		return as
	}
	out := as[:0]
	for i := range as {
		if last[as[i].local] == i {
			out = append(out, as[i])
		}
	}
	return out
}

// newSkel creates the locator of a new element whose parent is the top of
// the stack (if any).
func (x *xmlParser) newSkel(local string, g *xGroup) *xSkel {
	var parent *xSkel
	if len(x.stack) > 0 {
		parent = x.ensureSkel(len(x.stack) - 1)
	}
	return &xSkel{parent: parent, seg: xmlPathSeg(local), grp: g}
}

func (x *xmlParser) ensureSkel(i int) *xSkel {
	f := &x.stack[i]
	if f.skel == nil {
		var parent *xSkel
		if i > 0 {
			parent = x.ensureSkel(i - 1)
		}
		f.skel = &xSkel{parent: parent, seg: xmlPathSeg(f.local), grp: f.grp}
	}
	return f.skel
}

func xmlPathSeg(local string) string {
	if IsLiteralKey([]byte(local)) {
		return "." + local
	}
	return ".*"
}

func (x *xmlParser) closeTop() {
	f := &x.stack[len(x.stack)-1]
	x.popNS(f.nsMark)
	if f.el != nil {
		f.el.children = f.hasKids
		if f.kids {
			f.el.groups = f.groups
		}
	}
	x.stack[len(x.stack)-1] = xFrame{}
	x.stack = x.stack[:len(x.stack)-1]
}

// parse implements points 1–6 and returns the root element.
func (x *xmlParser) parse(data []byte) (*xElem, error) {
	s, ok := xmlPrepare(data)
	if !ok {
		return nil, errInvalidXML
	}
	x.s = s
	n := len(s)
	pos := 0
	// Prolog: spaces, comments and processing instructions only.
	for {
		pos = x.skipWS(pos)
		if pos >= n {
			return nil, errInvalidXML
		}
		e, ok, err := x.misc(pos)
		if err != nil {
			return nil, err
		}
		if ok {
			pos = e
			continue
		}
		if s[pos] != '<' || bytes.HasPrefix(s[pos:], []byte("<!")) {
			return nil, errInvalidXML
		}
		break
	}
	var err error
	if pos, err = x.startTag(pos); err != nil {
		return nil, err
	}
	for len(x.stack) > 0 {
		if pos >= n {
			return nil, errInvalidXML
		}
		top := &x.stack[len(x.stack)-1]
		if s[pos] != '<' {
			e := bytes.IndexByte(s[pos:], '<')
			if e < 0 {
				return nil, errInvalidXML
			}
			var ok bool
			if top.el != nil {
				top.el.text, ok = xmlRefs(top.el.text, s[pos:pos+e], false, true)
			} else {
				_, ok = xmlRefs(nil, s[pos:pos+e], false, false)
			}
			if !ok {
				return nil, errInvalidXML
			}
			pos += e
			continue
		}
		if bytes.HasPrefix(s[pos:], []byte("<![CDATA[")) {
			e := bytes.Index(s[pos+9:], []byte("]]>"))
			if e < 0 {
				return nil, errInvalidXML
			}
			if top.el != nil {
				top.el.text = append(top.el.text, s[pos+9:pos+9+e]...)
			}
			pos += 9 + e + 3
			continue
		}
		e, ok, err := x.misc(pos)
		if err != nil {
			return nil, err
		}
		if ok {
			pos = e
			continue
		}
		if bytes.HasPrefix(s[pos:], []byte("<!")) {
			return nil, errInvalidXML
		}
		if bytes.HasPrefix(s[pos:], []byte("</")) {
			end, err := x.readName(pos + 2)
			if err != nil {
				return nil, err
			}
			q := x.skipWS(end)
			if q >= n || s[q] != '>' || !bytes.Equal(s[pos+2:end], top.qname) {
				return nil, errInvalidXML
			}
			x.closeTop()
			pos = q + 1
			continue
		}
		if pos, err = x.startTag(pos); err != nil {
			return nil, err
		}
	}
	// Epilogue.
	for {
		pos = x.skipWS(pos)
		if pos >= n {
			break
		}
		e, ok, err := x.misc(pos)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errInvalidXML
		}
		pos = e
	}
	return x.root, nil
}

// nsPattern returns "ns:" + the pattern of a namespace URI (point 9).
func nsPattern(uri string) string {
	if uri == "" {
		return "ns:{none}"
	}
	if len(uri) > nsMaxBytes {
		return "ns:{*}"
	}
	for i := 0; i < len(uri); i++ {
		c := uri[i]
		if c < 0x21 || c > 0x7e || c == '@' || c == '{' || c == '}' {
			return "ns:{*}"
		}
	}
	var b strings.Builder
	b.WriteString("ns:")
	isRun := func(c byte) bool { return isAlpha(c) || isDigit(c) || c == '_' || c == '-' }
	for i := 0; i < len(uri); {
		if !isRun(uri[i]) {
			b.WriteByte(uri[i])
			i++
			continue
		}
		j := i
		for j < len(uri) && isRun(uri[j]) {
			j++
		}
		r := []byte(uri[i:j])
		if len(r) > 64 || hasSixDigits(r) || hasHexRun(r, 12) {
			b.WriteString("{*}")
		} else {
			b.Write(r)
		}
		i = j
	}
	return b.String()
}

// hasHexRun reports n consecutive hexadecimal digits in s.
func hasHexRun(s []byte, n int) bool {
	run := 0
	for _, c := range s {
		if isHex(c) {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// xmlnsValue builds the xmlns map (point 9): paths in document order of
// their first element, at most 64 entries, then {trunc}. Paths are
// interned as a trie so that memory stays proportional to the elements,
// not to the length of their paths.
func (x *xmlParser) xmlnsValue() ttjson.Value {
	if len(x.events) == 0 {
		return ttjson.Value{}
	}
	type node struct {
		parent int32
		seg    string
		rep    bool
	}
	ids := map[node]int32{}
	var nodes []node
	var idOf func(sk *xSkel) int32
	idOf = func(sk *xSkel) int32 {
		if sk.id > 0 {
			return sk.id - 1
		}
		k := node{parent: -1, seg: sk.seg, rep: sk.grp != nil && sk.grp.count > 1}
		if sk.parent != nil {
			k.parent = idOf(sk.parent)
		}
		id, ok := ids[k]
		if !ok {
			id = int32(len(nodes))
			nodes = append(nodes, k)
			ids[k] = id
		}
		sk.id = id + 1
		return id
	}
	pathOf := func(id int32) string {
		var segs []string
		for id >= 0 {
			nd := nodes[id]
			if nd.rep {
				segs = append(segs, "[*]")
			}
			segs = append(segs, nd.seg)
			id = nd.parent
		}
		var b strings.Builder
		b.WriteByte('$')
		for i := len(segs) - 1; i >= 0; i-- {
			b.WriteString(segs[i])
		}
		return b.String()
	}
	seen := map[int32]bool{}
	out := ttjson.Value{Kind: ttjson.Object}
	total := 0
	for _, ev := range x.events {
		id := idOf(ev.sk)
		if seen[id] {
			continue
		}
		seen[id] = true
		total++
		if len(out.Obj) < xmlnsMaxEntries {
			out.Obj = append(out.Obj, ttjson.Member{Key: pathOf(id), Value: ttjson.Str(ev.tok)})
		}
	}
	if total > xmlnsMaxEntries {
		out.Obj = append(out.Obj, ttjson.Member{Key: keyTrunc, Value: ttjson.Str("trunc:keys:" + LenClass(int64(total)))})
	}
	return out
}

// xmlBody sanitizes an XML body (section 22.2): the tree, fmt and xmlns.
// An invalid body gives trunc:invalid-xml with no discovery entry and no
// xmlns.
func (r *run) xmlBody(d []byte, rs *ruleSet, prefix string) (ttjson.Value, string, ttjson.Value) {
	storeCap := r.lim.MaxArray
	if r.large {
		storeCap = max(r.bodies.LargeArray, r.bodies.LargeNestedArray)
	}
	x := &xmlParser{maxDepth: r.lim.MaxDepth, maxKeys: r.lim.MaxKeys, storeCap: max(storeCap, 1)}
	root, err := x.parse(d)
	if err != nil {
		return tokTruncXML, "", ttjson.Value{}
	}
	f := "xml"
	if root.local == "Envelope" {
		switch x.rootNS {
		case nsSOAP11:
			f = "soap11"
		case nsSOAP12:
			f = "soap12"
		}
	}
	xmlns := x.xmlnsValue()
	b := bodyRun{r: r, rules: rs.body}
	cands := r.arena[:0]
	for i := range rs.body {
		cands = append(cands, int32(i))
	}
	r.arena = cands
	r.arrLevel = 0
	v := b.xmlRoot(root, cands, prefix)
	return v, f, xmlns
}

// ---- tree walk (sections 5.0, 9.3, 9.4 and 22.2 points 7–8) ----

func (b *bodyRun) childPath(path, key string, literal bool) string {
	if !b.r.discOn {
		return ""
	}
	if literal {
		return path + "." + key
	}
	return path + ".*"
}

// xmlRoot sanitizes the body object { <root local name>: <root value> }
// (depth 1).
func (b *bodyRun) xmlRoot(root *xElem, cands []int32, path string) ttjson.Value {
	if b.containerDrop(cands, 1) {
		return ttjson.Str("drop:obj:" + LenClass(1))
	}
	lit := IsLiteralKey([]byte(root.local))
	mark := len(b.r.arena)
	cc := b.filter(cands, 0, []byte(root.local), false)
	v := b.xmlElem(root, 2, cc, b.childPath(path, root.local, lit))
	b.r.arena = b.r.arena[:mark]
	return assembleObject([]objMember{{key: root.local, literal: lit, val: v}}, 1, false)
}

// xmlText reports text with a character other than space, tab, LF and CR.
func xmlText(t []byte) bool {
	for _, c := range t {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}

// xmlLeaf sanitizes a string leaf of the XML tree.
func (b *bodyRun) xmlLeaf(s []byte, depth int, cands []int32, path string) ttjson.Value {
	l := leaf{kind: leafStr, s: s}
	out, def := b.r.applyLeaf(&l, b.winner(cands, depth))
	if def {
		b.r.addDisc(path, &l)
	}
	return out
}

// xmlElem sanitizes the value of an element at tree depth depth: a string
// without attributes and children, otherwise an object with the
// attributes (@name), the groups of children and #text (point 7).
func (b *bodyRun) xmlElem(e *xElem, depth int, cands []int32, path string) ttjson.Value {
	r := b.r
	if len(e.attrs) == 0 && !e.children {
		return b.xmlLeaf(e.text, depth, cands, path)
	}
	if depth > r.lim.MaxDepth {
		return tokTruncDepth
	}
	hasText := xmlText(e.text)
	total := len(e.attrs) + len(e.groups)
	if hasText {
		total++
	}
	if b.containerDrop(cands, depth) {
		return ttjson.Str("drop:obj:" + LenClass(int64(total)))
	}
	keep := min(total, r.lim.MaxKeys)
	members := make([]objMember, 0, keep)
	mark := len(r.arena)
	for i := range e.attrs {
		if len(members) >= keep {
			break
		}
		a := &e.attrs[i]
		key := "@" + a.local
		lit := IsLiteralKey([]byte(a.local))
		cc := b.filter(cands, depth-1, []byte(key), false)
		v := b.xmlLeaf(a.val, depth+1, cc, b.childPath(path, key, lit))
		r.arena = r.arena[:mark]
		members = append(members, objMember{key: key, literal: lit, val: v})
	}
	for _, g := range e.groups {
		if len(members) >= keep {
			break
		}
		lit := IsLiteralKey([]byte(g.local))
		cc := b.filter(cands, depth-1, []byte(g.local), false)
		cp := b.childPath(path, g.local, lit)
		var v ttjson.Value
		if g.count == 1 {
			v = b.xmlElem(g.vals[0], depth+1, cc, cp)
		} else {
			v = b.xmlArray(g, depth+1, cc, cp)
		}
		r.arena = r.arena[:mark]
		members = append(members, objMember{key: g.local, literal: lit, val: v})
	}
	if hasText && len(members) < keep {
		cc := b.filter(cands, depth-1, []byte("#text"), false)
		v := b.xmlLeaf(e.text, depth+1, cc, b.childPath(path, "#text", true))
		r.arena = r.arena[:mark]
		members = append(members, objMember{key: "#text", literal: true, val: v})
	}
	return assembleObject(members, total, total > keep)
}

// xmlArray sanitizes a group of repeated elements (an array, section 9.4
// and 22.5).
func (b *bodyRun) xmlArray(g *xGroup, depth int, cands []int32, path string) ttjson.Value {
	r := b.r
	if depth > r.lim.MaxDepth {
		return tokTruncDepth
	}
	if b.containerDrop(cands, depth) {
		return ttjson.Str("drop:arr:" + LenClass(int64(g.count)))
	}
	limit := r.arrayCap()
	n := min(limit, len(g.vals))
	out := ttjson.Value{Kind: ttjson.Array, Arr: make([]ttjson.Value, 0, n+1)}
	cp := ""
	if r.discOn {
		cp = path + "[*]"
	}
	mark := len(r.arena)
	cc := b.filter(cands, depth-1, nil, true)
	r.arrLevel++
	for _, v := range g.vals[:n] {
		out.Arr = append(out.Arr, b.xmlElem(v, depth+1, cc, cp))
	}
	r.arrLevel--
	r.arena = r.arena[:mark]
	if g.count > limit {
		out.Arr = append(out.Arr, ttjson.Str("trunc:n:"+LenClass(int64(g.count))))
	}
	return out
}

// soapAction returns the soap_action field of a request with an XML
// content type (point 11), ok = false when absent.
func soapAction(n *normHeaders) (string, bool) {
	var raw string
	if v, ok := n.get("soapaction"); ok {
		if !utf8.Valid(v) {
			return keyAny, true
		}
		raw = string(v)
	} else {
		ctv, _ := n.get("content-type")
		a, ok := mediaParams(ctv, "action")
		if !ok {
			return "", false
		}
		raw = a
	}
	s := strings.Trim(raw, " \t")
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" {
		return "", false
	}
	name := s[strings.LastIndexAny(s, "/#:")+1:]
	if IsLiteralKey([]byte(name)) {
		return name, true
	}
	return keyAny, true
}
