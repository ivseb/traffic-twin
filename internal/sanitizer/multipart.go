package sanitizer

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// multipart/form-data bodies (section 22.3, spec v1.19).

var errInvalidMultipart = errors.New("sanitizer: invalid multipart body")

var tokTruncMultipart = ttjson.Str("trunc:invalid-multipart")

// mpPart is one part of a multipart body.
type mpPart struct {
	name    string // value of the name parameter (UTF-8)
	file    bool   // filename or filename* parameter present
	content []byte
	ct      string // media type of the part content-type, ASCII lower case
	hasCT   bool
}

// validBoundary matches ^[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]$.
func validBoundary(b string) bool {
	if len(b) < 1 || len(b) > 70 {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !(isAlpha(c) || isDigit(c) || bytes.IndexByte([]byte("'()+_,./:=?-"), c) >= 0 || (c == ' ' && i < len(b)-1)) {
			return false
		}
	}
	return true
}

// isTokenChar reports a token character of RFC 9110.
func isTokenChar(c byte) bool {
	return isAlpha(c) || isDigit(c) || bytes.IndexByte([]byte("!#$%&'*+.^_`|~-"), c) >= 0
}

func asciiLowerBytes(b []byte) string { return asciiLower(string(b)) }

// parseMultipart implements section 22.3 points 1–4. ctv is the
// normalized content-type value (its boundary parameter).
func parseMultipart(data, ctv []byte) ([]mpPart, error) {
	boundary, ok := mediaParams(ctv, "boundary")
	if !ok || !validBoundary(boundary) {
		return nil, errInvalidMultipart
	}
	delim := []byte("--" + boundary)
	crlfDelim := []byte("\r\n--" + boundary)
	pos := 0
	if !bytes.HasPrefix(data, delim) {
		i := bytes.Index(data, crlfDelim)
		if i < 0 {
			return nil, errInvalidMultipart
		}
		pos = i + 2
	}
	var raw [][]byte
	for {
		pos += len(delim)
		if bytes.HasPrefix(data[pos:], []byte("--")) {
			break
		}
		for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t') {
			pos++
		}
		if !bytes.HasPrefix(data[pos:], []byte("\r\n")) {
			return nil, errInvalidMultipart
		}
		pos += 2
		nxt := bytes.Index(data[pos:], crlfDelim)
		if nxt < 0 {
			return nil, errInvalidMultipart
		}
		raw = append(raw, data[pos:pos+nxt])
		pos += nxt + 2
	}
	parts := make([]mpPart, 0, len(raw))
	for _, p := range raw {
		var head, content []byte
		if bytes.HasPrefix(p, []byte("\r\n")) {
			content = p[2:]
		} else {
			j := bytes.Index(p, []byte("\r\n\r\n"))
			if j < 0 {
				return nil, errInvalidMultipart
			}
			head, content = p[:j], p[j+4:]
		}
		var cd, ct []byte
		var hasCD, hasCT bool
		for len(head) > 0 || head != nil {
			line := head
			if k := bytes.Index(head, []byte("\r\n")); k >= 0 {
				line, head = head[:k], head[k+2:]
			} else {
				head = nil
			}
			k := bytes.IndexByte(line, ':')
			if k <= 0 {
				return nil, errInvalidMultipart
			}
			for _, c := range line[:k] {
				if !isTokenChar(c) {
					return nil, errInvalidMultipart
				}
			}
			switch asciiLowerBytes(line[:k]) {
			case "content-disposition":
				if !hasCD {
					cd, hasCD = trimOWS(line[k+1:]), true
				}
			case "content-type":
				if !hasCT {
					ct, hasCT = trimOWS(line[k+1:]), true
				}
			}
		}
		if !hasCD || !utf8.Valid(cd) {
			return nil, errInvalidMultipart
		}
		params, err := disposition(cd)
		if err != nil {
			return nil, err
		}
		name, ok := params["name"]
		if !ok {
			return nil, errInvalidMultipart
		}
		_, f1 := params["filename"]
		_, f2 := params["filename*"]
		mp := mpPart{name: name, file: f1 || f2, content: content}
		if hasCT && utf8.Valid(ct) {
			if i := bytes.IndexByte(ct, ';'); i >= 0 {
				ct = ct[:i]
			}
			mp.ct, mp.hasCT = asciiLowerBytes(trimOWS(ct)), true
		}
		parts = append(parts, mp)
	}
	return parts, nil
}

// disposition parses a content-disposition value (section 22.3 point 4):
// type form-data, then parameters (first occurrence wins).
func disposition(s []byte) (map[string]string, error) {
	i := bytes.IndexByte(s, ';')
	kind := s
	if i >= 0 {
		kind = s[:i]
	}
	if asciiLowerBytes(trimOWS(kind)) != "form-data" {
		return nil, errInvalidMultipart
	}
	params := map[string]string{}
	set := func(k, v string) {
		if _, ok := params[k]; !ok {
			params[k] = v
		}
	}
	n := len(s)
	pos := n
	if i >= 0 {
		pos = i
	}
	for pos < n {
		for pos < n && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == ';') {
			pos++
		}
		if pos >= n {
			break
		}
		start := pos
		for pos < n && s[pos] != '=' && s[pos] != ';' {
			pos++
		}
		name := asciiLowerBytes(trimOWS(s[start:pos]))
		if pos >= n || s[pos] == ';' {
			set(name, "")
			continue
		}
		pos++ // '='
		for pos < n && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		var val []byte
		if pos < n && s[pos] == '"' {
			pos++
			for {
				if pos >= n {
					return nil, errInvalidMultipart
				}
				c := s[pos]
				if c == '\\' && pos+1 < n {
					val = append(val, s[pos+1])
					pos += 2
					continue
				}
				if c == '"' {
					pos++
					break
				}
				val = append(val, c)
				pos++
			}
			for pos < n && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos < n && s[pos] != ';' {
				return nil, errInvalidMultipart
			}
		} else {
			start := pos
			for pos < n && s[pos] != ';' {
				pos++
			}
			val = trimOWS(s[start:pos])
		}
		set(name, string(val))
	}
	return params, nil
}

// multipartBody sanitizes a multipart/form-data body as a form-like name
// map (section 22.3 points 5–6): fields like form values, file parts
// drop:file:<kind>:<class> with no rule and no discovery entry.
func (r *run) multipartBody(d, ctv []byte, rs *ruleSet, prefix string) ttjson.Value {
	parts, err := parseMultipart(d, ctv)
	if err != nil {
		return tokTruncMultipart
	}
	m := newMultimap(r.lim.MaxArray)
	for i := range parts {
		p := &parts[i]
		name := nameOut([]byte(p.name))
		if p.file {
			m.add(name, func() ttjson.Value { return ttjson.Str(fileToken(p.content, p.ct, p.hasCT)) })
			continue
		}
		dp := ""
		if r.discOn {
			if name == keyAny {
				dp = prefix + ".*"
			} else {
				dp = prefix + "." + name
			}
		}
		a := formRule(rs, p.name)
		m.add(name, func() ttjson.Value { return r.stringValue(p.content, a, dp) })
	}
	v, ok := m.value()
	if !ok {
		v = ttjson.Obj()
	}
	return v
}
