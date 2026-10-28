package sanitizer

import (
	"bytes"
	"encoding/base64"
	"unicode/utf8"
)

// Base64 documents (section 22.4, spec v1.19) and the document size classes.

// DocClass returns the document class of a decoded length: l1k, l16k,
// l128k, l1m, l8m or lmax (section 22.4).
func DocClass(n int64) string {
	switch {
	case n <= 1024:
		return "l1k"
	case n <= 16384:
		return "l16k"
	case n <= 131072:
		return "l128k"
	case n <= 1048576:
		return "l1m"
	case n <= 8388608:
		return "l8m"
	}
	return "lmax"
}

var (
	magicPNG = []byte("\x89PNG\r\n\x1a\n")
	magicOLE = []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
	magicZIP = []byte("PK\x03\x04")
)

// magicHead is how many leading bytes magicKind needs for every kind but
// the zip family (whose name search needs every byte).
const magicHead = 12

// magicKind returns the kind of a document from its first bytes (and, for
// zip, the names it holds), or "" (section 22.4 point 3).
func magicKind(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, magicPNG):
		return "png"
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "gif"
	case bytes.HasPrefix(b, []byte("RIFF")) && len(b) >= 12 && string(b[8:12]) == "WEBP":
		return "webp"
	case bytes.HasPrefix(b, magicOLE):
		return "ole"
	case bytes.HasPrefix(b, magicZIP):
		switch {
		case bytes.Contains(b, []byte("word/document.xml")):
			return "docx"
		case bytes.Contains(b, []byte("xl/workbook.xml")):
			return "xlsx"
		case bytes.Contains(b, []byte("ppt/presentation.xml")):
			return "pptx"
		}
		return "zip"
	}
	return ""
}

func isB64Char(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '-' || c == '_'
}

// docMinChars is the minimum length of the base64 content (section 22.4).
const docMinChars = 16

// base64Doc returns "drop:doc:<kind>:<class>" when s (valid UTF-8, not
// recognized by a format) is the base64 of a document, else "". Only the
// first bytes are decoded, except for the zip family, whose names are
// searched in the whole decoded content.
func base64Doc(s []byte) string {
	if bytes.HasPrefix(s, []byte("data:")) {
		i := bytes.IndexByte(s, ',')
		if i < 0 {
			return ""
		}
		pre := s[:i]
		if !bytes.HasSuffix(pre, []byte(";base64")) || len(pre) < len("data:;base64") {
			return ""
		}
		for _, c := range pre {
			if c < 0x21 || c > 0x7e {
				return ""
			}
		}
		s = s[i+1:]
	}
	if len(s) < docMinChars {
		return ""
	}
	body := s
	for len(body) > 0 && body[len(body)-1] == '=' {
		body = body[:len(body)-1]
	}
	pad := len(s) - len(body)
	if pad > 2 || (pad > 0 && len(s)%4 != 0) || len(body)%4 == 1 {
		return ""
	}
	for _, c := range body {
		if !isB64Char(c) {
			return ""
		}
	}
	n := len(body)
	decoded := int64(n/4*3 + [4]int{0, 0, 1, 2}[n%4])
	head := body
	if len(head) > 16 {
		head = head[:16] // 12 bytes
	}
	hb := b64Decode(head)
	kind := magicKind(hb)
	if kind == "zip" {
		kind = magicKind(b64Decode(body))
	}
	if kind == "" {
		return ""
	}
	return "drop:doc:" + kind + ":" + DocClass(decoded)
}

// b64Decode decodes unpadded base64 with the standard and URL alphabets
// mixed; the final padding bits are ignored. len(s)%4 must not be 1.
func b64Decode(s []byte) []byte {
	std := make([]byte, len(s))
	for i, c := range s {
		switch c {
		case '-':
			c = '+'
		case '_':
			c = '/'
		}
		std[i] = c
	}
	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(std)))
	n, _ := base64.RawStdEncoding.Decode(out, std)
	return out[:n]
}

// fileTypes maps the content-type of a file part to its kind when the first
// bytes give none (section 22.3 point 5).
var fileTypes = map[string]string{
	"text/plain": "text", "text/csv": "csv", "application/json": "json",
	"application/xml": "xml", "text/xml": "xml",
}

// fileToken returns drop:file:<kind>:<class> for a multipart file part.
func fileToken(content []byte, ct string, hasCT bool) string {
	kind := magicKind(content)
	if kind == "" {
		kind = "bin"
		if k, ok := fileTypes[ct]; ok && hasCT {
			kind = k
		}
	}
	return "drop:file:" + kind + ":" + DocClass(int64(len(content)))
}

// mediaParams returns the parameters of a normalized content-type value
// (sections 22.2 point 11 and 22.3 point 1): the value is split on ';', the
// first piece dropped, each piece trimmed of spaces and tabs and split on
// the first '=' (no '=' ⇒ ignored); the name is trimmed and ASCII
// lower-cased; the value is trimmed and, when it starts with '"', must end
// with '"' (length >= 2, else ignored) and loses both quotes. The first
// occurrence of a name wins; a value that is not UTF-8 has no parameters.
func mediaParams(v []byte, name string) (string, bool) {
	if !utf8.Valid(v) {
		return "", false
	}
	pieces := bytes.Split(v, []byte{';'})
	for _, p := range pieces[1:] {
		p = trimOWS(p)
		eq := bytes.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		n := asciiLower(string(trimOWS(p[:eq])))
		val := trimOWS(p[eq+1:])
		if len(val) > 0 && val[0] == '"' {
			if len(val) < 2 || val[len(val)-1] != '"' {
				continue
			}
			val = val[1 : len(val)-1]
		}
		if n == name {
			return string(val), true
		}
	}
	return "", false
}
