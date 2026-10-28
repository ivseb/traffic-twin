package event

import "strings"

// PathSeg is one segment of a sanitized req.path.
type PathSeg struct {
	// Raw is the segment as written ("orders" or "{tk1:k1:...}").
	Raw string
	// Literal is true for a plain segment; Inner is then the same as Raw.
	Literal bool
	// Inner is the token between braces for a parameter segment ("trunc"
	// for {trunc}).
	Inner string
}

// IsTrunc reports whether the segment is {trunc}.
func (s PathSeg) IsTrunc() bool { return !s.Literal && s.Inner == "trunc" }

const maxPathLen = 3500

func literalSeg(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '~' || c == '-') {
			return false
		}
	}
	return true
}

func keepPathValue(s string) bool { return literalSeg(s) }

// SplitPath splits a sanitized path into segments and validates the grammar
// of schema property req.path:
//
//	^/$|^(/([A-Za-z0-9._~-]{1,64}|\{(drop:...|keep:...|tk1:...|num:...|time:...|trunc)\}))+$
//
// Drop and time tokens are additionally checked for exact validity. The
// root path "/" yields no segments.
func SplitPath(path string) ([]PathSeg, bool) {
	if len(path) == 0 || len(path) > maxPathLen || path[0] != '/' {
		return nil, false
	}
	if path == "/" {
		return nil, true
	}
	var segs []PathSeg
	i := 0
	for i < len(path) {
		if path[i] != '/' {
			return nil, false
		}
		i++
		if i >= len(path) {
			return nil, false
		}
		if path[i] == '{' {
			end := strings.IndexByte(path[i:], '}')
			if end < 0 {
				return nil, false
			}
			inner := path[i+1 : i+end]
			if !validPathToken(inner) {
				return nil, false
			}
			segs = append(segs, PathSeg{Raw: path[i : i+end+1], Inner: inner})
			i += end + 1
			continue
		}
		j := strings.IndexByte(path[i:], '/')
		var seg string
		if j < 0 {
			seg = path[i:]
			i = len(path)
		} else {
			seg = path[i : i+j]
			i += j
		}
		if !literalSeg(seg) {
			return nil, false
		}
		segs = append(segs, PathSeg{Raw: seg, Literal: true, Inner: seg})
	}
	return segs, true
}

func validPathToken(t string) bool {
	switch {
	case t == "trunc":
		return true
	case strings.HasPrefix(t, "drop:"):
		return len(t) <= 29 && ValidDrop(t)
	case strings.HasPrefix(t, "keep:"):
		return keepPathValue(t[5:])
	case strings.HasPrefix(t, "tk1:"):
		return ValidHMACToken(t)
	case strings.HasPrefix(t, "num:"):
		r := t[4:]
		if len(r) < 1 || len(r) > 80 {
			return false
		}
		for i := 0; i < len(r); i++ {
			c := r[i]
			if !(c >= '!' && c <= 'z' || c == '|' || c == '~') {
				return false
			}
		}
		return ValidNumToken(t)
	case strings.HasPrefix(t, "time:"):
		return ValidTimeToken(t)
	}
	return false
}

// ValidPath reports whether p is a valid sanitized req.path.
func ValidPath(p string) bool {
	_, ok := SplitPath(p)
	return ok
}

// JoinPath builds a path from segments ("/" for none).
func JoinPath(segs []PathSeg) string {
	if len(segs) == 0 {
		return "/"
	}
	var sb strings.Builder
	for _, s := range segs {
		sb.WriteByte('/')
		sb.WriteString(s.Raw)
	}
	return sb.String()
}

// ParseOp splits "METHOD /path" into its method and path. The op must be
// valid per [ValidOp].
func ParseOp(op string) (method, path string, ok bool) {
	if !ValidOp(op) {
		return "", "", false
	}
	sp := strings.IndexByte(op, ' ')
	return op[:sp], op[sp+1:], true
}

// OpSegments splits the path part of an op into segments. For a template op
// ("GET /orders/{id}") a parameter segment has Inner "id"; for a raw op it
// has the sanitized token as in req.path. It returns false if the path is not
// made of plain segments and {...} segments.
func OpSegments(opPath string) ([]PathSeg, bool) {
	if opPath == "/" {
		return nil, true
	}
	if len(opPath) == 0 || opPath[0] != '/' {
		return nil, false
	}
	var segs []PathSeg
	i := 0
	for i < len(opPath) {
		i++ // skip '/'
		if i >= len(opPath) {
			return nil, false
		}
		if opPath[i] == '{' {
			end := strings.IndexByte(opPath[i:], '}')
			if end < 0 {
				return nil, false
			}
			segs = append(segs, PathSeg{Raw: opPath[i : i+end+1], Inner: opPath[i+1 : i+end]})
			i += end + 1
		} else {
			j := strings.IndexByte(opPath[i:], '/')
			var seg string
			if j < 0 {
				seg, i = opPath[i:], len(opPath)
			} else {
				seg, i = opPath[i:i+j], i+j
			}
			if seg == "" {
				return nil, false
			}
			segs = append(segs, PathSeg{Raw: seg, Literal: true, Inner: seg})
		}
		if i < len(opPath) && opPath[i] != '/' {
			return nil, false
		}
	}
	return segs, true
}
