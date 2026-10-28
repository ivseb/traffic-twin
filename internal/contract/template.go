package contract

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// Path templates inferred from raw traffic.
//
// A source whose policy declares no operation sends "raw" ops: the path as
// the sanitizer left it, with the segments it could not keep replaced by
// their drop form ("GET /bookings/{drop:str:uuid}") and the others kept as
// literals when they look like words (segments.auto_words). Without
// templates these ops were left out of the OpenAPI document, so a service
// observed for hours still had an empty contract.
//
// inferTemplates groups the raw ops of a service into templates:
//   - every sanitized segment ({drop:...}, {tk1:...}, {num:...}, ...) is a
//     parameter;
//   - a literal position becomes a parameter when, among the ops that agree
//     on every other segment, it takes many distinct values (cardinality:
//     at least templateMinDistinct) or identifier-looking values (format:
//     digits, long hex or base64url strings) next to other values or to an
//     already sanitized segment.
//
// A single parameter is called {id}; with several, each takes the name of
// the literal before it ({bookingId}, {userId}). Ops whose path is already
// a template (declared in the policy) are never changed.

// templateMinDistinct is the number of distinct literal values at a position
// from which it is a parameter whatever the values look like.
const templateMinDistinct = 8

// RouteInferred is the route source of an operation whose template was
// inferred from raw traffic.
const RouteInferred = "inferred"

const wildcard = "\x00"

type rawOp struct {
	key    string
	method string
	segs   []string // literal, or wildcard
	raw    bool     // had at least one sanitized segment
}

// isTokenSeg reports whether a segment of a raw op path is a sanitizer
// token (not a template parameter name).
func isTokenSeg(s event.PathSeg) bool {
	return !s.Literal && !validParamName(s.Inner)
}

// inferTemplates maps the op keys of one service that have no declared
// template to their inferred template ("GET /bookings/{id}"; a literal-only
// op maps to itself). Declared ops are absent from the result.
func inferTemplates(keys []string) map[string]string {
	var ops []*rawOp
	for _, k := range keys {
		if _, _, gql := event.GraphQLOperation(k); gql {
			continue // a GraphQL operation is named, never a template (event.md 6)
		}
		method, path, ok := event.ParseOp(k)
		if !ok {
			continue
		}
		segs, ok := event.OpSegments(path)
		if !ok {
			continue
		}
		o := &rawOp{key: k, method: method}
		declared := false
		for _, s := range segs {
			switch {
			case s.Literal:
				o.segs = append(o.segs, s.Inner)
			case isTokenSeg(s):
				o.segs = append(o.segs, wildcard)
				o.raw = true
			default:
				declared = true
			}
		}
		if declared {
			continue // a policy template: never touched
		}
		ops = append(ops, o)
	}
	if len(ops) == 0 {
		return nil
	}
	// Collapse literal positions until nothing changes.
	for changed := true; changed; {
		changed = false
		groups := map[string][]*rawOp{}
		for _, o := range ops {
			for i := range o.segs {
				k := groupKey(o, i)
				groups[k] = append(groups[k], o)
			}
		}
		for k, g := range groups {
			i, _ := strconv.Atoi(k[:strings.IndexByte(k, '|')])
			distinct := map[string]bool{}
			wild, idLike := false, true
			for _, o := range g {
				if o.segs[i] == wildcard {
					wild = true
					continue
				}
				distinct[o.segs[i]] = true
				idLike = idLike && looksLikeID(o.segs[i])
			}
			if len(distinct) == 0 {
				continue
			}
			if len(distinct) >= templateMinDistinct || (idLike && (len(distinct) >= 2 || wild)) {
				for _, o := range g {
					if o.segs[i] != wildcard {
						o.segs[i] = wildcard
						o.raw = true
						changed = true
					}
				}
			}
		}
	}
	// Every op without a declared template gets an entry (a literal-only
	// op maps to itself): raw events of these ops are rendered.
	out := map[string]string{}
	for _, o := range ops {
		out[o.key] = o.method + " " + templatePath(o.segs)
	}
	return out
}

func groupKey(o *rawOp, pos int) string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(pos))
	sb.WriteByte('|')
	sb.WriteString(o.method)
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(len(o.segs)))
	for j, s := range o.segs {
		sb.WriteByte('/')
		if j != pos {
			sb.WriteString(s)
		}
	}
	return sb.String()
}

// looksLikeID: digits (not a version like v2), or a long hex or base64url
// string.
func looksLikeID(s string) bool {
	if len(s) >= 2 && len(s) <= 4 && s[0] == 'v' && allDigits(s[1:]) {
		return false
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits > 0 {
		return true
	}
	return len(s) >= 16 && !strings.ContainsAny(s, ".~")
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// templatePath renders segments with parameters named as documented.
func templatePath(segs []string) string {
	params := 0
	for _, s := range segs {
		if s == wildcard {
			params++
		}
	}
	used := map[string]int{}
	var sb strings.Builder
	for i, s := range segs {
		sb.WriteByte('/')
		if s != wildcard {
			sb.WriteString(s)
			continue
		}
		name := "id"
		if params > 1 {
			name = paramFromLiteral(segs, i)
		}
		used[name]++
		if n := used[name]; n > 1 {
			name += strconv.Itoa(n)
		}
		sb.WriteString("{" + name + "}")
	}
	if len(segs) == 0 {
		return "/"
	}
	return sb.String()
}

// paramFromLiteral names the parameter at position i after the literal
// before it: "bookings" -> bookingId, "line-items" -> lineItemId.
func paramFromLiteral(segs []string, i int) string {
	if i == 0 || segs[i-1] == wildcard {
		return "id"
	}
	words := strings.FieldsFunc(segs[i-1], func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	if len(words) == 0 {
		return "id"
	}
	last := words[len(words)-1]
	switch {
	case strings.HasSuffix(last, "ies") && len(last) > 4:
		last = last[:len(last)-3] + "y"
	case strings.HasSuffix(last, "ses") && len(last) > 4:
		last = last[:len(last)-2]
	case strings.HasSuffix(last, "s") && !strings.HasSuffix(last, "ss") && !strings.HasSuffix(last, "us") && len(last) > 3:
		last = last[:len(last)-1]
	}
	words[len(words)-1] = last
	var sb strings.Builder
	for j, w := range words {
		w = strings.ToLower(w)
		if j > 0 && w != "" {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		sb.WriteString(w)
	}
	name := sb.String() + "Id"
	if !validParamName(name) {
		return "id"
	}
	return name
}

// literalShape is the drop token of a literal path segment (its format or
// length class), as the sanitizer would have written it.
func literalShape(s string) string {
	if f := sanitizer.DetectFormat([]byte(s)); f != "" {
		return "drop:str:" + f
	}
	return "drop:str:" + sanitizer.LenClass(int64(len(s)))
}

// templatesBySummary computes the templates of every service of the
// summaries.
func templatesBySummary(services map[string][]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for svc, keys := range services {
		sort.Strings(keys)
		if m := inferTemplates(keys); len(m) > 0 {
			out[svc] = m
		}
	}
	return out
}
