package intake

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/hostpat"
)

// applyQuarantine rewrites ev in place according to the active
// quarantines (docs/spec/event.md 5.2): keep values become their drop form,
// quarantined literal names become {*}, quarantined path segments become
// {drop:str:<class>} and the quarantined labels of host patterns become {*}
// (spec v1.5). The forms are the ones the sanitizer would have produced for
// the same values. It is idempotent and reports whether the event changed.
func applyQuarantine(ev *event.Event, s *qSnapshot) bool {
	if s == nil || s.empty() {
		return false
	}
	changed := false
	// Quarantines are keyed by the HTTP operation: a stored GraphQL event
	// carries its logical op (event.md 6), restored after the rewrite.
	if _, name, isGQL := event.GraphQLOperation(ev.Op); isGQL {
		ev.Op = event.HTTPOp(ev.Op)
		defer func() { ev.Op += "#" + name }()
	}
	opKey := ev.Op
	if ev.RouteSource == event.RouteRaw {
		opKey = rawOpKey
	}
	if len(s.byPrefix) > 0 {
		pre := ev.Policy.ID + "\x1f" + svcKey(ev.Service) + "\x1f" + opKey + "\x1f"
		for _, e := range s.byPrefix[pre] {
			if rewriteEntry(ev, e) {
				changed = true
			}
		}
	}
	if len(s.segments) > 0 {
		if pos := s.segments[svcKey(ev.Service)+"\x1f"+ev.OpMethod()]; len(pos) > 0 && rewriteSegments(ev, pos) {
			changed = true
		}
	}
	if len(s.hosts) > 0 || len(s.labels) > 0 {
		if h, isHost := event.IsHostService(ev.Service); isHost {
			_, srcQ := s.hosts[ev.Source.ID]
			if svc, ok := rewriteHost(h, s.labels, srcQ); ok {
				ev.Service = svc
				changed = true
			}
		}
	}
	return changed
}

// rewriteHost collapses the quarantined labels of a host service: the
// labels at the quarantined positions of its registrable domain and, when
// the source's registrable domains are quarantined, the registrable label
// itself. A result outside the service grammar (only possible for an odd
// host listed in segments.hosts_allow) becomes host:unlisted.
func rewriteHost(h string, labels map[string]map[int]struct{}, source bool) (string, bool) {
	host, port := hostpat.SplitPort(h)
	if hostpat.IsIP(host) {
		return "", false
	}
	ls, reg := hostpat.Registrable(host)
	changed := false
	for p := range labels[strings.Join(ls[reg:], ".")] {
		if i := reg - p; i >= 0 && i < len(ls) && ls[i] != hostpat.Star {
			ls[i] = hostpat.Star
			changed = true
		}
	}
	if source && ls[reg] != hostpat.Star {
		ls[reg] = hostpat.Star
		changed = true
	}
	if !changed {
		return "", false
	}
	out := strings.Join(ls, ".")
	if port != "" {
		out += ":" + port
	}
	svc := "host:" + out
	if !event.ValidServiceRef(svc) {
		svc = "host:unlisted"
	}
	return svc, true
}

func rewriteEntry(ev *event.Event, e qEntry) bool {
	switch e.part {
	case "req.body":
		return rewriteBody(ev.Req.Body, e)
	case "resp.body":
		if ev.Resp != nil {
			return rewriteBody(ev.Resp.Body, e)
		}
	case "req.query":
		return rewriteMulti(&ev.Req.Query, e)
	case "req.headers":
		return rewriteMulti(&ev.Req.Headers, e)
	case "req.cookies":
		return rewriteMulti(&ev.Req.Cookies, e)
	case "resp.headers":
		if ev.Resp != nil {
			return rewriteMulti(&ev.Resp.Headers, e)
		}
	case "resp.cookies":
		if ev.Resp != nil {
			return rewriteMulti(&ev.Resp.Cookies, e)
		}
	case "req.path":
		if e.kind == QuarantineKeep {
			return rewritePathKeep(ev, e.path)
		}
	}
	return false
}

// keepToDrop turns a keep leaf into its drop form.
func keepToDrop(v *event.Value) bool {
	switch v.Kind {
	case event.String:
		val, ok := event.KeepValue(v.S)
		if !ok {
			return false
		}
		v.S = event.DropForm(val)
	case event.Number:
		if isIntLexeme(v.S) {
			*v = event.Str("drop:int")
		} else {
			*v = event.Str("drop:dec")
		}
	case event.Bool:
		*v = event.Str("drop:bool")
	case event.Null:
		*v = event.Str("drop:null")
	default:
		return false
	}
	return true
}

func isIntLexeme(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func rewriteBody(b *event.Value, e qEntry) bool {
	if b == nil {
		return false
	}
	buf := append(make([]byte, 0, 64), '$')
	return rewriteWalk(b, buf, e)
}

func rewriteWalk(v *event.Value, path []byte, e qEntry) bool {
	changed := false
	switch v.Kind {
	case event.Array:
		p := append(path, '[', '*', ']')
		for i := range v.A {
			if rewriteWalk(&v.A[i], p, e) {
				changed = true
			}
		}
	case event.Object:
		if e.kind == QuarantineName && string(path) == e.path {
			if collapseObject(v) {
				changed = true
			}
		}
		for i := range v.O {
			m := &v.O[i]
			switch m.K {
			case "{trunc}":
				continue
			case "{*}":
				p := append(path, '.', '*')
				if m.V.Kind == event.Array {
					for k := range m.V.A {
						if rewriteWalk(&m.V.A[k], p, e) {
							changed = true
						}
					}
				}
			default:
				p := append(append(path, '.'), m.K...)
				if rewriteWalk(&m.V, p, e) {
					changed = true
				}
			}
		}
		if changed {
			sortObject(v)
		}
	default:
		if e.kind == QuarantineKeep && string(path) == e.path {
			if keepToDrop(v) {
				changed = true
			}
		}
	}
	return changed
}

// collapseObject moves every literal member of an object under {*}.
func collapseObject(v *event.Value) bool {
	var moved []event.Value
	var rest []event.Member
	var star *event.Member
	for i := range v.O {
		m := v.O[i]
		switch m.K {
		case "{*}":
			mm := m
			star = &mm
		case "{trunc}":
			rest = append(rest, m)
		default:
			moved = append(moved, m.V)
		}
	}
	if len(moved) == 0 {
		return false
	}
	var vals []event.Value
	if star != nil && star.V.Kind == event.Array {
		vals = append(vals, star.V.A...)
	}
	vals = append(vals, moved...)
	sort.SliceStable(vals, func(i, j int) bool { return event.CompareCanonical(&vals[i], &vals[j]) < 0 })
	rest = append(rest, event.Member{K: "{*}", V: event.Value{Kind: event.Array, A: vals}})
	v.O = rest
	sortObject(v)
	return true
}

func sortObject(v *event.Value) {
	sort.SliceStable(v.O, func(i, j int) bool { return v.O[i].K < v.O[j].K })
}

func rewriteMulti(m *event.Multi, e qEntry) bool {
	if len(*m) == 0 {
		return false
	}
	switch e.kind {
	case QuarantineKeep:
		changed := false
		for i := range *m {
			en := &(*m)[i]
			if en.Name != e.path {
				continue
			}
			for k, t := range en.Values {
				if val, ok := event.KeepValue(t); ok {
					en.Values[k] = event.DropForm(val)
					changed = true
				}
			}
		}
		return changed
	case QuarantineName:
		var moved []string
		var rest event.Multi
		var star []string
		for _, en := range *m {
			switch en.Name {
			case "{*}":
				star = en.Values
			case "{trunc}":
				rest = append(rest, en)
			default:
				moved = append(moved, en.Values...)
			}
		}
		if len(moved) == 0 {
			return false
		}
		vals := append(append([]string(nil), star...), moved...)
		rest = append(rest, event.MultiEntry{Name: "{*}", Values: vals})
		sort.SliceStable(rest, func(i, j int) bool { return rest[i].Name < rest[j].Name })
		*m = rest
		return true
	}
	return false
}

// rewritePathKeep rewrites {keep:x} at req.path segment p<i>.
func rewritePathKeep(ev *event.Event, name string) bool {
	if !strings.HasPrefix(name, "p") {
		return false
	}
	idx, err := strconv.Atoi(name[1:])
	if err != nil {
		return false
	}
	segs, ok := event.SplitPath(ev.Req.Path)
	if !ok || idx < 0 || idx >= len(segs) || segs[idx].Literal || !strings.HasPrefix(segs[idx].Inner, "keep:") {
		return false
	}
	repl := "drop:str:" + strings.TrimPrefix(event.DropForm(segs[idx].Inner[5:]), "drop:str:")
	segs[idx] = event.PathSeg{Raw: "{" + repl + "}", Inner: repl}
	ev.Req.Path = event.JoinPath(segs)
	return true
}

// rewriteSegments rewrites the literal segments of a raw route at the given
// operation positions (relative to the base of the service).
func rewriteSegments(ev *event.Event, positions map[int]struct{}) bool {
	if ev.RouteSource != event.RouteRaw {
		return false
	}
	method, opPath, ok := event.ParseOp(ev.Op)
	if !ok {
		return false
	}
	opSegs, ok1 := event.OpSegments(opPath)
	reqSegs, ok2 := event.SplitPath(ev.Req.Path)
	if !ok1 || !ok2 || len(reqSegs) < len(opSegs) {
		return false
	}
	n := len(reqSegs) - len(opSegs)
	changed := false
	for j, s := range opSegs {
		if _, hit := positions[j]; !hit || !s.Literal {
			continue
		}
		repl := event.DropForm(s.Raw)
		seg := event.PathSeg{Raw: "{" + repl + "}", Inner: repl}
		opSegs[j] = seg
		reqSegs[n+j] = seg
		changed = true
	}
	if changed {
		ev.Op = method + " " + event.JoinPath(opSegs)
		ev.Req.Path = event.JoinPath(reqSegs)
	}
	return changed
}
