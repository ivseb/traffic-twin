package fleet

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Classification of a policy change (docs/spec/policy.md 5). tt-core
// computes it to show approvers what a draft opens; keyguard recomputes it
// on its own before signing, so this code is advisory and deliberately
// conservative: anything not in the closed list of closing operations
// opens ("nel dubbio, la modifica apre").
const (
	Closing = "closing"
	Opening = "opening"
)

// DiffEntry is one human-readable change of a draft against the active
// version.
type DiffEntry struct {
	Change string `json:"change"` // added | removed | changed
	Where  string `json:"where"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Opens  bool   `json:"opens"`
}

type itemKind uint8

const (
	kOpaque   itemKind = iota // any change, addition or removal opens
	kSet                      // set member: adding opens, removing closes
	kLower                    // integer: lowering closes, raising opens
	kBool                     // false -> true opens, true -> false closes
	kWindow                   // timed switch (discovery, auto_words)
	kRule                     // rule action
	kPresence                 // service or operation entry
)

type item struct {
	kind   itemKind
	s      string
	n      int64
	on     bool
	until  time.Time
	action policy.Action
}

func (it item) String() string {
	switch it.kind {
	case kLower:
		return strconv.FormatInt(it.n, 10)
	case kBool:
		return strconv.FormatBool(it.on)
	case kWindow:
		if !it.on {
			return "off"
		}
		return "on until " + it.until.UTC().Format(time.RFC3339)
	case kRule:
		return FormatAction(it.action)
	case kPresence:
		return "present"
	case kSet:
		return "listed"
	}
	return it.s
}

// FormatAction renders a compiled action in the author syntax.
func FormatAction(a policy.Action) string {
	switch a.Kind {
	case policy.ActKeep:
		return "keep"
	case policy.ActCode:
		if a.Shape == policy.CodeShapeAlnum {
			return "code(alnum)"
		}
		return "code"
	case policy.ActGraphQL:
		return "graphql"
	case policy.ActHMAC:
		return "hmac(" + a.Domain + ")"
	case policy.ActBucketNum:
		lx := make([]string, len(a.Bounds))
		for i, b := range a.Bounds {
			lx[i] = b.Lexeme
		}
		return "bucket(num, [" + strings.Join(lx, ", ") + "])"
	case policy.ActBucketTime:
		return "bucket(time, " + a.Unit + ")"
	}
	return "drop"
}

func flatten(p *policy.Policy) map[string]item {
	m := map[string]item{}
	if p == nil {
		return m
	}
	set := func(prefix string, list []string) {
		for _, v := range list {
			m[prefix+"["+v+"]"] = item{kind: kSet}
		}
	}
	m["hmac.kid"] = item{kind: kOpaque, s: p.HMAC.Kid}
	m["hmac.epoch"] = item{kind: kOpaque, s: p.HMAC.Epoch}
	set("hmac.accept_kids", p.HMAC.AcceptKids)
	if s := p.Subject; s != nil {
		m["identity.subject"] = item{kind: kOpaque, s: fmt.Sprintf("%s:%s:%s:%s", s.From, s.Name, s.JWTClaim, s.JSONPath)}
	}
	m["sampling.rate_bp"] = item{kind: kLower, n: int64(p.Sampling.RateBP)}
	m["sampling.trust_baggage"] = item{kind: kBool, on: p.Sampling.TrustBaggage}
	set("sampling.propagate_to", p.Sampling.PropagateTo)
	m["segments.auto_words"] = item{kind: kWindow, on: p.Segments.AutoWords, until: p.Segments.AutoWordsExpiresAt}
	set("segments.allow", p.Segments.Allow)
	set("segments.hosts_allow", p.Segments.HostsAllow)
	// hosts.discovery (spec v1.5): off -> auto opens (host patterns leave),
	// auto -> off closes.
	m["hosts.discovery_auto"] = item{kind: kBool, on: p.Hosts.Auto()}
	l := p.Limits
	m["limits.max_body_bytes"] = item{kind: kLower, n: l.MaxBodyBytes}
	m["limits.max_depth"] = item{kind: kLower, n: int64(l.MaxDepth)}
	m["limits.max_array"] = item{kind: kLower, n: int64(l.MaxArray)}
	m["limits.max_keys"] = item{kind: kLower, n: int64(l.MaxKeys)}
	m["limits.keep_max_bytes"] = item{kind: kLower, n: int64(l.KeepMaxBytes)}
	d := item{kind: kWindow}
	if p.Discovery != nil && p.Discovery.Enabled {
		d.on, d.until = true, p.Discovery.ExpiresAt
	}
	m["discovery"] = d
	set("targets.groups", p.Groups)
	flattenScope(m, "global", &p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		w := "services." + s.Name
		m[w] = item{kind: kPresence}
		mt := "base " + s.Match.Base
		if s.Match.Inbound {
			mt = "inbound"
			if s.Match.Internal {
				mt = "inbound internal"
			}
		}
		m[w+".match"] = item{kind: kOpaque, s: mt}
		flattenScope(m, w, &s.Scope)
		for j := range s.Ops {
			op := &s.Ops[j]
			ow := w + ".ops." + op.Op
			m[ow] = item{kind: kPresence}
			flattenPart(m, ow+".request", &op.Request)
			flattenPart(m, ow+".response", &op.Response)
		}
	}
	return m
}

func flattenScope(m map[string]item, w string, s *policy.Scope) {
	flattenPart(m, w+".request", &s.Request)
	flattenPart(m, w+".response", &s.Response)
	flattenPart(m, w+".errors", &s.Errors)
}

func flattenPart(m map[string]item, w string, p *policy.Part) {
	for _, kv := range []struct {
		name string
		m    map[string]policy.Action
	}{{"path", p.Path}, {"query", p.Query}, {"headers", p.Headers}, {"cookies", p.Cookies}} {
		for k, a := range kv.m {
			m[w+"."+kv.name+"."+k] = item{kind: kRule, action: a}
		}
	}
	for _, r := range p.Body {
		m[w+".body."+r.Path] = item{kind: kRule, action: r.Action}
	}
}

var timeUnitRank = map[string]int{"hour": 0, "day": 1, "month": 2, "year": 3}

// ruleChangeCloses applies the closing list of policy.md 5 to one rule.
func ruleChangeCloses(from, to policy.Action) bool {
	switch {
	case to.Kind == policy.ActDrop:
		return true
	case from.Kind == policy.ActKeep && (to.Kind == policy.ActHMAC || to.Kind == policy.ActBucketNum || to.Kind == policy.ActBucketTime || to.Kind == policy.ActCode):
		return true
	case from.Kind == policy.ActCode && to.Kind == policy.ActHMAC:
		return true
	case from.Kind == policy.ActBucketNum && to.Kind == policy.ActBucketNum:
		old := map[string]bool{}
		for _, b := range from.Bounds {
			old[b.Lexeme] = true
		}
		for _, b := range to.Bounds {
			if !old[b.Lexeme] {
				return false
			}
		}
		return true
	case from.Kind == policy.ActBucketTime && to.Kind == policy.ActBucketTime:
		return timeUnitRank[to.Unit] >= timeUnitRank[from.Unit]
	}
	return false
}

func actionEqual(a, b policy.Action) bool {
	return FormatAction(a) == FormatAction(b)
}

// Classify compares a candidate policy with the active one (nil when there
// is none: the first policy always opens) and returns the classification
// and the diff, sorted by location.
func Classify(active, candidate *policy.Policy) (string, []DiffEntry) {
	old, nw := flatten(active), flatten(candidate)
	keys := make([]string, 0, len(old)+len(nw))
	for k := range old {
		keys = append(keys, k)
	}
	for k := range nw {
		if _, ok := old[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	diff := []DiffEntry{}
	for _, k := range keys {
		o, inOld := old[k]
		n, inNew := nw[k]
		var e DiffEntry
		switch {
		case !inOld:
			e = DiffEntry{Change: "added", Where: k, To: n.String(), Opens: true}
			if n.kind == kWindow && !n.on {
				continue // an "off" switch that did not exist before
			}
		case !inNew:
			e = DiffEntry{Change: "removed", Where: k, From: o.String()}
			switch o.kind {
			case kSet:
				e.Opens = false
			case kRule:
				// Removing keep/hmac/bucket leaves the default drop;
				// removing an explicit drop may un-collapse a container.
				e.Opens = o.action.Kind == policy.ActDrop
			case kWindow:
				e.Opens = false
			default:
				e.Opens = true
			}
		default:
			if o.kind != n.kind {
				e = DiffEntry{Change: "changed", Where: k, From: o.String(), To: n.String(), Opens: true}
				break
			}
			switch o.kind {
			case kRule:
				if actionEqual(o.action, n.action) {
					continue
				}
				e = DiffEntry{Change: "changed", Where: k, From: o.String(), To: n.String(), Opens: !ruleChangeCloses(o.action, n.action)}
			case kLower:
				if o.n == n.n {
					continue
				}
				e = DiffEntry{Change: "changed", Where: k, From: o.String(), To: n.String(), Opens: n.n > o.n}
			case kBool:
				if o.on == n.on {
					continue
				}
				e = DiffEntry{Change: "changed", Where: k, From: o.String(), To: n.String(), Opens: n.on}
			case kWindow:
				if o.on == n.on && (!o.on || o.until.Equal(n.until)) {
					continue
				}
				opens := n.on && (!o.on || n.until.After(o.until))
				e = DiffEntry{Change: "changed", Where: k, From: o.String(), To: n.String(), Opens: opens}
			case kSet, kPresence:
				continue
			default:
				if o.s == n.s {
					continue
				}
				e = DiffEntry{Change: "changed", Where: k, From: o.String(), To: n.String(), Opens: true}
			}
		}
		diff = append(diff, e)
	}
	class := Closing
	if active == nil || slices.ContainsFunc(diff, func(d DiffEntry) bool { return d.Opens }) {
		class = Opening
	}
	return class, diff
}
