package miner

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Entity names (docs/spec/rules.md 2.7). An entity is identified by the
// service that creates it and the group that owns that service, not by its
// HMAC domain alone: two teams sharing a console both create an "order"
// (shop-api of one, orders-api of the other) and those are two entities.
// The first creator of a domain keeps the bare name (order); a later one
// gets a qualified name (order-orders-api, then order-orders-api-<group>,
// then a number) and an id prefix of its own. The names given are stored
// (miner_entity_names) so that they never move between runs: an approved
// rule that writes "order" keeps writing the same team's order, whichever
// team has more traffic later.

// EntityName is the name given to the entity a service creates in a domain
// within a group.
type EntityName struct {
	Name     string
	Domain   string
	Service  string
	Group    string
	IDPrefix string
	// Created orders the names: the oldest of two entities with the same
	// service and domain in two groups keeps the rule signatures unchanged.
	Created time.Time
}

// maxEntityName bounds the generated names: effect ids are built from them
// ("<name>-requested", "<name>-<name>-linked") and are identifiers of at
// most 64 characters.
const maxEntityName = 40

type nameKey struct{ group, domain, service string }

// nameBook gives the names of one mining run, from the stored ones.
type nameBook struct {
	byKey    map[nameKey]*EntityName
	byName   map[string]*EntityName
	prefixes map[string]bool
	now      time.Time
}

func newNameBook(stored []EntityName, now time.Time) *nameBook {
	b := &nameBook{byKey: map[nameKey]*EntityName{}, byName: map[string]*EntityName{}, prefixes: map[string]bool{}, now: now}
	for i := range stored {
		n := stored[i]
		if n.Name == "" || b.byName[n.Name] != nil {
			continue
		}
		k := nameKey{n.Group, n.Domain, n.Service}
		if b.byKey[k] != nil {
			continue
		}
		b.byKey[k], b.byName[n.Name] = &n, &n
		b.prefixes[n.IDPrefix] = true
	}
	return b
}

// candidate is an accepted entity creator before it is named.
type candidate struct {
	group, domain, service string
	first                  time.Time // first creation seen
}

// assign names the candidates of a run: the stored name when there is one
// (a name stored before groups were known, group "", goes to the first
// group that creates the entity), else a new one, the earliest creation
// first.
func (b *nameBook) assign(cs []candidate) map[nameKey]*EntityName {
	sort.SliceStable(cs, func(i, j int) bool {
		if !cs[i].first.Equal(cs[j].first) {
			return cs[i].first.Before(cs[j].first)
		}
		if cs[i].group != cs[j].group {
			return cs[i].group < cs[j].group
		}
		return cs[i].service < cs[j].service
	})
	out := map[nameKey]*EntityName{}
	used := map[*EntityName]bool{}
	for _, c := range cs {
		if n := b.byKey[nameKey{c.group, c.domain, c.service}]; n != nil {
			used[n] = true
		}
	}
	var fresh []candidate
	for _, c := range cs {
		k := nameKey{c.group, c.domain, c.service}
		if n := b.byKey[k]; n != nil {
			out[k] = n
			continue
		}
		if c.group != "" {
			if n := b.byKey[nameKey{"", c.domain, c.service}]; n != nil && !used[n] {
				used[n] = true
				// Adopted: the stored row takes the group.
				delete(b.byKey, nameKey{"", c.domain, c.service})
				n.Group = c.group
				b.byKey[k] = n
				out[k] = n
				continue
			}
		}
		fresh = append(fresh, c)
	}
	for _, c := range fresh {
		k := nameKey{c.group, c.domain, c.service}
		n := &EntityName{Name: b.freeName(c), Domain: c.domain, Service: c.service, Group: c.group, Created: b.now}
		n.IDPrefix = b.freePrefix(c)
		b.byKey[k], b.byName[n.Name] = n, n
		b.prefixes[n.IDPrefix] = true
		out[k] = n
	}
	return out
}

// sigKey is what the rule signatures of an entity carry in place of its
// domain: the domain, unless an older entity of the same service and
// domain exists in another group (the same service name in two teams).
func (b *nameBook) sigKey(n *EntityName) string {
	for _, o := range b.byName {
		if o == n || o.Domain != n.Domain || o.Service != n.Service || o.Group == n.Group {
			continue
		}
		if o.Created.Before(n.Created) || (o.Created.Equal(n.Created) && o.Name < n.Name) {
			return n.Name
		}
	}
	return n.Domain
}

// names returns the names in use, sorted by name.
func (b *nameBook) names() []EntityName {
	out := make([]EntityName, 0, len(b.byName))
	for _, n := range b.byName {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (b *nameBook) freeName(c candidate) string {
	tries := []string{c.domain, joinName(c.domain, c.service), joinName(c.domain, c.service, c.group)}
	for _, t := range tries {
		if t != "" && reIdent.MatchString(t) && b.byName[t] == nil {
			return t
		}
	}
	base := tries[len(tries)-1]
	if base == "" || !reIdent.MatchString(base) {
		base = c.domain
	}
	for i := 2; ; i++ {
		suf := "-" + strconv.Itoa(i)
		t := base
		if len(t)+len(suf) > maxEntityName {
			t = strings.TrimRight(t[:maxEntityName-len(suf)], "-_")
		}
		if t += suf; b.byName[t] == nil {
			return t
		}
	}
}

// joinName joins name parts into an entity name (letters, digits, "-"),
// at most maxEntityName characters; "" when nothing is left.
func joinName(parts ...string) string {
	var sb strings.Builder
	for _, p := range parts {
		s := slug(p)
		if s == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(s)
	}
	s := sb.String()
	if len(s) > maxEntityName {
		s = strings.TrimRight(s[:maxEntityName], "-")
	}
	return s
}

// freePrefix returns an id prefix no other named entity uses: the one of
// the domain (ORD-SYN-), else the domain's letters followed by the
// initials of the service (ORDOA-SYN- for orders-api), else two letters.
func (b *nameBook) freePrefix(c candidate) string {
	p := idPrefix(c.domain)
	if !b.prefixes[p] {
		return p
	}
	base := strings.TrimSuffix(p, "-SYN-")
	var ini []byte
	for _, w := range strings.FieldsFunc(strings.ToUpper(c.service+"-"+c.group), func(r rune) bool { return r < 'A' || r > 'Z' }) {
		ini = append(ini, w[0])
	}
	for n := 1; n <= len(ini) && len(base)+n <= 5; n++ {
		if q := base + string(ini[:n]) + "-SYN-"; !b.prefixes[q] {
			return q
		}
	}
	if len(base) > 3 {
		base = base[:3]
	}
	for x := 'A'; x <= 'Z'; x++ {
		for y := 'A'; y <= 'Z'; y++ {
			if q := base + string(x) + string(y) + "-SYN-"; !b.prefixes[q] {
				return q
			}
		}
	}
	return p
}
