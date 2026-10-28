package policy

import "sort"

// Joinable HMAC domain families (spec v1.18, C15).
//
// A family declares that some HMAC domains name the same identifier under
// different field names (clientId and customerId): every hmac(d) with d in
// the family compiles to hmac(<family>), so equal values give equal tokens
// in all those fields. The compiled body keeps its shape (only domains
// change): sources need no change. Changing an hmac domain is observe-safe
// (policy.md 7.1): no value leaves in clear, the tokens of the joined fields
// become comparable with each other (linkable), never reversible
// (docs/THREAT_MODEL.md).

// Limits of a family.
const (
	MinFamilyDomains = 2
	MaxFamilyDomains = 16
	MaxFamilies      = 64
)

// ValidateFamilies checks hmac.families: family names and members follow
// the domain grammar, 2..16 members per family, no reserved domain, a
// domain in at most one family.
func ValidateFamilies(fams map[string][]string) error {
	_, err := familyAliases(fams)
	return err
}

// familyAliases maps every member domain to its family name.
func familyAliases(fams map[string][]string) (map[string]string, error) {
	if len(fams) == 0 {
		return nil, nil
	}
	if len(fams) > MaxFamilies {
		return nil, invalidf("hmac.families: at most %d families", MaxFamilies)
	}
	names := make([]string, 0, len(fams))
	for n := range fams {
		names = append(names, n)
	}
	sort.Strings(names)
	alias := map[string]string{}
	for _, n := range names {
		if !ValidDomain(n) || ReservedDomains[n] {
			return nil, invalidf("hmac.families: bad family name %q", n)
		}
		ds := fams[n]
		if len(ds) < MinFamilyDomains || len(ds) > MaxFamilyDomains {
			return nil, invalidf("hmac.families.%s: between %d and %d domains", n, MinFamilyDomains, MaxFamilyDomains)
		}
		seen := map[string]bool{}
		for _, d := range ds {
			if !ValidDomain(d) || ReservedDomains[d] {
				return nil, invalidf("hmac.families.%s: bad or reserved domain %q", n, d)
			}
			if seen[d] {
				return nil, invalidf("hmac.families.%s: duplicate domain %q", n, d)
			}
			seen[d] = true
			if f, ok := alias[d]; ok && f != n {
				return nil, invalidf("hmac.families: domain %q is in two families", d)
			}
			alias[d] = n
		}
	}
	// A family name that is a member of another family would chain.
	for _, n := range names {
		if f, ok := alias[n]; ok && f != n {
			return nil, invalidf("hmac.families: family %q is a member of family %q", n, f)
		}
	}
	return alias, nil
}

// applyFamilies rewrites the hmac domains of a compiled policy.
func applyFamilies(p *Policy, alias map[string]string) {
	if len(alias) == 0 {
		return
	}
	fixMap := func(m map[string]Action) {
		for k, a := range m {
			if a.Kind == ActHMAC {
				if f, ok := alias[a.Domain]; ok {
					a.Domain = f
					m[k] = a
				}
			}
		}
	}
	fixPart := func(pt *Part) {
		fixMap(pt.Path)
		fixMap(pt.Query)
		fixMap(pt.Headers)
		fixMap(pt.Cookies)
		for i := range pt.Body {
			if a := &pt.Body[i].Action; a.Kind == ActHMAC {
				if f, ok := alias[a.Domain]; ok {
					a.Domain = f
				}
			}
		}
	}
	fixScope := func(s *Scope) {
		fixPart(&s.Request)
		fixPart(&s.Response)
		fixPart(&s.Errors)
	}
	fixScope(&p.Global)
	for i := range p.Services {
		s := &p.Services[i]
		fixScope(&s.Scope)
		for j := range s.Ops {
			fixPart(&s.Ops[j].Request)
			fixPart(&s.Ops[j].Response)
		}
	}
}

// FamilyOf returns the family a domain compiles to (the domain itself when
// it is in none).
func FamilyOf(fams map[string][]string, d string) string {
	for n, ds := range fams {
		for _, x := range ds {
			if x == d {
				return n
			}
		}
	}
	return d
}

// ValidJSONPath matches a dotted path of 1..8 members, each
// ^[A-Za-z0-9_-]{1,64}$ (identity.subject.json_path, spec v1.18).
func ValidJSONPath(s string) bool {
	if s == "" || len(s) > 8*65 {
		return false
	}
	n, start := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			c := s[i]
			if !(isAlpha(c) || isDigit(c) || c == '_' || c == '-') {
				return false
			}
			continue
		}
		if i-start < 1 || i-start > 64 {
			return false
		}
		n++
		start = i + 1
	}
	return n <= 8
}
