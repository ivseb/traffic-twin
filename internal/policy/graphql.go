package policy

import "strings"

// GraphQL rules (policy.md 1.6, sanitizer.md 5.7, spec v1.14).
//
// A graphql rule is accepted by tt-core and keyguard only where it cannot
// carry a value: on the document of a GraphQL request (the request body
// member "query", a whole application/graphql body "$", the query parameter
// "query") and on the names of an introspection result (response body paths
// under $.data.__schema or $.data.__type, no ".*" step). The sanitizer
// itself never lets a literal out of a document and opens the response
// names only for introspection-only requests (the gate of sanitizer.md
// 5.7): these placement rules are the second line.

// GraphQLRequestBodyPaths are the request body tt-paths a graphql rule may
// use.
var GraphQLRequestBodyPaths = map[string]bool{"$.query": true, "$": true}

// GraphQLQueryParam is the query parameter a graphql rule may use (GET).
const GraphQLQueryParam = "query"

// GraphQLResponsePath reports whether a response body tt-path may carry a
// graphql rule: under $.data.__schema or $.data.__type, ending with a name
// step, with no ".*" step.
func GraphQLResponsePath(path string) bool {
	if !(path == "$.data.__schema" || path == "$.data.__type" ||
		strings.HasPrefix(path, "$.data.__schema.") || strings.HasPrefix(path, "$.data.__schema[") ||
		strings.HasPrefix(path, "$.data.__type.") || strings.HasPrefix(path, "$.data.__type[")) {
		return false
	}
	steps, ok := ParseTTPath(path)
	if !ok {
		return false
	}
	for _, s := range steps {
		if s.Kind == StepAnyMember {
			return false
		}
	}
	return true
}

// checkGraphQLRules applies the placement rules of policy.md 1.6.
func checkGraphQLRules(p *Policy) error {
	noGraphQL := func(part *Part, where string) error {
		for name, a := range part.Path {
			if a.Kind == ActGraphQL {
				return invalidf("%s: graphql is not allowed on path parameter %q", where, name)
			}
		}
		for name, a := range part.Query {
			if a.Kind == ActGraphQL {
				return invalidf("%s: graphql is not allowed on query parameter %q", where, name)
			}
		}
		for name, a := range part.Cookies {
			if a.Kind == ActGraphQL {
				return invalidf("%s: graphql is not allowed on cookie %q", where, name)
			}
		}
		for name, a := range part.Headers {
			if a.Kind == ActGraphQL {
				return invalidf("%s: graphql is not allowed on header %q", where, name)
			}
		}
		return nil
	}
	request := func(part *Part, where string) error {
		for name, a := range part.Query {
			if a.Kind == ActGraphQL && name != GraphQLQueryParam {
				return invalidf("%s: graphql is allowed only on the query parameter %q, not %q (policy.md 1.6)", where, GraphQLQueryParam, name)
			}
		}
		rest := *part
		rest.Query = nil // checked above
		if err := noGraphQL(&rest, where); err != nil {
			return err
		}
		for _, r := range part.Body {
			if r.Action.Kind == ActGraphQL && !GraphQLRequestBodyPaths[r.Path] {
				return invalidf("%s: graphql is allowed in a request body only on $.query or $, not %q (policy.md 1.6)", where, r.Path)
			}
		}
		return nil
	}
	response := func(part *Part, where string) error {
		if err := noGraphQL(part, where); err != nil {
			return err
		}
		for _, r := range part.Body {
			if r.Action.Kind == ActGraphQL && !GraphQLResponsePath(r.Path) {
				return invalidf("%s: graphql is allowed in a response body only under $.data.__schema or $.data.__type without .* steps, not %q (policy.md 1.6)", where, r.Path)
			}
		}
		return nil
	}
	none := func(part *Part, where string) error {
		if err := noGraphQL(part, where); err != nil {
			return err
		}
		for _, r := range part.Body {
			if r.Action.Kind == ActGraphQL {
				return invalidf("%s: graphql is not allowed here (%q, policy.md 1.6)", where, r.Path)
			}
		}
		return nil
	}
	for _, part := range []*Part{&p.Global.Request, &p.Global.Response, &p.Global.Errors} {
		if err := none(part, "global"); err != nil {
			return err
		}
	}
	for i := range p.Services {
		s := &p.Services[i]
		if err := request(&s.Request, s.Name); err != nil {
			return err
		}
		if err := response(&s.Response, s.Name); err != nil {
			return err
		}
		if err := none(&s.Errors, s.Name+" errors"); err != nil {
			return err
		}
		for j := range s.Ops {
			where := s.Name + " " + s.Ops[j].Op
			if err := request(&s.Ops[j].Request, where); err != nil {
				return err
			}
			if err := response(&s.Ops[j].Response, where); err != nil {
				return err
			}
		}
	}
	return nil
}

// HasGraphQLRules reports whether p has at least one graphql rule.
func HasGraphQLRules(p *Policy) bool {
	if p == nil {
		return false
	}
	for _, a := range RuleLocations(p) {
		if a.Kind == ActGraphQL {
			return true
		}
	}
	return false
}

// GraphQLTypeRefDepth is how many ofType levels the proposed introspection
// rules cover below a type reference (0 = the reference itself): enough for
// [[X!]!]! and deeper wrappers than real schemas use.
const GraphQLTypeRefDepth = 5

// GraphQLIntrospectionPaths returns the response body tt-paths of the
// names of a standard introspection result (__schema: root types, types,
// fields, arguments, input fields, interfaces, possible types, enum values,
// directives and their locations, type references down to
// GraphQLTypeRefDepth). The observe version puts graphql on them for the
// GraphQL endpoints it recognizes (policy.md 7.4); descriptions, default
// values and deprecation reasons are free text and get no rule.
func GraphQLIntrospectionPaths() []string {
	const s = "$.data.__schema"
	out := []string{
		s + ".queryType.name", s + ".mutationType.name", s + ".subscriptionType.name",
		s + ".types[*].kind", s + ".types[*].name",
		s + ".types[*].fields[*].name", s + ".types[*].fields[*].args[*].name",
		s + ".types[*].inputFields[*].name", s + ".types[*].enumValues[*].name",
		s + ".directives[*].name", s + ".directives[*].locations[*]", s + ".directives[*].args[*].name",
	}
	for _, base := range []string{
		s + ".types[*].fields[*].type", s + ".types[*].fields[*].args[*].type", s + ".types[*].inputFields[*].type",
		s + ".types[*].interfaces[*]", s + ".types[*].possibleTypes[*]", s + ".directives[*].args[*].type",
	} {
		p := base
		for d := 0; d <= GraphQLTypeRefDepth; d++ {
			out = append(out, p+".kind", p+".name")
			p += ".ofType"
		}
	}
	return out
}
