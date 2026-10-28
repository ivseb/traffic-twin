package sanitizer

import (
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/graphql"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// GraphQLIntrospectionMaxArray is the array limit of a response body when
// the introspection gate is open (section 5.7).
const GraphQLIntrospectionMaxArray = 4096

// graphqlLeaf applies the graphql action (section 5.7). ok false means the
// drop form.
//
// Request side: a string that is an executable document leaves as gql: and
// its shape (names kept, every literal a placeholder). Every request leaf
// with a graphql rule is recorded for the gate.
//
// Response side: with the gate open (at least one request value had a
// graphql rule and every such value was an introspection-only document), a
// string that is a GraphQL name passing the key rule leaves as gql: and the
// name.
func (r *run) graphqlLeaf(l *leaf) (ttjson.Value, bool) {
	if !r.resp {
		r.gqlSeen = true
		if l.kind == leafStr {
			if res, ok := graphql.Shape(string(l.s)); ok {
				if !res.Introspection {
					r.gqlNonIntro = true
				}
				return ttjson.Str("gql:" + res.Shape), true
			}
		}
		r.gqlNonIntro = true
		return ttjson.Value{}, false
	}
	if l.kind == leafStr && r.gqlGate() && graphql.IsName(string(l.s)) && graphql.NameSafe(string(l.s)) {
		return ttjson.Str("gql:" + string(l.s)), true
	}
	return ttjson.Value{}, false
}

// gqlGate reports whether the introspection gate is open.
func (r *run) gqlGate() bool { return r.gqlSeen && !r.gqlNonIntro }

// gqlUnusable records a request value under a graphql rule that has no
// usable text (not UTF-8, unpaired surrogate): it closes the gate.
func (r *run) gqlUnusable(a *policy.Action) {
	if a != nil && a.Kind == policy.ActGraphQL && !r.resp {
		r.gqlSeen, r.gqlNonIntro = true, true
	}
}

// graphqlBody treats an application/graphql body as one string leaf at $
// when the winning rule for $ is graphql (section 9.1). ok false: the body
// is treated as before (drop:bytes:<class>).
func (r *run) graphqlBody(b []byte, rs *ruleSet) (ttjson.Value, bool) {
	var a *policy.Action
	for i := range rs.body {
		if len(rs.body[i].steps) == 0 {
			a = rs.body[i].act
			break
		}
	}
	if a == nil || a.Kind != policy.ActGraphQL {
		return ttjson.Value{}, false
	}
	l := leaf{kind: leafStr, s: b, lone: !utf8.Valid(b)}
	out, _ := r.applyLeaf(&l, a)
	return out, true
}
