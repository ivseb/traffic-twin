package intake

import (
	"strings"

	"github.com/ivseb/traffic-twin/internal/graphql"
)

// introspectionMaxArray mirrors the source: with the introspection gate
// open a response body keeps arrays up to 4096 elements (sanitizer.md
// 5.7.2).
const introspectionMaxArray = 4096

// gqlDetail checks a gql: token against the action (event.md 5.1 point 6,
// sanitizer.md 5.7): only under a graphql rule; in a request it must parse
// as a shape, in a response it must be a safe GraphQL name and the
// introspection gate rebuilt from the request must be open. It returns ""
// when allowed.
func (c *checker) gqlDetail(tok string, a *action) string {
	if !strings.HasPrefix(tok, "gql:") {
		return "malformed token"
	}
	if a == nil || a.kind != actGraphQL {
		return "gql without graphql rule"
	}
	body := tok[4:]
	if !c.resp {
		if !graphql.ValidShape(body) {
			return "gql value that is not a GraphQL shape without values"
		}
		return ""
	}
	if !c.gqlGate() {
		return "gql in a response without an introspection-only request"
	}
	if !graphql.IsName(body) || !graphql.NameSafe(body) {
		return "gql in a response that is not a safe GraphQL name"
	}
	return ""
}

// gqlTrack records a request value under a graphql rule for the gate: it
// stays open only if every such value is the shape of an introspection-only
// document. tok is "" for a value that is not a string.
func (c *checker) gqlTrack(tok string, a *action) {
	if c.resp || a == nil || a.kind != actGraphQL {
		return
	}
	c.gqlSeen = true
	if !strings.HasPrefix(tok, "gql:") {
		c.gqlNonIntro = true
		return
	}
	d, err := graphql.ParseShape(tok[4:])
	if err != nil || !graphql.IsIntrospection(d) {
		c.gqlNonIntro = true
	}
}

func (c *checker) gqlGate() bool { return c.gqlSeen && !c.gqlNonIntro }

// rootGraphQL reports a graphql rule winning for the whole body ($): an
// application/graphql body is then one leaf (sanitizer.md 9.1).
func (c *checker) rootGraphQL() bool {
	a := c.gs.bodyAction(c.steps[:0])
	return a != nil && a.kind == actGraphQL
}

// maxArray is the array limit of the part being checked.
func (c *checker) maxArray() int {
	if c.resp && c.gqlGate() && c.pol.Limits.MaxArray < introspectionMaxArray {
		return introspectionMaxArray
	}
	return c.pol.Limits.MaxArray
}
