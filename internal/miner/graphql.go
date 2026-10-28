package miner

import (
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/graphql"
)

// GraphQL operations (event.md 6) are mined like REST ones: their op key is
// "POST /graphql#GetOrder", identifiers travel as HMAC tokens in
// $.variables and $.data. Two things differ: a query reads and a mutation
// writes although both are POSTs, and an "id" field names its entity from
// the response object that holds it (or from the operation name), not from
// a path segment.

func isGraphQLOp(op string) bool {
	_, _, ok := event.GraphQLOperation(op)
	return ok
}

// graphqlKind gives a logical GraphQL operation the method of its kind the
// first time the log sees it: GET for a query (a read), POST for a
// mutation or a subscription (a write).
func (l *Log) graphqlKind(op int32, ev *event.Event) {
	o := &l.ops[op]
	if o.gqlDone || !isGraphQLOp(o.op) {
		return
	}
	shape, ok := ev.GraphQLDocument()
	if !ok {
		return
	}
	o.gqlDone = true
	doc, err := graphql.ParseShape(shape)
	if err != nil {
		return
	}
	_, name, _ := event.GraphQLOperation(o.op)
	t := doc.Operations[0].Type
	for _, d := range doc.Operations {
		if graphql.OperationName(d, shape) == name {
			t = d.Type
			break
		}
	}
	if t == graphql.Query {
		o.method, o.write, o.read = "GET", false, true
	} else {
		o.method, o.write, o.read = "POST", true, false
	}
}

// graphqlStop are container names that never name an entity.
var graphqlStop = map[string]bool{
	"data": true, "variables": true, "input": true, "edges": true, "node": true, "nodes": true, "items": true,
	"result": true, "results": true, "payload": true, "response": true,
}

// graphqlVerbs are operation name prefixes left out when the operation name
// names the entity (GetOrder → order).
var graphqlVerbs = []string{"get", "list", "find", "fetch", "search", "create", "update", "delete", "remove", "add", "set", "query", "load"}

// graphqlDomain names the entity of an "id" field of a GraphQL operation:
// the nearest enclosing object key that is not a generic container
// ($.data.order.id → order, $.data.orders[*].id → order), else the
// operation name without its verb ($.variables.id of GetOrder → order).
func graphqlDomain(op string, r Ref) string {
	ps := splitTTPath(r.Path)
	for i := len(ps) - 2; i >= 0; i-- {
		p := ps[i]
		if p == "[*]" || graphqlStop[strings.ToLower(p)] {
			continue
		}
		return cleanDomain(singular(strings.ToLower(p)))
	}
	_, name, _ := event.GraphQLOperation(op)
	if strings.HasPrefix(name, "~") {
		return ""
	}
	lower := strings.ToLower(name)
	for _, v := range graphqlVerbs {
		if rest, ok := strings.CutPrefix(lower, v); ok && rest != "" {
			lower = rest
			break
		}
	}
	return cleanDomain(singular(lower))
}

// graphqlSelector reports whether a request body reference can select the
// entity of a read: a top-level variable of a GraphQL operation
// ($.variables.id), the GraphQL counterpart of a path parameter
// (rules.md 2.3, v1.14).
func graphqlSelector(op string, r Ref) bool {
	if !isGraphQLOp(op) || r.From != "req.body" {
		return false
	}
	name, ok := strings.CutPrefix(r.Path, "$.variables.")
	return ok && name != "" && !strings.ContainsAny(name, ".[*")
}

// selectorName is the name part of a selector key: the parameter name, or
// "\x01" and the body path of a GraphQL variable.
func selectorName(r Ref) string {
	if r.Path != "" {
		return "\x01" + r.Path
	}
	return r.Name
}

// selectorRef rebuilds the reference of a selector key.
func selectorRef(from, name string) *Ref {
	if p, ok := strings.CutPrefix(name, "\x01"); ok {
		return &Ref{From: from, Path: p}
	}
	return &Ref{From: from, Name: name}
}
