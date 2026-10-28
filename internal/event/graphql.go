package event

import "strings"

// HTTPOp returns the HTTP operation of an op key: a GraphQL logical
// operation "POST /graphql#GetOrder" (event.md 6) gives "POST /graphql";
// any other op is returned as is. Policy rules, quarantines and the
// observe proposals are keyed by the HTTP operation.
func HTTPOp(op string) string {
	if i := strings.IndexByte(op, '#'); i > 0 {
		return op[:i]
	}
	return op
}

// GraphQLOperation splits a logical GraphQL op key into its HTTP operation
// and the operation name ("GetOrder", or "~" and a hash for an anonymous
// operation). ok is false for any other op.
func GraphQLOperation(op string) (httpOp, name string, ok bool) {
	i := strings.IndexByte(op, '#')
	if i <= 0 || i == len(op)-1 {
		return op, "", false
	}
	return op[:i], op[i+1:], true
}

// GraphQLDocument returns the gql: shape of the GraphQL document of the
// request, if the exchange carries one (sanitizer.md 5.7.5): the member
// "query" of a JSON body, an application/graphql body, or the query
// parameter "query" (a single value). The shape is returned without the
// "gql:" prefix.
func (e *Event) GraphQLDocument() (string, bool) {
	isDoc := func(s string) bool { return strings.HasPrefix(s, "gql:") && ClassifyToken(s) == TokGQL }
	if b := e.Req.Body; b != nil {
		switch b.Kind {
		case Object:
			if q, ok := b.Get("query"); ok && q.Kind == String && isDoc(q.S) {
				return q.S[4:], true
			}
		case String:
			if isDoc(b.S) {
				return b.S[4:], true
			}
		}
	}
	if vs, ok := e.Req.Query.Get("query"); ok && len(vs) == 1 && isDoc(vs[0]) {
		return vs[0][4:], true
	}
	return "", false
}

// SOAPOperation returns the operation name of a SOAP exchange (event.md 6,
// spec v1.19): the request soap_action when it is a name, else the only
// element of the SOAP Body of the request (a literal key). ok is false for
// exchanges that are not SOAP (fmt soap11 or soap12) or without a name.
// The intake stores such an exchange under the logical op
// "<op HTTP>#<name>", like a GraphQL operation.
func (e *Event) SOAPOperation() (string, bool) {
	if e.Req.Fmt != FmtSOAP11 && e.Req.Fmt != FmtSOAP12 {
		return "", false
	}
	if e.Req.SoapAction != "" && e.Req.SoapAction != "{*}" {
		return e.Req.SoapAction, true
	}
	b := e.Req.Body
	if b == nil || b.Kind != Object {
		return "", false
	}
	env, ok := b.Get("Envelope")
	if !ok || env.Kind != Object {
		return "", false
	}
	body, ok := env.Get("Body")
	if !ok || body.Kind != Object {
		return "", false
	}
	name := ""
	for _, m := range body.O {
		if IsXMLKey(m.K) {
			continue
		}
		if name != "" || m.K == "{*}" || m.K == "{trunc}" {
			return "", false
		}
		name = m.K
	}
	return name, name != ""
}
