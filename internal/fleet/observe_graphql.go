package fleet

import (
	"slices"

	"github.com/ivseb/traffic-twin/internal/graphql"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// addGraphQLDecisions adds to the observe version the graphql rules of the
// GraphQL endpoints the assistant recognized by their structure
// (sanitizer.md 5.7, policy.md 1.6 and 7.4): graphql on the document of the
// request ($.query, the parameter query, or the whole application/graphql
// body) and on the names of an introspection result. They never open
// values: the source lets out the shape of a document without its
// literals, and the names of a response only behind the introspection
// gate. A field a person chose for (a rule, or a rule removed) is left
// alone, as for the identifiers.
func addGraphQLDecisions(req *AssistDraftRequest, res *AssistResult, a *policy.Author, hc *humanChoice) {
	for _, s := range res.Services {
		if s.Kind == "external" && !s.Declared {
			continue // its base (scheme) cannot be guessed
		}
		if !policy.ValidServiceName(s.Name) {
			continue
		}
		var ops []AssistDraftOp
		for _, o := range s.Ops {
			var reqPath string
			switch o.GraphQL {
			case graphql.InJSON:
				reqPath = "$.query"
			case graphql.InQuery:
				reqPath = "query." + policy.GraphQLQueryParam
			case graphql.InBody:
				reqPath = "$"
			default:
				continue
			}
			var rules []AssistDraftRule
			add := func(part, path string) {
				if authorHasRule(a, s.Name, o.Op, part, path) || hc.removedByPerson(s.Name, o.Op, part, path) {
					return
				}
				rules = append(rules, AssistDraftRule{Part: part, Path: path, Action: "graphql"})
			}
			add("request", reqPath)
			for _, p := range policy.GraphQLIntrospectionPaths() {
				add("response", p)
			}
			if len(rules) > 0 {
				ops = append(ops, AssistDraftOp{Op: o.Op, Rules: rules})
			}
		}
		if len(ops) == 0 {
			continue
		}
		i := slices.IndexFunc(req.Services, func(d AssistDraftService) bool { return d.Name == s.Name })
		if i < 0 {
			req.Services = append(req.Services, AssistDraftService{Service: s.Service, Name: s.Name, Ops: ops})
			continue
		}
		for _, op := range ops {
			j := slices.IndexFunc(req.Services[i].Ops, func(d AssistDraftOp) bool { return d.Op == op.Op })
			if j < 0 {
				req.Services[i].Ops = append(req.Services[i].Ops, op)
				continue
			}
			req.Services[i].Ops[j].Rules = append(req.Services[i].Ops[j].Rules, op.Rules...)
		}
	}
}
