package export

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const triggerPrefix = "tt-example-"

// triggerValue is the synthetic parameter value that selects a named contract
// example in Microcks (examples are correlated by name, selected by value).
func triggerValue(name string) string { return triggerPrefix + name }

// stripExt removes x-tt-* extensions (internal to traffic-twin).
func stripExt(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if strings.HasPrefix(k, "x-tt-") {
				continue
			}
			out[k] = stripExt(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = stripExt(x)
		}
		return out
	}
	return v
}

func apiVersion(svc Service, created string) string {
	if info := asMap(svc.Contract["info"]); info != nil {
		if v, ok := info["version"].(string); ok && v != "" {
			return v
		}
	}
	if len(created) >= 10 {
		return created[:10]
	}
	return "1"
}

// exampleNames lists every response example name of an operation.
func exampleNames(op *operation) []string {
	set := map[string]bool{}
	for _, r := range op.Responses {
		for _, e := range r.Examples {
			set[e.Name] = true
		}
	}
	return sortedKeys(set)
}

// addParamExamples gives every path and query parameter one example per
// response example name (Microcks correlates examples by name).
func addParamExamples(params any, names []string, only func(name string) bool) {
	for _, raw := range asSlice(params) {
		p := asMap(raw)
		if p == nil {
			continue
		}
		in, _ := p["in"].(string)
		if in != "path" && in != "query" {
			continue
		}
		ex := asMap(p["examples"])
		if ex == nil {
			ex = map[string]any{}
		}
		for _, n := range names {
			if only != nil && !only(n) {
				continue
			}
			if _, ok := ex[n]; !ok {
				ex[n] = map[string]any{"value": triggerValue(n)}
			}
		}
		p["examples"] = ex
	}
}

type mkOpPlan struct {
	dispatcher string
	rules      string
	delay      int
	hasDelay   bool
}

func exportMicrocks(m *model, opts MicrocksOptions) ([]outFile, *Report) {
	rep := newReport("microcks", m.in.Manifest.PackID)
	rep.addNotes(m.notes)
	var files []outFile

	for _, svc := range m.in.Services {
		ops := m.opsBySvc[svc.Name]
		if ops == nil {
			continue
		}
		rep.count("services", 1)
		ver := apiVersion(svc, m.in.Manifest.CreatedAt)
		name := svc.Name

		// ---- primary artifact: OpenAPI with correlated named examples
		doc := stripExt(deepCopy(svc.Contract)).(map[string]any)
		info := asMap(doc["info"])
		if info == nil {
			info = map[string]any{}
			doc["info"] = info
		}
		info["title"] = name
		info["version"] = ver
		paths := asMap(doc["paths"])
		plans := map[string]*mkOpPlan{}
		triggers := map[string][]string{}
		for _, op := range ops {
			rep.count("operations", 1)
			item := asMap(paths[op.Path])
			o := asMap(item[strings.ToLower(op.Method)])
			names := exampleNames(op)
			// Only parameters that exist get trigger values; an operation with
			// request-body examples is selected by JSON_BODY instead.
			if len(op.paramsIn("path"))+len(op.paramsIn("query")) > 0 {
				addParamExamples(item["parameters"], names, nil)
				addParamExamples(o["parameters"], names, nil)
				triggers[op.Key] = append(triggers[op.Key], names...)
			}
			rep.exported("example", "op:"+name+" "+op.Key, len(names))
			plans[op.Key] = m.microcksPlan(op, names, opts, rep)
		}
		files = append(files, outFile{Path: "microcks/" + name + "/" + name + "-openapi.yaml", Data: marshalYAML(doc)})

		// ---- secondary artifact: APIExamples (world-derived exchanges)
		exOps := map[string]any{}
		scripts := map[string][]*lookup{}
		for _, l := range m.lookups[name] {
			if opts.Stateless && l.stateful() {
				// Keep only the last observed step.
				last := 0
				for i, v := range l.Views {
					if !v.Projected {
						last = i
					}
				}
				cp := *l
				cp.Views = []view{l.Views[last]}
				l = &cp
			}
			oe, _ := exOps[l.Op.Key].(map[string]any)
			if oe == nil {
				oe = map[string]any{}
				exOps[l.Op.Key] = oe
			}
			for _, v := range l.Views {
				oe[v.Name] = map[string]any{
					"request":  map[string]any{"parameters": map[string]any{l.Param: l.Key}},
					"response": map[string]any{"status": strconv.Itoa(v.Status), "mediaType": v.Media, "body": v.Body},
				}
				rep.exported("example", "entity:"+l.Entity, 1)
			}
			if l.stateful() {
				scripts[l.Op.Key] = append(scripts[l.Op.Key], l)
			}
		}
		if len(exOps) > 0 {
			ex := map[string]any{
				"apiVersion": "mocks.microcks.io/v1alpha1",
				"kind":       "APIExamples",
				"metadata":   map[string]any{"name": name, "version": ver},
				"operations": exOps,
			}
			files = append(files, outFile{Path: "microcks/" + name + "/" + name + "-examples.yaml", Data: marshalYAML(ex)})
		}

		// ---- secondary artifact: APIMetadata (delay, dispatcher)
		mdOps := map[string]any{}
		for _, op := range ops {
			p := plans[op.Key]
			ent := map[string]any{}
			if p.hasDelay {
				ent["delay"] = p.delay
			}
			if ls := scripts[op.Key]; len(ls) > 0 && !opts.Stateless {
				ent["dispatcher"] = "SCRIPT"
				ent["dispatcherRules"] = microcksScript(op, ls, m.allLookupsFor(name, op.Key, opts), opts, defaultName(op))
				rep.exported("dispatcher", "op:"+name+" "+op.Key, 1)
				rep.lose("state", "op:"+name+" "+op.Key, "SCRIPT + store: the position of each subject lives in the Microcks service-scoped store (TTL "+strconv.Itoa(opts.StateTTL)+"s, shared by all clients, lost on restart); no per-session isolation and no entity creation", len(ls))
			} else if p.dispatcher != "" {
				ent["dispatcher"] = p.dispatcher
				ent["dispatcherRules"] = p.rules
				rep.exported("dispatcher", "op:"+name+" "+op.Key, 1)
			}
			if len(ent) > 0 {
				mdOps[op.Key] = ent
			}
		}
		if len(mdOps) > 0 {
			md := map[string]any{
				"apiVersion": "mocks.microcks.io/v1alpha1",
				"kind":       "APIMetadata",
				"metadata":   map[string]any{"name": name, "version": ver},
				"operations": mdOps,
			}
			files = append(files, outFile{Path: "microcks/" + name + "/" + name + "-metadata.yaml", Data: marshalYAML(md)})
		}

		// ---- losses common to the service
		for _, op := range ops {
			el := "op:" + name + " " + op.Key
			if f, ok := m.faults[name+"|"+op.Key]; ok {
				for _, fs := range f.Statuses {
					rep.lose("probabilistic-fault", el, fmt.Sprintf("status %d observed with p=%v: reachable only through the example's trigger parameter value, never injected at random", fs.Status, fs.P), 1)
				}
				for _, ne := range f.NetErrors {
					rep.lose("probabilistic-fault", el, fmt.Sprintf("network error %q (p=%v) cannot be expressed in Microcks", ne.Kind, ne.P), 1)
				}
			}
			if l := m.latencyOf(op); l != nil {
				if _, sg, _, ok := lognormalOf(l); ok && sg > 0 && opts.Delay != "none" {
					rep.lose("latency-distribution", el, "only a fixed delay (the median) is set: the log-normal spread is lost", 1)
				} else if opts.Delay == "none" {
					rep.lose("latency-distribution", el, "delay disabled by --microcks-delay=none", 1)
				}
			}
		}
		for _, k := range sortedKeys(triggers) {
			rep.lose("selection", "op:"+name+" "+k, "KO and alternative examples are selected with trigger parameter values ("+triggerPrefix+"<example>), not by a probability", len(triggers[k]))
		}
	}
	seenRules := map[string]bool{}
	for _, l := range m.allLookups() {
		if l.RuleID != "" && l.stateful() && !seenRules[l.RuleID] {
			seenRules[l.RuleID] = true
			rep.lose("time", "rule:"+l.RuleID, fmt.Sprintf("figurative delays (after: %s) and the virtual clock are not honoured: each call of the first exposing operation advances the scripted position by one step", m.delayInfo(l.RuleID)), 1)
		}
	}
	foreign := map[string]int{}
	for _, l := range m.allLookups() {
		if l.Foreign != nil {
			foreign["op:"+l.Service+" "+l.Op.Key]++
		}
	}
	for _, el := range sortedKeys(foreign) {
		rep.lose("scope", el, "owner-scoped read: the 404/403 given to another customer needs a session customer; the contract's 404/403 examples stay reachable through their trigger values", foreign[el])
	}
	rep.count("files", len(files))
	rep.count("rules_approved", m.stats.ApprovedRules)
	m.reportCommon(rep)
	rep.setPresets(m.presetReports(TargetMicrocks, presetOpts{}))
	return files, rep.build(files)
}

func (m *model) allLookups() []*lookup {
	var out []*lookup
	for _, k := range sortedKeys(m.lookups) {
		out = append(out, m.lookups[k]...)
	}
	return out
}

// allLookupsFor returns every lookup of one operation (stateful or static).
func (m *model) allLookupsFor(svc, opKey string, _ MicrocksOptions) []*lookup {
	var out []*lookup
	for _, l := range m.lookups[svc] {
		if l.Op.Key == opKey {
			out = append(out, l)
		}
	}
	return out
}

func defaultName(op *operation) string {
	if d, _, ok := op.defaultExample(); ok {
		return d.Name
	}
	return ""
}

// microcksPlan chooses the dispatcher of an operation that has no stateful
// lookups: URI_PARTS / URI_PARAMS / URI_ELEMENTS wrapped in FALLBACK, or
// JSON_BODY when request-body examples differ on a scalar property.
func (m *model) microcksPlan(op *operation, names []string, opts MicrocksOptions, rep *reportBuilder) *mkOpPlan {
	p := &mkOpPlan{}
	if opts.Delay != "none" {
		if med, _, _, ok := lognormalOf(m.latencyOf(op)); ok {
			p.delay, p.hasDelay = int(med), true
		}
	}
	def := defaultName(op)
	pathP, queryP := op.paramsIn("path"), op.paramsIn("query")
	var reqQuery []string
	for _, q := range queryP {
		if q.Required {
			reqQuery = append(reqQuery, q.Name)
		}
	}
	var pn []string
	for _, x := range pathP {
		pn = append(pn, x.Name)
	}
	switch {
	case len(pn) > 0 || len(reqQuery) > 0:
		var d, rules string
		switch {
		case len(pn) > 0 && len(reqQuery) > 0:
			d, rules = "URI_ELEMENTS", strings.Join(pn, " && ")+" ?? "+strings.Join(reqQuery, " && ")
		case len(pn) > 0:
			d, rules = "URI_PARTS", strings.Join(pn, " && ")
		default:
			d, rules = "URI_PARAMS", strings.Join(reqQuery, " && ")
		}
		if def != "" {
			p.dispatcher = "FALLBACK"
			p.rules = jsonString(map[string]any{"dispatcher": d, "dispatcherRules": rules, "fallback": def})
		} else {
			p.dispatcher, p.rules = d, rules
		}
	case len(op.ReqExamples) >= 2:
		if exp, cases, ok := bodyDiscriminant(op, def); ok {
			p.dispatcher = "JSON_BODY"
			p.rules = jsonString(map[string]any{"exp": exp, "operator": "equals", "cases": cases})
			// Response examples without a request example are discarded by Microcks.
			have := map[string]bool{}
			for _, e := range op.ReqExamples {
				have[e.Name] = true
			}
			for _, n := range names {
				if !have[n] {
					rep.lose("selection", "op:"+op.Service+" "+op.Key, fmt.Sprintf("response example %q has no request-body example with the same name: Microcks discards it", n), 1)
				}
			}
		}
	}
	if p.dispatcher == "" && len(names) > 1 {
		rep.lose("selection", "op:"+op.Service+" "+op.Key, "no parameter or body property tells the examples apart: Microcks answers with the first one", len(names)-1)
	}
	return p
}

// bodyDiscriminant finds the first top-level scalar property (sorted) whose
// value differs across the request examples and maps value -> example name.
func bodyDiscriminant(op *operation, def string) (string, map[string]any, bool) {
	var objs []map[string]any
	for _, e := range op.ReqExamples {
		o := asMap(e.Value)
		if o == nil {
			return "", nil, false
		}
		objs = append(objs, o)
	}
	props := map[string]bool{}
	for _, o := range objs {
		for k := range o {
			props[k] = true
		}
	}
	for _, k := range sortedKeys(props) {
		vals := map[string]bool{}
		okAll := true
		for _, o := range objs {
			v, present := o[k]
			if !present {
				okAll = false
				break
			}
			switch v.(type) {
			case string, json.Number, float64, bool:
				vals[stringify(v)] = true
			default:
				okAll = false
			}
		}
		if okAll && len(vals) == len(objs) {
			cases := map[string]any{}
			for i, e := range op.ReqExamples {
				cases[stringify(objs[i][k])] = e.Name
			}
			if def != "" {
				cases["default"] = def
			}
			return "/" + k, cases, true
		}
	}
	return "", nil, false
}

func jsonString(v any) string {
	b := marshalJSON(v)
	return strings.TrimSpace(string(b))
}

func groovyStr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "$", `\$`)
	return "'" + s + "'"
}

// microcksScript builds the Groovy SCRIPT dispatcher for an operation whose
// subjects move through scenario steps. The script returns the name of the
// response example for the current step and advances a position kept in the
// Microcks store (documented at
// https://microcks.io/documentation/explanations/dispatching/).
func microcksScript(op *operation, stateful []*lookup, all []*lookup, opts MicrocksOptions, fallback string) string {
	param := stateful[0].Param
	kind := stateful[0].Kind
	var b strings.Builder
	b.WriteString("// generated by traffic-twin: stateful approximation of rule effects\n")
	b.WriteString("def subjects = [\n")
	sort.SliceStable(all, func(i, j int) bool { return all[i].Key < all[j].Key })
	first := true
	for _, l := range all {
		if l.Param != param || l.Kind != kind {
			continue
		}
		if !first {
			b.WriteString(",\n")
		}
		first = false
		names := make([]string, len(l.Views))
		for i, v := range l.Views {
			names[i] = groovyStr(v.Name)
		}
		scen := l.Scenario
		if scen == "" {
			scen = l.Entity + "-" + l.Key
		}
		fmt.Fprintf(&b, "  %s: [s: %s, a: %t, n: [%s]]", groovyStr(l.Key), groovyStr(scen), l.Advance, strings.Join(names, ", "))
	}
	b.WriteString("\n];\n")
	b.WriteString("def req = mockRequest.getRequest();\n")
	if kind == "path" {
		tail := 0
		segs := strings.Split(strings.Trim(op.Path, "/"), "/")
		for i, s := range segs {
			if s == "{"+param+"}" {
				tail = len(segs) - 1 - i
			}
		}
		fmt.Fprintf(&b, "def uri = req.getRequestURI().split('/');\n")
		fmt.Fprintf(&b, "def key = uri[uri.length - 1 - %d];\n", tail)
	} else {
		fmt.Fprintf(&b, "def key = req.getParameter(%s);\n", groovyStr(param))
	}
	fmt.Fprintf(&b, "if (key != null && key.startsWith(%s)) { return key.substring(%d); }\n", groovyStr(triggerPrefix), len(triggerPrefix))
	b.WriteString("def entry = subjects[key];\n")
	fmt.Fprintf(&b, "if (entry == null) { return %s; }\n", groovyStr(fallback))
	b.WriteString("def skey = 'tt:' + entry.s;\n")
	b.WriteString("def raw = store.get(skey);\n")
	b.WriteString("def idx = (raw == null) ? 0 : Integer.parseInt(raw);\n")
	b.WriteString("if (idx > entry.n.size() - 1) { idx = entry.n.size() - 1; }\n")
	fmt.Fprintf(&b, "if (entry.a && idx < entry.n.size() - 1) { store.put(skey, String.valueOf(idx + 1), %d); }\n", opts.StateTTL)
	b.WriteString("return entry.n[idx];")
	return b.String()
}
