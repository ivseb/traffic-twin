package export

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// WireMock priorities (lower wins, documented at
// https://wiremock.org/docs/stubbing/).
const (
	wmPrioFault    = 1
	wmPrioExample  = 2
	wmPrioScenario = 3
	wmPrioStatic   = 4
	wmPrioForeign  = 5
	wmPrioNoHeader = 6
	wmPrioDefault  = 10
)

// wmTimeoutDelayMS is how long a "timeout" network error stalls the answer.
const wmTimeoutDelayMS = 30000

type wmStub struct {
	prio int
	name string
	body map[string]any
}

func exportWireMock(m *model, opts WireMockOptions) ([]outFile, *Report) {
	rep := newReport("wiremock", m.in.Manifest.PackID)
	rep.addNotes(m.notes)
	var files []outFile
	cust := map[string]bool{}

	svcs := sortedKeys(m.opsBySvc)
	for _, svc := range svcs {
		var stubs []wmStub
		add := func(prio int, name string, st map[string]any) {
			st["name"] = name
			st["id"] = detUUID("wiremock", svc, name)
			st["priority"] = prio
			stubs = append(stubs, wmStub{prio, name, st})
		}
		rep.count("services", 1)

		// 1. Contract examples: default (lowest priority) and header-selected.
		for _, op := range m.opsBySvc[svc] {
			rep.count("operations", 1)
			delay, delayLoss := wmDelay(m.latencyOf(op))
			if delayLoss != "" {
				rep.lose("latency-distribution", "op:"+svc+" "+op.Key, delayLoss, 1)
			} else if m.latencyOf(op) == nil {
				rep.lose("latency-distribution", "op:"+svc+" "+op.Key, "no latency profile in faults.json or contract: answers are immediate", 1)
			}
			if def, resp, ok := op.defaultExample(); ok {
				add(wmPrioDefault, fmt.Sprintf("%s | default %s", op.Key, def.Name),
					map[string]any{
						"request":  wmRequest(op, nil, nil),
						"response": wmResponse(resp.Status, resp.Media, def.Value, true, delay),
						"metadata": wmMeta(m, map[string]any{"example": def.Name, "kind": "contract-default"}),
					})
				rep.exported("stub", "op:"+svc+" "+op.Key, 1)
			} else {
				rep.lose("no-example", "op:"+svc+" "+op.Key, "the success response has no named example: no default stub", 1)
			}
			for _, r := range op.Responses {
				for _, ex := range r.Examples {
					add(wmPrioExample, fmt.Sprintf("%s | example %s", op.Key, ex.Name),
						map[string]any{
							"request":  wmRequest(op, nil, map[string]any{opts.ExampleHeader: map[string]any{"equalTo": ex.Name}}),
							"response": wmResponse(r.Status, r.Media, ex.Value, true, delay),
							"metadata": wmMeta(m, map[string]any{"example": ex.Name, "kind": "contract-example", "status": r.Status}),
						})
					rep.exported("example", "op:"+svc+" "+op.Key, 1)
				}
			}

			// 2. Faults observed for this operation.
			if f, ok := m.faults[svc+"|"+op.Key]; ok {
				wmFaults(m, rep, add, op, f, opts)
			}
		}

		// 3. Entity lookups: scenarios and static snapshots.
		scenarios := map[string]bool{}
		timeLoss := map[string]int{}
		type variant struct {
			hdr  map[string]any
			prio int
			tag  string
		}
		for _, l := range m.lookups[svc] {
			delay, _ := wmDelay(m.latencyOf(l.Op))
			scoped := l.Owner != "" && l.Foreign != nil
			base := wmPrioScenario
			if !l.stateful() {
				base = wmPrioStatic
			}
			variants := []variant{{nil, base, ""}}
			if scoped {
				variants = []variant{
					{map[string]any{opts.CustomerHeader: map[string]any{"equalTo": l.Owner}}, base, " [owner]"},
					{nil, wmPrioNoHeader, " [no customer]"},
				}
				fv := l.Foreign
				add(wmPrioForeign, fmt.Sprintf("%s | %s", l.Op.Key, fv.Name), map[string]any{
					"request":  wmRequest(l.Op, l, map[string]any{opts.CustomerHeader: map[string]any{"matches": ".+"}}),
					"response": wmResponse(fv.Status, fv.Media, fv.Body, true, delay),
					"metadata": wmMeta(m, map[string]any{"kind": "foreign", "entity": l.Entity, "owner": l.Owner}),
				})
				rep.exported("foreign-stub", "entity:"+l.Entity, 1)
				cust[l.Owner] = true
			}
			for _, vr := range variants {
				if !l.stateful() {
					v := l.Views[0]
					add(vr.prio, fmt.Sprintf("%s | %s%s", l.Op.Key, v.Name, vr.tag), map[string]any{
						"request":  wmRequest(l.Op, l, vr.hdr),
						"response": wmResponse(v.Status, v.Media, v.Body, true, delay),
						"metadata": wmMeta(m, map[string]any{"kind": "entity-snapshot", "entity": l.Entity, "rule": l.RuleID, "outcome": l.Outcome}),
					})
					rep.exported("stub", "entity:"+l.Entity, 1)
					continue
				}
				for i, v := range l.Views {
					st := map[string]any{
						"request":               wmRequest(l.Op, l, vr.hdr),
						"response":              wmResponse(v.Status, v.Media, v.Body, true, delay),
						"scenarioName":          l.Scenario,
						"requiredScenarioState": v.State,
					}
					if l.Advance && opts.Advance != "manual" && i < len(l.Views)-1 {
						st["newScenarioState"] = l.Views[i+1].State
					}
					meta := map[string]any{"kind": "scenario-step", "entity": l.Entity, "rule": l.RuleID, "outcome": l.Outcome, "step": i}
					if v.HasAfter {
						meta["effect"] = v.Effect
						meta["after"] = v.After.Value()
						meta["projected"] = v.Projected
					}
					st["metadata"] = wmMeta(m, meta)
					add(vr.prio, fmt.Sprintf("%s | %s%s", l.Op.Key, v.Name, vr.tag), st)
					rep.exported("scenario-step", "rule:"+l.RuleID, 1)
				}
			}
			if l.stateful() {
				scenarios[l.Scenario] = true
				timeLoss[l.RuleID]++
			}
		}
		rep.count("scenarios", len(scenarios))
		for _, rid := range sortedKeys(timeLoss) {
			adv := "each read of the first exposing operation advances the scenario by one step"
			if opts.Advance == "manual" {
				adv = "states change only through PUT /__admin/scenarios/{name}/state"
			}
			rep.lose("time", "rule:"+rid, fmt.Sprintf("figurative delays (after: %s) and the virtual clock are not honoured: %s", m.delayInfo(rid), adv), timeLoss[rid])
			rep.lose("state", "rule:"+rid, "scenario state is global per WireMock instance and per subject; creation of new entities by the cause operation and immediate effects on its response are not replayed (POST answers with contract examples)", timeLoss[rid])
		}

		sort.SliceStable(stubs, func(i, j int) bool {
			if stubs[i].prio != stubs[j].prio {
				return stubs[i].prio < stubs[j].prio
			}
			return stubs[i].name < stubs[j].name
		})
		list := make([]any, len(stubs))
		for i, s := range stubs {
			list[i] = s.body
		}
		rep.count("stubs", len(stubs))
		files = append(files, outFile{
			Path: "wiremock/" + svc + "/mappings/" + svc + ".json",
			Data: marshalJSON(map[string]any{"mappings": list}),
		})
	}
	rep.count("files", len(files))
	rep.count("rules_approved", m.stats.ApprovedRules)
	m.reportCommon(rep)
	rep.setPresets(m.presetReports(TargetWireMock, presetOpts{faultHeader: opts.FaultHeader, customerHeader: opts.CustomerHeader, scoped: cust}))
	return files, rep.build(files)
}

func wmMeta(m *model, extra map[string]any) map[string]any {
	t := map[string]any{"pack_id": m.in.Manifest.PackID}
	for k, v := range extra {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		t[k] = v
	}
	return map[string]any{"tt": t}
}

func wmRequest(op *operation, l *lookup, headers map[string]any) map[string]any {
	req := map[string]any{"method": op.Method}
	if op.hasTemplate() {
		req["urlPathTemplate"] = op.Path
	} else {
		req["urlPath"] = op.Path
	}
	if l != nil {
		switch l.Kind {
		case "query":
			req["queryParameters"] = map[string]any{l.Param: map[string]any{"equalTo": l.Key}}
		case "path":
			if op.hasTemplate() {
				req["pathParameters"] = map[string]any{l.Param: map[string]any{"equalTo": l.Key}}
			}
		}
	}
	if headers != nil {
		req["headers"] = headers
	}
	return req
}

// wmDelay maps a latency profile to documented response fields and says what
// was lost doing so.
func wmDelay(l *Latency) (map[string]any, string) {
	med, sigma, derived, ok := lognormalOf(l)
	if !ok {
		return nil, ""
	}
	if sigma == 0 {
		return map[string]any{"fixedDelayMilliseconds": int(med)}, "only the median is known: fixed delay instead of a distribution"
	}
	d := map[string]any{"type": "lognormal", "median": med, "sigma": sigma}
	if derived {
		return map[string]any{"delayDistribution": d}, "sigma derived from p50/p95 assuming a log-normal shape"
	}
	return map[string]any{"delayDistribution": d}, ""
}

func isJSONMedia(m string) bool {
	m = strings.ToLower(m)
	return m == "" || strings.HasPrefix(m, "application/json") || strings.HasSuffix(m, "+json")
}

func wmResponse(status int, media string, body any, hasBody bool, delay map[string]any) map[string]any {
	r := map[string]any{"status": status}
	if hasBody && body != nil {
		if isJSONMedia(media) {
			r["jsonBody"] = body
			r["headers"] = map[string]any{"Content-Type": orJSON(media)}
		} else if s, ok := body.(string); ok {
			r["body"] = s
			r["headers"] = map[string]any{"Content-Type": media}
		} else {
			r["jsonBody"] = body
		}
	}
	for k, v := range delay {
		r[k] = v
	}
	return r
}

func wmFaults(m *model, rep *reportBuilder, add func(int, string, map[string]any), op *operation, f FaultOps, opts WireMockOptions) {
	el := "op:" + op.Service + " " + op.Key
	for _, fs := range f.Statuses {
		var body any
		media := "application/json"
		pat := fmt.Sprintf("%d", fs.Status)
		if fs.Example != "" {
			pat += "|" + regexp.QuoteMeta(fs.Example)
			if _, ex, mt, ok := op.findExample(fs.Example); ok {
				body, media = deepCopy(ex.Value), mt
			}
		}
		if body == nil {
			if r := op.response(fs.Status); r != nil && len(r.Examples) > 0 {
				body, media = deepCopy(r.Examples[0].Value), r.Media
			}
		}
		add(wmPrioFault, fmt.Sprintf("%s | fault %d", op.Key, fs.Status), map[string]any{
			"request":  wmRequest(op, nil, map[string]any{opts.FaultHeader: map[string]any{"matches": "^(" + pat + ")$"}}),
			"response": wmResponse(fs.Status, media, body, body != nil, nil),
			"metadata": wmMeta(m, map[string]any{"kind": "fault", "status": fs.Status, "observed_p": fs.P, "example": fs.Example}),
		})
		rep.exported("fault-stub", el, 1)
		rep.lose("probabilistic-fault", el, fmt.Sprintf("status %d observed with p=%v: WireMock has no probabilistic selection, the stub answers only when the request carries %s: %d", fs.Status, fs.P, opts.FaultHeader, fs.Status), 1)
	}
	// Network faults follow the normative table of mock.md section 4.
	latency, _ := wmDelay(m.latencyOf(op))
	for _, ne := range f.NetErrors {
		resp := map[string]any{}
		withLatency := false
		approx := ""
		switch ne.Kind {
		case "timeout":
			resp["fault"] = "EMPTY_RESPONSE"
			resp["fixedDelayMilliseconds"] = wmTimeoutDelayMS
		case "reset":
			resp["fault"] = "CONNECTION_RESET_BY_PEER"
			withLatency = true
		case "refused", "dns":
			resp["fault"] = "CONNECTION_RESET_BY_PEER"
			approx = fmt.Sprintf("%s is approximated by a connection reset (the client cannot tell it from a reset); the mock already accepted the connection", ne.Kind)
		case "tls":
			resp["fault"] = "RANDOM_DATA_THEN_CLOSE"
			approx = "tls is approximated by garbage data followed by a close (WireMock cannot send a TLS alert)"
		case "other":
			resp["fault"] = "EMPTY_RESPONSE"
			withLatency = true
		default:
			rep.lose("probabilistic-fault", el, fmt.Sprintf("network error %q (p=%v) has no WireMock fault equivalent: not exported", ne.Kind, ne.P), 1)
			continue
		}
		if withLatency {
			for k, v := range latency {
				resp[k] = v
			}
		}
		add(wmPrioFault, fmt.Sprintf("%s | net %s", op.Key, ne.Kind), map[string]any{
			"request":  wmRequest(op, nil, map[string]any{opts.FaultHeader: map[string]any{"equalTo": ne.Kind}}),
			"response": resp,
			"metadata": wmMeta(m, map[string]any{"kind": "net-error", "net_kind": ne.Kind, "observed_p": ne.P}),
		})
		rep.exported("fault-stub", el, 1)
		rep.lose("probabilistic-fault", el, fmt.Sprintf("network error %q observed with p=%v: stub answers only when the request carries %s: %s", ne.Kind, ne.P, opts.FaultHeader, ne.Kind), 1)
		if approx != "" {
			rep.lose("approximation", el, approx, 1)
		}
	}
}
