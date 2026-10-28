package export

import (
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Contract operations

type param struct {
	Name     string
	In       string
	Required bool
}

type example struct {
	Name  string
	Value any
}

type response struct {
	Status   int
	Media    string
	Examples []example // sorted by name
	Schema   map[string]any
}

type operation struct {
	Service     string
	Key         string // "GET /v1/shipments"
	Method      string // upper case
	Path        string // "/v1/shipments/{shipmentId}"
	OperationID string
	Params      []param
	Responses   []response // sorted by status
	ReqMedia    string
	ReqExamples []example
	Doc         map[string]any // contract root, for $ref resolution
	Latency     *Latency       // from x-tt-latency-ms
}

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch"}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func mediaExamples(media map[string]any) []example {
	var out []example
	if ex := asMap(media["examples"]); ex != nil {
		for _, n := range sortedKeys(ex) {
			if e := asMap(ex[n]); e != nil {
				if v, ok := e["value"]; ok {
					out = append(out, example{n, v})
				}
			}
		}
	} else if v, ok := media["example"]; ok {
		out = append(out, example{"default", v})
	}
	return out
}

func firstMedia(content map[string]any) (string, map[string]any) {
	if content == nil {
		return "", nil
	}
	if m := asMap(content["application/json"]); m != nil {
		return "application/json", m
	}
	for _, k := range sortedKeys(content) {
		return k, asMap(content[k])
	}
	return "", nil
}

// indexOps lists the operations of one contract in a stable order.
func indexOps(svc Service) []*operation {
	var ops []*operation
	paths := asMap(svc.Contract["paths"])
	for _, p := range sortedKeys(paths) {
		item := asMap(paths[p])
		var common []param
		for _, raw := range asSlice(item["parameters"]) {
			common = append(common, parseParam(asMap(raw)))
		}
		for _, m := range httpMethods {
			o := asMap(item[m])
			if o == nil {
				continue
			}
			op := &operation{Service: svc.Name, Method: strings.ToUpper(m), Path: p, Doc: svc.Contract}
			op.Key = op.Method + " " + p
			op.OperationID, _ = o["operationId"].(string)
			op.Params = append(op.Params, common...)
			for _, raw := range asSlice(o["parameters"]) {
				op.Params = append(op.Params, parseParam(asMap(raw)))
			}
			if rb := asMap(o["requestBody"]); rb != nil {
				op.ReqMedia, _ = firstMedia(asMap(rb["content"]))
				_, mm := firstMedia(asMap(rb["content"]))
				op.ReqExamples = mediaExamples(mm)
			}
			for _, code := range sortedKeys(asMap(o["responses"])) {
				st, err := strconv.Atoi(code)
				if err != nil {
					continue // "default" or ranges are not exported
				}
				r := response{Status: st}
				mt, mm := firstMedia(asMap(asMap(asMap(o["responses"])[code])["content"]))
				r.Media = mt
				r.Examples = mediaExamples(mm)
				r.Schema = asMap(mm["schema"])
				op.Responses = append(op.Responses, r)
			}
			sort.Slice(op.Responses, func(i, j int) bool { return op.Responses[i].Status < op.Responses[j].Status })
			if lm := asMap(o["x-tt-latency-ms"]); lm != nil {
				l := &Latency{}
				l.P50 = intOf(lm["p50"])
				l.P95 = intOf(lm["p95"])
				l.P99 = intOf(lm["p99"])
				op.Latency = l
			}
			ops = append(ops, op)
		}
	}
	return ops
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

func intOf(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case interface{ Int64() (int64, error) }:
		i, _ := t.Int64()
		return int(i)
	}
	return 0
}

func parseParam(m map[string]any) param {
	p := param{}
	p.Name, _ = m["name"].(string)
	p.In, _ = m["in"].(string)
	p.Required, _ = m["required"].(bool)
	if p.In == "path" {
		p.Required = true
	}
	return p
}

// successResponse is the lowest 2xx response (or the lowest one).
func (o *operation) successResponse() *response {
	for i := range o.Responses {
		if o.Responses[i].Status >= 200 && o.Responses[i].Status < 300 {
			return &o.Responses[i]
		}
	}
	if len(o.Responses) > 0 {
		return &o.Responses[0]
	}
	return nil
}

func (o *operation) response(status int) *response {
	for i := range o.Responses {
		if o.Responses[i].Status == status {
			return &o.Responses[i]
		}
	}
	return nil
}

// findExample looks an example up by name across all responses.
func (o *operation) findExample(name string) (status int, ex example, media string, ok bool) {
	for _, r := range o.Responses {
		for _, e := range r.Examples {
			if e.Name == name {
				return r.Status, e, r.Media, true
			}
		}
	}
	return 0, example{}, "", false
}

// defaultExample is the first example (by name) of the success response.
func (o *operation) defaultExample() (example, *response, bool) {
	r := o.successResponse()
	if r == nil || len(r.Examples) == 0 {
		return example{}, nil, false
	}
	return r.Examples[0], r, true
}

func (o *operation) hasTemplate() bool { return strings.Contains(o.Path, "{") }

func (o *operation) paramsIn(in string) []param {
	var out []param
	for _, p := range o.Params {
		if p.In == in {
			out = append(out, p)
		}
	}
	return out
}

// resolve follows local $ref pointers ("#/components/schemas/X").
func (o *operation) resolve(sch map[string]any) map[string]any {
	for i := 0; i < 8 && sch != nil; i++ {
		ref, ok := sch["$ref"].(string)
		if !ok || !strings.HasPrefix(ref, "#/") {
			return sch
		}
		var cur any = o.Doc
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			cur = asMap(cur)[part]
		}
		sch = asMap(cur)
	}
	return sch
}

// hasProp reports whether the success response schema declares a top-level
// property.
func (o *operation) hasProp(name string) bool {
	r := o.successResponse()
	if r == nil {
		return false
	}
	_, ok := asMap(o.resolve(r.Schema)["properties"])[name]
	return ok
}
