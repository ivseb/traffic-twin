package mock

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// param is a declared operation parameter.
type param struct {
	name     string
	in       string // path | query | header
	required bool
	schema   any
}

// response is a declared response of an operation.
type response struct {
	status  int
	node    map[string]any
	schema  any // nil when no JSON content is declared
	media   map[string]any
	freq    float64
	headers map[string]any
	// doc is a document response (application/pdf, image/png, ...):
	// the mock answers with a valid synthetic file (docs/spec/mock.md 2.9).
	doc *docMedia
	// xml is an XML or SOAP body (x-tt-xml, docs/spec/mock.md 10): schema
	// and media hold its tree form, the answer is written as XML.
	xml *xmlSpec
}

// operation is a compiled contract operation.
type operation struct {
	service string
	key     string // "GET /v1/shipments"
	method  string
	tmpl    string
	segs    []string // template segments; params as "{name}"
	literal int      // number of literal segments (specificity)
	node    map[string]any

	params      []param
	bodySchema  any
	bodyReq     bool
	hasBody     bool
	responses   map[int]*response
	statuses    []int // sorted
	entityHint  string
	successCode int
	// reqXML is the envelope of an XML request body (docs/spec/mock.md 10).
	reqXML *xmlSpec
}

// contract is a compiled service contract.
type contract struct {
	service string
	sc      *schemaCtx
	ops     []*operation
	byKey   map[string]*operation
}

func compileContract(service string, doc map[string]any) (*contract, error) {
	c := &contract{service: service, sc: &schemaCtx{doc: doc, docs: hasDocSchema(doc, 0)}, byKey: map[string]*operation{}}
	paths, _ := doc["paths"].(map[string]any)
	for _, tmpl := range sortedKeys(paths) {
		if !strings.HasPrefix(tmpl, "/") {
			return nil, fmt.Errorf("path %q must start with /", tmpl)
		}
		item := c.sc.resolve(paths[tmpl])
		if item == nil {
			continue
		}
		shared := c.params(item["parameters"])
		for _, m := range httpMethods {
			node := c.sc.resolve(item[m])
			if node == nil {
				continue
			}
			op := &operation{service: service, method: strings.ToUpper(m), tmpl: tmpl, node: node}
			op.key = op.method + " " + tmpl
			op.segs = strings.Split(tmpl[1:], "/")
			if tmpl == "/" {
				op.segs = []string{""}
			}
			for _, s := range op.segs {
				if !isParamSeg(s) {
					op.literal++
				}
			}
			op.params = mergeParams(shared, c.params(node["parameters"]))
			if rb := c.sc.resolve(node["requestBody"]); rb != nil {
				op.hasBody = true
				op.bodyReq, _ = rb["required"].(bool)
				if media := jsonMedia(c.sc, rb["content"]); media != nil {
					op.bodySchema = media["schema"]
				} else if media, xs := xmlMedia(c.sc, rb["content"]); media != nil {
					op.bodySchema, op.reqXML = media["schema"], xs
				}
			}
			op.responses = map[int]*response{}
			rs, _ := node["responses"].(map[string]any)
			for code, rn := range rs {
				st, err := strconv.Atoi(code)
				if err != nil {
					continue // "default" and ranges are not served
				}
				node := c.sc.resolve(rn)
				if node == nil {
					continue
				}
				r := &response{status: st, node: node}
				r.freq, _ = numFloat(node["x-tt-frequency"])
				r.headers, _ = node["headers"].(map[string]any)
				if media := jsonMedia(c.sc, node["content"]); media != nil {
					r.media = media
					r.schema = media["schema"]
				} else if media, xs := xmlMedia(c.sc, node["content"]); media != nil {
					r.media, r.schema, r.xml = media, media["schema"], xs
				} else {
					r.doc = documentMedia(c.sc, node["content"])
				}
				op.responses[st] = r
				op.statuses = append(op.statuses, st)
			}
			sort.Ints(op.statuses)
			op.entityHint, _ = node["x-tt-entity"].(string)
			op.successCode = op.pickSuccess()
			c.ops = append(c.ops, op)
			c.byKey[op.key] = op
		}
	}
	return c, nil
}

func isParamSeg(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && len(s) > 2
}

func (c *contract) params(n any) []param {
	list, _ := n.([]any)
	var out []param
	for _, e := range list {
		p := c.sc.resolve(e)
		if p == nil {
			continue
		}
		name, _ := p["name"].(string)
		in, _ := p["in"].(string)
		if name == "" || (in != "path" && in != "query" && in != "header" && in != "cookie") {
			continue
		}
		req, _ := p["required"].(bool)
		if in == "path" {
			req = true
		}
		out = append(out, param{name: name, in: in, required: req, schema: p["schema"]})
	}
	return out
}

// mergeParams lets operation parameters override path-level ones.
func mergeParams(shared, own []param) []param {
	out := append([]param(nil), own...)
outer:
	for _, s := range shared {
		for _, o := range own {
			if o.name == s.name && o.in == s.in {
				continue outer
			}
		}
		out = append(out, s)
	}
	return out
}

// jsonMedia picks the JSON media type object of a content map.
func jsonMedia(sc *schemaCtx, content any) map[string]any {
	cm, _ := content.(map[string]any)
	if cm == nil {
		return nil
	}
	for _, k := range sortedKeys(cm) {
		mt := strings.ToLower(strings.TrimSpace(strings.SplitN(k, ";", 2)[0]))
		if mt == "application/json" || strings.HasSuffix(mt, "+json") {
			return sc.resolve(cm[k])
		}
	}
	return nil
}

// pickSuccess chooses the 2xx status the mock answers with: the most frequent
// one (x-tt-frequency), then the lowest.
func (o *operation) pickSuccess() int {
	best, bestF := 0, -1.0
	for _, st := range o.statuses {
		if st < 200 || st > 299 {
			continue
		}
		if f := o.responses[st].freq; f > bestF {
			best, bestF = st, f
		}
	}
	if best != 0 {
		return best
	}
	if len(o.statuses) > 0 {
		return o.statuses[0]
	}
	return 200
}

// exampleBody returns a named example of a response ("" = first by name, or
// the media-level example).
func (r *response) exampleBody(name string) (any, bool) {
	if r == nil || r.media == nil {
		return nil, false
	}
	if exs, ok := r.media["examples"].(map[string]any); ok && len(exs) > 0 {
		if name != "" {
			if e, ok := exs[name].(map[string]any); ok {
				if v, ok := e["value"]; ok {
					return v, true
				}
			}
		}
		if name == "" {
			if v, ok := r.media["example"]; ok {
				return v, true
			}
			for _, k := range sortedKeys(exs) {
				if e, ok := exs[k].(map[string]any); ok {
					if v, ok := e["value"]; ok {
						return v, true
					}
				}
			}
		}
	}
	if v, ok := r.media["example"]; ok {
		return v, true
	}
	return nil, false
}

// hasExample reports whether the response has a named example.
func (r *response) hasExample(name string) bool {
	if r == nil || r.media == nil {
		return false
	}
	exs, _ := r.media["examples"].(map[string]any)
	_, ok := exs[name]
	return ok
}

// ---- path matching ----

// match finds the best operation for a method and an escaped path. When the
// path exists with other methods only, allowed lists them and op is nil.
func (c *contract) match(method, escPath string) (op *operation, params map[string]string, allowed []string) {
	segs := strings.Split(strings.TrimPrefix(escPath, "/"), "/")
	if escPath == "/" {
		segs = []string{""}
	}
	var best *operation
	var bestParams map[string]string
	for _, o := range c.ops {
		p, ok := matchSegs(o.segs, segs)
		if !ok {
			continue
		}
		if o.method != method {
			allowed = append(allowed, o.method)
			continue
		}
		if best == nil || o.literal > best.literal || (o.literal == best.literal && o.tmpl < best.tmpl) {
			best, bestParams = o, p
		}
	}
	if best != nil {
		return best, bestParams, nil
	}
	sort.Strings(allowed)
	return nil, nil, dedupe(allowed)
}

func matchSegs(tmpl, segs []string) (map[string]string, bool) {
	if len(tmpl) != len(segs) {
		return nil, false
	}
	var params map[string]string
	for i, t := range tmpl {
		if isParamSeg(t) {
			v, err := url.PathUnescape(segs[i])
			if err != nil || v == "" {
				return nil, false
			}
			if params == nil {
				params = map[string]string{}
			}
			params[t[1:len(t)-1]] = v
			continue
		}
		if t != segs[i] {
			return nil, false
		}
	}
	return params, true
}

func dedupe(s []string) []string {
	var out []string
	for i, e := range s {
		if i == 0 || e != s[i-1] {
			out = append(out, e)
		}
	}
	return out
}

// nearest returns the key of the operation closest to the request, for the
// unmatched journal.
func (c *contract) nearest(method, escPath string) string {
	segs := strings.Split(strings.TrimPrefix(escPath, "/"), "/")
	bestKey, bestScore := "", -1000
	for _, o := range c.ops {
		score := 0
		if o.method == method {
			score++
		}
		n := len(segs)
		if len(o.segs) < n {
			n = len(o.segs)
		}
		for i := 0; i < n; i++ {
			switch {
			case o.segs[i] == segs[i]:
				score += 4
			case isParamSeg(o.segs[i]):
				score++
			default:
				score += int(3 * similarity(o.segs[i], segs[i]))
			}
		}
		d := len(segs) - len(o.segs)
		if d < 0 {
			d = -d
		}
		score -= 3 * d
		if score > bestScore || (score == bestScore && o.key < bestKey) {
			bestKey, bestScore = o.key, score
		}
	}
	return bestKey
}

// similarity is 1 - levenshtein/maxlen, in [0, 1].
func similarity(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	longest := max(len(ra), len(rb))
	return 1 - float64(prev[len(rb)])/float64(longest)
}
