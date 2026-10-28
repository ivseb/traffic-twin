package miner

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// The catalog is what a person may name in a rule written by hand: the
// services and operations of the contracts with their statuses, examples,
// parameters and body fields, and the entities with their fields and the
// values those fields take (the "states": the published keep values of the
// contracts, never anything else). It is built from the pack-safe OpenAPI
// documents of the contracts, so a rule that passes it also loads in the
// mock.

// ContractDoc is the OpenAPI 3.1 document of one service.
type ContractDoc struct {
	Service string
	Doc     []byte
}

// ContractSource gives the contracts of the selected groups (nil: every
// group). tt-core implements it with the live contracts.
type ContractSource interface {
	ContractDocs(ctx context.Context, groups []string) ([]ContractDoc, error)
}

// Catalog lists what a manual rule may name.
type Catalog struct {
	Services []CatalogService `json:"services"`
	Entities []CatalogEntity  `json:"entities"`
}

// CatalogService is one service of the contracts.
type CatalogService struct {
	Name string      `json:"name"`
	Ops  []CatalogOp `json:"ops"`
}

// CatalogOp is one operation: statuses observed, example names per status,
// request parameters and body fields, success response fields.
type CatalogOp struct {
	Op       string              `json:"op"`
	Statuses []int               `json:"statuses"`
	Examples map[string][]string `json:"examples,omitempty"`
	Params   []CatalogField      `json:"params,omitempty"`
	Request  []CatalogField      `json:"request,omitempty"`
	Response []CatalogField      `json:"response,omitempty"`
}

// CatalogField is a field: a parameter ({from, name}) or a body field (a
// tt-path), with what the contract says of its values.
type CatalogField struct {
	From   string   `json:"from"`
	Name   string   `json:"name,omitempty"`
	Path   string   `json:"path,omitempty"`
	Type   string   `json:"type,omitempty"`
	Kind   string   `json:"kind,omitempty"`
	Domain string   `json:"domain,omitempty"`
	Values []string `json:"values,omitempty"`
}

// CatalogEntity is an entity of the latest mining run with the fields its
// reads expose (dotted names, as in set/create).
type CatalogEntity struct {
	Name     string         `json:"name"`
	Service  string         `json:"service"`
	IDField  string         `json:"id_field"`
	IDDomain string         `json:"id_domain"`
	Ops      []string       `json:"ops"`
	Fields   []CatalogField `json:"fields"`
}

// Service returns the service with the given name.
func (c *Catalog) Service(name string) *CatalogService {
	for i := range c.Services {
		if c.Services[i].Name == name {
			return &c.Services[i]
		}
	}
	return nil
}

// Op returns the operation with the given key.
func (s *CatalogService) Op(key string) *CatalogOp {
	if s == nil {
		return nil
	}
	for i := range s.Ops {
		if s.Ops[i].Op == key {
			return &s.Ops[i]
		}
	}
	return nil
}

// Entity returns the entity with the given name.
func (c *Catalog) Entity(name string) *CatalogEntity {
	for i := range c.Entities {
		if c.Entities[i].Name == name {
			return &c.Entities[i]
		}
	}
	return nil
}

const (
	maxCatalogFields = 200
	maxCatalogDepth  = 5
)

type oaDoc struct{ doc map[string]any }

func (o oaDoc) resolve(s map[string]any) map[string]any {
	for i := 0; i < 16 && s != nil; i++ {
		ref, ok := s["$ref"].(string)
		if !ok {
			return s
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil
		}
		var cur any = o.doc
		for _, part := range strings.Split(ref[2:], "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			m, _ := cur.(map[string]any)
			cur = m[part]
		}
		s, _ = cur.(map[string]any)
	}
	return s
}

func jsonContent(content any) map[string]any {
	c, _ := content.(map[string]any)
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(k, "json") {
			m, _ := c[k].(map[string]any)
			return m
		}
	}
	return nil
}

func lexOf(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

// describe fills the type, kind, domain and published values of a field.
func (o oaDoc) describe(f *CatalogField, s map[string]any) {
	s = o.resolve(s)
	if s == nil {
		return
	}
	switch t := s["type"].(type) {
	case string:
		f.Type = t
	case []any:
		for _, x := range t {
			if v, ok := x.(string); ok && v != "null" {
				f.Type = v
				break
			}
		}
	}
	vals, _ := s["enum"].([]any)
	if xv, ok := s["x-tt-value"].(map[string]any); ok {
		f.Kind, _ = xv["kind"].(string)
		f.Domain, _ = xv["domain"].(string)
		if len(vals) == 0 {
			vals, _ = xv["enum"].([]any)
		}
	}
	for _, v := range vals {
		if l, ok := lexOf(v); ok {
			f.Values = append(f.Values, l)
		}
	}
	if len(f.Values) > 0 && f.Kind == "" {
		f.Kind = "enum"
	}
}

// fields flattens a body schema into tt-paths ("$.status",
// "$.items[*].sku").
func (o oaDoc) fields(s map[string]any, path string, depth int, out *[]CatalogField, from string) {
	s = o.resolve(s)
	if s == nil || depth > maxCatalogDepth || len(*out) >= maxCatalogFields {
		return
	}
	if it, ok := s["items"].(map[string]any); ok {
		o.fields(it, path+"[*]", depth+1, out, from)
		return
	}
	props, _ := s["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !reFieldName.MatchString(n) || len(*out) >= maxCatalogFields {
			continue
		}
		ps, _ := props[n].(map[string]any)
		f := CatalogField{From: from, Path: path + "." + n}
		o.describe(&f, ps)
		*out = append(*out, f)
		o.fields(ps, f.Path, depth+1, out, from)
	}
}

var methods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

// catalogService describes one contract.
func catalogService(service string, raw []byte) (CatalogService, bool) {
	var d map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&d) != nil {
		return CatalogService{}, false
	}
	o := oaDoc{doc: d}
	cs := CatalogService{Name: service, Ops: []CatalogOp{}}
	paths, _ := d["paths"].(map[string]any)
	for p, it := range paths {
		item, _ := it.(map[string]any)
		for _, m := range methods {
			om, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			op := CatalogOp{Op: strings.ToUpper(m) + " " + p, Statuses: []int{}, Examples: map[string][]string{}}
			params, _ := om["parameters"].([]any)
			for _, x := range params {
				pm := o.resolve(asMap(x))
				name, _ := pm["name"].(string)
				in, _ := pm["in"].(string)
				from := map[string]string{"path": "req.path", "query": "req.query", "header": "req.headers", "cookie": "req.cookies"}[in]
				if name == "" || from == "" {
					continue
				}
				f := CatalogField{From: from, Name: name}
				o.describe(&f, asMap(pm["schema"]))
				op.Params = append(op.Params, f)
			}
			if rb := o.resolve(asMap(om["requestBody"])); rb != nil {
				if mt := jsonContent(rb["content"]); mt != nil {
					o.fields(asMap(mt["schema"]), "$", 0, &op.Request, "req.body")
				}
			}
			resps, _ := om["responses"].(map[string]any)
			seen := map[string]bool{}
			for code, r := range resps {
				n, err := strconv.Atoi(code)
				if err != nil {
					continue
				}
				op.Statuses = append(op.Statuses, n)
				rm := o.resolve(asMap(r))
				mt := jsonContent(rm["content"])
				if exs, ok := mt["examples"].(map[string]any); ok {
					for name := range exs {
						op.Examples[code] = append(op.Examples[code], name)
					}
					sort.Strings(op.Examples[code])
				}
				if n >= 200 && n < 300 && mt != nil {
					var fs []CatalogField
					o.fields(asMap(mt["schema"]), "$", 0, &fs, "resp.body")
					for _, f := range fs {
						if !seen[f.Path] {
							seen[f.Path] = true
							op.Response = append(op.Response, f)
						}
					}
				}
			}
			sort.Ints(op.Statuses)
			if len(op.Examples) == 0 {
				op.Examples = nil
			}
			cs.Ops = append(cs.Ops, op)
		}
	}
	sort.Slice(cs.Ops, func(i, j int) bool { return cs.Ops[i].Op < cs.Ops[j].Op })
	return cs, true
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// BuildCatalog builds the catalog from contract documents and the entities
// of the latest mining run.
func BuildCatalog(docs []ContractDoc, ents []Entity) *Catalog {
	cat := &Catalog{Services: []CatalogService{}, Entities: []CatalogEntity{}}
	byName := map[string]int{}
	for _, d := range docs {
		cs, ok := catalogService(d.Service, d.Doc)
		if !ok {
			continue
		}
		if i, dup := byName[d.Service]; dup {
			// The same service seen by two groups: union of the operations.
			have := map[string]bool{}
			for _, op := range cat.Services[i].Ops {
				have[op.Op] = true
			}
			for _, op := range cs.Ops {
				if !have[op.Op] {
					cat.Services[i].Ops = append(cat.Services[i].Ops, op)
				}
			}
			sort.Slice(cat.Services[i].Ops, func(a, b int) bool { return cat.Services[i].Ops[a].Op < cat.Services[i].Ops[b].Op })
			continue
		}
		byName[d.Service] = len(cat.Services)
		cat.Services = append(cat.Services, cs)
	}
	sort.Slice(cat.Services, func(i, j int) bool { return cat.Services[i].Name < cat.Services[j].Name })
	for _, e := range ents {
		ce := CatalogEntity{Name: e.Name, Service: e.Service, IDField: e.IDField, IDDomain: e.IDDomain, Ops: []string{}, Fields: []CatalogField{}}
		fields := map[string]*CatalogField{}
		add := func(svc, op, at string) {
			cop := cat.Service(svc).Op(op)
			if cop == nil {
				return
			}
			ce.Ops = append(ce.Ops, op)
			for _, f := range cop.Response {
				rest, ok := strings.CutPrefix(f.Path, at+".")
				if !ok || strings.Contains(rest, "[") {
					continue
				}
				if cur := fields[rest]; cur != nil {
					cur.Values = unionStrings(cur.Values, f.Values)
					continue
				}
				nf := f
				nf.From, nf.Path, nf.Name = "", "", rest
				nf.Values = append([]string(nil), f.Values...)
				fields[rest] = &nf
			}
		}
		if e.CreatedBy != nil {
			add(e.Service, e.CreatedBy.Op, "$")
		}
		for _, rb := range e.ReadBy {
			svc := e.Service
			if rb.Service != "" {
				svc = rb.Service
			}
			add(svc, rb.Op, rb.At.Path)
		}
		for _, n := range sortedKeys(fields) {
			ce.Fields = append(ce.Fields, *fields[n])
		}
		cat.Entities = append(cat.Entities, ce)
	}
	return cat
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, v := range l {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}
