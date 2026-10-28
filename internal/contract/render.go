package contract

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivseb/traffic-twin/internal/dateoff"
	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

// num is a JSON number lexeme in a rendered document.
type num string

// RenderOptions tune OpenAPI rendering.
type RenderOptions struct {
	// PackSafe renders only what the publication gate can accept: operations
	// with fewer than KMin calls are left out and so are the responses with
	// fewer than KMin calls (docs/spec/pack.md section 7, k-thresholds).
	PackSafe bool
	// IncludeRaw renders operations without a route template.
	IncludeRaw bool
	// NoExamples leaves the examples out.
	NoExamples bool
	// Hints gives x-tt-entity; may be nil.
	Hints Hints
}

var openAPIMethods = map[string]bool{
	"GET": true, "PUT": true, "POST": true, "DELETE": true, "OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": true,
}

// OpenAPI renders the contract as an OpenAPI 3.1 document (a tree of maps,
// slices, strings, bools, int64 and float64 values ready for
// [CanonicalJSON] or [YAML]).
func (c *Contract) OpenAPI(o RenderOptions) map[string]any {
	paths := map[string]any{}
	used := map[string]int{}
	for _, op := range c.Ops {
		if !openAPIMethods[op.Method] {
			continue
		}
		if op.RouteSource == "raw" && !o.IncludeRaw {
			continue
		}
		if o.PackSafe && op.Calls < int64(c.KMin) {
			continue
		}
		path := op.Path
		if op.RouteSource == "raw" {
			path = rawPath(path)
		}
		item, _ := paths[path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[path] = item
		}
		method := strings.ToLower(op.Method)
		if _, dup := item[method]; dup {
			continue
		}
		item[method] = c.renderOp(op, path, o, used)
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": c.Service, "version": "1.0.0"},
		"paths":   paths,
	}
	if len(c.GraphQL) > 0 {
		doc["x-tt-graphql-schemas"] = renderGraphQLSchemas(c.GraphQL)
	}
	return doc
}

func rawPath(p string) string {
	var sb strings.Builder
	i := 0
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		i++
		sb.WriteByte('/')
		if strings.HasPrefix(seg, "{") {
			sb.WriteString("{p" + strconv.Itoa(i) + "}")
		} else {
			sb.WriteString(seg)
		}
	}
	return sb.String()
}

func operationID(method, path string, used map[string]int) string {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(method))
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg == "" {
			continue
		}
		sb.WriteByte('_')
		for _, r := range seg {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				sb.WriteRune(r)
			}
		}
	}
	id := sb.String()
	used[id]++
	if n := used[id]; n > 1 {
		id += "_" + strconv.Itoa(n)
	}
	return id
}

func dateOf(t interface{ Format(string) string }) string { return t.Format("2006-01-02") }

func (c *Contract) renderOp(op *Op, path string, o RenderOptions, used map[string]int) map[string]any {
	m := map[string]any{"operationId": operationID(op.Method, path, used)}
	if op.GraphQL != nil {
		// A logical GraphQL operation (event.md 6): POST /graphql#GetOrder.
		m["summary"] = op.GraphQL.GraphQLLabel()
		m["x-tt-graphql"] = renderGraphQLOp(op.GraphQL)
	}
	obs := map[string]any{}
	if !o.PackSafe || op.Calls >= int64(c.KMin) {
		obs["calls"] = op.Calls
	}
	obs["first_seen"] = dateOf(op.FirstSeen)
	obs["last_seen"] = dateOf(op.LastSeen)
	m["x-tt-observed"] = obs
	if op.Latency != nil {
		m["x-tt-latency-ms"] = map[string]any{"p50": op.Latency.P50, "p95": op.Latency.P95, "p99": op.Latency.P99}
	}
	if o.Hints != nil {
		if e := o.Hints.Entity(c.Service, op.Key); e != "" {
			m["x-tt-entity"] = e
		}
	}

	var params []any
	for _, p := range op.PathParams {
		params = append(params, renderParam(p, "path"))
	}
	for _, p := range op.Query {
		params = append(params, renderParam(p, "query"))
	}
	for _, p := range op.Headers {
		params = append(params, renderParam(p, "header"))
	}
	for _, p := range op.Cookies {
		params = append(params, renderParam(p, "cookie"))
	}
	if len(params) > 0 {
		m["parameters"] = params
	}

	if len(op.Body) > 0 {
		rb := map[string]any{"content": renderContent(op.Body, false, 0, o)}
		rb["required"] = op.BodyCalls == op.ReqCalls && op.BodyCalls >= int64(c.MinSamples)
		m["requestBody"] = rb
	}

	resps := map[string]any{}
	for _, r := range op.Responses {
		if o.PackSafe && r.Calls < int64(c.KMin) {
			continue
		}
		rm := map[string]any{"description": statusText(r.Status), "x-tt-frequency": round4(r.Frequency)}
		if hs := renderHeaders(r.Headers); len(hs) > 0 {
			rm["headers"] = hs
		}
		if len(r.Body) > 0 {
			rm["content"] = renderContent(r.Body, true, r.Status, o)
		}
		resps[strconv.Itoa(r.Status)] = rm
	}
	if len(resps) > 0 {
		m["responses"] = resps
	}
	return m
}

func statusText(s int) string {
	if t := http.StatusText(s); t != "" {
		return t
	}
	return "Status " + strconv.Itoa(s)
}

func renderParam(p *Param, in string) map[string]any {
	sch := renderSchema(p.Schema)
	if p.Multi {
		sch = map[string]any{"type": "array", "items": sch}
	}
	m := map[string]any{"name": p.Name, "in": in, "required": p.Required, "schema": sch}
	if !p.Required && in != "path" {
		sch["x-tt-presence"] = round4(p.Presence)
	}
	return m
}

func renderHeaders(ps []*Param) map[string]any {
	out := map[string]any{}
	for _, p := range ps {
		sch := renderSchema(p.Schema)
		if !p.Required {
			sch["x-tt-presence"] = round4(p.Presence)
		}
		h := map[string]any{"schema": sch}
		if p.Required {
			h["required"] = true
		}
		out[p.Name] = h
	}
	return out
}

func mediaType(ct string) string {
	switch ct {
	case "":
		return "*/*"
	case "invalid":
		return "application/octet-stream"
	}
	return ct
}

func renderContent(ms []*Media, response bool, status int, o RenderOptions) map[string]any {
	out := map[string]any{}
	for _, md := range ms {
		item := map[string]any{}
		if md.Schema != nil {
			item["schema"] = renderSchema(md.Schema)
			if !o.NoExamples {
				if ex := examplesFor(md.Schema, response, status); len(ex) > 0 {
					item["examples"] = ex
				}
			}
		}
		if md.XML != nil {
			x := map[string]any{"format": md.XML.Format}
			if len(md.XML.Namespaces) > 0 {
				ns := map[string]any{}
				for k, v := range md.XML.Namespaces {
					ns[k] = v
				}
				x["namespaces"] = ns
			}
			item["x-tt-xml"] = x
		}
		out[mediaType(md.CT)] = item
	}
	return out
}

// renderSchema renders a schema; presence is added by the caller of props.
func renderSchema(s *Schema) map[string]any {
	m := map[string]any{}
	if s == nil {
		return m
	}
	switch len(s.Types) {
	case 0:
	case 1:
		m["type"] = s.Types[0]
	default:
		ts := make([]any, len(s.Types))
		for i, t := range s.Types {
			ts[i] = t
		}
		m["type"] = ts
	}
	if s.Format != "" {
		m["format"] = s.Format
	}
	if s.Shape == "doc" && synthdoc.Known(s.DocType) {
		// a document in base64 (JSON Schema content keywords)
		m["contentEncoding"] = "base64"
		m["contentMediaType"] = synthdoc.MediaType(s.DocType)
	}
	if s.Kind == "enum" && !s.EnumPartial {
		var vals []any
		for _, e := range s.PublishedEnum() {
			vals = append(vals, enumJSON(e))
		}
		if len(vals) > 0 {
			m["enum"] = vals
		}
	}
	if len(s.Props) > 0 {
		props := map[string]any{}
		var req []any
		for _, p := range s.Props {
			ps := renderSchema(p.Schema)
			if a, ok := strings.CutPrefix(p.Name, "@"); ok && a != "" {
				// an XML attribute (sanitizer.md 22.2 point 7): JSON keys
				// starting with @ never leave literal (sanitizer.md 9.3)
				ps["xml"] = map[string]any{"name": a, "attribute": true}
			}
			if !p.Required {
				ps["x-tt-presence"] = round4(p.Presence)
				if p.When != nil {
					in := make([]any, len(p.When.In))
					for i, v := range p.When.In {
						in[i] = v
					}
					ps["x-tt-when"] = map[string]any{p.When.Prop: in}
				}
			} else {
				req = append(req, p.Name)
			}
			props[p.Name] = ps
		}
		m["properties"] = props
		if len(req) > 0 {
			m["required"] = req
		}
		if deps := renderDeps(s); len(deps) > 0 {
			m["x-tt-dependencies"] = deps
		}
	}
	if s.Additional != nil {
		m["additionalProperties"] = renderSchema(s.Additional)
	}
	if s.Items != nil {
		m["items"] = renderSchema(s.Items)
	}
	if s.MinItems != nil {
		m["minItems"] = int64(*s.MinItems)
	}
	if xv := renderXValue(s); xv != nil {
		m["x-tt-value"] = xv
	}
	return m
}

func enumJSON(e EnumValue) any {
	if e.Type == "string" {
		return e.Value
	}
	if c, ok := event.CanonicalNumber(e.Value); ok {
		return num(c)
	}
	return e.Value
}

func renderXValue(s *Schema) map[string]any {
	if s.Kind == "" {
		return nil
	}
	m := map[string]any{"kind": s.Kind}
	switch s.Kind {
	case "id":
		m["domain"] = s.Domain
		if s.LenClass != "" {
			m["len_class"] = s.LenClass
		}
	case "enum":
		var vals []any
		for _, e := range s.PublishedEnum() {
			vals = append(vals, enumJSON(e))
		}
		m["enum"] = vals
		if s.EnumPartial {
			m["enum_partial"] = true
		}
	case "bucket":
		if s.Unit != "" {
			m["unit"] = s.Unit
		}
		if s.DateOffset != nil {
			m[dateoff.Key] = map[string]any{"min": s.DateOffset.Min, "max": s.DateOffset.Max}
		}
		if len(s.Bounds) > 0 {
			bs := make([]any, len(s.Bounds))
			for i, b := range s.Bounds {
				bs[i] = num(b)
			}
			m["bounds"] = bs
			ps := make([]any, len(s.BucketP))
			for i, p := range s.BucketP {
				ps[i] = p
			}
			m["bucket_p"] = ps
		}
	case "shape":
		if s.LenClass != "" {
			m["len_class"] = s.LenClass
		}
		if s.Shape != "" {
			m["format"] = s.Shape
		}
		if s.Shape == "doc" {
			m["doc_type"] = s.DocType
			if s.DocClass != "" {
				m["doc_class"] = s.DocClass
			}
		}
		if s.EnumPartial {
			m["enum_partial"] = true
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// Serialization

// CanonicalJSON serializes a rendered document as canonical JSON (tt-cjson,
// docs/spec/sanitizer.md section 10): no whitespace, keys sorted by byte,
// strings escaped as the specification says, numbers in canonical form,
// followed by a newline.
func CanonicalJSON(doc any) ([]byte, error) {
	b, err := appendCanon(make([]byte, 0, 4096), doc)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func appendCanon(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case string:
		return event.AppendString(dst, x), nil
	case int:
		return strconv.AppendInt(dst, int64(x), 10), nil
	case int64:
		return strconv.AppendInt(dst, x, 10), nil
	case float64:
		return appendNum(dst, strconv.FormatFloat(x, 'f', -1, 64))
	case num:
		return appendNum(dst, string(x))
	case []any:
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendCanon(dst, e); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = event.AppendString(dst, k)
			dst = append(dst, ':')
			var err error
			if dst, err = appendCanon(dst, x[k]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	}
	return nil, fmt.Errorf("contract: cannot serialize %T", v)
}

func appendNum(dst []byte, lex string) ([]byte, error) {
	c, ok := event.CanonicalNumber(lex)
	if !ok {
		return nil, fmt.Errorf("contract: invalid number %q", lex)
	}
	return append(dst, c...), nil
}

// YAML serializes a rendered document as YAML (keys sorted, two-space
// indent).
func YAML(doc any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(yamlValue(doc)); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func yamlValue(v any) any {
	switch x := v.(type) {
	case num:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return i
		}
		f, _ := strconv.ParseFloat(string(x), 64)
		return f
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = yamlValue(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = yamlValue(e)
		}
		return out
	}
	return v
}

// JSON renders the contract as canonical OpenAPI JSON.
func (c *Contract) JSON(o RenderOptions) ([]byte, error) { return CanonicalJSON(c.OpenAPI(o)) }

// YAML renders the contract as OpenAPI YAML.
func (c *Contract) YAML(o RenderOptions) ([]byte, error) { return YAML(c.OpenAPI(o)) }
