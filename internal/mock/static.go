package mock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivseb/traffic-twin/internal/idfmt"
)

// Static mode (docs/spec/mock.md §2.5): an operation that no entity of the
// pack creates or reads answers from its contract alone. Since mock 1.5 the
// session still keeps what such a create answered, so that a test sees its
// own objects again:
//
//   - a POST on a collection (".../shipments") whose response has an id field
//     gets a new id per call, with the entity prefix of the worlds
//     (SHP-SYN-0001), and echoes the scalar fields of the request that the
//     response declares with the same name and type;
//   - a GET, PUT, PATCH or DELETE on an item of that collection
//     (".../shipments/{id}") answers the object created in the session; an
//     id the session never created answers the not-found status of the
//     contract (404) when the contract has it and the collection can be
//     created into, otherwise 200 from the contract as before;
//   - every such answer carries X-TT-Static: true.
//
// A read-only collection (no create operation in the contract: a catalog
// the system under test only reads) keeps answering 200 for any id: the
// mock cannot know its ids.

const (
	hdrStatic = "X-TT-Static"
	// maxStaticObjects bounds the objects a session keeps in static mode.
	maxStaticObjects = 10000
)

// staticObjects are the objects created in static mode, by service and
// collection template, then by id.
type staticObjects struct {
	byColl  map[string]map[string]map[string]any
	counter map[string]int
	n       int
}

func (so *staticObjects) reset() { *so = staticObjects{} }

func (so *staticObjects) get(coll, id string) (map[string]any, bool) {
	o, ok := so.byColl[coll][id]
	return o, ok
}

func (so *staticObjects) put(coll, id string, o map[string]any) {
	if so.byColl == nil {
		so.byColl = map[string]map[string]map[string]any{}
	}
	m := so.byColl[coll]
	if m == nil {
		m = map[string]map[string]any{}
		so.byColl[coll] = m
	}
	if _, ok := m[id]; !ok {
		if so.n >= maxStaticObjects {
			return // bounded: the answer is still built, it is just not kept
		}
		so.n++
	}
	m[id] = o
}

func (so *staticObjects) del(coll, id string) {
	if m := so.byColl[coll]; m != nil {
		if _, ok := m[id]; ok {
			delete(m, id)
			so.n--
		}
	}
}

func (so *staticObjects) next(coll string) int {
	if so.counter == nil {
		so.counter = map[string]int{}
	}
	so.counter[coll]++
	return so.counter[coll]
}

// staticPrepare is prepare for an operation without entity: it returns nil
// when the operation is neither a create on a collection nor an access to one
// of its items (the contract answers as before).
func (s *session) staticPrepare(svc *service, op *operation, params map[string]string, reqBody any, b *builder, hdr http.Header, build func(optVal) any) func() (int, any) {
	n := len(op.segs)
	if n == 0 {
		return nil
	}
	last := op.segs[n-1]
	isParam := isParamSeg(last)
	status := op.successCode
	resp := op.responses[status]
	switch {
	case op.method == http.MethodGet && !isParam:
		// rules v1.6: a list of a collection the session created into
		// lists those objects (a DELETE took its object away).
		coll := svc.name + "\x00/" + strings.Join(op.segs, "/")
		objs := s.static.byColl[coll]
		if resp == nil || resp.schema == nil || len(objs) == 0 {
			return nil
		}
		prop := listProperty(svc.c.sc, resp.schema)
		if prop == "" {
			return nil
		}
		return func() (int, any) {
			body := build(optVal{})
			obj, ok := body.(map[string]any)
			if !ok {
				return status, body
			}
			var itemProps map[string]any
			if ps := propsOf(svc.c.sc, resp.schema); ps != nil {
				if it, ok := svc.c.sc.flat(ps[prop], 0)["items"]; ok {
					itemProps = propsOf(svc.c.sc, it)
				}
			}
			items := []any{}
			for _, id := range sortedKeys(anyMap(objs)) {
				o := cloneMap(objs[id])
				if itemProps != nil {
					for k := range o {
						if _, ok := itemProps[k]; !ok {
							delete(o, k)
						}
					}
				}
				items = append(items, o)
			}
			obj[prop] = items
			for _, cnt := range []string{"count", "total"} {
				if _, ok := obj[cnt]; ok {
					obj[cnt] = intNumber(len(items))
				}
			}
			s.responseHeaders(resp, hdr, "")
			hdr.Set(hdrStatic, "true")
			return status, obj
		}
	case op.method == http.MethodPost && !isParam:
		if resp == nil || resp.schema == nil || status < 200 || status > 299 {
			return nil
		}
		idField := staticIDField(svc.c.sc, resp.schema, last)
		if idField == "" {
			return nil
		}
		coll := svc.name + "\x00/" + strings.Join(op.segs, "/")
		id := s.staticID(svc, resp.schema, idField, coll, last, b, reqBody)
		echo := echoFields(svc.c.sc, resp.schema, reqBody, idField)
		return func() (int, any) {
			body := build(optVal{})
			obj, ok := body.(map[string]any)
			if !ok {
				return status, body
			}
			for k, v := range echo {
				obj[k] = cloneJSON(v)
			}
			obj[idField] = id
			s.static.put(coll, id, cloneMap(obj))
			s.responseHeaders(resp, hdr, id)
			hdr.Set(hdrStatic, "true")
			return status, obj
		}
	case isParam && n >= 2 && (op.method == http.MethodGet || op.method == http.MethodPut || op.method == http.MethodPatch || op.method == http.MethodDelete):
		pname := strings.TrimSuffix(strings.TrimPrefix(last, "{"), "}")
		id, ok := params[pname]
		if !ok {
			return nil
		}
		collSegs := op.segs[:n-1]
		coll := svc.name + "\x00/" + strings.Join(collSegs, "/")
		creatable := svc.c.byKey[http.MethodPost+" /"+strings.Join(collSegs, "/")] != nil
		stored, known := s.static.get(coll, id)
		if op.method != http.MethodGet && !known && !creatable {
			return nil
		}
		if known && (op.method == http.MethodPut || op.method == http.MethodPatch) {
			for k, v := range echoFields(svc.c.sc, op.bodySchema, reqBody, "") {
				stored[k] = cloneJSON(v)
			}
		}
		if known && op.method == http.MethodDelete {
			s.static.del(coll, id)
		}
		return func() (int, any) {
			hdr.Set(hdrStatic, "true")
			if !known && creatable {
				if nf := op.responses[http.StatusNotFound]; nf != nil {
					return http.StatusNotFound, s.errorBody(op, http.StatusNotFound, "", b, "not_found")
				}
			}
			s.responseHeaders(resp, hdr, "")
			body := build(optVal{})
			obj, ok := body.(map[string]any)
			if !ok || resp == nil || resp.schema == nil {
				return status, body
			}
			props := propsOf(svc.c.sc, resp.schema)
			for k, v := range stored {
				if _, ok := props[k]; ok {
					obj[k] = cloneJSON(v)
				}
			}
			if f := staticIDField(svc.c.sc, resp.schema, collSegs[len(collSegs)-1]); f != "" {
				if _, isStr := obj[f].(string); isStr || obj[f] == nil {
					obj[f] = id // the id of the path, also for an id the mock does not know
				}
			}
			return status, obj
		}
	}
	return nil
}

func anyMap(m map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func propsOf(sc *schemaCtx, schema any) map[string]any {
	if schema == nil {
		return nil
	}
	p, _ := sc.flat(schema, 0)["properties"].(map[string]any)
	return p
}

// staticIDField is the id property of a response object: "id", else the id
// of the resource ("shipmentId" for .../shipments), else the only property
// annotated as an id (x-tt-value kind id). Only string properties.
func staticIDField(sc *schemaCtx, schema any, collection string) string {
	props := propsOf(sc, schema)
	isStr := func(k string) bool {
		p, ok := props[k]
		if !ok {
			return false
		}
		return primaryType(sc.flat(p, 0)) == "string"
	}
	if isStr("id") {
		return "id"
	}
	res := singularWord(strings.ToLower(collection))
	for _, k := range sortedKeys(props) {
		if strings.EqualFold(k, res+"Id") || strings.EqualFold(k, res+"_id") {
			if isStr(k) {
				return k
			}
		}
	}
	only := ""
	for _, k := range sortedKeys(props) {
		if xv, ok := sc.flat(props[k], 0)["x-tt-value"].(map[string]any); ok && xv["kind"] == "id" && isStr(k) {
			if only != "" {
				return ""
			}
			only = k
		}
	}
	return only
}

// staticID is a new id for a create in static mode: the prefix of the id
// domain when the pack knows it, else the entity prefix of the worlds made
// from the collection name (shipments -> SHP-SYN-), and a counter per
// session and collection.
func (s *session) staticID(svc *service, schema any, idField, coll, collection string, b *builder, req any) string {
	prefix := ""
	if p, ok := propsOf(svc.c.sc, schema)[idField]; ok {
		if xv, ok := svc.c.sc.flat(p, 0)["x-tt-value"].(map[string]any); ok {
			if d, _ := xv["domain"].(string); d != "" {
				if t := b.fmts[d]; t != nil {
					// The id format of the domain; it copies fields of the
					// request (docs/spec/pack.md 4.3).
					rm, _ := req.(map[string]any)
					for range 1000 {
						id := t.ID(uint64(s.static.next(coll)), d, idfmt.MapRef(rm))
						if _, taken := s.static.get(coll, id); !taken {
							return id
						}
					}
				}
				prefix = b.prefixes[d]
			}
		}
	}
	if prefix == "" {
		prefix = entityPrefix(singularWord(collection))
	}
	return fmt.Sprintf("%s%04d", prefix, s.static.next(coll))
}

// echoFields returns the top-level scalar fields of the request body that
// the response object declares with the same name and type (without enum
// or const: a value outside them would break the contract). skip is never
// echoed (the id the mock generates).
func echoFields(sc *schemaCtx, respSchema any, reqBody any, skip string) map[string]any {
	req, ok := reqBody.(map[string]any)
	if !ok {
		return nil
	}
	props := propsOf(sc, respSchema)
	out := map[string]any{}
	for k, v := range req {
		if k == skip {
			continue
		}
		p, ok := props[k]
		if !ok {
			continue
		}
		ps := sc.flat(p, 0)
		if _, has := ps["enum"]; has {
			continue
		}
		if _, has := ps["const"]; has {
			continue
		}
		t := primaryType(ps)
		switch v.(type) {
		case string:
			if t != "string" || ps["format"] != nil || ps["pattern"] != nil {
				continue
			}
		case bool:
			if t != "boolean" {
				continue
			}
		case json.Number, float64:
			if t != "number" && t != "integer" {
				continue
			}
			if _, has := ps["minimum"]; has {
				continue
			}
			if _, has := ps["maximum"]; has {
				continue
			}
		default:
			continue
		}
		if sc.validate(p, v, "", 0) != nil {
			continue
		}
		out[k] = v
	}
	return out
}

// singularWord: shipments -> shipment, categories -> category, boxes -> box.
func singularWord(w string) string {
	switch {
	case strings.HasSuffix(w, "ies") && len(w) > 3:
		return w[:len(w)-3] + "y"
	case strings.HasSuffix(w, "sses") || strings.HasSuffix(w, "xes") || strings.HasSuffix(w, "ches") || strings.HasSuffix(w, "shes"):
		return w[:len(w)-2]
	case strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") && len(w) > 1:
		return w[:len(w)-1]
	}
	return w
}

// entityPrefix builds ^[A-Z]{2,5}-SYN-$ from a name as the miner names
// entity prefixes: the first letter and the following consonants (order ->
// ORD-SYN-, shipment -> SHP-SYN-).
func entityPrefix(name string) string {
	up := strings.ToUpper(name)
	var b []byte
	for i := 0; i < len(up) && len(b) < 3; i++ {
		c := up[i]
		if c < 'A' || c > 'Z' {
			continue
		}
		if len(b) > 0 && strings.IndexByte("AEIOU", c) >= 0 {
			continue
		}
		b = append(b, c)
	}
	if len(b) < 2 {
		b = b[:0]
		for i := 0; i < len(up) && len(b) < 3; i++ {
			if c := up[i]; c >= 'A' && c <= 'Z' {
				b = append(b, c)
			}
		}
	}
	for len(b) < 2 {
		b = append(b, 'X')
	}
	return string(b) + "-SYN-"
}
