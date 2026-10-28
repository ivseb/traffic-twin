package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/ivseb/traffic-twin/internal/sanitizer"
)

// SOAP and XML operations (docs/spec/mock.md 10, spec v1.21). A SOAP
// service has one endpoint and many logical operations, "POST
// /ws/orders.asmx#GetOrder" in the contract (event.md 6.1), whose bodies
// are the XML trees of sanitizer.md 22.2 with the envelope in x-tt-xml
// (pack.md 4). The mock reads the request with the closed parser of the
// sources (no DTD, no entities, hardening.md 3), picks the logical
// operation by SOAPAction or by the first element of the Body, and serves
// it through the same path as every operation: the request is presented to
// validation, rules and reads as its tree; the answer is built as a JSON
// tree from the contract and the state, then written as XML with the
// observed namespaces and the SOAP envelope. Errors become SOAP Faults.

// Namespaces written by the mock.
const (
	nsSOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
	nsSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
	nsXSI    = "http://www.w3.org/2001/XMLSchema-instance"
)

// xmlSpec is the envelope of an XML body of the contract (x-tt-xml).
type xmlSpec struct {
	format string            // xml | soap11 | soap12
	ns     map[string]string // element path without [*] -> namespace URI ("" = none)
	ct     string            // media type of the contract
}

func (x *xmlSpec) soap() bool { return x.format == "soap11" || x.format == "soap12" }

// contentType is the Content-Type of an answer with this envelope.
func (x *xmlSpec) contentType() string {
	mt := x.ct
	if x.format == "soap12" && (mt == "" || mt == "text/xml" || mt == "application/xml") {
		mt = "application/soap+xml"
	}
	if mt == "" {
		mt = "text/xml"
	}
	return mt + "; charset=utf-8"
}

// isXMLMediaType reports an XML media type (text/xml, application/xml,
// application/soap+xml, any +xml).
func isXMLMediaType(mt string) bool {
	mt = strings.ToLower(strings.TrimSpace(strings.SplitN(mt, ";", 2)[0]))
	return mt == "text/xml" || mt == "application/xml" || strings.HasSuffix(mt, "+xml")
}

// nsURI turns a namespace pattern (sanitizer.md 22.2 point 9) into the URI
// the mock writes: ns:{none} is no namespace; a pattern whose value-like
// parts were collapsed at the source gets a synthetic part in their place.
func nsURI(pat string) string {
	p := strings.TrimPrefix(pat, "ns:")
	switch p {
	case "{none}":
		return ""
	case "{*}":
		return "urn:tt:synthetic"
	}
	return strings.ReplaceAll(p, "{*}", "synthetic")
}

func stripStars(path string) string { return strings.ReplaceAll(path, "[*]", "") }

// xmlMedia picks the XML media type object of a content map: one with
// x-tt-xml, or an XML media type with a schema or an example.
func xmlMedia(sc *schemaCtx, content any) (map[string]any, *xmlSpec) {
	cm, _ := content.(map[string]any)
	for _, k := range sortedKeys(cm) {
		mt := strings.ToLower(strings.TrimSpace(strings.SplitN(k, ";", 2)[0]))
		media := sc.resolve(cm[k])
		if media == nil {
			continue
		}
		x, _ := media["x-tt-xml"].(map[string]any)
		if x == nil {
			if !isXMLMediaType(mt) {
				continue
			}
			_, hs := media["schema"]
			_, he := media["example"]
			_, hx := media["examples"]
			if !hs && !he && !hx {
				continue
			}
		}
		spec := &xmlSpec{format: "xml", ns: map[string]string{}, ct: mt}
		if f, _ := x["format"].(string); f == "soap11" || f == "soap12" || f == "xml" {
			spec.format = f
		} else if mt == "application/soap+xml" {
			spec.format = "soap12"
		}
		if ns, ok := x["namespaces"].(map[string]any); ok {
			for p, v := range ns {
				if s, ok := v.(string); ok && strings.HasPrefix(s, "ns:") && strings.HasPrefix(p, "$") {
					spec.ns[stripStars(p)] = nsURI(s)
				}
			}
		}
		return media, spec
	}
	return nil, nil
}

// xmlDefault is the envelope of the operation's answers when a status has
// no XML body of its own (faults): the success answer's, else the
// request's, else any; nil for an operation that is not XML.
func (o *operation) xmlDefault() *xmlSpec {
	if r := o.responses[o.successCode]; r != nil && r.xml != nil {
		return r.xml
	}
	if o.reqXML != nil {
		return o.reqXML
	}
	for _, st := range o.statuses {
		if r := o.responses[st]; r.xml != nil {
			return r.xml
		}
	}
	return nil
}

// xmlFor is the envelope of the answer with this status: the status's own
// XML body; nil when the contract observed a JSON or document body for it;
// otherwise the operation's default.
func (o *operation) xmlFor(status int) *xmlSpec {
	if r := o.responses[status]; r != nil {
		if r.xml != nil {
			return r.xml
		}
		if r.media != nil || r.doc != nil {
			return nil
		}
	}
	return o.xmlDefault()
}

// ---- endpoints and routing ----

// soapEndpoint is one SOAP (or XML) endpoint with logical operations.
type soapEndpoint struct {
	path string
	ops  map[string]*operation // by op key "POST /ws#Name"
	spec *xmlSpec              // envelope of the protocol errors
}

var soapIndex sync.Map // *contract -> map[string]*soapEndpoint (by path)

// soapEndpoints indexes the logical XML operations of a compiled contract.
func soapEndpoints(c *contract) map[string]*soapEndpoint {
	if v, ok := soapIndex.Load(c); ok {
		return v.(map[string]*soapEndpoint)
	}
	out := map[string]*soapEndpoint{}
	for _, op := range c.ops {
		if op.node["x-tt-graphql"] != nil || !strings.Contains(op.tmpl, "#") {
			continue
		}
		xs := op.xmlDefault()
		if xs == nil {
			continue
		}
		path, _, _ := strings.Cut(op.tmpl, "#")
		ep := out[path]
		if ep == nil {
			ep = &soapEndpoint{path: path, ops: map[string]*operation{}}
			out[path] = ep
		}
		ep.ops[op.key] = op
		if ep.spec == nil || (op.reqXML != nil && op.reqXML.soap() && !ep.spec.soap()) {
			ep.spec = xs
			if op.reqXML != nil {
				ep.spec = op.reqXML
			}
		}
	}
	soapIndex.Store(c, out)
	return out
}

// soapCall is an XML request routed to a logical operation.
type soapCall struct {
	op *operation
	// path is the logical path the generator seeds on: the operation and
	// a hash of the request tree (two reads of two ids differ).
	path string
	// res is a complete answer (fault) that ends the dispatch.
	res *result
}

// parseXMLBody parses the XML body of a request once.
func (in *inbound) parseXMLBody() (*sanitizer.XMLDoc, error) {
	if in.xmlDoc == nil && in.xmlErr == nil {
		in.xmlDoc, in.xmlErr = sanitizer.ParseXML(in.body)
	}
	return in.xmlDoc, in.xmlErr
}

// soapName is the operation name of a request: from SOAPAction (or the
// action parameter of a SOAP 1.2 content type), otherwise the first
// element of the Body (the root element for plain XML).
func soapName(in *inbound, doc *sanitizer.XMLDoc, ep *soapEndpoint) (string, *operation) {
	find := func(name string) *operation {
		if op := ep.ops[in.method+" "+ep.path+"#"+name]; op != nil {
			return op
		}
		return ep.ops[http.MethodPost+" "+ep.path+"#"+name]
	}
	vals := in.header.Values("SOAPAction")
	hv := ""
	if len(vals) > 0 {
		hv = vals[0]
	}
	action, hasAction := sanitizer.SOAPActionName(hv, len(vals) > 0, in.header.Get("Content-Type"))
	if hasAction {
		if op := find(action); op != nil {
			return action, op
		}
	}
	elem := doc.Root
	if doc.Format != "xml" {
		elem = ""
		if len(doc.BodyElems) > 0 {
			elem = doc.BodyElems[0]
		}
	}
	if elem != "" && sanitizer.IsLiteralKey([]byte(elem)) {
		if op := find(elem); op != nil {
			return elem, op
		}
	}
	if hasAction {
		return action, nil
	}
	return elem, nil
}

// soapRoute recognizes a request to a SOAP (or XML) endpoint of svc with
// logical operations. It returns nil for any other request (the REST
// dispatch goes on).
func (s *session) soapRoute(svc *service, in *inbound, path string, e *journalEntry) *soapCall {
	eps := soapEndpoints(svc.c)
	if len(eps) == 0 {
		return nil
	}
	ep := eps[path]
	if ep == nil || in.method != http.MethodPost {
		return nil
	}
	call := &soapCall{}
	if ct := in.header.Get("Content-Type"); ct != "" && !isXMLMediaType(ct) {
		e.Matched, e.Reason = false, "invalid-request"
		call.res = s.protocolFault(ep.spec, "invalid-request", "the content type must be XML", "")
		return call
	}
	doc, err := in.parseXMLBody()
	if err != nil {
		e.Matched, e.Reason, e.Pointer = false, "invalid-request", "/body"
		call.res = s.protocolFault(ep.spec, "invalid-request", "the body is not valid XML (no DTD, no entities, at most 256 nested elements)", "/body")
		return call
	}
	name, op := soapName(in, doc, ep)
	if op == nil {
		if name == "" {
			if o, _, _ := svc.c.match(in.method, path); o != nil {
				return nil // observed without a name: the HTTP operation answers
			}
		}
		e.Matched, e.Reason = false, "no-operation"
		label := name
		if label == "" {
			label = "(no SOAPAction, no Body element)"
		}
		call.res = s.protocolFault(ep.spec, "no-operation", "operation not observed: "+label, "")
		return call
	}
	call.op = op
	h := sha256.Sum256(compactJSON(doc.Tree))
	call.path = op.tmpl + "?" + hex.EncodeToString(h[:6])
	return call
}

// protocolStatus is the status of a fault the mock raises itself (an
// unknown operation, a request it cannot read): SOAP 1.1 answers faults
// with 500, SOAP 1.2 a Sender fault with 400; plain XML 404 for an unknown
// operation and 400 otherwise.
func protocolStatus(x *xmlSpec, reason string) int {
	switch {
	case x.format == "soap11":
		return http.StatusInternalServerError
	case x.format == "soap12":
		return http.StatusBadRequest
	case reason == "no-operation":
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// protocolFault is a fault the mock raises itself, with X-TT-Unmatched.
func (s *session) protocolFault(x *xmlSpec, reason, msg, ptr string) *result {
	hdr := http.Header{}
	hdr.Set(hdrUnmatched, reason)
	hdr.Set("Content-Type", x.contentType())
	detail := map[string]any{"code": reason}
	if ptr != "" {
		detail["pointer"] = ptr
	}
	return &result{status: protocolStatus(x, reason), header: hdr, body: faultXML(x, true, msg, detail)}
}

// ---- request bodies ----

// xmlRequest reads and validates an XML request body: the tree, coerced
// to the schema (a single element where an array is declared, numbers and
// booleans written as text).
func (s *session) xmlRequest(sc *schemaCtx, op *operation, in *inbound) (any, *violation) {
	if ct := in.header.Get("Content-Type"); ct != "" && !isXMLMediaType(ct) {
		return nil, &violation{"/body", "content type must be XML"}
	}
	doc, err := in.parseXMLBody()
	if err != nil {
		return nil, &violation{"/body", "body is not valid XML"}
	}
	var v any = doc.Tree
	if op.bodySchema != nil {
		v = coerceXML(sc, op.bodySchema, v, 0)
		if viol := sc.validate(op.bodySchema, v, "/body", 0); viol != nil {
			return nil, viol
		}
	}
	return v, nil
}

// coerceXML fits a tree of strings to a schema: XML has no arrays of one,
// no numbers and no booleans (sanitizer.md 22.2 point 7).
func coerceXML(sc *schemaCtx, schema any, v any, depth int) any {
	if depth > maxSchemaDepth || schema == nil {
		return v
	}
	s := sc.flat(schema, 0)
	types := schemaTypes(s)
	has := func(t string) bool {
		for _, x := range types {
			if x == t {
				return true
			}
		}
		return false
	}
	pt := primaryType(s)
	if m, ok := v.(map[string]any); ok && len(m) == 1 && m["@nil"] == "true" && (has("null") || pt != "object") {
		return nil // xsi:nil
	}
	if pt == "array" {
		if _, ok := v.([]any); !ok && v != nil {
			v = []any{v}
		}
	}
	switch x := v.(type) {
	case []any:
		items := s["items"]
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = coerceXML(sc, items, e, depth+1)
		}
		return out
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		ap, _ := s["additionalProperties"].(map[string]any)
		out := make(map[string]any, len(x))
		for k, e := range x {
			switch {
			case props[k] != nil:
				out[k] = coerceXML(sc, props[k], e, depth+1)
			case ap != nil:
				out[k] = coerceXML(sc, ap, e, depth+1)
			default:
				out[k] = e
			}
		}
		return out
	case string:
		if has("string") {
			return x
		}
		switch pt {
		case "object":
			props, _ := s["properties"].(map[string]any)
			if strings.TrimSpace(x) == "" {
				return map[string]any{}
			}
			if props["#text"] != nil {
				return map[string]any{"#text": x}
			}
		case "integer", "number":
			t := strings.TrimSpace(x)
			if _, err := strconv.ParseFloat(t, 64); err == nil {
				return json.Number(t)
			}
		case "boolean":
			switch strings.TrimSpace(x) {
			case "true", "1":
				return true
			case "false", "0":
				return false
			}
		}
	}
	return v
}

// ---- answers ----

// xmlFinish writes the answer of an XML operation as XML (mock.md 10.3):
// the JSON tree built from the contract and the state with the observed
// namespaces and the SOAP envelope; an error the contract has no XML body
// for becomes a SOAP Fault (or an <error> element for plain XML); an error
// body typed by a person is honoured (a string starting with "<" is
// served as it is, another string is the text of the fault).
//
// forced tells a status chosen by a fault or a respond effect. A status
// the mock chose itself (a read without result: 404, 403) that the
// contract never observed follows the SOAP HTTP binding instead: 500 for
// SOAP 1.1, 400 (Sender) for SOAP 1.2, so that a SOAP client sees a fault
// and not a transport error.
func (s *session) xmlFinish(op *operation, x *xmlSpec, res *result, status int, body, typed any, forced bool) {
	if res.netErr != "" {
		return
	}
	setCT := func() { res.header.Set("Content-Type", x.contentType()) }
	if status >= 400 {
		sender := status < 500
		if !forced && op.responses[status] == nil {
			switch x.format {
			case "soap11":
				res.status = http.StatusInternalServerError
			case "soap12":
				if sender {
					res.status = http.StatusBadRequest
				}
			}
		}
		if typed != nil {
			switch t := typed.(type) {
			case string:
				if strings.HasPrefix(strings.TrimSpace(t), "<") {
					res.body = []byte(t)
				} else {
					res.body = faultXML(x, sender, t, nil)
				}
			case map[string]any:
				res.body = errorObjectXML(x, sender, status, t)
			default:
				res.body = faultXML(x, sender, http.StatusText(status), map[string]any{"item": t})
			}
			setCT()
			return
		}
		if r := op.responses[status]; r != nil && r.xml != nil && body != nil {
			fixFaultCodes(body, x, sender)
			res.body = renderXML(body, x)
			setCT()
			return
		}
		msg := http.StatusText(status)
		var detail map[string]any
		if m, ok := body.(map[string]any); ok {
			if t, ok := m["message"].(string); ok && t != "" {
				msg = t
			}
			if c, ok := m["code"].(string); ok && c != "" {
				detail = map[string]any{"code": c}
			}
		}
		res.body = faultXML(x, sender, msg, detail)
		setCT()
		return
	}
	if body == nil || status == http.StatusNoContent {
		return
	}
	res.body = renderXML(body, x)
	setCT()
}

// fixFaultCodes keeps the codes of a fault generated from the contract
// valid: the value of faultcode (SOAP 1.1) must be a qualified name and
// the Code/Value of SOAP 1.2 one of the codes of the standard; a value the
// source collapsed into a shape becomes Client/Server (Sender/Receiver)
// by status.
func fixFaultCodes(body any, x *xmlSpec, sender bool) {
	f, _ := evalOne(body, "Envelope", "Body", "Fault").(map[string]any)
	if f == nil {
		return
	}
	switch x.format {
	case "soap11":
		if c, ok := f["faultcode"]; ok {
			if s, _ := c.(string); !qnameOK(s) {
				f["faultcode"] = map[bool]string{true: "soap:Client", false: "soap:Server"}[sender]
			}
		}
	case "soap12":
		code, _ := f["Code"].(map[string]any)
		if code == nil {
			return
		}
		s, _ := code["Value"].(string)
		_, local, _ := strings.Cut(s, ":")
		switch local {
		case "Sender", "Receiver", "VersionMismatch", "MustUnderstand", "DataEncodingUnknown":
		default:
			code["Value"] = map[bool]string{true: "env:Sender", false: "env:Receiver"}[sender]
		}
	}
}

// qnameOK reports prefix:local with two valid names.
func qnameOK(s string) bool {
	p, l, ok := strings.Cut(s, ":")
	return ok && xmlNameOK(p) && xmlNameOK(l)
}

// errorObjectXML writes an error object typed by a person: an Envelope is
// written as it is, a Fault is wrapped in the envelope, anything else is
// the detail of a fault (plain XML: the object as it is).
func errorObjectXML(x *xmlSpec, sender bool, status int, m map[string]any) []byte {
	if !x.soap() {
		return renderXML(m, x)
	}
	if _, ok := m["Envelope"]; ok && len(m) == 1 {
		return renderXML(m, x)
	}
	if _, ok := m["Fault"]; ok && len(m) == 1 {
		return renderXML(m, x)
	}
	msg := http.StatusText(status)
	if t, ok := m["message"].(string); ok && t != "" {
		msg = t
	}
	return faultXML(x, sender, msg, m)
}

// faultXML is a SOAP Fault (1.1: faultcode, faultstring, detail; 1.2:
// Code/Value, Reason/Text, Detail) or, for plain XML, an <error> element.
func faultXML(x *xmlSpec, sender bool, msg string, detail map[string]any) []byte {
	spec := &xmlSpec{format: x.format, ns: map[string]string{}, ct: x.ct}
	var tree map[string]any
	switch x.format {
	case "soap11":
		code := "soap:Server"
		if sender {
			code = "soap:Client"
		}
		f := map[string]any{"faultcode": code, "faultstring": msg}
		if len(detail) > 0 {
			f["detail"] = detail
		}
		tree = map[string]any{"Envelope": map[string]any{"Body": map[string]any{"Fault": f}}}
	case "soap12":
		code := "env:Receiver"
		if sender {
			code = "env:Sender"
		}
		f := map[string]any{"Code": map[string]any{"Value": code}, "Reason": map[string]any{"Text": map[string]any{"@xml:lang": "en", "#text": msg}}}
		if len(detail) > 0 {
			f["Detail"] = detail
		}
		tree = map[string]any{"Envelope": map[string]any{"Body": map[string]any{"Fault": f}}}
	default:
		e := map[string]any{"message": msg}
		for k, v := range detail {
			if _, ok := e[k]; !ok {
				e[k] = v
			}
		}
		tree = map[string]any{"error": e}
	}
	return renderXML(tree, spec)
}

// ---- XML writer ----

// renderXML writes a body tree as an XML document with the envelope x:
// one root element (a SOAP body is wrapped in Envelope and Body when it
// is not already), the namespaces of x per element path, attributes from
// "@name" members, text from "#text", arrays as repeated elements.
func renderXML(body any, x *xmlSpec) []byte {
	m, ok := body.(map[string]any)
	if !ok {
		m = map[string]any{"response": body}
	}
	if x.soap() {
		if _, ok := m["Envelope"]; !(ok && len(m) == 1) {
			if b, ok := m["Body"]; ok && len(m) == 1 {
				m = map[string]any{"Envelope": map[string]any{"Body": b}}
			} else {
				m = map[string]any{"Envelope": map[string]any{"Body": m}}
			}
		}
	} else if len(m) != 1 {
		m = map[string]any{"response": m}
	}
	w := &xmlWriter{ns: faultNamespaces(m, x), format: x.format}
	switch x.format {
	case "soap11":
		w.envNS, w.envPrefix = nsSOAP11, "soap"
	case "soap12":
		w.envNS, w.envPrefix = nsSOAP12, "env"
	}
	var root string
	for k := range m {
		root = k
	}
	w.extra = w.faultPrefixes(m)
	w.b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	rootNS := ""
	if w.envNS != "" && root == "Envelope" {
		rootNS = w.envNS
	}
	if u, ok := w.ns["$."+root]; ok && !(w.envNS != "" && root == "Envelope") {
		rootNS = u
	}
	w.elem(root, m[root], "$."+root, rootNS, "", false, 0)
	return []byte(w.b.String())
}

// faultNamespaces completes the namespaces of x for a SOAP Fault: the
// children of a SOAP 1.1 Fault and the entries of a SOAP 1.2 Detail are in
// no namespace unless the contract says otherwise (they would otherwise
// inherit the envelope's).
func faultNamespaces(m map[string]any, x *xmlSpec) map[string]string {
	f, _ := evalOne(m, "Envelope", "Body", "Fault").(map[string]any)
	if f == nil || !x.soap() {
		return x.ns
	}
	ns := make(map[string]string, len(x.ns)+4)
	for k, v := range x.ns {
		ns[k] = v
	}
	add := func(p string) {
		if _, ok := ns[p]; !ok {
			ns[p] = ""
		}
	}
	if x.format == "soap11" {
		for _, k := range []string{"faultcode", "faultstring", "faultactor", "detail"} {
			add("$.Envelope.Body.Fault." + k)
		}
	} else if d, ok := f["Detail"].(map[string]any); ok {
		for k := range d {
			add("$.Envelope.Body.Fault.Detail." + k)
		}
	}
	return ns
}

type xmlWriter struct {
	b         strings.Builder
	ns        map[string]string
	format    string
	envNS     string
	envPrefix string
	extra     []string // further prefixes bound to the envelope namespace
}

// faultPrefixes are the prefixes of the fault codes of a body (faultcode
// "s:Client", Value "env:Sender") other than the mock's own: they are
// bound to the envelope namespace on the root so that the codes stay
// valid qualified names.
func (w *xmlWriter) faultPrefixes(m map[string]any) []string {
	if w.envNS == "" {
		return nil
	}
	f, _ := evalOne(m, "Envelope", "Body", "Fault").(map[string]any)
	if f == nil {
		return nil
	}
	var codes []any
	codes = append(codes, f["faultcode"])
	if c, ok := f["Code"].(map[string]any); ok {
		codes = append(codes, c["Value"])
		if sc, ok := c["Subcode"].(map[string]any); ok {
			codes = append(codes, sc["Value"])
		}
	}
	var out []string
	for _, c := range codes {
		s, _ := c.(string)
		p, local, ok := strings.Cut(s, ":")
		if !ok || p == w.envPrefix || p == "xml" || !xmlNameOK(p) || !xmlNameOK(local) || strings.HasPrefix(strings.ToLower(p), "xml") {
			continue
		}
		dup := false
		for _, e := range out {
			dup = dup || e == p
		}
		if !dup {
			out = append(out, p)
		}
	}
	return out
}

func evalOne(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// childOrder is the order SOAP requires among some children; the other
// children follow by name (the order between children of different names
// is not observed, sanitizer.md 22.2).
var childOrder = map[string][]string{
	"Envelope": {"Header", "Body"},
	"Fault":    {"faultcode", "faultstring", "faultactor", "detail", "Code", "Reason", "Node", "Role", "Detail"},
	"Code":     {"Value", "Subcode"},
	"Subcode":  {"Value", "Subcode"},
}

func orderedChildren(name string, m map[string]any) []string {
	var keys []string
	for k := range m {
		if !strings.HasPrefix(k, "@") && k != "#text" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	first := childOrder[name]
	if len(first) == 0 {
		return keys
	}
	rank := func(k string) int {
		for i, f := range first {
			if f == k {
				return i
			}
		}
		return len(first)
	}
	sort.SliceStable(keys, func(i, j int) bool { return rank(keys[i]) < rank(keys[j]) })
	return keys
}

// elem writes one element: name is its local name, path its element path
// (without [*]), ns its namespace, defNS the default namespace in scope,
// envDecl whether the envelope prefix is declared.
func (w *xmlWriter) elem(name string, v any, path, ns, defNS string, envDecl bool, depth int) {
	if depth > 256 || !xmlNameOK(name) {
		return
	}
	qname := name
	var decls strings.Builder
	if w.envNS != "" && ns == w.envNS {
		qname = w.envPrefix + ":" + name
		if !envDecl {
			decls.WriteString(` xmlns:` + w.envPrefix + `="` + escXML(w.envNS, true) + `"`)
			envDecl = true
		}
	} else if ns != defNS {
		decls.WriteString(` xmlns="` + escXML(ns, true) + `"`)
		defNS = ns
	}
	if depth == 0 {
		for _, p := range w.extra {
			decls.WriteString(` xmlns:` + p + `="` + escXML(w.envNS, true) + `"`)
		}
	}
	w.b.WriteString("<" + qname + decls.String())
	switch x := v.(type) {
	case nil:
		w.b.WriteString(` xsi:nil="true" xmlns:xsi="` + nsXSI + `"/>`)
		return
	case map[string]any:
		attrs := make([]string, 0, len(x))
		for k := range x {
			if strings.HasPrefix(k, "@") {
				attrs = append(attrs, k)
			}
		}
		sort.Strings(attrs)
		for _, k := range attrs {
			an := k[1:]
			if w.format == "soap12" && name == "Text" && an == "lang" {
				an = "xml:lang" // the prefix of an observed attribute is not kept
			}
			if !xmlNameOK(an) && !(strings.HasPrefix(an, "xml:") && xmlNameOK(an[4:])) {
				continue
			}
			sv, ok := xmlScalar(x[k])
			if !ok {
				continue
			}
			w.b.WriteString(" " + an + `="` + escXML(sv, true) + `"`)
		}
		kids := orderedChildren(name, x)
		text, hasText := xmlScalar(x["#text"])
		if len(kids) == 0 && (!hasText || text == "") {
			w.b.WriteString("/>")
			return
		}
		w.b.WriteString(">")
		for _, k := range kids {
			cp := path + "." + k
			cns := ns
			if u, ok := w.ns[cp]; ok {
				cns = u
			}
			if arr, ok := x[k].([]any); ok {
				for _, e := range arr {
					w.elem(k, e, cp, cns, defNS, envDecl, depth+1)
				}
				continue
			}
			w.elem(k, x[k], cp, cns, defNS, envDecl, depth+1)
		}
		if hasText {
			w.b.WriteString(escXML(text, false))
		}
	case []any:
		// an array directly inside an array: its items as text
		w.b.WriteString(">")
		for _, e := range x {
			if sv, ok := xmlScalar(e); ok {
				w.b.WriteString(escXML(sv, false))
			}
		}
	default:
		sv, _ := xmlScalar(x)
		if sv == "" {
			w.b.WriteString("/>")
			return
		}
		w.b.WriteString(">" + escXML(sv, false))
	}
	w.b.WriteString("</" + qname + ">")
}

// xmlScalar is the text of a scalar value.
func xmlScalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	}
	return "", false
}

// xmlNameOK is the rule of the names without ":" (sanitizer.md 22.2
// point 3).
func xmlNameOK(n string) bool {
	if n == "" || len(n) > 256 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !(alpha || c == '_' || c >= 0x80) {
			return false
		}
		if !(alpha || c == '_' || c >= 0x80 || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return utf8.ValidString(n) && !strings.HasPrefix(strings.ToLower(n), "xmlns")
}

// escXML escapes text (attr: an attribute value) and drops the characters
// XML 1.0 does not allow.
func escXML(s string, attr bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '"' && attr:
			b.WriteString("&quot;")
		case r == '\t' && attr:
			b.WriteString("&#9;")
		case r == '\n' && attr:
			b.WriteString("&#10;")
		case r == '\r':
			b.WriteString("&#13;")
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0xFFFE || r == 0xFFFF || r == utf8.RuneError:
			// not an XML character
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
